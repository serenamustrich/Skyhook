use std::{collections::HashMap, sync::Arc, time::Duration};

use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const DEFAULT_MAX_TASK_RECORDS: usize = 512;
const DEFAULT_TERMINAL_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_TASK_RESULT_BYTES: usize = 8 * 1024 * 1024;
const MAX_TASK_ERROR_CHARS: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TaskStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TaskFailure {
    pub code: String,
    pub kind: String,
    pub message: String,
    pub retryable: bool,
    pub trace_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TaskRecord {
    pub id: String,
    pub trace_id: String,
    pub kind: String,
    pub status: TaskStatus,
    pub current: u64,
    pub total: Option<u64>,
    pub message: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub result: Option<Value>,
    pub error: Option<TaskFailure>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TaskEvent {
    pub schema_version: u8,
    pub id: String,
    pub event: &'static str,
    pub timestamp: DateTime<Utc>,
    pub task: TaskRecord,
}

struct ManagedTask {
    record: TaskRecord,
    cancellation: CancellationToken,
}

#[derive(Clone)]
pub(crate) struct TaskManager {
    tasks: Arc<RwLock<HashMap<String, ManagedTask>>>,
    events: broadcast::Sender<TaskEvent>,
    max_records: usize,
    terminal_retention: TimeDelta,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_TASK_RECORDS, DEFAULT_TERMINAL_RETENTION)
    }
}

impl TaskManager {
    fn with_limits(max_records: usize, terminal_retention: Duration) -> Self {
        let (events, _) = broadcast::channel(512);
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            events,
            max_records: max_records.max(1),
            terminal_retention: TimeDelta::from_std(terminal_retention).unwrap_or(TimeDelta::MAX),
        }
    }

    pub(crate) async fn create(
        &self,
        kind: impl Into<String>,
        total: Option<u64>,
    ) -> (TaskRecord, CancellationToken) {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let record = TaskRecord {
            id: id.clone(),
            trace_id: Uuid::new_v4().to_string(),
            kind: kind.into(),
            status: TaskStatus::Queued,
            current: 0,
            total,
            message: "queued".to_string(),
            created_at: now,
            started_at: None,
            finished_at: None,
            result: None,
            error: None,
        };
        let cancellation = CancellationToken::new();
        {
            let mut tasks = self.tasks.write().await;
            prune_tasks(
                &mut tasks,
                now,
                self.max_records.saturating_sub(1),
                self.terminal_retention,
                None,
            );
            tasks.insert(
                id,
                ManagedTask {
                    record: record.clone(),
                    cancellation: cancellation.clone(),
                },
            );
        }
        self.publish(record.clone());
        (record, cancellation)
    }

    pub(crate) async fn mark_running(&self, id: &str, message: impl Into<String>) {
        let message = message.into();
        self.update(id, |record| {
            if is_terminal(record.status) {
                return false;
            }
            record.status = TaskStatus::Running;
            record.message = message;
            if record.started_at.is_none() {
                record.started_at = Some(Utc::now());
            }
            true
        })
        .await;
    }

    pub(crate) async fn progress(
        &self,
        id: &str,
        current: u64,
        total: Option<u64>,
        message: impl Into<String>,
    ) {
        let message = message.into();
        self.update(id, |record| {
            if is_terminal(record.status) {
                return false;
            }
            if total.is_some() {
                record.total = total;
            }
            record.current = record
                .total
                .map(|total| current.min(total))
                .unwrap_or(current);
            record.message = message;
            true
        })
        .await;
    }

    pub(crate) async fn succeed(&self, id: &str, result: Value) {
        self.update(id, |record| {
            if is_terminal(record.status) {
                return false;
            }
            let result_size = serde_json::to_vec(&result)
                .map(|encoded| encoded.len())
                .unwrap_or(usize::MAX);
            if result_size > MAX_TASK_RESULT_BYTES {
                record.status = TaskStatus::Failed;
                record.message = "task result exceeded the in-memory size limit".to_string();
                record.finished_at = Some(Utc::now());
                record.error = Some(TaskFailure {
                    code: "task_result_too_large".to_string(),
                    kind: "internal".to_string(),
                    message: record.message.clone(),
                    retryable: false,
                    trace_id: Uuid::new_v4().to_string(),
                });
                record.result = None;
                return true;
            }
            record.status = TaskStatus::Succeeded;
            record.current = record.total.unwrap_or(record.current.max(1));
            record.message = "completed".to_string();
            record.finished_at = Some(Utc::now());
            record.result = Some(result);
            record.error = None;
            true
        })
        .await;
    }

    pub(crate) async fn fail(&self, id: &str, mut failure: TaskFailure) {
        failure.message = truncate_chars(failure.message, MAX_TASK_ERROR_CHARS);
        if failure.trace_id.trim().is_empty() {
            failure.trace_id = Uuid::new_v4().to_string();
        }
        self.update(id, |record| {
            if is_terminal(record.status) {
                return false;
            }
            record.status = TaskStatus::Failed;
            record.message = failure.message.clone();
            record.finished_at = Some(Utc::now());
            record.error = Some(failure);
            record.result = None;
            true
        })
        .await;
    }

    pub(crate) async fn mark_cancelled(&self, id: &str) {
        self.update(id, |record| {
            if is_terminal(record.status) {
                return false;
            }
            record.status = TaskStatus::Cancelled;
            record.message = "cancelled".to_string();
            record.finished_at = Some(Utc::now());
            record.result = None;
            true
        })
        .await;
    }

    pub(crate) async fn cancel(&self, id: &str) -> Option<TaskRecord> {
        let (cancellation, status) = {
            let tasks = self.tasks.read().await;
            tasks
                .get(id)
                .map(|task| (task.cancellation.clone(), task.record.status))
        }?;
        if is_terminal(status) {
            return self.get(id).await;
        }
        cancellation.cancel();
        self.mark_cancelled(id).await;
        self.get(id).await
    }

    pub(crate) async fn cancel_all(&self, message: impl Into<String>) -> Vec<TaskRecord> {
        let message = message.into();
        let updated = {
            let mut tasks = self.tasks.write().await;
            let mut updated = Vec::new();
            for task in tasks.values_mut() {
                if is_terminal(task.record.status) {
                    continue;
                }
                task.cancellation.cancel();
                task.record.status = TaskStatus::Cancelled;
                task.record.message = message.clone();
                task.record.finished_at = Some(Utc::now());
                task.record.result = None;
                task.record.error = None;
                updated.push(task.record.clone());
            }
            updated
        };
        for record in &updated {
            self.publish(record.clone());
        }
        updated
    }

    pub(crate) async fn get(&self, id: &str) -> Option<TaskRecord> {
        self.tasks
            .read()
            .await
            .get(id)
            .map(|task| task.record.clone())
    }

    pub(crate) async fn list(&self) -> Vec<TaskRecord> {
        let mut tasks = self
            .tasks
            .read()
            .await
            .values()
            .map(|task| task.record.clone())
            .collect::<Vec<_>>();
        tasks.sort_by_key(|task| std::cmp::Reverse(task.created_at));
        tasks
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<TaskEvent> {
        self.events.subscribe()
    }

    async fn update(&self, id: &str, mutate: impl FnOnce(&mut TaskRecord) -> bool) {
        let updated = {
            let mut tasks = self.tasks.write().await;
            let Some(task) = tasks.get_mut(id) else {
                return;
            };
            if !mutate(&mut task.record) {
                return;
            }
            let updated = task.record.clone();
            if is_terminal(updated.status) {
                prune_tasks(
                    &mut tasks,
                    Utc::now(),
                    self.max_records,
                    self.terminal_retention,
                    Some(id),
                );
            }
            updated
        };
        self.publish(updated);
    }

    fn publish(&self, task: TaskRecord) {
        let _ = self.events.send(TaskEvent {
            schema_version: 1,
            id: Uuid::new_v4().to_string(),
            event: "task_updated",
            timestamp: Utc::now(),
            task,
        });
    }
}

fn prune_tasks(
    tasks: &mut HashMap<String, ManagedTask>,
    now: DateTime<Utc>,
    max_records: usize,
    terminal_retention: TimeDelta,
    preserve_id: Option<&str>,
) {
    let cutoff = now - terminal_retention;
    tasks.retain(|id, task| {
        preserve_id == Some(id.as_str())
            || !is_terminal(task.record.status)
            || task
                .record
                .finished_at
                .is_none_or(|finished| finished >= cutoff)
    });
    if tasks.len() <= max_records {
        return;
    }

    let mut removable = tasks
        .iter()
        .filter(|(id, task)| preserve_id != Some(id.as_str()) && is_terminal(task.record.status))
        .map(|(id, task)| (id.clone(), task.record.created_at))
        .collect::<Vec<_>>();
    removable.sort_by_key(|(_, created_at)| *created_at);
    let remove_count = tasks.len().saturating_sub(max_records);
    for (id, _) in removable.into_iter().take(remove_count) {
        tasks.remove(&id);
    }
}

fn truncate_chars(value: String, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value;
    }
    let mut truncated = value.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn is_terminal(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Succeeded | TaskStatus::Failed | TaskStatus::Cancelled
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::{TaskManager, TaskStatus};

    #[tokio::test]
    async fn tracks_task_lifecycle_and_cancellation() {
        let manager = TaskManager::default();
        let mut events = manager.subscribe();
        let (record, cancellation) = manager.create("probe", Some(2)).await;
        let created = events.recv().await.unwrap();
        assert_eq!(created.schema_version, 1);
        assert!(!created.id.is_empty());
        assert_eq!(created.event, "task_updated");
        assert_eq!(created.task.id, record.id);
        assert!(!created.task.trace_id.is_empty());
        manager.mark_running(&record.id, "running").await;
        manager.progress(&record.id, 1, Some(2), "half").await;
        let snapshot = manager.get(&record.id).await.unwrap();
        assert_eq!(snapshot.status, TaskStatus::Running);
        assert_eq!(snapshot.current, 1);

        manager.cancel(&record.id).await.unwrap();
        assert!(cancellation.is_cancelled());
        assert_eq!(
            manager.get(&record.id).await.unwrap().status,
            TaskStatus::Cancelled
        );

        let (record, _) = manager.create("update", Some(1)).await;
        manager.succeed(&record.id, json!({ "ok": true })).await;
        assert_eq!(
            manager.get(&record.id).await.unwrap().status,
            TaskStatus::Succeeded
        );
        manager
            .progress(&record.id, 0, Some(2), "late progress")
            .await;
        let snapshot = manager.get(&record.id).await.unwrap();
        assert_eq!(snapshot.status, TaskStatus::Succeeded);
        assert_eq!(snapshot.message, "completed");
    }

    #[tokio::test]
    async fn prunes_old_terminal_tasks_without_evicting_active_tasks() {
        let manager = TaskManager::with_limits(3, Duration::from_secs(24 * 60 * 60));
        let (active, _) = manager.create("active", None).await;
        manager.mark_running(&active.id, "running").await;

        let mut completed_ids = Vec::new();
        for index in 0..4 {
            let (record, _) = manager.create(format!("completed-{index}"), Some(1)).await;
            manager.succeed(&record.id, json!({ "index": index })).await;
            completed_ids.push(record.id);
        }

        let records = manager.list().await;
        assert!(records.iter().any(|record| record.id == active.id));
        assert!(records.len() <= 3);
        assert!(!records.iter().any(|record| record.id == completed_ids[0]));
        assert!(records.iter().any(|record| record.id == completed_ids[3]));
    }

    #[tokio::test]
    async fn expires_terminal_tasks_on_the_next_create() {
        let manager = TaskManager::with_limits(10, Duration::ZERO);
        let (finished, _) = manager.create("finished", Some(1)).await;
        manager.succeed(&finished.id, json!({ "ok": true })).await;
        let (active, _) = manager.create("active", None).await;

        assert!(manager.get(&finished.id).await.is_none());
        assert!(manager.get(&active.id).await.is_some());
    }

    #[tokio::test]
    async fn cancel_all_cancels_only_active_tasks() {
        let manager = TaskManager::default();
        let (active, active_cancellation) = manager.create("active", None).await;
        manager.mark_running(&active.id, "running").await;
        let (finished, _) = manager.create("finished", Some(1)).await;
        manager.succeed(&finished.id, json!({ "ok": true })).await;

        let cancelled = manager.cancel_all("control server stopped").await;

        assert_eq!(cancelled.len(), 1);
        assert_eq!(cancelled[0].id, active.id);
        assert!(active_cancellation.is_cancelled());
        assert_eq!(
            manager.get(&active.id).await.unwrap().status,
            TaskStatus::Cancelled
        );
        assert_eq!(
            manager.get(&finished.id).await.unwrap().status,
            TaskStatus::Succeeded
        );
    }
}
