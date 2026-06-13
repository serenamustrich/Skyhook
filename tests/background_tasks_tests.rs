use skyhook::background_tasks::BackgroundScheduler;

#[tokio::test]
async fn background_scheduler_register_and_list() {
    let scheduler = BackgroundScheduler::new();
    scheduler.register("test_task", 60).await;

    let tasks = scheduler.list().await;
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].name, "test_task");
    assert_eq!(tasks[0].interval_secs, 60);
    assert!(tasks[0].enabled);
}

#[tokio::test]
async fn background_scheduler_pause_resume() {
    let scheduler = BackgroundScheduler::new();
    scheduler.register("test_task", 60).await;

    // Pause
    assert!(scheduler.pause("test_task").await);
    assert!(!scheduler.is_enabled("test_task").await);

    let tasks = scheduler.list().await;
    assert!(!tasks[0].enabled);

    // Resume
    assert!(scheduler.resume("test_task").await);
    assert!(scheduler.is_enabled("test_task").await);

    let tasks = scheduler.list().await;
    assert!(tasks[0].enabled);
}

#[tokio::test]
async fn background_scheduler_pause_nonexistent() {
    let scheduler = BackgroundScheduler::new();
    assert!(!scheduler.pause("nonexistent").await);
}

#[tokio::test]
async fn background_scheduler_record_run() {
    let scheduler = BackgroundScheduler::new();
    scheduler.register("test_task", 60).await;

    scheduler.record_run("test_task", 100, None).await;

    let tasks = scheduler.list().await;
    assert_eq!(tasks[0].run_count, 1);
    assert_eq!(tasks[0].last_duration_ms, Some(100));
    assert!(tasks[0].last_error.is_none());
    assert!(tasks[0].last_run_at.is_some());
}

#[tokio::test]
async fn background_scheduler_record_run_with_error() {
    let scheduler = BackgroundScheduler::new();
    scheduler.register("test_task", 60).await;

    scheduler
        .record_run("test_task", 50, Some("connection failed".to_string()))
        .await;

    let tasks = scheduler.list().await;
    assert_eq!(tasks[0].run_count, 1);
    assert_eq!(tasks[0].last_error, Some("connection failed".to_string()));
}

#[tokio::test]
async fn background_scheduler_multiple_tasks() {
    let scheduler = BackgroundScheduler::new();
    scheduler.register("task_a", 60).await;
    scheduler.register("task_b", 120).await;
    scheduler.register("task_c", 300).await;

    let tasks = scheduler.list().await;
    assert_eq!(tasks.len(), 3);

    let names: Vec<&str> = tasks.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"task_a"));
    assert!(names.contains(&"task_b"));
    assert!(names.contains(&"task_c"));
}

#[tokio::test]
async fn background_scheduler_is_enabled_default() {
    let scheduler = BackgroundScheduler::new();
    scheduler.register("test_task", 60).await;

    assert!(scheduler.is_enabled("test_task").await);
    assert!(!scheduler.is_enabled("nonexistent").await);
}
