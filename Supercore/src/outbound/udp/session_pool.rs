use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

const DEFAULT_CAPACITY: usize = 4;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

struct SessionEntry<T> {
    session: Arc<Mutex<T>>,
    last_used: Instant,
}

pub(crate) struct RoundRobinSessionPool<T> {
    sessions: Vec<SessionEntry<T>>,
    next_index: usize,
    capacity: usize,
    idle_timeout: Duration,
}

pub(crate) struct KeyedRoundRobinSessionPool<T> {
    buckets: HashMap<String, RoundRobinSessionPool<T>>,
    capacity_per_key: usize,
    idle_timeout: Duration,
}

impl<T> Default for KeyedRoundRobinSessionPool<T> {
    fn default() -> Self {
        Self::with_limits(DEFAULT_CAPACITY, DEFAULT_IDLE_TIMEOUT)
    }
}

impl<T> KeyedRoundRobinSessionPool<T> {
    pub(crate) fn with_limits(capacity_per_key: usize, idle_timeout: Duration) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity_per_key: capacity_per_key.max(1),
            idle_timeout,
        }
    }

    pub(crate) fn len(&mut self, key: &str) -> usize {
        self.evict_idle();
        self.buckets.get_mut(key).map_or(0, |bucket| bucket.len())
    }

    pub(crate) fn push(&mut self, key: String, session: Arc<Mutex<T>>) {
        let capacity = self.capacity_per_key;
        let idle_timeout = self.idle_timeout;
        self.buckets
            .entry(key)
            .or_insert_with(|| RoundRobinSessionPool::with_limits(capacity, idle_timeout))
            .push(session);
    }

    pub(crate) fn next(&mut self, key: &str) -> Option<Arc<Mutex<T>>> {
        self.evict_idle();
        self.buckets
            .get_mut(key)
            .and_then(RoundRobinSessionPool::next)
    }

    pub(crate) fn remove(&mut self, key: &str, target: &Arc<Mutex<T>>) {
        let should_remove = self.buckets.get_mut(key).is_some_and(|bucket| {
            bucket.remove(target);
            bucket.len() == 0
        });
        if should_remove {
            self.buckets.remove(key);
        }
    }

    fn evict_idle(&mut self) {
        self.buckets.retain(|_, bucket| {
            bucket.evict_idle();
            !bucket.sessions.is_empty()
        });
    }
}

impl<T> Default for RoundRobinSessionPool<T> {
    fn default() -> Self {
        Self::with_limits(DEFAULT_CAPACITY, DEFAULT_IDLE_TIMEOUT)
    }
}

impl<T> RoundRobinSessionPool<T> {
    pub(crate) fn with_limits(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            sessions: Vec::new(),
            next_index: 0,
            capacity: capacity.max(1),
            idle_timeout,
        }
    }

    pub(crate) fn len(&mut self) -> usize {
        self.evict_idle();
        self.sessions.len()
    }

    pub(crate) fn push(&mut self, session: Arc<Mutex<T>>) {
        self.evict_idle();
        if self.sessions.len() >= self.capacity {
            let oldest = self
                .sessions
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(index, _)| index)
                .unwrap_or(0);
            self.sessions.remove(oldest);
            if self.next_index > oldest {
                self.next_index -= 1;
            }
        }
        self.sessions.push(SessionEntry {
            session,
            last_used: Instant::now(),
        });
        self.next_index = 0;
    }

    pub(crate) fn next(&mut self) -> Option<Arc<Mutex<T>>> {
        self.evict_idle();
        if self.sessions.is_empty() {
            self.next_index = 0;
            return None;
        }
        let index = self.next_index % self.sessions.len();
        self.next_index = (index + 1) % self.sessions.len();
        self.sessions[index].last_used = Instant::now();
        Some(Arc::clone(&self.sessions[index].session))
    }

    pub(crate) fn remove(&mut self, target: &Arc<Mutex<T>>) {
        self.sessions
            .retain(|entry| !Arc::ptr_eq(&entry.session, target));
        self.normalize_index();
    }

    pub(crate) fn clear(&mut self) {
        self.sessions.clear();
        self.next_index = 0;
    }

    fn evict_idle(&mut self) {
        let now = Instant::now();
        let idle_timeout = self.idle_timeout;
        self.sessions
            .retain(|entry| now.duration_since(entry.last_used) < idle_timeout);
        self.normalize_index();
    }

    fn normalize_index(&mut self) {
        if self.sessions.is_empty() {
            self.next_index = 0;
        } else {
            self.next_index %= self.sessions.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::sync::Mutex;

    use super::{KeyedRoundRobinSessionPool, RoundRobinSessionPool};

    #[test]
    fn rotates_and_removes_sessions() {
        let first = Arc::new(Mutex::new(1));
        let second = Arc::new(Mutex::new(2));
        let mut pool = RoundRobinSessionPool::default();
        pool.push(Arc::clone(&first));
        pool.push(Arc::clone(&second));

        assert!(Arc::ptr_eq(&pool.next().expect("first"), &first));
        assert!(Arc::ptr_eq(&pool.next().expect("second"), &second));
        pool.remove(&second);
        assert_eq!(pool.len(), 1);
        assert!(Arc::ptr_eq(&pool.next().expect("remaining"), &first));
    }

    #[test]
    fn isolates_round_robin_sessions_by_key() {
        let first = Arc::new(Mutex::new(1));
        let second = Arc::new(Mutex::new(2));
        let other = Arc::new(Mutex::new(3));
        let mut pool = KeyedRoundRobinSessionPool::default();

        pool.push("first".into(), Arc::clone(&first));
        pool.push("first".into(), Arc::clone(&second));
        pool.push("other".into(), Arc::clone(&other));

        assert!(Arc::ptr_eq(&pool.next("first").expect("first"), &first));
        assert!(Arc::ptr_eq(&pool.next("first").expect("second"), &second));
        assert!(Arc::ptr_eq(&pool.next("other").expect("other"), &other));
        pool.remove("first", &first);
        assert_eq!(pool.len("first"), 1);
    }

    #[test]
    fn evicts_oldest_session_at_capacity() {
        let first = Arc::new(Mutex::new(1));
        let second = Arc::new(Mutex::new(2));
        let mut pool = RoundRobinSessionPool::with_limits(1, Duration::from_secs(60));
        pool.push(Arc::clone(&first));
        pool.push(Arc::clone(&second));

        assert_eq!(pool.len(), 1);
        assert!(Arc::ptr_eq(&pool.next().expect("newest"), &second));
    }

    #[tokio::test]
    async fn evicts_idle_sessions() {
        let session = Arc::new(Mutex::new(1));
        let mut pool = RoundRobinSessionPool::with_limits(4, Duration::from_millis(5));
        pool.push(session);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(pool.len(), 0);
    }
}
