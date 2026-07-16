use std::time::{Duration, Instant};

pub(crate) struct IdlePool<T> {
    entries: Vec<IdleEntry<T>>,
    max_size: usize,
    max_idle: Duration,
}

struct IdleEntry<T> {
    value: T,
    idle_since: Instant,
}

impl<T> IdlePool<T> {
    pub(crate) fn new(max_size: usize, max_idle: Duration) -> Self {
        assert!(max_size > 0, "idle pool size must be greater than zero");
        Self {
            entries: Vec::new(),
            max_size,
            max_idle,
        }
    }

    pub(crate) fn take(&mut self) -> Option<T> {
        let now = Instant::now();
        self.entries
            .retain(|entry| now.duration_since(entry.idle_since) <= self.max_idle);
        self.entries.pop().map(|entry| entry.value)
    }

    pub(crate) fn put(&mut self, value: T) {
        if self.entries.len() >= self.max_size {
            self.entries.remove(0);
        }
        self.entries.push(IdleEntry {
            value,
            idle_since: Instant::now(),
        });
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::IdlePool;

    #[test]
    fn evicts_oldest_entry_at_capacity() {
        let mut pool = IdlePool::new(2, Duration::from_secs(60));
        pool.put(1);
        pool.put(2);
        pool.put(3);
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.take(), Some(3));
        assert_eq!(pool.take(), Some(2));
        assert_eq!(pool.take(), None);
    }

    #[test]
    fn removes_expired_entries_before_take() {
        let mut pool = IdlePool::new(1, Duration::from_millis(1));
        pool.put(1);
        thread::sleep(Duration::from_millis(3));
        assert_eq!(pool.take(), None);
    }
}
