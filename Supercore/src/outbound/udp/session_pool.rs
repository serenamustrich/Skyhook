use std::{collections::HashMap, sync::Arc};

use tokio::sync::Mutex;

pub(crate) struct RoundRobinSessionPool<T> {
    sessions: Vec<Arc<Mutex<T>>>,
    next_index: usize,
}

pub(crate) struct KeyedRoundRobinSessionPool<T> {
    buckets: HashMap<String, RoundRobinSessionPool<T>>,
}

impl<T> Default for KeyedRoundRobinSessionPool<T> {
    fn default() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }
}

impl<T> KeyedRoundRobinSessionPool<T> {
    pub(crate) fn len(&self, key: &str) -> usize {
        self.buckets.get(key).map_or(0, RoundRobinSessionPool::len)
    }

    pub(crate) fn push(&mut self, key: String, session: Arc<Mutex<T>>) {
        self.buckets.entry(key).or_default().push(session);
    }

    pub(crate) fn next(&mut self, key: &str) -> Option<Arc<Mutex<T>>> {
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
}

impl<T> Default for RoundRobinSessionPool<T> {
    fn default() -> Self {
        Self {
            sessions: Vec::new(),
            next_index: 0,
        }
    }
}

impl<T> RoundRobinSessionPool<T> {
    pub(crate) fn len(&self) -> usize {
        self.sessions.len()
    }

    pub(crate) fn push(&mut self, session: Arc<Mutex<T>>) {
        self.sessions.push(session);
        self.next_index = self.sessions.len();
    }

    pub(crate) fn next(&mut self) -> Option<Arc<Mutex<T>>> {
        if self.sessions.is_empty() {
            self.next_index = 0;
            return None;
        }
        let index = self.next_index % self.sessions.len();
        self.next_index = (index + 1) % self.sessions.len();
        Some(Arc::clone(&self.sessions[index]))
    }

    pub(crate) fn remove(&mut self, target: &Arc<Mutex<T>>) {
        self.sessions
            .retain(|session| !Arc::ptr_eq(session, target));
        if self.sessions.is_empty() {
            self.next_index = 0;
        } else {
            self.next_index %= self.sessions.len();
        }
    }

    pub(crate) fn clear(&mut self) {
        self.sessions.clear();
        self.next_index = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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
}
