use std::sync::Arc;

use tokio::sync::Mutex;

pub(crate) struct RoundRobinSessionPool<T> {
    sessions: Vec<Arc<Mutex<T>>>,
    next_index: usize,
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

    use super::RoundRobinSessionPool;

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
}
