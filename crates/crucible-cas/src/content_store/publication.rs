//! Owned shared publication leases and exclusive inventory exclusion.
//!
//! Leases own the lifecycle state so a page service can keep exclusion after
//! its constructor returns. Shared acquisition is reentrant across separate
//! leases: publishing a child while a source lease is live cannot deadlock
//! behind an inventory waiting for that same source to close.

use std::sync::{Arc, Condvar, Mutex};

#[derive(Clone, Debug, Default)]
pub(super) struct PublicationLock {
    lifecycle: Arc<Lifecycle>,
}

#[derive(Debug, Default)]
struct Lifecycle {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct State {
    readers: u64,
    exclusive: bool,
    failed: bool,
}

/// Owns one shared publication or exclusive inventory admission.
pub(super) struct PublicationLease {
    lifecycle: Arc<Lifecycle>,
    exclusive: bool,
}

impl PublicationLock {
    pub(super) fn read(&self) -> Result<PublicationLease, ()> {
        self.acquire(false)
    }

    pub(super) fn write(&self) -> Result<PublicationLease, ()> {
        self.acquire(true)
    }

    fn acquire(&self, exclusive: bool) -> Result<PublicationLease, ()> {
        let mut state = self.lifecycle.state.lock().map_err(|_| ())?;
        while !state.failed && (state.exclusive || (exclusive && state.readers != 0)) {
            state = self.lifecycle.changed.wait(state).map_err(|_| ())?;
        }
        if state.failed {
            return Err(());
        }
        if exclusive {
            state.exclusive = true;
        } else {
            state.readers = state.readers.checked_add(1).ok_or(())?;
        }
        Ok(PublicationLease {
            lifecycle: Arc::clone(&self.lifecycle),
            exclusive,
        })
    }
}

impl Drop for PublicationLease {
    fn drop(&mut self) {
        let Ok(mut state) = self.lifecycle.state.lock() else {
            self.lifecycle.changed.notify_all();
            return;
        };
        if self.exclusive {
            if !state.exclusive {
                state.failed = true;
            }
            state.exclusive = false;
        } else if let Some(readers) = state.readers.checked_sub(1) {
            state.readers = readers;
        } else {
            state.failed = true;
        }
        self.lifecycle.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture ownership failures must abort the test.
    #![allow(clippy::expect_used)]

    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn inventory_waits_for_every_independent_owned_lease() {
        let lock = PublicationLock::default();
        let first = lock.read().expect("first source lease");
        let second = lock.read().expect("second source lease");
        let inventory_lock = lock.clone();
        let (started, waiting) = mpsc::channel();
        let (acquired, result) = mpsc::channel();
        let inventory = std::thread::spawn(move || {
            started.send(()).expect("announce inventory");
            let _guard = inventory_lock.write().expect("exclusive inventory");
            acquired.send(()).expect("announce acquisition");
        });
        waiting.recv().expect("inventory started");

        assert!(result.recv_timeout(Duration::from_millis(20)).is_err());
        drop(first);
        assert!(result.recv_timeout(Duration::from_millis(20)).is_err());
        let nested = lock.read().expect("source child publication");
        drop(second);
        assert!(result.recv_timeout(Duration::from_millis(20)).is_err());
        drop(nested);

        result
            .recv_timeout(Duration::from_secs(2))
            .expect("inventory released");
        inventory.join().expect("inventory joined");
    }

    #[test]
    fn source_lease_owns_lifecycle_after_original_handle_closes() {
        let lock = PublicationLock::default();
        let source = lock.read().expect("source lease");
        let retained = lock.clone();
        drop(lock);
        assert_eq!(retained.lifecycle.state.lock().expect("state").readers, 1);
        drop(source);
        let _inventory = retained.write().expect("inventory after source close");
    }
}
