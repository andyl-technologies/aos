//! Closes resident backing without holding a mutex during native reads.
//!
//! A started operation owns its backing until completion. Quiescence includes
//! dropping that ownership, rather than merely returning its plaintext.

use std::{
    io,
    sync::{Arc, Mutex},
};

/// Retains a permanently closeable backing slot and its actual operation count.
pub(super) struct ReadView<T> {
    state: Mutex<State<T>>,
}

struct State<T> {
    source: Option<Arc<T>>,
    active: usize,
    closing: bool,
}

impl<T> ReadView<T> {
    /// Starts an open view over original verified backing.
    pub(super) fn new(source: T) -> Self {
        Self {
            state: Mutex::new(State {
                source: Some(Arc::new(source)),
                active: 0,
                closing: false,
            }),
        }
    }

    /// Retains backing before releasing the short slot mutex.
    ///
    /// # Errors
    /// Refuses a closed or poisoned view and exhausted operation counts.
    pub(super) fn begin(&self) -> io::Result<ActiveRead<'_, T>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("resident read slot poisoned"))?;
        let source = Arc::clone(state.source.as_ref().ok_or_else(closed)?);
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| io::Error::other("resident read count exhausted"))?;

        Ok(ActiveRead {
            source,
            _completion: Completion { view: self },
        })
    }

    /// Checks closure at an operation's final observation boundary.
    ///
    /// # Errors
    /// Refuses a closed or poisoned view.
    pub(super) fn check_open(&self) -> io::Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("resident read slot poisoned"))?;
        if state.source.is_none() {
            return Err(closed());
        }
        Ok(())
    }

    /// Permanently closes admission; repeated callers also observe an in-progress drop.
    pub(super) fn close(&self) -> bool {
        let source = {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            let Some(source) = state.source.take() else {
                return !state.closing && state.active == 0;
            };
            state.closing = true;
            source
        };

        // Destruction can close native descriptors or release job custody. It
        // precedes quiescence and runs outside the read-slot mutex.
        drop(source);

        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.closing = false;
        state.active == 0
    }
}

/// Drops original backing before reporting operation completion.
pub(super) struct ActiveRead<'a, T> {
    // Fields drop in declaration order: backing must disappear before the
    // completion counter permits retirement of its original protection.
    /// Original backing retained through the operation.
    pub(super) source: Arc<T>,
    _completion: Completion<'a, T>,
}

struct Completion<'a, T> {
    view: &'a ReadView<T>,
}

impl<T> Drop for Completion<'_, T> {
    fn drop(&mut self) {
        let mut state = match self.view.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.active -= 1;
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "resident read view closed")
}

#[cfg(test)]
mod tests {
    use super::ReadView;
    use std::{
        io,
        sync::{Arc, Barrier, mpsc},
        thread,
        time::Duration,
    };

    #[test]
    fn close_refuses_new_reads_until_started_backing_is_dropped() -> io::Result<()> {
        let source = Arc::new(());
        let observed = Arc::downgrade(&source);
        let view = ReadView::new(source);
        let read = view.begin()?;

        assert!(!view.close());
        assert!(
            view.begin()
                .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert!(view.check_open().is_err());
        assert!(observed.upgrade().is_some());

        drop(read);

        assert!(view.close());
        assert!(observed.upgrade().is_none());
        assert!(view.close());
        Ok(())
    }

    #[test]
    fn concurrent_close_does_not_report_quiescence_during_backing_destruction() {
        struct SlowDrop {
            started: mpsc::Sender<()>,
            finish: Arc<Barrier>,
        }

        impl Drop for SlowDrop {
            fn drop(&mut self) {
                assert!(self.started.send(()).is_ok());
                self.finish.wait();
            }
        }

        let (started, receive) = mpsc::channel();
        let finish = Arc::new(Barrier::new(2));
        let view = Arc::new(ReadView::new(SlowDrop {
            started,
            finish: Arc::clone(&finish),
        }));
        let closing_view = Arc::clone(&view);
        let closer = thread::spawn(move || closing_view.close());
        assert!(receive.recv_timeout(Duration::from_secs(5)).is_ok());

        assert!(!view.close());
        assert!(view.begin().is_err());
        finish.wait();

        assert!(matches!(closer.join(), Ok(true)));
        assert!(view.close());
    }
}
