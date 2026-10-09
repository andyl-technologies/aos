//! Cancellation-safe worker ownership keeps unconfirmed execution charged.

use std::sync::Arc;

use tokio::sync::OwnedSemaphorePermit;

use crate::{RuntimeError, connection::ConnectedWorker, providers::WorkerControl, session::Inner};

pub(crate) struct SlotCharge {
    _permit: OwnedSemaphorePermit,
}

impl SlotCharge {
    pub fn new(permit: OwnedSemaphorePermit) -> Arc<Self> {
        Arc::new(Self { _permit: permit })
    }
}

pub(crate) struct WorkerLease {
    pub worker: Option<ConnectedWorker>,
    inner: Arc<Inner>,
    charge: Option<Arc<SlotCharge>>,
}

impl WorkerLease {
    pub fn new(inner: Arc<Inner>, worker: ConnectedWorker, charge: Arc<SlotCharge>) -> Self {
        Self {
            worker: Some(worker),
            inner,
            charge: Some(charge),
        }
    }

    pub fn reuse(&mut self) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        if state.closed {
            return false;
        }
        if let Some(worker) = self.worker.take() {
            state.idle.push(worker);
        }
        self.charge.take();
        true
    }

    pub async fn retire(mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        let control = worker.connection.control.clone();
        drop(worker);
        cleanup(self.inner.clone(), control, self.charge.take()).await;
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        let control = worker.connection.control.clone();
        drop(worker);
        let inner = self.inner.clone();
        let charge = self.charge.take();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(cleanup(inner, control, charge));
        }
    }
}

pub(crate) struct StartupCleanup {
    pub control: Option<Arc<dyn WorkerControl>>,
    pub inner: Arc<Inner>,
    pub charge: Option<Arc<SlotCharge>>,
}

impl Drop for StartupCleanup {
    fn drop(&mut self) {
        let Some(control) = self.control.take() else {
            return;
        };
        let inner = self.inner.clone();
        let charge = self.charge.take();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(cleanup(inner, control, charge));
        }
    }
}

pub(crate) async fn cleanup(
    inner: Arc<Inner>,
    control: Arc<dyn WorkerControl>,
    charge: Option<Arc<SlotCharge>>,
) {
    if matches!(
        tokio::time::timeout(inner.limits.cleanup_timeout, control.stop()).await,
        Ok(Ok(()))
    ) {
        return;
    }
    quarantine(inner, control, charge);
}

pub(crate) fn quarantine(
    inner: Arc<Inner>,
    control: Arc<dyn WorkerControl>,
    charge: Option<Arc<SlotCharge>>,
) {
    if let Ok(mut state) = inner.lock() {
        state.unconfirmed_workers += 1;
    }
    // Hold the slot after the request ends. Replacement is admitted only when
    // the old execution boundary has actually stopped, even for a cooperative
    // provider that cannot implement hard cancellation.
    tokio::spawn(async move {
        let _charge = charge;
        loop {
            if matches!(
                tokio::time::timeout(inner.limits.cleanup_timeout, control.stop()).await,
                Ok(Ok(()))
            ) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        if let Ok(mut state) = inner.lock() {
            state.unconfirmed_workers = state.unconfirmed_workers.saturating_sub(1);
        }
        inner.changed.notify_waiters();
    });
}

impl Inner {
    pub async fn acquire_worker<F>(
        self: &Arc<Self>,
        dispatched: F,
    ) -> Result<WorkerLease, RuntimeError>
    where
        F: FnOnce() -> Result<(), RuntimeError>,
    {
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RuntimeError::Closed)?;
        dispatched()?;
        let charge = SlotCharge::new(permit);
        if let Some(worker) = self.lock()?.idle.pop() {
            return Ok(WorkerLease::new(self.clone(), worker, charge));
        }
        let (mut sender, receiver) = tokio::sync::oneshot::channel();
        let inner = self.clone();
        // Startup belongs to an independent supervisor, not the caller's future.
        // If cancellation drops the receiver, the returned lease cleans itself
        // up while retaining the same slot charge.
        tokio::spawn(async move {
            let mut cleanup = StartupCleanup {
                control: None,
                inner: inner.clone(),
                charge: Some(charge.clone()),
            };
            let result = tokio::select! {
                result = inner.create_worker(&mut cleanup) => result,
                _ = sender.closed() => return,
            };
            let result = result.map(|worker| {
                cleanup.control.take();
                WorkerLease::new(inner, worker, charge)
            });
            let _ = sender.send(result);
        });
        receiver
            .await
            .map_err(|error| RuntimeError::Provider(Box::new(error)))?
    }
}
