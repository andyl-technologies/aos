//! Capacity and physical-key ownership through bounded OCI observations.
//!
//! The R2 SDK exposes no HEAD/GET abort handle. A timed-out caller closes its
//! observation immediately, while a detached pending SDK await retains this
//! owner and its key/capacity until the actual promise resolves. Closure never
//! proves provider drain or settles a mutation journal.

#[cfg(target_arch = "wasm32")]
use crate::direct_digest::Reader;
use anyhow::{ensure, Result};
use std::cell::RefCell;
use std::{cell::Cell, rc::Rc};

pub(super) struct Owner<R> {
    closed: Cell<bool>,
    cleanup: RefCell<Option<Box<dyn FnOnce()>>>,
    _resources: R,
}

impl<R> Owner<R> {
    pub(super) fn new(resources: R) -> Rc<Self> {
        Rc::new(Self {
            closed: Cell::new(false),
            cleanup: RefCell::new(None),
            _resources: resources,
        })
    }

    pub(super) fn check_open(&self) -> Result<()> {
        ensure!(!self.closed.get(), "OCI observation closed");
        Ok(())
    }

    pub(super) fn close(&self) {
        if self.closed.replace(true) {
            return;
        }
        // Close before calling native cancellation. A late SDK completion
        // cannot attach a reader or turn into fresh business permission.
        if let Some(cleanup) = self.cleanup.borrow_mut().take() {
            cleanup();
        }
    }

    fn install_cleanup(&self, cleanup: Box<dyn FnOnce()>) -> Result<()> {
        self.check_open()?;
        ensure!(
            self.cleanup.borrow().is_none(),
            "OCI reader already attached"
        );
        *self.cleanup.borrow_mut() = Some(cleanup);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) fn attach(&self, reader: Reader) -> Result<Rc<Reader>> {
        let reader = Rc::new(reader);
        let held = Rc::clone(&reader);
        self.install_cleanup(Box::new(move || drop(held)))?;
        Ok(reader)
    }
}

impl<R> Drop for Owner<R> {
    fn drop(&mut self) {
        self.close();
    }
}

pub(super) struct Scope<R>(pub(super) Rc<Owner<R>>);
impl<R> Drop for Scope<R> {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_upload::provider_capacity::{self, Class};
    use futures_util::lock::Mutex;
    use std::{cell::Cell, sync::Arc};

    #[tokio::test]
    async fn deadline_closure_retains_pending_sdk_key_and_capacity_until_resolution() {
        provider_capacity::configure(1).unwrap();
        let gate = Arc::new(Mutex::new(()));
        let key = gate.try_lock_owned().unwrap();
        let permit = provider_capacity::acquire_class(1, Class::Metadata)
            .await
            .unwrap();
        let buffer = crate::mirror_import::buffers::acquire(false, || Ok(()))
            .await
            .unwrap();
        let owner = Owner::new((key, permit, buffer));
        let pending_sdk = Rc::clone(&owner);
        let scope = Scope(Rc::clone(&owner));
        drop(scope);
        drop(owner);
        assert!(pending_sdk.check_open().is_err());
        assert!(gate.try_lock_owned().is_none());
        let waiting = provider_capacity::acquire_class(1, Class::Metadata);
        futures_util::pin_mut!(waiting);
        assert!(futures_util::poll!(&mut waiting).is_pending());
        let buffer_waiting = crate::mirror_import::buffers::acquire(false, || Ok(()));
        futures_util::pin_mut!(buffer_waiting);
        assert!(futures_util::poll!(&mut buffer_waiting).is_pending());
        drop(pending_sdk);
        assert!(gate.try_lock_owned().is_some());
        let acquired = waiting.await;
        assert!(acquired.is_ok());
        assert!(buffer_waiting.await.is_ok());
    }

    #[test]
    fn close_is_idempotent_and_does_not_claim_resource_settlement() {
        struct Resource(Rc<Cell<usize>>);
        impl Drop for Resource {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let dropped = Rc::new(Cell::new(0));
        let owner = Owner::new(Resource(Rc::clone(&dropped)));
        owner.close();
        owner.close();
        assert!(owner.check_open().is_err());
        assert_eq!(dropped.get(), 0);
        drop(owner);
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    fn rejected_returned_body_is_closed_before_key_resources_are_released() {
        let gate = Arc::new(Mutex::new(()));
        let permit = gate.try_lock_owned().unwrap();
        let owner = Owner::new(permit);
        let cancelled = Rc::new(Cell::new(0));
        let observed = Rc::clone(&cancelled);
        let key = Arc::clone(&gate);
        owner
            .install_cleanup(Box::new(move || {
                assert!(key.try_lock_owned().is_none());
                observed.set(observed.get() + 1);
            }))
            .unwrap();
        let observation = || -> Result<()> {
            let _scope = Scope(Rc::clone(&owner));
            anyhow::bail!("returned body identity differs from conditional HEAD")
        };
        assert!(observation().is_err());
        assert_eq!(cancelled.get(), 1);
        owner.close();
        assert_eq!(cancelled.get(), 1);
        assert!(gate.try_lock_owned().is_none());
        drop(owner);
        assert!(gate.try_lock_owned().is_some());
    }
}
