//! Independent exact-node retirement receipts, armed after controller removal.
//!
//! A published client retains its receipt without retaining the registry. Once
//! retirement closes that client and removes its indexed Owner, the receipt
//! retains the original actor admission authority through final physical close.

use super::*;

pub(super) struct NodeRetirement {
    registry: Weak<Shared>,
    target: HostRamTarget,
    admission: Mutex<Option<Arc<dyn HostResourceAdmission>>>,
}

impl NodeRetirement {
    pub(super) fn arm(
        &self,
        admission: Arc<dyn HostResourceAdmission>,
    ) -> Result<(), RamControlError> {
        let mut slot = self
            .admission
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if slot.is_some() {
            return Err(RamControlError::AuthorityMismatch);
        }
        *slot = Some(admission);
        Ok(())
    }
}

impl RamControlRetirementAuthority for NodeRetirement {
    fn retire_after_cleanup(&self) -> Result<(), RamControlError> {
        let mut slot = self
            .admission
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        let admission = slot.as_ref().ok_or(RamControlError::AuthorityMismatch)?;
        // The callback comes from final private custody, after registry
        // retirement removed its own controller borrower. No current registrar
        // or mutable operator-selected target participates in this release.
        if let Some(shared) = self.registry.upgrade() {
            let registry = HostOperationalRegistry { shared };
            registry
                .finish_native_node_cleanup(self.target, || {
                    admission.release_after_cleanup(self.target)
                })
                .map_err(|_| RamControlError::AuthorityMismatch)?;
        } else {
            admission
                .release_after_cleanup(self.target)
                .map_err(|_| RamControlError::AuthorityMismatch)?;
        }
        *slot = None;
        Ok(())
    }
}

impl HostOperationalRegistry {
    pub(super) fn node_retirement_authority(
        &self,
        target: HostRamTarget,
    ) -> Result<Arc<NodeRetirement>, HostOperationalError> {
        let _transaction = self.shared.mutation.try_lock().map_err(unavailable)?;
        let owner = self.node(target)?;
        let mut slot = owner.retirement.lock().map_err(unavailable)?;
        if let Some(authority) = slot.as_ref().and_then(Weak::upgrade) {
            return Ok(authority);
        }
        let authority = Arc::new(NodeRetirement {
            registry: Arc::downgrade(&self.shared),
            target,
            admission: Mutex::new(None),
        });
        *slot = Some(Arc::downgrade(&authority));
        Ok(authority)
    }
}
