//! One-shot acknowledged-storage faults over the actual durable directory backend.

use std::sync::atomic::{AtomicBool, Ordering};

use crucible_cas::content_store::{RefBackendCapabilities, RefPublicationGuard, RefScanPage};

use super::*;

#[derive(Clone, Copy)]
pub(super) enum FailurePoint {
    BeforeActivationRoot,
    AfterActivationRoot,
}

pub(super) struct FaultRefs {
    inner: Arc<DirectoryRefBackend>,
    point: FailurePoint,
    armed: AtomicBool,
}

impl FaultRefs {
    pub(super) fn new(inner: Arc<DirectoryRefBackend>, point: FailurePoint) -> Self {
        Self {
            inner,
            point,
            armed: AtomicBool::new(true),
        }
    }
}

impl MutableRefBackend for FaultRefs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.inner.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        self.inner.acquire_publication_guard()
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        self.inner.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        self.inner.scan_refs(namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        let inject = name.as_str().starts_with("node-world-activations/")
            && self.armed.swap(false, Ordering::SeqCst);
        if inject && matches!(self.point, FailurePoint::BeforeActivationRoot) {
            return Err(StoreError::Incompatible);
        }
        let result = self.inner.compare_exchange(name, expected, next)?;
        if inject {
            // The durable comparison really happened, but its acknowledgement
            // was lost. The caller must reconcile the exact original objects.
            return Err(StoreError::Incompatible);
        }
        Ok(result)
    }
}
