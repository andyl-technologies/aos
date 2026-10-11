//! Places an exact original four-object result closure before native ACK.
//!
//! This private storage helper grants no native or collection authority. Its
//! source-specific caller supplies authenticated original plan/audit/report/root
//! bodies and a final direct installed/native read before every backend action.
//! One prepared closure remains owned through uncertain placement and retries.

use std::sync::Arc;

use crucible::node_contract::{PublicationStatus, RuntimeError};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName,
};

const MAXIMUM_CLOSURE_BYTES: usize = 64 * 1024 * 1024;

struct OriginalObject {
    id: ContentId,
    bytes: Vec<u8>,
    handle: BlobHandle,
}

pub(super) struct PreparedPacketPlacement {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    reference: RefName,
    objects: [OriginalObject; 4],
}

impl PreparedPacketPlacement {
    // This consumes already authenticated and precredited bodies, not vendor
    // records. Index three is the exact root; its immutable body binds 0..2.
    pub(super) fn prepare(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        reference: RefName,
        bodies: [Vec<u8>; 4],
        maximum_bytes: usize,
    ) -> Result<Self, RuntimeError> {
        if maximum_bytes == 0
            || maximum_bytes > MAXIMUM_CLOSURE_BYTES
            || !reference
                .as_str()
                .starts_with("node-packet-collecting-results/")
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let extent = bodies.iter().try_fold(0usize, |total, body| {
            if body.is_empty() {
                return Err(RuntimeError::ResourceLimit);
            }
            total
                .checked_add(body.len())
                .ok_or(RuntimeError::ResourceLimit)
        })?;
        // Each body, prepared handle, backend-returned in-memory handle and
        // readback may coexist. Backend-private allocation remains external.
        // Credit their complete peak before copying any BlobHandle bytes. The
        // caller separately precredits canonical root/report construction.
        if extent
            .checked_mul(4)
            .is_none_or(|peak| peak > maximum_bytes)
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let objects = bodies.map(|bytes| OriginalObject {
            id: ContentId::for_bytes(ObjectKind::Trace, 1, &bytes),
            handle: BlobHandle::from_bytes(bytes.clone()),
            bytes,
        });
        Ok(Self {
            blobs,
            refs,
            reference,
            objects,
        })
    }

    pub(super) fn publish(
        &self,
        current: impl Fn() -> Result<(), RuntimeError>,
    ) -> Result<PublicationStatus, RuntimeError> {
        // Backend metadata and guard acquisition are callbacks too. A changed
        // current scope cannot survive them into another placement effect.
        current()?;
        let blob_caps = self.blobs.capabilities();
        current()?;
        let ref_caps = self.refs.capabilities();
        current()?;
        if !blob_caps.durable || blob_caps.deferred_write || !ref_caps.durable {
            return Err(RuntimeError::PublicationFailed);
        }
        let Ok(_guard) = self.refs.acquire_publication_guard() else {
            return Ok(PublicationStatus::Unknown);
        };
        current()?;

        for object in &self.objects {
            current()?;
            let put = self.blobs.put_if_absent(object.id, &object.handle);
            current()?;
            // A lost Put reply is not absence. Reopen the SAME immutable bytes;
            // no alternative identity or native execution is introduced.
            if !matches!(put, Ok(ref receipt) if receipt.id == object.id && receipt.is_durable())
                && !self.reopen_object(object, &current)?
            {
                return Ok(PublicationStatus::Unknown);
            }
            if !self.reopen_object(object, &current)? {
                return Ok(PublicationStatus::Unknown);
            }
        }
        let expected = self.objects[3].id;
        current()?;
        let placement = self.refs.compare_exchange(&self.reference, None, expected);
        current()?;
        match placement {
            Ok(RefCasOutcome::Advanced { next }) if next == expected => {}
            Ok(RefCasOutcome::Conflict {
                current: Some(actual),
                ..
            }) if actual == expected => {}
            Ok(_) => return Ok(PublicationStatus::NotCommitted),
            // Uncertain CAS may have committed. Exact original reconciliation
            // below can establish the current root without another mutation.
            Err(_) => {}
        }
        self.reconcile_under_guard(&current)
    }

    pub(super) fn reconcile(
        &self,
        current: impl Fn() -> Result<(), RuntimeError>,
    ) -> Result<PublicationStatus, RuntimeError> {
        current()?;
        let blob_caps = self.blobs.capabilities();
        current()?;
        let ref_caps = self.refs.capabilities();
        current()?;
        if !blob_caps.durable || blob_caps.deferred_write || !ref_caps.durable {
            return Err(RuntimeError::PublicationFailed);
        }
        let Ok(_guard) = self.refs.acquire_publication_guard() else {
            return Ok(PublicationStatus::Unknown);
        };
        current()?;
        self.reconcile_under_guard(&current)
    }

    fn reconcile_under_guard(
        &self,
        current: &impl Fn() -> Result<(), RuntimeError>,
    ) -> Result<PublicationStatus, RuntimeError> {
        current()?;
        let root = self.refs.read_ref(&self.reference);
        current()?;
        match root {
            Ok(Some(actual)) if actual == self.objects[3].id => {}
            Ok(Some(_)) | Ok(None) => return Ok(PublicationStatus::NotCommitted),
            Err(_) => return Ok(PublicationStatus::Unknown),
        }
        for object in &self.objects {
            if !self.reopen_object(object, current)? {
                return Ok(PublicationStatus::Unknown);
            }
        }
        // Re-read the original root after all body callbacks. A backend that
        // changed the ref during readback cannot inherit historical commitment.
        current()?;
        let root = self.refs.read_ref(&self.reference);
        current()?;
        match root {
            Ok(Some(actual)) if actual == self.objects[3].id => Ok(PublicationStatus::Committed),
            Ok(_) => Ok(PublicationStatus::NotCommitted),
            Err(_) => Ok(PublicationStatus::Unknown),
        }
    }

    fn reopen_object(
        &self,
        object: &OriginalObject,
        current: &impl Fn() -> Result<(), RuntimeError>,
    ) -> Result<bool, RuntimeError> {
        current()?;
        let opened = self.blobs.read(object.id, None);
        current()?;
        let Ok(handle) = opened else {
            return Ok(false);
        };
        let maximum_bytes =
            u64::try_from(object.bytes.len()).map_err(|_| RuntimeError::ResourceLimit)?;
        let actual = handle.read_all(maximum_bytes);
        current()?;
        Ok(matches!(actual, Ok(bytes) if bytes == object.bytes))
    }
}

#[cfg(test)]
mod tests;
