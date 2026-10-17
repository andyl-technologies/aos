//! Durable original assertion reports under authoritative coordinator GC roots.

use std::sync::Arc;

use crucible::node_contract::{PublicationStatus, TerminalResultPublisher};
use crucible::node_scheduling::InputPayload;
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName, StoreError,
};
use crucible_node_contract::canonical;

/// Publishes unchanged terminal objects and one write-once complete result root.
///
/// The existing authoritative coordinator namespace retains both actual objects
/// through ordinary daemon GC. Reconciliation checks original bytes; no retry
/// reexecutes assertions or manufactures an acknowledgement permit.
pub struct StoredTerminalResultPublisher {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    reference: RefName,
    maximum_bytes: usize,
}

impl StoredTerminalResultPublisher {
    /// Binds a finite publisher to an independently reserved result root.
    ///
    /// # Errors
    /// Refuses nondurable references, a foreign namespace or invalid byte limits.
    pub fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        reference: RefName,
        maximum_bytes: usize,
    ) -> Result<Self, StoreError> {
        if !refs.capabilities().durable
            || maximum_bytes == 0
            || maximum_bytes > 16 * 1024 * 1024
            || !reference
                .as_str()
                .starts_with("node-world-coordinators/terminal/")
        {
            return Err(StoreError::Incompatible);
        }
        Ok(Self {
            blobs,
            refs,
            reference,
            maximum_bytes,
        })
    }

    fn record(
        &self,
        barrier: &InputPayload,
        report: &InputPayload,
    ) -> Option<(Vec<u8>, ContentId, ContentId)> {
        if barrier.bytes.len().checked_add(report.bytes.len())? > self.maximum_bytes
            || barrier.reference.verify(&barrier.bytes).is_err()
            || report.reference.verify(&report.bytes).is_err()
            || barrier.bytes.is_empty()
            || report.bytes.is_empty()
        {
            return None;
        }
        let barrier_id = ContentId::for_bytes(ObjectKind::Trace, 1, &barrier.bytes);
        let report_id = ContentId::for_bytes(ObjectKind::Trace, 1, &report.bytes);
        let record = canonical::canonical_json(&serde_json::json!({
            "format": "crucible.node-terminal-result",
            "version": 1,
            "barrier": barrier.reference,
            "report": report.reference,
            "barrier_object": barrier_id.to_string(),
            "report_object": report_id.to_string(),
        }))
        .ok()?;
        // Account for the metadata root as well as both retained native
        // objects before acquiring storage authority or writing any bytes.
        if record
            .len()
            .checked_add(barrier.bytes.len())?
            .checked_add(report.bytes.len())?
            > self.maximum_bytes
        {
            return None;
        }
        Some((record, barrier_id, report_id))
    }

    fn reconcile_exact(&self, barrier: &InputPayload, report: &InputPayload) -> PublicationStatus {
        let Some((record, barrier_id, report_id)) = self.record(barrier, report) else {
            return PublicationStatus::NotCommitted;
        };
        let record_id = ContentId::for_bytes(ObjectKind::Trace, 1, &record);
        match self.refs.read_ref(&self.reference) {
            Ok(None) => return PublicationStatus::NotCommitted,
            Ok(Some(actual)) if actual == record_id => {}
            Ok(Some(_)) => return PublicationStatus::NotCommitted,
            Err(_) => return PublicationStatus::Unknown,
        }
        for (id, expected) in [
            (record_id, record.as_slice()),
            (barrier_id, barrier.bytes.as_slice()),
            (report_id, report.bytes.as_slice()),
        ] {
            if !matches!(self.blobs.read(id, None).and_then(|handle| handle.read_all(self.maximum_bytes as u64)),
                Ok(bytes) if bytes == expected)
            {
                return PublicationStatus::Unknown;
            }
        }
        for (suffix, expected) in [("barrier", barrier_id), ("report", report_id)] {
            let Ok(reference) = RefName::new(format!("{}-{suffix}", self.reference.as_str()))
            else {
                return PublicationStatus::Unknown;
            };
            if !matches!(self.refs.read_ref(&reference), Ok(Some(actual)) if actual == expected) {
                return PublicationStatus::Unknown;
            }
        }
        PublicationStatus::Committed
    }
}

impl TerminalResultPublisher for StoredTerminalResultPublisher {
    fn publish(&mut self, barrier: &InputPayload, report: &InputPayload) -> PublicationStatus {
        let Some((record, barrier_id, report_id)) = self.record(barrier, report) else {
            return PublicationStatus::NotCommitted;
        };
        let record_id = ContentId::for_bytes(ObjectKind::Trace, 1, &record);
        let Ok(_guard) = self.refs.acquire_publication_guard() else {
            return PublicationStatus::Unknown;
        };
        for (id, bytes) in [
            (barrier_id, barrier.bytes.as_slice()),
            (report_id, report.bytes.as_slice()),
            (record_id, record.as_slice()),
        ] {
            if !matches!(self.blobs.put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec())),
                Ok(receipt) if receipt.is_durable())
            {
                return PublicationStatus::Unknown;
            }
        }
        // Sibling roots leave the result name available as a file in filesystem
        // reference backends. Each object is rooted directly, so collection does
        // not depend on interpreting an arbitrary JSON report body.
        for (suffix, id) in [("barrier", barrier_id), ("report", report_id)] {
            let Ok(reference) = RefName::new(format!("{}-{suffix}", self.reference.as_str()))
            else {
                return PublicationStatus::Unknown;
            };
            match self.refs.compare_exchange(&reference, None, id) {
                Ok(RefCasOutcome::Advanced { next }) if next == id => {}
                Ok(RefCasOutcome::Conflict {
                    current: Some(current),
                    ..
                }) if current == id => {}
                Ok(_) => return PublicationStatus::NotCommitted,
                Err(_) => return PublicationStatus::Unknown,
            }
        }
        match self.refs.compare_exchange(&self.reference, None, record_id) {
            Ok(RefCasOutcome::Advanced { next }) if next == record_id => {
                self.reconcile_exact(barrier, report)
            }
            Ok(RefCasOutcome::Conflict {
                current: Some(current),
                ..
            }) if current == record_id => self.reconcile_exact(barrier, report),
            Ok(_) => PublicationStatus::NotCommitted,
            Err(_) => PublicationStatus::Unknown,
        }
    }

    fn reconcile(&mut self, barrier: &InputPayload, report: &InputPayload) -> PublicationStatus {
        self.reconcile_exact(barrier, report)
    }
}

#[cfg(test)]
mod tests {
    // Fixture failures deliberately panic; publication code has no such path.
    // crucible-lint: allow panic-shortcut -- Durable publication fixture failures must invalidate the original result.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

    fn payload(bytes: &[u8]) -> InputPayload {
        InputPayload {
            reference: canonical::content_ref(bytes, "application/json").unwrap(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn terminal_metadata_credit_is_reserved_before_any_storage_effect() {
        let directory = tempfile::tempdir().unwrap();
        let blobs_path = directory.path().join("blobs");
        let refs_path = directory.path().join("refs");
        let mut publisher = StoredTerminalResultPublisher::new(
            Arc::new(DirectoryBlobBackend::new("terminal", &blobs_path)),
            Arc::new(DirectoryRefBackend::new(&refs_path)),
            RefName::new("node-world-coordinators/terminal/original").unwrap(),
            2,
        )
        .unwrap();

        assert_eq!(
            publisher.publish(&payload(b"0"), &payload(b"1")),
            PublicationStatus::NotCommitted
        );
        assert!(!blobs_path.exists());
        assert!(!refs_path.exists());
    }

    #[test]
    fn terminal_publication_roots_each_original_object_and_rejects_changed_report() {
        let directory = tempfile::tempdir().unwrap();
        let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "terminal",
            directory.path().join("blobs"),
        ));
        let refs: Arc<dyn MutableRefBackend> =
            Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
        let reference = RefName::new("node-world-coordinators/terminal/original").unwrap();
        let mut publisher =
            StoredTerminalResultPublisher::new(blobs, refs.clone(), reference.clone(), 4096)
                .unwrap();
        let barrier = payload(br#"{"barrier":"original"}"#);
        let report = payload(br#"{"report":"original"}"#);

        assert_eq!(
            publisher.publish(&barrier, &report),
            PublicationStatus::Committed
        );
        assert_eq!(
            publisher.reconcile(&barrier, &report),
            PublicationStatus::Committed
        );
        assert_eq!(
            publisher.publish(&barrier, &report),
            PublicationStatus::Committed
        );
        let original_root = refs.read_ref(&reference).unwrap();
        let roots = refs
            .scan_refs(
                &RefName::new("node-world-coordinators/terminal").unwrap(),
                None,
                16,
            )
            .unwrap();
        assert_eq!(roots.entries().len(), 3);
        for entry in roots.entries() {
            assert!(entry.name().as_str().starts_with(reference.as_str()));
        }

        let changed = payload(br#"{"report":"counterfactual"}"#);
        assert_eq!(
            publisher.publish(&barrier, &changed),
            PublicationStatus::NotCommitted
        );
        assert_eq!(
            publisher.reconcile(&barrier, &changed),
            PublicationStatus::NotCommitted
        );
        assert_eq!(refs.read_ref(&reference).unwrap(), original_root);
        assert_eq!(
            publisher.reconcile(&barrier, &report),
            PublicationStatus::Committed
        );
    }
}
