//! Durable original condition reports and resume receipts under coordinator GC roots.

use std::sync::Arc;

use crucible::node_contract::{ConditionResultPublisher, PublicationStatus};
use crucible::node_scheduling::InputPayload;
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName, StoreError,
};
use crucible_node_contract::canonical;

/// Roots each unchanged original condition object and a write-once result record.
///
/// Stop and resume use distinct immutable records. The resume record retains the
/// original barrier/report as well as its actual native control receipt. Current
/// reconciliation verifies every object and direct root without redoing control.
pub struct StoredConditionResultPublisher {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    reference: RefName,
    maximum_bytes: usize,
}

struct ResultObjects<'a> {
    reference: RefName,
    record: Vec<u8>,
    objects: Vec<(String, ContentId, &'a InputPayload)>,
}

impl StoredConditionResultPublisher {
    /// Binds finite durable publication to an independently reserved result name.
    ///
    /// # Errors
    /// Refuses nondurable references, a foreign namespace or invalid byte credit.
    pub fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        reference: RefName,
        maximum_bytes: usize,
    ) -> Result<Self, StoreError> {
        if !refs.capabilities().durable
            || maximum_bytes == 0
            || maximum_bytes > 64 << 20
            || !reference
                .as_str()
                .starts_with("node-world-coordinators/condition/")
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

    fn objects<'a>(
        &self,
        barrier: &'a InputPayload,
        report: &'a InputPayload,
        resume: Option<&'a InputPayload>,
        dependencies: &[&'a InputPayload],
    ) -> Option<ResultObjects<'a>> {
        let mut payloads = vec![
            ("barrier".to_owned(), barrier),
            ("report".to_owned(), report),
        ];
        if let Some(resume) = resume {
            payloads.push(("resume".to_owned(), resume));
        }
        let source: crucible::node_contract::ConditionStopRecord =
            serde_json::from_slice(&barrier.bytes).ok()?;
        source
            .verify_dependency_closure(dependencies, 65_536, self.maximum_bytes)
            .ok()?;
        let mut unique = std::collections::BTreeMap::new();
        for object in dependencies {
            if let Some(previous) = unique.insert(&object.reference, *object)
                && previous != *object
            {
                return None;
            }
        }
        if unique.len() > 65_536
            || source
                .native
                .iter()
                .any(|inventory| !unique.contains_key(&inventory.receipt.reference))
        {
            return None;
        }
        for (index, object) in unique.into_values().enumerate() {
            payloads.push((format!("dependency-{index}"), object));
        }
        let mut total = 0usize;
        let mut objects = Vec::new();
        let mut metadata = Vec::new();
        for (name, payload) in payloads {
            total = total.checked_add(payload.bytes.len())?;
            if payload.bytes.is_empty()
                || total > self.maximum_bytes
                || payload.reference.verify(&payload.bytes).is_err()
            {
                return None;
            }
            let id = ContentId::for_bytes(ObjectKind::Trace, 1, &payload.bytes);
            metadata.push(serde_json::json!({"name":name,"reference":payload.reference,"object":id.to_string()}));
            objects.push((name, id, payload));
        }
        let phase = if resume.is_some() { "resume" } else { "stop" };
        let reference = RefName::new(format!("{}-{phase}", self.reference.as_str())).ok()?;
        let record = canonical::canonical_json(&serde_json::json!({
            "format":"crucible.node-condition-result","version":1,"phase":phase,"objects":metadata,
        }))
        .ok()?;
        if total.checked_add(record.len())? > self.maximum_bytes {
            return None;
        }
        Some(ResultObjects {
            reference,
            record,
            objects,
        })
    }

    fn reconcile_objects(&self, objects: &ResultObjects<'_>) -> PublicationStatus {
        let record_id = ContentId::for_bytes(ObjectKind::Trace, 1, &objects.record);
        match self.refs.read_ref(&objects.reference) {
            Ok(Some(actual)) if actual == record_id => {}
            Ok(_) => return PublicationStatus::NotCommitted,
            Err(_) => return PublicationStatus::Unknown,
        }
        let reads = std::iter::once((record_id, objects.record.as_slice())).chain(
            objects
                .objects
                .iter()
                .map(|(_, id, payload)| (*id, payload.bytes.as_slice())),
        );
        for (id, expected) in reads {
            if !matches!(self.blobs.read(id,None).and_then(|handle| handle.read_all(self.maximum_bytes as u64)),Ok(bytes) if bytes == expected)
            {
                return PublicationStatus::Unknown;
            }
        }
        for (name, id, _) in &objects.objects {
            let Ok(reference) = RefName::new(format!("{}-{name}", objects.reference.as_str()))
            else {
                return PublicationStatus::Unknown;
            };
            if !matches!(self.refs.read_ref(&reference),Ok(Some(actual)) if actual == *id) {
                return PublicationStatus::Unknown;
            }
        }
        PublicationStatus::Committed
    }

    fn publish_objects(&self, objects: &ResultObjects<'_>) -> PublicationStatus {
        let record_id = ContentId::for_bytes(ObjectKind::Trace, 1, &objects.record);
        let Ok(_guard) = self.refs.acquire_publication_guard() else {
            return PublicationStatus::Unknown;
        };
        let writes = objects
            .objects
            .iter()
            .map(|(_, id, payload)| (*id, payload.bytes.as_slice()))
            .chain(std::iter::once((record_id, objects.record.as_slice())));
        for (id, bytes) in writes {
            if !matches!(self.blobs.put_if_absent(id,&BlobHandle::from_bytes(bytes.to_vec())),Ok(receipt) if receipt.is_durable())
            {
                return PublicationStatus::Unknown;
            }
        }
        for (name, id, _) in &objects.objects {
            let Ok(reference) = RefName::new(format!("{}-{name}", objects.reference.as_str()))
            else {
                return PublicationStatus::Unknown;
            };
            match self.refs.compare_exchange(&reference, None, *id) {
                Ok(RefCasOutcome::Advanced { next }) if next == *id => {}
                Ok(RefCasOutcome::Conflict {
                    current: Some(current),
                    ..
                }) if current == *id => {}
                Ok(_) => return PublicationStatus::NotCommitted,
                Err(_) => return PublicationStatus::Unknown,
            }
        }
        match self
            .refs
            .compare_exchange(&objects.reference, None, record_id)
        {
            Ok(RefCasOutcome::Advanced { next }) if next == record_id => {
                self.reconcile_objects(objects)
            }
            Ok(RefCasOutcome::Conflict {
                current: Some(current),
                ..
            }) if current == record_id => self.reconcile_objects(objects),
            Ok(_) => PublicationStatus::NotCommitted,
            Err(_) => PublicationStatus::Unknown,
        }
    }
}

impl ConditionResultPublisher for StoredConditionResultPublisher {
    fn publish_complete(
        &mut self,
        barrier: &InputPayload,
        report: &InputPayload,
        dependencies: &[&InputPayload],
    ) -> PublicationStatus {
        self.objects(barrier, report, None, dependencies)
            .map_or(PublicationStatus::NotCommitted, |objects| {
                self.publish_objects(&objects)
            })
    }
    fn reconcile_complete(
        &mut self,
        barrier: &InputPayload,
        report: &InputPayload,
        dependencies: &[&InputPayload],
    ) -> PublicationStatus {
        self.objects(barrier, report, None, dependencies)
            .map_or(PublicationStatus::NotCommitted, |objects| {
                self.reconcile_objects(&objects)
            })
    }
    fn publish_resume_complete(
        &mut self,
        barrier: &InputPayload,
        report: &InputPayload,
        resume: &InputPayload,
        dependencies: &[&InputPayload],
    ) -> PublicationStatus {
        self.objects(barrier, report, Some(resume), dependencies)
            .map_or(PublicationStatus::NotCommitted, |objects| {
                self.publish_objects(&objects)
            })
    }
    fn reconcile_resume_complete(
        &mut self,
        barrier: &InputPayload,
        report: &InputPayload,
        resume: &InputPayload,
        dependencies: &[&InputPayload],
    ) -> PublicationStatus {
        self.objects(barrier, report, Some(resume), dependencies)
            .map_or(PublicationStatus::NotCommitted, |objects| {
                self.reconcile_objects(&objects)
            })
    }

    fn publish(&mut self, barrier: &InputPayload, report: &InputPayload) -> PublicationStatus {
        self.objects(barrier, report, None, &[])
            .map_or(PublicationStatus::NotCommitted, |objects| {
                self.publish_objects(&objects)
            })
    }
    fn reconcile(&mut self, barrier: &InputPayload, report: &InputPayload) -> PublicationStatus {
        self.objects(barrier, report, None, &[])
            .map_or(PublicationStatus::NotCommitted, |objects| {
                self.reconcile_objects(&objects)
            })
    }
    fn publish_resume(
        &mut self,
        barrier: &InputPayload,
        report: &InputPayload,
        resume: &InputPayload,
    ) -> PublicationStatus {
        self.objects(barrier, report, Some(resume), &[])
            .map_or(PublicationStatus::NotCommitted, |objects| {
                self.publish_objects(&objects)
            })
    }
    fn reconcile_resume(
        &mut self,
        barrier: &InputPayload,
        report: &InputPayload,
        resume: &InputPayload,
    ) -> PublicationStatus {
        self.objects(barrier, report, Some(resume), &[])
            .map_or(PublicationStatus::NotCommitted, |objects| {
                self.reconcile_objects(&objects)
            })
    }
}
