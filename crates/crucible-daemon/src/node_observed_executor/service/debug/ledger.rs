//! Roots exact Debug originals before queueing and reconciles their unchanged outcomes.

use super::super::original_claim::{OriginalClaims, Reservation, Route};
use super::{
    NodeDebugRecord, NodeDebugResumeRequest, NodeDebugStartRequest, NodeDebugState, NodeDebugStop,
    NodeObservationServiceError, encode, refused,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName,
};
use crucible_node_contract::canonical;
use std::{collections::BTreeSet, sync::Arc};

const MAX_RECORD_BYTES: usize = 32 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub(in crate::node_observed_executor::service) struct DebugLedger {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

pub(in crate::node_observed_executor::service) struct DebugReservation {
    pub(in crate::node_observed_executor::service) record: NodeDebugRecord,
    pub(in crate::node_observed_executor::service) original_dispatch: bool,
    identity: ContentId,
}

impl DebugLedger {
    pub(in crate::node_observed_executor::service) fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        if !refs.capabilities().durable {
            return Err(refused("live Debug requires durable original refs"));
        }
        Ok(Self { blobs, refs })
    }

    pub(in crate::node_observed_executor::service) fn reserve_start(
        &self,
        request: &NodeDebugStartRequest,
    ) -> Result<DebugReservation, NodeObservationServiceError> {
        request.validate()?;
        let bytes = encode(request)?;
        let request_id = identity(&bytes);
        let reference = operation_ref(&request.execution)?;
        let claims = OriginalClaims::new(self.blobs.clone(), self.refs.clone())?;
        let publication = self.refs.acquire_publication_guard().map_err(refused)?;
        if let Some(existing) = self.refs.read_ref(&reference).map_err(refused)? {
            let record = self.read(existing, &request.execution)?;
            if record.request != request_id.encode() {
                return Err(refused("Debug nonce already owns different original bytes"));
            }
            claims.existing(&request.execution, Route::Debug, &bytes)?;
            return Ok(DebugReservation {
                record,
                identity: existing,
                original_dispatch: false,
            });
        }
        if claims.existing(&request.execution, Route::Debug, &bytes)? {
            return Err(refused(
                "original Debug claim has no record; redispatch is forbidden",
            ));
        }
        drop(publication);
        let claim = claims.reserve(&request.execution, Route::Debug, &bytes)?;
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        if let Some(existing) = self.refs.read_ref(&reference).map_err(refused)? {
            let record = self.read(existing, &request.execution)?;
            if record.request != request_id.encode() {
                return Err(refused("Debug nonce already owns different original bytes"));
            }
            return Ok(DebugReservation {
                record,
                identity: existing,
                original_dispatch: false,
            });
        }
        if claim != Reservation::Original {
            return Err(refused(
                "only the original Debug claim may dispatch native work",
            ));
        }
        self.put(request_id, &bytes)?;
        let record = NodeDebugRecord {
            format: "crucible.live-debug-record".into(),
            version: 1,
            execution: request.execution.clone(),
            request: request_id.encode(),
            resume_request: None,
            stop: None,
            outcome: NodeDebugState::AwaitingAdmission {},
        };
        let next = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(&reference, None, next)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next: actual } if actual == next => Ok(DebugReservation {
                record,
                identity: next,
                original_dispatch: true,
            }),
            // Even an identical record published by another owner supplies no
            // dispatch ticket to this caller. The common claim stays original.
            _ => Err(refused("original Debug record requires reconciliation")),
        }
    }

    pub(in crate::node_observed_executor::service) fn reserve_resume(
        &self,
        request: &NodeDebugResumeRequest,
    ) -> Result<DebugReservation, NodeObservationServiceError> {
        request.validate()?;
        let bytes = encode(request)?;
        let request_id = identity(&bytes);
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        let reference = operation_ref(&request.execution)?;
        let previous = self
            .refs
            .read_ref(&reference)
            .map_err(refused)?
            .ok_or_else(|| refused("original Debug execution is absent"))?;
        let record = self.read(previous, &request.execution)?;
        if let Some(original) = &record.resume_request {
            if original != &request_id.encode() {
                return Err(refused("Debug original resume bytes changed"));
            }
            return Ok(DebugReservation {
                record,
                identity: previous,
                original_dispatch: false,
            });
        }
        let NodeDebugState::Stopped { cut, .. } = &record.outcome else {
            return Err(refused(
                "Debug resume requires an original durably reported stop",
            ));
        };
        if request.horizon_ps <= cut.time_ps {
            return Err(refused(
                "Debug suffix horizon does not follow the original stop",
            ));
        }
        self.put(request_id, &bytes)?;
        let next_record = NodeDebugRecord {
            resume_request: Some(request_id.encode()),
            outcome: NodeDebugState::AwaitingResume {
                request: request_id.encode(),
            },
            ..record
        };
        let next = self.put_record(&next_record)?;
        match self
            .refs
            .compare_exchange(&reference, Some(previous), next)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next: actual } if actual == next => Ok(DebugReservation {
                record: next_record,
                identity: next,
                original_dispatch: true,
            }),
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } => {
                let record = self.read(current, &request.execution)?;
                if record.resume_request.as_deref() != Some(request_id.encode().as_str()) {
                    return Err(refused("another original owns Debug resume custody"));
                }
                Ok(DebugReservation {
                    record,
                    identity: current,
                    original_dispatch: false,
                })
            }
            _ => Err(refused("Debug original resume requires reconciliation")),
        }
    }

    pub(in crate::node_observed_executor::service) fn complete(
        &self,
        original: &DebugReservation,
        outcome: NodeDebugState,
    ) -> Result<NodeDebugRecord, NodeObservationServiceError> {
        if !original.original_dispatch
            || !matches!(
                original.record.outcome,
                NodeDebugState::AwaitingAdmission { .. } | NodeDebugState::AwaitingResume { .. }
            )
            || matches!(
                outcome,
                NodeDebugState::AwaitingAdmission { .. } | NodeDebugState::AwaitingResume { .. }
            )
        {
            return Err(refused(
                "Debug completion is not the retained original transition",
            ));
        }
        let stop = match &outcome {
            NodeDebugState::Stopped {
                cut,
                barrier,
                report,
            } => Some(NodeDebugStop {
                cut: *cut,
                barrier: barrier.clone(),
                report: report.clone(),
            }),
            _ => original.record.stop.clone(),
        };
        let record = NodeDebugRecord {
            outcome,
            stop,
            ..original.record.clone()
        };
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        let next = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(
                &operation_ref(&record.execution)?,
                Some(original.identity),
                next,
            )
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next: actual } if actual == next => Ok(record),
            RefCasOutcome::Conflict {
                current: Some(actual),
                ..
            } if actual == next => self.read(actual, &record.execution),
            _ => Err(refused("Debug original completion requires reconciliation")),
        }
    }

    pub(in crate::node_observed_executor::service) fn publish_outputs(
        &self,
        execution: &str,
        publications: &[crucible::node_scheduling::NativePublication],
    ) -> Result<crucible_node_contract::ContentRef, NodeObservationServiceError> {
        super::super::conditional_preparation::validate_execution(execution)?;
        // Charge the worst-case JSON byte expansion before serde copies any
        // payload. The actual source bodies and all associations remain intact.
        let mut credit = 1024usize;
        if publications.len() > 8192 {
            return Err(refused(
                "Debug original output association credit exhausted",
            ));
        }
        for publication in publications {
            publication
                .payload
                .verify(&publication.payload_bytes)
                .map_err(refused)?;
            let payload = publication.payload_bytes.len().checked_mul(4);
            let parents = publication.causal_parents.len().checked_mul(128);
            credit = payload
                .and_then(|bytes| {
                    parents.and_then(|parents| {
                        credit
                            .checked_add(bytes)?
                            .checked_add(parents)?
                            .checked_add(4096)
                    })
                })
                .ok_or_else(|| refused("Debug original output byte credit overflow"))?;
            if credit > 32 * 1024 * 1024 {
                return Err(refused("Debug original output byte credit exhausted"));
            }
        }
        #[derive(serde::Serialize)]
        struct Outputs<'a> {
            format: &'static str,
            version: u32,
            execution: &'a str,
            publications: &'a [crucible::node_scheduling::NativePublication],
        }
        let bytes = encode(&Outputs {
            format: "crucible.live-debug-publications",
            version: 1,
            execution,
            publications,
        })?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err(refused(
                "Debug encoded original output byte credit exhausted",
            ));
        }
        let identity = identity(&bytes);
        let reference = canonical::content_ref(&bytes, "application/json").map_err(refused)?;
        let name = RefName::new(format!("node-debug-publications/{execution}")).map_err(refused)?;
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        self.put(identity, &bytes)?;
        match self
            .refs
            .compare_exchange(&name, None, identity)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == identity => {}
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == identity => {}
            _ => {
                return Err(refused(
                    "Debug original output publication requires reconciliation",
                ));
            }
        }
        if self.bytes(identity, 32 * 1024 * 1024)? != bytes {
            return Err(refused("Debug original output publication changed"));
        }
        Ok(reference)
    }

    pub(in crate::node_observed_executor::service) fn owns(
        &self,
        execution: &str,
    ) -> Result<bool, NodeObservationServiceError> {
        Ok(self
            .refs
            .read_ref(&operation_ref(execution)?)
            .map_err(refused)?
            .is_some())
    }

    pub(in crate::node_observed_executor::service) fn state(
        &self,
        execution: &str,
    ) -> Result<NodeDebugRecord, NodeObservationServiceError> {
        let id = self
            .refs
            .read_ref(&operation_ref(execution)?)
            .map_err(refused)?
            .ok_or_else(|| refused("original Debug record is absent"))?;
        self.read(id, execution)
    }

    pub(in crate::node_observed_executor::service) fn retention_roots(
        &self,
    ) -> Result<BTreeSet<ContentId>, NodeObservationServiceError> {
        let mut roots = BTreeSet::new();
        let namespace = RefName::new("node-debug-preparations").map_err(refused)?;
        let mut after = None;
        let mut records = 0;
        loop {
            let page = self
                .refs
                .scan_refs(&namespace, after.as_ref(), 64)
                .map_err(refused)?;
            for entry in page.entries() {
                records += 1;
                if records > 4096 {
                    return Err(refused(
                        "Debug retained namespace exceeds common original credit",
                    ));
                }
                let execution = entry
                    .name()
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| refused("Debug original namespace differs"))?;
                let record = self.read(entry.target(), execution)?;
                roots.insert(entry.target());
                if let Some(outputs) = self
                    .refs
                    .read_ref(
                        &RefName::new(format!("node-debug-publications/{execution}"))
                            .map_err(refused)?,
                    )
                    .map_err(refused)?
                {
                    let bytes = self.bytes(outputs, 32 * 1024 * 1024)?;
                    if let NodeDebugState::Resumed { publications, .. } = &record.outcome {
                        publications.verify(&bytes).map_err(refused)?;
                    }
                    roots.insert(outputs);
                }
                roots.insert(ContentId::parse(&record.request).map_err(refused)?);
                if let Some(resume) = record.resume_request {
                    roots.insert(ContentId::parse(&resume).map_err(refused)?);
                }
            }
            after = page.next_after().cloned();
            if after.is_none() {
                break;
            }
        }
        roots
            .extend(OriginalClaims::new(self.blobs.clone(), self.refs.clone())?.retention_roots()?);
        Ok(roots)
    }

    fn read(
        &self,
        id: ContentId,
        execution: &str,
    ) -> Result<NodeDebugRecord, NodeObservationServiceError> {
        let bytes = self.bytes(id, MAX_RECORD_BYTES)?;
        let record: NodeDebugRecord = serde_json::from_value(
            canonical::parse_json(&bytes, MAX_RECORD_BYTES).map_err(refused)?,
        )
        .map_err(refused)?;
        if record.format != "crucible.live-debug-record"
            || record.version != 1
            || record.execution != execution
            || encode(&record)? != bytes
        {
            return Err(refused("Debug original record identity or edition differs"));
        }
        let source = self.bytes(
            ContentId::parse(&record.request).map_err(refused)?,
            MAX_REQUEST_BYTES,
        )?;
        let original = NodeDebugStartRequest::from_json(&source)?;
        if original.execution != execution || encode(&original)? != source {
            return Err(refused("Debug original request identity differs"));
        }
        if let Some(resume) = &record.resume_request {
            let source = self.bytes(ContentId::parse(resume).map_err(refused)?, 4096)?;
            let original: NodeDebugResumeRequest =
                serde_json::from_value(canonical::parse_json(&source, 4096).map_err(refused)?)
                    .map_err(refused)?;
            original.validate()?;
            if original.execution != execution || encode(&original)? != source {
                return Err(refused("Debug original resume identity differs"));
            }
        }
        Ok(record)
    }

    fn put_record(
        &self,
        record: &NodeDebugRecord,
    ) -> Result<ContentId, NodeObservationServiceError> {
        let bytes = encode(record)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(refused("Debug record byte credit exceeded"));
        }
        let id = identity(&bytes);
        self.put(id, &bytes)?;
        Ok(id)
    }

    fn put(&self, id: ContentId, bytes: &[u8]) -> Result<(), NodeObservationServiceError> {
        if !self
            .blobs
            .put_if_absent(id, &BlobHandle::from_bytes(bytes.to_vec()))
            .map_err(refused)?
            .is_durable()
        {
            return Err(refused("Debug original immutable bytes are not durable"));
        }
        if self.bytes(id, bytes.len())? != bytes {
            return Err(refused("Debug immutable bytes changed"));
        }
        Ok(())
    }

    fn bytes(&self, id: ContentId, limit: usize) -> Result<Vec<u8>, NodeObservationServiceError> {
        let bytes = self
            .blobs
            .read(id, None)
            .map_err(refused)?
            .read_all(limit as u64)
            .map_err(refused)?;
        if identity(&bytes) != id {
            return Err(refused("Debug immutable identity differs"));
        }
        Ok(bytes)
    }
}

fn identity(bytes: &[u8]) -> ContentId {
    ContentId::for_bytes(ObjectKind::Trace, 1, bytes)
}

fn operation_ref(execution: &str) -> Result<RefName, NodeObservationServiceError> {
    super::super::conditional_preparation::validate_execution(execution)?;
    RefName::new(format!("node-debug-preparations/{execution}")).map_err(refused)
}
