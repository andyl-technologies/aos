//! Roots exact preserving Debug originals before queueing and reconciles their unchanged outcomes.

use super::super::original_claim::{OriginalClaims, Reservation as ClaimReservation, Route};
use super::{
    NodeObservationServiceError, NodePreservingDebugCapture, NodePreservingDebugRecord,
    NodePreservingDebugRequest, NodePreservingDebugResumeRequest, NodePreservingDebugState, encode,
    refused,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName,
};
use crucible_node_contract::canonical;
use std::{collections::BTreeSet, sync::Arc};

const MAX_RECORD_BYTES: usize = 32 * 1024;
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub(in crate::node_observed_executor::service) struct Ledger {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

pub(in crate::node_observed_executor::service) struct Reservation {
    pub(in crate::node_observed_executor::service) record: NodePreservingDebugRecord,
    pub(in crate::node_observed_executor::service) original_dispatch: bool,
    identity: ContentId,
}

/// Retains one immutable original suffix body across uncertain placement.
pub(super) struct SealedOutputs {
    bytes: Vec<u8>,
    identity: ContentId,
    reference: crucible_node_contract::ContentRef,
    name: RefName,
}

impl Ledger {
    pub(in crate::node_observed_executor::service) fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        if !refs.capabilities().durable {
            return Err(refused(
                "live preserving Debug requires durable original refs",
            ));
        }
        Ok(Self { blobs, refs })
    }

    pub(in crate::node_observed_executor::service) fn reserve_prepare(
        &self,
        request: &NodePreservingDebugRequest,
    ) -> Result<Reservation, NodeObservationServiceError> {
        request.validate()?;
        let _ = self.source_capture(request)?;
        let bytes = encode(request)?;
        let request_id = identity(&bytes);
        let reference = operation_ref(&request.execution)?;
        let claims = OriginalClaims::new(self.blobs.clone(), self.refs.clone())?;
        let publication = self.refs.acquire_publication_guard().map_err(refused)?;
        if let Some(existing) = self.refs.read_ref(&reference).map_err(refused)? {
            let record = self.read(existing, &request.execution)?;
            if record.request != request_id.encode() {
                return Err(refused(
                    "preserving Debug nonce already owns different original bytes",
                ));
            }
            claims.existing(&request.execution, Route::DebugPreserving, &bytes)?;
            return Ok(Reservation {
                record,
                identity: existing,
                original_dispatch: false,
            });
        }
        if claims.existing(&request.execution, Route::DebugPreserving, &bytes)? {
            return Err(refused(
                "original preserving Debug claim has no record; redispatch is forbidden",
            ));
        }
        drop(publication);
        let claim = claims.reserve(&request.execution, Route::DebugPreserving, &bytes)?;
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        if let Some(existing) = self.refs.read_ref(&reference).map_err(refused)? {
            let record = self.read(existing, &request.execution)?;
            if record.request != request_id.encode() {
                return Err(refused(
                    "preserving Debug nonce already owns different original bytes",
                ));
            }
            return Ok(Reservation {
                record,
                identity: existing,
                original_dispatch: false,
            });
        }
        if claim != ClaimReservation::Original {
            return Err(refused(
                "only the original preserving Debug claim may dispatch native work",
            ));
        }
        self.put(request_id, &bytes)?;
        let record = NodePreservingDebugRecord {
            format: "crucible.preserving-debug-record".into(),
            version: 1,
            execution: request.execution.clone(),
            request: request_id.encode(),
            resume_request: None,
            capture: self.source_capture(request)?,
            outcome: NodePreservingDebugState::AwaitingAdmission {},
        };
        let next = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(&reference, None, next)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next: actual } if actual == next => Ok(Reservation {
                record,
                identity: next,
                original_dispatch: true,
            }),
            // Even an identical record published by another owner supplies no
            // dispatch ticket to this caller. The common claim stays original.
            _ => Err(refused(
                "original preserving Debug record requires reconciliation",
            )),
        }
    }

    pub(super) fn source_capture(
        &self,
        request: &NodePreservingDebugRequest,
    ) -> Result<Option<NodePreservingDebugCapture>, NodeObservationServiceError> {
        let super::NodePreservingDebugAction::Restore {
            source_execution,
            capture,
        } = &request.action
        else {
            return Ok(None);
        };
        let record = self.state(source_execution)?;
        let link = record
            .capture
            .ok_or_else(|| refused("original source has no authentic capture record"))?;
        let source_bytes = self.bytes(
            ContentId::parse(&record.request).map_err(refused)?,
            MAX_REQUEST_BYTES,
        )?;
        let source = NodePreservingDebugRequest::from_json(&source_bytes)?;
        if !matches!(source.action, super::NodePreservingDebugAction::Capture {})
            || link.source_execution != *source_execution
            || link.source_request != record.request
            || link.artifact != *capture
            || source.scenario != request.scenario
            || source.observer != request.observer
            || source.maximum_physical_cut != request.maximum_physical_cut
            || source.maximum_record_bytes != request.maximum_record_bytes
            || encode(&source.selections)? != encode(&request.selections)?
            || !OriginalClaims::new(self.blobs.clone(), self.refs.clone())?.existing(
                source_execution,
                Route::DebugPreserving,
                &source_bytes,
            )?
        {
            return Err(refused(
                "signed capture is outside its original source-owned operator relation",
            ));
        }
        Ok(Some(link))
    }

    pub(super) fn refuse_preparation(
        &self,
        original: &NodePreservingDebugRecord,
        reason: &str,
    ) -> Result<(), NodeObservationServiceError> {
        let bytes = encode(original)?;
        let reservation = Reservation {
            record: original.clone(),
            identity: identity(&bytes),
            original_dispatch: true,
        };
        self.complete(
            &reservation,
            NodePreservingDebugState::Unknown {
                reason: reason.chars().take(2048).collect(),
            },
            None,
        )?;
        Ok(())
    }

    pub(in crate::node_observed_executor::service) fn reserve_resume(
        &self,
        request: &NodePreservingDebugResumeRequest,
    ) -> Result<Reservation, NodeObservationServiceError> {
        request.validate()?;
        let bytes = encode(request)?;
        let request_id = identity(&bytes);
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        let reference = operation_ref(&request.execution)?;
        let previous = self
            .refs
            .read_ref(&reference)
            .map_err(refused)?
            .ok_or_else(|| refused("original preserving Debug execution is absent"))?;
        let record = self.read(previous, &request.execution)?;
        if let Some(original) = &record.resume_request {
            if original != &request_id.encode() {
                return Err(refused("preserving Debug original resume bytes changed"));
            }
            return Ok(Reservation {
                record,
                identity: previous,
                original_dispatch: false,
            });
        }
        let NodePreservingDebugState::Stopped {} = &record.outcome else {
            return Err(refused(
                "preserving Debug resume requires an original durably reported stop",
            ));
        };
        if request.horizon_ps
            <= record
                .capture
                .as_ref()
                .ok_or_else(|| refused("original preserving capture absent"))?
                .cut
                .time_ps
        {
            return Err(refused(
                "preserving Debug suffix horizon does not follow the original stop",
            ));
        }
        self.put(request_id, &bytes)?;
        let next_record = NodePreservingDebugRecord {
            resume_request: Some(request_id.encode()),
            outcome: NodePreservingDebugState::AwaitingResume {},
            ..record
        };
        let next = self.put_record(&next_record)?;
        match self
            .refs
            .compare_exchange(&reference, Some(previous), next)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next: actual } if actual == next => Ok(Reservation {
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
                    return Err(refused(
                        "another original owns preserving Debug resume custody",
                    ));
                }
                Ok(Reservation {
                    record,
                    identity: current,
                    original_dispatch: false,
                })
            }
            _ => Err(refused(
                "preserving Debug original resume requires reconciliation",
            )),
        }
    }

    pub(in crate::node_observed_executor::service) fn complete(
        &self,
        original: &Reservation,
        outcome: NodePreservingDebugState,
        capture: Option<NodePreservingDebugCapture>,
    ) -> Result<NodePreservingDebugRecord, NodeObservationServiceError> {
        if !original.original_dispatch
            || !matches!(
                original.record.outcome,
                NodePreservingDebugState::AwaitingAdmission { .. }
                    | NodePreservingDebugState::AwaitingResume { .. }
            )
            || matches!(
                outcome,
                NodePreservingDebugState::AwaitingAdmission { .. }
                    | NodePreservingDebugState::AwaitingResume { .. }
            )
        {
            return Err(refused(
                "preserving Debug completion is not the retained original transition",
            ));
        }
        let record = NodePreservingDebugRecord {
            outcome,
            capture: capture.or_else(|| original.record.capture.clone()),
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
            _ => Err(refused(
                "preserving Debug original completion requires reconciliation",
            )),
        }
    }

    pub(super) fn seal_outputs(
        &self,
        execution: &str,
        publications: &[crucible::node_scheduling::NativePublication],
        runtime: &crucible::node_contract::RuntimeSnapshot,
        declared_record_bytes: usize,
    ) -> Result<SealedOutputs, NodeObservationServiceError> {
        super::super::conditional_preparation::validate_execution(execution)?;
        // The whole suffix envelope spends the original authored credit,
        // independently bounded by the unchanged server output ceiling.
        let maximum_bytes = declared_record_bytes.min(32 * 1024 * 1024);
        // Charge the worst-case JSON byte expansion before serde copies any
        // payload. The actual source bodies and all associations remain intact.
        let mut credit = 1024usize;
        if publications.len() > 8192 {
            return Err(refused(
                "preserving Debug original output association credit exhausted",
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
                .ok_or_else(|| refused("preserving Debug original output byte credit overflow"))?;
            if credit > maximum_bytes {
                return Err(refused(
                    "preserving Debug original output byte credit exhausted",
                ));
            }
        }
        #[derive(serde::Serialize)]
        struct Outputs<'a> {
            format: &'static str,
            version: u32,
            execution: &'a str,
            publications: &'a [crucible::node_scheduling::NativePublication],
            runtime: &'a crucible::node_contract::RuntimeSnapshot,
        }
        let original = Outputs {
            format: "crucible.preserving-debug-publications",
            version: 1,
            execution,
            publications,
            runtime,
        };
        // The complete original operation/input/ACK ledger is data only. Its
        // byte-owning serializer is precredited before canonical allocation,
        // and no native owner is discharged until this exact body is durable.
        super::budget::bounded_json(&original, maximum_bytes)?;
        let bytes = encode(&original)?;
        if bytes.len() > maximum_bytes {
            return Err(refused(
                "preserving Debug encoded original output byte credit exhausted",
            ));
        }
        let identity = identity(&bytes);
        let reference = canonical::content_ref(&bytes, "application/json").map_err(refused)?;
        let name = RefName::new(format!("node-preserving-debug-publications/{execution}"))
            .map_err(refused)?;
        Ok(SealedOutputs {
            bytes,
            identity,
            reference,
            name,
        })
    }

    /// Reconciles only the exact presealed body without rerunning native work.
    pub(super) fn place_outputs(
        &self,
        original: &SealedOutputs,
    ) -> Result<crucible_node_contract::ContentRef, NodeObservationServiceError> {
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        self.put(original.identity, &original.bytes)?;
        match self
            .refs
            .compare_exchange(&original.name, None, original.identity)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == original.identity => {}
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == original.identity => {}
            _ => {
                return Err(refused(
                    "preserving Debug original output publication requires reconciliation",
                ));
            }
        }
        if self.bytes(original.identity, 32 * 1024 * 1024)? != original.bytes {
            return Err(refused(
                "preserving Debug original output publication changed",
            ));
        }
        Ok(original.reference.clone())
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
    ) -> Result<NodePreservingDebugRecord, NodeObservationServiceError> {
        let id = self
            .refs
            .read_ref(&operation_ref(execution)?)
            .map_err(refused)?
            .ok_or_else(|| refused("original preserving Debug record is absent"))?;
        self.read(id, execution)
    }

    pub(in crate::node_observed_executor::service) fn retention_roots(
        &self,
    ) -> Result<BTreeSet<ContentId>, NodeObservationServiceError> {
        let mut roots = BTreeSet::new();
        let namespace = RefName::new("node-preserving-debug-preparations").map_err(refused)?;
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
                        "preserving Debug retained namespace exceeds common original credit",
                    ));
                }
                let execution = entry
                    .name()
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| refused("preserving Debug original namespace differs"))?;
                let record = self.read(entry.target(), execution)?;
                roots.insert(entry.target());
                if let Some(outputs) = self
                    .refs
                    .read_ref(
                        &RefName::new(format!("node-preserving-debug-publications/{execution}"))
                            .map_err(refused)?,
                    )
                    .map_err(refused)?
                {
                    let bytes = self.bytes(outputs, 32 * 1024 * 1024)?;
                    if let NodePreservingDebugState::Resumed { publications, .. } = &record.outcome
                    {
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
    ) -> Result<NodePreservingDebugRecord, NodeObservationServiceError> {
        let bytes = self.bytes(id, MAX_RECORD_BYTES)?;
        let record: NodePreservingDebugRecord = serde_json::from_value(
            canonical::parse_json(&bytes, MAX_RECORD_BYTES).map_err(refused)?,
        )
        .map_err(refused)?;
        if record.format != "crucible.preserving-debug-record"
            || record.version != 1
            || record.execution != execution
            || encode(&record)? != bytes
        {
            return Err(refused(
                "preserving Debug original record identity or edition differs",
            ));
        }
        let source = self.bytes(
            ContentId::parse(&record.request).map_err(refused)?,
            MAX_REQUEST_BYTES,
        )?;
        let original = NodePreservingDebugRequest::from_json(&source)?;
        if original.execution != execution
            || encode(&original)? != source
            || !OriginalClaims::new(self.blobs.clone(), self.refs.clone())?.existing(
                execution,
                Route::DebugPreserving,
                &source,
            )?
        {
            return Err(refused(
                "preserving Debug original request identity differs",
            ));
        }
        if let Some(resume) = &record.resume_request {
            let source = self.bytes(ContentId::parse(resume).map_err(refused)?, 4096)?;
            let original: NodePreservingDebugResumeRequest =
                serde_json::from_value(canonical::parse_json(&source, 4096).map_err(refused)?)
                    .map_err(refused)?;
            original.validate()?;
            if original.execution != execution || encode(&original)? != source {
                return Err(refused("preserving Debug original resume identity differs"));
            }
        }
        Ok(record)
    }

    fn put_record(
        &self,
        record: &NodePreservingDebugRecord,
    ) -> Result<ContentId, NodeObservationServiceError> {
        let bytes = encode(record)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(refused("preserving Debug record byte credit exceeded"));
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
            return Err(refused(
                "preserving Debug original immutable bytes are not durable",
            ));
        }
        if self.bytes(id, bytes.len())? != bytes {
            return Err(refused("preserving Debug immutable bytes changed"));
        }
        Ok(())
    }

    pub(super) fn bytes(
        &self,
        id: ContentId,
        limit: usize,
    ) -> Result<Vec<u8>, NodeObservationServiceError> {
        let bytes = self
            .blobs
            .read(id, None)
            .map_err(refused)?
            .read_all(limit as u64)
            .map_err(refused)?;
        if identity(&bytes) != id {
            return Err(refused("preserving Debug immutable identity differs"));
        }
        Ok(bytes)
    }
}

fn identity(bytes: &[u8]) -> ContentId {
    ContentId::for_bytes(ObjectKind::Trace, 1, bytes)
}

fn operation_ref(execution: &str) -> Result<RefName, NodeObservationServiceError> {
    super::super::conditional_preparation::validate_execution(execution)?;
    RefName::new(format!("node-preserving-debug-preparations/{execution}")).map_err(refused)
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;
