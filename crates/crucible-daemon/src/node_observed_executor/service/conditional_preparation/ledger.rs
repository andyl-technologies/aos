//! Reserves exact original conditional admission under durable finite CAS credit.
//!
//! The original request is recorded before queueing source authentication. A
//! Reserved receipt after restart is never a permission to dispatch again.

use super::{
    ConditionalPreparationRecord, ConditionalPreparationRequest, ConditionalPreparationState,
    NodeObservationServiceError, encode, refused, validate_execution,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName,
};
use crucible_node_contract::canonical;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

const MAXIMUM_REQUEST_BYTES: usize = 64 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 1024 * 1024;
const MAXIMUM_RECORDS: usize = 4096;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordQuota {
    format: String,
    version: u32,
    consumed: usize,
}

#[derive(Clone)]
pub(crate) struct ConditionalPreparationLedger {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

pub(crate) struct PreparationReservation {
    pub(crate) record: ConditionalPreparationRecord,
    pub(crate) original_dispatch: bool,
    identity: ContentId,
}

impl ConditionalPreparationLedger {
    pub(crate) fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        if !refs.capabilities().durable {
            return Err(refused(
                "conditional preparation requires durable original refs",
            ));
        }
        Ok(Self { blobs, refs })
    }

    pub(crate) fn reserve(
        &self,
        request: &ConditionalPreparationRequest,
    ) -> Result<PreparationReservation, NodeObservationServiceError> {
        request.validate()?;
        let bytes = encode(request)?;
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(refused(
                "conditional original request exceeds finite byte credit",
            ));
        }
        let request_id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let reference = operation_ref(&request.execution)?;
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        if let Some(identity) = self.refs.read_ref(&reference).map_err(refused)? {
            let record = self.read(identity, &request.execution)?;
            if record.request != request_id.encode() {
                return Err(refused(
                    "conditional nonce already owns different original bytes",
                ));
            }
            return Ok(PreparationReservation {
                record,
                identity,
                original_dispatch: false,
            });
        }
        self.reserve_credit()?;
        self.put(request_id, bytes)?;
        let record = ConditionalPreparationRecord {
            format: "crucible.conditional-preparation".into(),
            version: 1,
            execution: request.execution.clone(),
            request: request_id.encode(),
            outcome: ConditionalPreparationState::AwaitingAdmission {},
        };
        let identity = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(&reference, None, identity)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == identity => Ok(PreparationReservation {
                record,
                identity,
                original_dispatch: true,
            }),
            RefCasOutcome::Conflict {
                current: Some(identity),
                ..
            } => {
                let record = self.read(identity, &request.execution)?;
                if record.request != request_id.encode() {
                    return Err(refused(
                        "conditional nonce already owns different original bytes",
                    ));
                }
                Ok(PreparationReservation {
                    record,
                    identity,
                    original_dispatch: false,
                })
            }
            _ => Err(refused(
                "conditional preparation unique reservation requires reconciliation",
            )),
        }
    }

    pub(crate) fn state(
        &self,
        execution: &str,
    ) -> Result<ConditionalPreparationRecord, NodeObservationServiceError> {
        validate_execution(execution)?;
        let identity = self
            .refs
            .read_ref(&operation_ref(execution)?)
            .map_err(refused)?
            .ok_or_else(|| refused("original conditional preparation is absent"))?;
        self.read(identity, execution)
    }

    pub(crate) fn complete(
        &self,
        reservation: &PreparationReservation,
        outcome: ConditionalPreparationState,
    ) -> Result<ConditionalPreparationRecord, NodeObservationServiceError> {
        if !reservation.original_dispatch
            || !matches!(
                reservation.record.outcome,
                ConditionalPreparationState::AwaitingAdmission { .. }
            )
            || matches!(
                outcome,
                ConditionalPreparationState::AwaitingAdmission { .. }
            )
        {
            return Err(refused(
                "conditional completion differs from original pending custody",
            ));
        }
        let record = ConditionalPreparationRecord {
            outcome,
            ..reservation.record.clone()
        };
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        let identity = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(
                &operation_ref(&record.execution)?,
                Some(reservation.identity),
                identity,
            )
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == identity => Ok(record),
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == identity => self.read(identity, &record.execution),
            _ => Err(refused(
                "original conditional completion requires reconciliation",
            )),
        }
    }

    pub(crate) fn retention_roots(
        &self,
    ) -> Result<BTreeSet<ContentId>, NodeObservationServiceError> {
        self.inventory().map(|(roots, _)| roots)
    }

    fn reserve_credit(&self) -> Result<(), NodeObservationServiceError> {
        let quota_ref =
            RefName::new("node-conditional-preparation-quota/records").map_err(refused)?;
        for _ in 0..64 {
            let current = self.refs.read_ref(&quota_ref).map_err(refused)?;
            let recorded = self.inventory()?.1;
            let consumed = match current {
                Some(id) => self.read_quota(id)?,
                None => recorded,
            };
            if consumed < recorded || consumed >= MAXIMUM_RECORDS {
                return Err(refused(
                    "conditional preparation durable record credit unavailable",
                ));
            }
            let bytes = encode(&RecordQuota {
                format: "crucible.conditional-preparation-quota".into(),
                version: 1,
                consumed: consumed + 1,
            })?;
            let next = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
            self.put(next, bytes)?;
            match self
                .refs
                .compare_exchange(&quota_ref, current, next)
                .map_err(refused)?
            {
                RefCasOutcome::Advanced { next: actual } if actual == next => return Ok(()),
                RefCasOutcome::Conflict { .. } => continue,
                _ => {
                    return Err(refused(
                        "conditional preparation credit requires reconciliation",
                    ));
                }
            }
        }
        Err(refused(
            "conditional preparation credit contention exceeds finite ceiling",
        ))
    }

    fn read_quota(&self, identity: ContentId) -> Result<usize, NodeObservationServiceError> {
        let bytes = self.read_bytes(identity, 1024)?;
        let quota: RecordQuota =
            serde_json::from_value(canonical::parse_json(&bytes, 1024).map_err(refused)?)
                .map_err(refused)?;
        if quota.format != "crucible.conditional-preparation-quota"
            || quota.version != 1
            || quota.consumed > MAXIMUM_RECORDS
            || encode(&quota)? != bytes
        {
            return Err(refused("conditional preparation quota edition differs"));
        }
        Ok(quota.consumed)
    }

    fn inventory(&self) -> Result<(BTreeSet<ContentId>, usize), NodeObservationServiceError> {
        let namespace = RefName::new("node-conditional-preparations").map_err(refused)?;
        let mut after = None;
        let mut roots = BTreeSet::new();
        let mut count = 0;
        loop {
            let page = self
                .refs
                .scan_refs(&namespace, after.as_ref(), 64)
                .map_err(refused)?;
            for entry in page.entries() {
                count += 1;
                if count > MAXIMUM_RECORDS {
                    return Err(refused(
                        "conditional preparation retained record ceiling exceeded",
                    ));
                }
                let execution = entry
                    .name()
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| refused("conditional preparation namespace differs"))?;
                let record = self.read(entry.target(), execution)?;
                roots.insert(entry.target());
                roots.insert(ContentId::parse(&record.request).map_err(refused)?);
            }
            after = page.next_after().cloned();
            if after.is_none() {
                let quota_ref =
                    RefName::new("node-conditional-preparation-quota/records").map_err(refused)?;
                if let Some(quota) = self.refs.read_ref(&quota_ref).map_err(refused)? {
                    if self.read_quota(quota)? < count {
                        return Err(refused("conditional quota omits original reservations"));
                    }
                    roots.insert(quota);
                }
                return Ok((roots, count));
            }
        }
    }

    fn read(
        &self,
        identity: ContentId,
        execution: &str,
    ) -> Result<ConditionalPreparationRecord, NodeObservationServiceError> {
        let bytes = self.read_bytes(identity, MAXIMUM_RECORD_BYTES)?;
        let record = ConditionalPreparationRecord::from_canonical_bytes(&bytes)?;
        if record.execution != execution {
            return Err(refused("conditional preparation original nonce differs"));
        }
        let request_id = ContentId::parse(&record.request).map_err(refused)?;
        let bytes = self.read_bytes(request_id, MAXIMUM_REQUEST_BYTES)?;
        let request: ConditionalPreparationRequest = serde_json::from_value(
            canonical::parse_json(&bytes, MAXIMUM_REQUEST_BYTES).map_err(refused)?,
        )
        .map_err(refused)?;
        request.validate()?;
        if request.execution != execution || encode(&request)? != bytes {
            return Err(refused(
                "conditional preparation omitted exact original request",
            ));
        }
        Ok(record)
    }

    fn read_bytes(
        &self,
        identity: ContentId,
        maximum: usize,
    ) -> Result<Vec<u8>, NodeObservationServiceError> {
        let bytes = self
            .blobs
            .read(identity, None)
            .and_then(|body| body.read_all(maximum as u64))
            .map_err(refused)?;
        if ContentId::for_bytes(ObjectKind::Trace, 1, &bytes) != identity {
            return Err(refused("conditional original CAS bytes differ"));
        }
        Ok(bytes)
    }

    fn put_record(
        &self,
        record: &ConditionalPreparationRecord,
    ) -> Result<ContentId, NodeObservationServiceError> {
        let bytes = record.canonical_bytes()?;
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        self.put(identity, bytes)?;
        Ok(identity)
    }

    fn put(&self, identity: ContentId, bytes: Vec<u8>) -> Result<(), NodeObservationServiceError> {
        if !self
            .blobs
            .put_if_absent(identity, &BlobHandle::from_bytes(bytes))
            .map_err(refused)?
            .is_durable()
        {
            return Err(refused("conditional original reservation is not durable"));
        }
        Ok(())
    }
}

fn operation_ref(execution: &str) -> Result<RefName, NodeObservationServiceError> {
    validate_execution(execution)?;
    RefName::new(format!("node-conditional-preparations/{execution}")).map_err(refused)
}
