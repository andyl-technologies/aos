//! Reserves exact original capability admission under durable finite CAS credit.
//!
//! The original request is recorded before queueing source authentication. A
//! Reserved receipt after restart is never a permission to dispatch again.

use super::{
    CapabilityPreparationRecord, CapabilityPreparationRequest, CapabilityPreparationState,
    NodeObservationServiceError, encode, refused, validate_execution,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName,
};
use crucible_node_contract::canonical;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

const MAXIMUM_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_RECORDS: usize = 4096;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordQuota {
    format: String,
    version: u32,
    consumed: usize,
}

#[derive(Clone)]
pub(crate) struct CapabilityPreparationLedger {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

pub(crate) struct CapabilityReservation {
    pub(crate) record: CapabilityPreparationRecord,
    pub(crate) original_dispatch: bool,
    identity: ContentId,
}

impl CapabilityPreparationLedger {
    pub(crate) fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        if !refs.capabilities().durable {
            return Err(refused(
                "capability preparation requires durable original refs",
            ));
        }

        Ok(Self { blobs, refs })
    }

    pub(crate) fn reserve(
        &self,
        request: &CapabilityPreparationRequest,
    ) -> Result<CapabilityReservation, NodeObservationServiceError> {
        request.validate()?;
        let bytes = encode(request)?;
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(refused(
                "capability original request exceeds finite byte credit",
            ));
        }
        let request_id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let reference = operation_ref(&request.execution)?;
        let claims = super::super::original_claim::OriginalClaims::new(
            self.blobs.clone(),
            self.refs.clone(),
        )?;
        let route = super::super::original_claim::Route::Capability;
        let publication = self.refs.acquire_publication_guard().map_err(refused)?;
        if let Some(identity) = self.refs.read_ref(&reference).map_err(refused)? {
            let record = self.read(identity, &request.execution)?;
            if record.request != request_id.encode() {
                return Err(refused(
                    "capability nonce already owns different original bytes",
                ));
            }
            // Legacy records already own their route. Checking a present claim
            // cannot mint another dispatch or require new lifetime credit.
            claims.existing(&request.execution, route, &bytes)?;
            return Ok(CapabilityReservation {
                record,
                identity,
                original_dispatch: false,
            });
        }
        if claims.existing(&request.execution, route, &bytes)? {
            return Err(refused(
                "original capability claim lacks its admission record; redispatch is forbidden",
            ));
        }

        // Existing per-route allowances remain preconditions for publishing
        // original request bytes. Contenders may consume credit but no loser
        // can acquire native dispatch from that consumption.
        self.reserve_credit()?;
        drop(publication);
        let claim = claims.reserve(&request.execution, route, &bytes)?;
        let _publication = self.refs.acquire_publication_guard().map_err(refused)?;
        if let Some(identity) = self.refs.read_ref(&reference).map_err(refused)? {
            let record = self.read(identity, &request.execution)?;
            if record.request != request_id.encode() {
                return Err(refused(
                    "capability nonce already owns different original bytes",
                ));
            }
            return Ok(CapabilityReservation {
                record,
                identity,
                original_dispatch: false,
            });
        }
        if claim != super::super::original_claim::Reservation::Original {
            return Err(refused(
                "original capability claim lacks its admission record; redispatch is forbidden",
            ));
        }
        self.put(request_id, bytes)?;
        let record = CapabilityPreparationRecord {
            format: "crucible.capability-preparation".into(),
            version: 1,
            execution: request.execution.clone(),
            request: request_id.encode(),
            outcome: CapabilityPreparationState::AwaitingAdmission {},
        };
        let identity = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(&reference, None, identity)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == identity => Ok(CapabilityReservation {
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
                        "capability nonce already owns different original bytes",
                    ));
                }
                Ok(CapabilityReservation {
                    record,
                    identity,
                    original_dispatch: false,
                })
            }
            _ => Err(refused(
                "capability preparation unique reservation requires reconciliation",
            )),
        }
    }

    pub(crate) fn owns(&self, execution: &str) -> Result<bool, NodeObservationServiceError> {
        validate_execution(execution)?;
        self.refs
            .read_ref(&operation_ref(execution)?)
            .map(|record| record.is_some())
            .map_err(refused)
    }

    pub(crate) fn state(
        &self,
        execution: &str,
    ) -> Result<CapabilityPreparationRecord, NodeObservationServiceError> {
        validate_execution(execution)?;
        let identity = self
            .refs
            .read_ref(&operation_ref(execution)?)
            .map_err(refused)?
            .ok_or_else(|| refused("original capability preparation is absent"))?;
        self.read(identity, execution)
    }

    pub(crate) fn complete(
        &self,
        reservation: &CapabilityReservation,
        outcome: CapabilityPreparationState,
    ) -> Result<CapabilityPreparationRecord, NodeObservationServiceError> {
        if !reservation.original_dispatch
            || !matches!(
                reservation.record.outcome,
                CapabilityPreparationState::AwaitingAdmission { .. }
            )
            || matches!(
                outcome,
                CapabilityPreparationState::AwaitingAdmission { .. }
            )
        {
            return Err(refused(
                "capability completion differs from original pending custody",
            ));
        }

        let record = CapabilityPreparationRecord {
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
                "original capability completion requires reconciliation",
            )),
        }
    }

    pub(crate) fn retention_roots(
        &self,
    ) -> Result<BTreeSet<ContentId>, NodeObservationServiceError> {
        let mut roots = self.inventory()?.0;
        roots.extend(
            super::super::original_claim::OriginalClaims::new(
                self.blobs.clone(),
                self.refs.clone(),
            )?
            .retention_roots()?,
        );
        Ok(roots)
    }

    fn reserve_credit(&self) -> Result<(), NodeObservationServiceError> {
        let quota_ref =
            RefName::new("node-capability-preparation-quota/records").map_err(refused)?;
        for _ in 0..64 {
            let current = self.refs.read_ref(&quota_ref).map_err(refused)?;
            let recorded = self.inventory()?.1;
            let consumed = match current {
                Some(id) => self.read_quota(id)?,
                None => recorded,
            };
            if consumed < recorded || consumed >= MAXIMUM_RECORDS {
                return Err(refused(
                    "capability preparation durable record credit unavailable",
                ));
            }
            let bytes = encode(&RecordQuota {
                format: "crucible.capability-preparation-quota".into(),
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
                        "capability preparation credit requires reconciliation",
                    ));
                }
            }
        }
        Err(refused(
            "capability preparation credit contention exceeds finite ceiling",
        ))
    }

    fn read_quota(&self, identity: ContentId) -> Result<usize, NodeObservationServiceError> {
        let bytes = self.read_bytes(identity, 1024)?;
        let quota: RecordQuota =
            serde_json::from_value(canonical::parse_json(&bytes, 1024).map_err(refused)?)
                .map_err(refused)?;
        if quota.format != "crucible.capability-preparation-quota"
            || quota.version != 1
            || quota.consumed > MAXIMUM_RECORDS
            || encode(&quota)? != bytes
        {
            return Err(refused("capability preparation quota edition differs"));
        }
        Ok(quota.consumed)
    }

    fn inventory(&self) -> Result<(BTreeSet<ContentId>, usize), NodeObservationServiceError> {
        let namespace = RefName::new("node-capability-preparations").map_err(refused)?;
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
                        "capability preparation retained record ceiling exceeded",
                    ));
                }
                let execution = entry
                    .name()
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| refused("capability preparation namespace differs"))?;
                let record = self.read(entry.target(), execution)?;
                roots.insert(entry.target());
                roots.insert(ContentId::parse(&record.request).map_err(refused)?);
            }
            after = page.next_after().cloned();
            if after.is_none() {
                let quota_ref =
                    RefName::new("node-capability-preparation-quota/records").map_err(refused)?;
                if let Some(quota) = self.refs.read_ref(&quota_ref).map_err(refused)? {
                    if self.read_quota(quota)? < count {
                        return Err(refused("capability quota omits original reservations"));
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
    ) -> Result<CapabilityPreparationRecord, NodeObservationServiceError> {
        let bytes = self.read_bytes(identity, MAXIMUM_RECORD_BYTES)?;
        let record = CapabilityPreparationRecord::from_canonical_bytes(&bytes)?;
        if record.execution != execution {
            return Err(refused("capability preparation original nonce differs"));
        }
        let request_id = ContentId::parse(&record.request).map_err(refused)?;
        let bytes = self.read_bytes(request_id, MAXIMUM_REQUEST_BYTES)?;
        let request: CapabilityPreparationRequest = serde_json::from_value(
            canonical::parse_json(&bytes, MAXIMUM_REQUEST_BYTES).map_err(refused)?,
        )
        .map_err(refused)?;
        request.validate()?;
        if request.execution != execution || encode(&request)? != bytes {
            return Err(refused(
                "capability preparation omitted exact original request",
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
            return Err(refused("capability original CAS bytes differ"));
        }
        Ok(bytes)
    }

    fn put_record(
        &self,
        record: &CapabilityPreparationRecord,
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
            return Err(refused("capability original reservation is not durable"));
        }
        Ok(())
    }
}

fn operation_ref(execution: &str) -> Result<RefName, NodeObservationServiceError> {
    validate_execution(execution)?;
    RefName::new(format!("node-capability-preparations/{execution}")).map_err(refused)
}
