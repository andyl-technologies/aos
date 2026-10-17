//! Reserves exact original root admission under durable finite CAS credit.
//!
//! The original request is recorded before queueing source authentication. A
//! Reserved receipt after restart is never a permission to dispatch again.

use super::{
    NodeObservationServiceError, RootPreparationRecord, RootPreparationRequest,
    RootPreparationState, encode, refused, validate_execution,
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
pub(crate) struct RootPreparationLedger {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

pub(crate) struct RootReservation {
    pub(crate) record: RootPreparationRecord,
    pub(crate) original_dispatch: bool,
    identity: ContentId,
}

impl RootPreparationLedger {
    pub(crate) fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        if !refs.capabilities().durable {
            return Err(refused("root preparation requires durable original refs"));
        }

        Ok(Self { blobs, refs })
    }

    pub(crate) fn reserve(
        &self,
        request: &RootPreparationRequest,
    ) -> Result<RootReservation, NodeObservationServiceError> {
        request.validate()?;
        let bytes = encode(request)?;
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(refused("root original request exceeds finite byte credit"));
        }
        let request_id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let reference = operation_ref(&request.execution)?;
        let claims = super::super::original_claim::OriginalClaims::new(
            self.blobs.clone(),
            self.refs.clone(),
        )?;
        let route = super::super::original_claim::Route::Root;
        let publication = self.refs.acquire_publication_guard().map_err(refused)?;
        if let Some(identity) = self.refs.read_ref(&reference).map_err(refused)? {
            let record = self.read(identity, &request.execution)?;
            if record.request != request_id.encode() {
                return Err(refused("root nonce already owns different original bytes"));
            }
            // Legacy records already own their route. Checking a present claim
            // cannot mint another dispatch or require new lifetime credit.
            claims.existing(&request.execution, route, &bytes)?;
            return Ok(RootReservation {
                record,
                identity,
                original_dispatch: false,
            });
        }
        if claims.existing(&request.execution, route, &bytes)? {
            return Err(refused(
                "original root claim lacks its admission record; redispatch is forbidden",
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
                return Err(refused("root nonce already owns different original bytes"));
            }
            return Ok(RootReservation {
                record,
                identity,
                original_dispatch: false,
            });
        }
        if claim != super::super::original_claim::Reservation::Original {
            return Err(refused(
                "original root claim lacks its admission record; redispatch is forbidden",
            ));
        }
        self.put(request_id, bytes)?;
        let record = RootPreparationRecord {
            format: "crucible.root-preparation".into(),
            version: 1,
            execution: request.execution.clone(),
            request: request_id.encode(),
            outcome: RootPreparationState::AwaitingAdmission {},
        };
        let identity = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(&reference, None, identity)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == identity => Ok(RootReservation {
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
                    return Err(refused("root nonce already owns different original bytes"));
                }
                Ok(RootReservation {
                    record,
                    identity,
                    original_dispatch: false,
                })
            }
            _ => Err(refused(
                "root preparation unique reservation requires reconciliation",
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
    ) -> Result<RootPreparationRecord, NodeObservationServiceError> {
        validate_execution(execution)?;
        let identity = self
            .refs
            .read_ref(&operation_ref(execution)?)
            .map_err(refused)?
            .ok_or_else(|| refused("original root preparation is absent"))?;
        self.read(identity, execution)
    }

    pub(super) fn diagnostic(
        &self,
        execution: &str,
    ) -> Result<super::RootPreparationDiagnostic, NodeObservationServiceError> {
        let original = self.state(execution)?;
        let identity = self
            .refs
            .read_ref(&diagnostic_ref(execution)?)
            .map_err(refused)?
            .ok_or_else(|| refused("Root original diagnostic is not published"))?;
        let value = super::RootPreparationDiagnostic::from_canonical_bytes(
            &self.read_bytes(identity, super::diagnostics::MAXIMUM_BYTES)?,
        )?;
        if value.execution != original.execution || value.request != original.request {
            return Err(refused("Root diagnostic original request differs"));
        }
        Ok(value)
    }

    pub(super) fn publish_diagnostic(
        &self,
        value: &super::RootPreparationDiagnostic,
        previous: Option<&super::RootPreparationDiagnostic>,
    ) -> Result<(), NodeObservationServiceError> {
        let original = self.state(&value.execution)?;
        if value.request != original.request {
            return Err(refused(
                "Root diagnostic cannot replace original request scope",
            ));
        }
        let valid_successor = match previous {
            Some(previous) => {
                previous.execution == value.execution
                    && previous.request == value.request
                    && previous.revision.checked_add(1) == Some(value.revision)
                    && (value.revision <= 64
                        || (previous.revision == 64
                            && previous.first_refusal.is_none()
                            && value.first_refusal.is_some()))
                    && previous
                        .first_refusal
                        .as_ref()
                        .is_none_or(|first| value.first_refusal.as_ref() == Some(first))
            }
            None => value.revision == 1,
        };
        if !valid_successor {
            return Err(refused(
                "Root diagnostic changed original sequence or first refusal",
            ));
        }
        let bytes = value.canonical_bytes()?;
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let prior = previous
            .map(|value| value.canonical_bytes())
            .transpose()?
            .map(|bytes| ContentId::for_bytes(ObjectKind::Trace, 1, &bytes));
        // The publication fence protects newly stored bytes through their ref
        // placement. It never encloses native preparation or reclamation.
        let _guard = self.refs.acquire_publication_guard().map_err(refused)?;
        self.put(identity, bytes)?;
        match self
            .refs
            .compare_exchange(&diagnostic_ref(&value.execution)?, prior, identity)
            .map_err(refused)?
        {
            RefCasOutcome::Advanced { next } if next == identity => Ok(()),
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == identity => Ok(()),
            _ => Err(refused(
                "Root diagnostic original writer requires reconciliation",
            )),
        }
    }

    pub(crate) fn complete(
        &self,
        reservation: &RootReservation,
        outcome: RootPreparationState,
    ) -> Result<RootPreparationRecord, NodeObservationServiceError> {
        if !reservation.original_dispatch
            || !matches!(
                reservation.record.outcome,
                RootPreparationState::AwaitingAdmission { .. }
            )
            || matches!(outcome, RootPreparationState::AwaitingAdmission { .. })
        {
            return Err(refused(
                "root completion differs from original pending custody",
            ));
        }

        let record = RootPreparationRecord {
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
            _ => Err(refused("original root completion requires reconciliation")),
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
        let quota_ref = RefName::new("node-root-preparation-quota/records").map_err(refused)?;
        for _ in 0..64 {
            let current = self.refs.read_ref(&quota_ref).map_err(refused)?;
            let recorded = self.inventory()?.1;
            let consumed = match current {
                Some(id) => self.read_quota(id)?,
                None => recorded,
            };
            if consumed < recorded || consumed >= MAXIMUM_RECORDS {
                return Err(refused(
                    "root preparation durable record credit unavailable",
                ));
            }
            let bytes = encode(&RecordQuota {
                format: "crucible.root-preparation-quota".into(),
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
                    return Err(refused("root preparation credit requires reconciliation"));
                }
            }
        }
        Err(refused(
            "root preparation credit contention exceeds finite ceiling",
        ))
    }

    fn read_quota(&self, identity: ContentId) -> Result<usize, NodeObservationServiceError> {
        let bytes = self.read_bytes(identity, 1024)?;
        let quota: RecordQuota =
            serde_json::from_value(canonical::parse_json(&bytes, 1024).map_err(refused)?)
                .map_err(refused)?;
        if quota.format != "crucible.root-preparation-quota"
            || quota.version != 1
            || quota.consumed > MAXIMUM_RECORDS
            || encode(&quota)? != bytes
        {
            return Err(refused("root preparation quota edition differs"));
        }
        Ok(quota.consumed)
    }

    fn inventory(&self) -> Result<(BTreeSet<ContentId>, usize), NodeObservationServiceError> {
        let namespace = RefName::new("node-root-preparations").map_err(refused)?;
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
                    return Err(refused("root preparation retained record ceiling exceeded"));
                }
                let execution = entry
                    .name()
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| refused("root preparation namespace differs"))?;
                let record = self.read(entry.target(), execution)?;
                roots.insert(entry.target());
                roots.insert(ContentId::parse(&record.request).map_err(refused)?);
                if let Some(identity) = self
                    .refs
                    .read_ref(&diagnostic_ref(execution)?)
                    .map_err(refused)?
                {
                    self.diagnostic(execution)?;
                    roots.insert(identity);
                }
            }
            after = page.next_after().cloned();
            if after.is_none() {
                let quota_ref =
                    RefName::new("node-root-preparation-quota/records").map_err(refused)?;
                if let Some(quota) = self.refs.read_ref(&quota_ref).map_err(refused)? {
                    if self.read_quota(quota)? < count {
                        return Err(refused("root quota omits original reservations"));
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
    ) -> Result<RootPreparationRecord, NodeObservationServiceError> {
        let bytes = self.read_bytes(identity, MAXIMUM_RECORD_BYTES)?;
        let record = RootPreparationRecord::from_canonical_bytes(&bytes)?;
        if record.execution != execution {
            return Err(refused("root preparation original nonce differs"));
        }
        let request_id = ContentId::parse(&record.request).map_err(refused)?;
        let bytes = self.read_bytes(request_id, MAXIMUM_REQUEST_BYTES)?;
        let request: RootPreparationRequest = serde_json::from_value(
            canonical::parse_json(&bytes, MAXIMUM_REQUEST_BYTES).map_err(refused)?,
        )
        .map_err(refused)?;
        request.validate()?;
        if request.execution != execution || encode(&request)? != bytes {
            return Err(refused("root preparation omitted exact original request"));
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
            return Err(refused("root original CAS bytes differ"));
        }
        Ok(bytes)
    }

    fn put_record(
        &self,
        record: &RootPreparationRecord,
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
            return Err(refused("root original reservation is not durable"));
        }
        Ok(())
    }
}

fn operation_ref(execution: &str) -> Result<RefName, NodeObservationServiceError> {
    validate_execution(execution)?;
    RefName::new(format!("node-root-preparations/{execution}")).map_err(refused)
}

fn diagnostic_ref(execution: &str) -> Result<RefName, NodeObservationServiceError> {
    validate_execution(execution)?;
    RefName::new(format!("node-root-diagnostics/{execution}")).map_err(refused)
}
