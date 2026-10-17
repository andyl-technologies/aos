//! Durably reserves one original native-world request before actor admission.
//!
//! ```text
//! node-native-operations/<nonce32hex> -> Trace.1(record)
//! record.request -> Trace.1(canonical original NativeWorldRequest)
//! node-native-quota/records -> Trace.1(canonical consumed-slot counter)
//! ```
//!
//! A reserved nonce stays reserved after process death. Neither restart nor a
//! repeated exact request can issue a second original native dispatch.

use std::{collections::BTreeSet, sync::Arc};

use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName,
};
use crucible_node_contract::{Validate, canonical};
use serde::{Deserialize, Serialize};

use super::super::{NodeObservedError, refused};
use super::control::{
    NativeWorldOutcome, NativeWorldRecord, NativeWorldRequest, validate_execution,
};

const MAXIMUM_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_REQUEST_BYTES: usize = 64 * 1024;
const MAXIMUM_RECORDS: usize = 4096;
const MAXIMUM_QUOTA_BYTES: usize = 1024;
const MAXIMUM_QUOTA_CONTENTION: usize = 64;

/// Accounts for consumed durable record credits across every publisher instance.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordQuota {
    format: String,
    version: u32,
    consumed: u32,
}

#[derive(Clone)]
pub(super) struct NativeWorldLedger {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

pub(super) struct NativeReservation {
    pub(super) record: NativeWorldRecord,
    identity: ContentId,
    pub(super) original_dispatch: bool,
}

impl NativeWorldLedger {
    pub(super) fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservedError> {
        if !refs.capabilities().durable {
            return Err(refused(
                "native-world reservation requires durable mutable refs",
            ));
        }
        Ok(Self { blobs, refs })
    }

    pub(super) fn reserve(
        &self,
        request: &NativeWorldRequest,
    ) -> Result<NativeReservation, NodeObservedError> {
        request.validate()?;
        if matches!(request, NativeWorldRequest::Status { .. }) {
            return Err(refused("native-world status cannot reserve native work"));
        }
        let bytes = encode(request)?;
        if bytes.len() > MAXIMUM_REQUEST_BYTES {
            return Err(refused("native-world request exceeds its finite ceiling"));
        }
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let reference = operation_ref(request.execution())?;
        let _guard = self.refs.acquire_publication_guard().map_err(error)?;
        if let Some(record_identity) = self.refs.read_ref(&reference).map_err(error)? {
            let record = self.read(record_identity, request.execution())?;
            if record.request != identity.encode() {
                return Err(refused(
                    "native-world nonce belongs to another original request",
                ));
            }
            return Ok(NativeReservation {
                record,
                identity: record_identity,
                original_dispatch: false,
            });
        }
        self.reserve_record_credit()?;
        self.put(identity, bytes)?;
        let record = NativeWorldRecord {
            format: "crucible.native-world-operation".into(),
            version: 1,
            execution: request.execution().to_owned(),
            request: identity.encode(),
            state: NativeWorldOutcome::Reserved {},
        };
        let record_identity = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(&reference, None, record_identity)
            .map_err(error)?
        {
            RefCasOutcome::Advanced { next } if next == record_identity => Ok(NativeReservation {
                record,
                identity: record_identity,
                original_dispatch: true,
            }),
            _ => Err(refused(
                "native-world reservation did not establish unique original custody",
            )),
        }
    }

    pub(super) fn state(&self, execution: &str) -> Result<NativeWorldRecord, NodeObservedError> {
        let identity = self
            .refs
            .read_ref(&operation_ref(execution)?)
            .map_err(error)?
            .ok_or_else(|| refused("original native-world operation is absent"))?;
        self.read(identity, execution)
    }

    pub(super) fn complete(
        &self,
        reservation: &NativeReservation,
        state: NativeWorldOutcome,
    ) -> Result<NativeWorldRecord, NodeObservedError> {
        if !reservation.original_dispatch
            || !matches!(
                reservation.record.state,
                NativeWorldOutcome::Reserved { .. }
            )
            || matches!(state, NativeWorldOutcome::Reserved { .. })
        {
            return Err(refused(
                "native-world completion differs from original reservation",
            ));
        }
        let record = NativeWorldRecord {
            state,
            ..reservation.record.clone()
        };
        let _guard = self.refs.acquire_publication_guard().map_err(error)?;
        let identity = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(
                &operation_ref(&record.execution)?,
                Some(reservation.identity),
                identity,
            )
            .map_err(error)?
        {
            RefCasOutcome::Advanced { next } if next == identity => Ok(record),
            RefCasOutcome::Conflict {
                current: Some(current),
                ..
            } if current == identity => self.read(identity, &record.execution),
            _ => Err(refused(
                "original native-world completion requires reconciliation",
            )),
        }
    }

    pub(super) fn retention_roots(&self) -> Result<BTreeSet<ContentId>, NodeObservedError> {
        self.inventory().map(|(roots, _)| roots)
    }

    fn reserve_record_credit(&self) -> Result<(), NodeObservedError> {
        let reference = record_quota_ref()?;
        for _ in 0..MAXIMUM_QUOTA_CONTENTION {
            let current = self.refs.read_ref(&reference).map_err(error)?;
            let recorded = self.inventory()?.1;
            let consumed = match current {
                Some(identity) => self.read_quota(identity)?,
                // Old records remain readable. The first new publisher accounts
                // for their complete inventory before atomically creating the
                // shared counter; concurrent initializers must win this same CAS.
                None => recorded,
            };
            if consumed < recorded {
                if self.refs.read_ref(&reference).map_err(error)? != current {
                    continue;
                }
                return Err(refused(
                    "native-world record quota omits original reservations",
                ));
            }
            if consumed >= MAXIMUM_RECORDS {
                return Err(refused("persistent native-world record capacity exhausted"));
            }
            let bytes = encode(&RecordQuota {
                format: "crucible.native-world-record-quota".into(),
                version: 1,
                consumed: u32::try_from(consumed + 1).map_err(error)?,
            })?;
            let next = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
            self.put(next, bytes)?;
            match self
                .refs
                .compare_exchange(&reference, current, next)
                .map_err(error)?
            {
                RefCasOutcome::Advanced { next: actual } if actual == next => return Ok(()),
                RefCasOutcome::Conflict { .. } => continue,
                _ => {
                    return Err(refused(
                        "native-world record credit requires reconciliation",
                    ));
                }
            }
        }
        Err(refused(
            "native-world record credit contention exceeds its finite ceiling",
        ))
    }

    fn read_quota(&self, identity: ContentId) -> Result<usize, NodeObservedError> {
        let bytes = self.read_bytes(identity, MAXIMUM_QUOTA_BYTES)?;
        let quota: RecordQuota =
            serde_json::from_value(canonical::parse_json(&bytes, MAXIMUM_QUOTA_BYTES)?)
                .map_err(error)?;
        let consumed = usize::try_from(quota.consumed).map_err(error)?;
        if quota.format != "crucible.native-world-record-quota"
            || quota.version != 1
            || consumed > MAXIMUM_RECORDS
            || encode(&quota)? != bytes
        {
            return Err(refused(
                "native-world record quota is not an original canonical budget",
            ));
        }
        Ok(consumed)
    }

    fn inventory(&self) -> Result<(BTreeSet<ContentId>, usize), NodeObservedError> {
        let namespace = RefName::new("node-native-operations").map_err(error)?;
        let mut after = None;
        let mut roots = BTreeSet::new();
        let mut count = 0;
        loop {
            let page = self
                .refs
                .scan_refs(&namespace, after.as_ref(), 64)
                .map_err(error)?;
            for entry in page.entries() {
                count += 1;
                if count > MAXIMUM_RECORDS {
                    return Err(refused("persistent native-world record capacity exhausted"));
                }
                let execution = entry
                    .name()
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| refused("native-world operation namespace differs"))?;
                let record = self.read(entry.target(), execution)?;
                roots.insert(entry.target());
                roots.insert(ContentId::parse(&record.request).map_err(error)?);
                if let Some(evidence) = self
                    .refs
                    .read_ref(&evidence_ref(execution)?)
                    .map_err(error)?
                {
                    self.read_bytes(evidence, 24 * 1024 * 1024)?;
                    roots.insert(evidence);
                }
                let activation = self
                    .refs
                    .read_ref(&activation_ref(execution)?)
                    .map_err(error)?;
                if let Some(activation) = activation {
                    roots.insert(activation);
                } else if matches!(record.state, NativeWorldOutcome::Completed { .. }) {
                    return Err(refused(
                        "completed native world lacks original activation custody",
                    ));
                }
            }
            after = page.next_after().cloned();
            if after.is_none() {
                if let Some(quota) = self.refs.read_ref(&record_quota_ref()?).map_err(error)? {
                    if self.read_quota(quota)? < count {
                        return Err(refused(
                            "native-world record quota omits original reservations",
                        ));
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
    ) -> Result<NativeWorldRecord, NodeObservedError> {
        let bytes = self.read_bytes(identity, MAXIMUM_RECORD_BYTES)?;
        let record: NativeWorldRecord =
            serde_json::from_value(canonical::parse_json(&bytes, MAXIMUM_RECORD_BYTES)?)
                .map_err(error)?;
        validate_record(&record)?;
        if record.execution != execution || encode(&record)? != bytes {
            return Err(refused(
                "native-world record scope or canonical spelling differs",
            ));
        }
        let request_identity = ContentId::parse(&record.request).map_err(error)?;
        if let NativeWorldOutcome::Completed {
            completion_evidence: Some(evidence),
            ..
        } = &record.state
        {
            let expected = ContentId::parse(evidence).map_err(error)?;
            if self
                .refs
                .read_ref(&evidence_ref(execution)?)
                .map_err(error)?
                != Some(expected)
            {
                return Err(refused(
                    "completed native world omits its original receipt custody root",
                ));
            }
            self.read_bytes(expected, 24 * 1024 * 1024)?;
        }
        let request_bytes = self.read_bytes(request_identity, MAXIMUM_REQUEST_BYTES)?;
        let request: NativeWorldRequest = serde_json::from_value(canonical::parse_json(
            &request_bytes,
            MAXIMUM_REQUEST_BYTES,
        )?)
        .map_err(error)?;
        request.validate()?;
        if request.execution() != execution
            || encode(&request)? != request_bytes
            || matches!(request, NativeWorldRequest::Status { .. })
        {
            return Err(refused(
                "native-world record omits its exact original request",
            ));
        }
        Ok(record)
    }

    fn read_bytes(
        &self,
        identity: ContentId,
        maximum: usize,
    ) -> Result<Vec<u8>, NodeObservedError> {
        let bytes = self
            .blobs
            .read(identity, None)
            .and_then(|handle| handle.read_all(maximum as u64))
            .map_err(error)?;
        if ContentId::for_bytes(ObjectKind::Trace, 1, &bytes) != identity {
            return Err(refused("native-world original CAS bytes differ"));
        }
        Ok(bytes)
    }

    fn put_record(&self, record: &NativeWorldRecord) -> Result<ContentId, NodeObservedError> {
        validate_record(record)?;
        let bytes = encode(record)?;
        if bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(refused("native-world result exceeds its finite ceiling"));
        }
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        self.put(identity, bytes)?;
        Ok(identity)
    }

    fn put(&self, identity: ContentId, bytes: Vec<u8>) -> Result<(), NodeObservedError> {
        let receipt = self
            .blobs
            .put_if_absent(identity, &BlobHandle::from_bytes(bytes))
            .map_err(error)?;
        if !receipt.is_durable() {
            return Err(refused(
                "native-world original content was not durably retained",
            ));
        }
        Ok(())
    }
}

pub(super) fn record_quota_ref() -> Result<RefName, NodeObservedError> {
    RefName::new("node-native-quota/records").map_err(error)
}

pub(super) fn validate_record(record: &NativeWorldRecord) -> Result<(), NodeObservedError> {
    validate_execution(&record.execution)?;
    let request = ContentId::parse(&record.request).map_err(error)?;
    if record.format != "crucible.native-world-operation"
        || record.version != 1
        || request.encode() != record.request
        || request.kind() != ObjectKind::Trace
        || request.schema_version() != 1
    {
        return Err(refused("unsupported original native-world record edition"));
    }
    match &record.state {
        NativeWorldOutcome::Completed {
            artifact,
            manifest,
            completion_evidence,
            ..
        } => {
            artifact.validate()?;
            manifest.validate()?;
            if canonical::content_ref(&encode(manifest)?, "application/json")? != *artifact {
                return Err(refused(
                    "native-world archive differs from its original manifest",
                ));
            }
            if let Some(evidence) = completion_evidence {
                let identity = ContentId::parse(evidence).map_err(error)?;
                if identity.encode() != *evidence
                    || identity.kind() != ObjectKind::Trace
                    || identity.schema_version() != 1
                {
                    return Err(refused(
                        "original native completion evidence has an unsupported identity",
                    ));
                }
            }
        }
        NativeWorldOutcome::Unknown { reason } if reason.len() > 4096 => {
            return Err(refused(
                "native-world uncertainty exceeds its finite ceiling",
            ));
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn activation_ref(execution: &str) -> Result<RefName, NodeObservedError> {
    validate_execution(execution)?;
    RefName::new(format!("node-world-activations/native-{execution}")).map_err(error)
}

pub(super) fn evidence_ref(execution: &str) -> Result<RefName, NodeObservedError> {
    validate_execution(execution)?;
    RefName::new(format!("node-native-evidence/{execution}")).map_err(error)
}

fn operation_ref(execution: &str) -> Result<RefName, NodeObservedError> {
    validate_execution(execution)?;
    RefName::new(format!("node-native-operations/{execution}")).map_err(error)
}

fn encode(value: &impl serde::Serialize) -> Result<Vec<u8>, NodeObservedError> {
    canonical::canonical_json(&serde_json::to_value(value).map_err(error)?).map_err(error)
}

fn error(error: impl std::fmt::Display) -> NodeObservedError {
    refused(&error.to_string())
}
