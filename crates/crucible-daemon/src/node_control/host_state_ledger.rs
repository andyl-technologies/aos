//! Durable original state-operation commitments and GC-visible request roots.

#[cfg(test)]
#[path = "host_state_tests.rs"]
mod tests;

use std::{collections::BTreeSet, sync::Arc};

use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName,
};
use crucible_node_contract::canonical;
use serde::{Deserialize, Serialize};

use super::{
    NodeControlError, execution_id,
    host_state::{
        NodeHostStateOutcome, NodeHostStateRecord, NodeHostStateRequest, activation_reference,
    },
    refused,
};

const MAXIMUM_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_OPERATION_RECORDS: usize = 4096;
const MAXIMUM_QUOTA_BYTES: usize = 1024;
const MAXIMUM_QUOTA_CONTENTION: usize = 64;

/// Retains consumed namespace-wide admission credits, including uncertain attempts.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordQuota {
    format: String,
    version: u32,
    consumed: u32,
}

#[derive(Clone)]
pub(super) struct HostStateLedger {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

pub(super) struct StateReservation {
    pub record: NodeHostStateRecord,
    pub identity: ContentId,
    pub original_dispatch: bool,
}

impl HostStateLedger {
    pub(super) fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeControlError> {
        if !refs.capabilities().durable {
            return Err(refused("exact state custody requires durable mutable refs"));
        }
        Ok(Self { blobs, refs })
    }

    pub(super) fn reserve(
        &self,
        request: &NodeHostStateRequest,
    ) -> Result<StateReservation, NodeControlError> {
        request.validate()?;
        if is_status(request) {
            return Err(refused("read-only state status cannot reserve native work"));
        }
        let bytes = canonical::canonical_json(
            &serde_json::to_value(request).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        let request_identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let reference = operation_ref(request.execution())?;
        let _publication = self.refs.acquire_publication_guard().map_err(refused)?;
        if let Some(identity) = self.refs.read_ref(&reference).map_err(refused)? {
            let record = self.read(identity, request.execution())?;
            if record.request != request_identity
                || self
                    .blobs
                    .read(record.request, None)
                    .and_then(|handle| handle.read_all(super::MAX_NODE_CONTROL_BYTES as u64))
                    .map_err(refused)?
                    != bytes
            {
                return Err(refused(
                    "state nonce belongs to a different original request",
                ));
            }
            return Ok(StateReservation {
                record,
                identity,
                original_dispatch: false,
            });
        }

        // The publication guard excludes GC, not concurrent publishers. A
        // shared durable CAS therefore owns each credit before any new record.
        // Uncertain or competing reservations never return their credit.
        self.reserve_record_credit()?;
        self.put(request_identity, bytes)?;
        let record = NodeHostStateRecord {
            format: "crucible.node-state-operation".into(),
            version: if matches!(request, NodeHostStateRequest::Terminal { .. }) {
                2
            } else {
                1
            },
            execution: request.execution().to_owned(),
            request: request_identity,
            state: NodeHostStateOutcome::Reserved {},
        };
        let identity = self.put_record(&record)?;
        match self.refs.compare_exchange(&reference, None, identity) {
            Ok(RefCasOutcome::Advanced { next }) if next == identity => Ok(StateReservation {
                record,
                identity,
                original_dispatch: true,
            }),
            // An ambiguous or competing durable commitment grants no dispatch.
            _ => Err(refused(
                "original state reservation did not establish unique custody",
            )),
        }
    }

    pub(super) fn state(&self, execution: &str) -> Result<NodeHostStateRecord, NodeControlError> {
        let reference = operation_ref(execution)?;
        let identity = self
            .refs
            .read_ref(&reference)
            .map_err(refused)?
            .ok_or_else(|| refused("original state operation is absent"))?;
        self.read(identity, execution)
    }

    pub(super) fn complete(
        &self,
        reservation: &StateReservation,
        outcome: NodeHostStateOutcome,
    ) -> Result<NodeHostStateRecord, NodeControlError> {
        if !reservation.original_dispatch
            || !matches!(
                reservation.record.state,
                NodeHostStateOutcome::Reserved { .. }
            )
            || matches!(outcome, NodeHostStateOutcome::Reserved { .. })
        {
            return Err(refused(
                "state publication differs from original reservation",
            ));
        }
        let record = NodeHostStateRecord {
            state: outcome,
            ..reservation.record.clone()
        };
        let reference = operation_ref(&record.execution)?;
        let _publication = self.refs.acquire_publication_guard().map_err(refused)?;
        let identity = self.put_record(&record)?;
        match self
            .refs
            .compare_exchange(&reference, Some(reservation.identity), identity)
        {
            Ok(RefCasOutcome::Advanced { next }) if next == identity => Ok(record),
            Ok(RefCasOutcome::Conflict {
                current: Some(current),
                ..
            }) if current == identity => self.read(identity, &record.execution),
            _ => Err(refused("original state completion requires reconciliation")),
        }
    }

    pub(super) fn retention_roots(&self) -> Result<BTreeSet<ContentId>, NodeControlError> {
        let (mut roots, recorded) = self.inventory()?;
        if let Some(identity) = self.refs.read_ref(&record_quota_ref()?).map_err(refused)? {
            if self.read_quota(identity)? < recorded {
                return Err(refused("host-state quota omits original reservations"));
            }
            roots.insert(identity);
        }
        Ok(roots)
    }

    fn reserve_record_credit(&self) -> Result<(), NodeControlError> {
        let reference = record_quota_ref()?;
        for _ in 0..MAXIMUM_QUOTA_CONTENTION {
            let current = self.refs.read_ref(&reference).map_err(refused)?;
            let recorded = self.inventory()?.1;
            let consumed = match current {
                Some(identity) => self.read_quota(identity)?,
                // Migrating existing records does not alter their bytes. Every
                // first publisher competes for this same initialization CAS.
                None => recorded,
            };
            if consumed < recorded {
                if self.refs.read_ref(&reference).map_err(refused)? != current {
                    continue;
                }
                return Err(refused("host-state quota omits original reservations"));
            }
            if consumed >= MAXIMUM_OPERATION_RECORDS {
                return Err(refused(
                    "persistent host-state operation capacity exhausted",
                ));
            }
            let quota = RecordQuota {
                format: "crucible.host-state-record-quota".into(),
                version: 1,
                consumed: u32::try_from(consumed + 1).map_err(refused)?,
            };
            let bytes = canonical::canonical_json(
                &serde_json::to_value(&quota)
                    .map_err(crucible_node_contract::ContractError::from)?,
            )?;
            let next = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
            self.put(next, bytes)?;
            match self
                .refs
                .compare_exchange(&reference, current, next)
                .map_err(refused)?
            {
                RefCasOutcome::Advanced { next: actual } if actual == next => return Ok(()),
                RefCasOutcome::Conflict { .. } => continue,
                _ => return Err(refused("host-state record credit requires reconciliation")),
            }
        }
        Err(refused(
            "host-state record credit contention exceeds its finite ceiling",
        ))
    }

    fn read_quota(&self, identity: ContentId) -> Result<usize, NodeControlError> {
        let bytes = self
            .blobs
            .read(identity, None)
            .and_then(|handle| handle.read_all(MAXIMUM_QUOTA_BYTES as u64))
            .map_err(refused)?;
        if ContentId::for_bytes(ObjectKind::Trace, 1, &bytes) != identity {
            return Err(refused("host-state quota identity is corrupt"));
        }
        let value = canonical::parse_json(&bytes, MAXIMUM_QUOTA_BYTES)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused("host-state quota is not canonical"));
        }
        let quota: RecordQuota =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        let consumed = usize::try_from(quota.consumed).map_err(refused)?;
        if quota.format != "crucible.host-state-record-quota"
            || quota.version != 1
            || consumed > MAXIMUM_OPERATION_RECORDS
        {
            return Err(refused(
                "host-state quota is not an original bounded budget",
            ));
        }
        Ok(consumed)
    }

    fn inventory(&self) -> Result<(BTreeSet<ContentId>, usize), NodeControlError> {
        let namespace = RefName::new("node-state-operations").map_err(refused)?;
        let mut after = None;
        let mut roots = BTreeSet::new();
        let mut count = 0usize;
        loop {
            let page = self
                .refs
                .scan_refs(&namespace, after.as_ref(), 64)
                .map_err(refused)?;
            for entry in page.entries() {
                count += 1;
                if count > MAXIMUM_OPERATION_RECORDS {
                    return Err(refused(
                        "persistent host-state operation capacity exhausted",
                    ));
                }
                let execution = entry
                    .name()
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or_else(|| refused("host-state operation namespace is malformed"))?;
                let record = self.read(entry.target(), execution)?;
                roots.insert(entry.target());
                roots.insert(record.request);
                if let Some(activation) = self
                    .refs
                    .read_ref(&activation_reference(execution)?)
                    .map_err(refused)?
                {
                    roots.insert(activation);
                } else if matches!(record.state, NodeHostStateOutcome::Completed { .. }) {
                    return Err(refused(
                        "completed state lacks its original durable activation",
                    ));
                }
            }
            after = page.next_after().cloned();
            if after.is_none() {
                break;
            }
        }
        Ok((roots, count))
    }

    fn read(
        &self,
        identity: ContentId,
        execution: &str,
    ) -> Result<NodeHostStateRecord, NodeControlError> {
        let bytes = self
            .blobs
            .read(identity, None)
            .and_then(|handle| handle.read_all(MAXIMUM_RECORD_BYTES as u64))
            .map_err(refused)?;
        if ContentId::for_bytes(ObjectKind::Trace, 1, &bytes) != identity {
            return Err(refused("host-state record identity is corrupt"));
        }
        let value = canonical::parse_json(&bytes, MAXIMUM_RECORD_BYTES)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(refused("host-state record is not canonical"));
        }
        let record: NodeHostStateRecord =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        record.validate()?;
        if record.execution != execution {
            return Err(refused(
                "host-state record belongs to another edition or execution",
            ));
        }
        execution_id(execution)?;
        let request_bytes = self
            .blobs
            .read(record.request, None)
            .and_then(|handle| handle.read_all(super::MAX_NODE_CONTROL_BYTES as u64))
            .map_err(refused)?;
        if ContentId::for_bytes(ObjectKind::Trace, 1, &request_bytes) != record.request {
            return Err(refused("original state request identity is corrupt"));
        }
        let original: NodeHostStateRequest = serde_json::from_value(canonical::parse_json(
            &request_bytes,
            super::MAX_NODE_CONTROL_BYTES,
        )?)
        .map_err(crucible_node_contract::ContractError::from)?;
        original.validate()?;
        if original.execution() != execution
            || is_status(&original)
            || record.version
                != if matches!(original, NodeHostStateRequest::Terminal { .. }) {
                    2
                } else {
                    1
                }
        {
            return Err(refused(
                "state record does not retain its original dispatch request",
            ));
        }
        Ok(record)
    }

    fn put_record(&self, record: &NodeHostStateRecord) -> Result<ContentId, NodeControlError> {
        record.validate()?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(record).map_err(crucible_node_contract::ContractError::from)?,
        )?;
        if bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(refused("host-state operation record exceeds finite bounds"));
        }
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        self.put(identity, bytes)?;
        Ok(identity)
    }

    fn put(&self, identity: ContentId, bytes: Vec<u8>) -> Result<(), NodeControlError> {
        let receipt = self
            .blobs
            .put_if_absent(identity, &BlobHandle::from_bytes(bytes))
            .map_err(refused)?;
        if !receipt.is_durable() {
            return Err(refused("host-state content was not durably retained"));
        }
        Ok(())
    }
}

pub(super) fn is_status(request: &NodeHostStateRequest) -> bool {
    matches!(request, NodeHostStateRequest::Status { .. })
        || matches!(request, NodeHostStateRequest::Terminal { request }
            if matches!(request.as_ref(), super::terminal_state::NodeTerminalStateRequest::Status { .. }))
}

fn operation_ref(execution: &str) -> Result<RefName, NodeControlError> {
    execution_id(execution)?;
    RefName::new(format!("node-state-operations/{execution}")).map_err(refused)
}

fn record_quota_ref() -> Result<RefName, NodeControlError> {
    RefName::new("node-state-quota/records").map_err(refused)
}
