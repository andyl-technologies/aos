//! Durably retains complete original typed results before publication ACK.
//!
//! Each write-once coordinator root contains the full public plan, refused audit,
//! native body/direct rows, source staging body and original common completion.
//! Private Hello, launch credentials and Connection incidents are never read.
//!
//! ```text
//! crucible.typed-conformance-original-result.v1
//!   plan + refused audit: full CFs and unchanged canonical bodies
//!   activation + operation + request + complete outcome
//!   native rows: full CF, unchanged bytes, complete direct dependencies
//!   staging: full source-owned StagedView v1 bytes and its full CF
//!   output/pending inventories: verified complete bodies and direct rows
//! ```

use std::{rc::Rc, sync::Arc};

use crucible::{
    node_admission::{ConformanceAdmissionAuthority, ConformancePlanEvidence},
    node_contract::{
        ConformanceResultPublisher, OriginalCompletedOperation, PublicationStatus, RuntimeError,
    },
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName, StoreError,
};
use crucible_node_contract::{ContentRef, Id};

use super::TypedReaderWitnessAuthority;

#[path = "host_publication/codec.rs"]
mod codec;

const MAXIMUM_WINDOWS: usize = 9;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1024 * 1024;

struct RetainedRecord {
    operation: Id,
    reference: RefName,
    id: ContentId,
    bytes: Vec<u8>,
}

/// Retains full original typed window results under durable coordinator roots.
///
/// Installation binds the same independently configured witness authority used
/// by the collecting graph. Successful publication authenticates all original
/// bodies and their direct rows, writes one complete immutable record, then
/// checks its write-once root and full readback. The publisher issues no class,
/// runtime permission or ACK; the original runtime retains those obligations.
pub struct StoredTypedReaderResultPublisher {
    authority: Rc<TypedReaderWitnessAuthority>,
    plan: ContentRef,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    reference: RefName,
    maximum_bytes: usize,
    retained: Vec<RetainedRecord>,
}

impl StoredTypedReaderResultPublisher {
    /// Reserves nine original result holders before participant launch.
    ///
    /// The independently selected name must belong to the daemon's existing
    /// authoritative coordinator inventory. Full bodies stay inline in that
    /// rooted record, so reclamation does not depend on inferring JSON edges.
    ///
    /// # Errors
    /// Refuses a changed plan, nondurable references, foreign coordinator
    /// namespace, invalid byte credit or unavailable prelaunch holder capacity.
    pub fn new(
        authority: Rc<TypedReaderWitnessAuthority>,
        plan: ContentRef,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        reference: RefName,
        maximum_bytes: usize,
    ) -> Result<Self, StoreError> {
        if !refs.capabilities().durable
            || !reference
                .as_str()
                .starts_with("node-world-coordinators/conformance/")
            || maximum_bytes == 0
            || maximum_bytes > MAXIMUM_RECORD_BYTES
            || authority.current_plan(&plan).is_err()
            || RefName::new(format!(
                "{}-{}",
                reference.as_str(),
                ContentId::for_bytes(ObjectKind::Trace, 1, &[])
            ))
            .is_err()
        {
            return Err(StoreError::Incompatible);
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(MAXIMUM_WINDOWS)
            .map_err(|_| StoreError::Incompatible)?;
        Ok(Self {
            authority,
            plan,
            blobs,
            refs,
            reference,
            maximum_bytes,
            retained,
        })
    }

    fn current(
        &self,
        plan: &ConformancePlanEvidence<'_>,
        original: &OriginalCompletedOperation<'_>,
        case: &str,
    ) -> Result<(), RuntimeError> {
        if plan.plan_ref != &self.plan {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authority
            .authenticate_collection_plan(borrow_plan(plan))
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let admission = original.admission();
        self.authority
            .source()
            .authenticate_collection_operation(
                &admission.token().route().node,
                admission.token().operation(),
                admission.request(),
            )
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let staged = original
            .staged_inputs()?
            .ok_or(RuntimeError::InvalidReceipt)?;
        self.authority
            .source()
            .authenticate_collection_inputs(staged.batch())
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        // The borrowed original source view is dropped before any backend can
        // execute. Current installation must survive every storage callback.
        {
            let seal = self
                .authority
                .original_window_evidence(case)
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            if seal.stop().operation_id != *admission.token().operation()
                || seal.stop().activation_id != admission.activation().record().activation_id
                || seal.stop().world_binding_hash != *plan.world
                || seal.stop().world_generation != admission.activation().record().generation
            {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        self.authority
            .current_plan(&self.plan)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        // Finish with the same direct original owner reads used at native
        // dispatch. No source callback follows before the storage operation.
        self.authority
            .source()
            .authenticate_current_native_owners()
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    fn retain(
        &mut self,
        plan: &ConformancePlanEvidence<'_>,
        original: &OriginalCompletedOperation<'_>,
        case: &str,
    ) -> Result<usize, RuntimeError> {
        self.current(plan, original, case)?;
        let encoded = codec::record(&self.authority, plan, original, case, self.maximum_bytes)?;
        let operation = original.admission().token().operation();
        if let Some(index) = self
            .retained
            .iter()
            .position(|retained| &retained.operation == operation)
        {
            if self.retained[index].bytes != encoded.bytes {
                return Err(RuntimeError::InvalidReceipt);
            }
            return Ok(index);
        }
        if self.retained.len() >= MAXIMUM_WINDOWS {
            return Err(RuntimeError::ResourceLimit);
        }
        let reference = RefName::new(format!("{}-{}", self.reference.as_str(), encoded.identity))
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &encoded.bytes);
        self.current(plan, original, case)?;

        // The same full bytes are retained before the first uncertain storage
        // effect. Retry reconciles this original record, never native execution.
        self.retained.push(RetainedRecord {
            operation: operation.clone(),
            reference,
            id,
            bytes: encoded.bytes,
        });
        Ok(self.retained.len() - 1)
    }
}

#[cfg(test)]
#[path = "host_publication/tests.rs"]
mod tests;

impl ConformanceResultPublisher for StoredTypedReaderResultPublisher {
    fn publish_original(
        &mut self,
        plan: ConformancePlanEvidence<'_>,
        original: &OriginalCompletedOperation<'_>,
    ) -> Result<PublicationStatus, RuntimeError> {
        let case = self
            .authority
            .programme()
            .windows()
            .iter()
            .find(|planned| &planned.operation == original.admission().token().operation())
            .ok_or(RuntimeError::InvalidReceipt)?
            .case
            .clone();
        let index = self.retain(&plan, original, &case)?;
        let record = &self.retained[index];
        let current = || self.current(&plan, original, &case);
        store_record(self.blobs.as_ref(), self.refs.as_ref(), record, &current)
    }
}

fn borrow_plan<'a>(plan: &ConformancePlanEvidence<'a>) -> ConformancePlanEvidence<'a> {
    ConformancePlanEvidence {
        plan_ref: plan.plan_ref,
        plan_bytes: plan.plan_bytes,
        refused_ref: plan.refused_ref,
        refused_bytes: plan.refused_bytes,
        world: plan.world,
        sources: plan.sources,
    }
}

fn store_record(
    blobs: &dyn ImmutableBlobBackend,
    refs: &dyn MutableRefBackend,
    record: &RetainedRecord,
    current: &impl Fn() -> Result<(), RuntimeError>,
) -> Result<PublicationStatus, RuntimeError> {
    current()?;
    let Ok(guard) = refs.acquire_publication_guard() else {
        return Ok(PublicationStatus::Unknown);
    };
    current()?;
    let write = blobs.put_if_absent(record.id, &BlobHandle::from_bytes(record.bytes.clone()));
    // Even a backend reporting failure may have stored bytes. Late refusal
    // cannot retract that effect or release the original native obligation.
    current()?;
    if !matches!(write, Ok(receipt) if receipt.is_durable()) {
        return Ok(PublicationStatus::Unknown);
    }
    let placement = refs.compare_exchange(&record.reference, None, record.id);
    current()?;
    match placement {
        Ok(RefCasOutcome::Advanced { next }) if next == record.id => {}
        Ok(RefCasOutcome::Conflict {
            current: Some(actual),
            ..
        }) if actual == record.id => {}
        Ok(_) => return Ok(PublicationStatus::NotCommitted),
        Err(_) => return Ok(PublicationStatus::Unknown),
    }
    let root = refs.read_ref(&record.reference);
    current()?;
    if !matches!(root, Ok(Some(actual)) if actual == record.id) {
        return Ok(PublicationStatus::Unknown);
    }
    let handle = blobs.read(record.id, None);
    current()?;
    let readback = handle.and_then(|handle| handle.read_all(record.bytes.len() as u64));
    current()?;
    if !matches!(readback, Ok(bytes) if bytes == record.bytes) {
        return Ok(PublicationStatus::Unknown);
    }
    drop(guard);
    current()?;
    Ok(PublicationStatus::Committed)
}
