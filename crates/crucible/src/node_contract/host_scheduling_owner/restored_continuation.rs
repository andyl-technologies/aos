//! Preserves the current restored coordinator separately from immutable ancestry.
//!
//! This edition is not an extension or promotion of the original Host2 codec.
//! Its strict reader returns inert facts; a fresh owner still requires the signed
//! archive, actual native17 validation and a new current restoration context.
//!
//! ```text
//! {"schema_version":17,"source":{},"runtime":{},"scheduling":{},
//!  "objects":[],"ancestry":{},"admission_policy":{}}
//! ```

use super::*;
use crate::node_contract::{
    OriginalInputLineageLimits, OriginalLineageRuntimeRecord, RuntimeLimits,
};
use crate::node_scheduling::{InputPayload, SchedulingSnapshot};
use serde::{Deserialize, Serialize};

const CONTRACT_BYTES: &[u8] = include_bytes!("restored_continuation/contract17.json");

#[path = "restored_continuation/validation.rs"]
mod validation;

#[path = "restored_continuation/capture.rs"]
mod capture;
pub(crate) use capture::{
    HostSchedulingRestoredCaptureAttempt17, HostSchedulingRestoredContinuation17,
    RestoredHostCaptureAncestryBorrowed17,
};

#[path = "restored_continuation/host_role.rs"]
mod host_role;

#[path = "restored_continuation/storage.rs"]
mod storage;

/// Binds one immutable first semantic component to its logical participant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredHostSemanticAncestor {
    /// Names the actual native participant in the signed owner roster.
    pub node: Id,
    /// Names the first semantic state, without rewriting its original identity.
    pub object: ContentRef,
}

/// Retains immutable ancestry independently of the current captured activation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredHostAncestry17 {
    /// Names the authenticated signed Index3 used to construct this target.
    pub parent_archive_index: ContentRef,
    /// Names the actual original Host owner state within that ancestry DAG.
    pub first_host: ContentRef,
    /// Enumerates the exact three first semantic objects in participant order.
    pub first_semantic: [RestoredHostSemanticAncestor; 3],
}

/// Preserves finite admission policy without preserving host-only heap padding.
///
/// These are policy ceilings, not fresh remaining grants. Used identities and
/// retained operations remain in the Runtime7 and scheduling ledgers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredHostAdmissionPolicy17 {
    /// Bounds the complete participant roster.
    pub maximum_nodes: usize,
    /// Bounds the complete mutable owner roster.
    pub maximum_owners: usize,
    /// Bounds all original operation identities without recycling them.
    pub maximum_operations: usize,
    /// Bounds one complete retained output inventory.
    pub maximum_retained_outputs: usize,
}

impl From<RuntimeLimits> for RestoredHostAdmissionPolicy17 {
    fn from(limits: RuntimeLimits) -> Self {
        Self {
            maximum_nodes: limits.maximum_nodes,
            maximum_owners: limits.maximum_owners,
            maximum_operations: limits.maximum_operations,
            maximum_retained_outputs: limits.maximum_retained_outputs,
        }
    }
}

impl RestoredHostAdmissionPolicy17 {
    /// Returns the same policy ceilings for independently validated fresh custody.
    pub fn limits_data(self) -> RuntimeLimits {
        RuntimeLimits {
            maximum_nodes: self.maximum_nodes,
            maximum_owners: self.maximum_owners,
            maximum_operations: self.maximum_operations,
            maximum_retained_outputs: self.maximum_retained_outputs,
        }
    }
}

/// Encodes the current Host17 state without serializing process-local authority.
///
/// The current Runtime7 and scheduler retain the current World and reached cut.
/// Immutable first ancestry remains separate. The record does not contain or
/// recreate a Window, Source key, operation token, capture ticket or native owner.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSchedulingRestoredContinuationRecord17 {
    /// Selects this distinct current-state envelope, exactly seventeen.
    pub schema_version: u16,
    /// Binds the actual current Host descriptor, binding and owner domains.
    pub source: HostSchedulingSelection,
    /// Retains every current common operation and original input association.
    pub runtime: OriginalLineageRuntimeRecord,
    /// Retains current queues, used identities, frontiers and input custody.
    pub scheduling: SchedulingSnapshot,
    /// Retains complete referenced input bodies in strict full-reference order.
    pub objects: Vec<InputPayload>,
    /// Retains actual immutable first ancestry without relabeling it as current.
    pub ancestry: RestoredHostAncestry17,
    /// Retains the actual finite global admission ceilings.
    pub admission_policy: RestoredHostAdmissionPolicy17,
}

impl HostSchedulingRestoredContinuationRecord17 {
    /// Counts actual retained backing separately from the containing root.
    ///
    /// This census observes real capacities; it does not make those host-only
    /// capacities part of the portable modeled state or require a future loader
    /// to reproduce them.
    ///
    /// # Errors
    /// Refuses checked overflow in the complete current-record owner walk.
    pub fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        crate::node_contract::NodeRuntime::capture_restored_host_record_storage_data(self)
    }

    /// Checks the exact funded policy retained by an actual fresh constructor.
    ///
    /// # Errors
    /// Refuses either widened or tightened limits; neither may silently change
    /// future admission behavior of the captured World.
    pub fn authenticate_target_policy_data(
        &self,
        actual: RuntimeLimits,
    ) -> Result<(), RuntimeError> {
        if self.admission_policy.limits_data() != actual {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Checks the independent current coordinator commitment against this record.
    ///
    /// Full-reference body verification remains the outer signed archive's
    /// responsibility. The complete current Runtime7 and Scheduling1 bodies must
    /// be independently present; neither a Host object hash nor an ancestor is
    /// substituted for either commitment.
    ///
    /// # Errors
    /// Refuses another cut, ordinal, current activation, full reference, changed
    /// checkpoint structure or conflated Runtime and scheduler roles.
    pub fn validate_matching_checkpoint_data(
        &self,
        runtime_reference: &ContentRef,
        scheduling_reference: &ContentRef,
        checkpoint: &crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentCheckpoint17,
    ) -> Result<(), RuntimeError> {
        checkpoint
            .authenticate_structure_data(
                runtime_reference,
                self.runtime.capture_cut,
                self.runtime.capture_ordinal,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let activation = &self.runtime.source_activation;
        if runtime_reference == scheduling_reference
            || checkpoint.safe_point.scheduling != *scheduling_reference
            || checkpoint.activation.world_binding != activation.world_binding_hash
            || checkpoint.activation.activation_id != activation.activation_id
            || checkpoint.activation.world_generation != activation.generation
            || checkpoint.activation.boundary != activation.boundary
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(())
    }

    /// Decodes bounded canonical facts without installing or authorizing a World.
    ///
    /// The caller must separately verify these bytes against the signed archive,
    /// validate the complete native/Host/semantic correspondence and create fresh
    /// custody. This reader never invokes a native callback or resolves a path.
    ///
    /// # Errors
    /// Refuses other editions, noncanonical or unknown fields, malformed current
    /// or ancestry references, incomplete bodies, inconsistent cuts or exceeded
    /// finite record, lineage, operation and roster policy.
    pub fn decode(
        bytes: &[u8],
        limits: HostSchedulingContinuationLimits,
    ) -> Result<Self, RuntimeError> {
        validation::validate_limits(limits)?;
        let value = canonical::parse_json(bytes, limits.maximum_record_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)? != bytes {
            return Err(RuntimeError::InvalidReceipt);
        }
        let record: Self =
            serde_json::from_value(value).map_err(|_| RuntimeError::InvalidReceipt)?;
        record.validate_data(limits)?;
        Ok(record)
    }

    /// Rechecks the complete inert record without constructing a new permission.
    ///
    /// # Errors
    /// Refuses unsupported editions, inconsistent current ledgers, malformed or
    /// omitted bodies/ancestry, or finite policy excess.
    pub fn validate_data(
        &self,
        limits: HostSchedulingContinuationLimits,
    ) -> Result<(), RuntimeError> {
        validation::validate_limits(limits)?;
        validation::validate_record(self, limits)
    }
}

/// Borrows the exact compiled Host17 contract bytes without constructing owners.
///
/// This immutable format DATA loan grants no Source, World or capture authority.
/// Its borrowed bytes are identical to the owning definition producer's output.
pub fn host_scheduling_restored_continuation_definition17_bytes_data() -> &'static [u8] {
    CONTRACT_BYTES
}

/// Encodes the distinct current Host17 contract for immutable implementation binding.
///
/// # Errors
/// Reports canonical encoding failure of the fixed compiled definition.
pub fn host_scheduling_restored_continuation_definition17() -> Result<Vec<u8>, OperationFailure> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(CONTRACT_BYTES.len())
        .map_err(failure)?;
    bytes.extend_from_slice(CONTRACT_BYTES);
    Ok(bytes)
}

/// Binds the exact current Host17 grammar independently of its preservation facet.
///
/// # Errors
/// Reports invalid fixed identity or canonical definition encoding failure.
pub fn host_scheduling_restored_continuation_schema17() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("source-owned.host-scheduling-continuation/17").map_err(failure)?,
        version: 17,
        definition: canonical::content_ref(
            &host_scheduling_restored_continuation_definition17()?,
            "application/json",
        )
        .map_err(failure)?,
        extensions: Default::default(),
    })
}

/// Checks the complete compiled Host17 schema without an owning definition copy.
///
/// This comparison grants no World, Capture, restored model or allocation right.
///
/// # Errors
/// Refuses any changed identity, edition, extension, media, length or digest.
pub fn authenticate_host_scheduling_restored_continuation_schema17_data(
    schema: &SchemaRef,
) -> Result<(), RuntimeError> {
    let reference = &schema.definition;
    if schema.id.as_str() != "source-owned.host-scheduling-continuation/17"
        || schema.version != 17
        || !schema.extensions.is_empty()
        || reference.media_type != "application/json"
        || reference.length.get() != CONTRACT_BYTES.len() as u64
        || reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    const DOMAIN: &[u8] = b"cnp.blob.v1";
    hasher.update(&(DOMAIN.len() as u32).to_be_bytes());
    hasher.update(DOMAIN);
    hasher.update(&(CONTRACT_BYTES.len() as u64).to_be_bytes());
    hasher.update(CONTRACT_BYTES);
    let hash = hasher.finalize();
    let digest = reference.hash.digest.as_bytes();
    if digest.len() != 64 {
        return Err(RuntimeError::InvalidReceipt);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (byte, pair) in hash.as_bytes().iter().zip(digest.chunks_exact(2)) {
        if pair[0] != HEX[usize::from(byte >> 4)] || pair[1] != HEX[usize::from(byte & 15)] {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    Ok(())
}

/// Counts the fixed workspace of the exact compiled Host17 schema comparator.
///
/// The output definition remains borrowed static bytes; no allocation credit or
/// historical validation authority is supplied by this DATA getter.
pub fn host_scheduling_restored_continuation_schema17_counter_scratch_data() -> usize {
    let terms = [
        std::mem::size_of::<&SchemaRef>(),
        std::mem::size_of::<&ContentRef>(),
        std::mem::size_of::<blake3::Hasher>(),
        std::mem::size_of::<blake3::Hash>(),
        std::mem::size_of::<&[u8]>(),
        std::mem::size_of::<&[u8; 16]>(),
        std::mem::size_of::<std::slice::Iter<'static, u8>>(),
        std::mem::size_of::<std::slice::ChunksExact<'static, u8>>(),
        std::mem::size_of::<
            std::iter::Zip<std::slice::Iter<'static, u8>, std::slice::ChunksExact<'static, u8>>,
        >(),
        std::mem::size_of::<(&u8, &[u8])>(),
        std::mem::size_of::<Result<(), RuntimeError>>(),
        std::mem::size_of::<[u8; 4]>(),
        std::mem::size_of::<[u8; 8]>(),
        std::mem::size_of::<usize>(),
    ];
    std::mem::size_of_val(&terms)
        + std::mem::size_of::<std::array::IntoIter<usize, 14>>()
        + terms.into_iter().sum::<usize>()
}

#[path = "restored_continuation/preparation.rs"]
mod preparation;
pub(crate) use preparation::{
    PreparedRestoredHost17Capture, RestoredHost17CaptureConstructionData,
};
