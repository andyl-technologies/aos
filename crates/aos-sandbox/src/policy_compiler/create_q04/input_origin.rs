//! Owns source-priced original-input capture DATA for the called Q04 path.
//!
//! Costing values are not a loan or a successful Create. The genuine Project
//! preparation owns their once-only admission before capture; the later
//! co-issuance keeps inclusive capacity C distinct from retained use U.

use aos_sandbox_core::{ObjectDigest, ResourceVector};
use sha2::{Digest as _, Sha256};

use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::controller_resource_reservation::service_interval::JournalShape;
use super::CreateQ04ErrorV1;

pub(crate) const CONTROLLER_INPUT_ORIGIN_KEY: &[u8] = b"\0aos-controller-q04-input-origin-v1\0";

pub(crate) fn cache_replay_cell_bytes() -> Result<usize, ResourceReservationErrorV1> {
    std::mem::size_of::<crate::cache_residency::CacheAtomicObjectPayloadV1>()
        .checked_add(std::mem::size_of::<crate::cache_residency::CacheGlobalRecoveryStateV1>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::cache_residency::CacheRecoveryWorkV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::cache_residency::CacheTypedCheckpointV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::cache_residency::CacheRecoveryInventoryV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(Vec<u8>, Vec<u8>, [usize; 4])>()))
        .ok_or(ResourceReservationErrorV1::Conflict)
}

pub(crate) fn candidate_capacity(
    candidate: &super::super::CompiledPolicyCandidateV1,
) -> Result<ResourceVector, CreateQ04ErrorV1> {
    use aos_sandbox_core::{ResourceDimension, ResourceLimit};

    let mut values = [0; ResourceDimension::COUNT];
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        let ResourceLimit::Bounded(value) = candidate.hard_resources().accounting_ceilings().get(dimension) else {
            return Err(CreateQ04ErrorV1::ChangedCut);
        };
        values[index] = value;
    }
    Ok(ResourceVector::new(values))
}

/// Owns the exact existing AOSPCO03 bytes as prepared provenance, not authority.
pub(crate) struct Q04PreparedInputOriginV1 {
    bytes: Vec<u8>,
}

impl Q04PreparedInputOriginV1 {
    pub(super) fn retain(
        input: &super::super::PolicyCompilerInputV1,
        candidate: &super::super::CompiledPolicyCandidateV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        let original = super::super::publisher_origin::retain_q04_original_derivation(input, candidate)?;
        Ok(Self { bytes: original.to_record_bytes()? })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn raw_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    pub(crate) fn require_identity(
        &self,
        identity: &super::Q04CutIdentityV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        require_origin_identity(&self.bytes, identity)
    }
}

pub(crate) fn require_origin_identity(
    bytes: &[u8],
    identity: &super::Q04CutIdentityV1,
) -> Result<(), CreateQ04ErrorV1> {
    let original = super::super::RetainedPublisherCompilerOriginV3::from_record_bytes(bytes)?;
    if original.project() != identity.project() || original.original_target() != identity.sandbox()
        || original.normalized_input() != ObjectDigest::from_bytes(super::fixed(identity.bytes(), 456))
        || original.candidate() != ObjectDigest::from_bytes(super::fixed(identity.bytes(), 488))
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    Ok(())
}

pub(crate) struct Q04OriginalInputDemandV1 {
    retained: ResourceVector,
    continuation: ResourceVector,
}

impl Q04OriginalInputDemandV1 {
    pub(crate) fn total(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        Ok(self.retained.checked_add(self.continuation)?)
    }

    pub(crate) fn require_subdivision(
        &self,
        original: ResourceVector,
        inclusive: ResourceVector,
    ) -> Result<(), ResourceReservationErrorV1> {
        inclusive.checked_sub(self.retained)?;
        original.checked_sub(inclusive)?.checked_sub(self.continuation)?;
        original.checked_sub(self.total()?)?;
        Ok(())
    }

    pub(crate) const fn retained(&self) -> ResourceVector {
        self.retained
    }

    pub(crate) const fn continuation(&self) -> ResourceVector {
        self.continuation
    }
}

pub(crate) fn original_input_demand(
    controller: &JournalShape,
    source: &JournalShape,
) -> Result<Q04OriginalInputDemandV1, ResourceReservationErrorV1> {
    let failed = || ResourceReservationErrorV1::Conflict;
    let layer = super::super::MAXIMUM_POLICY_LAYER_BYTES;
    // The parentless path has four layers, two branded catalogs and backend
    // input. Four portable outputs, original/candidate verification copies,
    // and the AOSPCO03 serializer's independent record remain simultaneously
    // owned. Every encoded byte is also a conservative possible owned cell.
    let input_bytes = layer.checked_mul(4 + 2 + 1).ok_or_else(failed)?;
    let output_bytes = layer.checked_mul(4).ok_or_else(failed)?;
    let origin_bytes = 4 * 1024 * 1024;
    let compiler_bytes = input_bytes.checked_add(output_bytes)
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(origin_bytes * 2)).ok_or_else(failed)?;
    let cell_bytes = std::mem::size_of::<(Vec<u8>, Vec<u8>, [usize; 4])>()
        .checked_add(std::mem::size_of::<super::super::PolicyLayerV1>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::super::CompiledPolicyCandidateV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::super::PolicyCompilerInputV1>()))
        .ok_or_else(failed)?;
    let compiler_cells = compiler_bytes;
    let compiler_memory = compiler_bytes.checked_add(compiler_cells.checked_mul(cell_bytes).ok_or_else(failed)?)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::super::PolicyCompilerInputV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::super::CompiledPolicyCandidateV1>()))
        .ok_or_else(failed)?;

    // The actual fresh Controller and unchanged Source shapes are not replaced
    // with namespace maxima. Future complete recipes use their existing native
    // transaction ceilings: eight Controller phases plus terminal retention,
    // and a conservative four Source/Cache recipes for their three-phase cuts.
    // Cache's state/authority use JournalLimits::default, not the smaller
    // Controller cache-source opener. Complete replay/error owners count too.
    let controller_suffix = controller.maximum_transaction_bytes.checked_mul(9).ok_or_else(failed)?;
    let source_suffix = source.maximum_transaction_bytes.checked_mul(4).ok_or_else(failed)?;
    let cache = crate::JournalLimits::default();
    let cache_suffix = cache.maximum_transaction_bytes.checked_mul(4).ok_or_else(failed)?;
    let cache_native = usize::try_from(cache.maximum_journal_bytes).map_err(|_| failed())?
        .checked_mul(2).and_then(|bytes| bytes.checked_add(256 * 1024 * 1024)).ok_or_else(failed)?;
    let cache_cell = cache_replay_cell_bytes()?.checked_add(cell_bytes).ok_or_else(failed)?;
    // Each canonical byte can conservatively name an owned decoded cell.
    // The sum includes the largest nested payload/global/work carriers and
    // tree-node/key overhead; whole native extents bound all admitted input.
    let cache_materialized = cache_native.checked_mul(cache_cell)
        .and_then(|bytes| bytes.checked_mul(4)).ok_or_else(failed)?;
    let suffix = controller_suffix.checked_add(source_suffix)
        .and_then(|bytes| bytes.checked_add(cache_suffix))
        .and_then(|bytes| bytes.checked_add(cache_native)).ok_or_else(failed)?;
    let replay = controller.native_bytes.checked_add(source.native_bytes)
        .and_then(|bytes| bytes.checked_add(u64::try_from(suffix).ok()?)).ok_or_else(failed)?;
    let rows = controller.cells.checked_add(source.cells)
        .and_then(|cells| cells.checked_mul(9 + 4))
        .and_then(|cells| cells.checked_add(cache_native))
        .and_then(|cells| cells.checked_add(compiler_cells)).ok_or_else(failed)?;
    let materialized = controller.retained_bytes.checked_add(source.retained_bytes)
        .and_then(|bytes| bytes.checked_mul(9 + 4))
        .and_then(|bytes| bytes.checked_add(rows.checked_mul(cell_bytes)?))
        .and_then(|bytes| bytes.checked_add(suffix.checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(usize::try_from(replay).ok()?))
        .and_then(|bytes| bytes.checked_add(compiler_memory))
        .and_then(|bytes| bytes.checked_add(cache_materialized))
        .and_then(|bytes| bytes.checked_add(origin_bytes.checked_mul(16)?)).ok_or_else(failed)?;
    let memory = u64::try_from(materialized).map_err(|_| failed())?;
    let rows = u64::try_from(rows).map_err(|_| failed())?;

    // The existing Project preparation keeps its own residual/native binding,
    // original cut and first cause after moving the child. Price those distinct
    // continuation slots rather than treating P-C as free budget. Canonical
    // Project policy copies stay with the priced child compiler/ledger owners;
    // the Project continuation retains its actual attempt and fixed native
    // original/residual rows, not fabricated signed input buffers.
    let continuation = std::mem::size_of::<crate::ProjectPreparationReservationAttemptV1>()
        .checked_add(945 + 531 + 787).ok_or_else(failed)?;
    let continuation = u64::try_from(continuation).map_err(|_| failed())?;

    // Q already pays the exact original profile/CPU/observer archive and early
    // invocation/wire/native-prefix owners. This slice creates no processes,
    // mounts, descendants, mappings, fetch/decompression, backing attachments
    // or executions. Its new owners are compiler/recipe/replay/record DATA.
    Ok(Q04OriginalInputDemandV1 {
        retained: ResourceVector::new([
            0, memory, 0, 0, 0, 0, replay, 0, 0, 0, rows, 0, 0, 0,
            memory, 0, 0, 0, 0, memory, memory, 1,
        ]),
        continuation: ResourceVector::new([
            0, continuation, 0, 0, 0, 0, 945 + 531 + 787, 0, 0, 0,
            continuation, 0, 0, 0, continuation, 0, 0, 0, 0,
            continuation, continuation, 0,
        ]),
    })
}
