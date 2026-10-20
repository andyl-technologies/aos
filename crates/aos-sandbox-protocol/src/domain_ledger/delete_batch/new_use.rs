//! Rejects typed new uses of resources covered by canonical Delete tombstones.
//!
//! This allocation-free comparison consumes already decoded request DATA and
//! existing DesiredState rows. It grants no authorization, currentness or native
//! custody. The caller must retain its genuine current Controller interval;
//! accepted operations must repeat this comparison before resuming effects.

use aos_sandbox_core::ProjectId;
use aos_sandbox_core::model::ViewSource;
use crate::public_api::request::DormantSandboxRequestKindV1;
use super::{LifecycleModelError, LifecycleResourceV1, TOMBSTONE_PREFIX};

/// Reports a malformed target/record or a resource denied by a tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PublicMutationNewUseErrorV2 {
    /// A known mutation contains a malformed concrete target identity.
    #[error("public mutation new-use target is malformed")]
    InvalidTarget,
    /// This entry does not describe a supported public mutation.
    #[error("request has no supported public mutation new-use contract")]
    UnsupportedRequest,
    /// A recognized tombstone violates its canonical key or value grammar.
    #[error("public mutation tombstone is corrupt: {0}")]
    CorruptTombstone(#[source] LifecycleModelError),
    /// The exact typed target is covered by a canonical tombstone.
    #[error("public mutation uses a tombstoned resource: {0:?}")]
    Tombstoned(LifecycleResourceV1),
}

/// Returns the fixed byte peak for target, checksum and refusal scratch.
///
/// This is MemoryBytes only: fixed Rust carriers are not namespace entries.
/// Callers admit this term before entering the comparison; no input-sized
/// allocation, second request decoder or graph reconstruction occurs here.
#[must_use]
pub const fn public_mutation_new_use_receiving_bytes_v2() -> usize {
    std::mem::size_of::<[Option<LifecycleResourceV1>; 2]>() * 4
        + std::mem::size_of::<sha2::Sha256>() * 4
        + std::mem::size_of::<PublicMutationNewUseErrorV2>() * 4
}

/// Rejects new concrete uses of tombstoned resources in one project.
///
/// Cleanup and capability-management requests create no physical use under
/// this contract. Their authorization and transaction barriers remain required.
/// ViewCreate names only a descriptor: its genuine producer separately invokes
/// [`require_view_source_live_data_v2`] after decoding the actual immutable View.
/// Neither a descriptor digest nor the endpoint's ResourceKind is an owner ID.
///
/// # Errors
/// Refuses malformed concrete identities, unsupported request purposes, every
/// malformed recognized tombstone, and an exact project/typed-target match.
pub fn require_public_mutation_targets_live_data_v2<'a>(
    project: ProjectId,
    request: &DormantSandboxRequestKindV1,
    desired_rows: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<(), PublicMutationNewUseErrorV2> {
    require_targets_live_data_v2(project, targets_v2(request)?, desired_rows)
}

/// Rejects a tombstoned owner from an already verified immutable View model.
///
/// The producer supplies the typed source only after its existing descriptor
/// integrity and canonical View decoder. This negative comparison establishes
/// no Source provenance, export permission or native/currentness association.
///
/// # Errors
/// Refuses sentinel project/owner identities, malformed recognized tombstones,
/// and a canonical tombstone for the exact LiveExport sandbox owner.
pub fn require_view_source_live_data_v2<'a>(
    project: ProjectId,
    source: &ViewSource,
    desired_rows: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<(), PublicMutationNewUseErrorV2> {
    let targets = match source {
        ViewSource::LiveExport { owner_sandbox, .. } => {
            [Some(LifecycleResourceV1::Sandbox(*owner_sandbox)), None]
        }
        ViewSource::ImmutableTree { .. } => [None, None],
    };
    require_targets_live_data_v2(project, targets, desired_rows)
}

fn require_targets_live_data_v2<'a>(
    project: ProjectId,
    targets: [Option<LifecycleResourceV1>; 2],
    desired_rows: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<(), PublicMutationNewUseErrorV2> {
    if project.as_bytes() == &[0; 16]
        || targets.iter().flatten().any(|target| target.as_bytes() == &[0; 16])
    {
        return Err(PublicMutationNewUseErrorV2::InvalidTarget);
    }
    if targets.iter().all(Option::is_none) {
        return Ok(());
    }
    for (key, value) in desired_rows {
        if !key.starts_with(TOMBSTONE_PREFIX) {
            continue;
        }
        super::validate_tombstone(value)
            .map_err(PublicMutationNewUseErrorV2::CorruptTombstone)?;
        let suffix = key.strip_prefix(TOMBSTONE_PREFIX)
            .ok_or(PublicMutationNewUseErrorV2::CorruptTombstone(LifecycleModelError::CorruptEncoding))?;
        if suffix.len() != 33 || suffix[..16] != value[12..28]
            || suffix[16..] != value[60..77]
        {
            return Err(PublicMutationNewUseErrorV2::CorruptTombstone(LifecycleModelError::CorruptEncoding));
        }
        let resource = super::resource(&value[60..77])
            .map_err(PublicMutationNewUseErrorV2::CorruptTombstone)?;
        if value[12..28] == project.as_bytes()[..]
            && targets.iter().flatten().any(|target| *target == resource)
        {
            return Err(PublicMutationNewUseErrorV2::Tombstoned(resource));
        }
    }
    Ok(())
}

fn targets_v2(request: &DormantSandboxRequestKindV1)
    -> Result<[Option<LifecycleResourceV1>; 2], PublicMutationNewUseErrorV2>
{
    use DormantSandboxRequestKindV1 as R;
    let one = |code, bytes: &[u8]| -> Result<_, PublicMutationNewUseErrorV2> {
        Ok([Some(target_v2(code, bytes)?), None])
    };
    let optional = |code, bytes: &[u8]| -> Result<_, PublicMutationNewUseErrorV2> {
        if bytes.is_empty() { Ok(None) } else { target_v2(code, bytes).map(Some) }
    };
    match request {
        R::Create(value) => Ok([optional(1, &value.parent_sandbox_id)?, None]),
        R::UpdatePolicy(value) => one(1, &value.sandbox_id),
        R::Start(value) | R::Suspend(value) | R::Resume(value) => one(1, &value.sandbox_id),
        R::Exec(value) => one(1, &value.sandbox_id),
        R::ExecutionControl(value) => one(2, &value.execution_id),
        R::Snapshot(value) => one(1, &value.sandbox_id),
        R::Restore(value) => Ok([Some(target_v2(3, &value.snapshot_id)?), Some(target_v2(1, &value.target_sandbox_id)?)]),
        R::Fork(value) => Ok([Some(target_v2(3, &value.snapshot_id)?), optional(1, &value.parent_sandbox_id)?]),
        R::ViewAttach(value) => Ok([Some(target_v2(1, &value.sandbox_id)?), Some(target_v2(4, &value.view_id)?)]),
        R::ViewReplace(value) => Ok([Some(target_v2(5, &value.attachment_id)?), Some(target_v2(4, &value.new_view_id)?)]),
        R::CachePin(value) => Ok([Some(target_v2(4, &value.view_id)?), optional(5, &value.attachment_id)?]),
        // These operations remove/settle work, manage authority, or supply only
        // an immutable descriptor whose real Source producer must resolve it.
        R::Stop(_) | R::Delete(_) | R::CancelExec(_) | R::CancelOperation(_)
        | R::DeleteSnapshot(_) | R::ViewDetach(_) | R::ViewRelease(_)
        | R::CacheUnpin(_) | R::CapabilityAttenuate(_) | R::CapabilityRenew(_)
        | R::CapabilityRevoke(_) | R::ViewCreate(_) => Ok([None, None]),
        // Read/planning and operator recovery are separate closed entrypoints.
        // A newly added request variant must choose its contract explicitly.
        R::PlanCreate(_) | R::GetSandbox(_) | R::GetExecution(_) | R::GetView(_)
        | R::GetAttachment(_) | R::GetSnapshot(_) | R::GetOperation(_)
        | R::ListSandboxes(_) | R::ListExecutions(_) | R::ListSnapshots(_)
        | R::Tree(_) | R::Children(_) | R::Ancestors(_) | R::PlanPolicy(_)
        | R::Events(_) | R::ViewList(_) | R::CacheStatus(_)
        | R::CapabilitiesPublicApi(_) | R::CapabilitiesNode(_)
        | R::CapabilityInspect(_) | R::OperatorRecover(_) | R::Completions(_) => {
            Err(PublicMutationNewUseErrorV2::UnsupportedRequest)
        }
    }
}

fn target_v2(code: u8, bytes: &[u8]) -> Result<LifecycleResourceV1, PublicMutationNewUseErrorV2> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| PublicMutationNewUseErrorV2::InvalidTarget)?;
    LifecycleResourceV1::from_code(code, bytes).map_err(|_| PublicMutationNewUseErrorV2::InvalidTarget)
}

#[cfg(test)]
mod tests;
