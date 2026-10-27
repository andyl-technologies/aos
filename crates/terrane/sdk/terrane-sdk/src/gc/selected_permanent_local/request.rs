//! Resolves a selected Planned local request without treating pass data as authority.

use super::denied;
use crate::bucket::publication::receipts::RecordRead;
use crate::bucket::{BucketBinding, held::HeldBucket};
use crate::selected_bridge::native_copied_placement::CheckedOwnedPlacement;
use crate::store::StoreFailure;
use crate::store::{Clock, ContentValidator, LocalFs};
use terrane_format::gc::GcLease;
use terrane_format::gc::retirement::{
    ObservationState, ObservedArtifact, ObservedInstance, PermanentDeleteOperation,
    PermanentDeletePass,
};

/// Borrows one selected Planned request and its genuinely current owner/DATA carrier.
pub(crate) struct CheckedPermanentReclaim<'request, 'operation, 'held> {
    current: &'request CheckedOwnedPlacement<'operation, 'held>,
    artifact: ObservedArtifact,
    key: String,
    bytes: Vec<u8>,
    pass: PermanentDeletePass,
    read: RecordRead,
}

impl<'request, 'operation, 'held> CheckedPermanentReclaim<'request, 'operation, 'held> {
    /// Borrows the exact same-held current owner and complete DATA checks.
    pub(crate) fn current(&self) -> &'request CheckedOwnedPlacement<'operation, 'held> {
        self.current
    }

    /// Returns the selected target kind, never an arbitrary native path.
    pub(crate) fn artifact(&self) -> ObservedArtifact {
        self.artifact
    }

    /// Borrows the independently selected immutable progress event key.
    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    /// Borrows the actual selected canonical progress bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the canonical selected event without granting new progress permission.
    pub(crate) fn pass(&self) -> &PermanentDeletePass {
        &self.pass
    }

    /// Borrows the actual protected event body and incarnation retained for effects.
    pub(crate) fn read(&self) -> &RecordRead {
        &self.read
    }

    /// Refreshes the borrowed carrier's selected observation and live Session.
    ///
    /// Physical DATA and consumed Original predicates are retained separately in
    /// the native Frame and refreshed by the actual worker around the request.
    ///
    /// # Errors
    /// Refuses changed selected state, owner association or an invalid Session.
    pub(crate) async fn revalidate(&self) -> Result<(), StoreFailure> {
        self.current.revalidate().await
    }
}

/// Resolves an actual selected Planned event under independently current owner/DATA.
///
/// # Errors
/// Refuses missing protected progress, wrong owner or backend, a stale whole lease,
/// unversioned-target disagreement and changed current prerequisites.
pub(crate) async fn qualify_reclaim<'request, 'operation, 'held, F, B, V>(
    current: &'request CheckedOwnedPlacement<'operation, 'held>,
    held: &HeldBucket<'_, F, B, V, true>,
    artifact: ObservedArtifact,
) -> Result<CheckedPermanentReclaim<'request, 'operation, 'held>, StoreFailure>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    current.revalidate().await?;
    let owner = current.owner();
    let observed = owner.observed();
    if held.root() != observed.identity().root()
        || held.physical_identity() != observed.identity().physical_identity()
    {
        return Err(denied());
    }
    let operation_bytes = observed
        .logical()
        .get(owner.key())
        .and_then(Option::as_deref)
        .ok_or_else(denied)?;
    let operation = PermanentDeleteOperation::decode(operation_bytes).map_err(|_| denied())?;
    if &operation.authorization != owner.authorization()
        || operation.owner.as_ref() != Some(owner.owner())
    {
        return Err(denied());
    }
    let pointer = operation.pass.as_ref().ok_or_else(denied)?;
    let read = crate::bucket::permanent_restore::read_pass(
        held.fs(),
        owner.backend_control(),
        &pointer.key,
        observed.configured_operator_uid(),
        owner.authorization().exclusion().cycle,
    )
    .await?;
    let bytes = read.bytes().ok_or_else(denied)?;
    operation
        .check_pass(bytes, owner.key())
        .map_err(|_| denied())?;
    let pass = PermanentDeletePass::decode(bytes).map_err(|_| denied())?;
    let selected_lease = observed
        .logical()
        .get("gc/lease")
        .and_then(Option::as_deref)
        .ok_or_else(denied)?;
    let selected_lease = GcLease::decode(selected_lease).map_err(|_| denied())?;
    if &selected_lease != owner.session().lease()
        || pass.lease != selected_lease
        || observed.state().binding != pass.backend
        || !pass.observations.iter().any(|observation| {
            observation.artifact == artifact
                && observation.instance == ObservedInstance::Unversioned
                && observation.state == ObservationState::Planned
        })
    {
        return Err(denied());
    }
    let result = CheckedPermanentReclaim {
        current,
        artifact,
        key: pointer.key.clone(),
        bytes: bytes.to_vec(),
        pass,
        read,
    };
    current.revalidate().await?;
    Ok(result)
}
