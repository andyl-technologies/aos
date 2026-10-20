//! Resolves exact immutable owner and genesis records from a retained selected chain.

use super::{SelectedObservation, denied, physical::PhysicalReads};
use crate::store::StoreFailure;
use std::path::{Path, PathBuf};
use terrane_format::bucket::{BucketCapabilities, GenerationManifest};
use terrane_format::gc::publication::{
    Activation, BackendBinding, BackendRegistration, PermanentOwnerSelection, PublicationCommit,
    PublicationProof, PublicationTransaction,
};
use terrane_format::gc::retirement::{
    OperationPhase, OwnershipSlot, PermanentDeleteAuthorization, PermanentDeleteOperation,
    RecordPointer,
};

/// Resolves permanent ownership records from the retained selected publication chain.
pub(super) struct ResolvedOwner {
    /// Names the backend control directory containing the retained immutable slots.
    pub(super) backend_control: PathBuf,
    /// Retains the authorization bound to the selected permanent owner.
    pub(super) authorization: PermanentDeleteAuthorization,
    /// Identifies the genesis slot bound to the active backend registration.
    pub(super) genesis: OwnershipSlot,
    /// Identifies the slot that selected the permanent retirement authorization.
    pub(super) owner: OwnershipSlot,
    /// Binds the selected operation key to the canonical authorization digest.
    pub(super) selected_owner: RecordPointer,
}

/// Resolves a publication slot and its bound transaction from retained physical reads.
///
/// # Errors
/// Refuses missing retained slot or proposal bytes, invalid encodings, mismatched
/// slot keys or transaction bindings, and revisions that differ from the request.
pub(super) fn transaction(
    physical: &PhysicalReads<'_>,
    control: &Path,
    revision: u64,
) -> Result<(OwnershipSlot, PublicationTransaction), StoreFailure> {
    let key = format!("publication/commits/{revision}");
    let bytes = physical.bytes(control, &key)?;
    let commit = PublicationCommit::decode(bytes).map_err(|_| denied())?;
    let proposal = physical.bytes(control, &commit.transaction_key)?;
    commit
        .check_transaction(&key, proposal)
        .map_err(|_| denied())?;
    let proposal = PublicationTransaction::decode(proposal).map_err(|_| denied())?;
    if commit.revision != revision || proposal.new.revision != revision {
        return Err(denied());
    }
    Ok((
        OwnershipSlot {
            revision,
            digest: *blake3::hash(bytes).as_bytes(),
        },
        proposal,
    ))
}

/// Resolves already-selected permanent ownership without granting first-owner rights.
///
/// # Errors
/// Refuses unknown owner completeness, visibility-only burns, wrong backend,
/// missing selected immutable history or conflicting authorization associations.
pub(super) fn resolve(
    observed: &SelectedObservation<'_>,
    key: &str,
) -> Result<ResolvedOwner, StoreFailure> {
    let operation_bytes = observed
        .logical()
        .get(key)
        .and_then(Option::as_deref)
        .ok_or_else(denied)?;
    let operation = PermanentDeleteOperation::decode(operation_bytes).map_err(|_| denied())?;
    if operation.phase == OperationPhase::Cancelled {
        return Err(denied());
    }
    let authorization = operation.authorization;
    authorization.check_key(key).map_err(|_| denied())?;
    if authorization.backend() != &observed.state().binding
        || !matches!(authorization.backend(), BackendBinding::Local { .. })
    {
        return Err(denied());
    }
    let pack = authorization.exclusion().pack;
    let selector = observed
        .state()
        .burn_owners
        .as_ref()
        .and_then(|owners| owners.iter().find(|owner| owner.pack == pack))
        .ok_or_else(denied)?;
    let PermanentOwnerSelection::Permanent(pointer) = &selector.selection else {
        return Err(denied());
    };
    let canonical = authorization.encode().map_err(|_| denied())?;
    if pointer.key != key || pointer.digest != *blake3::hash(&canonical).as_bytes() {
        return Err(denied());
    }

    let capabilities = observed
        .logical()
        .get("CAPABILITIES")
        .and_then(Option::as_deref)
        .ok_or_else(denied)?;
    let capabilities = BucketCapabilities::decode(capabilities).map_err(|_| denied())?;
    let generation = capabilities.generation.ok_or_else(denied)?;
    let manifest = observed
        .logical()
        .get(&format!("objects/index/{generation}/MANIFEST"))
        .and_then(Option::as_deref)
        .ok_or_else(denied)?;
    let manifest = GenerationManifest::decode(manifest).map_err(|_| denied())?;
    if manifest
        .burns
        .as_ref()
        .is_none_or(|burns| burns.binary_search(&pack).is_err())
    {
        return Err(denied());
    }

    let registration = observed.physical_reads().first().ok_or_else(denied)?;
    let control = registration.path().parent().ok_or_else(denied)?;
    if registration.path() != control.join("backend-registration.cbor") {
        return Err(denied());
    }
    let registration = BackendRegistration::decode(registration.bytes().ok_or_else(denied)?)
        .map_err(|_| denied())?;
    if registration.activation != Activation::Active
        || registration.binding != observed.state().binding
    {
        return Err(denied());
    }
    let physical = PhysicalReads::new(observed);
    let (genesis, genesis_transaction) = transaction(&physical, control, 0)?;
    if registration.genesis != Some(genesis.digest)
        || genesis_transaction.old.is_some()
        || genesis_transaction.predecessor.is_some()
        || genesis_transaction.new.binding != registration.binding
    {
        return Err(denied());
    }
    if let PermanentDeleteAuthorization::Copied(copied) = &authorization
        && copied.genesis != genesis
    {
        return Err(denied());
    }

    // The exact authorization determines one owner revision. Only its actual
    // selected case-3 transaction can establish irreversible ownership.
    let revision = match &authorization {
        PermanentDeleteAuthorization::Sweep(value) => &value.fence.key,
        PermanentDeleteAuthorization::Copied(value) => &value.fence.key,
    }
    .rsplit('/')
    .next()
    .ok_or_else(denied)?
    .parse::<u64>()
    .map_err(|_| denied())?
    .checked_add(1)
    .ok_or_else(denied)?;
    let (owner, owner_transaction) = transaction(&physical, control, revision)?;
    authorization
        .check_owner_slot(&owner)
        .map_err(|_| denied())?;
    let PublicationProof::PermanentRetirement {
        authorization: selected_authorization,
        ..
    } = &owner_transaction.proof
    else {
        return Err(denied());
    };
    if selected_authorization != &canonical
        || owner_transaction.new.binding != observed.state().binding
        || owner_transaction
            .new
            .burn_owners
            .as_ref()
            .is_none_or(|owners| {
                !owners
                    .iter()
                    .any(|owner| owner.pack == pack && owner.selection == selector.selection)
            })
    {
        return Err(denied());
    }
    let initial = owner_transaction
        .changes
        .iter()
        .find(|change| change.key == key)
        .and_then(|change| change.new.as_deref())
        .ok_or_else(denied)?;
    let initial = PermanentDeleteOperation::decode(initial).map_err(|_| denied())?;
    if initial.phase != OperationPhase::Proposed
        || initial.authorization != authorization
        || initial.owner.is_some()
        || initial.pass.is_some()
        || operation
            .owner
            .as_ref()
            .is_some_and(|selected| selected != &owner)
    {
        return Err(denied());
    }
    Ok(ResolvedOwner {
        backend_control: control.to_path_buf(),
        authorization,
        genesis,
        owner,
        selected_owner: pointer.clone(),
    })
}
