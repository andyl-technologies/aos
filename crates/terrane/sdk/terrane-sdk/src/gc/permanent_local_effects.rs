//! Captures whole current owner, DATA, Original and lease inputs for native requests.
//!
//! Every request consumes the same selected holder and live Session as its
//! independently checked current DATA carrier. Native observations are physical
//! receipts only; they cannot expand this selected permission.

use super::super::artifact_seal::permanent_local::{effects, observation};
use super::super::artifact_seal::restore_pair::eligible_data_pair_plan;
use super::{BucketBinding, FencePolicy, Frame, LocalFs, StoreFailure, corrupt, io_failure};
use crate::selected_bridge::native_copied_placement::CheckedOwnedPlacement;
use crate::selected_bridge::native_permanent_local::{
    CheckedPermanentLocalOwner, CheckedPermanentReclaim,
};

#[path = "permanent_local_effects/publication.rs"]
mod publication;
pub(crate) use publication::publish_observed;

#[path = "permanent_local_effects/admission.rs"]
mod admission;
pub(crate) use admission::{publish_candidate, stage_candidate};

/// Exposes only actual worker-produced family observations to the closed selector.
pub(crate) use super::super::artifact_seal::permanent_local::NativePermanentObservation;
pub(crate) use super::super::artifact_seal::permanent_local::effects::NativeReclaimReceipt;

/// Extracts actual owned source descriptors without a complete serving DATA premise.
///
/// This raw physical receipt is provisional. Fresh admission requires separate
/// complete content and dependency verification; it never restores serving P.
///
/// # Errors
/// Refuses stale selected ownership, current Guard, Original controls or lease,
/// missing or unsafe source leaves and absent real native extraction receipt.
pub(crate) async fn extract_owned<F: LocalFs + BucketBinding>(
    fs: &F,
    owner: &CheckedPermanentLocalOwner<'_, '_>,
) -> Result<NativePermanentObservation, StoreFailure> {
    let (mut frame, control) = capture_owned(fs, owner).await?;
    let expected = owner
        .observed()
        .logical()
        .get(owner.key())
        .and_then(Option::as_deref)
        .ok_or_else(corrupt)?;
    let root = owner.observed().identity().root();
    let id = crate::pack::PackId::from_random_bytes(owner.pack());
    let path = root.join(id.pack_key());
    let shard = path.parent().ok_or_else(corrupt)?;
    let mut parent = root.to_owned();
    for component in shard
        .strip_prefix(root)
        .map_err(|_| corrupt())?
        .components()
    {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(corrupt());
        }
        parent.push(component);
        let metadata = fs
            .symlink_metadata(&parent)
            .await
            .map_err(super::io_failure)?;
        let stamp = super::MetadataStamp::checked(&metadata).map_err(super::io_failure)?;
        frame
            .name(
                fs,
                parent.clone(),
                stamp.identity,
                FencePolicy::NamespaceDirectory { owner: frame.owner },
                None,
            )
            .await?;
    }
    owner.revalidate().await?;
    let (plan, receiver) = observation::plan(
        root,
        &control,
        owner.key(),
        expected.to_vec(),
        (Vec::new(), Vec::new()),
        frame.owner,
        observation::ObservationPurpose::ExtractEligible,
    )
    .map_err(crate::selected_bridge::native_restore_failure)?;
    frame.execute(fs, plan).await?;
    owner.revalidate().await?;
    receiver
        .take()
        .map_err(crate::selected_bridge::native_restore_failure)
}

async fn capture_owned<F: LocalFs + BucketBinding>(
    fs: &F,
    owner: &CheckedPermanentLocalOwner<'_, '_>,
) -> Result<(Frame, std::path::PathBuf), StoreFailure> {
    owner.revalidate().await?;
    crate::selected_bridge::native_collection::revalidate_controls(
        fs,
        owner.controls(),
        owner.control_pins(),
    )
    .await?;
    let (mut frame, control) = super::collection_checkpoints::retained_controls_frame(
        fs,
        owner.observed(),
        owner.guard(),
        owner.effects(),
    )
    .await?;
    let expected = owner
        .observed()
        .logical()
        .get(owner.key())
        .and_then(Option::as_deref)
        .ok_or_else(corrupt)?;
    let actual = frame
        .actual_read(
            fs,
            &control.join(owner.key()),
            FencePolicy::ProtectedRecord { owner: frame.owner },
        )
        .await?;
    if actual.as_deref() != Some(expected) {
        if let Some(bytes) = actual {
            let cache = terrane_format::gc::retirement::PermanentDeleteOperation::decode(&bytes)
                .map_err(|_| corrupt())?;
            if &cache.authorization != owner.authorization()
                || cache
                    .owner
                    .as_ref()
                    .is_some_and(|slot| slot != owner.owner())
            {
                return Err(corrupt());
            }
        }
        owner.revalidate().await?;
        frame
            .install(
                fs,
                &control,
                owner.key(),
                expected,
                FencePolicy::ProtectedRecord { owner: frame.owner },
                terrane_format::bucket::Mutability::CompareAndSwap,
            )
            .await?;
    }
    Ok((frame, control))
}

async fn capture_parent<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    checked: &CheckedOwnedPlacement<'_, '_>,
    parent: &std::path::Path,
) -> Result<(), StoreFailure> {
    let root = checked.owner().observed().identity().root();
    let relative = parent.strip_prefix(root).map_err(|_| corrupt())?;
    let mut path = root.to_owned();
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(corrupt());
        }
        path.push(component);
        checked.revalidate().await?;
        match fs.symlink_metadata(&path).await {
            Ok(metadata) => {
                let stamp = super::MetadataStamp::checked(&metadata).map_err(io_failure)?;
                frame
                    .name(
                        fs,
                        path.clone(),
                        stamp.identity,
                        FencePolicy::NamespaceDirectory { owner: frame.owner },
                        None,
                    )
                    .await?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let actual = frame
                    .actual_read(fs, &path, FencePolicy::Payload { owner: frame.owner })
                    .await?;
                if actual.is_some() {
                    return Err(corrupt());
                }
                // Retain the FIRST missing ancestor, not optimistic descendant
                // absence. Every native refresh checks this exact anchor again.
                checked.revalidate().await?;
                return Ok(());
            }
            Err(error) => return Err(io_failure(error)),
        }
    }
    checked.revalidate().await
}

/// Captures fresh physical ancestry inside one bracketed readonly request.
///
/// The caller requalifies the whole current placement before and after its
/// complete parent vector. This helper still reads every original ancestor,
/// validates its name/policy/incarnation, and retains the first absent anchor.
/// It grants no effect permission; reclamation uses `capture_parent` instead.
async fn capture_observation_parent<F: LocalFs + BucketBinding>(
    fs: &F,
    frame: &mut Frame,
    root: &std::path::Path,
    parent: &std::path::Path,
) -> Result<(), StoreFailure> {
    let relative = parent.strip_prefix(root).map_err(|_| corrupt())?;
    let mut path = root.to_owned();
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(corrupt());
        }
        path.push(component);
        match fs.symlink_metadata(&path).await {
            Ok(metadata) => {
                let stamp = super::MetadataStamp::checked(&metadata).map_err(io_failure)?;
                frame
                    .name(
                        fs,
                        path.clone(),
                        stamp.identity,
                        FencePolicy::NamespaceDirectory { owner: frame.owner },
                        None,
                    )
                    .await?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let actual = frame
                    .actual_read(fs, &path, FencePolicy::Payload { owner: frame.owner })
                    .await?;
                if actual.is_some() {
                    return Err(corrupt());
                }
                // Retain the FIRST missing ancestor, not optimistic descendant
                // absence. Every native refresh checks this exact anchor again.
                return Ok(());
            }
            Err(error) => return Err(io_failure(error)),
        }
    }
    Ok(())
}

async fn capture<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedOwnedPlacement<'_, '_>,
) -> Result<(Frame, std::path::PathBuf), StoreFailure> {
    checked.revalidate().await?;
    let data = checked.data();
    let owner = checked.owner();
    if !std::ptr::eq(data.observed(), owner.observed())
        || !std::ptr::eq(data.session(), owner.session())
        || data.pack() != owner.pack()
        || data.guard().path() != owner.guard().path()
        || data.guard().bytes() != owner.guard().bytes()
        || !data.effects().controls().iter().any(|controls| {
            controls.directory() == owner.controls().directory()
                && controls.identities() == owner.controls().identities()
                && controls.owner() == owner.controls().owner()
        })
    {
        return Err(corrupt());
    }
    crate::selected_bridge::native_collection::revalidate_controls(
        fs,
        owner.controls(),
        owner.control_pins(),
    )
    .await?;
    let (mut frame, control) = super::collection_checkpoints::retained_controls_frame(
        fs,
        data.observed(),
        data.guard(),
        data.effects(),
    )
    .await?;
    for record in owner.controls().records() {
        let actual = frame
            .actual_read(
                fs,
                record.path(),
                FencePolicy::ProtectedRecord { owner: frame.owner },
            )
            .await?;
        if actual.as_deref() != Some(record.bytes()) {
            return Err(corrupt());
        }
    }
    for read in data.reads() {
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::Payload { owner: frame.owner },
            )
            .await?;
    }
    // Keep the original current check while each actual acknowledgment extends
    // the retained prefix. Forward and reverse observations bracket earlier
    // pairs without recursively duplicating their checks.
    let base_current = frame.final_check.clone().ok_or_else(corrupt)?;
    let mut pairs = Vec::with_capacity(data.packs().len());

    for pack in data.packs() {
        frame
            .observed_read(
                fs,
                pack.index().path(),
                pack.index().bytes(),
                pack.index().metadata(),
                FencePolicy::Payload { owner: frame.owner },
            )
            .await?;
        let (plan, receiver) = eligible_data_pair_plan(
            data.observed().identity().root(),
            &control,
            pack,
            frame.owner,
        )
        .map_err(crate::selected_bridge::native_restore_failure)?;
        frame.execute(fs, plan).await?;
        let pair = receiver
            .take()
            .map_err(crate::selected_bridge::native_restore_failure)?;
        pairs.push(pair);
        frame.final_check = Some(base_current.with_restore_pairs(&pairs));
    }
    let expected = data
        .observed()
        .logical()
        .get(owner.key())
        .and_then(Option::as_deref)
        .ok_or_else(corrupt)?;
    let actual = frame
        .actual_read(
            fs,
            &control.join(owner.key()),
            FencePolicy::ProtectedRecord { owner: frame.owner },
        )
        .await?;
    if actual.as_deref() != Some(expected) {
        // Selection comes from immutable slot history. The mutable cache can
        // lag a selected event or contain an unselected attempted successor;
        // neither cache state replaces that independently checked authority.
        if let Some(bytes) = actual {
            let cached = terrane_format::gc::retirement::PermanentDeleteOperation::decode(&bytes)
                .map_err(|_| corrupt())?;
            if &cached.authorization != owner.authorization()
                || cached
                    .owner
                    .as_ref()
                    .is_some_and(|slot| slot != owner.owner())
            {
                return Err(corrupt());
            }
        }
        checked.revalidate().await?;
        frame
            .install(
                fs,
                &control,
                owner.key(),
                expected,
                FencePolicy::ProtectedRecord { owner: frame.owner },
                terrane_format::bucket::Mutability::CompareAndSwap,
            )
            .await?;
        checked.revalidate().await?;
    }
    checked.revalidate().await?;
    Ok((frame, control))
}

/// Observes fixed family leaves under complete current retained prerequisites.
///
/// # Errors
/// Refuses mismatched holders, unavailable current DATA or Original pins, unsafe
/// ancestry, unprotected owner records, changed leases and no-op execution.
///
/// # Panics
/// In test builds, panics if opt-in phase diagnostics cannot write to
/// standard error.
async fn observe_for<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedOwnedPlacement<'_, '_>,
    cycles: Vec<u64>,
    purpose: observation::ObservationPurpose,
    history: &crate::selected_bridge::native_permanent_local::history::History,
) -> Result<NativePermanentObservation, StoreFailure> {
    #[cfg(test)]
    let trace = crate::ref_advance::NativeTrace::new(
        checked.owner().observed().identity().root(),
        "permanent-observation-producer",
    );
    let (mut frame, control) = capture(fs, checked).await?;
    #[cfg(test)]
    trace.mark("frame-captured");

    let owner = checked.owner();
    for read in history.reads() {
        frame
            .observed_read(
                fs,
                read.path(),
                read.bytes(),
                read.metadata(),
                FencePolicy::ProtectedRecord { owner: frame.owner },
            )
            .await?;
    }
    #[cfg(test)]
    trace.mark("history-captured");

    let root = owner.observed().identity().root();
    let id = crate::pack::PackId::from_random_bytes(owner.pack());
    let pack_path = root.join(id.pack_key());
    let shard = pack_path.parent().ok_or_else(corrupt)?;
    let mut parents = vec![shard.to_owned(), root.join("trash")];
    parents.extend(
        cycles
            .iter()
            .map(|cycle| root.join(format!("trash/{cycle}"))),
    );
    #[cfg(test)]
    trace.mark(&format!("parent-paths-fixed count={}", parents.len()));

    // These are internal physical reads of one fixed observation request, not
    // separate requests or effects. Fresh whole authority brackets the vector;
    // each ancestor still contributes its actual checked physical preimage.
    checked.revalidate().await?;
    for parent in parents {
        capture_observation_parent(fs, &mut frame, root, &parent).await?;
    }
    checked.revalidate().await?;
    #[cfg(test)]
    trace.mark("parents-captured");

    let bytes = owner
        .observed()
        .logical()
        .get(owner.key())
        .and_then(Option::as_ref)
        .ok_or_else(corrupt)?
        .clone();
    let (plan, receiver) = observation::plan(
        root,
        &control,
        owner.key(),
        bytes,
        (cycles, history.visited().into_iter().collect()),
        frame.owner,
        purpose,
    )
    .map_err(crate::selected_bridge::native_restore_failure)?;
    #[cfg(test)]
    trace.mark("native-plan-fixed");
    #[cfg(test)]
    trace.mark("native-execute-submitting");

    frame.execute(fs, plan).await?;
    #[cfg(test)]
    trace.mark("native-execute-returned");

    checked.revalidate().await?;
    #[cfg(test)]
    trace.mark("current-revalidated");

    receiver
        .take()
        .map_err(crate::selected_bridge::native_restore_failure)
}

/// Observes fixed family leaves under complete current retained prerequisites.
///
/// # Errors
/// Refuses stale owner, DATA, Original or lease inputs, unsafe physical instances
/// and missing native completion.
///
/// # Panics
/// In test builds, panics if opt-in phase diagnostics cannot write to
/// standard error.
pub(crate) async fn observe<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedOwnedPlacement<'_, '_>,
    cycles: Vec<u64>,
    history: &crate::selected_bridge::native_permanent_local::history::History,
) -> Result<NativePermanentObservation, StoreFailure> {
    observe_for(
        fs,
        checked,
        cycles,
        observation::ObservationPurpose::Discover,
        history,
    )
    .await
}

/// Reclaims only one selected Planned instance through actual native completion.
///
/// # Errors
/// Refuses stale selected progress, replaced instances, changed Original or DATA
/// predicates, expired leases, partial unlink/durability and missing native receipt.
pub(crate) async fn reclaim<F: LocalFs + BucketBinding>(
    fs: &F,
    checked: &CheckedPermanentReclaim<'_, '_, '_>,
    observed: std::sync::Arc<NativePermanentObservation>,
) -> Result<NativeReclaimReceipt, StoreFailure> {
    checked.revalidate().await?;
    let (mut frame, control) = capture(fs, checked.current()).await?;
    checked
        .pass()
        .check_owner(
            checked.current().owner().authorization(),
            checked.current().owner().key(),
            checked.current().owner().owner(),
        )
        .map_err(|_| corrupt())?;
    let path = control.join(checked.key());
    if checked.read().path() != path {
        return Err(corrupt());
    }
    frame
        .observed_read(
            fs,
            checked.read().path(),
            checked.read().bytes(),
            checked.read().metadata(),
            FencePolicy::ProtectedRecord { owner: frame.owner },
        )
        .await?;
    let actual = frame
        .actual_read(
            fs,
            &path,
            FencePolicy::ProtectedRecord { owner: frame.owner },
        )
        .await?;
    if actual.as_deref() != Some(checked.bytes()) {
        return Err(corrupt());
    }
    // Only retained names needed by the actual instance are captured. Other
    // residues are separate future requests, not assumed absent or unchanged.
    let owner = checked.current().owner();
    let id = crate::pack::PackId::from_random_bytes(owner.pack());
    let key = match checked.artifact() {
        terrane_format::gc::retirement::ObservedArtifact::Pack => id.pack_key(),
        terrane_format::gc::retirement::ObservedArtifact::Index => id.index_key(),
        terrane_format::gc::retirement::ObservedArtifact::Trash(cycle) => {
            format!("trash/{cycle}/{id}")
        }
    };
    let target = owner.observed().identity().root().join(key);
    if !observed.paths().any(|path| path == target) {
        return Err(corrupt());
    }
    let parent = target.parent().ok_or_else(corrupt)?;
    capture_parent(fs, &mut frame, checked.current(), parent).await?;
    let (plan, receiver) =
        effects::plan(checked, observed).map_err(crate::selected_bridge::native_restore_failure)?;
    frame.execute(fs, plan).await?;
    checked.revalidate().await?;
    let receipt = receiver
        .take()
        .map_err(crate::selected_bridge::native_restore_failure)?;
    if receipt.path() != target {
        return Err(corrupt());
    }
    Ok(receipt)
}
