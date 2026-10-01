//! Native control of resumable storage-local managed R2 mirror imports.
//!
//! Every invocation reloads the retained SQL original. Controls contain only
//! the immutable selection and bounded progress; source bytes stay with Worker
//! Fetch and R2. Unknown mutations stop the controller until an exact positive
//! guard receipt can be read. Neither scheduler leases nor retries invent a new
//! source, destination or effect identity.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::db::{Database, RegistryRecord, SurfaceTarget};
use aos_hub_core::mirror_work::{
    MirrorOriginal, MirrorProgress, MirrorStep, MirrorVerification, MIRROR_MAX_PARTS_PER_STEP,
    MIRROR_PART_BYTES,
};
use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkOutcome};

use crate::fetch::SurfaceFetch as _;
use crate::storage_work::RemoteStorageWorkClient;

mod batch;
mod discovery;
mod live;
mod publication;
mod selection;

pub(crate) use live::delivery as live_delivery;
pub(crate) use live::metadata as live_metadata;
pub(crate) use live::batch::metadata as live_metadata_batch;

use discovery::MetadataDiscovery;

/// Imports one Native-selected immutable representation without receiving it.
///
/// # Errors
/// Returns an error for unsupported source capabilities, changed SQL authority,
/// missing producer acceptance, unknown provider effects or invalid proof.
pub async fn import_object(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry: &RegistryRecord,
    path: &str,
    verification: MirrorVerification,
) -> Result<MirrorProgress> {
    let prepared = prepare_object(db, work, registry, path, verification, None).await?;
    publish_object(db, work, prepared, None).await
}

struct PreparedObject {
    original: MirrorOriginal,
    verified: aos_hub_core::mirror_work::MirrorVerifiedObject,
    committed: bool,
}

enum Admission {
    Ready(PreparedObject),
    Active {
        original: MirrorOriginal,
        progress: Option<MirrorProgress>,
    },
}

async fn prepare_object(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry: &RegistryRecord,
    path: &str,
    verification: MirrorVerification,
    selection: Option<&selection::Selection>,
) -> Result<PreparedObject> {
    let (original, progress) =
        match admit_object(db, work, registry, path, verification, selection).await? {
            Admission::Ready(prepared) => return Ok(prepared),
            Admission::Active { original, progress } => (original, progress),
        };
    let mut progress = match progress {
        Some(progress) => progress,
        None => {
            run_step(
                db,
                work,
                &original,
                MirrorStep::Status { destination: false },
            )
            .await?
        }
    };
    if progress.stage_upload_id.is_none() && progress.stage_object.is_none() {
        progress = run_step(db, work, &original, MirrorStep::Begin).await?;
    }
    let part_count = original.verification.size().div_ceil(MIRROR_PART_BYTES) as usize;
    while progress.stage_parts.len() < part_count {
        progress = run_step(
            db,
            work,
            &original,
            MirrorStep::UploadParts {
                first_part: progress.stage_parts.len() as u32 + 1,
                maximum_parts: MIRROR_MAX_PARTS_PER_STEP,
            },
        )
        .await?;
    }
    if progress.stage_object.is_none() {
        progress = run_step(db, work, &original, MirrorStep::CloseStage).await?;
    }
    if progress.verified.is_none() {
        progress = run_step(db, work, &original, MirrorStep::VerifyStage).await?;
    }

    prepared(original, &progress, false)
}

async fn admit_object(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry: &RegistryRecord,
    path: &str,
    verification: MirrorVerification,
    selected: Option<&selection::Selection>,
) -> Result<Admission> {
    verification.validate()?;
    let fresh_selection;
    let selected = match selected {
        Some(selected) => selected,
        None => {
            let source = db
                .registry_mirror(registry.id)
                .await?
                .context("registry is not a mirror")?;
            fresh_selection = selection::Selection::capture(db, work, registry, source).await?;
            &fresh_selection
        }
    };
    selected.validate_current(db, work, registry).await?;
    if let Some(retained) = db.mirror_import_for_path(registry.id, path).await? {
        if retained.state == "published" {
            let progress = retained
                .progress
                .as_ref()
                .context("published mirror lacks retained final proof")?;
            ensure!(
                retained.original.verification == verification,
                "published mirror retains another source original"
            );
            db.validate_mirror_import_authority(&retained.original)
                .await?;
            // Independent guard readback and current SQL publication consume
            // these held positives without granting another provider effect.
            return Ok(Admission::Ready(prepared(
                retained.original.clone(),
                progress,
                false,
            )?));
        }
        if retained.state == "committed" {
            let progress = retained
                .progress
                .context("committed mirror has no final proof")?;
            // Only the qualified atomic catalogue transaction can authorize
            // reuse. Historical terminal journals remain ACK/recovery facts.
            let reuse = async {
                Ok::<_, anyhow::Error>(
                    retained.original.verification == verification
                        && db
                            .mirror_committed_catalogue_matches(&retained.original, &progress)
                            .await?
                        && current_destination_matches(db, work, &retained.original, &progress)
                            .await?
                        && db
                            .mirror_committed_catalogue_matches(&retained.original, &progress)
                            .await?,
                )
            }
            .await;
            // ACK is independent of producer expiry or failed fresh HEAD.
            acknowledge(db, work, &retained.original, &progress).await?;
            if reuse? {
                return Ok(Admission::Ready(prepared(
                    retained.original,
                    &progress,
                    true,
                )?));
            }
        }
    }
    ensure!(
        path.len() <= 512,
        "new mirror catalogue paths must fit 512 UTF-8 bytes"
    );
    let source = &selected.source;
    let placement = &selected.placement;
    let binding = &selected.binding;
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some(uuid::Uuid::new_v4().simple().to_string()),
        registry_id: registry.id,
        registry_resource_version: registry.resource_version,
        mirror_resource_version: source.resource_version,
        upstream_base: source.source_url.clone(),
        path: path.into(),
        placement_id: placement.id,
        placement_resource_version: placement.resource_version,
        write_spec_version: placement.write_spec_version,
        binding_id: binding.id,
        binding_resource_version: binding.resource_version,
        placement_prefix: placement.prefix.clone(),
        protected_profile_digest: selected.profile_digest.clone(),
        verification,
    };
    original.job_id = original.identity()?;
    let retained = match db.mirror_import_for_path(registry.id, path).await? {
        Some(retained) => retained,
        None => match db
            .admit_mirror_import(&original, aos_hub_core::clock::now_unix_secs())
            .await
        {
            Ok(retained) => retained,
            Err(error) => db
                .mirror_import_for_path(registry.id, path)
                .await?
                .ok_or(error)?,
        },
    };
    // The winner's operation generation survives retries and competing leases.
    original.copy_operation_id = retained.original.copy_operation_id.clone();
    original.job_id = original.identity()?;
    ensure!(
        retained.original == original,
        "mirror path retains a conflicting source or destination original"
    );

    // A committed object still holds its physical owner until positive ACK.
    // Recover it directly, without replaying source reads or provider effects.
    if retained.state == "committed" {
        let progress = retained
            .progress
            .context("committed mirror has no final proof")?;
        let reuse = async {
            Ok::<_, anyhow::Error>(
                db.mirror_committed_catalogue_matches(&original, &progress)
                    .await?
                    && current_destination_matches(db, work, &original, &progress).await?
                    && db
                        .mirror_committed_catalogue_matches(&original, &progress)
                        .await?,
            )
        }
        .await;
        acknowledge(db, work, &original, &progress).await?;
        ensure!(
            reuse?,
            "retired mirror destination changed; a fresh operation is required"
        );
        return Ok(Admission::Ready(prepared(original, &progress, true)?));
    }

    Ok(Admission::Active {
        original,
        progress: retained.progress,
    })
}

async fn publish_object(
    db: &Database,
    work: &RemoteStorageWorkClient,
    prepared: PreparedObject,
    publication_id: Option<&str>,
) -> Result<MirrorProgress> {
    let PreparedObject {
        original,
        verified,
        committed,
    } = prepared;
    if committed {
        return archived_progress(work, &original, &verified).await;
    }
    let retained = db
        .mirror_import(&original.job_id)
        .await?
        .context("prepared mirror original disappeared")?;
    ensure!(
        retained.original == original,
        "prepared mirror original changed"
    );
    let mut progress = retained
        .progress
        .context("prepared mirror progress disappeared")?;
    ensure!(
        progress.verified.as_ref() == Some(&verified),
        "prepared mirror verification changed during manifest admission"
    );
    ensure!(
        original.path.len() <= 512 || progress.destination.is_some(),
        "mirror final catalogue paths must fit 512 UTF-8 bytes"
    );
    let part_count = original.verification.size().div_ceil(MIRROR_PART_BYTES) as usize;
    // Destination Status observes a distinct key owner. It is not a source
    // proof; BeginPromotion independently asks the private source guard.
    if progress.destination.is_none() {
        let destination = run_step(
            db,
            work,
            &original,
            MirrorStep::Status { destination: true },
        )
        .await?;
        if destination.verified.is_some() {
            progress = destination;
        }
    }
    if progress.destination_upload_id.is_none() && progress.destination.is_none() {
        progress = run_publication_step(
            db,
            work,
            &original,
            MirrorStep::BeginPromotion,
            publication_id,
        )
        .await?;
    }
    while progress.destination_parts.len() < part_count {
        progress = run_publication_step(
            db,
            work,
            &original,
            MirrorStep::CopyParts {
                first_part: progress.destination_parts.len() as u32 + 1,
                maximum_parts: MIRROR_MAX_PARTS_PER_STEP,
            },
            publication_id,
        )
        .await?;
    }
    if progress.destination.is_none() {
        progress = run_publication_step(
            db,
            work,
            &original,
            MirrorStep::CompletePromotion,
            publication_id,
        )
        .await?;
    }

    // Retain the exact positive provider facts before independent readback.
    // A quota or catalogue refusal must not erase completed physical effects.
    db.record_mirror_import_progress(
        &original,
        &progress,
        false,
        aos_hub_core::clock::now_unix_secs(),
    )
    .await?;
    let proof = work.lookup_mirror_final_guard(&original, &progress).await?;
    db.commit_mirror_import(
        &original,
        &progress,
        &proof,
        publication_id,
        aos_hub_core::clock::now_unix_secs(),
    )
    .await?;
    acknowledge(db, work, &original, &progress).await?;
    Ok(progress)
}

fn prepared(
    original: MirrorOriginal,
    progress: &MirrorProgress,
    committed: bool,
) -> Result<PreparedObject> {
    progress.validate(&original)?;
    Ok(PreparedObject {
        original,
        verified: progress
            .verified
            .clone()
            .context("prepared mirror has no verified stage")?,
        committed,
    })
}

async fn archived_progress(
    work: &RemoteStorageWorkClient,
    original: &MirrorOriginal,
    verified: &aos_hub_core::mirror_work::MirrorVerifiedObject,
) -> Result<MirrorProgress> {
    let now = aos_hub_core::clock::now_unix_secs();
    let plan = aos_hub_core::storage_work::StorageWorkPlan {
        version: 1,
        plan_id: uuid::Uuid::new_v4().simple().to_string(),
        deployment_id: work.deployment_id().into(),
        issued_at: now,
        expires_at: now
            .checked_add(30)
            .context("mirror status expiry overflow")?,
        placement_id: original.placement_id,
        placement_resource_version: original.placement_resource_version,
        binding_id: original.binding_id,
        binding_resource_version: original.binding_resource_version,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: vec![],
        placement_prefix: original.placement_prefix.clone(),
        operation: StorageWorkOperation::MirrorTransfer {
            original: original.clone(),
            step: MirrorStep::Status { destination: true },
        },
    };
    let StorageWorkOutcome::MirrorProgress { progress } = work.execute(&plan).await?.outcome else {
        anyhow::bail!("mirror archived status returned another result");
    };
    progress.commit_digest(original)?;
    ensure!(
        progress.verified.as_ref() == Some(verified),
        "mirror archived status changed exact verification"
    );
    Ok(progress)
}

async fn current_destination_matches(
    db: &Database,
    work: &RemoteStorageWorkClient,
    original: &MirrorOriginal,
    progress: &MirrorProgress,
) -> Result<bool> {
    db.validate_mirror_import_authority(original).await?;
    let placement = db
        .surface_placement(original.placement_id)
        .await?
        .context("mirror placement disappeared")?;
    let binding = db
        .binding(original.binding_id)
        .await?
        .context("mirror binding disappeared")?;
    let plan = work.plan_for_placement(
        &placement,
        &binding,
        StorageWorkOperation::Head {
            path: original.path.clone(),
        },
        aos_hub_core::clock::now_unix_secs(),
    )?;
    let outcome = work.execute(&plan).await?.outcome;
    db.validate_mirror_import_authority(original).await?;
    match outcome {
        StorageWorkOutcome::Head { object } => Ok(progress
            .destination
            .as_ref()
            .is_some_and(|destination| destination.object == object)),
        StorageWorkOutcome::NotFound => Ok(false),
        _ => anyhow::bail!("mirror current destination returned another result"),
    }
}

async fn run_step(
    db: &Database,
    work: &RemoteStorageWorkClient,
    original: &MirrorOriginal,
    step: MirrorStep,
) -> Result<MirrorProgress> {
    run_publication_step(db, work, original, step, None).await
}

async fn run_publication_step(
    db: &Database,
    work: &RemoteStorageWorkClient,
    original: &MirrorOriginal,
    step: MirrorStep,
    publication_id: Option<&str>,
) -> Result<MirrorProgress> {
    let retained = db
        .mirror_import(&original.job_id)
        .await?
        .context("mirror original disappeared")?;
    ensure!(
        retained.original == *original,
        "mirror control changed retained original"
    );
    db.validate_mirror_import_authority(original).await?;
    ensure!(
        work.mirror_managed_profile_digest()? == original.protected_profile_digest,
        "mirror accepted profile changed original"
    );
    let placement = db
        .surface_placement(original.placement_id)
        .await?
        .context("mirror placement disappeared")?;
    let binding = db
        .binding(original.binding_id)
        .await?
        .context("mirror binding disappeared")?;
    if matches!(
        step,
        MirrorStep::BeginPromotion | MirrorStep::CopyParts { .. } | MirrorStep::CompletePromotion
    ) {
        let progress = retained
            .progress
            .as_ref()
            .context("mirror promotion has no retained verified source")?;
        // Current SQL authority is checked immediately before every signed
        // destination plan, including bounded copy batches and Complete.
        db.validate_mirror_publication_dispatch(
            original,
            progress,
            publication_id,
            aos_hub_core::clock::now_unix_secs(),
        )
        .await?;
    }
    let status = matches!(step, MirrorStep::Status { .. });
    let plan = work.plan_for_placement(
        &placement,
        &binding,
        StorageWorkOperation::MirrorTransfer {
            original: original.clone(),
            step,
        },
        aos_hub_core::clock::now_unix_secs(),
    )?;
    let result = work.execute(&plan).await?;
    let StorageWorkOutcome::MirrorProgress { progress } = result.outcome else {
        anyhow::bail!("Worker returned another mirror result");
    };
    progress.validate(original)?;
    // Empty destination Status cannot regress the retained source progress.
    if !status || retained.progress.is_none() {
        db.record_mirror_import_progress(
            original,
            &progress,
            retained.state == "committed",
            aos_hub_core::clock::now_unix_secs(),
        )
        .await?;
    } else {
        db.validate_mirror_import_authority(original).await?;
    }
    Ok(progress)
}

async fn acknowledge(
    db: &Database,
    work: &RemoteStorageWorkClient,
    original: &MirrorOriginal,
    progress: &MirrorProgress,
) -> Result<()> {
    let retained = db
        .mirror_import(&original.job_id)
        .await?
        .context("mirror terminal original disappeared")?;
    ensure!(
        retained.state == "committed"
            && retained.original == *original
            && retained.progress.as_ref() == Some(progress)
            && retained.commit_digest.as_deref()
                == Some(progress.commit_digest(original)?.as_str()),
        "mirror ACK lacks exact retained SQL commit"
    );
    let now = aos_hub_core::clock::now_unix_secs();
    let plan = aos_hub_core::storage_work::StorageWorkPlan {
        version: 1,
        plan_id: uuid::Uuid::new_v4().simple().to_string(),
        deployment_id: work.deployment_id().into(),
        issued_at: now,
        expires_at: now.checked_add(30).context("mirror ACK expiry overflow")?,
        placement_id: original.placement_id,
        placement_resource_version: original.placement_resource_version,
        binding_id: original.binding_id,
        binding_resource_version: original.binding_resource_version,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: vec![],
        placement_prefix: original.placement_prefix.clone(),
        operation: StorageWorkOperation::MirrorTransfer {
            original: original.clone(),
            step: MirrorStep::Acknowledge {
                commit_digest: progress.commit_digest(original)?,
            },
        },
    };
    let StorageWorkOutcome::MirrorProgress {
        progress: acknowledged,
    } = work.execute(&plan).await?.outcome
    else {
        anyhow::bail!("mirror terminal ACK returned another result");
    };
    ensure!(
        acknowledged == *progress,
        "mirror ACK changed committed final proof"
    );
    db.retire_acknowledged_mirror_import(original, &acknowledged)
        .await
}

/// Selects encoded and decoded NAR bounds from the exact governing narinfo.
pub(super) fn nar_proof(info: &aos_core::nar::info::NarInfo) -> Result<MirrorVerification> {
    let proof = MirrorVerification::Nar {
        file_sha256: info
            .file_hash
            .as_deref()
            .map(aos_core::nar::cache::canonical_sha256_hex)
            .transpose()?,
        file_size: info
            .file_size
            .context("hybrid mirror requires an explicit NAR FileSize")?,
        compression: info.compression.clone(),
        nar_sha256: aos_core::nar::cache::canonical_sha256_hex(&info.nar_hash)?,
        nar_size: info.nar_size,
    };
    proof.validate().context("hybrid NAR mirror supports none/zstd, encoded and decoded sizes independently <=2GiB, and zstd windows <=8MiB")?;
    Ok(proof)
}

/// Copies a full verified surface through bounded storage-side controls.
///
/// # Errors
/// Returns an error for upstream trust failures, unsupported storage-side
/// formats, current authority changes or unsettled effects. Failed attempts are
/// visible in the mirror status; no Native source-body fallback is available.
pub async fn sync_full_mirror(
    db: &std::sync::Arc<Database>,
    work: &std::sync::Arc<RemoteStorageWorkClient>,
    registry: &RegistryRecord,
) -> Result<super::MirrorSyncResult> {
    let source = db
        .registry_mirror(registry.id)
        .await?
        .context("registry is not a mirror")?;
    ensure!(source.mode == "full", "scheduled mirror requires full mode");
    let selection = selection::Selection::capture(db, work, registry, source).await?;
    let attempt = async {
        let fetch = MetadataDiscovery::new(db, work, registry, &selection).await?;
        let verified = super::verify_surface_inner(
            &fetch,
            &registry.trust_keys,
            selection.source.signature_policy == "required",
            true,
        )
        .await?;
        let mut proofs = fetch.proofs()?;
        // Pair semantics are verified beside storage before admitting either
        // encoded representation. Native retains only their exact commitments.
        for index_path in verified
            .immutable
            .iter()
            .filter(|path| path.ends_with(".idx"))
        {
            let inspected = work
                .inspect_mirror_pack(db, registry, index_path, Vec::new())
                .await?;
            for source in [inspected.pack, inspected.index] {
                let proof = MirrorVerification::Sha256 {
                    sha256: source.sha256,
                    size: source.size,
                };
                if let Some(prior) = proofs.get(&source.path) {
                    ensure!(
                        prior == &proof,
                        "upstream pack commitment changed during discovery"
                    );
                }
                proofs.insert(source.path, proof);
            }
        }
        let mut selected = selected_proofs(
            verified
                .immutable
                .iter()
                .filter(|path| !verified.nar_proofs.contains_key(*path))
                .chain(verified.mutable.iter()),
            &proofs,
        )?;
        selected.extend(
            verified
                .nar_proofs
                .iter()
                .map(|(path, proof)| (path.clone(), proof.clone())),
        );
        selected.sort_by(|left, right| left.0.cmp(&right.0));
        let prepared = prepare_group(db, work, registry, selected, &selection).await?;
        let refs_digest = match proofs.get("info/refs") {
            Some(MirrorVerification::Sha256 { sha256, .. }) => sha256,
            _ => anyhow::bail!("mirror discovery omitted exact refs commitment"),
        };
        let publication =
            publication::admit(db, registry.id, &verified.commit, refs_digest, &prepared).await?;
        let placement_id = prepared
            .first()
            .context("mirror has no prepared objects")?
            .original
            .placement_id;
        // Already committed recovery must carry current catalogue evidence.
        // The final SQL barrier independently refuses missing or stale pins.
        db.inherit_registry_publication_object_evidence(
            &publication.publication_id,
            aos_hub_core::clock::now_unix_secs(),
        )
        .await?;
        let mut nars = Vec::new();
        let mut leaves = Vec::new();
        let mut narinfos = Vec::new();
        let mut pointers = Vec::new();
        for object in prepared {
            let path = &object.original.path;
            if aos_hub_core::keymap::is_mutable_path(path) {
                pointers.push(object);
            } else if verified.nar_proofs.contains_key(path) {
                nars.push(object);
            } else if path.ends_with(".narinfo") {
                narinfos.push(object);
            } else {
                leaves.push(object);
            }
        }
        let mut copied = 0;
        copied += publish_group(db, work, nars, &publication.publication_id).await?;
        copied += publish_group(db, work, leaves, &publication.publication_id).await?;
        copied += publish_group(db, work, narinfos, &publication.publication_id).await?;
        publication::begin_pointers(db, &publication, placement_id).await?;
        copied += publish_group(db, work, pointers, &publication.publication_id).await?;
        publication::finish(db, &publication, placement_id).await?;
        use aos_hub_core::fetch::SurfaceProvider as _;
        let provider = crate::storage_work::HybridSurfaceProvider::new(
            std::sync::Arc::clone(db),
            std::sync::Arc::clone(work),
        );
        let placement = db
            .reconciled_surface_writer(SurfaceTarget::Registry(registry.id))
            .await?;
        let surface = provider.placement_fetcher(&placement).await?;
        crate::indexer::index_and_record(db, surface.as_ref(), registry).await?;
        db.update_mirror_sync(
            registry.id,
            aos_hub_core::clock::now_unix_secs(),
            "ok",
            None,
            verified.frontier.as_deref(),
        )
        .await?;
        Ok(super::MirrorSyncResult {
            commit: verified.commit,
            frontier: verified.frontier,
            files_copied: copied,
            releases: verified.releases,
            channels: verified.channels,
        })
    }
    .await;
    if let Err(error) = &attempt {
        db.update_mirror_sync(
            registry.id,
            aos_hub_core::clock::now_unix_secs(),
            "failed",
            Some(&format!("{error:#}")),
            None,
        )
        .await?;
    }
    attempt
}

fn selected_proofs<'a>(
    paths: impl Iterator<Item = &'a String>,
    proofs: &std::collections::BTreeMap<String, MirrorVerification>,
) -> Result<Vec<(String, MirrorVerification)>> {
    paths
        .map(|path| {
            Ok((
                path.clone(),
                proofs
                    .get(path)
                    .with_context(|| {
                        format!("mirror path {path} was not part of bounded verified discovery")
                    })?
                    .clone(),
            ))
        })
        .collect()
}

fn metadata_object(verification: &MirrorVerification) -> bool {
    match verification {
        MirrorVerification::Sha256 { size, .. } => {
            *size <= aos_hub_core::mirror_acceptance::MIRROR_METADATA_BUFFER_BYTES
        }
        MirrorVerification::Nar {
            file_size,
            nar_size,
            compression,
            ..
        } => {
            compression == "none"
                && (*file_size).max(*nar_size)
                    <= aos_hub_core::mirror_acceptance::MIRROR_METADATA_BUFFER_BYTES
        }
    }
}

async fn prepare_group(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry: &RegistryRecord,
    selected: Vec<(String, MirrorVerification)>,
    selection: &selection::Selection,
) -> Result<Vec<PreparedObject>> {
    let (metadata, bulk) = selected
        .into_iter()
        .partition(|(_, verification)| metadata_object(verification));
    // Separate bounded admissions keep small objects progressing during a full
    // bulk verifier. Provider reservation alone cannot fix an occupied task pool.
    let (metadata, bulk) = futures_util::future::join(
        prepare_class(
            db,
            work,
            registry,
            metadata,
            aos_hub_core::mirror_acceptance::MIRROR_METADATA_BUFFERED_PRODUCERS as usize,
            selection,
        ),
        prepare_class(
            db,
            work,
            registry,
            bulk,
            aos_hub_core::mirror_acceptance::MIRROR_BULK_BUFFERED_PRODUCERS as usize,
            selection,
        ),
    )
    .await;
    let mut prepared = metadata?;
    prepared.extend(bulk?);
    prepared.sort_by(|left, right| left.original.path.cmp(&right.original.path));
    Ok(prepared)
}

async fn prepare_class(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry: &RegistryRecord,
    selected: Vec<(String, MirrorVerification)>,
    parallel_objects: usize,
    selection: &selection::Selection,
) -> Result<Vec<PreparedObject>> {
    use futures_util::StreamExt as _;
    let mut chunks = Vec::new();
    let mut current = Vec::with_capacity(64);
    for object in selected {
        current.push(object);
        if current.len() == 64 {
            chunks.push(std::mem::replace(&mut current, Vec::with_capacity(64)));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    let mut results = futures_util::stream::iter(chunks.into_iter().map(|objects| async move {
        batch::prepare_selected(db, work, registry, objects, Some(selection)).await
    }))
    .buffer_unordered(parallel_objects);
    let mut prepared = Vec::new();
    let mut first_failure = None;
    while let Some(result) = results.next().await {
        match result {
            Ok(objects) => prepared.extend(objects),
            Err(error) if first_failure.is_none() => first_failure = Some(error),
            Err(_) => {}
        }
    }
    if let Some(error) = first_failure {
        return Err(error);
    }
    prepared.sort_by(|left, right| left.original.path.cmp(&right.original.path));
    Ok(prepared)
}

async fn publish_group(
    db: &Database,
    work: &RemoteStorageWorkClient,
    prepared: Vec<PreparedObject>,
    publication_id: &str,
) -> Result<usize> {
    let (metadata, bulk) = prepared
        .into_iter()
        .partition(|object| metadata_object(&object.original.verification));
    let (metadata, bulk) = futures_util::future::join(
        publish_class(
            db,
            work,
            metadata,
            publication_id,
            aos_hub_core::mirror_acceptance::MIRROR_METADATA_BUFFERED_PRODUCERS as usize,
        ),
        publish_class(
            db,
            work,
            bulk,
            publication_id,
            aos_hub_core::mirror_acceptance::MIRROR_BULK_BUFFERED_PRODUCERS as usize,
        ),
    )
    .await;
    Ok(metadata? + bulk?)
}

async fn publish_class(
    db: &Database,
    work: &RemoteStorageWorkClient,
    prepared: Vec<PreparedObject>,
    publication_id: &str,
    parallel_objects: usize,
) -> Result<usize> {
    use futures_util::StreamExt as _;
    let mut chunks = Vec::new();
    let mut current = Vec::with_capacity(64);
    for object in prepared {
        current.push(object);
        if current.len() == 64 {
            chunks.push(std::mem::replace(&mut current, Vec::with_capacity(64)));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    let mut results = futures_util::stream::iter(
        chunks
            .into_iter()
            .map(|objects| async move { batch::publish(db, work, objects, publication_id).await }),
    )
    .buffer_unordered(parallel_objects);

    // Drain all admitted independent controls before crossing a dependency
    // barrier. Cancellation could otherwise conceal a positive provider result.
    let mut completed = 0;
    let mut first_failure = None;
    while let Some(result) = results.next().await {
        match result {
            Ok(count) => completed += count,
            Err(error) if first_failure.is_none() => first_failure = Some(error),
            Err(_) => {}
        }
    }
    match first_failure {
        Some(error) => Err(error),
        None => Ok(completed),
    }
}

/// Imports one pull-through miss and leaves delivery to the normal Worker grant.
///
/// # Errors
/// Returns an error for unverifiable bulk representations, unsafe upstreams,
/// changed trust or writer authority, or unsettled provider effects.
pub async fn fetch_through(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry_id: i64,
    path: &str,
) -> Result<bool> {
    let Some(source) = db.registry_mirror(registry_id).await? else {
        return Ok(false);
    };
    if source.mode != "pull_through" {
        return Ok(false);
    }
    let registry = db
        .registry_by_id(registry_id)
        .await?
        .context("pull-through registry disappeared")?;
    let selection = selection::Selection::capture(db, work, &registry, source).await?;
    let fetch = MetadataDiscovery::new(db, work, &registry, &selection).await?;
    let narinfo_path = if path.starts_with("nar/") {
        super::narinfo_path_and_store_hash_for_nar(path)
            .context("pull-through NAR requires its exact governing narinfo")?
            .0
    } else {
        path.to_string()
    };
    if path.starts_with("nar/") || path.ends_with(".narinfo") {
        let Some(bytes) = fetch.fetch(&narinfo_path).await? else {
            return Ok(false);
        };
        let text = std::str::from_utf8(&bytes)?;
        if selection.source.signature_policy == "required" {
            crate::nar_verification::verify_narinfo_signature(text, &registry.trust_keys)?;
        }
        super::assert_narinfo_matches_requested(&narinfo_path, text)?;
        let info = aos_core::nar::info::parse(text)?;
        let nar_path = super::narinfo_nar_url(text)
            .context("pull-through narinfo URL is outside the admitted NAR namespace")?;
        if path.starts_with("nar/") {
            super::assert_nar_matches_requested(path, text)?;
        }
        import_selected(
            db,
            work,
            &registry,
            &selection,
            &nar_path,
            nar_proof(&info)?,
        )
        .await?;
        let proofs = fetch.proofs()?;
        import_selected(
            db,
            work,
            &registry,
            &selection,
            &narinfo_path,
            proofs
                .get(&narinfo_path)
                .context("narinfo discovery proof missing")?
                .clone(),
        )
        .await?;
        return Ok(true);
    }
    // Mutable live pointers need upstream freshness rather than permanent
    // cache admission. Their typed live-read projection is a separate workflow.
    ensure!(matches!(super::pull_class(path), super::PullClass::VerifiedObject),
        "hybrid pull-through currently requires a verifiable loose object or NAR/narinfo; live pointers and packs need storage-side projection");
    let Some(bytes) = fetch.fetch(path).await? else {
        return Ok(false);
    };
    let oid =
        super::oid_from_loose_path(path).context("pull-through object path has no exact OID")?;
    validate_pullthrough_loose(&bytes, oid)?;
    let proofs = fetch.proofs()?;
    import_selected(
        db,
        work,
        &registry,
        &selection,
        path,
        proofs
            .get(path)
            .context("loose object proof missing")?
            .clone(),
    )
    .await?;
    Ok(true)
}

async fn import_selected(
    db: &Database,
    work: &RemoteStorageWorkClient,
    registry: &RegistryRecord,
    selection: &selection::Selection,
    path: &str,
    verification: MirrorVerification,
) -> Result<MirrorProgress> {
    let prepared = prepare_object(db, work, registry, path, verification, Some(selection)).await?;
    publish_object(db, work, prepared, None).await
}

fn validate_pullthrough_loose(bytes: &[u8], oid: aos_registry_surface::object::Oid) -> Result<()> {
    let (_, content) =
        crate::surface::object::decode_loose_with_limit(bytes, Some(oid), 4 * 1024 * 1024 + 64)?;
    ensure!(
        content.len() <= 4 * 1024 * 1024,
        "pull-through decoded Git object exceeds its explicit 4MiB bound"
    );
    Ok(())
}
