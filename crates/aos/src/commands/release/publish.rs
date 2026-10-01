//! `aos maintain release step publish`: place a finalized bundle on one destination.
//!
//! One command serves staging and production destinations on Hub and static
//! surfaces. Before any upload it verifies the bundle, its build-phase
//! observations, and the journal (`finalized`, with every `after` surface
//! role already published). A production destination additionally requires
//! the staging publication receipt, the destination's signed staging-phase
//! qualification (`--evidence`), and fresh fitness attestations.
//!
//! A composed surface given with `--surface` is admitted only after its TUF
//! chain verifies against independently trusted root keys and binds this
//! manifest; the published surface then holds exactly the projected bundle
//! plus those verified additions (TUF metadata, public manifest, and the
//! release record the delegated role authorizes).
//!
//! The bundle is projected into the machine surface layout, uploaded through
//! the destination's [`SurfaceClient`](super::surface), read back
//! anonymously, and receipted. A surface that already holds this release for
//! another destination (candidate then stable on one production surface) is
//! verified by read-back instead of a second upload and serves its existing
//! receipt. The output is the destination's `receipt.json` and a successor
//! `release-journal.jsonl` with a `published` entry.

use aos_registry_surface::staging::{
    STAGE_SCHEMA, StageObject, StagePointer, StageRecord, StageRevision, StageState,
    inventory_digest,
};
use std::io::{Read as _, Write as _};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::artifact::BundlePath;
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::plan::{PlannedDestination, ReleasePlan, SurfaceRole};
use aos_release::qualification::QualificationPhase;
use aos_release::receipt::PublicationReceipt;
use aos_release::state::ReleaseState;
use aos_release::tuf::{
    DelegatedTargetsMetadataV1, ImmutableTufSetV1, RootMetadataV1, SnapshotMetadataV1,
    TargetsMetadataV1, TimestampMetadataV1, TufEnvelopeV1, TufReleaseExpectation, TufRole,
    TufRootTrust, verify_immutable_set, verify_timestamp,
};
use aos_release::verify::CapturedFile;
use serde::de::DeserializeOwned;

use super::access::{self, SignerNeed};
use super::journal::{self, Journal, Transition};
use super::qualification_transition::{AdmittedQualification, verify_staging_evidence};
use super::surface::project::{self, Overlay, ProjectedSurface};
use super::surface::{
    Promotion, PublicationRequest, SignedReceipt, SurfaceClient, SurfaceObject, key_map,
    verify_publication_receipt,
};
use super::verify::{VerifiedBundle, verified_bundle};
use super::{capture, tuf, verify};
use crate::cli::ReleasePublishArgs;
use crate::commands::hub::publication::inventory::{
    publication_from_root, snapshot_publication_object,
};

/// Path of the only mutable TUF pointer in a composed surface.
const TUF_TIMESTAMP: &str = "tuf/timestamp.json";

/// Staging continuity admitted for a production destination.
struct ProductionContinuity {
    staging_receipt: SignedReceipt,
    qualifications: Vec<AdmittedQualification>,
}

/// Verifies, publishes, reads back, and receipts one destination.
pub(super) async fn run(args: &ReleasePublishArgs, printer: &Printer) -> Result<()> {
    let bundle = verified_bundle(&args.bundle, &args.trusted_keys)?;
    let plan = &bundle.plan;
    let destination = plan.destination(&args.to)?;
    let manifest_digest = bundle.summary.manifest_digest;

    let journal = Journal::read(&args.journal, "release journal")?;
    journal.require_release(plan, manifest_digest)?;
    journal.summary.can_publish(plan, &destination.name)?;
    aos_release::qualification_evidence::validate_observations(
        plan,
        &bundle.manifest.payload,
        None,
        QualificationPhase::Build,
        &bundle.manifest.payload.evidence,
        &journal::now_utc(),
        None,
    )?;

    let continuity = match destination.surface {
        SurfaceRole::Staging => {
            if args.predecessor_receipt.is_some() || !args.evidence.is_empty() {
                bail!("staging destinations take no predecessor receipt or qualification evidence");
            }
            None
        }
        SurfaceRole::Production => {
            Some(production_continuity(args, &bundle, destination, &journal)?)
        }
    };
    super::fitness_gate::require_fitness(
        plan,
        destination,
        &args.fitness,
        args.config.as_deref(),
        &bundle.manifest_keys,
    )?;

    let client = access::connect(
        plan,
        destination.surface,
        args.token.as_deref(),
        args.config.as_deref(),
        SignerNeed::Receipts,
    )
    .await?;
    let receipt_keys = key_map(&args.receipt_keys)?;
    client.verify_identity().await?;

    // A surface already holding this release is verified, not rewritten, so
    // a composed overlay (newer TUF metadata) is not part of that check.
    let reused = journal
        .summary
        .surface_holds_publication(destination.surface);
    let composed = match args.surface.as_deref() {
        Some(surface) if !reused => Some((surface, verify_overlay(args, surface, &bundle)?)),
        _ => None,
    };
    let overlay = composed
        .as_ref()
        .map(|(root, additions)| Overlay { root, additions });
    let projection = project::plan_projection(&args.bundle, &bundle.manifest.payload)?;
    let projected = project::materialize(
        &args.bundle,
        &bundle.captured.files,
        &projection,
        &bundle.captured.manifest_bytes,
        overlay.as_ref(),
    )?;
    if args.stage_only || args.staged_upload.is_some() {
        materialize_container_stage(args, projected.root(), &projection, &bundle)?;
    }
    let _stage_lock = if args.stage_only || args.staged_upload.is_some() {
        let output = args.staged_upload.as_deref().unwrap_or(&args.output);
        std::fs::create_dir_all(output)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(output.join(".stage.lock"))?;
        lock.try_lock()
            .context("another process is updating or finalizing this candidate")?;
        Some(lock)
    } else {
        None
    };
    let stage = if args.stage_only || args.staged_upload.is_some() {
        Some(candidate_revision(args, projected.root(), &bundle, client.as_ref()).await?)
    } else {
        None
    };
    if args.stage_only {
        let revision = stage.as_ref().context("candidate revision is absent")?;
        persist_stage_record(
            &args.output,
            &StageRecord {
                revision: revision.clone(),
                state: StageState::Draft,
                released_version: None,
            },
        )?;
        let staged = client
            .stage_surface(projected.root(), revision, printer)
            .await?;
        client.read_back(&staged.publication.objects).await?;
        client.verify_identity().await?;
        persist_stage_record(&args.output, &staged.record)?;
        let result = serde_json::json!({
            "schema_version": "aos.registry-staged-upload/v1",
            "destination": destination.name, "release_id": plan.release_id,
            "bundle_digest": bundle.bundle_digest, "manifest_digest": manifest_digest,
            "operation_id": staged.publication.operation_id, "stage": staged.record,
        });
        persist_stage_file(
            &args.output.join("staged-upload.json"),
            &canonical::to_vec(&result)?,
        )?;
        let prior_journal = capture::control_file(&args.journal, "release journal")?;
        persist_stage_file(&args.output.join("release-journal.jsonl"), &prior_journal)?;
        if !printer.json_if_active(&result) {
            printer.success(&format!(
                "Uploaded and verified candidate {} revision {} to {}",
                revision.id, revision.revision, destination.name
            ));
        }
        return Ok(());
    }

    if let (Some(revision), Some(output)) = (&stage, args.staged_upload.as_deref()) {
        persist_stage_record(
            output,
            &StageRecord {
                revision: revision.clone(),
                state: StageState::Releasing,
                released_version: None,
            },
        )?;
    }
    let receipt = if reused {
        verify_existing_publication(client.as_ref(), &projected, &bundle).await?
    } else {
        publish_new(
            client.as_ref(),
            &projected,
            &bundle,
            destination,
            continuity.as_ref(),
            stage.as_ref(),
            printer,
        )
        .await?
    };
    client.verify_identity().await?;
    if let (Some(revision), Some(output)) = (&stage, args.staged_upload.as_deref()) {
        persist_stage_record(
            output,
            &StageRecord {
                revision: revision.clone(),
                state: StageState::Released,
                released_version: Some(revision.release_id.clone()),
            },
        )?;
    }

    let view = verify_publication_receipt(plan, destination, &receipt, &receipt_keys)?;
    require_receipt_binds(&view, &bundle, &journal, continuity.as_ref(), reused)?;

    let mut evidence = vec![receipt.digest];
    if let Some(continuity) = &continuity {
        evidence.extend(
            continuity
                .qualifications
                .iter()
                .map(|admitted| admitted.digest),
        );
    }
    let successor = journal::append(
        &journal.entries,
        Transition {
            new_state: ReleaseState::Published,
            destination: Some(&destination.name),
            operation_ids: vec![view.operation_id.clone()],
            evidence,
            recorded_at: if reused {
                journal::now_utc()
            } else {
                view.committed_at.clone()
            },
        },
    )?;
    journal::persist_tree(
        &args.output,
        &[
            ("receipt.json", &receipt.bytes),
            ("release-journal.jsonl", &successor),
        ],
        "publication",
    )?;

    if printer.json_if_active(&serde_json::json!({
        "schema_version": "aos.release.publish-result/v1",
        "destination": destination.name,
        "release_id": plan.release_id,
        "bundle_digest": bundle.bundle_digest,
        "surface_kind": view.surface_kind,
        "surface_identity": view.surface_identity,
        "operation_id": view.operation_id,
        "receipt_digest": receipt.digest,
        "reused_publication": reused,
        "output": args.output,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Published and publicly verified {} to {} as {}{}",
        plan.release_id,
        destination.name,
        view.operation_id,
        if reused {
            " (existing publication)"
        } else {
            ""
        }
    ));
    Ok(())
}

/// Builds or resumes the exact shared candidate revision from captured registry evidence.
async fn candidate_revision(
    args: &ReleasePublishArgs,
    root: &Path,
    bundle: &VerifiedBundle,
    client: &dyn SurfaceClient,
) -> Result<StageRevision> {
    let mut revision = build_candidate_revision(args, root, bundle)?;
    let prior_path = args
        .staged_upload
        .as_deref()
        .map(|path| path.join("stage.json"))
        .unwrap_or_else(|| args.output.join("stage.json"));
    if prior_path.exists() {
        let prior: StageRecord = serde_json::from_slice(&capture::control_file(
            &prior_path,
            "candidate stage record",
        )?)?;
        if let Some(resumed) = resumable_candidate_revision(
            &prior,
            &revision,
            args.stage_only,
            args.stage_revision,
            args.staged_upload.is_some(),
        )? {
            return Ok(resumed);
        }
        revision.revision = prior
            .revision
            .revision
            .checked_add(1)
            .context("candidate revision overflow")?;
    } else {
        anyhow::ensure!(
            args.staged_upload.is_none(),
            "explicit publication has no shared candidate record"
        );
        anyhow::ensure!(
            args.stage_revision.is_none() || args.stage_revision == Some(0),
            "candidate does not exist for revision compare-and-swap"
        );
    }
    let surface = client.surface();
    let origin = match surface.kind {
        aos_release::plan::SurfaceKind::Hub => format!(
            "{}/{}",
            surface.origin.trim_end_matches('/'),
            bundle.plan.registry
        ),
        aos_release::plan::SurfaceKind::Static => surface.readback().to_owned(),
    };
    let base = super::surface::readback::base_url(&origin)?;
    let public = super::surface::readback::public_client()?;
    for pointer in &mut revision.publication {
        pointer.expected_sha256 =
            super::surface::readback::fetch_small(&public, &base, &pointer.path, 4 * 1024 * 1024)
                .await?
                .map(|bytes| format!("sha256:{}", Sha256Digest::of_bytes(bytes).hex()));
    }
    revision.validate()?;
    Ok(revision)
}

/// Returns the frozen revision for an exact retry, or admits an explicit draft update.
fn resumable_candidate_revision(
    prior: &StageRecord,
    proposed: &StageRevision,
    stage_only: bool,
    expected_revision: Option<u64>,
    finalizing: bool,
) -> Result<Option<StageRevision>> {
    prior.revision.validate()?;
    if let Some(expected) = expected_revision {
        anyhow::ensure!(
            expected == prior.revision.revision,
            "candidate revision changed"
        );
    }
    let mut compared = prior.revision.clone();
    compared.revision = 1;
    for pointer in &mut compared.publication {
        pointer.expected_sha256 = None;
    }
    if compared == *proposed {
        if stage_only {
            anyhow::ensure!(
                matches!(prior.state, StageState::Draft | StageState::Ready),
                "candidate cannot be edited after finalization begins"
            );
        }
        if finalizing {
            anyhow::ensure!(
                matches!(
                    prior.state,
                    StageState::Ready | StageState::Releasing | StageState::Released
                ),
                "candidate is not ready for explicit publication"
            );
        }
        return Ok(Some(prior.revision.clone()));
    }
    anyhow::ensure!(
        stage_only && expected_revision == Some(prior.revision.revision),
        "candidate inventory changed; provide --stage-revision {}",
        prior.revision.revision
    );
    anyhow::ensure!(
        matches!(prior.state, StageState::Draft | StageState::Ready),
        "candidate cannot be edited after finalization begins"
    );
    Ok(None)
}

fn object_kind(path: &str) -> &'static str {
    if path.starts_with("images/") && !path.ends_with("image-info.json") {
        "image-disk"
    } else if path.starts_with("images/") {
        "image-metadata"
    } else if path.starts_with("nar/") {
        "nar"
    } else if path.starts_with("oci/") {
        "oci"
    } else if aos_registry_surface::keymap::is_git_pack_path(path) {
        "git-pack"
    } else if path.starts_with("tuf/") {
        "tuf"
    } else if path.starts_with("releases/") {
        "release-metadata"
    } else {
        "registry-object"
    }
}

fn build_candidate_revision(
    args: &ReleasePublishArgs,
    root: &Path,
    bundle: &VerifiedBundle,
) -> Result<StageRevision> {
    let pinned = publication_from_root(root, &bundle.plan.registry)?;
    let finalized = captured_finalization(args, bundle)?;
    let mut inventory = pinned
        .request
        .objects
        .iter()
        .filter(|object| object.kind != "mutable_pointer")
        .map(|object| {
            Ok(StageObject {
                path: object.path.clone(),
                sha256: format!("sha256:{}", object.sha256),
                byte_size: u64::try_from(object.byte_size)?,
                kind: object_kind(&object.path).into(),
                media_type: object.media_type.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(graph) = &finalized.container {
        inventory.extend(aos_package::registry::container_stage::graph_objects(graph));
        inventory.sort_by(|left, right| left.path.cmp(&right.path));
    }
    let mut publication = Vec::new();
    for object in pinned
        .request
        .objects
        .iter()
        .filter(|object| object.kind == "mutable_pointer")
    {
        let mut snapshot = snapshot_publication_object(&pinned.root, object)?;
        let mut bytes = Vec::new();
        snapshot.read_to_end(&mut bytes)?;
        publication.push(StagePointer {
            path: object.path.clone(),
            bytes,
            expected_sha256: None,
        });
    }
    let revision = StageRevision {
        schema: STAGE_SCHEMA.into(),
        id: format!(
            "aos-{}",
            Sha256Digest::of_bytes(serde_json::to_vec(&(
                &bundle.plan.registry,
                &bundle.plan.version,
                &args.to
            ))?)
            .hex()
        ),
        registry: bundle.plan.registry.clone(),
        revision: 1,
        release_id: bundle.plan.version.clone(),
        source_branch: finalized.source_branch,
        commit: finalized.commit,
        container: finalized.container,
        inventory_digest: inventory_digest(&inventory)?,
        inventory,
        publication,
        store_roots: bundle
            .manifest
            .payload
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.store_path.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
    };
    revision.validate()?;
    Ok(revision)
}

fn captured_finalization(
    args: &ReleasePublishArgs,
    bundle: &VerifiedBundle,
) -> Result<aos_package::registry::release::FinalizedRegistryRelease> {
    let relative = "evidence/registry-finalization.json";
    let bytes = capture::control_file(
        &args.bundle.join(relative),
        "registry finalization evidence",
    )?;
    let expected = bundle
        .captured
        .files
        .iter()
        .find(|file| file.path.as_str() == relative)
        .context("verified bundle lacks registry finalization evidence")?;
    anyhow::ensure!(
        bytes.len() as u64 == expected.size_bytes
            && Sha256Digest::of_bytes(&bytes) == expected.sha256,
        "registry finalization evidence changed after bundle verification"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

/// Copies graph bytes from the already verified projection into OCI digest storage.
fn materialize_container_stage(
    args: &ReleasePublishArgs,
    root: &Path,
    projection: &project::Projection,
    bundle: &VerifiedBundle,
) -> Result<()> {
    let finalized = captured_finalization(args, bundle)?;
    let Some(graph) = finalized.container else {
        return Ok(());
    };
    let objects = aos_package::registry::container_stage::graph_objects(&graph);
    graph.validate(&objects, &bundle.plan.version)?;
    let projected_paths = projection
        .objects
        .iter()
        .map(|object| (object.bundle_path.as_str(), object.surface_path.as_str()))
        .collect::<std::collections::BTreeMap<_, _>>();
    for object in objects {
        let source = projected_paths.get(object.path.as_str()).with_context(|| {
            format!(
                "signed container graph member {} is absent from the release bundle",
                object.path
            )
        })?;
        let destination = root.join(&object.path);
        std::fs::create_dir_all(
            destination
                .parent()
                .context("OCI graph object has no parent")?,
        )?;
        let captured = capture::copy_payload_file(&root.join(source), &destination, &object.path)?;
        anyhow::ensure!(
            captured.size_bytes == object.byte_size && captured.sha256.to_string() == object.sha256,
            "projected OCI graph member differs from its signed descriptor: {}",
            object.path
        );
    }
    Ok(())
}

/// Verifies local candidate upload evidence against the current signed bundle and overlay.
pub(super) fn inspect_staged_upload(args: &ReleasePublishArgs) -> Result<StageRecord> {
    let bundle = verified_bundle(&args.bundle, &args.trusted_keys)?;
    let additions = args
        .surface
        .as_deref()
        .map(|surface| verify_overlay(args, surface, &bundle))
        .transpose()?;
    let overlay = args
        .surface
        .as_deref()
        .zip(additions.as_ref())
        .map(|(root, additions)| Overlay { root, additions });
    let projection = project::plan_projection(&args.bundle, &bundle.manifest.payload)?;
    let projected = project::materialize(
        &args.bundle,
        &bundle.captured.files,
        &projection,
        &bundle.captured.manifest_bytes,
        overlay.as_ref(),
    )?;
    materialize_container_stage(args, projected.root(), &projection, &bundle)?;
    let expected = build_candidate_revision(args, projected.root(), &bundle)?;
    let output = args.staged_upload.as_deref().unwrap_or(&args.output);
    let record: StageRecord = serde_json::from_slice(&capture::control_file(
        &output.join("stage.json"),
        "candidate record",
    )?)?;
    record.revision.validate()?;
    anyhow::ensure!(
        matches!(
            record.state,
            StageState::Ready | StageState::Releasing | StageState::Released
        ),
        "candidate has no verified immutable upload"
    );
    anyhow::ensure!(
        if record.state == StageState::Released {
            record.released_version.as_deref() == Some(bundle.plan.version.as_str())
        } else {
            record.released_version.is_none()
        },
        "candidate release state differs from the selected version"
    );
    let mut normalized = record.revision.clone();
    normalized.revision = 1;
    for pointer in &mut normalized.publication {
        pointer.expected_sha256 = None;
    }
    anyhow::ensure!(
        normalized == expected,
        "candidate upload inventory differs from the current signed release"
    );
    let marker: serde_json::Value = serde_json::from_slice(&capture::control_file(
        &output.join("staged-upload.json"),
        "candidate upload evidence",
    )?)?;
    let uploaded: StageRecord = serde_json::from_value(
        marker
            .get("stage")
            .cloned()
            .context("upload evidence has no shared stage record")?,
    )?;
    anyhow::ensure!(
        marker
            .get("schema_version")
            .and_then(|value| value.as_str())
            == Some("aos.registry-staged-upload/v1")
            && marker.get("destination").and_then(|value| value.as_str()) == Some(args.to.as_str())
            && marker.get("release_id").and_then(|value| value.as_str())
                == Some(bundle.plan.release_id.as_str())
            && marker.get("bundle_digest") == Some(&serde_json::to_value(bundle.bundle_digest)?)
            && marker.get("manifest_digest")
                == Some(&serde_json::to_value(bundle.summary.manifest_digest)?)
            && uploaded.state == StageState::Ready
            && uploaded.released_version.is_none()
            && uploaded.revision == record.revision,
        "candidate upload evidence differs from the exact revision"
    );
    Ok(record)
}

fn persist_stage_record(output: &Path, record: &StageRecord) -> Result<()> {
    std::fs::create_dir_all(output)?;
    persist_stage_file(&output.join("stage.json"), &canonical::to_vec(record)?)
}

fn persist_stage_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("candidate state has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .context("persisting candidate state")?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Verifies a composed surface's TUF chain and returns its exact additions.
///
/// The chain is located from the surface's single snapshot (or its timestamp,
/// when present), every role keeps the plan's frozen signer policy, and the
/// immutable set verifies against the independently trusted root keys and
/// binds this release's manifest envelope. The public manifest must equal the
/// verified envelope, and a release record is admitted only as the delegated
/// role authorizes it.
///
/// # Errors
/// Returns an error for malformed or missing metadata, changed role policy,
/// invalid or expired signatures, an untrusted root, a different manifest, or
/// a release record without (or differing from) its delegated target entry.
fn verify_overlay(
    args: &ReleasePublishArgs,
    surface: &Path,
    bundle: &VerifiedBundle,
) -> Result<Vec<CapturedFile>> {
    let plan = &bundle.plan;
    let role = TufRole::for_release(plan.release_class);
    let mut files = Vec::new();

    let timestamp = if surface.join(TUF_TIMESTAMP).exists() {
        Some(read_tuf::<TimestampMetadataV1>(
            surface,
            "timestamp.json",
            &mut files,
        )?)
    } else {
        None
    };
    let snapshot_name = match &timestamp {
        Some(timestamp) => timestamp.signed.snapshot.path.clone(),
        None => single_snapshot(surface)?,
    };
    let snapshot: TufEnvelopeV1<SnapshotMetadataV1> =
        read_tuf(surface, &snapshot_name, &mut files)?;
    let root_name = metadata_name(&snapshot.signed, ".root.json")?;
    let targets_name = metadata_name(&snapshot.signed, ".targets.json")?;
    let delegated_name = metadata_name(&snapshot.signed, &format!(".{}.json", role.as_str()))?;
    let set = ImmutableTufSetV1 {
        root: read_tuf::<RootMetadataV1>(surface, &root_name, &mut files)?,
        targets: read_tuf::<TargetsMetadataV1>(surface, &targets_name, &mut files)?,
        delegated: read_tuf::<DelegatedTargetsMetadataV1>(surface, &delegated_name, &mut files)?,
        snapshot,
    };

    for policy_role in [
        TufRole::Root,
        TufRole::Targets,
        role,
        TufRole::Snapshot,
        TufRole::Timestamp,
    ] {
        tuf::require_policy_match(&set.root.signed, plan, policy_role)?;
    }
    let trusted = verify::load_trusted_keys(&args.trusted_root_keys)?;
    let now = std::time::SystemTime::now();
    verify_immutable_set(
        &set,
        &TufRootTrust {
            keys: &trusted,
            threshold: args.trusted_root_threshold,
        },
        None,
        now,
        &TufReleaseExpectation {
            registry: &plan.registry,
            release_id: &plan.release_id,
            release_class: plan.release_class,
            manifest_digest: Sha256Digest::of_bytes(&bundle.captured.manifest_bytes),
        },
    )?;
    if let Some(timestamp) = &timestamp {
        verify_timestamp(timestamp, &set.root.signed, &set.snapshot, None, now)?;
    }

    // The projection writes the public manifest itself; a composed copy must
    // be the verified envelope.
    let manifest_path = project::manifest_path(&bundle.manifest.payload);
    if surface.join(&manifest_path).exists() {
        let bytes =
            capture::control_file(&surface.join(&manifest_path), "public release manifest")?;
        if bytes != bundle.captured.manifest_bytes {
            bail!("composed surface has a different public release manifest");
        }
        files.push(file_identity(manifest_path, &bytes)?);
    }

    let record_path = aos_release::record::record_path(plan.release_class, &plan.version);
    let authorized = set
        .delegated
        .signed
        .targets
        .iter()
        .find(|target| target.release_id == plan.release_id)
        .and_then(|target| target.record.as_ref());
    let present = surface.join(&record_path).exists();
    match (authorized, present) {
        (None, false) => {}
        (Some(entry), true) => {
            let bytes = capture::control_file(&surface.join(&record_path), "release record")?;
            if entry.path != record_path
                || Sha256Digest::of_bytes(&bytes) != entry.digest
                || bytes.len() as u64 != entry.length
            {
                bail!("composed release record does not match its delegated TUF target");
            }
            files.push(file_identity(record_path, &bytes)?);
        }
        (Some(_), false) => {
            bail!("delegated TUF targets authorize a release record the composed surface lacks")
        }
        (None, true) => bail!("composed surface has a release record without a delegated target"),
    }
    Ok(files)
}

/// Names the one snapshot file of a composed surface without a timestamp.
fn single_snapshot(surface: &Path) -> Result<String> {
    let directory = surface.join("tuf");
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&directory)
        .with_context(|| format!("reading composed TUF metadata {}", directory.display()))?
    {
        let name = entry?.file_name();
        let name = name
            .to_str()
            .context("composed TUF metadata has a non-UTF-8 name")?;
        if name.ends_with(".snapshot.json") {
            names.push(name.to_owned());
        }
    }
    match names.as_slice() {
        [name] => Ok(name.clone()),
        [] => bail!("composed surface has no TUF snapshot"),
        _ => bail!("composed surface has more than one TUF snapshot"),
    }
}

/// Returns the one snapshot-listed metadata file name ending in `suffix`.
fn metadata_name(snapshot: &SnapshotMetadataV1, suffix: &str) -> Result<String> {
    let mut matching = snapshot
        .metadata
        .iter()
        .filter(|entry| entry.path.ends_with(suffix));
    let entry = matching
        .next()
        .with_context(|| format!("TUF snapshot lacks its {suffix} metadata"))?;
    if matching.next().is_some() {
        bail!("TUF snapshot repeats its {suffix} metadata");
    }
    Ok(entry.path.clone())
}

/// Reads one canonical TUF envelope below `tuf/` and records its identity.
fn read_tuf<T: DeserializeOwned>(
    surface: &Path,
    name: &str,
    files: &mut Vec<CapturedFile>,
) -> Result<TufEnvelopeV1<T>> {
    if name.is_empty() || name.contains('/') {
        bail!("TUF metadata description must name one file");
    }
    let relative = format!("tuf/{name}");
    let bytes = capture::control_file(&surface.join(&relative), "composed TUF metadata")?;
    canonical::require_canonical(&bytes, "composed TUF metadata")?;
    let envelope = canonical::from_slice(&bytes, "composed TUF metadata")?;
    files.push(file_identity(relative, &bytes)?);
    Ok(envelope)
}

fn file_identity(path: String, bytes: &[u8]) -> Result<CapturedFile> {
    Ok(CapturedFile {
        path: BundlePath::parse(path)?,
        size_bytes: u64::try_from(bytes.len())?,
        sha256: Sha256Digest::of_bytes(bytes),
    })
}

/// Verifies the staging receipt and staging-phase qualification of a production destination.
fn production_continuity(
    args: &ReleasePublishArgs,
    bundle: &VerifiedBundle,
    destination: &PlannedDestination,
    journal: &Journal,
) -> Result<ProductionContinuity> {
    let plan = &bundle.plan;
    let path = args
        .predecessor_receipt
        .as_deref()
        .context("production destinations require --predecessor-receipt")?;
    let staging_receipt = SignedReceipt::read(path, "staging publication receipt")?;
    let staging_destination = published_staging_destination(plan, journal, &staging_receipt)?;
    let staging = verify_publication_receipt(
        plan,
        staging_destination,
        &staging_receipt,
        &key_map(&args.predecessor_receipt_keys)?,
    )?;
    if staging.bundle_digest != bundle.bundle_digest
        || staging.manifest_digest != bundle.summary.manifest_digest
    {
        bail!("staging receipt does not bind the exact published bundle");
    }

    if args.evidence.is_empty() {
        bail!(
            "{} requires its signed staging qualification (--evidence)",
            destination.name
        );
    }
    let qualifications = args
        .evidence
        .iter()
        .map(|directory| {
            verify_staging_evidence(
                plan,
                &bundle.manifest.payload,
                &destination.name,
                directory,
                staging_receipt.digest,
                bundle.summary.manifest_digest,
                &args.qualification_keys,
                &bundle.manifest_keys,
            )
            .with_context(|| format!("verifying qualification evidence {}", directory.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ProductionContinuity {
        staging_receipt,
        qualifications,
    })
}

/// Finds the staging destination whose publication recorded `receipt`.
fn published_staging_destination<'a>(
    plan: &'a ReleasePlan,
    journal: &Journal,
    receipt: &SignedReceipt,
) -> Result<&'a PlannedDestination> {
    let name = journal
        .entries
        .iter()
        .filter(|entry| entry.new_state == ReleaseState::Published)
        .filter(|entry| entry.evidence.contains(&receipt.digest))
        .find_map(|entry| entry.destination.as_deref())
        .context("journal records no staging publication with this receipt")?;
    let destination = plan.destination(name)?;
    if destination.surface != SurfaceRole::Staging {
        bail!("predecessor receipt belongs to a production publication");
    }
    Ok(destination)
}

/// Uploads a new publication, reads it back, and obtains its receipt.
async fn publish_new(
    client: &dyn SurfaceClient,
    projected: &ProjectedSurface,
    bundle: &VerifiedBundle,
    destination: &PlannedDestination,
    continuity: Option<&ProductionContinuity>,
    stage: Option<&StageRevision>,
    printer: &Printer,
) -> Result<SignedReceipt> {
    let plan = &bundle.plan;
    let publication = match stage {
        Some(revision) => {
            client
                .finalize_stage(
                    projected.root(),
                    revision,
                    &plan.registry_base_commit,
                    printer,
                )
                .await?
        }
        None => {
            client
                .publish_surface(projected.root(), &plan.registry_base_commit, printer)
                .await?
        }
    };
    client.verify_identity().await?;
    client.read_back(&publication.objects).await?;

    let promotion = continuity
        .map(|continuity| {
            let first = continuity
                .qualifications
                .first()
                .context("production publication lacks admitted qualification")?;
            Ok::<_, anyhow::Error>(Promotion {
                staging_receipt: &continuity.staging_receipt,
                qualification_payload: &first.payload,
                signed_qualification: &first.signed,
            })
        })
        .transpose()?;
    let receipt = client
        .receipt(&PublicationRequest {
            plan,
            destination,
            bundle_digest: bundle.bundle_digest,
            manifest_digest: bundle.summary.manifest_digest,
            publication: &publication,
            promotion,
        })
        .await?;

    // The receipt consumers fetch anonymously must be the committed one.
    let public = client.published_receipt(bundle.bundle_digest).await?;
    if public != receipt {
        bail!("anonymous receipt read-back differs from the committed receipt");
    }
    Ok(receipt)
}

/// Verifies a publication another destination already placed on this surface.
///
/// Every immutable projected object and the manifest are read back; mutable
/// pointers may legitimately have moved since and are not compared.
async fn verify_existing_publication(
    client: &dyn SurfaceClient,
    projected: &ProjectedSurface,
    bundle: &VerifiedBundle,
) -> Result<SignedReceipt> {
    let pinned = publication_from_root(projected.root(), &bundle.plan.registry)?;
    let objects = pinned
        .request
        .objects
        .iter()
        .filter(|object| object.kind != "mutable_pointer")
        .map(|object| {
            Ok(SurfaceObject {
                path: object.path.clone(),
                sha256: object.sha256.clone(),
                byte_size: u64::try_from(object.byte_size)?,
                mutable: false,
                media_type: object.media_type.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    client.read_back(&objects).await?;
    client.published_receipt(bundle.bundle_digest).await
}

/// Requires the receipt to bind this bundle and its staging continuity.
fn require_receipt_binds(
    view: &PublicationReceipt,
    bundle: &VerifiedBundle,
    journal: &Journal,
    continuity: Option<&ProductionContinuity>,
    reused: bool,
) -> Result<()> {
    if view.release_id != bundle.plan.release_id
        || view.manifest_digest != bundle.summary.manifest_digest
        || view.bundle_digest != bundle.bundle_digest
    {
        bail!("publication receipt does not bind the exact release bundle");
    }
    match (continuity, view.predecessor_receipt_digest) {
        (None, None) => Ok(()),
        (Some(continuity), Some(predecessor)) if !reused => {
            if predecessor != continuity.staging_receipt.digest {
                bail!("production receipt names a different staging publication");
            }
            Ok(())
        }
        // A reused production publication was admitted with a staging
        // receipt that this journal already recorded.
        (Some(_), Some(predecessor)) if journal.contains_evidence(predecessor) => Ok(()),
        _ => bail!("publication receipt continuity differs from the destination's role"),
    }
}

#[cfg(test)]
mod stage_resume_tests {
    use super::*;

    fn candidate() -> StageRevision {
        let inventory = vec![StageObject {
            path: "nar/candidate.nar.zst".into(),
            sha256: format!("sha256:{}", "a".repeat(64)),
            byte_size: 12,
            kind: "nar".into(),
            media_type: "application/zstd".into(),
        }];
        StageRevision {
            schema: STAGE_SCHEMA.into(),
            id: "aos-stable-candidate".into(),
            registry: "owner/registry".into(),
            revision: 1,
            release_id: "1.2.3".into(),
            source_branch: "dplecki/release-1.2.3".into(),
            commit: "b".repeat(40),
            container: None,
            inventory_digest: inventory_digest(&inventory).unwrap(),
            inventory,
            publication: vec![StagePointer {
                path: "HEAD".into(),
                bytes: b"ref: refs/heads/stable\n".to_vec(),
                expected_sha256: None,
            }],
            store_roots: Vec::new(),
        }
    }

    #[test]
    fn interrupted_finalization_keeps_revision_and_pointer_expectations_frozen() {
        let proposed = candidate();
        let mut frozen = proposed.clone();
        frozen.revision = 3;
        frozen.publication[0].expected_sha256 = Some(format!("sha256:{}", "c".repeat(64)));
        let record = StageRecord {
            revision: frozen.clone(),
            state: StageState::Releasing,
            released_version: None,
        };

        let resumed = resumable_candidate_revision(&record, &proposed, false, Some(3), true)
            .unwrap()
            .unwrap();

        assert_eq!(resumed, frozen);
        assert!(resumable_candidate_revision(&record, &proposed, true, Some(3), false).is_err());
        let mut changed = proposed;
        changed.commit = "d".repeat(40);
        assert!(resumable_candidate_revision(&record, &changed, true, Some(3), false).is_err());
        assert_eq!(record.state, StageState::Releasing);
    }

    #[test]
    fn matching_inventory_still_requires_the_requested_revision() {
        let proposed = candidate();
        let record = StageRecord {
            revision: proposed.clone(),
            state: StageState::Ready,
            released_version: None,
        };

        assert!(resumable_candidate_revision(&record, &proposed, false, Some(2), true).is_err());
        assert!(resumable_candidate_revision(&record, &proposed, false, Some(1), true).is_ok());
    }
}
