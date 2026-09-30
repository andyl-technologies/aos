//! `aos release step publish`: place a finalized bundle on one destination.
//!
//! One command serves staging and production destinations on Hub and static
//! surfaces. Before any upload it verifies the bundle, its build-phase
//! observations, and the journal (`finalized`, with every `after` surface
//! role already published). A production destination additionally requires
//! the staging publication receipt, the destination's signed staging-phase
//! qualification (`--evidence`), and fresh fitness attestations.
//!
//! The bundle is projected into the machine surface layout, uploaded through
//! the destination's [`SurfaceClient`](super::surface), read back
//! anonymously, and receipted. A surface that already holds this release for
//! another destination (candidate then stable on one production surface) is
//! verified by read-back instead of a second upload and serves its existing
//! receipt. The output is the destination's `receipt.json` and a successor
//! `release-journal.jsonl` with a `published` entry.

use anyhow::{Context as _, Result, bail};
use aos_core::output::Printer;
use aos_release::plan::{PlannedDestination, ReleasePlan, SurfaceRole};
use aos_release::qualification::QualificationPhase;
use aos_release::receipt::PublicationReceipt;
use aos_release::state::ReleaseState;

use super::access::{self, SignerNeed};
use super::journal::{self, Journal, Transition};
use super::qualification_transition::{AdmittedQualification, verify_staging_evidence};
use super::surface::project::{self, ProjectedSurface};
use super::surface::{
    Promotion, PublicationRequest, SignedReceipt, SurfaceClient, SurfaceObject, key_map,
    verify_publication_receipt,
};
use super::verify::{VerifiedBundle, verified_bundle};
use crate::cli::ReleasePublishArgs;
use crate::commands::hub::publication::inventory::publication_from_root;

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
    let projection = project::plan_projection(&args.bundle, &bundle.manifest.payload)?;
    let projected = project::materialize(
        &args.bundle,
        &bundle.captured.files,
        &projection,
        &bundle.captured.manifest_bytes,
        if reused {
            None
        } else {
            args.surface.as_deref()
        },
    )?;
    let receipt = if reused {
        verify_existing_publication(client.as_ref(), &projected, &bundle).await?
    } else {
        publish_new(
            client.as_ref(),
            &projected,
            &bundle,
            destination,
            continuity.as_ref(),
            printer,
        )
        .await?
    };
    client.verify_identity().await?;

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
    printer: &Printer,
) -> Result<SignedReceipt> {
    let plan = &bundle.plan;
    let publication = client
        .publish_surface(projected.root(), &plan.registry_base_commit, printer)
        .await?;
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
