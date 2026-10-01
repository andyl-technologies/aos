//! Direct publication readback through the existing external authority floor.
//!
//! This seam reads actual stage receipts and hashes held destination bytes. It
//! creates no stamp for legacy objects, and never interprets HEAD or absence as
//! settlement of a pending provider turn.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use aos_hub_core::s3surface::{Method as S3Method, S3Surface};
use aos_hub_core::storage_authority::{
    external_object::stage::{ExternalStageContext, ExternalStageOperation, ExternalStageOutcome},
    lease::LeaseEffect,
};
use aos_hub_core::storage_work::StorageCredentialSelector;
use worker::{Env, Fetch, Method, Request, RequestInit, RequestRedirect, Storage};

use super::super::{
    config::configured,
    protocol::{digest, Effect, Intent},
    state::Head,
    storage::{load_head, HEAD},
};
use super::{
    config, executor::validate_domain_publication, planning::prepare_observation_read_lease,
    storage::load_receipt,
};

/// Checks old physical uncertainty before a new direct reservation is admitted.
///
/// # Errors
///
/// Returns an error when authority configuration differs, an earlier effect is
/// unresolved, or another destination session still owns the physical key.
pub(crate) async fn check_direct_available(
    env: &Env,
    storage: &Storage,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
) -> Result<()> {
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let context = ExternalStageContext::from_admission(admission, placement_id, &deployment)?;
    let object = configured(env)?.ok_or_else(|| anyhow::anyhow!("external authority disabled"))?;
    if let Some(head) = load_head(storage).await? {
        head.validate(&object, &context.scope(true)?)?;
        ensure!(
            head.pending.is_none()
                && head.observation.is_none()
                && head
                    .stage
                    .as_ref()
                    .is_none_or(|stage| stage.pending.is_none() && stage.pending_parts.is_empty()),
            "external physical effect remains unknown"
        );
        ensure!(
            head.stage
                .as_ref()
                .is_none_or(|stage| stage.context == context
                    || matches!(
                        stage.phase,
                        super::state::Phase::Closed | super::state::Phase::Aborted
                    )),
            "external former destination session remains active"
        );
    }
    Ok(())
}

/// Measures the current whole object under the already retained direct owner.
///
/// # Errors
///
/// Returns an error when the held authority or read lease cannot be validated,
/// the bounded GET is not positively acknowledged, or its body identity differs.
pub(crate) async fn direct_baseline(
    env: &Env,
    storage: &Storage,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    expires_at: u64,
) -> Result<DirectDestinationBaselineState> {
    check_direct_available(env, storage, admission, placement_id).await?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let context = ExternalStageContext::from_admission(admission, placement_id, &deployment)?;
    let scope = context.scope(true)?;
    let object =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external object consumer disabled"))?;
    let config = config::configured(env, &object)?
        .ok_or_else(|| anyhow::anyhow!("external stage consumer disabled"))?;
    let domain = config.domain(&context)?;
    let publication = crate::hybrid_binding::resolve_for_delivery(
        env,
        i64::try_from(context.placement.binding_id.get())?,
        i64::try_from(context.placement.binding_resource_version.get())?,
    )
    .await?;
    validate_domain_publication(
        domain,
        &publication,
        &deployment,
        object.clock().observed_at,
    )?;
    let profile = super::profiles::resolve_external_profiles(
        env,
        &[DirectExternalProfileSelector {
            physical_authority_id: domain.write_cohort.authority.authority_id.clone(),
            association: domain.write_cohort.association.clone(),
            write_credential: domain.write_credential.clone(),
            read_credential: domain.read_credential.clone(),
            presign_credential: domain.presign_credential.clone(),
        }],
    )
    .await?
    .pop()
    .ok_or_else(|| anyhow::anyhow!("external baseline protected profile absent"))?;
    let lease = prepare_observation_read_lease(env, &object, &profile).await?;
    let mut head = match load_head(storage).await? {
        Some(head) => head,
        None => {
            let intent = Intent {
                scope: scope.clone(),
                operation_id: "direct-baseline-read".into(),
                context: digest(&context)?,
                cohort_digest: digest(&domain.read_cohort)?,
                effect: Effect::Head,
            };
            Head::initialize(&object, &intent, object.clock())?
        }
    };
    head.validate(&object, &scope)?;
    ensure!(
        head.pending.is_none()
            && head.observation.is_none()
            && head
                .stage
                .as_ref()
                .is_none_or(|stage| stage.pending.is_none() && stage.pending_parts.is_empty()),
        "external baseline provider effect remains unknown"
    );
    let selector = StorageCredentialSelector {
        purpose: "read".into(),
        generation: i64::try_from(domain.read_credential.generation.get())?,
    };
    let secret = publication.credential_text(&selector, &deployment, object.clock().observed_at)?;
    let surface = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        "",
        Some(secret.as_str()),
        object.clock().observed_at,
    )?;
    let prefix = &publication.snapshot.object_prefix;
    let path = if prefix.is_empty() {
        scope.full_key.as_str()
    } else {
        scope
            .full_key
            .strip_prefix(&format!("{prefix}/"))
            .ok_or_else(|| {
                anyhow::anyhow!("external baseline full key differs from binding prefix")
            })?
    };
    let url = surface.object_url(S3Method::Get, path, object.clock().observed_at)?;
    aos_hub_core::url_guard::is_safe_remote_url(&url)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get)
        .with_redirect(RequestRedirect::Manual);
    let provider = Request::new_with_init(&url, &init)?;
    let validated = object.verifier()?.validate_lease(
        lease.as_bytes(),
        &domain.read_cohort,
        &object.timing_profile,
        &head.floor,
        &scope.full_key,
        LeaseEffect::Read,
        object.clock(),
    )?;
    head.floor = validated.next_floor;
    storage.put(HEAD, serde_json::to_string(&head)?).await?;
    // Floor advancement is durable before the final synchronous lease check.
    object.verifier()?.validate_lease(
        lease.as_bytes(),
        &domain.read_cohort,
        &object.timing_profile,
        &head.floor,
        &scope.full_key,
        LeaseEffect::Read,
        object.clock(),
    )?;
    ensure!(
        u64::try_from(object.clock().observed_at)?
            .saturating_add(u64::try_from(object.clock_uncertainty)?)
            < expires_at,
        "external baseline authorization expired"
    );
    let response = Fetch::Request(provider).send().await?;
    if response.status_code() == 404 {
        return Ok(DirectDestinationBaselineState::Missing {});
    }
    ensure!(
        response.status_code() == 200,
        "external baseline GET not positively acknowledged"
    );
    let etag = response
        .headers()
        .get("etag")?
        .ok_or_else(|| anyhow::anyhow!("external baseline ETag absent"))?;
    let etag = aos_hub_core::surface_write::strong_if_match_etag(&etag)?;
    let length: u64 = response
        .headers()
        .get("content-length")?
        .ok_or_else(|| anyhow::anyhow!("external baseline length absent"))?
        .parse()?;
    ensure!(
        length <= MAX_DIRECT_OBJECT_BYTES,
        "external baseline object exceeds bound"
    );
    let provider_version = response
        .headers()
        .get("x-amz-version-id")?
        .filter(|value| value != "null");
    let measured = crate::direct_digest::hash_response(response, MAX_DIRECT_OBJECT_BYTES).await?;
    ensure!(
        measured.byte_size == length,
        "external baseline stream length differs"
    );
    Ok(DirectDestinationBaselineState::Present {
        byte_size: WireInteger::new(length),
        sha256: measured.sha256,
        etag,
        provider_version,
        guard_stamp: None,
    })
}

/// Reads the exact retained terminal destination receipt without provider I/O.
///
/// # Errors
///
/// Returns an error when the original receipt is missing, unresolved, or no
/// longer identifies the current positively acknowledged incarnation.
pub(crate) async fn direct_final(
    env: &Env,
    storage: &Storage,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    operation_id: &str,
) -> Result<(DirectObjectIncarnation, String)> {
    check_direct_available(env, storage, admission, placement_id).await?;
    let context = ExternalStageContext::from_admission(
        admission,
        placement_id,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
    )?;
    let head = load_head(storage)
        .await?
        .ok_or_else(|| anyhow::anyhow!("external final guard head absent"))?;
    let receipt = load_receipt(storage, operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("external final positive receipt absent"))?;
    receipt.validate()?;
    ensure!(
        receipt.turn.intent.context == context && receipt.turn.intent.operation.destination(),
        "external final original context differs"
    );
    crate::direct_guard::verify_external_dispatch(
        storage,
        &receipt.turn.intent.operation_id,
        &receipt.turn.intent.context,
        &receipt.turn.intent.operation,
    )
    .await?;
    let receipt_digest = digest(&receipt)?;
    let (etag, stamp) = match receipt.outcome {
        ExternalStageOutcome::Closed {
            etag, guard_stamp, ..
        }
        | ExternalStageOutcome::EmptyClosed { etag, guard_stamp } => (etag, guard_stamp),
        _ => anyhow::bail!("external final positive publication absent"),
    };
    let visible = head
        .visible_receipt
        .ok_or_else(|| anyhow::anyhow!("external final current incarnation receipt absent"))?;
    ensure!(
        visible.operation_id == operation_id
            && visible.incarnation == receipt.turn.expected_incarnation
            && head.incarnation == receipt.turn.expected_incarnation
            && visible.receipt_digest == receipt_digest,
        "external final provider incarnation changed"
    );
    Ok((DirectObjectIncarnation::GuardStamp { stamp }, etag))
}

/// Reads positively closed and fully verified stage receipts from this source guard.
///
/// # Errors
///
/// Returns an error when the original source session, manifest, incarnation, or
/// full integrity acknowledgement differs from the requested evidence.
pub(crate) async fn direct_source(
    env: &Env,
    storage: &Storage,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    expected: &DirectStagePlacementEvidence,
) -> Result<()> {
    let context = ExternalStageContext::from_admission(
        admission,
        expected.placement.placement_id,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
    )?;
    let object =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external source authority disabled"))?;
    let head = load_head(storage)
        .await?
        .ok_or_else(|| anyhow::anyhow!("external source guard head absent"))?;
    head.validate(&object, &context.scope(false)?)?;
    let session = head
        .stage
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("external source session absent"))?;
    ensure!(
        head.pending.is_none()
            && head.observation.is_none()
            && session.pending.is_none()
            && session.pending_parts.is_empty()
            && session.context == context
            && !session.destination
            && session.phase == super::state::Phase::Verified,
        "external immutable stage remains unsettled or changed"
    );
    let closed = session
        .closed
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("external positive source Close absent"))?;
    let verified = session
        .verified
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("external full source verification absent"))?;
    let closed_receipt = load_receipt(storage, &closed.operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("external retained source Close receipt absent"))?;
    let verified_receipt = load_receipt(storage, &verified.operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("external retained integrity receipt absent"))?;
    closed_receipt.validate()?;
    verified_receipt.validate()?;
    ensure!(
        digest(&closed_receipt)? == closed.digest
            && digest(&verified_receipt)? == verified.digest
            && head.incarnation == closed_receipt.turn.expected_incarnation
            && verified_receipt.turn.expected_incarnation
                == closed_receipt.turn.expected_incarnation
            && verified.operation_id == expected.verification_operation_id
            && complete.manifests.contains(&expected.manifest)
            && (admission.intent.byte_size.get() == 0
                || session.manifest.as_ref() == Some(&expected.manifest)),
        "external source manifest or immutable receipt changed"
    );
    let stamp = match closed_receipt.outcome {
        ExternalStageOutcome::Closed { guard_stamp, .. }
        | ExternalStageOutcome::EmptyClosed { guard_stamp, .. } => guard_stamp,
        _ => anyhow::bail!("external source provider positively closed incarnation absent"),
    };
    ensure!(
        expected.staging_incarnation == DirectObjectIncarnation::GuardStamp { stamp },
        "external source guard incarnation changed"
    );
    ensure!(
        matches!(verified_receipt.outcome, ExternalStageOutcome::Verified { ref sha256, byte_size, ref close_receipt_digest }
        if sha256 == &admission.intent.expected_sha256 && byte_size == admission.intent.byte_size && close_receipt_digest == &closed.digest),
        "external original full SHA verification differs"
    );
    Ok(())
}

/// Reads the exact terminal stage abort from this addressed original source guard.
///
/// # Errors
///
/// Returns an error when the original authority or positive abort receipt is
/// absent or differs from the admitted stage and retained upload identifier.
pub(crate) async fn direct_abort(
    env: &Env,
    storage: &Storage,
    admission: &DirectUploadAdmission,
    abort: &DirectAbortRequest,
    placement_id: WireInteger,
) -> Result<()> {
    let context = ExternalStageContext::from_admission(
        admission,
        placement_id,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
    )?;
    let object =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external source authority disabled"))?;
    let head = load_head(storage)
        .await?
        .ok_or_else(|| anyhow::anyhow!("external abort guard head absent"))?;
    head.validate(&object, &context.scope(false)?)?;
    let operation_id = crate::direct_upload::verification::step_id(
        admission,
        placement_id,
        &abort.operation_id,
        "abort-stage",
    )?;
    let receipt = load_receipt(storage, &operation_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("external positive abort receipt absent"))?;
    receipt.validate()?;
    ensure!(
        receipt.turn.intent.context == context
            && matches!((&receipt.turn.intent.operation, &receipt.outcome),
        (ExternalStageOperation::AbortStage { upload_id }, ExternalStageOutcome::Aborted { upload_id: acknowledged, .. }) if upload_id == acknowledged),
        "external original Abort receipt differs"
    );
    Ok(())
}

/// Retires only a positively closed former session before a newly retained owner.
///
/// # Errors
///
/// Returns an error when a former session remains active or unresolved, its
/// authority differs, or durable storage cannot retain the cleared pointer.
pub(crate) async fn prepare_direct_destination(
    env: &Env,
    storage: &Storage,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
) -> Result<()> {
    check_direct_available(env, storage, admission, placement_id).await?;
    let context = ExternalStageContext::from_admission(
        admission,
        placement_id,
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
    )?;
    let Some(mut head) = load_head(storage).await? else {
        return Ok(());
    };
    if let Some(session) = &head.stage {
        if session.context != context {
            ensure!(
                matches!(
                    session.phase,
                    super::state::Phase::Closed | super::state::Phase::Aborted
                ),
                "external former destination session remains active"
            );
            // Positive old receipts and the permanent floor/incarnation remain.
            // Only the now-terminal transient ownership pointer is replaced.
            head.stage = None;
            storage.put(HEAD, serde_json::to_string(&head)?).await?;
        }
    }
    Ok(())
}
