//! Original queue read admission and bounded inspection of verified metadata.
//!
//! Queue admission retains an immutable read turn before delivery. Metadata
//! inspection acquires the real source guard's current floor and exact positive
//! closure; a fresh read lease cannot manufacture either provider acknowledgement.

use anyhow::{ensure, Result};
use aos_hub_core::{
    direct_upload::{
        DirectExternalProfileSelector, DirectUploadAdmission, DirectUploadTarget, WireInteger,
    },
    s3surface::{Method as S3Method, S3Surface},
    storage_authority::{
        external_object::stage::{
            ExternalStageAdmissionMode, ExternalStageContext, ExternalStageOutcome,
            ExternalStageRequest, ExternalStageResult,
        },
        lease::LeaseEffect,
    },
    storage_work::StorageCredentialSelector,
};
use sha2::{Digest as _, Sha256};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

use super::super::config::configured;
use super::{
    config,
    executor::{
        call, executor_key, relative_key, validate_domain_publication, validate_publication,
    },
    planning::prepare_observation_read_lease,
    protocol::{self, Intent, Operation, Reply},
};

/// Admits the original immutable queue read without dispatching provider I/O.
///
/// # Errors
/// Returns an error for expired original eligibility, changed physical authority,
/// an unrelated pending effect, or failed durable admission.
pub(crate) async fn admit_stage_read(env: &Env, work: &ExternalStageRequest) -> Result<()> {
    executor_key(env)?;
    ensure!(
        work.admission_mode == ExternalStageAdmissionMode::Fresh && work.operation.immutable_read(),
        "queue admission requires a fresh original immutable read"
    );
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let object = configured(env)?.ok_or_else(|| anyhow::anyhow!("external authority disabled"))?;
    let config = config::configured(env, &object)?
        .ok_or_else(|| anyhow::anyhow!("external stage disabled"))?;
    work.validate(&deployment, object.clock().observed_at)?;
    let publication = crate::hybrid_binding::resolve_for_delivery(
        env,
        i64::try_from(work.context.placement.binding_id.get())?,
        i64::try_from(work.context.placement.binding_resource_version.get())?,
    )
    .await?;
    validate_publication(&object, &config, work, &publication, &deployment)?;
    let intent = Intent {
        operation_id: work.operation_id.clone(),
        context: work.context.clone(),
        operation: work.operation.clone(),
    };
    intent.validate()?;
    let reply = call(
        env,
        &protocol::Request {
            domain: protocol::DOMAIN.into(),
            scope: intent.scope()?,
            operation: Operation::Begin {
                admission_mode: work.admission_mode,
                intent: intent.clone(),
                write_lease: work.write_lease.clone(),
                read_lease: work.read_lease.clone(),
                source: None,
            },
        },
    )
    .await?;
    match reply {
        Reply::Dispatch { turn, source, .. } => ensure!(
            turn.intent == intent && source.is_none(),
            "queue immutable read admission changed"
        ),
        Reply::Terminal { receipt } => ensure!(
            receipt.turn.intent == intent,
            "queue immutable read terminal changed"
        ),
        _ => anyhow::bail!("queue immutable read admission refused"),
    }
    Ok(())
}

/// Reads bounded narinfo bytes from the exact positively verified source.
///
/// # Errors
/// Returns an error for another target or source incarnation, failed read
/// authority, an oversized response, or changed whole-object SHA and size.
pub(crate) async fn read_stage_metadata(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    closed: &ExternalStageResult,
    verified: &ExternalStageResult,
    maximum: usize,
) -> Result<Vec<u8>> {
    ensure!(
        matches!(&admission.intent.target, DirectUploadTarget::CacheObject { path, .. } if path.ends_with(".narinfo"))
            && maximum <= 512 * 1024
            && admission.intent.byte_size.get() <= maximum as u64,
        "external metadata target or bound differs"
    );
    executor_key(env)?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let context = ExternalStageContext::from_admission(admission, placement_id, &deployment)?;
    let object = configured(env)?.ok_or_else(|| anyhow::anyhow!("external authority disabled"))?;
    let config = config::configured(env, &object)?
        .ok_or_else(|| anyhow::anyhow!("external stage disabled"))?;
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
            physical_authority_id: domain.read_cohort.authority.authority_id.clone(),
            association: domain.read_cohort.association.clone(),
            write_credential: domain.write_credential.clone(),
            read_credential: domain.read_credential.clone(),
            presign_credential: domain.presign_credential.clone(),
        }],
    )
    .await?
    .pop()
    .ok_or_else(|| anyhow::anyhow!("external metadata profile absent"))?;
    let lease = prepare_observation_read_lease(env, &object, &profile).await?;
    let Reply::SourceProof { proof, part: None } = call(
        env,
        &protocol::Request {
            domain: protocol::DOMAIN.into(),
            scope: context.scope(false)?,
            operation: Operation::SourceProof {
                context: context.clone(),
                receipt_digest: verified.receipt_digest.clone(),
                part_number: None,
                read_lease: lease.clone(),
            },
        },
    )
    .await?
    else {
        anyhow::bail!("external metadata original source proof absent");
    };
    proof.validate(&context, &verified.receipt_digest)?;
    ensure!(
        proof.closed.result()? == *closed && proof.verified.result()? == *verified,
        "external metadata original source receipt changed"
    );
    let etag = match &proof.closed.outcome {
        ExternalStageOutcome::Closed { etag, .. }
        | ExternalStageOutcome::EmptyClosed { etag, .. } => etag,
        _ => anyhow::bail!("external metadata positive source closure absent"),
    };
    let secret = publication.credential_text(
        &StorageCredentialSelector {
            purpose: "read".into(),
            generation: i64::try_from(domain.read_credential.generation.get())?,
        },
        &deployment,
        object.clock().observed_at,
    )?;
    let surface = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        "",
        Some(secret.as_str()),
        object.clock().observed_at,
    )?;
    let source_key = context.stage_key()?;
    let path = relative_key(&publication.snapshot.object_prefix, &source_key)?;
    let url = surface.object_url(S3Method::Get, path, object.clock().observed_at)?;
    aos_hub_core::url_guard::is_safe_remote_url(&url)?;
    let headers = Headers::new();
    headers.set(
        "if-match",
        &aos_hub_core::surface_write::strong_if_match_etag(etag)?,
    )?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual);
    let request = Request::new_with_init(&url, &init)?;
    object.verifier()?.validate_lease(
        lease.as_bytes(),
        &domain.read_cohort,
        &object.timing_profile,
        &proof.floor,
        &source_key,
        LeaseEffect::Read,
        object.clock(),
    )?;
    let response = Fetch::Request(request).send().await?;
    ensure!(
        response.status_code() == 200,
        "external metadata GET not positively acknowledged"
    );
    let returned_etag = response
        .headers()
        .get("etag")?
        .ok_or_else(|| anyhow::anyhow!("external metadata ETag absent"))?;
    ensure!(
        aos_hub_core::surface_write::strong_if_match_etag(&returned_etag)?
            == aos_hub_core::surface_write::strong_if_match_etag(etag)?,
        "external metadata returned incarnation changed"
    );
    let original = crate::direct_upload::observation::Object::new(
        &admission.session_id,
        &admission.logical_fingerprint,
        &admission.intent,
        placement_id,
        &verified.receipt_digest,
    );
    let mut observed = crate::direct_upload::observation::Read::metadata(original);
    let bytes = crate::direct_digest::read_bounded_native_observed(response, maximum, &|bytes| {
        observed.consumed(bytes)
    })
    .await?;
    ensure!(
        bytes.len() as u64 == admission.intent.byte_size.get()
            && hex::encode(Sha256::digest(&bytes)) == admission.intent.expected_sha256,
        "external metadata original full SHA or size changed"
    );
    observed.positive();
    Ok(bytes)
}
