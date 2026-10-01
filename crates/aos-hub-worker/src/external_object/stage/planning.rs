//! Broker-facing exact context/lease preparation and retained part delegation.
//!
//! Token reuse is an optional bounded isolate cache, never durable authority.
//! Every actual dispatch and capability issuance still validates the physical
//! guard's permanent floor. Cache eviction/expiry never settles provider work.

use std::{cell::RefCell, collections::BTreeMap};

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{
    DirectExternalStorageCapabilities, DirectPartGrant, DirectUploadAdmission, WireInteger,
};
use aos_hub_core::storage_authority::{
    external_object::stage::{
        ExternalStageAdmissionMode, ExternalStageContext, ExternalStageOperation,
        ExternalStageOutcome, ExternalStageRequest, ExternalStageResult,
    },
    lease::{
        control::{
            sign_issuer_request, verify_issuer_reply_at_time, IssuerOperation, IssuerRequest,
            ISSUER_CONTROL_PATH,
        },
        EpochLeaseFloor, LeaseCohort, LeaseEffect, LeaseInteger,
    },
};
use aos_hub_core::storage_work::{
    StorageCredentialSelector, StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER,
};
use rand::TryRngCore as _;
use worker::{Env, Headers, Method, Request, RequestInit};

use super::super::{
    config::{configured, Config as ObjectConfig},
    protocol::digest,
};
use super::{
    config::{self, Domain},
    executor::{call, executor_key, recovery_read, relative_key, validate_publication},
    protocol::{self, Intent, Operation, Reply},
};

const MAX_CACHED_COHORTS: usize = 32;
const MAX_ISSUER_REPLY: usize = 64 * 1024;

#[derive(Clone)]
struct CachedLease {
    token: String,
    issued_at: i64,
    not_after: i64,
    last_observed_at: i64,
}

thread_local! {
    static LEASE_CACHE: RefCell<BTreeMap<String, CachedLease>> = RefCell::new(BTreeMap::new());
}

/// Acquires only the actual independently configured profile's existing read lease.
///
/// # Errors
/// Returns an error for a changed profile, missing or ambiguous domain, or an
/// issuer response that fails the existing signed context and timing checks.
pub(in crate::external_object) async fn prepare_observation_read_lease(
    env: &Env,
    object: &ObjectConfig,
    profile: &DirectExternalStorageCapabilities,
) -> Result<String> {
    profile.validate()?;
    ensure!(
        profile.issuer_key_id == object.issuer_key_id
            && profile.issuer_public_key == object.issuer_public_key
            && profile.timing_profile == object.timing_profile
            && profile.clock_uncertainty.get() == object.clock_uncertainty
            && object
                .cohorts
                .iter()
                .any(|cohort| cohort == &profile.read_cohort)
            && profile
                .read_cohort
                .allowed_effects
                .contains(&LeaseEffect::Head),
        "observation profile differs from independent executor"
    );
    let config = config::configured(env, object)?
        .ok_or_else(|| anyhow::anyhow!("observation issuer domain disabled"))?;
    let domain = config.observation_domain(&profile.read_cohort)?;
    ensure!(
        domain.issuer_installation == profile.issuer_installation
            && domain.write_cohort == profile.write_cohort
            && domain.read_credential == profile.selector.read_credential
            && domain.write_credential == profile.selector.write_credential
            && domain.presign_credential == profile.selector.presign_credential,
        "observation issuer domain differs from protected profile"
    );
    // Reuse the original profile/attestation horizon and cache key. The caller's
    // shorter application deadline separately bounds this individual HEAD.
    acquire_lease(env, object, domain, &domain.read_cohort).await
}

/// Prepares only the original retained placement, with independently pinned leases.
///
/// The broker first authenticates and durably reserves this complete admission.
/// This helper selects neither a newer SQL placement nor a replacement session.
///
/// # Errors
/// Returns a redacted failure for invalid/expired admission, absent qualified
/// domain or an issuer reply that fails audience, signature, cohort or freshness.
pub(crate) async fn prepare_stage_request(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    operation_id: String,
    operation: ExternalStageOperation,
) -> Result<ExternalStageRequest> {
    prepare_stage_with_mode(
        env,
        admission,
        placement_id,
        operation_id,
        operation,
        ExternalStageAdmissionMode::Fresh,
    )
    .await
}

/// Prepares a stage turn bounded by the original foreground invocation.
///
/// # Errors
///
/// Returns an error when stage authority cannot be prepared or the original
/// cutoff has expired before preparation completes.
pub(crate) async fn prepare_stage_request_with_cutoff(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    operation_id: String,
    operation: ExternalStageOperation,
    expires_at: WireInteger,
) -> Result<ExternalStageRequest> {
    let mut work =
        prepare_stage_request(env, admission, placement_id, operation_id, operation).await?;
    work.expires_at = WireInteger::new(work.expires_at.get().min(expires_at.get()));
    work.validate(
        &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
        aos_hub_core::clock::now_unix_secs(),
    )?;
    Ok(work)
}

/// Prepares fresh authentication/read authority for an exact interrupted stage read.
///
/// A read-only probe must find the original pending verification or its exact
/// terminal receipt. A pending probe is never a dispatch permit; Begin repeats
/// eligibility under the physical guard's CAS. Terminal replay admits no Begin.
///
/// # Errors
/// Returns a value-free refusal for a missing or changed original read, or failed
/// fresh authentication or read authority.
pub(crate) async fn prepare_stage_read_recovery(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    operation_id: String,
    operation: ExternalStageOperation,
) -> Result<ExternalStageRequest> {
    ensure!(
        operation.immutable_read(),
        "recovery requires immutable stage verification"
    );
    prepare_stage_with_mode(
        env,
        admission,
        placement_id,
        operation_id,
        operation,
        ExternalStageAdmissionMode::ResumeImmutableRead,
    )
    .await
}

async fn prepare_stage_with_mode(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    operation_id: String,
    operation: ExternalStageOperation,
    admission_mode: ExternalStageAdmissionMode,
) -> Result<ExternalStageRequest> {
    executor_key(env)?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    admission.validate(&deployment)?;
    let context = ExternalStageContext::from_admission(admission, placement_id, &deployment)?;
    let object =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external object consumer disabled"))?;
    let config = config::configured(env, &object)?
        .ok_or_else(|| anyhow::anyhow!("external stage consumer disabled"))?;
    let domain = config.domain(&context)?;
    let now = object.clock().observed_at;
    let (write_lease, read_lease) =
        if admission_mode == ExternalStageAdmissionMode::ResumeImmutableRead {
            let intent = Intent {
                operation_id: operation_id.clone(),
                context: context.clone(),
                operation: operation.clone(),
            };
            let retained = call(
                env,
                &protocol::Request {
                    domain: protocol::DOMAIN.into(),
                    scope: intent.scope()?,
                    operation: Operation::Lookup {
                        intent: intent.clone(),
                    },
                },
            )
            .await?;
            let read_lease = match retained {
                Reply::Terminal { receipt } => {
                    receipt.validate()?;
                    ensure!(
                        receipt.turn.intent == intent,
                        "immutable read terminal changed"
                    );
                    // Historical positive replay needs only fresh bounded
                    // authentication. Empty leases cannot admit another Begin.
                    String::new()
                }
                Reply::Unsettled => {
                    recovery_read(env, &intent).await?;
                    acquire_lease(env, &object, domain, &domain.read_cohort).await?
                }
                _ => anyhow::bail!("immutable read original lookup differs"),
            };
            (String::new(), read_lease)
        } else if now < i64::try_from(admission.expires_at.get())? {
            (
                acquire_lease(env, &object, domain, &domain.write_cohort).await?,
                acquire_lease(env, &object, domain, &domain.read_cohort).await?,
            )
        } else {
            // Fresh authentication can recover an exact historical terminal after
            // original eligibility. Empty leases cannot authorize any new Begin.
            (String::new(), String::new())
        };
    let now = object.clock().observed_at;
    let expires = now
        .checked_add(30)
        .ok_or_else(|| anyhow::anyhow!("stage auth time overflow"))?;
    let mut work = ExternalStageRequest::new(
        deployment.clone(),
        operation_id,
        WireInteger::new(u64::try_from(now)?),
        WireInteger::new(u64::try_from(expires)?),
        context,
        write_lease,
        read_lease,
        operation,
    );
    work.admission_mode = admission_mode;
    work.validate(&deployment, now)?;
    Ok(work)
}

/// Signs only exact registered UploadPart grants with their original horizons.
///
/// Registered receipt replay alone does not admit new capability exposure. The
/// guard rechecks live grant admission and the latest permanent lease floor.
/// Original timestamps/expiry and credential generation are never regenerated.
///
/// # Errors
/// Returns a value-free failure for closed grant admission, changed receipt,
/// expired original horizon, mismatched credential or stale actual issuance.
pub(crate) async fn presign_registered_parts(
    env: &Env,
    work: &ExternalStageRequest,
    result: &ExternalStageResult,
) -> Result<Vec<DirectPartGrant>> {
    executor_key(env)?;
    let object = configured(env)?.ok_or_else(|| anyhow::anyhow!("external consumer disabled"))?;
    let config = config::configured(env, &object)?
        .ok_or_else(|| anyhow::anyhow!("stage consumer disabled"))?;
    let domain = config.domain(&work.context)?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    work.validate(&deployment, object.clock().observed_at)?;
    let ExternalStageOperation::RegisterParts { upload_id, grants } = &work.operation else {
        anyhow::bail!("only exact registered parts may be delegated");
    };
    let intent = Intent {
        operation_id: work.operation_id.clone(),
        context: work.context.clone(),
        operation: work.operation.clone(),
    };
    ensure!(
        result.version == 1
            && result.operation_id == work.operation_id
            && result.intent_digest == intent.fingerprint()?
            && result.outcome == ExternalStageOutcome::Registered,
        "registration result differs from original delegation"
    );
    let publication = crate::hybrid_binding::resolve_for_delivery(
        env,
        i64::try_from(work.context.placement.binding_id.get())?,
        i64::try_from(work.context.placement.binding_resource_version.get())?,
    )
    .await?;
    validate_publication(&object, &config, work, &publication, &deployment)?;
    let scope = work.context.scope(false)?;
    let reply = call(
        env,
        &protocol::Request {
            domain: protocol::DOMAIN.into(),
            scope: scope.clone(),
            operation: Operation::Delegation {
                intent: intent.clone(),
                write_lease: work.write_lease.clone(),
            },
        },
    )
    .await?;
    let Reply::Delegation { receipt, floor } = reply else {
        anyhow::bail!("grant admission reply differs");
    };
    ensure!(
        receipt.turn.intent == intent && digest(&receipt)? == result.receipt_digest,
        "registered grant receipt differs"
    );
    let credential = &domain.presign_credential;
    let now = object.clock().observed_at;
    let secret = publication.credential_text(
        &StorageCredentialSelector {
            purpose: credential.purpose.clone(),
            generation: i64::try_from(credential.generation.get())?,
        },
        &deployment,
        now,
    )?;
    let surface = aos_hub_core::s3surface::S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        "",
        Some(secret.as_str()),
        now,
    )?;
    let relative = relative_key(&publication.snapshot.object_prefix, &scope.full_key)?;
    let placement = work.context.placement.public_ref(&deployment)?;
    let mut signed = Vec::with_capacity(grants.len());
    for grant in grants {
        let horizon = grant
            .expires_at
            .get()
            .checked_sub(grant.issued_at.get())
            .ok_or_else(|| anyhow::anyhow!("original grant horizon invalid"))?;
        ensure!(
            horizon > 0
                && horizon <= domain.maximum_grant_lifetime.get()
                && grant.expires_at <= work.context.logical_expires_at,
            "original grant horizon exceeds admission"
        );
        let issued = i64::try_from(grant.issued_at.get())?;
        let provider = surface.direct_upload_part_request(
            relative,
            upload_id,
            &grant.part,
            issued,
            u32::try_from(horizon)?,
        )?;
        signed.push(DirectPartGrant {
            session_id: work.context.session_id.clone(),
            logical_fingerprint: work.context.logical_fingerprint.clone(),
            placement: placement.clone(),
            grant_id: grant.grant_id.clone(),
            grant_revision: grant.grant_revision,
            part: grant.part.clone(),
            method: "PUT".into(),
            url: provider.url,
            required_headers: provider.required_headers,
            expires_at: grant.expires_at,
        });
    }
    let validated = object.verifier()?.validate_lease(
        work.write_lease.as_bytes(),
        &domain.write_cohort,
        &object.timing_profile,
        &floor,
        &scope.full_key,
        LeaseEffect::MultipartPart,
        object.clock(),
    )?;
    let clock = object.clock();
    work.check_dispatch_time(&publication.snapshot, &validated, &floor, clock)?;
    let latest = clock
        .observed_at
        .checked_add(clock.uncertainty)
        .ok_or_else(|| anyhow::anyhow!("grant issuance clock overflow"))?;
    for grant in grants {
        ensure!(
            grant.issued_at.get() <= u64::try_from(latest)?
                && u64::try_from(latest)? < grant.expires_at.get(),
            "original grant expired at capability issuance"
        );
    }
    // No await follows this final observation before capabilities are returned.
    // These are explicit private-stage bearer grants, not invocation-time leases.
    Ok(signed)
}

async fn acquire_lease(
    env: &Env,
    object: &ObjectConfig,
    domain: &Domain,
    cohort: &LeaseCohort,
) -> Result<String> {
    acquire_configured_lease(
        env,
        object,
        &domain.issuer_installation,
        cohort,
        &domain.staging_prefix,
    )
    .await
}

/// Acquires only an independently configured cohort's existing issuer lease.
///
/// # Errors
/// Returns an error for changed installation/cohort pins, missing renewal
/// authority, or an issuer reply that fails exact signature/time validation.
pub(in crate::external_object) async fn acquire_configured_lease(
    env: &Env,
    object: &ObjectConfig,
    installation: &aos_hub_core::storage_authority::lease::control::IssuerInstallation,
    cohort: &LeaseCohort,
    cache_prefix: &str,
) -> Result<String> {
    installation.validate()?;
    ensure!(
        installation.authority == cohort.authority
            && installation.executor_identity == object.executor_identity,
        "renewal cohort is not independently configured"
    );
    let cache_key = digest(&(
        installation,
        cache_prefix,
        &object.issuer_key_id,
        &object.issuer_public_key,
        &object.timing_profile,
        cohort,
    ))?;
    let clock = object.clock();
    let latest = clock
        .observed_at
        .checked_add(clock.uncertainty)
        .ok_or_else(|| anyhow::anyhow!("lease cache clock overflow"))?;
    let cached = LEASE_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(value) = cache.get_mut(&cache_key) {
            if clock.observed_at >= value.last_observed_at
                && value.issued_at <= latest
                && latest
                    .checked_add(5)
                    .is_some_and(|next| next < value.not_after)
            {
                value.last_observed_at = clock.observed_at;
                return Some(value.token.clone());
            }
        }
        cache.remove(&cache_key);
        None
    });
    if let Some(token) = cached {
        return Ok(token);
    }

    let mut nonce = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| anyhow::anyhow!("lease correlation randomness unavailable"))?;
    let now = object.clock().observed_at;
    let request = IssuerRequest {
        protocol_version: 1,
        installation: installation.clone(),
        nonce: hex::encode(nonce),
        issued_at: LeaseInteger::new(now)?,
        expires_at: LeaseInteger::new(
            now.checked_add(30)
                .ok_or_else(|| anyhow::anyhow!("issuer deadline overflow"))?,
        )?,
        operation: IssuerOperation::Issue {
            cohort: cohort.clone(),
            requested_not_after: LeaseInteger::new(
                now.checked_add(object.timing_profile.maximum_lifetime.get())
                    .ok_or_else(|| anyhow::anyhow!("lease horizon overflow"))?,
            )?,
        },
    };
    request.validate(installation, now)?;
    let body = serde_json::to_vec(&request)?;
    ensure!(
        body.len() <= MAX_ISSUER_REPLY,
        "bounded renewal request oversized"
    );
    let renewal = env.secret("HUB_AUTHORITY_RENEWAL_KEY")?.to_string();
    ensure!(
        renewal != env.secret("HUB_STORAGE_WORK_KEY")?.to_string()
            && renewal != env.secret("HUB_EXTERNAL_OBJECT_GUARD_KEY")?.to_string()
            && env
                .secret("HUB_EXTERNAL_STAGE_KEY")
                .map_or(true, |key| renewal != key.to_string()),
        "issuer renewal key must be independent"
    );
    let signature = sign_issuer_request(&StorageWorkKey::new(renewal)?, &body)?;
    let headers = Headers::new();
    headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let provider =
        Request::new_with_init(&format!("https://authority{ISSUER_CONTROL_PATH}"), &init)?;
    let response = env
        .service("HUB_AUTHORITY_ISSUER")?
        .fetch_request(provider)
        .await?;
    ensure!(response.status_code() == 200, "issuer renewal refused");
    let bytes = crate::direct_digest::read_bounded_native(response, MAX_ISSUER_REPLY).await?;
    let verifier = object.verifier()?;
    let reply = verify_issuer_reply_at_time(&verifier, &request, &bytes, || Ok(object.clock()))?;
    ensure!(
        reply.installation == *installation
            && reply.current.journal.policy.timing_profile == object.timing_profile,
        "issuer renewal policy differs from independent configuration"
    );
    let token = reply
        .lease
        .ok_or_else(|| anyhow::anyhow!("issuer omitted requested lease"))?;
    // This temporary verifier floor establishes cache eligibility only. Every
    // real effect still validates against its permanent addressed guard floor.
    let cache_scope = if cache_prefix.is_empty() {
        "lease-cache-probe".to_owned()
    } else {
        format!("{cache_prefix}/lease-cache-probe")
    };
    let cache_floor = EpochLeaseFloor::initialize_fresh_guard(
        cohort.authority.clone(),
        object.executor_identity.clone(),
        cache_scope.clone(),
        &object.timing_profile,
        object.clock(),
    )?;
    let effect = *cohort
        .allowed_effects
        .first()
        .ok_or_else(|| anyhow::anyhow!("lease cache cohort has no effect"))?;
    let payload = verifier
        .validate_lease(
            token.as_bytes(),
            cohort,
            &object.timing_profile,
            &cache_floor,
            &cache_scope,
            effect,
            object.clock(),
        )?
        .payload;
    ensure!(
        payload.cohort == *cohort && payload.timing_profile == object.timing_profile,
        "issuer lease differs from configured cohort"
    );
    LEASE_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= MAX_CACHED_COHORTS {
            cache.clear();
        }
        cache.insert(
            cache_key,
            CachedLease {
                token: token.clone(),
                issued_at: payload.issued_at.get(),
                not_after: payload.not_after.get(),
                last_observed_at: object.clock().observed_at,
            },
        );
    });
    Ok(token)
}
