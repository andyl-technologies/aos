//! Authenticated byte executor; actual provider invocation follows final lease check.
//!
//! Bodies, provider URLs and secrets never enter compact object DO messages.
//! Ambiguous provider failure leaves the retained turn untouched. Successful
//! terminal replay returns historical acknowledgement without provider access.

use anyhow::{ensure, Result};
use aos_hub_core::s3surface::{Method as S3Method, S3Surface};
use aos_hub_core::storage_authority::{
    external_object::{
        ExternalObjectRequest, ExternalObjectResult, EXTERNAL_OBJECT_PATH,
        MAX_EXTERNAL_OBJECT_REQUEST_BYTES,
    },
    lease::LeaseCohort,
};
use aos_hub_core::storage_work::{
    StorageBindingPublication, StorageBindingSnapshot, StorageCredentialSelector, StorageWorkKey,
    StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
    STORAGE_WORK_SIGNATURE_HEADER,
};
use base64::Engine as _;
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response};

use super::{
    config::{configured, coordinates, Config},
    protocol::{
        self, Effect, GuardOperation, GuardReply, GuardRequest, HeadValue, Intent, Outcome,
        Receipt, DOMAIN, GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER,
    },
    storage,
};

pub(crate) const PATH: &str = EXTERNAL_OBJECT_PATH;

/// Refuses configured physical aliases on legacy Hybrid paths before egress.
///
/// # Errors
/// Returns an error for managed coordinates or malformed consumer configuration.
pub(crate) fn deny_legacy(env: &Env, snapshot: &StorageBindingSnapshot) -> Result<()> {
    if let Some(config) = configured(env)? {
        ensure!(
            !config.manages(snapshot)?,
            "managed external alias requires compact object consumer"
        );
    }
    Ok(())
}

/// Executes only authenticated bounded metadata PUT or historical guarded HEAD.
///
/// # Errors
/// Returns a generic response for invalid grants, unknown turns or provider I/O.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match execute(&mut request, env).await {
        Ok(value) => {
            let headers = Headers::new();
            headers.set("cache-control", "private, no-store")?;
            Ok(Response::from_json(&value)?.with_headers(headers))
        }
        Err(_) => Ok(Response::error("external object request refused", 409)?),
    }
}

async fn execute(request: &mut Request, env: &Env) -> Result<ExternalObjectResult> {
    ensure!(request.method() == Method::Post, "invalid consumer method");
    let config =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external object consumer disabled"))?;
    let signature = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("application signature missing"))?;
    let body = crate::hybrid::read_bounded_body(request, MAX_EXTERNAL_OBJECT_REQUEST_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("oversized application request"))?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let application_key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
    let work = ExternalObjectRequest::authenticate(
        &application_key,
        &signature,
        &body,
        &deployment,
        config.clock().observed_at,
    )?;
    let publication = crate::hybrid_binding::resolve_for_plan(env, &work.plan).await?;
    publication
        .snapshot
        .authorizes(&work.plan, &deployment, config.clock().observed_at)?;
    execute_authorized(env, config, work, &publication, deployment).await
}

/// Executes a Native-signed conditional delete through the configured issuer.
///
/// The claim ID, exact version, and immutable binding revision survive fresh
/// application plans. Unknown turns and historical receipts are retained by
/// the existing permanent object guard, never by this executor's memory.
///
/// # Errors
/// Returns an error for unsupported provider/configuration, changed credentials,
/// expiry, physical uncertainty, or an unacknowledged conditional effect.
pub(crate) async fn execute_delete_plan(
    env: &Env,
    plan: &StorageWorkPlan,
    publication: &StorageBindingPublication,
) -> Result<StorageWorkResult> {
    let StorageWorkOperation::DeleteIfMatches {
        claim_id,
        delete_binding_write_revision,
        ..
    } = &plan.operation
    else {
        anyhow::bail!("external delete dispatcher requires a conditional claim");
    };
    let revision = delete_binding_write_revision
        .ok_or_else(|| anyhow::anyhow!("external delete authority revision missing"))?;
    let config =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external object consumer disabled"))?;
    let cohort = select_cohort(&config, publication, "delete", revision)?;
    ensure!(
        plan.credential_references
            .contains(&StorageCredentialSelector {
                purpose: "delete".into(),
                generation: cohort.credential.generation.get(),
            }),
        "delete cohort does not match signed generation"
    );
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let work = ExternalObjectRequest {
        version: 1,
        domain:
            aos_hub_core::storage_authority::external_object::EXTERNAL_OBJECT_APPLICATION_DOMAIN
                .into(),
        operation_id: claim_id.clone(),
        binding_write_revision: aos_hub_core::storage_authority::lease::LeaseInteger::new(
            revision,
        )?,
        plan: plan.clone(),
        lease: String::new(),
    };
    work.validate(&deployment, config.clock().observed_at)?;
    publication
        .snapshot
        .authorizes(plan, &deployment, config.clock().observed_at)?;
    let result = execute_authorized(env, config, work, publication, deployment).await?;
    let outcome = match result.outcome {
        Outcome::DeleteAcknowledged { etag, .. } => StorageWorkOutcome::ObjectDeleted { etag },
        Outcome::DeleteAbsent => StorageWorkOutcome::NotFound,
        Outcome::DeletePreconditionFailed => StorageWorkOutcome::DeletePreconditionFailed,
        _ => anyhow::bail!("external guard returned another effect"),
    };
    Ok(crate::surface::storage_work_result(plan, outcome, 0))
}

/// Reads an exact deletion receipt without renewal or provider material.
///
/// # Errors
/// Returns an error for changed originals, held uncertainty, or an unavailable
/// permanent guard. `None` means no turn was found and grants no dispatch.
pub(crate) async fn lookup_delete_plan(
    env: &Env,
    plan: &StorageWorkPlan,
    publication: &StorageBindingPublication,
) -> Result<Option<StorageWorkResult>> {
    let StorageWorkOperation::DeleteIfMatches {
        path,
        claim_id,
        expected_etag,
        expected_size,
        expected_hash,
        expected_provider_version,
        delete_binding_write_revision,
    } = &plan.operation
    else {
        anyhow::bail!("delete lookup requires an exact conditional claim");
    };
    let revision = delete_binding_write_revision
        .ok_or_else(|| anyhow::anyhow!("delete lookup revision absent"))?;
    let config =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external object consumer disabled"))?;
    let cohort = select_cohort(&config, publication, "delete", revision)?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let work = ExternalObjectRequest {
        version: 1,
        domain:
            aos_hub_core::storage_authority::external_object::EXTERNAL_OBJECT_APPLICATION_DOMAIN
                .into(),
        operation_id: claim_id.clone(),
        binding_write_revision: aos_hub_core::storage_authority::lease::LeaseInteger::new(
            revision,
        )?,
        plan: plan.clone(),
        lease: String::new(),
    };
    work.validate(&deployment, config.clock().observed_at)?;
    publication
        .snapshot
        .authorizes(plan, &deployment, config.clock().observed_at)?;
    let expected =
        aos_hub_core::storage_authority::external_object::deletion::ExternalDeletePrecondition {
            provider_version: expected_provider_version
                .clone()
                .ok_or_else(|| anyhow::anyhow!("versioned delete unsupported"))?,
            etag: expected_etag.clone(),
            bytes: expected_size.to_string(),
            content_hash: expected_hash.clone(),
        };
    expected.validate()?;
    let intent = make_intent(
        &config,
        publication,
        &work,
        cohort,
        Effect::Delete { expected },
        path,
    )?;
    match call(
        env,
        &GuardRequest {
            domain: DOMAIN.into(),
            scope: intent.scope.clone(),
            operation: GuardOperation::Lookup {
                intent: intent.clone(),
            },
        },
    )
    .await?
    {
        GuardReply::Unseen => Ok(None),
        GuardReply::Terminal { receipt } => {
            let result = result(&intent, &receipt)?;
            let outcome = match result.outcome {
                Outcome::DeleteAcknowledged { etag, .. } => {
                    StorageWorkOutcome::ObjectDeleted { etag }
                }
                Outcome::DeleteAbsent => StorageWorkOutcome::NotFound,
                Outcome::DeletePreconditionFailed => StorageWorkOutcome::DeletePreconditionFailed,
                _ => anyhow::bail!("lookup returned another effect"),
            };
            Ok(Some(crate::surface::storage_work_result(plan, outcome, 0)))
        }
        _ => anyhow::bail!("delete lookup returned a dispatch permit"),
    }
}

/// Executes only bounded service-owned delete capability probes.
///
/// # Errors
/// Returns an error for another key/operation, unavailable configured cohorts,
/// expiry, provider refusal, or held uncertainty. No object body is returned.
pub(crate) async fn execute_probe_plan(
    env: &Env,
    plan: &StorageWorkPlan,
    publication: &StorageBindingPublication,
) -> Result<StorageWorkResult> {
    let (path, purpose) = match &plan.operation {
        StorageWorkOperation::PutProbe { path, .. } => (path, "write"),
        StorageWorkOperation::Head { path } | StorageWorkOperation::InspectSha256 { path, .. } => {
            (path, "read")
        }
        _ => anyhow::bail!("unsupported delete capability probe"),
    };
    ensure!(
        aos_hub_core::storage_work::admitted_probe_path(path),
        "probe key outside reserved namespace"
    );
    let config =
        configured(env)?.ok_or_else(|| anyhow::anyhow!("external object consumer disabled"))?;
    let mut cohorts = config.cohorts.iter().filter(|cohort| {
        cohort.association.binding_id.get() == plan.binding_id
            && cohort.association.binding_resource_version.get() == plan.binding_resource_version
            && match purpose {
                "read" => {
                    cohort.credential.purpose
                        == aos_hub_core::storage_authority::lease::LeasePurpose::Read
                }
                "write" => {
                    cohort.credential.purpose
                        == aos_hub_core::storage_authority::lease::LeasePurpose::Write
                }
                _ => false,
            }
            && plan
                .credential_references
                .contains(&StorageCredentialSelector {
                    purpose: purpose.into(),
                    generation: cohort.credential.generation.get(),
                })
    });
    let cohort = cohorts
        .next()
        .ok_or_else(|| anyhow::anyhow!("probe cohort unavailable"))?;
    ensure!(cohorts.next().is_none(), "probe cohort ambiguous");
    let domains = super::delete_config::configured(env, &config)?;
    let mut domains = domains.domains.iter().filter(|domain| {
        domain.delete_cohort.authority == cohort.authority
            && domain.delete_cohort.association == cohort.association
    });
    let domain = domains
        .next()
        .ok_or_else(|| anyhow::anyhow!("probe issuer domain unavailable"))?;
    ensure!(domains.next().is_none(), "probe issuer domain ambiguous");
    let lease = super::stage::acquire_configured_lease(
        env,
        &config,
        &domain.issuer_installation,
        cohort,
        &cohort.admitted_prefix,
    )
    .await?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let work = ExternalObjectRequest {
        version: 1,
        domain:
            aos_hub_core::storage_authority::external_object::EXTERNAL_OBJECT_APPLICATION_DOMAIN
                .into(),
        operation_id: plan.plan_id.clone(),
        binding_write_revision: cohort.association.binding_write_revision,
        plan: plan.clone(),
        lease,
    };
    work.validate(&deployment, config.clock().observed_at)?;
    publication
        .snapshot
        .authorizes(plan, &deployment, config.clock().observed_at)?;
    let result = execute_authorized(env, config, work, publication, deployment).await?;
    let (outcome, source_bytes) = match result.outcome {
        Outcome::PutAcknowledged => (StorageWorkOutcome::ProbeAcknowledged, 0),
        Outcome::HistoricalHead { object: None } => (StorageWorkOutcome::NotFound, 0),
        Outcome::HistoricalHead {
            object: Some(object),
        } => (
            StorageWorkOutcome::Head {
                object: aos_hub_core::storage_work::StorageObjectIdentity {
                    key: plan.object_key(path)?,
                    size: object.bytes.parse()?,
                    etag: object.etag,
                    provider_version: object.provider_version,
                },
            },
            0,
        ),
        Outcome::ProbeEvidence { object, sha256 } => {
            if let StorageWorkOperation::InspectSha256 {
                expected_sha256: Some(expected),
                ..
            } = &plan.operation
            {
                ensure!(expected == &sha256, "probe hash differs");
            }
            let size = object.bytes.parse()?;
            (
                StorageWorkOutcome::Sha256Evidence {
                    object: aos_hub_core::storage_work::StorageObjectIdentity {
                        key: plan.object_key(path)?,
                        size,
                        etag: object.etag,
                        provider_version: object.provider_version,
                    },
                    sha256,
                },
                size,
            )
        }
        _ => anyhow::bail!("probe returned another effect"),
    };
    Ok(crate::surface::storage_work_result(
        plan,
        outcome,
        source_bytes,
    ))
}

async fn execute_authorized(
    env: &Env,
    config: Config,
    mut work: ExternalObjectRequest,
    publication: &StorageBindingPublication,
    deployment: String,
) -> Result<ExternalObjectResult> {
    let (path, effect, bytes, purpose) = match &work.plan.operation {
        StorageWorkOperation::PutMetadata {
            path,
            content_base64,
            sha256,
        } => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(content_base64)?;
            ensure!(
                bytes.len() <= aos_hub_core::storage_work::MAX_METADATA_BYTES
                    && hex::encode(Sha256::digest(&bytes)) == *sha256,
                "metadata commitment differs"
            );
            (
                path,
                Effect::Put {
                    sha256: sha256.clone(),
                    bytes: u32::try_from(bytes.len())?,
                },
                Some(bytes),
                "write",
            )
        }
        StorageWorkOperation::Head { path } => (path, Effect::Head, None, "read"),
        StorageWorkOperation::InspectSha256 {
            path,
            max_source_bytes,
            ..
        } => {
            ensure!(
                aos_hub_core::storage_work::admitted_probe_path(path) && *max_source_bytes <= 4096,
                "external hash operation exceeds reserved probe scope"
            );
            (
                path,
                Effect::ProbeHash {
                    maximum_bytes: u32::try_from(*max_source_bytes)?,
                },
                None,
                "read",
            )
        }
        StorageWorkOperation::PutProbe {
            path,
            content_base64,
        } => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(content_base64)?;
            ensure!(bytes.len() <= 4096, "oversized delete capability probe");
            (
                path,
                Effect::Put {
                    sha256: hex::encode(Sha256::digest(&bytes)),
                    bytes: u32::try_from(bytes.len())?,
                },
                Some(bytes),
                "write",
            )
        }
        StorageWorkOperation::DeleteIfMatches {
            path,
            claim_id,
            expected_etag,
            expected_size,
            expected_hash,
            expected_provider_version,
            delete_binding_write_revision,
        } => {
            ensure!(
                claim_id == &work.operation_id
                    && *delete_binding_write_revision == Some(work.binding_write_revision.get()),
                "delete original differs"
            );
            let expected =
                aos_hub_core::storage_authority::external_object::deletion::ExternalDeletePrecondition {
                    provider_version: expected_provider_version
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("versioned delete unsupported"))?,
                    etag: expected_etag.clone(),
                    bytes: expected_size.to_string(),
                    content_hash: expected_hash.clone(),
                };
            expected.validate()?;
            (path, Effect::Delete { expected }, None, "delete")
        }
        _ => anyhow::bail!("unsupported compact external operation"),
    };
    let cohort = select_cohort(
        &config,
        &publication,
        purpose,
        work.binding_write_revision.get(),
    )?;
    let intent = make_intent(&config, &publication, &work, cohort, effect, path)?;
    let scope = intent.scope.clone();
    intent.validate()?;
    if matches!(intent.effect, Effect::Delete { .. }) {
        // Exact historical receipts need no renewal. A held unknown turn is
        // refused by this read-only lookup and never gets another permit.
        let lookup = GuardRequest {
            domain: DOMAIN.into(),
            scope: scope.clone(),
            operation: GuardOperation::Lookup {
                intent: intent.clone(),
            },
        };
        match call(env, &lookup).await? {
            GuardReply::Terminal { receipt } => return result(&intent, &receipt),
            GuardReply::Unseen => {}
            _ => anyhow::bail!("delete lookup returned a dispatch permit"),
        }
        let domains = super::delete_config::configured(env, &config)?;
        let domain = domains.domain(cohort)?;
        work.lease = super::stage::acquire_configured_lease(
            env,
            &config,
            &domain.issuer_installation,
            cohort,
            &cohort.admitted_prefix,
        )
        .await?;
        work.validate(&deployment, config.clock().observed_at)?;
        publication
            .snapshot
            .authorizes(&work.plan, &deployment, config.clock().observed_at)?;
    }
    let begin = GuardRequest {
        domain: DOMAIN.into(),
        scope: scope.clone(),
        operation: GuardOperation::Begin {
            intent: intent.clone(),
            lease: work.lease.clone(),
        },
    };
    let reply = call(env, &begin).await?;
    let (turn, floor) = match reply {
        GuardReply::Terminal { receipt } => return result(&intent, &receipt),
        GuardReply::Dispatch { turn, floor } => (turn, floor),
        GuardReply::Unseen => anyhow::bail!("guard begin returned no retained dispatch"),
    };
    ensure!(
        turn.intent == intent && protocol::digest_string(&turn.dispatch_nonce),
        "guard acknowledged another turn"
    );
    ensure!(
        floor.full_key == scope.full_key
            && floor.authority == cohort.authority
            && floor.executor_identity == config.executor_identity,
        "guard floor differs from configured execution domain"
    );

    // All async resolution and guard acknowledgement has finished. Provider
    // credentials are request-local; the URL is minted only for this dispatch.
    let now = config.clock().observed_at;
    publication
        .snapshot
        .authorizes(&work.plan, &deployment, now)?;
    let selector = StorageCredentialSelector {
        purpose: purpose.into(),
        generation: cohort.credential.generation.get(),
    };
    let secret = publication.credential_text(&selector, &deployment, now)?;
    let surface = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        &work.plan.placement_prefix,
        Some(secret.as_str()),
        now,
    )?;
    let outcome = if let Effect::Delete { expected } = &intent.effect {
        super::deletion::runtime::execute(
            env,
            &config,
            &publication,
            &work,
            &intent,
            &floor,
            expected,
            path,
        )
        .await?
    } else {
        let method = match intent.effect {
            Effect::Put { .. } => S3Method::Put,
            Effect::Head => S3Method::Head,
            Effect::ProbeHash { .. } => S3Method::Get,
            Effect::Delete { .. } => anyhow::bail!("delete bypassed its versioned dispatcher"),
        };
        let url = surface.object_url(method, path, now)?;
        aos_hub_core::url_guard::is_safe_remote_url(&url)?;
        let mut init = RequestInit::new();
        init.with_method(match intent.effect {
            Effect::Put { .. } => Method::Put,
            Effect::Head => Method::Head,
            Effect::ProbeHash { .. } => Method::Get,
            Effect::Delete { .. } => anyhow::bail!("conditional delete bypassed its dispatcher"),
        })
        .with_redirect(RequestRedirect::Manual);
        if let Some(bytes) = bytes.as_ref() {
            init.with_body(Some(js_sys::Uint8Array::from(bytes.as_slice()).into()));
        }
        let provider = Request::new_with_init(&url, &init)?;

        // No awaited helper lies between this validation and actual provider Fetch.
        // This is bounded new-dispatch revocation, not immediate global deny/drain.
        let validated = config.verifier()?.validate_lease(
            work.lease.as_bytes(),
            cohort,
            &config.timing_profile,
            &floor,
            &scope.full_key,
            intent.effect.lease_effect(),
            config.clock(),
        )?;
        work.check_dispatch_time(&publication.snapshot, &validated, &floor, config.clock())?;
        let mut response = Fetch::Request(provider).send().await?;
        let outcome = match &intent.effect {
            Effect::Put { .. } => {
                ensure!(
                    response.status_code() == 200,
                    "provider PUT lacks exact S3 completion acknowledgement"
                );
                Outcome::PutAcknowledged
            }
            Effect::Head => match response.status_code() {
                404 => Outcome::HistoricalHead { object: None },
                200 => {
                    let bytes = response
                        .headers()
                        .get("content-length")?
                        .ok_or_else(|| anyhow::anyhow!("HEAD length missing"))?;
                    let etag = response
                        .headers()
                        .get("etag")?
                        .ok_or_else(|| anyhow::anyhow!("HEAD ETag missing"))?;
                    Outcome::HistoricalHead {
                        object: Some(HeadValue {
                            bytes,
                            etag,
                            provider_version: response.headers().get("x-amz-version-id")?,
                        }),
                    }
                }
                _ => anyhow::bail!("provider HEAD not positively acknowledged"),
            },
            Effect::Delete { .. } => anyhow::bail!("delete bypassed its versioned dispatcher"),
            Effect::ProbeHash { maximum_bytes } => {
                ensure!(
                    response.status_code() == 200,
                    "probe GET not positively acknowledged"
                );
                let bytes = response
                    .headers()
                    .get("content-length")?
                    .ok_or_else(|| anyhow::anyhow!("probe length absent"))?;
                let etag = response
                    .headers()
                    .get("etag")?
                    .ok_or_else(|| anyhow::anyhow!("probe ETag absent"))?;
                let provider_version = response.headers().get("x-amz-version-id")?;
                let mut stream = response.stream()?;
                let mut collected = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    ensure!(
                        collected
                            .len()
                            .checked_add(chunk.len())
                            .is_some_and(|size| size <= *maximum_bytes as usize),
                        "probe body oversized"
                    );
                    collected.extend_from_slice(&chunk);
                }
                ensure!(
                    collected.len().to_string() == bytes,
                    "probe body length changed"
                );
                Outcome::ProbeEvidence {
                    object: HeadValue {
                        bytes,
                        etag,
                        provider_version,
                    },
                    sha256: hex::encode(Sha256::digest(collected)),
                }
            }
        };
        outcome
    };
    let receipt = Receipt { turn, outcome };
    receipt.validate()?;
    let terminal = GuardRequest {
        domain: DOMAIN.into(),
        scope,
        operation: GuardOperation::Terminal {
            receipt: receipt.clone(),
        },
    };
    match call(env, &terminal).await? {
        GuardReply::Terminal {
            receipt: acknowledged,
        } if acknowledged == receipt => result(&intent, &acknowledged),
        _ => anyhow::bail!("terminal acknowledgement differs"),
    }
}

pub(super) fn select_cohort<'a>(
    config: &'a Config,
    publication: &StorageBindingPublication,
    purpose: &str,
    binding_write_revision: i64,
) -> Result<&'a LeaseCohort> {
    let snapshot = &publication.snapshot;
    let coordinates = coordinates(snapshot)?;
    let candidates = config
        .cohorts
        .iter()
        .filter(|cohort| {
            let association = &cohort.association;
            let credential = &cohort.credential;
            cohort.alias.spec == coordinates
                && association.binding_write_revision.get() == binding_write_revision
                && association.binding_id.get() == snapshot.binding_id
                && association.binding_stable_id == snapshot.binding_stable_id
                && association.binding_resource_version.get() == snapshot.binding_resource_version
                && association.binding_prefix == snapshot.object_prefix
                && snapshot.credentials.iter().any(|reference| {
                    reference.purpose == purpose
                        && reference.generation == credential.generation.get()
                        && reference.secret_version_ref == credential.secret_version_ref
                        && reference.fingerprint == credential.credential_fingerprint
                })
                && matches!(
                    (purpose, credential.purpose),
                    (
                        "read",
                        aos_hub_core::storage_authority::lease::LeasePurpose::Read
                    ) | (
                        "write",
                        aos_hub_core::storage_authority::lease::LeasePurpose::Write
                    ) | (
                        "delete",
                        aos_hub_core::storage_authority::lease::LeasePurpose::Delete
                    )
                )
        })
        .collect::<Vec<_>>();
    ensure!(
        candidates.len() == 1,
        "binding does not select one configured cohort"
    );
    Ok(candidates[0])
}

fn make_intent(
    config: &Config,
    publication: &StorageBindingPublication,
    work: &ExternalObjectRequest,
    cohort: &LeaseCohort,
    effect: Effect,
    path: &str,
) -> Result<Intent> {
    let full_key = [
        publication.snapshot.object_prefix.as_str(),
        work.plan.placement_prefix.as_str(),
        path,
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join("/");
    Ok(Intent {
        scope: config.scope(cohort, full_key)?,
        operation_id: work.operation_id.clone(),
        context: protocol::digest(&(
            cohort,
            work.plan.placement_id,
            work.plan.placement_resource_version,
            &work.plan.placement_prefix,
        ))?,
        cohort_digest: protocol::digest(cohort)?,
        effect,
    })
}

fn result(intent: &Intent, receipt: &Receipt) -> Result<ExternalObjectResult> {
    receipt.validate()?;
    ensure!(
        receipt.turn.intent == *intent,
        "terminal replay context differs"
    );
    Ok(ExternalObjectResult {
        version: 1,
        operation_id: intent.operation_id.clone(),
        intent_digest: intent.fingerprint()?,
        outcome: receipt.outcome.clone(),
    })
}

async fn call(env: &Env, message: &GuardRequest) -> Result<GuardReply> {
    let body = serde_json::to_vec(message)?;
    ensure!(body.len() <= MAX_MESSAGE, "oversized compact turn");
    let signature = storage::key(env)?.sign_body(&body)?;
    let name = message.scope.guard_name()?;
    let namespace = env.durable_object(storage::BINDING)?;
    let stub = namespace.id_from_name(&name)?.get_stub()?;
    let headers = Headers::new();
    headers.set(GUARD_HEADER, &signature)?;
    headers.set(SCOPE_HEADER, &name)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request = Request::new_with_init("https://external-object/turn", &init)?;
    let mut response = stub.fetch_with_request(request).await?;
    ensure!(
        response.status_code() == 200,
        "object journal refused compact turn"
    );
    let mut stream = response.stream()?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            body.len()
                .checked_add(chunk.len())
                .is_some_and(|n| n <= MAX_MESSAGE),
            "oversized guard reply"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}
