//! Outer byte executor for retained private staging and guarded final visibility.
//!
//! The physical-key DO holds only compact intent, manifests and receipts. Native
//! sees compact results; provider bytes remain here or inside UploadPartCopy.
//! Unknown mutation outcomes do not produce acknowledgements or clear turns.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::{
    canonical_manifest_digest, DirectCredentialRevision, DirectManifestPart,
};
use aos_hub_core::s3surface::{self, Method as S3Method, S3Surface};
use aos_hub_core::storage_authority::{
    external_object::stage::{
        ExternalStageAdmissionMode, ExternalStageOperation as Action,
        ExternalStageOutcome as Outcome, ExternalStageRequest, ExternalStageResult,
        EXTERNAL_STAGE_PATH, EXTERNAL_STAGE_SIGNATURE_HEADER, MAX_EXTERNAL_STAGE_REQUEST_BYTES,
    },
    lease::{EpochLeaseFloor, LeaseEffect},
    GuardIncarnation, StorageGuardStamp,
};
use aos_hub_core::storage_work::{
    StorageBindingPublication, StorageCredentialSelector, StorageWorkKey,
};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response};

use super::super::{
    config::{configured, coordinates, Config as ObjectConfig},
    protocol::{digest, GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER},
    storage,
};
use super::{
    config::{self, Config},
    protocol::{self, Intent, Operation, Receipt, Reply, SourceProof, Turn},
};

const EXECUTOR_KEY: &str = "HUB_EXTERNAL_STAGE_KEY";
const PROVIDER_URL_SECONDS: u32 = 30;

/// Serves only closed authenticated internal staging controls.
///
/// # Errors
/// Returns a redacted refusal for invalid configuration, state or provider I/O.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    let result = async {
        ensure!(
            request.method() == Method::Post && request.url()?.path() == EXTERNAL_STAGE_PATH,
            "invalid external stage route"
        );
        let signature = request
            .headers()
            .get(EXTERNAL_STAGE_SIGNATURE_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("stage executor signature missing"))?;
        let bytes =
            crate::hybrid::read_bounded_body(&mut request, MAX_EXTERNAL_STAGE_REQUEST_BYTES)
                .await?
                .ok_or_else(|| anyhow::anyhow!("stage executor request oversized"))?;
        let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let work = ExternalStageRequest::authenticate(
            &executor_key(env)?,
            &signature,
            &bytes,
            &deployment,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        execute_stage(env, &work).await
    }
    .await;
    match result {
        Ok(result) => {
            let headers = Headers::new();
            headers.set("cache-control", "private, no-store")?;
            Ok(Response::from_json(&result)?.with_headers(headers))
        }
        Err(_) => Response::error("external stage request refused", 409),
    }
}

/// Executes the broker's exact retained external placement without bulk RPCs.
///
/// The caller authenticates the original logical admission before invoking this
/// internal seam. Protected configuration and physical journal are still checked
/// here. A historical terminal is returned before credential or lease renewal.
///
/// # Errors
/// Returns a value-free failure for absent qualification, changed context,
/// pending uncertainty, expired permission or an unacknowledged provider effect.
pub(crate) async fn execute_stage(
    env: &Env,
    work: &ExternalStageRequest,
) -> Result<ExternalStageResult> {
    execute_stage_observed(env, work, &|| {}).await
}

/// Observes actual provider dispatch while preserving retained terminal replay.
///
/// The observer runs after final eligibility checks, immediately before Fetch.
/// Returning a retained physical receipt never invokes it.
///
/// # Errors
/// Returns the same configuration, authorization, unknown-effect and provider
/// errors as [`execute_stage`].
pub(crate) async fn execute_stage_observed(
    env: &Env,
    work: &ExternalStageRequest,
    before_dispatch: &dyn Fn(),
) -> Result<ExternalStageResult> {
    executor_key(env)?;
    let object = configured(env)?.ok_or_else(|| anyhow::anyhow!("object consumer disabled"))?;
    let config = config::configured(env, &object)?
        .ok_or_else(|| anyhow::anyhow!("stage consumer disabled"))?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    work.validate(&deployment, object.clock().observed_at)?;
    config.domain(&work.context)?;
    let intent = Intent {
        operation_id: work.operation_id.clone(),
        context: work.context.clone(),
        operation: work.operation.clone(),
    };
    intent.validate()?;
    let scope = intent.scope()?;

    // This readonly lookup cannot infer settlement from a missing receipt. The
    // subsequent Begin still refuses every unrelated or unknown mutation.
    match call(
        env,
        &protocol::Request {
            domain: protocol::DOMAIN.into(),
            scope: scope.clone(),
            operation: Operation::Lookup {
                intent: intent.clone(),
            },
        },
    )
    .await?
    {
        Reply::Terminal { receipt } => return checked_result(&intent, &receipt),
        Reply::Unsettled => {}
        _ => anyhow::bail!("stage lookup reply differs"),
    }

    let recovery = if work.admission_mode == ExternalStageAdmissionMode::ResumeImmutableRead {
        Some(recovery_read(env, &intent).await?)
    } else {
        ensure!(
            object.clock().observed_at < i64::try_from(work.context.logical_expires_at.get())?,
            "original logical stage eligibility expired"
        );
        None
    };
    let publication = crate::hybrid_binding::resolve_for_delivery(
        env,
        i64::try_from(work.context.placement.binding_id.get())?,
        i64::try_from(work.context.placement.binding_resource_version.get())?,
    )
    .await?;
    validate_publication(&object, &config, work, &publication, &deployment)?;
    let source = if work.operation.destination() {
        let expected = match &work.operation {
            Action::CreateDestination {
                verified_stage_receipt_digest,
            }
            | Action::CopyDestinationPart {
                verified_stage_receipt_digest,
                ..
            }
            | Action::CompleteDestination {
                verified_stage_receipt_digest,
                ..
            }
            | Action::AbortDestination {
                verified_stage_receipt_digest,
                ..
            } => verified_stage_receipt_digest.clone(),
            _ => anyhow::bail!("invalid destination stage operation"),
        };
        Some(source_proof(env, work, &expected).await?)
    } else {
        None
    };
    let reply = call(
        env,
        &protocol::Request {
            domain: protocol::DOMAIN.into(),
            scope: scope.clone(),
            operation: Operation::Begin {
                admission_mode: work.admission_mode,
                intent: intent.clone(),
                write_lease: work.write_lease.clone(),
                read_lease: work.read_lease.clone(),
                source,
            },
        },
    )
    .await?;
    let (turn, floor, source, direct_permission_expires_at) = match reply {
        Reply::Terminal { receipt } => return checked_result(&intent, &receipt),
        Reply::Dispatch {
            turn,
            floor,
            source,
            direct_permission_expires_at,
        } => (turn, floor, source, direct_permission_expires_at),
        _ => anyhow::bail!("stage begin reply differs"),
    };
    ensure!(
        turn.intent == intent
            && recovery.as_ref().is_none_or(|retained| retained == &turn)
            && super::super::protocol::digest_string(&turn.dispatch_nonce)
            && floor.full_key == scope.full_key
            && floor.executor_identity == object.executor_identity,
        "stage dispatch projection changed"
    );
    let domain = config.domain(&work.context)?;
    ensure!(
        floor.authority == domain.write_cohort.authority,
        "stage authority differs"
    );

    let parts = if matches!(
        work.operation,
        Action::CompleteStage { .. }
            | Action::CompleteDestination { .. }
            | Action::VerifyClosedStage { .. }
    ) {
        load_manifest(env, &turn).await?
    } else {
        Vec::new()
    };
    if let Action::CompleteStage { manifest, .. } | Action::CompleteDestination { manifest, .. } =
        &work.operation
    {
        ensure!(
            canonical_manifest_digest(&work.context.intent, &manifest.placement, &parts)?
                == manifest.manifest_digest,
            "retained manifest commitment differs"
        );
    }

    let read = work.operation.immutable_read();
    let selected = if read {
        &domain.read_credential
    } else {
        &domain.write_credential
    };
    let now = object.clock().observed_at;
    let secret = publication.credential_text(
        &StorageCredentialSelector {
            purpose: selected.purpose.clone(),
            generation: i64::try_from(selected.generation.get())?,
        },
        &deployment,
        now,
    )?;
    let surface = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        "",
        Some(secret.as_str()),
        now,
    )?;
    let relative = relative_key(&publication.snapshot.object_prefix, &scope.full_key)?;
    let outcome = dispatch(
        env,
        work,
        &object,
        &config,
        &publication,
        &surface,
        relative,
        &turn,
        &floor,
        source.as_ref(),
        &parts,
        direct_permission_expires_at,
        before_dispatch,
    )
    .await?;
    let receipt = Receipt { turn, outcome };
    receipt.validate()?;
    match call(
        env,
        &protocol::Request {
            domain: protocol::DOMAIN.into(),
            scope,
            operation: Operation::Terminal {
                receipt: receipt.clone(),
            },
        },
    )
    .await?
    {
        Reply::Terminal {
            receipt: acknowledged,
        } if acknowledged == receipt => checked_result(&intent, &acknowledged),
        _ => anyhow::bail!("stage terminal acknowledgement differs"),
    }
}

/// Returns a retained projection only; Begin must repeat admission under CAS.
pub(super) async fn recovery_read(env: &Env, intent: &Intent) -> Result<Turn> {
    match call(
        env,
        &protocol::Request {
            domain: protocol::DOMAIN.into(),
            scope: intent.scope()?,
            operation: Operation::RecoveryRead {
                intent: intent.clone(),
            },
        },
    )
    .await?
    {
        Reply::RecoveryRead { turn, floor } => {
            ensure!(
                turn.intent == *intent && floor.full_key == intent.scope()?.full_key,
                "recovery projection changed original owner"
            );
            Ok(turn)
        }
        _ => anyhow::bail!("recovery lacks exact retained immutable read"),
    }
}

async fn dispatch(
    _env: &Env,
    work: &ExternalStageRequest,
    object: &ObjectConfig,
    config: &Config,
    publication: &StorageBindingPublication,
    surface: &S3Surface,
    relative: &str,
    turn: &Turn,
    floor: &EpochLeaseFloor,
    source: Option<&SourceProof>,
    parts: &[DirectManifestPart],
    direct_permission_expires_at: Option<aos_hub_core::direct_upload::WireInteger>,
    before_dispatch: &dyn Fn(),
) -> Result<Outcome> {
    let now = object.clock().observed_at;
    let domain = config.domain(&work.context)?;
    let headers = Headers::new();
    let mut body = None;
    let (url, method) = match &work.operation {
        Action::CreateStage | Action::CreateDestination { .. }
            if work.context.intent.byte_size.get() == 0 =>
        {
            anyhow::bail!("external empty-object deletion is not qualified")
        }
        Action::CreateStage | Action::CreateDestination { .. } => {
            let signed = surface.direct_create_multipart_request(
                relative,
                work.context.placement.checksum_algorithm,
                now,
                PROVIDER_URL_SECONDS,
            )?;
            for header in signed.required_headers {
                headers.set(&header.name, &header.value)?;
            }
            (signed.url, Method::Post)
        }
        Action::CompleteStage {
            upload_id,
            manifest,
        }
        | Action::CompleteDestination {
            upload_id,
            manifest,
            ..
        } => {
            body = Some(
                s3surface::direct_complete_multipart_xml(
                    &work.context.intent,
                    &manifest.placement,
                    parts,
                )?
                .into_bytes(),
            );
            headers.set("content-type", "application/xml")?;
            (
                surface.multipart_url("complete", relative, Some(upload_id), None, now)?,
                Method::Post,
            )
        }
        Action::VerifyClosedStage { .. } => (
            surface.object_url(S3Method::Get, relative, now)?,
            Method::Get,
        ),
        Action::AbortStage { upload_id } | Action::AbortDestination { upload_id, .. } => (
            surface.multipart_url("abort", relative, Some(upload_id), None, now)?,
            Method::Delete,
        ),
        Action::CopyDestinationPart {
            upload_id, part, ..
        } => {
            let source =
                source.ok_or_else(|| anyhow::anyhow!("copy lost immutable source proof"))?;
            source.validate(&work.context, &digest(&source.verified)?)?;
            let source_key = work.context.stage_key()?;
            let last = part
                .offset
                .get()
                .checked_add(part.byte_size.get())
                .and_then(|end| end.checked_sub(1))
                .ok_or_else(|| anyhow::anyhow!("copy source range overflow"))?;
            let signed = surface.direct_upload_part_copy_request(
                relative,
                upload_id,
                part.part_number,
                &aos_hub_core::sigv4::DirectPartCopySource {
                    bucket: &publication.snapshot.object_bucket,
                    full_key: &source_key,
                    first_byte: part.offset.get(),
                    last_byte: last,
                },
                now,
                PROVIDER_URL_SECONDS,
            )?;
            for header in signed.required_headers {
                headers.set(&header.name, &header.value)?;
            }
            (signed.url, Method::Put)
        }
        Action::RegisterParts { .. } | Action::FreezeParts { .. } => {
            anyhow::bail!("metadata unexpectedly dispatched")
        }
    };
    aos_hub_core::url_guard::is_safe_remote_url(&url)?;
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_redirect(RequestRedirect::Manual)
        .with_headers(headers);
    if let Some(body) = body.as_ref() {
        init.with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    }
    let request = Request::new_with_init(&url, &init)?;
    validate_publication(
        object,
        config,
        work,
        publication,
        &publication.snapshot.deployment_id,
    )?;
    let read = work.operation.immutable_read();
    let (lease, cohort) = if read {
        (&work.read_lease, &domain.read_cohort)
    } else {
        (&work.write_lease, &domain.write_cohort)
    };
    let validated = object.verifier()?.validate_lease(
        lease.as_bytes(),
        cohort,
        &object.timing_profile,
        floor,
        &turn.intent.scope()?.full_key,
        super::state::effect(&work.operation, work.context.intent.byte_size.get() == 0),
        object.clock(),
    )?;
    let source_validated = if work.operation.destination() {
        let source =
            source.ok_or_else(|| anyhow::anyhow!("destination lacks immutable read admission"))?;
        Some(object.verifier()?.validate_lease(
            work.read_lease.as_bytes(),
            &domain.read_cohort,
            &object.timing_profile,
            &source.floor,
            &work.context.stage_key()?,
            LeaseEffect::Read,
            object.clock(),
        )?)
    } else {
        None
    };
    // Both crypto validations and all async guard/manifest/binding work finish
    // before a fresh scalar observation. Actual JS Fetch starts synchronously.
    let final_clock = object.clock();
    work.check_dispatch_time(&publication.snapshot, &validated, floor, final_clock)?;
    ensure!(
        u64::try_from(final_clock.observed_at)?
            .saturating_add(u64::try_from(final_clock.uncertainty)?)
            < work.expires_at.get(),
        "external original invocation expired before Fetch"
    );
    if let Some(validated) = source_validated.as_ref() {
        let source = source.ok_or_else(|| anyhow::anyhow!("destination lost source floor"))?;
        work.check_dispatch_time(&publication.snapshot, validated, &source.floor, final_clock)?;
    }
    if let Some(expires_at) = direct_permission_expires_at {
        ensure!(
            u64::try_from(final_clock.observed_at)?
                .saturating_add(u64::try_from(final_clock.uncertainty)?)
                < expires_at.get(),
            "direct external Native publication permission expired before Fetch"
        );
    }
    before_dispatch();
    crate::direct_upload::provider_capacity::record_dispatch();
    let response = Fetch::Request(request).send().await?;
    match &work.operation {
        Action::CreateStage | Action::CreateDestination { .. }
            if work.context.intent.byte_size.get() == 0 =>
        {
            ensure!(
                response.status_code() == 200,
                "empty staging PUT unacknowledged"
            );
            let etag = response
                .headers()
                .get("etag")?
                .ok_or_else(|| anyhow::anyhow!("empty stage ETag absent"))?;
            Ok(Outcome::EmptyClosed {
                etag,
                guard_stamp: stamp(turn)?,
            })
        }
        Action::CreateStage | Action::CreateDestination { .. } => {
            ensure!(
                response.status_code() == 200,
                "multipart Create unacknowledged"
            );
            let xml = provider_metadata(response).await?;
            let upload_id = s3surface::parse_direct_create_multipart(
                &xml,
                &publication.snapshot.object_bucket,
                &turn.intent.scope()?.full_key,
            )?;
            Ok(Outcome::Created { upload_id })
        }
        Action::CompleteStage { upload_id, .. } | Action::CompleteDestination { upload_id, .. } => {
            ensure!(
                response.status_code() == 200,
                "multipart Complete unacknowledged"
            );
            let xml = provider_metadata(response).await?;
            let positive = s3surface::parse_direct_complete_multipart(
                &xml,
                &publication.snapshot.object_bucket,
                &turn.intent.scope()?.full_key,
            )?;
            Ok(Outcome::Closed {
                upload_id: upload_id.clone(),
                etag: positive.etag,
                guard_stamp: stamp(turn)?,
            })
        }
        Action::VerifyClosedStage {
            close_receipt_digest,
            ..
        } => {
            let original = crate::direct_upload::observation::Object::new(
                &work.context.session_id,
                &work.context.logical_fingerprint,
                &work.context.intent,
                work.context.placement.placement_id,
                &work.operation_id,
            );
            let mut observed = crate::direct_upload::observation::Read::new(original);
            let verified = crate::direct_digest::verify_response_observed(
                response,
                &work.context.intent,
                parts,
                &|bytes| observed.consumed(bytes),
            )
            .await?;
            observed.positive();
            Ok(Outcome::Verified {
                sha256: verified.sha256,
                byte_size: aos_hub_core::direct_upload::WireInteger::new(verified.byte_size),
                close_receipt_digest: close_receipt_digest.clone(),
            })
        }
        Action::CopyDestinationPart { part, .. } => {
            ensure!(
                response.status_code() == 200,
                "multipart Copy unacknowledged"
            );
            let xml = provider_metadata(response).await?;
            let positive = s3surface::parse_direct_upload_part_copy(&xml)?;
            Ok(Outcome::Copied {
                part: part.clone(),
                etag: positive.etag,
            })
        }
        Action::AbortStage { upload_id } | Action::AbortDestination { upload_id, .. } => {
            // Exact positive Abort is provider-qualified UploadId visibility
            // closure. It does not prove drain/reclamation of outstanding parts.
            ensure!(
                response.status_code() == 204,
                "multipart Abort unacknowledged"
            );
            Ok(Outcome::Aborted {
                upload_id: upload_id.clone(),
            })
        }
        _ => anyhow::bail!("metadata operation reached provider"),
    }
}

pub(super) fn validate_publication(
    object: &ObjectConfig,
    config: &Config,
    work: &ExternalStageRequest,
    publication: &StorageBindingPublication,
    deployment: &str,
) -> Result<()> {
    let now = object.clock().observed_at;
    work.validate(deployment, now)?;
    let domain = config.domain(&work.context)?;
    validate_domain_publication(domain, publication, deployment, now)
}

pub(super) fn validate_domain_publication(
    domain: &super::config::Domain,
    publication: &StorageBindingPublication,
    deployment: &str,
    now: i64,
) -> Result<()> {
    publication.validate(deployment, now)?;
    let snapshot = &publication.snapshot;
    let association = &domain.write_cohort.association;
    ensure!(
        snapshot.access_mode == "private"
            && coordinates(snapshot)? == domain.write_cohort.alias.spec
            && snapshot.binding_id == association.binding_id.get()
            && snapshot.binding_stable_id == association.binding_stable_id
            && snapshot.binding_resource_version == association.binding_resource_version.get()
            && snapshot.object_prefix == association.binding_prefix,
        "private stage binding differs from independent publication"
    );
    for selected in [
        &domain.write_credential,
        &domain.read_credential,
        &domain.presign_credential,
    ] {
        validate_credential(selected, publication)?;
        let secret = publication.credential_text(
            &StorageCredentialSelector {
                purpose: selected.purpose.clone(),
                generation: i64::try_from(selected.generation.get())?,
            },
            deployment,
            now,
        )?;
        // A matching material hash alone does not establish a usable private
        // capability. Parse each exact purpose without returning its secret.
        S3Surface::from_snapshot(snapshot, deployment, "", Some(secret.as_str()), now)?;
    }
    Ok(())
}

fn validate_credential(
    selected: &DirectCredentialRevision,
    publication: &StorageBindingPublication,
) -> Result<()> {
    ensure!(
        publication
            .snapshot
            .credentials
            .iter()
            .any(|credential| credential.purpose == selected.purpose
                && u64::try_from(credential.generation).ok() == Some(selected.generation.get())
                && credential.secret_version_ref == selected.secret_version_ref
                && credential.fingerprint == selected.credential_fingerprint),
        "stage credential differs from exact published revision"
    );
    Ok(())
}

pub(super) fn relative_key<'a>(prefix: &str, full_key: &'a str) -> Result<&'a str> {
    if prefix.is_empty() {
        return Ok(full_key);
    }
    full_key
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .filter(|relative| !relative.is_empty())
        .ok_or_else(|| anyhow::anyhow!("stage escapes binding prefix"))
}

fn stamp(turn: &Turn) -> Result<StorageGuardStamp> {
    Ok(StorageGuardStamp {
        physical_authority_id: turn.intent.scope()?.physical_authority_id,
        incarnation: GuardIncarnation::parse(turn.expected_incarnation.get().to_string())?,
    })
}

fn checked_result(intent: &Intent, receipt: &Receipt) -> Result<ExternalStageResult> {
    ensure!(
        receipt.turn.intent == *intent,
        "historical stage receipt context differs"
    );
    receipt.result()
}

async fn source_proof(
    env: &Env,
    work: &ExternalStageRequest,
    receipt_digest: &str,
) -> Result<SourceProof> {
    let reply = call(
        env,
        &protocol::Request {
            domain: protocol::DOMAIN.into(),
            scope: work.context.scope(false)?,
            operation: Operation::SourceProof {
                context: work.context.clone(),
                receipt_digest: receipt_digest.into(),
                part_number: match &work.operation {
                    Action::CopyDestinationPart { part, .. } => Some(part.part_number),
                    _ => None,
                },
                read_lease: work.read_lease.clone(),
            },
        },
    )
    .await?;
    let Reply::SourceProof { proof, part } = reply else {
        anyhow::bail!("source proof reply differs");
    };
    proof.validate(&work.context, receipt_digest)?;
    match &work.operation {
        Action::CopyDestinationPart { part: expected, .. } => ensure!(
            part.as_ref() == Some(expected),
            "copy descriptor differs from the independently verified frozen source"
        ),
        _ => ensure!(part.is_none(), "unexpected source part projection"),
    }
    Ok(proof)
}

async fn load_manifest(env: &Env, turn: &Turn) -> Result<Vec<DirectManifestPart>> {
    let mut parts = Vec::new();
    let mut first_part = 1;
    loop {
        let reply = call(
            env,
            &protocol::Request {
                domain: protocol::DOMAIN.into(),
                scope: turn.intent.scope()?,
                operation: Operation::ManifestPage {
                    turn: turn.clone(),
                    first_part,
                    limit: protocol::MAX_PART_PAGE,
                },
            },
        )
        .await?;
        let Reply::ManifestPage {
            parts: page,
            next_part,
        } = reply
        else {
            anyhow::bail!("manifest page reply differs");
        };
        ensure!(
            page.len() <= protocol::MAX_PART_PAGE as usize
                && parts.len() + page.len() <= turn.intent.context.intent.part_count()? as usize,
            "manifest exceeds source geometry"
        );
        for (offset, part) in page.iter().enumerate() {
            ensure!(
                part.part.part_number as u64 == u64::from(first_part) + offset as u64,
                "manifest page order differs"
            );
        }
        let expected_next = first_part
            .checked_add(page.len() as u32)
            .ok_or_else(|| anyhow::anyhow!("manifest page count overflow"))?;
        parts.extend(page);
        if let Some(next) = next_part {
            ensure!(
                next == expected_next && next > first_part,
                "manifest continuation differs"
            );
            first_part = next;
        } else {
            break;
        }
    }
    ensure!(
        parts.len() == turn.intent.context.intent.part_count()? as usize,
        "manifest incomplete"
    );
    Ok(parts)
}

async fn provider_metadata(response: Response) -> Result<String> {
    let bytes = bounded_reply(response, s3surface::MAX_DIRECT_MULTIPART_RESPONSE_BYTES).await?;
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("provider metadata not UTF-8"))
}

async fn bounded_reply(response: Response, cap: usize) -> Result<Vec<u8>> {
    crate::direct_digest::read_bounded_native(response, cap).await
}

pub(super) async fn call(env: &Env, message: &protocol::Request) -> Result<Reply> {
    let body = serde_json::to_vec(message)?;
    ensure!(body.len() <= MAX_MESSAGE, "stage guard control oversized");
    let name = message.scope.guard_name()?;
    let signature = storage::key(env)?.sign_body(&body)?;
    let headers = Headers::new();
    headers.set(GUARD_HEADER, &signature)?;
    headers.set(SCOPE_HEADER, &name)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request = Request::new_with_init("https://external-object/stage-turn", &init)?;
    let stub = env
        .durable_object(storage::BINDING)?
        .id_from_name(&name)?
        .get_stub()?;
    let response = stub.fetch_with_request(request).await?;
    ensure!(
        response.status_code() == 200,
        "stage journal refused control"
    );
    let bytes = bounded_reply(response, MAX_MESSAGE).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) fn executor_key(env: &Env) -> Result<StorageWorkKey> {
    let key = env.secret(EXECUTOR_KEY)?.to_string();
    ensure!(
        key != env.secret("HUB_STORAGE_WORK_KEY")?.to_string()
            && key != env.secret("HUB_EXTERNAL_OBJECT_GUARD_KEY")?.to_string(),
        "stage application and guard keys must be independent"
    );
    Ok(StorageWorkKey::new(key)?)
}
