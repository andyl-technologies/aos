//! Guard-selected versioned copy execution beside the provider.
//!
//! Native sends only an existing operation original and fresh claim permission.
//! The permanent guard selects each effect and retains it before dispatch. Any
//! failed or ambiguous provider outcome leaves that turn unresolved; only an
//! exact positive receipt may advance it. Object bytes never enter a Hub RPC.

use anyhow::{ensure, Result};
use aos_hub_core::{
    direct_upload::{DirectChecksumAlgorithm, DirectPart, DirectPartChecksum, WireInteger},
    s3surface::{self, S3Surface},
    storage_authority::{
        external_object::copy::{
            control::{
                CopyControl, CopyProgress, ExternalCopyReply, ExternalCopyRequest,
                EXTERNAL_COPY_PATH, MAX_EXTERNAL_COPY_CONTROL_BYTES,
            },
            session::{CopyAction, CopyOutcome, CopyPhase, CopyReceipt, CopyTurn},
            CopySourceObject,
        },
        lease::{LeaseEffect, LeaseInteger},
    },
    storage_work::{
        StorageBindingPublication, StorageCredentialSelector, StorageWorkKey,
        STORAGE_WORK_SIGNATURE_HEADER,
    },
};
use base64::Engine as _;
use rand::TryRngCore as _;
use worker::{Env, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response};

use super::super::{
    config::{configured, Config as ObjectConfig},
    protocol::{GUARD_HEADER, MAX_MESSAGE, SCOPE_HEADER},
    storage,
};
use super::{
    config,
    protocol::{self, Operation, Reply},
    stream,
    window::DispatchWindow,
};

const PROVIDER_TTL: u32 = 30;
const PROVIDER_METADATA_BYTES: usize = 512 * 1024;

/// Handles authenticated closed copy controls and exactly correlated metadata replies.
///
/// # Errors
/// Returns a bounded refusal for changed claims, unsupported domains or unknown I/O.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    let signal = request.inner().signal();
    let result = async {
        ensure!(
            request.method() == Method::Post && request.url()?.path() == EXTERNAL_COPY_PATH,
            "copy route requires POST"
        );
        let object = configured(env)?.ok_or_else(|| anyhow::anyhow!("object consumer disabled"))?;
        let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
        let signature = request
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("copy application signature absent"))?;
        let body = crate::hybrid::read_bounded_body(&mut request, MAX_EXTERNAL_COPY_CONTROL_BYTES)
            .await?
            .ok_or_else(|| anyhow::anyhow!("copy application body oversized"))?;
        let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
        let work = ExternalCopyRequest::authenticate(
            &key,
            &signature,
            &body,
            &deployment,
            object.clock().observed_at,
        )?;
        let progress = execute(env, &object, &work, &signal).await?;
        ExternalCopyReply::new(&work, progress)?.sign(&key, &work)
    }
    .await;
    match result {
        Ok((body, signature)) => {
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
            Ok(Response::from_bytes(body)?.with_headers(headers))
        }
        Err(_) => Response::error("external copy request refused", 409),
    }
}

async fn execute(
    env: &Env,
    object: &ObjectConfig,
    work: &ExternalCopyRequest,
    signal: &worker::web_sys::AbortSignal,
) -> Result<CopyProgress> {
    let config = config::configured(env, object)?
        .ok_or_else(|| anyhow::anyhow!("copy consumer disabled"))?;
    let domain = config.domain(object, &work.original)?;
    let mut message = message(object, domain, work, Operation::Lookup)?;
    let prior = match call(env, &message).await? {
        Reply::Progress { progress } => Some(progress),
        Reply::Unseen => None,
        _ => anyhow::bail!("copy lookup reply differs"),
    };
    if let Some(progress) = &prior {
        if work.control == CopyControl::Status
            || progress.pending
            || matches!(progress.phase, CopyPhase::Closed | CopyPhase::Aborted)
        {
            return Ok(progress.clone());
        }
    } else {
        ensure!(
            work.control == CopyControl::Advance,
            "unseen copy has no status or abort"
        );
    }

    ensure!(
        work.original.source_object.bytes.get() > 0,
        "empty copy executor is not qualified"
    );
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let publication = crate::hybrid_binding::resolve_for_plan(env, &work.plan).await?;
    check_publication(object, domain, work, &publication, &deployment)?;
    let write_lease = super::super::stage::planning::acquire_configured_lease(
        env,
        object,
        &domain.issuer_installation,
        &domain.write_cohort,
        &domain.write_cohort.admitted_prefix,
    )
    .await?;
    check_publication(object, domain, work, &publication, &deployment)?;

    // A part is selected only after a positive Create. Read permission is
    // acquired before reserving the destination turn so unsupported/expired
    // source admission cannot leave a preventable destination unknown.
    let part_count = work.original.part_count()?;
    let part = prior.as_ref().is_some_and(|progress| {
        progress.phase == CopyPhase::Active && progress.completed_parts < part_count
    }) && work.control == CopyControl::Advance;
    let read = if part {
        let token = super::super::stage::planning::acquire_configured_lease(
            env,
            object,
            &domain.issuer_installation,
            &domain.read_cohort,
            &domain.read_cohort.admitted_prefix,
        )
        .await?;
        check_publication(object, domain, work, &publication, &deployment)?;
        let mut source = message.clone();
        source.request_nonce = nonce()?;
        source.scope = domain.scope(object, &work.original, false)?;
        source.operation = Operation::SourceRead {
            read_lease: token.clone(),
        };
        let Reply::ReadAuthorized { floor } = call(env, &source).await? else {
            anyhow::bail!("source read floor absent");
        };
        Some((token, floor, source.scope))
    } else {
        None
    };
    check_publication(object, domain, work, &publication, &deployment)?;
    message.request_nonce = nonce()?;
    message.operation = Operation::Begin {
        control: work.control,
        write_lease: write_lease.clone(),
    };
    let (turn, floor, continuation) = match call(env, &message).await? {
        Reply::Progress { progress } => return Ok(progress),
        Reply::Dispatch {
            turn,
            floor,
            source_state,
        } => (turn, floor, source_state),
        _ => anyhow::bail!("copy guard dispatch absent"),
    };
    let fresh = || -> Result<()> {
        check_publication(object, domain, work, &publication, &deployment)?;
        object.verifier()?.validate_lease(
            write_lease.as_bytes(),
            &domain.write_cohort,
            &object.timing_profile,
            &floor,
            &message.scope.full_key,
            effect(&turn.action),
            object.clock(),
        )?;
        if let Some((token, source_floor, scope)) = &read {
            object.verifier()?.validate_lease(
                token.as_bytes(),
                &domain.read_cohort,
                &object.timing_profile,
                source_floor,
                &scope.full_key,
                LeaseEffect::Read,
                object.clock(),
            )?;
        }
        Ok(())
    };
    let window = DispatchWindow {
        expires_at: work.plan.expires_at,
        uncertainty: object.clock_uncertainty,
        client_signal: signal,
        fresh: &fresh,
        lifetime: super::lifetime::Lifetime::new(signal.clone())?,
    };
    window.check()?;
    crate::direct_upload::provider_capacity::configure(u32::from(domain.provider_concurrency))?;
    let capacity = crate::direct_upload::provider_capacity::acquire_class_checked(
        if part { 2 } else { 1 },
        if part {
            crate::direct_upload::provider_capacity::Class::Bulk
        } else {
            crate::direct_upload::provider_capacity::Class::Metadata
        },
        &|| window.check(),
    )
    .await?;
    window.lifetime.retain_capacity(capacity)?;
    let write_secret = publication.credential_text(
        &StorageCredentialSelector {
            purpose: "write".into(),
            generation: work.original.write_generation.get(),
        },
        &deployment,
        object.clock().observed_at,
    )?;
    let destination = S3Surface::from_snapshot(
        &publication.snapshot,
        &deployment,
        &work.original.destination.prefix,
        Some(write_secret.as_str()),
        object.clock().observed_at,
    )?;
    let outcome = match &turn.action {
        CopyAction::Part {
            upload_id,
            number,
            offset,
            bytes,
            ..
        } => {
            ensure!(read.is_some(), "part lacks guarded source read");
            let read_secret = publication.credential_text(
                &StorageCredentialSelector {
                    purpose: "read".into(),
                    generation: work.original.read_generation.get(),
                },
                &deployment,
                object.clock().observed_at,
            )?;
            let source = S3Surface::from_snapshot(
                &publication.snapshot,
                &deployment,
                &work.original.source.prefix,
                Some(read_secret.as_str()),
                object.clock().observed_at,
            )?;
            let continuation = continuation
                .ok_or_else(|| anyhow::anyhow!("private source continuation absent"))?;
            let range = stream::SourceRange {
                source: &work.original.source_object,
                offset: *offset,
                bytes: *bytes,
            };
            let signed_read = source.versioned_conditional_range_request(
                &work.original.path,
                &work.original.source_object,
                *offset,
                *bytes,
                object.clock().observed_at,
                PROVIDER_TTL,
            )?;
            let expected =
                stream::hash_range(&signed_read, &range, continuation.clone(), &window).await?;
            let descriptor = DirectPart {
                part_number: *number,
                offset: WireInteger::new(*offset),
                byte_size: WireInteger::new(*bytes),
                sha256: expected.sha256.clone(),
                checksum: DirectPartChecksum {
                    algorithm: DirectChecksumAlgorithm::Sha256,
                    value: base64::engine::general_purpose::STANDARD
                        .encode(hex::decode(&expected.sha256)?),
                },
            };
            let signed_write = destination.direct_upload_part_request(
                &work.original.path,
                upload_id,
                &descriptor,
                object.clock().observed_at,
                PROVIDER_TTL,
            )?;
            let signed_read = source.versioned_conditional_range_request(
                &work.original.path,
                &work.original.source_object,
                *offset,
                *bytes,
                object.clock().observed_at,
                PROVIDER_TTL,
            )?;
            let (etag, actual) = stream::upload_range(
                &signed_read,
                &signed_write,
                &range,
                continuation,
                &expected,
                &window,
            )
            .await?;
            CopyOutcome::Part {
                etag,
                sha256: actual.sha256,
                source_state: actual.source_state,
            }
        }
        _ => {
            metadata_effect(
                env,
                object,
                work,
                &message,
                &turn,
                &destination,
                &publication,
                &window,
            )
            .await?
        }
    };
    // Failed I/O returns above with the immutable pending turn still held.
    // Terminal acknowledgement persists only this exact actual positive result.
    message.request_nonce = nonce()?;
    message.operation = Operation::Terminal {
        receipt: CopyReceipt { turn, outcome },
    };
    match call(env, &message).await? {
        Reply::Progress { progress } => Ok(progress),
        _ => anyhow::bail!("copy terminal acknowledgement differs"),
    }
}

fn message(
    object: &ObjectConfig,
    domain: &config::Domain,
    work: &ExternalCopyRequest,
    operation: Operation,
) -> Result<protocol::Request> {
    Ok(protocol::Request {
        domain: protocol::DOMAIN.into(),
        request_nonce: nonce()?,
        permission_expires_at: LeaseInteger::new(work.plan.expires_at)?,
        scope: domain.scope(object, &work.original, true)?,
        original: work.original.clone(),
        operation,
    })
}

fn nonce() -> Result<String> {
    let mut nonce = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| anyhow::anyhow!("copy correlation randomness unavailable"))?;
    Ok(hex::encode(nonce))
}

fn effect(action: &CopyAction) -> LeaseEffect {
    match action {
        CopyAction::Create => LeaseEffect::MultipartCreate,
        CopyAction::EmptyPut => LeaseEffect::Put,
        CopyAction::Part { .. } => LeaseEffect::MultipartPart,
        CopyAction::Complete { .. } => LeaseEffect::MultipartComplete,
        CopyAction::Abort { .. } => LeaseEffect::MultipartAbort,
    }
}

fn check_publication(
    object: &ObjectConfig,
    domain: &config::Domain,
    work: &ExternalCopyRequest,
    publication: &StorageBindingPublication,
    deployment: &str,
) -> Result<()> {
    let now = object.clock().observed_at;
    work.validate(deployment, now)?;
    domain.validate_original(object, &work.original)?;
    publication
        .snapshot
        .authorizes(&work.plan, deployment, now)?;
    ensure!(
        publication.snapshot.binding_stable_id == work.original.binding_stable_id
            && publication.snapshot.object_prefix == domain.write_cohort.association.binding_prefix,
        "copy publication physical identity differs"
    );
    for (cohort, purpose) in [
        (&domain.read_cohort, "read"),
        (&domain.write_cohort, "write"),
    ] {
        ensure!(
            super::super::executor::select_cohort(
                object,
                publication,
                purpose,
                work.original.binding_write_revision.get()
            )? == cohort,
            "copy purpose cohort changed"
        );
    }
    Ok(())
}

async fn metadata_effect(
    env: &Env,
    object: &ObjectConfig,
    work: &ExternalCopyRequest,
    message: &protocol::Request,
    turn: &CopyTurn,
    surface: &S3Surface,
    publication: &StorageBindingPublication,
    window: &DispatchWindow<'_>,
) -> Result<CopyOutcome> {
    let now = object.clock().observed_at;
    let headers = Headers::new();
    let mut body = None;
    let (url, method) = match &turn.action {
        CopyAction::Create => {
            let signed = surface.direct_create_multipart_request(
                &work.original.path,
                DirectChecksumAlgorithm::Sha256,
                now,
                PROVIDER_TTL,
            )?;
            for header in signed.required_headers {
                headers.set(&header.name, &header.value)?;
            }
            (signed.url, Method::Post)
        }
        CopyAction::Complete { upload_id, .. } => {
            let mut parts = Vec::new();
            let mut first = 1;
            loop {
                window.check()?;
                let mut page = message.clone();
                page.request_nonce = nonce()?;
                page.operation = Operation::ManifestPage {
                    turn: turn.clone(),
                    first_part: first,
                    limit: protocol::MAX_PART_PAGE,
                };
                let Reply::ManifestPage {
                    parts: members,
                    next_part,
                } = call(env, &page).await?
                else {
                    anyhow::bail!("copy manifest page absent");
                };
                parts.extend(members);
                ensure!(
                    parts.len() <= aos_hub_core::direct_upload::MAX_DIRECT_PARTS as usize,
                    "copy manifest part bound exceeded"
                );
                match next_part {
                    Some(next) => first = next,
                    None => break,
                }
            }
            ensure!(
                parts.len() == work.original.part_count()? as usize,
                "copy manifest incomplete"
            );
            let mut xml = String::from("<CompleteMultipartUpload>");
            for part in parts {
                aos_hub_core::surface_write::strong_if_match_etag(&part.etag)?;
                let checksum =
                    base64::engine::general_purpose::STANDARD.encode(hex::decode(part.sha256)?);
                xml.push_str(&format!("<Part><PartNumber>{}</PartNumber><ETag>{}</ETag><ChecksumSHA256>{checksum}</ChecksumSHA256></Part>",
                    part.number, super::provider_receipt::xml_text(&part.etag)));
                ensure!(
                    xml.len() <= s3surface::MAX_DIRECT_COMPLETE_XML_BYTES - 26,
                    "copy Complete provider XML oversized"
                );
            }
            xml.push_str("</CompleteMultipartUpload>");
            headers.set("content-type", "application/xml")?;
            body = Some(xml.into_bytes());
            (
                surface.multipart_url(
                    "complete",
                    &work.original.path,
                    Some(upload_id),
                    None,
                    now,
                )?,
                Method::Post,
            )
        }
        CopyAction::Abort { upload_id } => (
            surface.multipart_url("abort", &work.original.path, Some(upload_id), None, now)?,
            Method::Delete,
        ),
        CopyAction::EmptyPut => anyhow::bail!("empty copy executor is not qualified"),
        CopyAction::Part { .. } => anyhow::bail!("part cannot use metadata effect"),
    };
    aos_hub_core::url_guard::is_safe_remote_url(&url)?;
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_redirect(RequestRedirect::Manual)
        .with_headers(headers);
    if let Some(body) = body {
        init.with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    }
    let request = Request::new_with_init(&url, &init)?;
    let controller = worker::web_sys::AbortController::new()
        .map_err(|_| anyhow::anyhow!("copy provider cancellation unavailable"))?;
    let _registration = window
        .lifetime
        .register(controller.clone().into(), "abort")?;
    let result = window
        .run(async {
            window.check()?;
            crate::direct_upload::provider_capacity::record_dispatch();
            let response = Fetch::Request(request)
                .send_with_signal(&worker::AbortSignal::from(controller.signal()))
                .await?;
            ensure!(
                response.status_code() == 200
                    || matches!(turn.action, CopyAction::Abort { .. })
                        && response.status_code() == 204,
                "copy provider effect unacknowledged"
            );
            let version = response.headers().get("x-amz-version-id")?;
            let xml = crate::direct_digest::read_bounded_native(response, PROVIDER_METADATA_BYTES)
                .await?;
            let xml = std::str::from_utf8(&xml)?;
            window.check()?;
            match &turn.action {
                CopyAction::Create => {
                    let physical = surface.physical_key(&work.original.path)?;
                    let expected_key = physical
                        .strip_prefix(&format!("{}/", publication.snapshot.object_bucket))
                        .ok_or_else(|| anyhow::anyhow!("copy Create bucket prefix differs"))?;
                    Ok(CopyOutcome::Created {
                        upload_id: super::provider_receipt::created(
                            xml,
                            &publication.snapshot.object_bucket,
                            expected_key,
                        )?,
                    })
                }
                CopyAction::Abort { .. } => {
                    ensure!(xml.is_empty(), "Abort returned an unknown body");
                    Ok(CopyOutcome::Aborted)
                }
                CopyAction::Complete { sha256, .. } => {
                    let full_key = surface.physical_key(&work.original.path)?;
                    let full_key = full_key
                        .strip_prefix(&format!("{}/", publication.snapshot.object_bucket))
                        .ok_or_else(|| anyhow::anyhow!("copy Complete bucket prefix differs"))?;
                    let receipt = s3surface::parse_direct_complete_multipart(
                        xml,
                        &publication.snapshot.object_bucket,
                        full_key,
                    )?;
                    let destination = CopySourceObject {
                        provider_version: version
                            .ok_or_else(|| anyhow::anyhow!("copy Complete version absent"))?,
                        etag: receipt.etag,
                        bytes: work.original.source_object.bytes,
                    };
                    destination.validate()?;
                    Ok(CopyOutcome::Closed {
                        destination,
                        sha256: sha256.clone(),
                    })
                }
                _ => anyhow::bail!("copy metadata receipt differs"),
            }
        })
        .await;
    if result.is_err() {
        controller.abort();
    }
    result
}

async fn call(env: &Env, message: &protocol::Request) -> Result<Reply> {
    message.validate()?;
    let key = storage::key(env)?;
    let body = serde_json::to_vec(message)?;
    let name = message.scope.guard_name()?;
    let headers = Headers::new();
    headers.set(GUARD_HEADER, &key.sign_body(&body)?)?;
    headers.set(SCOPE_HEADER, &name)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request =
        Request::new_with_init(&format!("https://external-object{}", protocol::PATH), &init)?;
    let response = env
        .durable_object(storage::BINDING)?
        .id_from_name(&name)?
        .get_stub()?
        .fetch_with_request(request)
        .await?;
    ensure!(
        response.status_code() == 200,
        "copy physical guard refused control"
    );
    let signature = response
        .headers()
        .get(GUARD_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("copy guard reply signature absent"))?;
    let body = crate::direct_digest::read_bounded_native(response, MAX_MESSAGE).await?;
    protocol::verify_reply(&key, message, &signature, &body)
}
