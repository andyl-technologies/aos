//! Fresh independently keyed readback of canonical durable producer originals.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use futures_util::StreamExt as _;
use worker::{Env, Headers, Method, Request, RequestInit, Response, State};

use super::{runtime, transport};
use crate::direct_upload::{config::QualifiedConfig, journal, storage, verification};

/// Serves fresh independently keyed lookups of canonical retained originals.
///
/// # Errors
/// Returns a Worker error when the bounded response cannot be constructed.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    match handle(&mut request, env).await {
        Ok((signed, body)) => {
            let path = request.url()?.path().to_owned();
            let response = response(signed, path == DIRECT_FINAL_GUARD_PATH)?;
            crate::control_receipt::emit_buffered_response(&path, &body, &response).await;
            Ok(response)
        }
        Err(_) => Response::error("direct storage authority lookup refused", 409),
    }
}

async fn handle(request: &mut Request, env: &Env) -> Result<(SignedDirectControl, Vec<u8>)> {
    ensure!(
        request.method() == Method::Post,
        "direct authority lookup method differs"
    );
    let body = crate::hybrid::read_bounded_body(request, MAX_DIRECT_CONTROL_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("direct authority lookup body exceeds bound"))?;
    let signed = handle_body(request, env, &body).await?;
    Ok((signed, body))
}

async fn handle_body(request: &Request, env: &Env, body: &[u8]) -> Result<SignedDirectControl> {
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let key = transport::key(env)?;
    if request.url()?.path() == DIRECT_FINAL_GUARD_PATH {
        let signature = request
            .headers()
            .get(DIRECT_FINAL_GUARD_SIGNATURE_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("direct final authority signature absent"))?;
        let challenge = verify_direct_final_guard_lookup(
            &key,
            &signature,
            &body,
            &deployment,
            crate::direct_upload::config::guard_latest_now(env)?,
        )?;
        return forward(
            env,
            &challenge.admission,
            challenge.expected.reservation.placement.placement_id,
            DIRECT_FINAL_GUARD_PATH,
            DIRECT_FINAL_GUARD_SIGNATURE_HEADER,
            &signature,
            &body,
        )
        .await;
    }
    ensure!(
        request.url()?.path() == DIRECT_AUTHORITY_LOOKUP_PATH,
        "direct authority lookup route differs"
    );
    let signature = request
        .headers()
        .get(DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("direct source authority signature absent"))?;
    let challenge = verify_direct_authority_lookup(
        &key,
        &signature,
        &body,
        &deployment,
        crate::direct_upload::config::guard_latest_now(env)?,
    )?;
    // Positive Stage receipt lookup is historical metadata. It grants no
    // provider read or mutation; every other authority path remains qualified.
    let qualified = if matches!(
        &challenge.operation,
        DirectAuthorityLookupOperation::Stage { .. }
    ) {
        None
    } else {
        Some(QualifiedConfig::load(env).await?)
    };
    let latest_now = || match &qualified {
        Some(qualified) => qualified.latest_now(),
        None => crate::direct_upload::config::guard_latest_now(env),
    };
    match &challenge.operation {
        DirectAuthorityLookupOperation::Stage {
            admission,
            complete,
            evidence,
        } => {
            validate_originals(env, admission, complete).await?;
            runtime::validate_stage(env, admission, complete, evidence).await?;
            for placement in &admission.placements {
                if matches!(placement.physical, DirectPhysicalContext::External { .. }) {
                    let signed =
                        forward_source(env, admission, placement.placement_id, &signature, &body)
                            .await?;
                    verify_direct_authority_lookup_reply(
                        &key,
                        &signed.signature,
                        &signed.body,
                        &challenge,
                        latest_now()?,
                    )?;
                }
            }
        }
        DirectAuthorityLookupOperation::Baseline {
            admission,
            complete,
            evidence,
            ..
        } => {
            validate_originals(env, admission, complete).await?;
            return forward(
                env,
                admission,
                evidence.binding.placement.placement_id,
                DIRECT_AUTHORITY_LOOKUP_PATH,
                DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER,
                &signature,
                &body,
            )
            .await;
        }
        DirectAuthorityLookupOperation::Abort {
            admission,
            abort,
            evidence,
        } => {
            let storage::Reply::Abort { abort: original } =
                storage::call(env, admission, storage::Operation::ReadAbort).await?
            else {
                anyhow::bail!("direct original Abort lookup differs");
            };
            ensure!(
                original.as_ref() == Some(abort),
                "direct original Abort differs"
            );
            let mut receipts =
                Vec::<crate::direct_upload::broker::AbortPlacementReceipt>::with_capacity(
                    admission.placements.len(),
                );
            for placement in &admission.placements {
                let operation_id = verification::step_id(
                    admission,
                    placement.placement_id,
                    &abort.operation_id,
                    "abort-stage",
                )?;
                let storage::Reply::Effect { effect } = storage::call(
                    env,
                    admission,
                    storage::Operation::ReadEffect { operation_id },
                )
                .await?
                else {
                    anyhow::bail!("direct positive abort lookup differs");
                };
                let effect =
                    effect.ok_or_else(|| anyhow::anyhow!("direct abort provider effect absent"))?;
                ensure!(
                    effect.pending_attempt.is_none() && !effect.immutable_read,
                    "direct abort provider effect remains unknown"
                );
                let expected = crate::direct_upload::journal::Effect::new(
                    effect.operation_id.clone(),
                    &(admission, abort, placement.placement_id),
                    false,
                )?;
                ensure!(
                    effect.intent_digest == expected.intent_digest,
                    "direct original abort provider intent changed"
                );
                let receipt: crate::direct_upload::broker::AbortPlacementReceipt =
                    serde_json::from_value(effect.terminal.ok_or_else(|| {
                        anyhow::anyhow!("direct positive provider abort receipt absent")
                    })?)?;
                validate_abort_receipt(env, admission, placement, &receipt).await?;
                receipts.push(receipt);
                if matches!(placement.physical, DirectPhysicalContext::External { .. }) {
                    let signed =
                        forward_source(env, admission, placement.placement_id, &signature, &body)
                            .await?;
                    verify_direct_authority_lookup_reply(
                        &key,
                        &signed.signature,
                        &signed.body,
                        &challenge,
                        latest_now()?,
                    )?;
                }
            }
            ensure!(
                evidence.receipt_digest.as_deref() == Some(journal::digest(&receipts)?.as_str()),
                "direct immutable positive abort receipt digest differs"
            );
        }
    }
    challenge.validate(&deployment, latest_now()?)?;
    sign_direct_authority_lookup_reply(&key, &DirectAuthorityLookupReply { request: challenge })
}

async fn validate_abort_receipt(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement: &DirectPlacement,
    receipt: &crate::direct_upload::broker::AbortPlacementReceipt,
) -> Result<()> {
    use crate::direct_upload::broker::AbortPlacementReceipt;
    use aos_hub_core::storage_authority::external_object::stage::ExternalStageOutcome;

    let operation_id = verification::step_id(
        admission,
        placement.placement_id,
        &admission.intent.client_operation_id,
        "create-stage",
    )?;
    let expected = journal::Effect::new(
        operation_id.clone(),
        &(admission, placement.placement_id),
        false,
    )?;
    let storage::Reply::Effect {
        effect: Some(created),
    } = storage::call(
        env,
        admission,
        storage::Operation::ReadEffect { operation_id },
    )
    .await?
    else {
        anyhow::bail!("direct original abort source Create absent");
    };
    ensure!(
        created.intent_digest == expected.intent_digest
            && !created.immutable_read
            && created.pending_attempt.is_none(),
        "direct original abort source Create unknown or changed"
    );
    let created: verification::CreatedStage = serde_json::from_value(
        created
            .terminal
            .ok_or_else(|| anyhow::anyhow!("direct abort source positive Create absent"))?,
    )?;
    match (receipt, created) {
        (
            AbortPlacementReceipt::Multipart {
                placement_id,
                upload_id,
                provider_closed,
            },
            verification::CreatedStage::Managed { receipt },
        ) => {
            ensure!(
                *placement_id == placement.placement_id
                    && *provider_closed
                    && !upload_id.is_empty()
                    && receipt.upload_id.as_ref() == Some(upload_id)
                    && receipt.empty.is_none(),
                "direct original managed abort UploadId changed"
            );
        }
        (
            AbortPlacementReceipt::Multipart {
                placement_id,
                upload_id,
                provider_closed,
            },
            verification::CreatedStage::External { result },
        ) => {
            ensure!(
                *placement_id == placement.placement_id
                    && *provider_closed
                    && matches!(result.outcome, ExternalStageOutcome::Created { upload_id: original } if original == *upload_id),
                "direct original external abort UploadId changed"
            );
        }
        (
            AbortPlacementReceipt::EmptyObject {
                placement_id,
                original,
                provider_closed,
            },
            verification::CreatedStage::Managed { receipt },
        ) => {
            ensure!(
                *placement_id == placement.placement_id
                    && *provider_closed
                    && admission.intent.byte_size.get() == 0
                    && original.byte_size.get() == 0
                    && receipt.upload_id.is_none()
                    && receipt.empty.as_ref() == Some(original),
                "direct original empty abort incarnation changed"
            );
        }
        _ => anyhow::bail!("direct positive provider abort physical scope differs"),
    }
    Ok(())
}

pub(super) async fn validate_originals(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
) -> Result<()> {
    let storage::Reply::Original {
        admission: original,
        complete: frozen,
    } = storage::call(env, admission, storage::Operation::ReadOriginal).await?
    else {
        anyhow::bail!("direct producer original lookup differs");
    };
    ensure!(
        original == *admission && frozen.as_ref() == Some(complete),
        "direct producer canonical originals differ"
    );
    Ok(())
}

pub(super) async fn confirm_external_stage(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    placement_id: WireInteger,
    context: &DirectRequestContext,
) -> Result<()> {
    let mut retained = Vec::with_capacity(admission.placements.len());
    for placement in &admission.placements {
        retained.push(
            verification::retained(env, admission, complete, placement.placement_id)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("direct external independent stage set incomplete")
                })?,
        );
    }
    let evidence = DirectVerifiedStageEvidence {
        session_id: admission.session_id.clone(),
        logical_fingerprint: admission.logical_fingerprint.clone(),
        operation_id: complete.operation_id.clone(),
        part_count: admission.intent.part_count()?,
        sha256: admission.intent.expected_sha256.clone(),
        byte_size: admission.intent.byte_size,
        placements: retained.iter().map(|item| item.placement.clone()).collect(),
        projection: retained.first().and_then(|item| item.projection.clone()),
    };
    let request = DirectAuthorityLookup {
        deployment_id: context.deployment_id.clone(),
        request_nonce: context.request_nonce.clone(),
        issued_at: context.issued_at,
        expires_at: context.expires_at,
        operation: DirectAuthorityLookupOperation::Stage {
            admission: admission.clone(),
            complete: complete.clone(),
            evidence,
        },
    };
    let key = transport::key(env)?;
    let signed = sign_direct_authority_lookup(&key, &request)?;
    let reply = forward_source(
        env,
        admission,
        placement_id,
        &signed.signature,
        &signed.body,
    )
    .await?;
    let qualified = QualifiedConfig::load(env).await?;
    verify_direct_authority_lookup_reply(
        &key,
        &reply.signature,
        &reply.body,
        &request,
        qualified.latest_now()?,
    )?;
    Ok(())
}

async fn forward(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    path: &str,
    header: &str,
    signature: &str,
    body: &[u8],
) -> Result<SignedDirectControl> {
    let (binding, address, full_key) = transport::physical_address(env, admission, placement_id)?;
    forward_address(
        env, &binding, &address, &full_key, path, header, signature, body,
    )
    .await
}

async fn forward_source(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    signature: &str,
    body: &[u8],
) -> Result<SignedDirectControl> {
    let context = aos_hub_core::storage_authority::external_object::stage::ExternalStageContext::from_admission(admission, placement_id, &env.var("HUB_DEPLOYMENT_ID")?.to_string())?;
    let scope = context.scope(false)?;
    forward_address(
        env,
        "EXTERNAL_OBJECT_GUARD",
        &scope.guard_name()?,
        &scope.full_key,
        DIRECT_AUTHORITY_LOOKUP_PATH,
        DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER,
        signature,
        body,
    )
    .await
}

async fn forward_address(
    env: &Env,
    binding: &str,
    address: &str,
    full_key: &str,
    path: &str,
    header: &str,
    signature: &str,
    body: &[u8],
) -> Result<SignedDirectControl> {
    let headers = Headers::new();
    headers.set(header, signature)?;
    headers.set("x-aos-hybrid-object-key", &full_key)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body).into()));
    let mut response = env
        .durable_object(binding)?
        .id_from_name(address)?
        .get_stub()?
        .fetch_with_request(Request::new_with_init(
            &format!("https://physical-guard{path}"),
            &init,
        )?)
        .await?;
    ensure!(
        response.status_code() == 200,
        "direct independently held physical authority refused"
    );
    let signature = response
        .headers()
        .get(header)?
        .ok_or_else(|| anyhow::anyhow!("direct physical authority response signature absent"))?;
    let mut stream = response.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            bytes
                .len()
                .checked_add(chunk.len())
                .is_some_and(|size| size <= MAX_DIRECT_CONTROL_BYTES),
            "direct physical authority response exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(SignedDirectControl {
        body: bytes,
        signature,
    })
}

/// Reads an exact fresh challenge under the permanent physical guard gate.
///
/// # Errors
/// Returns a Worker error when the bounded response cannot be constructed.
pub(crate) async fn physical_lookup(
    request: &mut Request,
    env: &Env,
    state: &State,
) -> worker::Result<Response> {
    match read_physical(request, env, state).await {
        Ok(signed) => response(signed, request.url()?.path() == DIRECT_FINAL_GUARD_PATH),
        Err(_) => Response::error("direct physical authority refused", 409),
    }
}

async fn read_physical(
    request: &mut Request,
    env: &Env,
    state: &State,
) -> Result<SignedDirectControl> {
    ensure!(
        request.method() == Method::Post,
        "direct physical lookup method differs"
    );
    let bytes = crate::hybrid::read_bounded_body(request, MAX_DIRECT_CONTROL_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("direct physical lookup exceeds bound"))?;
    if request.url()?.path() == DIRECT_FINAL_GUARD_PATH {
        return read_retained_final(request, env, state, &bytes).await;
    }
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let key = transport::key(env)?;
    let storage = state.storage();
    if request.url()?.path() == DIRECT_AUTHORITY_LOOKUP_PATH {
        let signature = request
            .headers()
            .get(DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER)?
            .ok_or_else(|| anyhow::anyhow!("direct source readback signature absent"))?;
        let challenge = verify_direct_authority_lookup(
            &key,
            &signature,
            &bytes,
            &deployment,
            crate::direct_upload::config::guard_latest_now(env)?,
        )?;
        match &challenge.operation {
            DirectAuthorityLookupOperation::Stage {
                admission,
                complete,
                evidence,
            } => {
                let placement_id = addressed_source(env, state, admission, None).await?;
                let placement = evidence
                    .placements
                    .iter()
                    .find(|item| item.placement.placement_id == placement_id)
                    .ok_or_else(|| anyhow::anyhow!("direct expected external source absent"))?;
                crate::external_object::direct_source(
                    env, &storage, admission, complete, placement,
                )
                .await?;
                challenge.validate(
                    &deployment,
                    crate::direct_upload::config::guard_latest_now(env)?,
                )?;
                return sign_direct_authority_lookup_reply(
                    &key,
                    &DirectAuthorityLookupReply { request: challenge },
                );
            }
            DirectAuthorityLookupOperation::Abort {
                admission, abort, ..
            } => {
                let qualified = QualifiedConfig::load(env).await?;
                let placement_id =
                    addressed_source(env, state, admission, Some(&qualified)).await?;
                crate::external_object::direct_abort(env, &storage, admission, abort, placement_id)
                    .await?;
                challenge.validate(&deployment, qualified.latest_now()?)?;
                return sign_direct_authority_lookup_reply(
                    &key,
                    &DirectAuthorityLookupReply { request: challenge },
                );
            }
            DirectAuthorityLookupOperation::Baseline { .. } => {}
        }
    }
    let qualified = QualifiedConfig::load(env).await?;
    let owner = runtime::retained(&storage).await?;
    owner.validate()?;
    let (binding, address, _) =
        transport::physical_address(env, &owner.admission, owner.binding.placement.placement_id)?;
    ensure!(
        env.durable_object(&binding)?
            .id_from_name(&address)?
            .to_string()
            == state.id().to_string(),
        "direct physical readback owner differs"
    );
    let placement = crate::direct_upload::storage::placement(
        &owner.admission,
        owner.binding.placement.placement_id,
    )?;
    qualified.protected(env, placement).await?;
    ensure!(
        request.url()?.path() == DIRECT_AUTHORITY_LOOKUP_PATH,
        "direct physical readback route differs"
    );
    let signature = request
        .headers()
        .get(DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("direct baseline readback signature absent"))?;
    let challenge = verify_direct_authority_lookup(
        &key,
        &signature,
        &bytes,
        &deployment,
        qualified.latest_now()?,
    )?;
    let DirectAuthorityLookupOperation::Baseline {
        admission,
        complete,
        evidence,
        witness,
    } = &challenge.operation
    else {
        anyhow::bail!("direct physical readback kind differs");
    };
    ensure!(
        owner.admission == *admission
            && owner.complete == *complete
            && !owner.native_committed
            && owner.final_record.is_none()
            && owner.baseline.as_ref() == Some(evidence),
        "direct baseline reservation no longer held"
    );
    ensure!(
        runtime::read::<crate::direct_upload::journal::Effect>(&storage, "direct-guard/pending/v1")
            .await?
            .is_none(),
        "direct baseline provider effect remains unknown"
    );
    let saved: DirectDestinationBaselineWitness =
        runtime::read(&storage, &runtime::witness_key(witness)?)
            .await?
            .ok_or_else(|| anyhow::anyhow!("direct fresh baseline witness absent"))?;
    ensure!(saved == *witness, "direct fresh baseline witness differs");
    if matches!(placement.physical, DirectPhysicalContext::External { .. }) {
        crate::external_object::check_direct_available(
            env,
            &storage,
            &owner.admission,
            owner.binding.placement.placement_id,
        )
        .await?;
    }
    challenge.validate(&deployment, qualified.latest_now()?)?;
    sign_direct_authority_lookup_reply(&key, &DirectAuthorityLookupReply { request: challenge })
}

/// Authenticates only the held durable final record, without provider authority.
async fn read_retained_final(
    request: &Request,
    env: &Env,
    state: &State,
    bytes: &[u8],
) -> Result<SignedDirectControl> {
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let latest_now = || crate::direct_upload::config::guard_latest_now(env);
    let key = transport::key(env)?;
    let signature = request
        .headers()
        .get(DIRECT_FINAL_GUARD_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("direct retained final signature absent"))?;
    let challenge =
        verify_direct_final_guard_lookup(&key, &signature, bytes, &deployment, latest_now()?)?;
    let storage = state.storage();
    let owner = runtime::retained(&storage).await?;
    owner.validate()?;
    let (binding, address, _) =
        transport::physical_address(env, &owner.admission, owner.binding.placement.placement_id)?;
    ensure!(
        env.durable_object(&binding)?
            .id_from_name(&address)?
            .to_string()
            == state.id().to_string(),
        "direct retained final physical owner differs"
    );
    ensure!(
        owner.admission == challenge.admission
            && owner.complete == challenge.complete
            && !owner.native_committed
            && owner.final_record.as_ref() == Some(&challenge.expected),
        "direct retained final owner released or originals changed"
    );
    let record: DirectFinalGuardRecord = runtime::read(
        &storage,
        &runtime::final_key(&owner.binding.reservation_operation_id),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("direct retained final positive receipt absent"))?;
    ensure!(
        record == challenge.expected,
        "direct retained final receipt changed"
    );
    challenge.validate(&deployment, latest_now()?)?;
    sign_direct_final_guard_reply(
        &key,
        &DirectFinalGuardReply {
            request: challenge,
            record,
        },
    )
}

async fn addressed_source(
    env: &Env,
    state: &State,
    admission: &DirectUploadAdmission,
    qualified: Option<&QualifiedConfig>,
) -> Result<WireInteger> {
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let mut found = None;
    for placement in &admission.placements {
        if !matches!(placement.physical, DirectPhysicalContext::External { .. }) {
            continue;
        }
        let context = aos_hub_core::storage_authority::external_object::stage::ExternalStageContext::from_admission(admission, placement.placement_id, &deployment)?;
        if env
            .durable_object("EXTERNAL_OBJECT_GUARD")?
            .id_from_name(&context.scope(false)?.guard_name()?)?
            .to_string()
            == state.id().to_string()
        {
            ensure!(found.is_none(), "direct source physical guard is ambiguous");
            if let Some(qualified) = qualified {
                qualified.protected(env, placement).await?;
            }
            found = Some(placement.placement_id);
        }
    }
    found.ok_or_else(|| anyhow::anyhow!("direct readback addressed another source guard"))
}

fn response(signed: SignedDirectControl, final_record: bool) -> worker::Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("cache-control", "private, no-store")?;
    headers.set(
        if final_record {
            DIRECT_FINAL_GUARD_SIGNATURE_HEADER
        } else {
            DIRECT_AUTHORITY_LOOKUP_SIGNATURE_HEADER
        },
        &signed.signature,
    )?;
    Ok(Response::ok(
        String::from_utf8(signed.body)
            .map_err(|_| worker::Error::RustError("direct lookup encoding invalid".into()))?,
    )?
    .with_headers(headers))
}
