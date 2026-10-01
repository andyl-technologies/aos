//! Permanent physical-key journal and positively acknowledged managed effects.
//!
//! The caller holds the existing physical guard's gate. Durable writes precede
//! each provider dispatch, and no failed request or provider HEAD clears an
//! unresolved effect. Final receipts remain held until authenticated Native commit.

use anyhow::{ensure, Result};
use aos_hub_core::{direct_upload::*, storage_work::StorageWorkKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use worker::{Env, Method, Request, Response, ResponseBody, State, Storage};

#[cfg(feature = "do-e2e")]
pub(super) use super::effects::effect;
use super::effects::{managed_promote, recover_known_pending, recover_publication};

use super::{
    state::{Reservation, Source},
    transport::{self, Operation, Reply, Turn, OWNER, TURN_DOMAIN, TURN_HEADER, TURN_PATH},
};
use crate::direct_upload::{
    config::QualifiedConfig,
    journal::{self, Effect},
    managed, storage as original,
    verification::{self, ClosedStage, VerifiedPlacement},
};

/// Serves independently authenticated turns while the physical guard gate is held.
///
/// # Errors
/// Returns a Worker error when a bounded response cannot be constructed.
pub(crate) async fn physical_fetch(
    request: &mut Request,
    env: &Env,
    state: &State,
) -> worker::Result<Response> {
    match handle(request, env, state).await {
        Ok(reply) => {
            let body = encode_direct_control(&reply).map_err(error)?;
            let headers = worker::Headers::new();
            headers.set("content-type", "application/json")?;
            headers.set("cache-control", "private, no-store")?;
            Ok(Response::ok(String::from_utf8(body).map_err(error)?)?.with_headers(headers))
        }
        Err(_) => Response::error("direct physical guard refused", 409),
    }
}

async fn handle(request: &mut Request, env: &Env, state: &State) -> Result<Reply> {
    ensure!(
        request.method() == Method::Post && request.url()?.path() == TURN_PATH,
        "direct guard route differs"
    );
    let body = crate::hybrid::read_bounded_body(request, transport::MAX_TURN_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("direct guard body exceeds bound"))?;
    let signature = request
        .headers()
        .get(TURN_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("direct guard authentication missing"))?;
    transport::key(env)?.verify_body(&signature, &[TURN_DOMAIN, &body].concat())?;
    let turn: Turn = serde_json::from_slice(&body)?;
    ensure!(
        serde_json::to_vec(&turn)? == body,
        "direct guard request noncanonical"
    );
    if matches!(
        turn.operation,
        Operation::ReadPublication | Operation::NativeCommit { .. }
    ) {
        return historical_metadata(env, state, &turn).await;
    }
    crate::mirror_import::runtime::deny_other_owner(&state.storage()).await?;
    let qualified = QualifiedConfig::load(env).await?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    turn.context.validate(
        &deployment,
        &env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string(),
        qualified.latest_now()?,
    )?;
    let (binding, address, _) =
        transport::physical_address(env, &turn.admission, turn.placement_id)?;
    ensure!(
        env.durable_object(&binding)?
            .id_from_name(&address)?
            .to_string()
            == state.id().to_string(),
        "direct reservation physical owner differs"
    );
    let placement = original::placement(&turn.admission, turn.placement_id)?;
    let profile = qualified.protected(env, placement).await?;
    let selected = DirectSelectedCompleteCommitment::new(
        &turn.admission,
        &turn.complete,
        turn.placement_id,
        &deployment,
        &profile,
    )?;
    let storage = state.storage();

    match &turn.operation {
        Operation::Reserve => reserve(env, &storage, &turn, selected, &qualified).await,
        Operation::ReadPublication | Operation::NativeCommit { .. } => {
            anyhow::bail!("direct metadata operation reached provider authority path")
        }
        Operation::Promote {
            stage,
            baseline,
            witness,
            permission,
            native_reply_body,
            native_reply_signature,
        } => {
            let owner = retained(&storage).await?;
            check_originals(&owner, &turn, &selected)?;
            ensure!(
                owner.baseline.as_ref() == Some(baseline),
                "direct guard original baseline changed"
            );
            permission.validate_for(baseline, witness, &turn.context, qualified.latest_now()?)?;
            let native_key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
            super::state::authenticate_native_permission(
                &native_key,
                permission,
                &turn.context,
                native_reply_body.as_bytes(),
                native_reply_signature,
                qualified.latest_now()?,
            )?;
            validate_stage(env, &turn.admission, &turn.complete, stage).await?;
            let source = retained_source(env, &turn).await?;
            ensure!(
                source_identity(&source) == owner.source,
                "direct guard source incarnation changed"
            );
            retain_native_control(
                &storage,
                "permission",
                &owner.binding.reservation_operation_id,
                &turn.context,
                native_reply_body,
                native_reply_signature,
            )
            .await?;
            if let Some(record) = &owner.final_record {
                return Ok(Reply::Final {
                    evidence: placement_evidence(placement, record),
                    record: record.clone(),
                });
            }
            ensure!(
                !owner.native_committed,
                "direct guard publication already released"
            );
            if matches!(placement.physical, DirectPhysicalContext::External { .. }) {
                let verified = source
                    .external_verified
                    .ok_or_else(|| anyhow::anyhow!("direct external source receipt absent"))?;
                let authorization = ExternalPermission {
                    context: turn.context.clone(),
                    permission: permission.clone(),
                    source_receipt_digest: verified.receipt_digest,
                };
                write(
                    &storage,
                    "direct-guard/external-permission/v1",
                    &authorization,
                )
                .await?;
                Ok(Reply::Acknowledged)
            } else {
                managed_promote(env, &storage, &turn, owner, source, &qualified, permission).await
            }
        }
        Operation::ExternalFinalize => {
            let owner = retained(&storage).await?;
            check_originals(&owner, &turn, &selected)?;
            let source = retained_source(env, &turn).await?;
            ensure!(
                source_identity(&source) == owner.source,
                "direct external final source changed"
            );
            let step = if turn.admission.intent.byte_size.get() == 0 {
                "final-create"
            } else {
                "final-close"
            };
            let operation_id = verification::step_id(
                &turn.admission,
                turn.placement_id,
                &turn.complete.operation_id,
                step,
            )?;
            let (incarnation, etag) = crate::external_object::direct_final(
                env,
                &storage,
                &turn.admission,
                turn.placement_id,
                &operation_id,
            )
            .await?;
            let record = DirectFinalGuardRecord {
                version: 1,
                reservation: owner.binding.clone(),
                selected: owner.selected.clone(),
                sha256: owner.source.sha256.clone(),
                byte_size: owner.source.byte_size,
                source_incarnation: owner.source.incarnation.clone(),
                final_incarnation: incarnation,
                final_etag: etag,
            };
            let next = owner.acknowledge_publication(record.clone())?;
            write(
                &storage,
                &final_key(&owner.binding.reservation_operation_id),
                &record,
            )
            .await?;
            write(&storage, OWNER, &next).await?;
            Ok(Reply::Final {
                evidence: placement_evidence(placement, &record),
                record,
            })
        }
    }
}

/// Replays retained positives and exact Native acknowledgements without dispatch.
async fn historical_metadata(env: &Env, state: &State, turn: &Turn) -> Result<Reply> {
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let latest_now = || crate::direct_upload::config::guard_latest_now(env);
    turn.context.validate(
        &deployment,
        &env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string(),
        latest_now()?,
    )?;
    let (binding, address, _) =
        transport::physical_address(env, &turn.admission, turn.placement_id)?;
    ensure!(
        env.durable_object(&binding)?
            .id_from_name(&address)?
            .to_string()
            == state.id().to_string(),
        "direct historical physical owner differs"
    );
    let placement = original::placement(&turn.admission, turn.placement_id)?;
    let storage = state.storage();
    match &turn.operation {
        Operation::ReadPublication => {
            let operation = direct_destination_promotion_operation_id(
                &turn.complete.session,
                turn.placement_id,
                &turn.complete.operation_id,
            )?;
            let record = read::<DirectFinalGuardRecord>(&storage, &final_key(&operation)).await?;
            let record = match record {
                Some(record) => Some(record),
                None => {
                    let owner: Option<Reservation> = read(&storage, OWNER).await?;
                    match owner {
                        Some(owner) => {
                            check_originals(&owner, turn, &owner.selected)?;
                            // This repairs only an already positive retained SDK
                            // receipt; it performs no provider read or mutation.
                            recover_publication(env, &storage, turn, &owner.selected).await?
                        }
                        None => None,
                    }
                }
            };
            let Some(record) = record else {
                return Ok(Reply::Unsettled);
            };
            let evidence = placement_evidence(placement, &record);
            record.validate_placement_for(
                &turn.admission,
                &turn.complete,
                &evidence,
                &deployment,
            )?;
            turn.context.validate(
                &deployment,
                &env.var("HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN")?.to_string(),
                latest_now()?,
            )?;
            Ok(Reply::Final { evidence, record })
        }
        Operation::NativeCommit {
            record,
            public_body,
            reply_body,
            reply_signature,
        } => {
            let owner = retained(&storage).await?;
            check_originals(&owner, turn, &owner.selected)?;
            ensure!(
                owner.final_record.as_ref() == Some(record),
                "direct historical Native acknowledgement differs"
            );
            let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
            let committed = super::state::authenticate_native_commit(
                &key,
                &owner,
                record,
                &turn.context,
                public_body.as_bytes(),
                reply_body.as_bytes(),
                reply_signature,
                latest_now()?,
            )?;
            retain_native_control(
                &storage,
                "native",
                &owner.binding.reservation_operation_id,
                &turn.context,
                reply_body,
                reply_signature,
            )
            .await?;
            write(&storage, OWNER, &committed).await?;
            Ok(Reply::Acknowledged)
        }
        _ => anyhow::bail!("direct historical route attempted provider dispatch"),
    }
}

async fn retain_native_control(
    storage: &Storage,
    family: &str,
    reservation_id: &str,
    context: &DirectRequestContext,
    body: &str,
    signature: &str,
) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use sha2::{Digest as _, Sha256};

    ensure!(
        body.len() <= MAX_DIRECT_CONTROL_BYTES,
        "direct Native evidence exceeds bound"
    );
    let prefix = format!(
        "direct-guard/{family}/v1/{reservation_id}/{}",
        context.request_nonce
    );
    let mut chunks = 0;
    for (index, bytes) in body.as_bytes().chunks(48 * 1024).enumerate() {
        let key = format!("{prefix}/body/{index}");
        let encoded = STANDARD.encode(bytes);
        if let Some(original) = read::<String>(storage, &key).await? {
            ensure!(
                original == encoded,
                "direct original Native evidence changed"
            );
        } else {
            write(storage, &key, &encoded).await?;
        }
        chunks += 1;
    }
    // Every bounded body chunk precedes this authenticated durable evidence
    // pointer. Physical exclusion can be released only after that last write.
    let metadata = (
        context,
        signature,
        hex::encode(Sha256::digest(body.as_bytes())),
        body.len(),
        chunks,
    );
    write(storage, &format!("{prefix}/receipt"), &metadata).await
}

async fn reserve(
    env: &Env,
    storage: &Storage,
    turn: &Turn,
    selected: DirectSelectedCompleteCommitment,
    qualified: &QualifiedConfig,
) -> Result<Reply> {
    let placement = original::placement(&turn.admission, turn.placement_id)?;
    ensure!(
        qualified.latest_now()? < turn.admission.expires_at.get(),
        "direct guard original admission expired"
    );
    let source = retained_source(env, turn).await?;
    let existing: Option<Reservation> = read(storage, OWNER).await?;
    recover_known_pending(storage).await?;
    ensure!(
        read::<Effect>(storage, "direct-guard/pending/v1")
            .await?
            .is_none(),
        "direct guard provider effect remains unknown"
    );
    if matches!(placement.physical, DirectPhysicalContext::External { .. }) {
        crate::external_object::check_direct_available(
            env,
            storage,
            &turn.admission,
            turn.placement_id,
        )
        .await?;
    }
    let mut owner = match existing {
        Some(owner) if !owner.native_committed || owner.complete == turn.complete => {
            check_originals(&owner, turn, &selected)?;
            ensure!(
                owner.source == source_identity(&source),
                "direct reservation source changed"
            );
            owner
        }
        old => {
            ensure!(
                read::<serde_json::Value>(storage, "pending-mutation")
                    .await?
                    .is_none()
                    && read::<serde_json::Value>(storage, "pending-delete")
                        .await?
                        .is_none(),
                "direct guard prior physical effect unknown"
            );
            let revision = old.as_ref().map_or(1, |old| {
                old.binding.reservation_revision.get().saturating_add(1)
            });
            let reservation_operation_id = direct_destination_promotion_operation_id(
                &turn.complete.session,
                turn.placement_id,
                &turn.complete.operation_id,
            )?;
            let scope = match &placement.physical {
                DirectPhysicalContext::DeploymentR2 {
                    bucket_namespace, ..
                } => DirectDestinationReservationScope::Managed {
                    bucket_namespace: bucket_namespace.clone(),
                },
                DirectPhysicalContext::External { write_cohort, .. } => {
                    DirectDestinationReservationScope::External {
                        physical_authority_id: write_cohort.authority.authority_id.clone(),
                    }
                }
            };
            let binding = DirectDestinationBaselineBinding {
                deployment_id: turn.context.deployment_id.clone(),
                session: turn.complete.session.clone(),
                admission_expires_at: turn.admission.expires_at,
                complete_operation_id: turn.complete.operation_id.clone(),
                complete_intent_digest: turn.complete.fingerprint()?,
                placement: selected.manifest.placement.clone(),
                protected_profile_digest: selected.protected_profile_digest.clone(),
                final_key_digest: direct_destination_key_digest(&placement.final_key)?,
                scope,
                reservation_operation_id,
                reservation_nonce: journal::digest(&uuid::Uuid::new_v4().to_string())?,
                reservation_revision: WireInteger::new(revision),
            };
            let owner = Reservation {
                admission: turn.admission.clone(),
                complete: turn.complete.clone(),
                selected,
                binding,
                source: source_identity(&source),
                baseline: None,
                final_record: None,
                native_committed: false,
            };
            owner.validate()?;
            // This first durable owner write excludes every legacy mutation
            // before baseline I/O or provider destination creation.
            write(storage, OWNER, &owner).await?;
            if matches!(placement.physical, DirectPhysicalContext::External { .. }) {
                crate::external_object::prepare_direct_destination(
                    env,
                    storage,
                    &turn.admission,
                    turn.placement_id,
                )
                .await?;
            }
            owner
        }
    };
    ensure!(
        owner.final_record.is_none() && !owner.native_committed,
        "direct baseline already published"
    );
    let state = match placement.physical {
        DirectPhysicalContext::DeploymentR2 { .. } => {
            managed_baseline(env, &placement.final_key).await?
        }
        DirectPhysicalContext::External { .. } => {
            crate::external_object::direct_baseline(
                env,
                storage,
                &turn.admission,
                turn.placement_id,
                turn.context.expires_at.get(),
            )
            .await?
        }
    };
    let now = qualified.latest_now()?;
    let expires_at = WireInteger::new(
        turn.context
            .expires_at
            .get()
            .min(turn.admission.expires_at.get()),
    );
    ensure!(
        now < expires_at.get(),
        "direct baseline observation expired"
    );
    if owner.baseline.is_none() {
        let baseline = DirectDestinationBaselineEvidence {
            binding: owner.binding.clone(),
            observation_operation_id: verification::step_id(
                &turn.admission,
                turn.placement_id,
                &turn.complete.operation_id,
                "baseline-original",
            )?,
            issued_at: WireInteger::new(now),
            expires_at,
            state: state.clone(),
        };
        owner = owner.retain_baseline(baseline)?;
        write(storage, OWNER, &owner).await?;
    }
    let baseline = owner
        .baseline
        .clone()
        .ok_or_else(|| anyhow::anyhow!("direct baseline lost original document"))?;
    ensure!(
        baseline.state == state,
        "direct reservation baseline incarnation changed"
    );
    let proposed = DirectDestinationBaselineWitness {
        binding: owner.binding.clone(),
        baseline_digest: baseline.fingerprint()?,
        observation_operation_id: journal::digest(&(
            &owner.binding.reservation_operation_id,
            &turn.context.request_nonce,
            "held-baseline-witness",
        ))?,
        issued_at: WireInteger::new(now),
        expires_at,
    };
    let witness =
        match read::<DirectDestinationBaselineWitness>(storage, &witness_key(&proposed)?).await? {
            Some(original) => {
                ensure!(
                    original.binding == proposed.binding
                        && original.baseline_digest == proposed.baseline_digest
                        && original.expires_at == proposed.expires_at,
                    "direct original held witness changed"
                );
                original
            }
            None => proposed,
        };
    witness.validate_for(&baseline, &turn.context, qualified.latest_now()?)?;
    write(storage, &witness_key(&witness)?, &witness).await?;
    Ok(Reply::Baseline { baseline, witness })
}

async fn managed_baseline(env: &Env, final_key: &str) -> Result<DirectDestinationBaselineState> {
    let Some(head) = managed::head(env, final_key).await? else {
        return Ok(DirectDestinationBaselineState::Missing {});
    };
    let (identity, stream, _capacity) = managed::get(env, final_key, None).await?;
    ensure!(
        identity == head,
        "direct baseline same-action source incarnation changed"
    );
    let digest = crate::direct_digest::hash_response(
        Response::from_body(ResponseBody::Stream(stream))?,
        MAX_DIRECT_OBJECT_BYTES,
    )
    .await?;
    ensure!(
        digest.byte_size == identity.byte_size.get(),
        "direct baseline measured size differs"
    );
    Ok(DirectDestinationBaselineState::Present {
        byte_size: identity.byte_size,
        sha256: digest.sha256,
        etag: identity.etag,
        provider_version: Some(identity.version),
        guard_stamp: None,
    })
}

pub(super) async fn retained_source(env: &Env, turn: &Turn) -> Result<VerifiedPlacement> {
    super::lookup::validate_originals(env, &turn.admission, &turn.complete).await?;
    let source = verification::retained(env, &turn.admission, &turn.complete, turn.placement_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("direct independent source verification absent"))?;
    ensure!(
        source.sha256 == turn.admission.intent.expected_sha256
            && source.byte_size == turn.admission.intent.byte_size
            && source.placement.manifest
                == *turn
                    .complete
                    .manifests
                    .iter()
                    .find(|item| item.placement.placement_id == turn.placement_id)
                    .ok_or_else(|| anyhow::anyhow!("direct source manifest absent"))?,
        "direct guard independently retained source differs"
    );
    validate_positive_source(
        env,
        &turn.admission,
        &turn.complete,
        turn.placement_id,
        &source,
    )
    .await?;
    if matches!(source.closed, ClosedStage::External { .. }) {
        let placement = original::placement(&turn.admission, turn.placement_id)?;
        ensure!(
            direct_staging_key(&turn.admission.session_id, placement)? != placement.final_key,
            "direct source and destination physical keys coincide"
        );
        super::lookup::confirm_external_stage(
            env,
            &turn.admission,
            &turn.complete,
            turn.placement_id,
            &turn.context,
        )
        .await?;
    }
    Ok(source)
}

async fn validate_positive_source(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    placement_id: WireInteger,
    source: &VerifiedPlacement,
) -> Result<()> {
    let create_id = verification::step_id(
        admission,
        placement_id,
        &admission.intent.client_operation_id,
        "create-stage",
    )?;
    let original::Reply::Effect {
        effect: Some(create),
    } = original::call(
        env,
        admission,
        original::Operation::ReadEffect {
            operation_id: create_id.clone(),
        },
    )
    .await?
    else {
        anyhow::bail!("direct original stage Create receipt absent");
    };
    let expected_create = Effect::new(create_id, &(admission, placement_id), false)?;
    let created: verification::CreatedStage = serde_json::from_value(
        super::state::positive_effect_terminal(&create, &expected_create)?.clone(),
    )?;
    if let ClosedStage::Managed { object } = &source.closed {
        let verification::CreatedStage::Managed { receipt } = created else {
            anyhow::bail!("direct original provider Create scope differs");
        };
        if admission.intent.byte_size.get() == 0 {
            ensure!(
                receipt.empty.as_ref() == Some(object) && receipt.upload_id.is_none(),
                "direct original EmptyPut incarnation changed"
            );
        } else {
            let upload_id = receipt
                .upload_id
                .ok_or_else(|| anyhow::anyhow!("direct original stage UploadId absent"))?;
            let close_id = verification::step_id(
                admission,
                placement_id,
                &complete.operation_id,
                "close-stage",
            )?;
            let original::Reply::Effect {
                effect: Some(close),
            } = original::call(
                env,
                admission,
                original::Operation::ReadEffect {
                    operation_id: close_id.clone(),
                },
            )
            .await?
            else {
                anyhow::bail!("direct original positive stage Close absent");
            };
            let expected = Effect::new(close_id, &(complete, placement_id, &upload_id), false)?;
            let acknowledged: managed::ObjectReceipt = serde_json::from_value(
                super::state::positive_effect_terminal(&close, &expected)?.clone(),
            )?;
            ensure!(
                &acknowledged == object,
                "direct stage source incarnation differs from positive Close"
            );
        }
    }
    let verify_id = verification::step_id(
        admission,
        placement_id,
        &complete.operation_id,
        "verify-stage",
    )?;
    let original::Reply::Effect {
        effect: Some(verified),
    } = original::call(
        env,
        admission,
        original::Operation::ReadEffect {
            operation_id: verify_id.clone(),
        },
    )
    .await?
    else {
        anyhow::bail!("direct original full integrity receipt absent");
    };
    let job = verification::VerificationJob {
        version: 1,
        admission: admission.clone(),
        complete: complete.clone(),
        placement_id,
        closed: source.closed.clone(),
    };
    super::state::positive_effect_terminal(&verified, &Effect::new(verify_id, &job, true)?)?;
    Ok(())
}

pub(super) async fn validate_stage(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    stage: &DirectVerifiedStageEvidence,
) -> Result<()> {
    stage.validate_against(admission, &env.var("HUB_DEPLOYMENT_ID")?.to_string())?;
    ensure!(
        stage.operation_id == complete.operation_id,
        "direct verified original Complete differs"
    );
    for expected in &stage.placements {
        let actual =
            verification::retained(env, admission, complete, expected.placement.placement_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("direct storage verification receipt absent"))?;
        ensure!(
            actual.placement == *expected
                && actual.sha256 == stage.sha256
                && actual.byte_size == stage.byte_size
                && actual.projection == stage.projection,
            "direct independent stage receipt differs"
        );
        validate_positive_source(
            env,
            admission,
            complete,
            expected.placement.placement_id,
            &actual,
        )
        .await?;
    }
    Ok(())
}

fn source_identity(source: &VerifiedPlacement) -> Source {
    Source {
        sha256: source.sha256.clone(),
        byte_size: source.byte_size,
        incarnation: source.placement.staging_incarnation.clone(),
    }
}

pub(super) fn check_originals(
    owner: &Reservation,
    turn: &Turn,
    selected: &DirectSelectedCompleteCommitment,
) -> Result<()> {
    owner.validate()?;
    ensure!(
        owner.admission == turn.admission
            && owner.complete == turn.complete
            && &owner.selected == selected,
        "direct physical guard originals changed"
    );
    Ok(())
}

pub(super) fn placement_evidence(
    placement: &DirectPlacement,
    record: &DirectFinalGuardRecord,
) -> DirectPlacementEvidence {
    DirectPlacementEvidence {
        placement_id: placement.placement_id,
        placement_resource_version: placement.placement_resource_version,
        write_spec_version: placement.write_spec_version,
        binding_id: placement.binding_id,
        binding_resource_version: placement.binding_resource_version,
        binding_write_revision: placement.binding_write_revision,
        manifest: record.selected.manifest.clone(),
        promotion_operation_id: record.reservation.reservation_operation_id.clone(),
        staging_incarnation: record.source_incarnation.clone(),
        final_incarnation: record.final_incarnation.clone(),
        final_etag: record.final_etag.clone(),
    }
}

/// Excludes legacy operations while an unacknowledged direct owner is retained.
///
/// # Errors
/// Returns an error for a held owner or unreadable durable reservation.
pub(crate) async fn deny_legacy(storage: &Storage) -> Result<()> {
    ensure!(
        read::<Reservation>(storage, OWNER)
            .await?
            .is_none_or(|owner| owner.native_committed),
        "direct publication reservation remains held"
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalPermission {
    context: DirectRequestContext,
    permission: DirectDestinationBaselinePermission,
    source_receipt_digest: String,
}

/// Admits only the exact authorized destination effect under the held owner.
///
/// # Errors
/// Returns an error for another owner, expired permission, changed source,
/// unresolved storage or a receipt that predates the reservation.
pub(crate) async fn check_external_stage(
    storage: &Storage,
    operation_id: &str,
    context: &aos_hub_core::storage_authority::external_object::stage::ExternalStageContext,
    operation: &aos_hub_core::storage_authority::external_object::stage::ExternalStageOperation,
    receipt_exists: bool,
) -> Result<Option<WireInteger>> {
    use aos_hub_core::storage_authority::external_object::stage::{
        ExternalStageContext, ExternalStageOperation as Action,
    };
    let Some(owner) = read::<Reservation>(storage, OWNER).await? else {
        return Ok(None);
    };
    if owner.native_committed {
        return Ok(None);
    }
    ensure!(
        operation.destination() && owner.final_record.is_none(),
        "direct publication reservation excludes another stage writer"
    );
    owner.validate()?;
    let expected = ExternalStageContext::from_admission(
        &owner.admission,
        owner.binding.placement.placement_id,
        &owner.binding.deployment_id,
    )?;
    ensure!(
        context == &expected,
        "direct external stage original owner differs"
    );
    let authorization: ExternalPermission = read(storage, "direct-guard/external-permission/v1")
        .await?
        .ok_or_else(|| anyhow::anyhow!("direct external Native publication permission absent"))?;
    let receipt_digest = match operation {
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
        } => verified_stage_receipt_digest,
        _ => anyhow::bail!("direct reservation excludes a stage source operation"),
    };
    ensure!(
        receipt_digest == &authorization.source_receipt_digest
            && authorization.permission.binding == owner.binding,
        "direct external source or permission differs"
    );
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
    ensure!(
        now < authorization.permission.expires_at.get() && now < owner.admission.expires_at.get(),
        "direct external publication permission expired"
    );
    let key = format!("direct-guard/external-effect/v1/{operation_id}");
    let expected = (
        owner.binding,
        journal::digest(&(operation_id, context, operation))?,
    );
    match read::<(DirectDestinationBaselineBinding, String)>(storage, &key).await? {
        Some(original) => ensure!(
            original == expected,
            "direct external dispatch owner changed"
        ),
        None => {
            ensure!(
                !receipt_exists,
                "external receipt predates direct reservation"
            );
            // This marker binds the existing authority's actual effect to the
            // already durable reservation before its provider dispatch begins.
            write(storage, &key, &expected).await?;
        }
    }
    Ok(Some(authorization.permission.expires_at))
}

/// Correlates an actual external terminal with its original reserved dispatch.
///
/// # Errors
/// Returns an error for absent dispatch evidence or a changed original owner.
pub(crate) async fn verify_external_dispatch(
    storage: &Storage,
    operation_id: &str,
    context: &aos_hub_core::storage_authority::external_object::stage::ExternalStageContext,
    operation: &aos_hub_core::storage_authority::external_object::stage::ExternalStageOperation,
) -> Result<()> {
    let owner = retained(storage).await?;
    owner.validate()?;
    let actual: (DirectDestinationBaselineBinding, String) = read(
        storage,
        &format!("direct-guard/external-effect/v1/{operation_id}"),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("external original reserved dispatch absent"))?;
    ensure!(
        actual
            == (
                owner.binding,
                journal::digest(&(operation_id, context, operation))?
            ),
        "external publication receipt belongs to another reservation"
    );
    Ok(())
}

pub(super) async fn retained(storage: &Storage) -> Result<Reservation> {
    read(storage, OWNER)
        .await?
        .ok_or_else(|| anyhow::anyhow!("direct physical reservation absent"))
}

pub(super) async fn read<T: DeserializeOwned>(storage: &Storage, key: &str) -> Result<Option<T>> {
    original::read(storage, key).await
}

pub(super) async fn write<T: Serialize>(storage: &Storage, key: &str, value: &T) -> Result<()> {
    original::write(storage, key, value).await
}

pub(super) fn final_key(operation: &str) -> String {
    format!("direct-guard/final/v1/{operation}")
}

pub(super) fn witness_key(witness: &DirectDestinationBaselineWitness) -> Result<String> {
    witness.validate()?;
    Ok(format!(
        "direct-guard/witness/v1/{}",
        witness.observation_operation_id
    ))
}

fn error(_: impl std::fmt::Display) -> worker::Error {
    worker::Error::RustError("direct physical guard unavailable".into())
}
