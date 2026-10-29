//! Authenticated bounded calls to the permanent physical-key reservation owner.

use anyhow::{ensure, Result};
use aos_hub_db::direct_upload::*;
use aos_hub_db::storage_work::StorageWorkKey;
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{Env, Headers, Method, Request, RequestInit};

pub(super) const TURN_PATH: &str = "/direct-guard-turn";
// This internal envelope contains separately bounded public and signed Native
// controls. JSON strings preserve their exact bytes without numeric-array bloat.
pub(super) const MAX_TURN_BYTES: usize =
    aos_hub_db::storage_work::MAX_PLAN_BYTES - TURN_DOMAIN.len();
pub(super) const TURN_HEADER: &str = "x-aos-direct-physical-guard-signature";
pub(super) const TURN_DOMAIN: &[u8] = b"aos.direct-upload.physical-guard-turn.v1\0";
pub(super) const OWNER: &str = "direct-guard/owner/v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Turn {
    pub(super) admission: DirectUploadAdmission,
    pub(super) complete: DirectCompleteRequest,
    pub(super) placement_id: WireInteger,
    pub(super) context: DirectRequestContext,
    pub(super) operation: Operation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Reserve,
    ReadPublication,
    Promote {
        stage: DirectVerifiedStageEvidence,
        baseline: DirectDestinationBaselineEvidence,
        witness: DirectDestinationBaselineWitness,
        permission: DirectDestinationBaselinePermission,
        native_reply_body: String,
        native_reply_signature: String,
    },
    ExternalFinalize,
    AcknowledgeCopyProgress {
        after: u32,
        through: u32,
    },
    ReadCopiedParts {
        after: u32,
        through: u32,
    },
    NativeCommit {
        record: DirectFinalGuardRecord,
        public_body: String,
        reply_body: String,
        reply_signature: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Reply {
    Baseline {
        baseline: DirectDestinationBaselineEvidence,
        witness: DirectDestinationBaselineWitness,
    },
    Final {
        evidence: DirectPlacementEvidence,
        record: DirectFinalGuardRecord,
    },
    Acknowledged,
    // Older executors reject these variants before provider dispatch. A missing
    // progress journal starts at zero and reuses only exact positive receipts.
    CopyProgress {
        copied_through: u32,
    },
    CopiedParts {
        parts: Vec<DirectManifestPart>,
    },
    Unsettled,
}

pub(super) fn key(env: &Env) -> Result<StorageWorkKey> {
    let secret = env.secret("HUB_DIRECT_UPLOAD_GUARD_KEY")?.to_string();
    for name in ["HUB_STORAGE_WORK_KEY", "HUB_DIRECT_UPLOAD_JOURNAL_KEY"] {
        ensure!(
            secret != env.secret(name)?.to_string(),
            "direct guard authentication key must be independent"
        );
    }
    Ok(StorageWorkKey::new(secret)?)
}

pub(super) fn physical_address(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
) -> Result<(String, String, String)> {
    let placement = crate::direct_upload::storage::placement(admission, placement_id)?;
    match &placement.physical {
        DirectPhysicalContext::DeploymentR2 { deployment_id, .. } => {
            ensure!(
                deployment_id == &env.var("HUB_DEPLOYMENT_ID")?.to_string(),
                "direct physical deployment differs"
            );
            let address = format!(
                "{deployment_id}:{}",
                hex::encode(Sha256::digest(&placement.final_key))
            );
            Ok((
                "HYBRID_OBJECT_GUARD".into(),
                address,
                placement.final_key.clone(),
            ))
        }
        DirectPhysicalContext::External { .. } => {
            let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
            let context = aos_hub_db::storage_authority::external_object::stage::ExternalStageContext::from_admission(admission, placement_id, &deployment)?;
            let scope = context.scope(true)?;
            Ok((
                "EXTERNAL_OBJECT_GUARD".into(),
                scope.guard_name()?,
                scope.full_key,
            ))
        }
    }
}

pub(super) async fn call(env: &Env, turn: &Turn) -> Result<Reply> {
    call_with_signal(env, turn, None).await
}

// The native Request carries the existing HTTP signal across the internal DO
// hop; signed turn bytes and physical reservation identity remain unchanged.
async fn call_with_signal(
    env: &Env,
    turn: &Turn,
    signal: Option<worker::web_sys::AbortSignal>,
) -> Result<Reply> {
    let (binding, address, full_key) = physical_address(env, &turn.admission, turn.placement_id)?;
    let body = serde_json::to_vec(turn)?;
    ensure!(
        body.len() <= MAX_TURN_BYTES,
        "direct guard turn exceeds bound"
    );
    let headers = Headers::new();
    headers.set(
        TURN_HEADER,
        &key(env)?.sign_body(&[TURN_DOMAIN, &body].concat())?,
    )?;
    headers.set("x-aos-hybrid-object-key", &full_key)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request = if let Some(signal) = signal {
        let native = worker::web_sys::RequestInit::from(&init);
        native.set_signal(Some(&signal));
        worker::web_sys::Request::new_with_str_and_init(
            &format!("https://physical-guard{TURN_PATH}"),
            &native,
        )
        .map(Request::from)
        .map_err(|_| anyhow::anyhow!("direct guard cancellation handoff failed"))?
    } else {
        Request::new_with_init(&format!("https://physical-guard{TURN_PATH}"), &init)?
    };
    let mut response = env
        .durable_object(&binding)?
        .id_from_name(&address)?
        .get_stub()?
        .fetch_with_request(request)
        .await?;
    ensure!(
        response.status_code() == 200,
        "direct physical reservation refused"
    );
    let mut stream = response.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            bytes
                .len()
                .checked_add(chunk.len())
                .is_some_and(|size| size <= MAX_DIRECT_CONTROL_BYTES),
            "direct physical guard response exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(decode_direct_control(&bytes)?)
}

/// Retains the exact physical owner and measures its first held baseline.
///
/// # Errors
/// Returns an error for changed originals, unresolved effects, failed authority,
/// or an unacknowledged bounded baseline observation.
pub(crate) async fn reserve_baseline(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    placement_id: WireInteger,
    context: &DirectRequestContext,
    signal: Option<worker::web_sys::AbortSignal>,
) -> Result<(
    DirectDestinationBaselineEvidence,
    DirectDestinationBaselineWitness,
)> {
    let turn = Turn {
        admission: admission.clone(),
        complete: complete.clone(),
        placement_id,
        context: context.clone(),
        operation: Operation::Reserve,
    };
    match call_with_signal(env, &turn, signal).await? {
        Reply::Baseline { baseline, witness } => Ok((baseline, witness)),
        _ => anyhow::bail!("direct baseline reservation response differs"),
    }
}

/// Returns an exact positive publication retained across acknowledgement loss.
///
/// # Errors
/// Returns an error for changed original identity, failed authority or storage.
pub(crate) async fn read_publication(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    placement_id: WireInteger,
    context: &DirectRequestContext,
) -> Result<Option<(DirectPlacementEvidence, DirectFinalGuardRecord)>> {
    let turn = Turn {
        admission: admission.clone(),
        complete: complete.clone(),
        placement_id,
        context: context.clone(),
        operation: Operation::ReadPublication,
    };
    match call(env, &turn).await? {
        Reply::Final { evidence, record } => Ok(Some((evidence, record))),
        Reply::Unsettled => Ok(None),
        _ => anyhow::bail!("direct publication readback response differs"),
    }
}

/// Publishes the exact verified R2 source under authenticated Native permission.
///
/// # Errors
/// Returns an error for changed source or baseline, failed Native authentication,
/// expired permission, or an unresolved provider attempt.
pub(crate) async fn promote_managed(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    placement_id: WireInteger,
    stage: &DirectVerifiedStageEvidence,
    baseline: &DirectDestinationBaselineEvidence,
    witness: &DirectDestinationBaselineWitness,
    permission: &DirectDestinationBaselinePermission,
    context: &DirectRequestContext,
    native_reply_body: &[u8],
    native_reply_signature: &str,
) -> Result<(DirectPlacementEvidence, DirectFinalGuardRecord)> {
    let turn = Turn {
        admission: admission.clone(),
        complete: complete.clone(),
        placement_id,
        context: context.clone(),
        operation: Operation::Promote {
            stage: stage.clone(),
            baseline: baseline.clone(),
            witness: witness.clone(),
            permission: permission.clone(),
            native_reply_body: std::str::from_utf8(native_reply_body)?.into(),
            native_reply_signature: native_reply_signature.into(),
        },
    };
    match call(env, &turn).await? {
        Reply::Final { evidence, record } => Ok((evidence, record)),
        _ => anyhow::bail!("direct publication response differs"),
    }
}

/// Publishes the exact external source through its permanent physical authority.
///
/// # Errors
/// Returns an error for changed source or baseline, failed Native authentication,
/// expired permission, or an unresolved actual external stage effect.
pub(crate) async fn promote_external(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    placement_id: WireInteger,
    stage: &DirectVerifiedStageEvidence,
    baseline: &DirectDestinationBaselineEvidence,
    witness: &DirectDestinationBaselineWitness,
    permission: &DirectDestinationBaselinePermission,
    context: &DirectRequestContext,
    native_reply_body: &[u8],
    native_reply_signature: &str,
    signal: Option<worker::web_sys::AbortSignal>,
) -> Result<Option<(DirectPlacementEvidence, DirectFinalGuardRecord)>> {
    use crate::direct_upload::verification;
    use aos_hub_db::storage_authority::external_object::stage::ExternalStageOperation as Action;
    use aos_hub_db::storage_authority::external_object::stage::ExternalStageOutcome as Outcome;

    let mut turn = Turn {
        admission: admission.clone(),
        complete: complete.clone(),
        placement_id,
        context: context.clone(),
        operation: Operation::Promote {
            stage: stage.clone(),
            baseline: baseline.clone(),
            witness: witness.clone(),
            permission: permission.clone(),
            native_reply_body: std::str::from_utf8(native_reply_body)?.into(),
            native_reply_signature: native_reply_signature.into(),
        },
    };
    let copied_through = match call(env, &turn).await? {
        Reply::Final { evidence, record } => return Ok(Some((evidence, record))),
        Reply::CopyProgress { copied_through } => copied_through,
        _ => anyhow::bail!("direct external publication authorization differs"),
    };
    let verified = verification::retained(env, admission, complete, placement_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("direct external verified source absent"))?;
    let receipt_digest = verified
        .external_verified
        .ok_or_else(|| anyhow::anyhow!("direct external immutable source receipt absent"))?
        .receipt_digest;
    let step =
        |name: &str| verification::step_id(admission, placement_id, &complete.operation_id, name);
    let create = crate::external_object::prepare_stage_request(
        env,
        admission,
        placement_id,
        step("final-create")?,
        Action::CreateDestination {
            verified_stage_receipt_digest: receipt_digest.clone(),
        },
    )
    .await?;
    let created =
        crate::external_object::execute_stage_with_signal(env, &create, signal.clone()).await?;
    match created.outcome {
        Outcome::EmptyClosed { .. } => {}
        Outcome::Created { upload_id } => {
            let manifest = complete
                .manifests
                .iter()
                .find(|item| item.placement.placement_id == placement_id)
                .ok_or_else(|| anyhow::anyhow!("direct external original manifest absent"))?;
            let parts =
                verification::load_parts(env, admission, placement_id, Some(manifest)).await?;
            // A large object must not serialize hundreds of independent SDK
            // copies inside one foreground window. Each wave still uses the
            // shared provider pool and the original signed permission.
            let wave = super::copy_progress::next_wave(parts.len(), copied_through)?;
            let start = wave.start;
            let end = wave.end;
            if start < end {
                super::copy_parts::copy_parts(&parts[start..end], |original| {
                    let upload_id = upload_id.clone();
                    let receipt_digest = receipt_digest.clone();
                    let signal = signal.clone();
                    let operation_id = step(&format!("final-copy:{}", original.part.part_number));

                    async move {
                        let work = crate::external_object::prepare_stage_request(
                            env,
                            admission,
                            placement_id,
                            operation_id?,
                            Action::CopyDestinationPart {
                                upload_id,
                                verified_stage_receipt_digest: receipt_digest,
                                part: original.part.clone(),
                            },
                        )
                        .await?;
                        let receipt =
                            crate::external_object::execute_stage_with_signal(env, &work, signal)
                                .await?;
                        let Outcome::Copied { part, etag } = receipt.outcome else {
                            anyhow::bail!("direct external copied part acknowledgement differs");
                        };
                        Ok(DirectManifestPart { part, etag })
                    }
                })
                .await?;
                turn.operation = Operation::AcknowledgeCopyProgress {
                    after: copied_through,
                    through: u32::try_from(end)?,
                };
                ensure!(
                    matches!(call(env, &turn).await?, Reply::CopyProgress { copied_through }
                        if usize::try_from(copied_through).ok() == Some(end)),
                    "direct copied prefix acknowledgement differs"
                );
                // A drained wave has no outstanding mutations. A later exact
                // Complete renews authorization for the same retained owner.
                // Keep final closure separate after a large copy wave.
                if end < parts.len()
                    || parts.len() > super::copy_progress::MAX_COPY_PARTS_PER_INVOCATION
                {
                    return Ok(None);
                }
            }
            let mut copied = Vec::with_capacity(parts.len());
            for page_start in
                (0..parts.len()).step_by(crate::external_object::MAX_PENDING_DESTINATION_PARTS)
            {
                let page_end = page_start
                    .saturating_add(crate::external_object::MAX_PENDING_DESTINATION_PARTS)
                    .min(parts.len());
                turn.operation = Operation::ReadCopiedParts {
                    after: u32::try_from(page_start)?,
                    through: u32::try_from(page_end)?,
                };
                let Reply::CopiedParts { parts: page } = call(env, &turn).await? else {
                    anyhow::bail!("direct copied part page acknowledgement differs");
                };
                ensure!(
                    page.len() == page_end - page_start
                        && page
                            .iter()
                            .zip(&parts[page_start..page_end])
                            .all(|(actual, original)| actual.part == original.part),
                    "direct copied part page geometry changed"
                );
                copied.extend(page);
            }
            let final_manifest = DirectManifestCommitment {
                placement: manifest.placement.clone(),
                manifest_digest: canonical_manifest_digest(
                    &admission.intent,
                    &manifest.placement,
                    &copied,
                )?,
                part_count: manifest.part_count,
            };
            let work = crate::external_object::prepare_stage_request(
                env,
                admission,
                placement_id,
                step("final-close")?,
                Action::CompleteDestination {
                    verified_stage_receipt_digest: receipt_digest,
                    upload_id,
                    manifest: final_manifest,
                },
            )
            .await?;
            crate::external_object::execute_stage_with_signal(env, &work, signal.clone()).await?;
        }
        _ => anyhow::bail!("direct external destination Create acknowledgement differs"),
    }
    turn.operation = Operation::ExternalFinalize;
    match call(env, &turn).await? {
        Reply::Final { evidence, record } => Ok(Some((evidence, record))),
        _ => anyhow::bail!("direct external independently retained publication differs"),
    }
}

/// Releases the physical owner after retaining Native's exact signed commit.
///
/// # Errors
/// Returns an error for changed public Complete bytes, Native authentication,
/// final incarnation, or durable evidence storage.
pub(crate) async fn acknowledge_native_commit(
    env: &Env,
    admission: &DirectUploadAdmission,
    complete: &DirectCompleteRequest,
    record: &DirectFinalGuardRecord,
    context: &DirectRequestContext,
    public_body: &[u8],
    reply_body: &[u8],
    reply_signature: &str,
) -> Result<()> {
    let turn = Turn {
        admission: admission.clone(),
        complete: complete.clone(),
        placement_id: record.reservation.placement.placement_id,
        context: context.clone(),
        operation: Operation::NativeCommit {
            record: record.clone(),
            public_body: std::str::from_utf8(public_body)?.into(),
            reply_body: std::str::from_utf8(reply_body)?.into(),
            reply_signature: reply_signature.into(),
        },
    };
    ensure!(
        matches!(call(env, &turn).await?, Reply::Acknowledged),
        "direct Native acknowledgement response differs"
    );
    Ok(())
}
