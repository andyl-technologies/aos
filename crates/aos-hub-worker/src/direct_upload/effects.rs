//! Original part grants and ordered private-stage effects for one object.
//!
//! Journal identity precedes every provider effect. A lost or negative effect
//! reply cannot manufacture a terminal receipt or permit dispatch replay.

use anyhow::{ensure, Result};
use aos_hub_core::{
    direct_upload::*,
    storage_authority::external_object::stage::{
        ExternalStageGrant, ExternalStageOperation, ExternalStageOutcome,
    },
};
use serde::{Deserialize, Serialize};
use worker::Env;

use super::{
    authority::{current, MaterialProfile, StageAuthority},
    config::QualifiedConfig,
    journal::{self, PartRecord},
    managed,
    storage::{self, Operation, Reply},
    verification::{self, CreatedStage},
};

/// Reads the retained positive creation receipt for an original placement.
///
/// # Errors
/// Returns an error if the original creation is unknown or its receipt differs
/// from the typed creation contract.
pub(crate) async fn created(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
) -> Result<CreatedStage> {
    let operation_id = verification::step_id(
        admission,
        placement_id,
        &admission.intent.client_operation_id,
        "create-stage",
    )?;
    let Reply::Effect { effect } =
        storage::call(env, admission, Operation::ReadEffect { operation_id }).await?
    else {
        anyhow::bail!("direct stage create lookup differs");
    };
    let terminal = effect
        .and_then(|value| value.terminal)
        .ok_or_else(|| anyhow::anyhow!("direct stage create outcome unknown"))?;
    serde_json::from_value(terminal)
        .map_err(|_| anyhow::anyhow!("direct stage create receipt malformed"))
}

pub(super) async fn begin(
    env: &Env,
    authority: &dyn StageAuthority,
    admission: &DirectUploadAdmission,
    context: &DirectRequestContext,
) -> Result<()> {
    // External EmptyPut has no qualified exact-incarnation deletion primitive.
    // Reject the whole object before creating any of its required placements.
    ensure!(
        admission.intent.byte_size.get() != 0
            || admission.placements.iter().all(|placement| {
                matches!(
                    placement.physical,
                    DirectPhysicalContext::DeploymentR2 { .. }
                )
            }),
        "external empty direct upload unavailable"
    );
    current(authority, context, admission)?;
    storage::call(env, admission, Operation::Admit).await?;
    for placement in &admission.placements {
        authority.protected_material(env, placement).await?;
        current(authority, context, admission)?;
        let operation_id = verification::step_id(
            admission,
            placement.placement_id,
            &admission.intent.client_operation_id,
            "create-stage",
        )?;
        storage::effect(
            env,
            admission,
            operation_id.clone(),
            &(admission, placement.placement_id),
            false,
            || async {
                current(authority, context, admission)?;
                match &placement.physical {
                    DirectPhysicalContext::DeploymentR2 { .. } => {
                        let key = direct_staging_key(&admission.session_id, placement)?;
                        Ok(CreatedStage::Managed {
                            receipt: managed::create_checked(
                                env,
                                &key,
                                admission.intent.byte_size.get() == 0,
                                || current(authority, context, admission),
                            )
                            .await?,
                        })
                    }
                    DirectPhysicalContext::External { .. } => {
                        let work = crate::external_object::prepare_stage_request_with_cutoff(
                            env,
                            admission,
                            placement.placement_id,
                            operation_id.clone(),
                            ExternalStageOperation::CreateStage,
                            context.foreground.expires_at,
                        )
                        .await?;
                        current(authority, context, admission)?;
                        Ok(CreatedStage::External {
                            result: crate::external_object::execute_stage(env, &work).await?,
                        })
                    }
                }
            },
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn grant(
    env: &Env,
    authority: &dyn StageAuthority,
    admission: &DirectUploadAdmission,
    request: &DirectGrantPartRequest,
    context: &DirectRequestContext,
) -> Result<DirectPartGrant> {
    let placement = storage::placement(admission, request.placement.placement_id)?;
    let protected = authority.protected_material(env, placement).await?;
    request.part.validate(&admission.intent)?;
    ensure!(
        request.placement == placement.public_ref(&context.deployment_id)?
            && request.part.checksum.algorithm == placement.checksum_algorithm,
        "direct requested placement differs"
    );
    let mut existing = part_at(
        env,
        admission,
        placement.placement_id,
        request.part.part_number,
    )
    .await?;
    let issued = u64::try_from(aos_hub_core::clock::now_unix_secs())?;
    let expires = admission
        .expires_at
        .get()
        .min(context.foreground.expires_at.get());
    let grant_id = journal::digest(&(
        &request.operation_id,
        &request.session,
        &request.placement,
        &request.part,
    ))?;
    let record = match existing.take() {
        Some(existing) => {
            ensure!(
                existing.grant_id == grant_id && existing.part == request.part,
                "direct original grant changed"
            );
            existing
        }
        None => PartRecord {
            session: request.session.clone(),
            placement: request.placement.clone(),
            grant_id,
            grant_revision: WireInteger::new(1),
            part: request.part.clone(),
            issued_at: WireInteger::new(issued),
            expires_at: WireInteger::new(expires),
            observed: None,
        },
    };
    ensure!(
        authority.latest_now()? < record.expires_at.get(),
        "direct original grant expired"
    );
    let created = created(env, admission, placement.placement_id).await?;
    let mut registration = record.clone();
    registration.observed = None;
    current(authority, context, admission)?;
    storage::call(env, admission, Operation::Register { part: registration }).await?;
    match (&protected, created) {
        (MaterialProfile::Managed { profile }, CreatedStage::Managed { receipt }) => {
            let upload_id = receipt
                .upload_id
                .ok_or_else(|| anyhow::anyhow!("empty direct stage has no part"))?;
            let (_, credentials) = authority.managed(env)?;
            let key = direct_staging_key(&admission.session_id, placement)?;
            let path = format!("/{}/{}", profile.bucket_name, key);
            let host = format!("{}.r2.cloudflarestorage.com", profile.account_id);
            let date =
                aos_hub_core::sigv4::amz_date_from_unix(i64::try_from(record.issued_at.get())?);
            let seconds = u32::try_from(
                record
                    .expires_at
                    .get()
                    .checked_sub(record.issued_at.get())
                    .ok_or_else(|| anyhow::anyhow!("direct grant original horizon invalid"))?,
            )?;
            let signed = aos_hub_core::sigv4::presign_direct_upload_part(
                &aos_hub_core::sigv4::PresignParams {
                    access_key: &credentials.access_key,
                    secret_key: &credentials.secret_key,
                    region: "auto",
                    service: "s3",
                    scheme: "https",
                    host: &host,
                    path: &path,
                    expires_secs: seconds,
                    amz_date: &date,
                },
                &upload_id,
                &record.part,
                30,
            )?;
            ensure!(
                authority.latest_now()? < record.expires_at.get(),
                "direct grant expired before exposure"
            );
            Ok(DirectPartGrant {
                session_id: admission.session_id.clone(),
                logical_fingerprint: admission.logical_fingerprint.clone(),
                placement: record.placement,
                grant_id: record.grant_id,
                grant_revision: record.grant_revision,
                part: record.part,
                method: "PUT".into(),
                url: signed.url,
                required_headers: signed.required_headers,
                expires_at: record.expires_at,
            })
        }
        (MaterialProfile::External { .. }, CreatedStage::External { result }) => {
            let ExternalStageOutcome::Created { upload_id } = result.outcome else {
                anyhow::bail!("direct external part stage absent");
            };
            let grant = ExternalStageGrant {
                grant_id: record.grant_id.clone(),
                grant_revision: record.grant_revision,
                part: record.part,
                issued_at: record.issued_at,
                expires_at: record.expires_at,
            };
            let operation_id = journal::digest(&(&request.operation_id, &grant))?;
            let work = crate::external_object::prepare_stage_request_with_cutoff(
                env,
                admission,
                placement.placement_id,
                operation_id,
                ExternalStageOperation::RegisterParts {
                    upload_id,
                    grants: vec![grant],
                },
                context.foreground.expires_at,
            )
            .await?;
            current(authority, context, admission)?;
            let result = crate::external_object::execute_stage(env, &work).await?;
            let mut grants =
                crate::external_object::presign_registered_parts(env, &work, &result).await?;
            current(authority, context, admission)?;
            ensure!(
                authority.latest_now()? < record.expires_at.get(),
                "direct original grant expired before exposure"
            );
            grants
                .pop()
                .ok_or_else(|| anyhow::anyhow!("direct external delegated grant absent"))
        }
        _ => anyhow::bail!("direct created stage profile kind differs"),
    }
}

async fn part_at(
    env: &Env,
    admission: &DirectUploadAdmission,
    placement_id: WireInteger,
    number: u32,
) -> Result<Option<PartRecord>> {
    let Reply::Parts { mut parts } = storage::call(
        env,
        admission,
        Operation::PartPage {
            placement_id,
            after: number
                .checked_sub(1)
                .ok_or_else(|| anyhow::anyhow!("direct part zero invalid"))?,
            maximum: 1,
        },
    )
    .await?
    else {
        anyhow::bail!("direct part journal differs");
    };
    Ok(parts.pop().filter(|part| part.part.part_number == number))
}

/// Retains the positive provider closure and exact original stage identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AbortPlacementReceipt {
    /// Acknowledged abort of the original multipart upload.
    Multipart {
        /// Required original placement.
        placement_id: WireInteger,
        /// Actual upload identifier returned by the original creation.
        upload_id: String,
        /// Positive provider acknowledgement of the abort.
        provider_closed: bool,
    },
    /// Acknowledged deletion of the exact empty object incarnation.
    EmptyObject {
        /// Required original placement.
        placement_id: WireInteger,
        /// Positive receipt of the original empty object creation.
        original: managed::ObjectReceipt,
        /// Positive provider acknowledgement of the exact deletion.
        provider_closed: bool,
    },
}

pub(super) async fn abort_one(
    env: &Env,
    qualified: &QualifiedConfig,
    admission: &DirectUploadAdmission,
    abort: &DirectAbortRequest,
    context: &DirectRequestContext,
) -> Result<DirectAbortEvidence> {
    current(qualified, context, admission)?;
    storage::call(
        env,
        admission,
        Operation::RetainAbort {
            abort: abort.clone(),
        },
    )
    .await?;
    let mut receipts = Vec::new();
    for placement in &admission.placements {
        qualified.protected(env, placement).await?;
        let created = created(env, admission, placement.placement_id).await?;
        let operation_id = verification::step_id(
            admission,
            placement.placement_id,
            &abort.operation_id,
            "abort-stage",
        )?;
        current(qualified, context, admission)?;
        let receipt = storage::effect(
            env,
            admission,
            operation_id.clone(),
            &(admission, abort, placement.placement_id),
            false,
            || async {
                current(qualified, context, admission)?;
                match created {
                    CreatedStage::Managed { receipt } => {
                        let key = direct_staging_key(&admission.session_id, placement)?;
                        match (receipt.upload_id, receipt.empty) {
                            (Some(upload_id), None) => {
                                managed::abort_checked(env, &key, &upload_id, || {
                                    current(qualified, context, admission)
                                })
                                .await?;
                                Ok(AbortPlacementReceipt::Multipart {
                                    placement_id: placement.placement_id,
                                    upload_id,
                                    provider_closed: true,
                                })
                            }
                            (None, Some(original)) => {
                                ensure!(
                                    admission.intent.byte_size.get() == 0,
                                    "direct empty stage original size differs"
                                );
                                managed::abort_empty_checked(env, &key, &original, || {
                                    current(qualified, context, admission)
                                })
                                .await?;
                                Ok(AbortPlacementReceipt::EmptyObject {
                                    placement_id: placement.placement_id,
                                    original,
                                    provider_closed: true,
                                })
                            }
                            _ => anyhow::bail!("direct original create receipt differs"),
                        }
                    }
                    CreatedStage::External { result } => {
                        let ExternalStageOutcome::Created { upload_id } = result.outcome else {
                            anyhow::bail!("positively closed external stage cannot be aborted");
                        };
                        let work = crate::external_object::prepare_stage_request_with_cutoff(
                            env,
                            admission,
                            placement.placement_id,
                            operation_id,
                            ExternalStageOperation::AbortStage {
                                upload_id: upload_id.clone(),
                            },
                            context.foreground.expires_at,
                        )
                        .await?;
                        current(qualified, context, admission)?;
                        let result = crate::external_object::execute_stage(env, &work).await?;
                        ensure!(
                            matches!(result.outcome, ExternalStageOutcome::Aborted { .. }),
                            "direct external abort positive receipt absent"
                        );
                        Ok(AbortPlacementReceipt::Multipart {
                            placement_id: placement.placement_id,
                            upload_id,
                            provider_closed: true,
                        })
                    }
                }
            },
        )
        .await?;
        receipts.push(receipt);
    }
    Ok(DirectAbortEvidence {
        session: abort.session.clone(),
        operation_id: abort.operation_id.clone(),
        outcome: DirectAbortOutcome::Aborted,
        receipt_digest: Some(journal::digest(&receipts)?),
    })
}
