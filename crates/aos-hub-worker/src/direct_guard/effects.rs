//! Durable provider attempts, positive receipt recovery and managed publication.
//!
//! Every mutation attempt is retained before actual dispatch. Recovery consumes
//! only exact positive acknowledgements; unknown attempts have no expiry path.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use serde::{de::DeserializeOwned, Serialize};
use worker::{Env, Storage};

use super::{
    runtime::{check_originals, final_key, placement_evidence, read, write},
    state::Reservation,
    transport::{Reply, Turn, OWNER},
};
use crate::direct_upload::{
    config::QualifiedConfig,
    journal::{self, Effect},
    managed, storage as original,
    verification::{self, ClosedStage, VerifiedPlacement},
};

pub(super) async fn recover_publication(
    env: &Env,
    storage: &Storage,
    turn: &Turn,
    selected: &DirectSelectedCompleteCommitment,
) -> Result<Option<DirectFinalGuardRecord>> {
    let Some(owner) = read::<Reservation>(storage, OWNER).await? else {
        return Ok(None);
    };
    check_originals(&owner, turn, selected)?;
    if owner.final_record.is_some() {
        return Ok(owner.final_record);
    }
    let placement = original::placement(&turn.admission, turn.placement_id)?;
    let step = if owner.source.byte_size.get() == 0 {
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
    let (final_incarnation, final_etag) = match placement.physical {
        DirectPhysicalContext::DeploymentR2 { .. } => {
            let Some(effect) =
                read::<Effect>(storage, &format!("direct-guard/effect/v1/{operation_id}")).await?
            else {
                return Ok(None);
            };
            ensure!(
                effect.operation_id == operation_id && !effect.immutable_read,
                "direct final retained effect identity differs"
            );
            let Some(terminal) = effect.terminal else {
                return Ok(None);
            };
            ensure!(
                effect.pending_attempt.is_none(),
                "direct final retained effect remains unknown"
            );
            let expected_intent = if owner.source.byte_size.get() == 0 {
                journal::digest(&(&owner.binding, &owner.source))?
            } else {
                recovered_close_intent(env, storage, turn, &owner).await?
            };
            ensure!(
                effect.intent_digest == expected_intent,
                "direct recovered final original provider intent differs"
            );
            let acknowledged: managed::ObjectReceipt = if owner.source.byte_size.get() == 0 {
                let created: managed::CreateReceipt = serde_json::from_value(terminal)?;
                created
                    .empty
                    .ok_or_else(|| anyhow::anyhow!("direct final acknowledged EmptyPut absent"))?
            } else {
                serde_json::from_value(terminal)?
            };
            ensure!(
                acknowledged.byte_size == owner.source.byte_size,
                "direct recovered final source size differs"
            );
            (
                DirectObjectIncarnation::ProviderVersion {
                    version: acknowledged.version,
                },
                acknowledged.etag,
            )
        }
        DirectPhysicalContext::External { .. } => {
            match crate::external_object::direct_final(
                env,
                storage,
                &turn.admission,
                turn.placement_id,
                &operation_id,
            )
            .await
            {
                Ok(acknowledged) => acknowledged,
                Err(_) => return Ok(None),
            }
        }
    };
    let record = DirectFinalGuardRecord {
        version: 1,
        reservation: owner.binding.clone(),
        selected: owner.selected.clone(),
        sha256: owner.source.sha256.clone(),
        byte_size: owner.source.byte_size,
        source_incarnation: owner.source.incarnation.clone(),
        final_incarnation,
        final_etag,
    };
    let next = owner.acknowledge_publication(record.clone())?;
    write(
        storage,
        &final_key(&owner.binding.reservation_operation_id),
        &record,
    )
    .await?;
    write(storage, OWNER, &next).await?;
    recover_known_pending(storage).await?;
    Ok(Some(record))
}

async fn recovered_close_intent(
    env: &Env,
    storage: &Storage,
    turn: &Turn,
    owner: &Reservation,
) -> Result<String> {
    let create_id = verification::step_id(
        &turn.admission,
        turn.placement_id,
        &turn.complete.operation_id,
        "final-create",
    )?;
    let created: managed::CreateReceipt = positive_receipt(
        storage,
        &Effect::new(create_id, &(&owner.binding, &owner.source), false)?,
    )
    .await?;
    ensure!(
        created.empty.is_none(),
        "direct recovered multipart Create changed"
    );
    let upload_id = created
        .upload_id
        .ok_or_else(|| anyhow::anyhow!("direct recovered original destination UploadId absent"))?;
    let originals = verification::load_parts(
        env,
        &turn.admission,
        turn.placement_id,
        Some(&owner.selected.manifest),
    )
    .await?;
    let mut copied = Vec::with_capacity(originals.len());
    for original in originals {
        let operation_id = verification::step_id(
            &turn.admission,
            turn.placement_id,
            &turn.complete.operation_id,
            &format!("final-copy:{}", original.part.part_number),
        )?;
        let part: DirectManifestPart = positive_receipt(
            storage,
            &Effect::new(
                operation_id,
                &(&owner.binding, &owner.source, &upload_id, &original.part),
                false,
            )?,
        )
        .await?;
        ensure!(
            part.part == original.part,
            "direct recovered original part changed"
        );
        copied.push(part);
    }
    journal::digest(&(&owner.binding, &owner.source, &upload_id, &copied))
}

async fn positive_receipt<T: DeserializeOwned>(storage: &Storage, expected: &Effect) -> Result<T> {
    let retained: Effect = read(
        storage,
        &format!("direct-guard/effect/v1/{}", expected.operation_id),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("direct recovered original provider receipt absent"))?;
    ensure!(
        retained.operation_id == expected.operation_id
            && retained.intent_digest == expected.intent_digest
            && retained.immutable_read == expected.immutable_read
            && retained.pending_attempt.is_none(),
        "direct recovered original provider effect unknown or changed"
    );
    Ok(serde_json::from_value(retained.terminal.ok_or_else(
        || anyhow::anyhow!("direct recovered positive provider acknowledgement absent"),
    )?)?)
}

pub(super) async fn managed_promote(
    env: &Env,
    storage: &Storage,
    turn: &Turn,
    owner: Reservation,
    source: VerifiedPlacement,
    qualified: &QualifiedConfig,
    permission: &DirectDestinationBaselinePermission,
) -> Result<Reply> {
    let placement = original::placement(&turn.admission, turn.placement_id)?;
    ensure!(
        matches!(
            placement.physical,
            DirectPhysicalContext::DeploymentR2 { .. }
        ),
        "direct managed producer physical profile differs"
    );
    let ClosedStage::Managed { object: closed } = &source.closed else {
        anyhow::bail!("direct managed positive source closure absent");
    };
    let source_key = direct_staging_key(&turn.admission.session_id, placement)?;
    let parts = verification::load_parts(
        env,
        &turn.admission,
        turn.placement_id,
        Some(&owner.selected.manifest),
    )
    .await?;
    managed::verify(env, &source_key, closed, &turn.admission.intent, &parts).await?;

    let operation = |step: &str| {
        verification::step_id(
            &turn.admission,
            turn.placement_id,
            &turn.complete.operation_id,
            step,
        )
    };
    let created: managed::CreateReceipt = effect(
        storage,
        operation("final-create")?,
        &(&owner.binding, &owner.source),
        || async {
            dispatch_time(qualified, turn, permission)?;
            managed::create_checked(
                env,
                &placement.final_key,
                turn.admission.intent.byte_size.get() == 0,
                || dispatch_time(qualified, turn, permission),
            )
            .await
        },
    )
    .await?;
    let final_object = if let Some(object) = created.empty {
        object
    } else {
        let upload_id = created
            .upload_id
            .ok_or_else(|| anyhow::anyhow!("direct final original upload absent"))?;
        let mut copied = Vec::with_capacity(parts.len());
        for original_part in &parts {
            let part = &original_part.part;
            let receipt: DirectManifestPart = effect(
                storage,
                operation(&format!("final-copy:{}", part.part_number))?,
                &(&owner.binding, &owner.source, &upload_id, part),
                || async {
                    dispatch_time(qualified, turn, permission)?;
                    managed::copy_part_checked(
                        env,
                        &source_key,
                        closed,
                        &placement.final_key,
                        &upload_id,
                        &turn.admission.intent,
                        part,
                        || dispatch_time(qualified, turn, permission),
                    )
                    .await
                },
            )
            .await?;
            ensure!(
                receipt.part == *part,
                "direct final copy original descriptor differs"
            );
            copied.push(receipt);
        }
        effect(
            storage,
            operation("final-close")?,
            &(&owner.binding, &owner.source, &upload_id, &copied),
            || async {
                dispatch_time(qualified, turn, permission)?;
                managed::complete_checked(env, &placement.final_key, &upload_id, &copied, || {
                    dispatch_time(qualified, turn, permission)
                })
                .await
            },
        )
        .await?
    };
    ensure!(
        final_object.byte_size == owner.source.byte_size,
        "direct final positive acknowledgement size differs"
    );
    let record = DirectFinalGuardRecord {
        version: 1,
        reservation: owner.binding.clone(),
        selected: owner.selected.clone(),
        sha256: owner.source.sha256.clone(),
        byte_size: owner.source.byte_size,
        source_incarnation: owner.source.incarnation.clone(),
        final_incarnation: DirectObjectIncarnation::ProviderVersion {
            version: final_object.version,
        },
        final_etag: final_object.etag,
    };
    let next = owner.acknowledge_publication(record.clone())?;
    // The terminal effect is already retained. A crash before either write can
    // reconstruct only this exact acknowledged incarnation, without another PUT.
    write(
        storage,
        &final_key(&owner.binding.reservation_operation_id),
        &record,
    )
    .await?;
    write(storage, OWNER, &next).await?;
    Ok(Reply::Final {
        evidence: placement_evidence(placement, &record),
        record,
    })
}

fn dispatch_time(
    qualified: &QualifiedConfig,
    turn: &Turn,
    permission: &DirectDestinationBaselinePermission,
) -> Result<()> {
    let now = qualified.latest_now()?;
    turn.context.validate(
        &turn.context.deployment_id,
        &turn.context.executor_public_origin,
        now,
    )?;
    ensure!(
        now < turn.admission.expires_at.get() && now < permission.expires_at.get(),
        "direct final dispatch authorization expired"
    );
    Ok(())
}

pub(super) async fn effect<T, F, Fut>(
    storage: &Storage,
    operation_id: String,
    intent: &impl Serialize,
    dispatch: F,
) -> Result<T>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let expected = Effect::new(operation_id.clone(), intent, false)?;
    let key = format!("direct-guard/effect/v1/{operation_id}");
    let current: Effect = read(storage, &key)
        .await?
        .unwrap_or_else(|| expected.clone());
    let nonce = journal::digest(&uuid::Uuid::new_v4().to_string())?;
    let (pending, terminal) = current.begin(&expected, &nonce)?;
    if let Some(terminal) = terminal {
        recover_known_pending(storage).await?;
        return serde_json::from_value(terminal)
            .map_err(|_| anyhow::anyhow!("direct guard positive receipt malformed"));
    }
    ensure!(
        read::<Effect>(storage, "direct-guard/pending/v1")
            .await?
            .is_none(),
        "direct guard prior provider effect remains unknown"
    );
    write(
        storage,
        &format!("direct-guard/attempt/v1/{operation_id}/{nonce}"),
        &pending,
    )
    .await?;
    write(storage, &key, &pending).await?;
    write(storage, "direct-guard/pending/v1", &pending).await?;
    let result = dispatch().await?;
    write(
        storage,
        &key,
        &pending.finish(&nonce, serde_json::to_value(&result)?)?,
    )
    .await?;
    storage.delete("direct-guard/pending/v1").await?;
    Ok(result)
}

pub(super) async fn recover_known_pending(storage: &Storage) -> Result<()> {
    let Some(pending) = read::<Effect>(storage, "direct-guard/pending/v1").await? else {
        return Ok(());
    };
    let terminal: Option<Effect> = read(
        storage,
        &format!("direct-guard/effect/v1/{}", pending.operation_id),
    )
    .await?;
    if terminal.as_ref().is_some_and(|closed| {
        closed.operation_id == pending.operation_id
            && closed.intent_digest == pending.intent_digest
            && closed.immutable_read == pending.immutable_read
            && closed.pending_attempt.is_none()
            && closed.terminal.is_some()
    }) {
        storage.delete("direct-guard/pending/v1").await?;
    }
    Ok(())
}
