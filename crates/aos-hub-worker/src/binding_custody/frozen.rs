//! Exact archival delete material for frozen metadata and conditional cleanup.

use super::{
    runtime::{credential_key, read, write, Outcome},
    state::HeldCredential,
};
use anyhow::{ensure, Result};
use aos_hub_core::storage_work::{
    binding_custody::*, StorageBindingPublication, StorageCredentialMaterial,
    StorageCredentialSelector, StorageFrozenCleanupHeadResult, StorageFrozenCleanupOperation,
    StorageWorkKey, StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{Env, Fetch, Method, Request, RequestInit, RequestRedirect, Storage};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryMaterial {
    pub(super) request: StorageFrozenCleanupCustodyRequest,
    pub(super) material: Option<StorageCredentialMaterial>,
    pub(super) material_not_after: i64,
    pub(super) revoked: bool,
}

pub(super) async fn handle(
    path: &str,
    body: &[u8],
    signature: &str,
    env: &Env,
    storage: &Storage,
    binding_id: i64,
) -> Result<Outcome> {
    let key = StorageWorkKey::new(env.secret("HUB_STORAGE_WORK_KEY")?.to_string())?;
    let deployment = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    let now = aos_hub_core::clock::now_unix_secs();
    if path == STORAGE_FROZEN_CLEANUP_CREDENTIAL_STAGE_PATH {
        let stage = verify_storage_frozen_cleanup_credential_stage(
            &key,
            signature,
            body,
            &deployment,
            now,
        )?;
        ensure!(
            stage.request.snapshot.binding_id == binding_id,
            "frozen custody address differs"
        );
        fence(storage, &stage.request).await?;
        let original_key = credential_key(
            &stage.request.snapshot,
            &stage.request.snapshot.credentials[0],
        )?;
        refuse_revoked(storage, &original_key).await?;
        if let Some(held) = read::<HeldCredential>(storage, &original_key).await? {
            ensure!(
                !held.revoked,
                "frozen retained credential explicitly revoked"
            );
        }
        let record_key = recovery_key(&stage.request)?;
        if let Some(mut old) = read::<RecoveryMaterial>(storage, &record_key).await? {
            if now >= old.material_not_after {
                old.material = None;
                write(storage, &record_key, &old).await?;
            }
            ensure!(
                !old.revoked
                    && old.request.claim_fingerprint()? == stage.request.claim_fingerprint()?,
                "frozen recovery original changed"
            );
        }
        let reply = StorageFrozenCleanupCredentialStageReply {
            request: stage.request.clone(),
            material_not_after: stage.material_not_after,
            stage_body_sha256: hex::encode(Sha256::digest(body)),
        };
        write(
            storage,
            &record_key,
            &RecoveryMaterial {
                request: stage.request.clone(),
                material: Some(stage.material),
                material_not_after: stage.material_not_after,
                revoked: false,
            },
        )
        .await?;
        stage
            .request
            .validate(&deployment, aos_hub_core::clock::now_unix_secs())?;
        return Ok(Outcome::Reply(
            sign_storage_frozen_cleanup_credential_stage_reply(&key, &reply)?,
        ));
    }

    let deletion = if path == STORAGE_FROZEN_DELETE_CUSTODY_PATH {
        Some(verify_storage_frozen_delete_custody(
            &key,
            signature,
            body,
            &deployment,
            now,
        )?)
    } else {
        None
    };
    let challenge = match &deletion {
        Some(request) => request.claim.clone(),
        None => verify_storage_frozen_cleanup_custody(&key, signature, body, &deployment, now)?,
    };
    ensure!(
        challenge.snapshot.binding_id == binding_id
            && challenge.operation
                == if deletion.is_some() {
                    StorageFrozenCleanupOperation::DeleteIfMatches
                } else {
                    StorageFrozenCleanupOperation::Head
                },
        "frozen custody address or operation differs"
    );
    fence(storage, &challenge).await?;
    if let Some(request) = &deletion {
        // Positive historical receipt lookup precedes material retention and
        // renewal. A held unknown original never receives another permit.
        let plan = delete_plan(request)?;
        let publication = StorageBindingPublication {
            snapshot: challenge.snapshot.clone(),
            materials: Vec::new(),
        };
        if let Some(result) =
            crate::external_object::lookup_delete_plan(env, &plan, &publication).await?
        {
            return delete_reply(storage, &key, request, result.outcome).await;
        }
    } else {
        crate::external_object::check_cleanup_ready(env, &challenge).await?;
    }
    let record_key = credential_key(&challenge.snapshot, &challenge.snapshot.credentials[0])?;
    refuse_revoked(storage, &record_key).await?;
    let material = if let Some(mut held) = read::<HeldCredential>(storage, &record_key).await? {
        if held.expire(now) {
            write(storage, &record_key, &held).await?;
        }
        ensure!(
            !held.revoked,
            "frozen retained credential explicitly revoked"
        );
        held.material.take()
    } else {
        None
    };
    let material = match material {
        Some(material) => material,
        None => {
            let recovery_key = recovery_key(&challenge)?;
            let mut recovery: RecoveryMaterial = read(storage, &recovery_key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("frozen exact retained material absent"))?;
            if now >= recovery.material_not_after {
                recovery.material = None;
                write(storage, &recovery_key, &recovery).await?;
            }
            ensure!(
                !recovery.revoked
                    && recovery.request.claim_fingerprint()? == challenge.claim_fingerprint()?,
                "frozen recovery original changed or revoked"
            );
            recovery
                .material
                .take()
                .ok_or_else(|| anyhow::anyhow!("frozen recovery material expired"))?
        }
    };
    let physical = challenge.with_material(material, now)?;
    if let Some(request) = &deletion {
        let plan = delete_plan(request)?;
        let result =
            crate::external_object::execute_delete_plan(env, &plan, &physical.publication).await?;
        return delete_reply(storage, &key, request, result.outcome).await;
    }
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&physical)?);
    let signature = key.sign_frozen_cleanup_body(&encoded)?;
    let grant = crate::hybrid_frozen_cleanup::FrozenCleanupHead::authorize(
        &key,
        &signature,
        &encoded,
        &deployment,
        now,
    )?;
    aos_hub_core::url_guard::is_safe_remote_url(grant.signed_url())?;
    let mut init = RequestInit::new();
    init.with_method(Method::Head)
        .with_redirect(RequestRedirect::Manual);
    let request = Request::new_with_init(grant.signed_url(), &init)?;
    // The existing binding gate retains exact archival material throughout I/O.
    // Fresh claim expiry is checked after all awaited preparation and before Fetch.
    challenge.validate(&deployment, aos_hub_core::clock::now_unix_secs())?;
    crate::direct_upload::provider_capacity::record_dispatch();
    let response = Fetch::Request(request).send().await?;
    let length = response.headers().get("content-length")?;
    let etag = response.headers().get("etag")?;
    let result: StorageFrozenCleanupHeadResult = serde_json::from_slice(&grant.result(
        response.status_code(),
        length.as_deref(),
        etag.as_deref(),
    )?)?;
    let observed_at = aos_hub_core::clock::now_unix_secs();
    challenge.validate(&deployment, observed_at)?;
    write(storage, "credential-custody/clock/v1", &observed_at).await?;
    Ok(Outcome::Reply(sign_storage_frozen_cleanup_custody_reply(
        &key,
        &StorageFrozenCleanupCustodyReply {
            request: challenge,
            result,
            observed_at,
        },
    )?))
}

fn delete_plan(request: &StorageFrozenDeleteCustodyRequest) -> Result<StorageWorkPlan> {
    let claim = &request.claim;
    let snapshot = &claim.snapshot;
    let plan = StorageWorkPlan {
        version: 1,
        plan_id: claim.request_id.clone(),
        deployment_id: snapshot.deployment_id.clone(),
        issued_at: claim.issued_at,
        expires_at: claim.expires_at,
        placement_id: claim.access.placement_id,
        placement_resource_version: claim.access.placement_resource_version,
        binding_id: snapshot.binding_id,
        binding_resource_version: snapshot.binding_resource_version,
        binding_kind: snapshot.binding_kind.clone(),
        binding_snapshot_revision: Some(snapshot.revision()?),
        credential_references: vec![StorageCredentialSelector {
            purpose: "delete".into(),
            generation: claim.access.delete_credential_generation,
        }],
        placement_prefix: claim.access.placement_prefix.clone(),
        operation: StorageWorkOperation::DeleteIfMatches {
            path: claim.path.clone(),
            claim_id: claim.action_id.clone(),
            expected_etag: claim
                .expected_etag
                .clone()
                .ok_or_else(|| anyhow::anyhow!("frozen delete ETag absent"))?,
            expected_size: claim.expected_size,
            expected_hash: Some(claim.expected_hash.to_string()),
            expected_provider_version: Some(request.expected_provider_version.clone()),
            delete_binding_write_revision: Some(claim.access.binding_write_revision),
        },
    };
    plan.validate(
        &snapshot.deployment_id,
        aos_hub_core::clock::now_unix_secs(),
    )?;
    Ok(plan)
}

async fn delete_reply(
    storage: &Storage,
    key: &StorageWorkKey,
    request: &StorageFrozenDeleteCustodyRequest,
    outcome: StorageWorkOutcome,
) -> Result<Outcome> {
    use aos_hub_core::storage_authority::external_object::ExternalObjectOutcome;
    let outcome = match outcome {
        StorageWorkOutcome::ObjectDeleted { etag } => ExternalObjectOutcome::DeleteAcknowledged {
            provider_version: request.expected_provider_version.clone(),
            etag,
        },
        StorageWorkOutcome::NotFound => ExternalObjectOutcome::DeleteAbsent,
        StorageWorkOutcome::DeletePreconditionFailed => {
            ExternalObjectOutcome::DeletePreconditionFailed
        }
        _ => anyhow::bail!("frozen delete returned another effect"),
    };
    let observed_at = aos_hub_core::clock::now_unix_secs();
    request.validate(&request.claim.snapshot.deployment_id, observed_at)?;
    write(storage, "credential-custody/clock/v1", &observed_at).await?;
    Ok(Outcome::Reply(sign_storage_frozen_delete_custody_reply(
        key,
        &StorageFrozenDeleteCustodyReply {
            request: request.clone(),
            outcome,
            observed_at,
        },
    )?))
}

async fn fence(storage: &Storage, request: &StorageFrozenCleanupCustodyRequest) -> Result<()> {
    let key = format!(
        "credential-custody/frozen-action/v1/{}",
        hex::encode(Sha256::digest(&request.action_id))
    );
    let fingerprint = request.claim_fingerprint()?;
    if let Some(original) = read::<String>(storage, &key).await? {
        ensure!(original == fingerprint, "frozen action original changed");
    } else {
        write(storage, &key, &fingerprint).await?;
    }
    Ok(())
}

fn recovery_key(request: &StorageFrozenCleanupCustodyRequest) -> Result<String> {
    Ok(format!(
        "credential-custody/frozen-material/v1/{}",
        request.claim_fingerprint()?
    ))
}

async fn refuse_revoked(storage: &Storage, original_key: &str) -> Result<()> {
    ensure!(
        !read::<bool>(
            storage,
            &format!(
                "credential-custody/revoked/v1/{}",
                hex::encode(Sha256::digest(original_key))
            )
        )
        .await?
        .unwrap_or(false),
        "frozen retained credential explicitly revoked"
    );
    Ok(())
}
