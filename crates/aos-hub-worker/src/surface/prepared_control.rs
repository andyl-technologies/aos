//! Executes exact prepared registry controls without returning companion packs.
//!
//! The signed plan binds the attached control's hash and size. The Worker reads
//! and verifies companion packs locally, then writes through the existing object
//! coordinator. Protected external bindings keep their existing legacy refusal.

use super::*;

pub(crate) async fn execute(
    env: &Env,
    plan: &StorageWorkPlan,
    control: &[u8],
) -> Result<StorageWorkResult> {
    aos_hub_core::storage_work::prepared_control::validate_body(&plan.operation, control)?;
    let deployment_id = env.var("HUB_DEPLOYMENT_ID")?.to_string();
    plan.validate(&deployment_id, aos_hub_core::clock::now_unix_secs())?;

    let (outcome, source_bytes) = if plan.binding_kind == "deployment_r2" {
        anyhow::ensure!(
            plan.binding_snapshot_revision.is_none() && plan.credential_references.is_empty(),
            "deployment R2 control requires its exact binding"
        );
        let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
        let fetcher = R2SurfaceFetch {
            #[cfg(feature = "do-e2e")]
            sdk_trace: None,
            contract: R2Contract::new(WorkerR2BucketAdapter {
                bucket: bucket.as_ref().clone(),
            }),
            bucket,
            prefix: plan.placement_prefix.clone(),
        };
        let (outcome, source_bytes) = validate_control(&fetcher, plan, control).await?;
        plan.validate(&deployment_id, aos_hub_core::clock::now_unix_secs())?;
        if let StorageWorkOperation::PutPreparedControl { path, .. } = &plan.operation {
            put_control(env, &plan.object_key(path)?, control).await?;
        }
        (outcome, source_bytes)
    } else {
        let publication = crate::hybrid_binding::resolve_for_plan(env, plan).await?;
        crate::external_object::deny_legacy(env, &publication.snapshot)?;
        let now = aos_hub_core::clock::now_unix_secs();
        publication.snapshot.authorizes(plan, &deployment_id, now)?;
        let fetcher = S3SurfaceFetch {
            surface: external_surface(&publication, plan, &deployment_id, "read", now)?,
            egress: Arc::new(WorkerEgressClient::direct()),
        };
        let (outcome, source_bytes) = validate_control(&fetcher, plan, control).await?;
        let now = aos_hub_core::clock::now_unix_secs();
        publication.snapshot.authorizes(plan, &deployment_id, now)?;
        if let StorageWorkOperation::PutPreparedControl { path, .. } = &plan.operation {
            let writer = S3Write {
                surface: external_surface(&publication, plan, &deployment_id, "write", now)?,
                egress: Arc::new(WorkerEgressClient::direct()),
            };
            writer.write(path, control).await?;
        }
        (outcome, source_bytes)
    };
    Ok(storage_work_result(plan, outcome, source_bytes))
}

/// Stages larger prepared bundles in bounded parts while preserving the same
/// physical-key completion fence. This does not expand ordinary upload grants.
async fn put_control(env: &Env, key: &str, bytes: &[u8]) -> Result<()> {
    let chunk_bytes = aos_hub_core::hybrid_ingress::MAX_HYBRID_OCI_CHUNK_BYTES;
    if bytes.len() <= chunk_bytes {
        return crate::hybrid_object::put(env, key, bytes).await;
    }
    anyhow::ensure!(
        bytes.len() <= aos_hub_core::storage_work::prepared_control::MAX_CONTROL_BYTES,
        "prepared control exceeds its staged representation limit"
    );
    let bucket = env.bucket(aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT)?;
    let upload_id = hybrid_r2_create_multipart(bucket.clone(), key).await?;
    let write = async {
        let mut parts = Vec::new();
        for (position, chunk) in bytes.chunks(chunk_bytes).enumerate() {
            let part_number = u32::try_from(position + 1)?;
            let etag =
                hybrid_r2_upload_part(bucket.clone(), key, &upload_id, part_number, chunk).await?;
            parts.push(PartTag { part_number, etag });
        }
        crate::hybrid_object::complete(env, key, &upload_id, &parts).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if write.is_err() {
        let _ = hybrid_r2_abort_multipart(bucket, key, &upload_id).await;
    }
    write
}

fn external_surface(
    publication: &StorageBindingPublication,
    plan: &StorageWorkPlan,
    deployment_id: &str,
    purpose: &str,
    now: i64,
) -> Result<S3Surface> {
    let credential = if publication.snapshot.access_mode == "private" {
        let selector = plan
            .credential_references
            .iter()
            .find(|selector| selector.purpose == purpose)
            .context("prepared control has no purpose credential")?;
        Some(publication.credential_text(selector, deployment_id, now)?)
    } else {
        None
    };
    S3Surface::from_snapshot(
        &publication.snapshot,
        deployment_id,
        &plan.placement_prefix,
        credential.as_ref().map(|value| value.as_str()),
        now,
    )
}

async fn validate_control(
    fetcher: &dyn SurfaceFetch,
    plan: &StorageWorkPlan,
    control: &[u8],
) -> Result<(StorageWorkOutcome, u64)> {
    let (path, sha256, size, expected_companion) = match &plan.operation {
        StorageWorkOperation::VerifyPreparedGitIndex {
            path,
            sha256,
            size,
            companion_sha256,
        } => (path, sha256, size, companion_sha256.as_deref()),
        StorageWorkOperation::PutPreparedControl { path, sha256, size } => {
            (path, sha256, size, None)
        }
        _ => anyhow::bail!("operation does not accept prepared controls"),
    };
    aos_hub_core::service::verify_registry_publication_object_bytes(
        path,
        i64::try_from(*size)?,
        sha256,
        control,
    )?;

    if path == "objects/aos-index-v1/all" {
        object_bundle::decode_aggregate(control)?;
    } else if let Some(shard) = path.strip_prefix("objects/aos-index-v1/") {
        object_bundle::decode(shard, control)?;
    }

    let mut source_bytes = 0;
    let mut companion_sha256 = String::new();
    if let Some(companion) = aos_registry_surface::pack_index::companion_pack_path(path) {
        let pack = fetcher
            .fetch_bounded(
                &companion,
                aos_registry_surface::pack_index::MAX_PUBLISHED_PACK_BYTES as usize,
            )
            .await?
            .context("prepared pack index companion is absent")?;
        source_bytes = pack.len() as u64;
        companion_sha256 = hex::encode(Sha256::digest(&pack));
        anyhow::ensure!(
            expected_companion.is_none_or(|expected| expected == companion_sha256),
            "prepared pack index companion changed from the frozen inventory"
        );
        aos_registry_surface::pack_index::validate_against_pack(path, control, &pack)?;
    }
    let outcome = match plan.operation {
        StorageWorkOperation::VerifyPreparedGitIndex { .. } => {
            StorageWorkOutcome::PreparedGitIndexVerified {
                companion_sha256,
                companion_size: source_bytes,
            }
        }
        StorageWorkOperation::PutPreparedControl { .. } => StorageWorkOutcome::MetadataWritten,
        _ => anyhow::bail!("operation does not accept prepared controls"),
    };
    Ok((outcome, source_bytes))
}
