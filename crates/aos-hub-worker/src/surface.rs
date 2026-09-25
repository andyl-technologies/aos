//! The R2-backed [`SurfaceProvider`] for the shared service (wasm32-only).
//!
//! The shared [`RpcService`](aos_hub_core::service::RpcService) reads a
//! registry/cache wire surface (loose git objects, `info/refs`, channel
//! partitions, NARs, …) through the [`SurfaceProvider`]/[`SurfaceFetch`] ports
//! ([`aos_hub_core::fetch`]). On the Cloudflare Worker a topology placement maps
//! its binding plus prefix to either the hub-owned R2 bucket or an external
//! S3-compatible store. R2 reads map `{prefix}{path}` via the
//! [`crate::keymap::r2_key`] mapping. The shared
//! machine-surface facade
//! ([`aos_hub_core::service::RpcService::registry_serve`] and
//! [`aos_hub_core::service::RpcService::cache_serve`]) and the RPC `GitService`
//! reads all use this provider, so runtime adapters cannot drift.
//!
//! The R2 bucket handle is not `Send`/`Sync`, but on the single-threaded Worker
//! the core ports drop those bounds (the wasm32 `BackendBounds` is unbounded),
//! so an `Rc`-free owned [`worker::Bucket`] satisfies the trait directly.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use worker::Bucket;

use aos_hub_core::db::{BindingWriteRevisionRecord, Database, SurfacePlacementRecord};
use aos_hub_core::fetch::{
    DocumentationInspection, OriginFetch, StreamedRead, SurfaceFetch, SurfaceListPage,
    SurfaceListedEvidence, SurfaceObjectEvidence, SurfaceProvider,
};
use aos_hub_core::hybrid_ingress::HybridDeliveryTarget;
use aos_hub_core::s3surface::{Method as S3Method, S3Surface};
use aos_hub_core::secret_version::SecretVersionResolver;
use aos_hub_core::storage_credential::{
    DatabaseStorageCredentialResolver, StorageCredentialResolver,
};
use aos_hub_core::storage_work::{
    StorageDocumentationPage, StorageGitObjectProjection, StorageObjectIdentity,
    StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan, StorageWorkResult,
    MAX_GIT_INSPECTION_CONTENT_BYTES, MAX_METADATA_BYTES, MAX_OCI_HASH_RANGE_BYTES,
    MAX_OCI_RANGE_BYTES,
};
use aos_hub_core::surface_write::{
    FrozenSurfaceAccess, MultipartAbortOutcome, PartTag, SurfaceWrite, SurfaceWriteProvider,
};
use aos_registry_surface::{object, object_bundle};

use crate::consoleports::WorkerEgressClient;
use crate::frozen_surface_access::{
    binding as frozen_access_binding, delete_credential as frozen_delete_credential,
};
use crate::keymap;
use crate::r2_adapter::{R2BucketAdapter, R2Contract, R2HeadObject, R2ListObject, R2ListPage};

#[derive(Clone)]
struct WorkerR2BucketAdapter {
    /// Raw JavaScript R2 binding. Keeping reflection behind this exact value
    /// makes the production adapter executable against a JS-shape fixture.
    bucket: wasm_bindgen::JsValue,
}

/// Executes a signed, validated storage plan against the deployment R2 bucket.
///
/// The Worker reads object bodies locally for verification and returns only
/// bounded identity or digest evidence to Native. This function has no SQL
/// access and cannot select a placement outside the signed plan.
///
/// # Errors
///
/// Returns an error for an unavailable object store, a source limit, or an
/// object identity that fails the plan's digest check.
pub(crate) async fn execute_r2_storage_work(
    bucket: Bucket,
    plan: &StorageWorkPlan,
) -> Result<StorageWorkResult> {
    let fetcher = R2SurfaceFetch {
        contract: R2Contract::new(WorkerR2BucketAdapter {
            bucket: bucket.as_ref().clone(),
        }),
        bucket,
        prefix: plan.placement_prefix.clone(),
    };
    let (outcome, source_bytes) = match &plan.operation {
        StorageWorkOperation::Head { path } => {
            let key = plan.object_key(path)?;
            let outcome = match fetcher.contract.head(&key).await? {
                Some(head) => StorageWorkOutcome::Head {
                    object: storage_object_identity(key, head),
                },
                None => StorageWorkOutcome::NotFound,
            };
            (outcome, 0)
        }
        StorageWorkOperation::ListPage {
            prefix,
            cursor,
            limit,
        } => {
            let key_prefix = plan.object_key(prefix)?;
            let page = fetcher
                .contract
                .list(&key_prefix, cursor.as_deref(), *limit)
                .await?;
            anyhow::ensure!(
                page.objects
                    .iter()
                    .all(|object| object.key.starts_with(&key_prefix)),
                "R2 listing escaped the selected placement prefix"
            );
            let objects = page
                .objects
                .into_iter()
                .map(|object| StorageObjectIdentity {
                    key: object.key,
                    size: object.size,
                    etag: object.etag,
                })
                .collect();
            (
                StorageWorkOutcome::ListPage {
                    objects,
                    cursor: page.cursor,
                },
                0,
            )
        }
        StorageWorkOperation::InspectSha256 {
            path,
            expected_sha256,
            max_source_bytes,
        } => {
            let key = plan.object_key(path)?;
            let Some(evidence) = fetcher
                .inventory_evidence_bounded(path, *max_source_bytes)
                .await?
            else {
                return Ok(storage_work_result(plan, StorageWorkOutcome::NotFound, 0));
            };
            let sha256 = hex::encode(evidence.sha256);
            if let Some(expected_sha256) = expected_sha256 {
                anyhow::ensure!(
                    sha256.eq_ignore_ascii_case(expected_sha256),
                    "R2 object SHA-256 does not match the plan"
                );
            }
            let size = u64::try_from(evidence.size).context("R2 object size is negative")?;
            let etag = evidence
                .strong_etag
                .context("R2 verification returned no strong ETag")?;
            (
                StorageWorkOutcome::Sha256Evidence {
                    object: StorageObjectIdentity { key, size, etag },
                    sha256,
                },
                size,
            )
        }
        StorageWorkOperation::InspectGitObject { oid } => {
            let (projection, source_bytes) = inspect_git_object(&fetcher, plan, oid).await?;
            let Some(projection) = projection else {
                return Ok(storage_work_result(
                    plan,
                    StorageWorkOutcome::NotFound,
                    source_bytes,
                ));
            };
            (
                StorageWorkOutcome::GitObject {
                    source: projection.source,
                    oid: projection.oid,
                    object_kind: projection.object_kind,
                    content_base64: projection.content_base64,
                },
                source_bytes,
            )
        }
        StorageWorkOperation::InspectGitObjects { oids } => {
            let mut shards = std::collections::BTreeMap::<&str, Vec<&str>>::new();
            for oid in oids {
                shards.entry(&oid[..2]).or_default().push(oid);
            }
            let inspections = futures_util::future::try_join_all(
                shards
                    .into_iter()
                    .map(|(shard, oids)| inspect_git_shard(&fetcher, plan, shard, oids)),
            )
            .await?;
            let mut objects = Vec::with_capacity(oids.len());
            let mut source_bytes = 0_u64;
            let mut missing = false;
            for (projections, observed_bytes) in inspections {
                source_bytes = source_bytes
                    .checked_add(observed_bytes)
                    .context("Git batch source byte count overflowed")?;
                for projection in projections {
                    match projection {
                        Some(projection) => objects.push(projection),
                        None => missing = true,
                    }
                }
            }
            if missing {
                return Ok(storage_work_result(
                    plan,
                    StorageWorkOutcome::NotFound,
                    source_bytes,
                ));
            }
            (StorageWorkOutcome::GitObjects { objects }, source_bytes)
        }
        StorageWorkOperation::InspectMetadata { path } => {
            let Some((bytes, source)) =
                read_bounded_source(&fetcher, plan, path, MAX_METADATA_BYTES).await?
            else {
                return Ok(storage_work_result(plan, StorageWorkOutcome::NotFound, 0));
            };
            let source_bytes = source.size;
            (
                StorageWorkOutcome::Metadata {
                    source,
                    content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
                },
                source_bytes,
            )
        }
        StorageWorkOperation::InspectDocumentation {
            package_name,
            package_version,
            platform,
            artifact,
            cursor,
        } => {
            let store_hash = aos_registry_surface::store::store_path_hash(&artifact.store_path)?;
            let narinfo_key = format!("{store_hash}.narinfo");
            let narinfo_size = fetcher
                .size(&narinfo_key)
                .await?
                .context("documentation narinfo disappeared before inspection")?;
            anyhow::ensure!(
                narinfo_size <= MAX_METADATA_BYTES as u64,
                "documentation narinfo exceeds the metadata limit"
            );
            let document = aos_hub_core::indexer::fetch_package_documentation(
                &fetcher,
                package_name,
                package_version,
                platform,
                artifact,
            )
            .await?;
            let source_bytes = narinfo_size
                .checked_add(artifact.nar_size)
                .context("documentation source byte count overflowed")?;
            let inspection = DocumentationInspection::from_document(&document);
            let page = StorageDocumentationPage::from_inspection(&inspection, *cursor)?;
            (StorageWorkOutcome::Documentation { page }, source_bytes)
        }
        StorageWorkOperation::InspectOciRange { path, start, end } => {
            use futures_util::TryStreamExt as _;

            let Some(read) = fetcher.fetch_stream(path, Some((*start, *end))).await? else {
                return Ok(storage_work_result(plan, StorageWorkOutcome::NotFound, 0));
            };
            anyhow::ensure!(
                read.range == Some((*start, *end)) && *end < read.total,
                "R2 returned a different OCI range"
            );
            let etag = read
                .strong_etag
                .context("R2 OCI range has no strong ETag")?;
            let expected = end - start + 1;
            let mut bytes = Vec::new();
            let mut stream = read.body.into_data_stream();
            while let Some(chunk) = stream.try_next().await? {
                let next = bytes
                    .len()
                    .checked_add(chunk.len())
                    .context("OCI range size overflow")?;
                anyhow::ensure!(
                    next <= MAX_OCI_RANGE_BYTES && next as u64 <= expected,
                    "OCI range exceeded its signed length"
                );
                bytes.extend_from_slice(&chunk);
            }
            anyhow::ensure!(
                bytes.len() as u64 == expected,
                "OCI range ended before its signed length"
            );
            (
                StorageWorkOutcome::OciRange {
                    source: StorageObjectIdentity {
                        key: plan.object_key(path)?,
                        size: read.total,
                        etag,
                    },
                    start: *start,
                    end: *end,
                    content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
                },
                expected,
            )
        }
        StorageWorkOperation::HashOciRange {
            path,
            start,
            end,
            total,
            strong_etag,
            sha256_state,
        } => {
            let requested_bytes = end - start + 1;
            let Some(chunk) = fetcher
                .inventory_chunk_bounded(path, *start, *total, requested_bytes)
                .await?
            else {
                return Ok(storage_work_result(plan, StorageWorkOutcome::NotFound, 0));
            };
            anyhow::ensure!(
                chunk.total == *total
                    && chunk.range == (*start, *end)
                    && chunk.strong_etag == strong_etag.as_str()
                    && chunk.bytes.len() as u64 == requested_bytes
                    && chunk.bytes.len() <= MAX_OCI_HASH_RANGE_BYTES,
                "R2 OCI inventory range changed identity or length"
            );
            let mut next_state = sha256_state.clone();
            next_state.update(&chunk.bytes)?;
            (
                StorageWorkOutcome::OciRangeHashed {
                    source: StorageObjectIdentity {
                        key: plan.object_key(path)?,
                        size: chunk.total,
                        etag: chunk.strong_etag,
                    },
                    start: *start,
                    end: *end,
                    sha256_state: next_state,
                },
                requested_bytes,
            )
        }
        StorageWorkOperation::CopyObject {
            source_prefix,
            path,
            expected_size,
            expected_etag,
            ..
        } => {
            let source_key = keymap::r2_key(source_prefix, path);
            let destination_key = plan.object_key(path)?;
            let source = fetcher
                .contract
                .head(&source_key)
                .await?
                .context("placement copy source disappeared")?;
            anyhow::ensure!(
                source.size == *expected_size && source.etag == expected_etag.as_str(),
                "placement copy source differs from its listed identity"
            );
            r2_copy_stream(
                fetcher.bucket.as_ref(),
                &source_key,
                &destination_key,
                *expected_size,
                expected_etag,
            )
            .await?;
            let after = fetcher
                .contract
                .head(&source_key)
                .await?
                .context("placement copy source disappeared after streaming")?;
            let destination = fetcher
                .contract
                .head(&destination_key)
                .await?
                .context("placement copy destination disappeared")?;
            anyhow::ensure!(
                after.size == *expected_size
                    && after.etag == expected_etag.as_str()
                    && destination.size == *expected_size,
                "placement copy source or destination changed during streaming"
            );
            (
                StorageWorkOutcome::ObjectCopied {
                    source: storage_object_identity(source_key, source),
                    destination: storage_object_identity(destination_key, destination),
                },
                *expected_size,
            )
        }
        StorageWorkOperation::ComposeOciBlob {
            path,
            staging_prefix,
            chunks,
            expected_size,
            expected_sha256,
        } => {
            let object_key = plan.object_key(path)?;
            let object = compose_oci_blob(
                &fetcher.contract,
                &object_key,
                staging_prefix,
                chunks,
                *expected_size,
                expected_sha256,
            )
            .await?;
            (
                StorageWorkOutcome::OciBlobComposed {
                    object,
                    sha256: expected_sha256.clone(),
                },
                *expected_size,
            )
        }
        StorageWorkOperation::DeleteOciStaging { path } => {
            let object_key = plan.object_key(path)?;
            fetcher.contract.delete(&object_key).await?;
            (StorageWorkOutcome::OciStagingDeleted, 0)
        }
        StorageWorkOperation::CreateMultipart { path } => {
            let object_key = plan.object_key(path)?;
            let upload_id = fetcher.contract.create_multipart(&object_key).await?;
            (StorageWorkOutcome::MultipartCreated { upload_id }, 0)
        }
        StorageWorkOperation::CompleteMultipart {
            path,
            upload_id,
            parts,
        } => {
            let object_key = plan.object_key(path)?;
            fetcher
                .contract
                .complete_multipart(&object_key, upload_id, parts)
                .await?;
            let head = fetcher
                .contract
                .head(&object_key)
                .await?
                .context("completed multipart object is missing")?;
            (
                StorageWorkOutcome::MultipartCompleted {
                    object: StorageObjectIdentity {
                        key: object_key,
                        size: head.size,
                        etag: head.etag,
                    },
                },
                0,
            )
        }
        StorageWorkOperation::AbortMultipart { path, upload_id } => {
            let object_key = plan.object_key(path)?;
            let outcome = fetcher
                .contract
                .abort_multipart(&object_key, upload_id)
                .await?;
            (StorageWorkOutcome::MultipartAborted { outcome }, 0)
        }
    };
    Ok(storage_work_result(plan, outcome, source_bytes))
}

async fn compose_oci_blob(
    contract: &R2Contract<WorkerR2BucketAdapter>,
    object_key: &str,
    staging_prefix: &str,
    chunks: &[aos_hub_core::storage_work::StorageOciChunkSource],
    expected_size: u64,
    expected_sha256: &str,
) -> Result<StorageObjectIdentity> {
    const PART_BYTES: usize = 8 * 1024 * 1024;

    if expected_size == 0 {
        anyhow::ensure!(
            expected_sha256 == hex::encode(Sha256::digest(b"")),
            "empty OCI blob digest differs from its signed plan"
        );
        contract.put(object_key, &[]).await?;
    } else {
        let upload_id = contract.create_multipart(object_key).await?;
        let materialized = async {
            let mut parts = Vec::new();
            let mut pending = Vec::new();
            let mut hasher = Sha256::new();
            let mut observed_size = 0_u64;

            for chunk in chunks {
                let staging_key = aos_hub_core::keymap::r2_key(staging_prefix, &chunk.path);
                let bytes = contract
                    .read_bounded(
                        &staging_key,
                        aos_hub_core::hybrid_ingress::MAX_HYBRID_OCI_CHUNK_BYTES,
                    )
                    .await?
                    .context("staged OCI chunk is missing")?;
                anyhow::ensure!(
                    bytes.len() as u64 == chunk.size
                        && hex::encode(Sha256::digest(&bytes)) == chunk.sha256,
                    "staged OCI chunk differs from the SQL-frozen digest and length"
                );
                observed_size = observed_size
                    .checked_add(chunk.size)
                    .context("OCI composition size overflowed")?;
                hasher.update(&bytes);
                pending.extend_from_slice(&bytes);

                while pending.len() >= PART_BYTES {
                    let remaining = pending.split_off(PART_BYTES);
                    let part_number = u32::try_from(parts.len() + 1)?;
                    parts.push(
                        contract
                            .upload_part(object_key, &upload_id, part_number, &pending)
                            .await?,
                    );
                    pending = remaining;
                }
            }
            anyhow::ensure!(
                observed_size == expected_size && hex::encode(hasher.finalize()) == expected_sha256,
                "assembled OCI blob differs from the claimed digest and length"
            );
            if !pending.is_empty() {
                let part_number = u32::try_from(parts.len() + 1)?;
                parts.push(
                    contract
                        .upload_part(object_key, &upload_id, part_number, &pending)
                        .await?,
                );
            }
            contract
                .complete_multipart(object_key, &upload_id, &parts)
                .await
        }
        .await;
        if materialized.is_err() {
            let _ = contract.abort_multipart(object_key, &upload_id).await;
        }
        materialized?;
    }

    let head = contract
        .head(object_key)
        .await?
        .context("materialized OCI blob is missing")?;
    anyhow::ensure!(
        head.size == expected_size,
        "materialized OCI blob has the wrong length"
    );
    Ok(StorageObjectIdentity {
        key: object_key.to_string(),
        size: head.size,
        etag: head.etag,
    })
}

async fn inspect_git_object(
    fetcher: &R2SurfaceFetch,
    plan: &StorageWorkPlan,
    oid: &str,
) -> Result<(Option<StorageGitObjectProjection>, u64)> {
    let oid_value = object::Oid::from_hex(oid)?;
    let shard = &oid[..2];
    let shard_path = object_bundle::shard_path(shard)?;
    let bundled =
        read_bounded_source(fetcher, plan, &shard_path, object_bundle::MAX_BUNDLE_BYTES).await?;
    let bundle_bytes = bundled.as_ref().map_or(0, |(_, source)| source.size);
    let selected = bundled.as_ref().and_then(|(bytes, _)| {
        match object_bundle::decode(shard, bytes) {
            Ok(entries) => entries.into_iter().find(|(entry, _)| *entry == oid_value),
            Err(error) => {
                tracing::warn!(%shard_path, error = %format!("{error:#}"), "ignoring invalid Git bundle shard");
                None
            }
        }
    });
    let (loose, source) = match selected {
        Some((_, loose)) => {
            let source = bundled
                .as_ref()
                .map(|(_, source)| source.clone())
                .context("selected Git bundle source disappeared")?;
            (loose, source)
        }
        None => {
            let path = oid_value.loose_path();
            let Some((loose, source)) = read_bounded_source(
                fetcher,
                plan,
                &path,
                object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES as usize,
            )
            .await?
            else {
                return Ok((None, bundle_bytes));
            };
            (loose, source)
        }
    };
    let source_bytes = if source.key == plan.object_key(&shard_path)? {
        bundle_bytes
    } else {
        bundle_bytes
            .checked_add(source.size)
            .context("Git inspection source byte count overflowed")?
    };
    Ok((Some(project_git_loose(oid, &loose, source)?), source_bytes))
}

async fn inspect_git_shard(
    fetcher: &R2SurfaceFetch,
    plan: &StorageWorkPlan,
    shard: &str,
    oids: Vec<&str>,
) -> Result<(Vec<Option<StorageGitObjectProjection>>, u64)> {
    let shard_path = object_bundle::shard_path(shard)?;
    let bundled =
        read_bounded_source(fetcher, plan, &shard_path, object_bundle::MAX_BUNDLE_BYTES).await?;
    let bundle_bytes = bundled.as_ref().map_or(0, |(_, source)| source.size);
    let entries = match bundled.as_ref() {
        Some((bytes, _)) => match object_bundle::decode(shard, bytes) {
            Ok(entries) => entries
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>(),
            Err(error) => {
                tracing::warn!(%shard_path, error = %format!("{error:#}"), "ignoring invalid Git bundle shard");
                std::collections::BTreeMap::new()
            }
        },
        None => std::collections::BTreeMap::new(),
    };
    let inspections = futures_util::future::try_join_all(oids.into_iter().map(|oid| async {
        let oid_value = object::Oid::from_hex(oid)?;
        if let (Some(loose), Some((_, source))) = (entries.get(&oid_value), bundled.as_ref()) {
            return Ok::<_, anyhow::Error>((
                Some(project_git_loose(oid, loose, source.clone())?),
                0_u64,
            ));
        }
        let path = oid_value.loose_path();
        let Some((loose, source)) = read_bounded_source(
            fetcher,
            plan,
            &path,
            object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES as usize,
        )
        .await?
        else {
            return Ok((None, 0));
        };
        let source_bytes = source.size;
        Ok((Some(project_git_loose(oid, &loose, source)?), source_bytes))
    }))
    .await?;
    let mut projections = Vec::with_capacity(inspections.len());
    let mut source_bytes = bundle_bytes;
    for (projection, loose_bytes) in inspections {
        projections.push(projection);
        source_bytes = source_bytes
            .checked_add(loose_bytes)
            .context("Git shard source byte count overflowed")?;
    }
    Ok((projections, source_bytes))
}

fn project_git_loose(
    oid: &str,
    loose: &[u8],
    source: StorageObjectIdentity,
) -> Result<StorageGitObjectProjection> {
    let oid_value = object::Oid::from_hex(oid)?;
    let (kind, content) = object::decode_loose(loose, Some(oid_value))?;
    anyhow::ensure!(
        content.len() <= MAX_GIT_INSPECTION_CONTENT_BYTES,
        "Git object projection exceeds the semantic response limit"
    );
    Ok(StorageGitObjectProjection {
        source,
        oid: oid.to_owned(),
        object_kind: kind.as_str().into(),
        content_base64: base64::engine::general_purpose::STANDARD.encode(content),
    })
}

async fn read_bounded_source(
    fetcher: &R2SurfaceFetch,
    plan: &StorageWorkPlan,
    path: &str,
    maximum: usize,
) -> Result<Option<(Vec<u8>, StorageObjectIdentity)>> {
    use futures_util::TryStreamExt as _;

    let Some(read) = fetcher.fetch_stream(path, None).await? else {
        return Ok(None);
    };
    anyhow::ensure!(
        read.total <= maximum as u64,
        "storage source exceeds its byte limit"
    );
    let etag = read
        .strong_etag
        .context("storage source has no strong R2 ETag")?;
    let expected = read.total;
    let mut bytes = Vec::new();
    let mut stream = read.body.into_data_stream();
    while let Some(chunk) = stream.try_next().await? {
        let next = bytes
            .len()
            .checked_add(chunk.len())
            .context("storage source size overflow")?;
        anyhow::ensure!(
            next <= maximum && next as u64 <= expected,
            "storage source exceeded its declared size"
        );
        bytes.extend_from_slice(&chunk);
    }
    anyhow::ensure!(
        bytes.len() as u64 == expected,
        "storage source ended before its declared size"
    );
    let source = StorageObjectIdentity {
        key: plan.object_key(path)?,
        size: expected,
        etag,
    };
    Ok(Some((bytes, source)))
}

fn storage_object_identity(key: String, head: R2HeadObject) -> StorageObjectIdentity {
    StorageObjectIdentity {
        key,
        size: head.size,
        etag: head.etag,
    }
}

fn storage_work_result(
    plan: &StorageWorkPlan,
    outcome: StorageWorkOutcome,
    source_bytes: u64,
) -> StorageWorkResult {
    StorageWorkResult {
        plan_id: plan.plan_id.clone(),
        placement_id: plan.placement_id,
        placement_resource_version: plan.placement_resource_version,
        binding_id: plan.binding_id,
        binding_resource_version: plan.binding_resource_version,
        source_bytes,
        outcome,
    }
}

#[async_trait(?Send)]
impl R2BucketAdapter for WorkerR2BucketAdapter {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        use js_sys::{Function, Promise, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let bucket = &self.bucket;
        let put: Function = Reflect::get(bucket, &JsValue::from_str("put"))
            .map_err(|e| anyhow::anyhow!("R2 put {key}: method: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 put {key}: not a function: {e:?}"))?;
        let bytes = Uint8Array::from(bytes);
        let promise: Promise = put
            .call2(bucket, &JsValue::from_str(key), bytes.as_ref())
            .map_err(|e| anyhow::anyhow!("R2 put {key}: call: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 put {key}: not a promise: {e:?}"))?;
        JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 put {key}: {e:?}"))?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let promise = js_promise(
            js_method(&self.bucket, "delete")?.call1(&self.bucket, &JsValue::from_str(key)),
            key,
            "delete",
        )?;
        JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 delete {key}: {e:?}"))?;
        Ok(())
    }

    async fn list(&self, prefix: &str, cursor: Option<&str>, limit: usize) -> Result<R2ListPage> {
        use js_sys::{Array, Function, Object, Promise, Reflect};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let bucket = &self.bucket;
        let list: Function = Reflect::get(bucket, &JsValue::from_str("list"))
            .map_err(|e| anyhow::anyhow!("R2 list: method: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 list: not a function: {e:?}"))?;
        let options = Object::new();
        Reflect::set(
            &options,
            &JsValue::from_str("prefix"),
            &JsValue::from_str(prefix),
        )
        .map_err(|e| anyhow::anyhow!("R2 list: prefix: {e:?}"))?;
        Reflect::set(
            &options,
            &JsValue::from_str("limit"),
            &JsValue::from_f64(limit as f64),
        )
        .map_err(|e| anyhow::anyhow!("R2 list: limit: {e:?}"))?;
        if let Some(cursor) = cursor {
            Reflect::set(
                &options,
                &JsValue::from_str("cursor"),
                &JsValue::from_str(cursor),
            )
            .map_err(|e| anyhow::anyhow!("R2 list: cursor: {e:?}"))?;
        }
        let promise: Promise = list
            .call1(bucket, &options)
            .map_err(|e| anyhow::anyhow!("R2 list: call: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 list: not a promise: {e:?}"))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 list: {e:?}"))?;
        let objects: Array = Reflect::get(&result, &JsValue::from_str("objects"))
            .map_err(|e| anyhow::anyhow!("R2 list: objects: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 list: objects not an array: {e:?}"))?;
        let mut listed = Vec::with_capacity(objects.length() as usize);
        for object in objects.iter() {
            let key = Reflect::get(&object, &JsValue::from_str("key"))
                .map_err(|e| anyhow::anyhow!("R2 list: key: {e:?}"))?
                .as_string()
                .context("R2 list object has no string key")?;
            let size = Reflect::get(&object, &JsValue::from_str("size"))
                .map_err(|e| anyhow::anyhow!("R2 list {key}: size: {e:?}"))?
                .as_f64()
                .filter(|value| {
                    value.is_finite()
                        && *value >= 0.0
                        && value.fract() == 0.0
                        && *value <= ((1_u64 << 53) - 1) as f64
                })
                .context("R2 list object has an invalid size")? as u64;
            let etag = Reflect::get(&object, &JsValue::from_str("etag"))
                .map_err(|e| anyhow::anyhow!("R2 list {key}: etag: {e:?}"))?
                .as_string()
                .context("R2 list object has no string etag")?;
            let etag = aos_hub_core::surface_write::strong_if_match_etag(&etag)
                .with_context(|| format!("R2 list {key} returned an invalid strong ETag"))?;
            listed.push(R2ListObject { key, size, etag });
        }
        let truncated = Reflect::get(&result, &JsValue::from_str("truncated"))
            .ok()
            .map(|value| value.is_truthy())
            .unwrap_or(false);
        let cursor = if truncated {
            Some(
                Reflect::get(&result, &JsValue::from_str("cursor"))
                    .ok()
                    .and_then(|value| value.as_string())
                    .context("truncated R2 page has no cursor")?,
            )
        } else {
            None
        };
        Ok(R2ListPage {
            objects: listed,
            cursor,
        })
    }

    async fn head(&self, key: &str) -> Result<Option<R2HeadObject>> {
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let promise = js_promise(
            js_method(&self.bucket, "head")?.call1(&self.bucket, &JsValue::from_str(key)),
            key,
            "head",
        )?;
        let object = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 head {key}: {e:?}"))?;
        if object.is_null() || object.is_undefined() {
            return Ok(None);
        }
        let size = js_sys::Reflect::get(&object, &JsValue::from_str("size"))
            .map_err(|e| anyhow::anyhow!("R2 head {key}: size: {e:?}"))?
            .as_f64()
            .context("R2 HEAD object has no numeric size")?;
        anyhow::ensure!(
            size.is_finite() && size >= 0.0 && size < (u64::MAX as f64) && size.fract() == 0.0,
            "R2 HEAD object size is invalid"
        );
        let etag = js_sys::Reflect::get(&object, &JsValue::from_str("etag"))
            .map_err(|e| anyhow::anyhow!("R2 head {key}: etag: {e:?}"))?
            .as_string()
            .context("R2 HEAD object has no string etag")?;
        Ok(Some(R2HeadObject {
            size: size as u64,
            etag,
        }))
    }

    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>> {
        use js_sys::{Function, Promise, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let Some(object) = r2_get(&self.bucket, key).await? else {
            return Ok(None);
        };
        let read: Function = Reflect::get(&object, &JsValue::from_str("arrayBuffer"))
            .map_err(|e| anyhow::anyhow!("R2 read {key}: method: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 read {key}: not a function: {e:?}"))?;
        let promise: Promise = read
            .call0(&object)
            .map_err(|e| anyhow::anyhow!("R2 read {key}: call: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 read {key}: not a promise: {e:?}"))?;
        let buffer = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 read {key}: {e:?}"))?;
        Ok(Some(Uint8Array::new(&buffer).to_vec()))
    }

    async fn create_multipart(&self, key: &str) -> Result<String> {
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let bucket = &self.bucket;
        let promise = js_promise(
            js_method(bucket, "createMultipartUpload")?.call1(bucket, &JsValue::from_str(key)),
            key,
            "createMultipartUpload",
        )?;
        let upload = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 create {key}: {e:?}"))?;
        js_sys::Reflect::get(&upload, &JsValue::from_str("uploadId"))
            .ok()
            .and_then(|v| v.as_string())
            .context("R2 multipart create returned no upload id")
    }

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<String> {
        use js_sys::Uint8Array;
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let upload = resume_r2_multipart(&self.bucket, key, upload_id)?;
        let bytes = Uint8Array::from(bytes);
        let promise = js_promise(
            js_method(&upload, "uploadPart")?.call2(
                &upload,
                &JsValue::from(part_number),
                bytes.as_ref(),
            ),
            key,
            "uploadPart",
        )?;
        let part = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 part {key}: {e:?}"))?;
        js_sys::Reflect::get(&part, &JsValue::from_str("etag"))
            .ok()
            .and_then(|v| v.as_string())
            .context("R2 multipart part returned no ETag")
    }

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: &[PartTag],
    ) -> Result<String> {
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let upload = resume_r2_multipart(&self.bucket, key, upload_id)?;
        let array = js_sys::Array::new();
        for part in parts {
            let value = js_sys::Object::new();
            js_sys::Reflect::set(
                &value,
                &JsValue::from_str("partNumber"),
                &JsValue::from(part.part_number),
            )
            .map_err(|e| anyhow::anyhow!("R2 complete part: {e:?}"))?;
            js_sys::Reflect::set(
                &value,
                &JsValue::from_str("etag"),
                &JsValue::from_str(&part.etag),
            )
            .map_err(|e| anyhow::anyhow!("R2 complete ETag: {e:?}"))?;
            array.push(&value);
        }
        let promise = js_promise(
            js_method(&upload, "complete")?.call1(&upload, array.as_ref()),
            key,
            "complete",
        )?;
        let object = JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 complete {key}: {e:?}"))?;
        js_sys::Reflect::get(&object, &JsValue::from_str("etag"))
            .ok()
            .and_then(|value| value.as_string())
            .context("R2 multipart completion returned no ETag")
    }

    async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<()> {
        use wasm_bindgen_futures::JsFuture;
        let upload = resume_r2_multipart(&self.bucket, key, upload_id)?;
        let promise = js_promise(js_method(&upload, "abort")?.call0(&upload), key, "abort")?;
        JsFuture::from(promise)
            .await
            .map_err(|e| anyhow::anyhow!("R2 abort {key}: {e:?}"))?;
        Ok(())
    }
}

fn resume_r2_multipart(
    bucket: &wasm_bindgen::JsValue,
    key: &str,
    upload_id: &str,
) -> Result<wasm_bindgen::JsValue> {
    use wasm_bindgen::JsValue;
    js_method(bucket, "resumeMultipartUpload")?
        .call2(
            bucket,
            &JsValue::from_str(key),
            &JsValue::from_str(upload_id),
        )
        .map_err(|e| anyhow::anyhow!("R2 resumeMultipartUpload {key}: {e:?}"))
}

/// Resolves one explicit placement to an external object store.
///
/// The instance-default binding maps to the Worker's bound R2 bucket and thus
/// returns `None`; external S3/R2 bindings return a signed surface scoped to the
/// placement prefix.
async fn placement_s3_surface(
    db: &Database,
    credentials: &dyn StorageCredentialResolver,
    placement: &SurfacePlacementRecord,
    write_revision: Option<&BindingWriteRevisionRecord>,
) -> Result<Option<S3Surface>> {
    let binding = db.binding(placement.binding_id).await?.ok_or_else(|| {
        aos_hub_core::placement_read::terminal_read_error(format!(
            "placement '{}' references a missing binding",
            placement.name
        ))
    })?;
    if binding.is_instance_default {
        return Ok(None);
    }
    if !matches!(binding.kind.as_str(), "s3" | "r2") {
        return Err(aos_hub_core::placement_read::terminal_read_error(format!(
            "placement '{}' uses unsupported Worker storage kind '{}'",
            placement.name, binding.kind
        )));
    }
    let credential = if binding.access_mode.as_deref() == Some("private") {
        if let Some(revision) = write_revision {
            anyhow::ensure!(
                placement.binding_id == revision.binding_id,
                "placement does not match frozen binding revision"
            );
            Some(
                credentials
                    .resolve_exact(
                        binding.id,
                        &revision.write_credential_purpose,
                        revision.write_credential_generation,
                    )
                    .await?,
            )
        } else {
            Some(credentials.resolve_current(binding.id, "read").await?)
        }
    } else {
        None
    };
    S3Surface::from_binding(
        &binding,
        &placement.prefix,
        credential
            .as_ref()
            .map(|credential| credential.secret())
            .transpose()?,
    )
    .map_err(|error| {
        aos_hub_core::placement_read::terminal_read_error(format!(
            "placement '{}' has invalid object-store configuration: {error:#}",
            placement.name
        ))
    })
}

/// Resolves physical conditional-delete access without consulting write authority.
async fn placement_s3_delete_surface(
    db: &Database,
    credentials: &dyn StorageCredentialResolver,
    placement: &SurfacePlacementRecord,
    expected_binding_resource_version: i64,
    delete_credential_generation: i64,
) -> Result<S3Surface> {
    let binding = db
        .binding(placement.binding_id)
        .await?
        .context("deletion placement references a missing binding")?;
    if binding.resource_version != expected_binding_resource_version {
        anyhow::bail!(
            "placement '{}' binding changed after deletion was planned",
            placement.name
        );
    }
    if binding.is_instance_default || !matches!(binding.kind.as_str(), "s3" | "r2") {
        anyhow::bail!(
            "placement '{}' backend '{}' cannot enforce conditional deletion",
            placement.name,
            binding.kind
        );
    }
    let credential = credentials
        .resolve_exact(binding.id, "delete", delete_credential_generation)
        .await?;
    S3Surface::from_binding(&binding, &placement.prefix, Some(credential.secret()?))?
        .context("deletion placement object-store binding cannot be resolved")
}

/// Whether an R2 error message names a transient, retryable condition.
///
/// Cloudflare R2 surfaces error `10001` ("We encountered an internal error.
/// Please try again.") for transient server-side faults, which it explicitly
/// asks callers to retry. A missing object is not an error (it returns
/// `Ok(None)`), so this never matches a 404-equivalent.
fn is_transient_r2(message: &str) -> bool {
    message.contains("(10001)") || message.contains("Please try again")
}

/// Streams one R2 snapshot directly into another key in the same binding.
async fn r2_copy_stream(
    bucket: &wasm_bindgen::JsValue,
    source_key: &str,
    destination_key: &str,
    expected_size: u64,
    expected_etag: &str,
) -> Result<()> {
    use js_sys::{Function, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    // Multipart keeps large copies within R2's single-PUT limit and bounds the
    // amount of work in each storage request. The small-object path avoids the
    // extra round trips for the common case.
    if expected_size > 8 * 1024 * 1024 {
        return r2_copy_multipart(
            bucket,
            source_key,
            destination_key,
            expected_size,
            expected_etag,
        )
        .await;
    }

    let object = r2_get(bucket, source_key)
        .await?
        .context("placement copy source has no body snapshot")?;
    let size = Reflect::get(&object, &JsValue::from_str("size"))
        .ok()
        .and_then(|value| value.as_f64())
        .filter(|value| {
            value.is_finite()
                && *value >= 0.0
                && value.fract() == 0.0
                && *value <= ((1_u64 << 53) - 1) as f64
        })
        .context("placement copy source returned an invalid size")? as u64;
    let etag = Reflect::get(&object, &JsValue::from_str("etag"))
        .ok()
        .and_then(|value| value.as_string())
        .context("placement copy source returned no ETag")?;
    let etag = aos_hub_core::surface_write::strong_if_match_etag(&etag)?;
    anyhow::ensure!(
        size == expected_size && etag == expected_etag,
        "placement copy body snapshot differs from its listed identity"
    );
    let body = Reflect::get(&object, &JsValue::from_str("body"))
        .map_err(|error| anyhow::anyhow!("placement copy source body is unreadable: {error:?}"))?;
    anyhow::ensure!(
        expected_size == 0 || (!body.is_null() && !body.is_undefined()),
        "placement copy source has no stream"
    );
    let value = if expected_size == 0 {
        &JsValue::NULL
    } else {
        &body
    };
    let put: Function = Reflect::get(bucket, &JsValue::from_str("put"))
        .map_err(|error| anyhow::anyhow!("placement copy R2 put is unavailable: {error:?}"))?
        .dyn_into()
        .map_err(|error| anyhow::anyhow!("placement copy R2 put is invalid: {error:?}"))?;
    let promise: Promise = put
        .call2(bucket, &JsValue::from_str(destination_key), value)
        .map_err(|error| anyhow::anyhow!("placement copy R2 put failed: {error:?}"))?
        .dyn_into()
        .map_err(|error| anyhow::anyhow!("placement copy R2 put returned no promise: {error:?}"))?;
    let stored = JsFuture::from(promise)
        .await
        .map_err(|error| anyhow::anyhow!("placement copy R2 stream failed: {error:?}"))?;
    anyhow::ensure!(
        !stored.is_null() && !stored.is_undefined(),
        "placement copy R2 put did not store the destination"
    );
    Ok(())
}

/// Copies bounded R2 ranges into a multipart upload without materializing a part in WASM.
async fn r2_copy_multipart(
    bucket: &wasm_bindgen::JsValue,
    source_key: &str,
    destination_key: &str,
    expected_size: u64,
    expected_etag: &str,
) -> Result<()> {
    use wasm_bindgen::JsValue;

    const SMALL_PART_BYTES: u64 = 8 * 1024 * 1024;
    const LARGE_PART_BYTES: u64 = 64 * 1024 * 1024;
    const LARGE_COPY_THRESHOLD: u64 = 128 * 1024 * 1024;

    let adapter = WorkerR2BucketAdapter {
        bucket: bucket.clone(),
    };
    let upload_id = adapter.create_multipart(destination_key).await?;
    let part_bytes = if expected_size <= LARGE_COPY_THRESHOLD {
        SMALL_PART_BYTES
    } else {
        LARGE_PART_BYTES
    };

    let copy: Result<()> = async {
        let mut offset = 0_u64;
        let mut parts = Vec::new();
        while offset < expected_size {
            let length = (expected_size - offset).min(part_bytes);
            let object = r2_get_range(bucket, source_key, offset, length)
                .await?
                .context("placement copy source range disappeared")?;
            let etag = js_sys::Reflect::get(&object, &JsValue::from_str("etag"))
                .ok()
                .and_then(|value| value.as_string())
                .context("placement copy source range has no ETag")?;
            anyhow::ensure!(
                aos_hub_core::surface_write::strong_if_match_etag(&etag)? == expected_etag,
                "placement copy source changed between ranges"
            );

            let body = js_sys::Reflect::get(&object, &JsValue::from_str("body"))
                .map_err(|error| anyhow::anyhow!("placement copy range body: {error:?}"))?;
            anyhow::ensure!(
                !body.is_null() && !body.is_undefined(),
                "placement copy source range has no stream"
            );
            let part_number = u32::try_from(parts.len() + 1)
                .context("placement copy exceeds R2 multipart part limit")?;
            let upload = resume_r2_multipart(bucket, destination_key, &upload_id)?;
            let promise = js_promise(
                js_method(&upload, "uploadPart")?.call2(
                    &upload,
                    &JsValue::from(part_number),
                    &body,
                ),
                destination_key,
                "uploadPart",
            )?;
            let stored = wasm_bindgen_futures::JsFuture::from(promise)
                .await
                .map_err(|error| anyhow::anyhow!("R2 copy part {part_number}: {error:?}"))?;
            let etag = js_sys::Reflect::get(&stored, &JsValue::from_str("etag"))
                .ok()
                .and_then(|value| value.as_string())
                .context("R2 copy part returned no ETag")?;
            parts.push(PartTag { part_number, etag });
            offset += length;
        }
        adapter
            .complete_multipart(destination_key, &upload_id, &parts)
            .await?;
        Ok(())
    }
    .await;

    if copy.is_err() {
        // Incomplete uploads are otherwise retained by R2 for several days.
        let _ = adapter.abort_multipart(destination_key, &upload_id).await;
    }
    copy
}

/// Run an R2 `get`, retrying a few times on a transient R2 internal error
/// ([`is_transient_r2`]).
///
/// A missing object (`Ok(None)`) and a non-transient error return immediately;
/// only a transient `10001`-class fault is retried (up to three attempts total),
/// so a brief R2 hiccup does not, for example, mark a registry's index `failed`.
///
/// # Errors
///
/// Returns an error if a non-transient error occurs or every attempt fails (the
/// last error is reported, prefixed with the key).
async fn r2_get(
    bucket: &wasm_bindgen::JsValue,
    key: &str,
) -> Result<Option<wasm_bindgen::JsValue>> {
    // Call the R2 binding's `get` method directly with *only* the key, rather
    // than via worker-rs `Bucket::get(key).execute()`. The 0.8 `GetOptionsBuilder`
    // always serializes an options object whose `onlyIf`/`range` keys are present
    // and set to JS `undefined` even when unset (`js_object!` does an
    // unconditional `Reflect::set`), and the current workerd/R2 rejects those
    // present-but-`undefined` option keys by failing the GET with a *persistent*
    // `10001` "internal error" — the same class of 0.8 R2 option-serialization
    // bug worked around in [`R2SurfaceFetch::list_page`] (unset `cursor`) and the
    // ranged read in [`R2SurfaceFetch::fetch_stream`] (`suffix: undefined`).
    // Passing no options object at all avoids it; the returned value is the raw
    // R2 object (or `null`/`undefined` for a miss), read via `js_sys` since
    // worker-rs `Object` has no public constructor from a `JsValue`.
    use js_sys::{Function, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    let get_fn: Function = Reflect::get(bucket, &JsValue::from_str("get"))
        .map_err(|e| anyhow::anyhow!("R2 get {key}: get method: {e:?}"))?
        .dyn_into()
        .map_err(|e| anyhow::anyhow!("R2 get {key}: get is not a function: {e:?}"))?;
    let mut attempt = 0u32;
    loop {
        let promise: Promise = get_fn
            .call1(bucket, &JsValue::from_str(key))
            .map_err(|e| anyhow::anyhow!("R2 get {key}: call: {e:?}"))?
            .dyn_into()
            .map_err(|e| anyhow::anyhow!("R2 get {key}: get did not return a promise: {e:?}"))?;
        match JsFuture::from(promise).await {
            Ok(v) if v.is_null() || v.is_undefined() => return Ok(None),
            Ok(v) => return Ok(Some(v)),
            Err(e) if attempt < 2 && is_transient_r2(&format!("{e:?}")) => attempt += 1,
            Err(e) if is_transient_r2(&format!("{e:?}")) => {
                return Err(aos_hub_core::placement_read::retryable_read_error(format!(
                    "R2 get {key}: {e:?}"
                )));
            }
            Err(e) => {
                return Err(aos_hub_core::placement_read::terminal_read_error(format!(
                    "R2 get {key}: {e:?}"
                )));
            }
        }
    }
}

/// Run an R2 ranged `get` without worker-rs's invalid `suffix: undefined` field.
async fn r2_get_range(
    bucket: &wasm_bindgen::JsValue,
    key: &str,
    offset: u64,
    length: u64,
) -> Result<Option<wasm_bindgen::JsValue>> {
    use js_sys::{Function, Object, Promise, Reflect};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
    if offset > MAX_SAFE_INTEGER || length > MAX_SAFE_INTEGER {
        return Err(aos_hub_core::placement_read::terminal_read_error(format!(
            "R2 range for {key} exceeds JavaScript's exact integer range"
        )));
    }

    let range = Object::new();
    Reflect::set(
        &range,
        &JsValue::from_str("offset"),
        &JsValue::from_f64(offset as f64),
    )
    .map_err(|e| anyhow::anyhow!("R2 get {key}: range offset: {e:?}"))?;
    Reflect::set(
        &range,
        &JsValue::from_str("length"),
        &JsValue::from_f64(length as f64),
    )
    .map_err(|e| anyhow::anyhow!("R2 get {key}: range length: {e:?}"))?;
    let options = Object::new();
    Reflect::set(&options, &JsValue::from_str("range"), &range)
        .map_err(|e| anyhow::anyhow!("R2 get {key}: range options: {e:?}"))?;

    let get_fn: Function = Reflect::get(bucket, &JsValue::from_str("get"))
        .map_err(|e| anyhow::anyhow!("R2 get {key}: get method: {e:?}"))?
        .dyn_into()
        .map_err(|e| anyhow::anyhow!("R2 get {key}: get is not a function: {e:?}"))?;
    let mut attempt = 0u32;
    loop {
        let promise: Promise = get_fn
            .call2(bucket, &JsValue::from_str(key), &options)
            .map_err(|e| anyhow::anyhow!("R2 get {key}: ranged call: {e:?}"))?
            .dyn_into()
            .map_err(|e| {
                anyhow::anyhow!("R2 get {key}: ranged get did not return a promise: {e:?}")
            })?;
        match JsFuture::from(promise).await {
            Ok(v) if v.is_null() || v.is_undefined() => return Ok(None),
            Ok(v) => return Ok(Some(v)),
            Err(e) if attempt < 2 && is_transient_r2(&format!("{e:?}")) => attempt += 1,
            Err(e) if is_transient_r2(&format!("{e:?}")) => {
                return Err(aos_hub_core::placement_read::retryable_read_error(format!(
                    "R2 ranged get {key}: {e:?}"
                )));
            }
            Err(e) => {
                return Err(aos_hub_core::placement_read::terminal_read_error(format!(
                    "R2 ranged get {key}: {e:?}"
                )));
            }
        }
    }
}

/// Adapts an R2 object's raw `ReadableStream` body into Rust byte chunks.
///
/// The raw reflected object cannot be converted into worker-rs's private
/// `ObjectBody`, but its public [`worker::ByteStream`] accepts the same
/// `ReadableStream`. Reusing that adapter keeps stream locking, promise
/// polling, cancellation, and JavaScript exception handling aligned with the
/// Workers runtime instead of maintaining a second hand-written reader.
fn r2_body_stream(
    body: wasm_bindgen::JsValue,
) -> Result<impl futures_util::Stream<Item = std::result::Result<Vec<u8>, std::io::Error>>> {
    use futures_util::TryStreamExt as _;
    use wasm_bindgen::JsCast as _;

    let stream = body
        .dyn_into::<worker::web_sys::ReadableStream>()
        .map_err(|value| anyhow::anyhow!("R2 body is not a ReadableStream: {value:?}"))?;
    Ok(worker::ByteStream::from(stream)
        .map_err(|error| std::io::Error::other(format!("R2 body stream: {error}"))))
}

/// A [`SurfaceProvider`] that serves every registry from one R2 bucket, or from
/// an external S3/R2 origin when the resource names an `s3`/`r2` storage
/// binding.
///
/// Holds the hub-owned bucket binding plus the shared [`Database`] and
/// [`SecretVersionResolver`] needed to resolve a per-resource binding;
/// [`fetcher`](SurfaceProvider::fetcher) scopes a reader to the requested
/// registry's prefix — proxying to the external origin via signed URLs when the
/// binding is external ([`S3SurfaceFetch`]), else reading the hub R2 bucket
/// ([`R2SurfaceFetch`]).
pub struct R2SurfaceProvider {
    bucket: Bucket,
    db: Arc<Database>,
    credentials: Arc<dyn StorageCredentialResolver>,
    egress: Arc<WorkerEgressClient>,
}

impl R2SurfaceProvider {
    /// Wrap a bound R2 bucket (`env.bucket(binding)`) as a surface provider,
    /// with the HubDb [`Database`] and [`SecretVersionResolver`] used to resolve external
    /// S3/R2 bindings.
    #[must_use]
    pub fn new(
        bucket: Bucket,
        db: Arc<Database>,
        secrets: Arc<dyn SecretVersionResolver>,
        egress: Arc<WorkerEgressClient>,
    ) -> R2SurfaceProvider {
        let credentials = Arc::new(DatabaseStorageCredentialResolver::new(
            Arc::clone(&db),
            secrets,
        ));
        R2SurfaceProvider {
            bucket,
            db,
            credentials,
            egress,
        }
    }
}

#[async_trait(?Send)]
impl SurfaceProvider for R2SurfaceProvider {
    async fn placement_fetcher(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceFetch>> {
        if let Some(surface) =
            placement_s3_surface(&self.db, self.credentials.as_ref(), placement, None).await?
        {
            return Ok(Box::new(S3SurfaceFetch {
                surface,
                egress: Arc::clone(&self.egress),
            }));
        }
        Ok(Box::new(R2SurfaceFetch {
            bucket: self.bucket.clone(),
            contract: R2Contract::new(WorkerR2BucketAdapter {
                bucket: self.bucket.as_ref().clone(),
            }),
            prefix: placement.prefix.clone(),
        }))
    }

    async fn frozen_placement_fetcher(
        &self,
        access: &FrozenSurfaceAccess,
    ) -> Result<Box<dyn SurfaceFetch>> {
        let binding = frozen_access_binding(&self.db, access).await?;
        if binding.is_instance_default || binding.kind == "deployment_r2" {
            anyhow::bail!(
                "deployment R2 has no atomic conditional-delete capability for GC access"
            );
        }
        anyhow::ensure!(
            matches!(binding.kind.as_str(), "s3" | "r2"),
            "frozen placement uses unsupported Worker storage"
        );
        let credential = frozen_delete_credential(self.credentials.as_ref(), access).await?;
        let surface = S3Surface::from_binding(
            &binding,
            &access.placement_prefix,
            credential
                .as_ref()
                .map(|credential| credential.secret())
                .transpose()?,
        )?
        .context("frozen placement object-store binding cannot be resolved")?;
        Ok(Box::new(S3SurfaceFetch {
            surface,
            egress: Arc::clone(&self.egress),
        }))
    }
}

/// A [`SurfaceFetch`] reading one registry's prefix from an R2 bucket.
struct R2SurfaceFetch {
    bucket: Bucket,
    contract: R2Contract<WorkerR2BucketAdapter>,
    prefix: String,
}

/// Opens the exact R2 snapshot admitted by the Native hybrid origin.
///
/// # Errors
///
/// Returns an error if the object disappeared, changed version, or R2 failed.
pub(crate) async fn hybrid_delivery_read(
    bucket: Bucket,
    target: &HybridDeliveryTarget,
    range: Option<(u64, u64)>,
) -> Result<StreamedRead> {
    let fetcher = R2SurfaceFetch {
        contract: R2Contract::new(WorkerR2BucketAdapter {
            bucket: bucket.as_ref().clone(),
        }),
        bucket,
        prefix: String::new(),
    };
    let read = fetcher
        .fetch_stream(&target.object_key, range)
        .await?
        .context("authorized R2 delivery object disappeared")?;
    anyhow::ensure!(
        read.total == target.object_size
            && read.strong_etag.as_deref() == Some(target.object_etag.as_str()),
        "authorized R2 delivery object changed after Native admission"
    );
    Ok(read)
}

/// Confirms a bodyless HEAD against the exact Native-authorized R2 snapshot.
///
/// # Errors
///
/// Returns an error if the object disappeared, changed version, or R2 failed.
pub(crate) async fn hybrid_delivery_head(
    bucket: Bucket,
    target: &HybridDeliveryTarget,
) -> Result<()> {
    let contract = R2Contract::new(WorkerR2BucketAdapter {
        bucket: bucket.as_ref().clone(),
    });
    let head = contract
        .head(&target.object_key)
        .await?
        .context("authorized R2 delivery object disappeared")?;
    anyhow::ensure!(
        head.size == target.object_size && head.etag == target.object_etag,
        "authorized R2 delivery object changed after Native admission"
    );
    Ok(())
}

/// Writes one Native-admitted cache body beside the deployment R2 bucket.
///
/// # Errors
///
/// Returns an error if R2 does not acknowledge the exact object write.
pub(crate) async fn hybrid_r2_put(bucket: Bucket, object_key: &str, bytes: &[u8]) -> Result<()> {
    let contract = R2Contract::new(WorkerR2BucketAdapter {
        bucket: bucket.as_ref().clone(),
    });
    contract.put(object_key, bytes).await
}

/// Writes one SQL-admitted multipart part directly into deployment R2.
///
/// # Errors
///
/// Returns an error if the provider rejects the upload identity or part body.
pub(crate) async fn hybrid_r2_upload_part(
    bucket: Bucket,
    object_key: &str,
    upload_id: &str,
    part_number: u32,
    bytes: &[u8],
) -> Result<String> {
    let contract = R2Contract::new(WorkerR2BucketAdapter {
        bucket: bucket.as_ref().clone(),
    });
    Ok(contract
        .upload_part(object_key, upload_id, part_number, bytes)
        .await?
        .etag)
}

/// Reads a Git pack beside R2 for semantic pack-index validation.
///
/// # Errors
///
/// Returns an error when the companion is absent, oversized, or unreadable.
pub(crate) async fn hybrid_publication_companion_pack(
    bucket: Bucket,
    object_key: &str,
) -> Result<Vec<u8>> {
    let contract = R2Contract::new(WorkerR2BucketAdapter {
        bucket: bucket.as_ref().clone(),
    });
    contract
        .read_bounded(
            object_key,
            aos_registry_surface::pack_index::MAX_PUBLISHED_PACK_BYTES as usize,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("publication companion pack is absent"))
}

#[async_trait(?Send)]
impl SurfaceFetch for R2SurfaceFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let key = keymap::r2_key(&self.prefix, path);
        self.contract
            .read_bounded(
                &key,
                usize::try_from(aos_hub_core::s3surface::MAX_S3_BUFFERED_OBJECT_BYTES)
                    .context("R2 buffered-object cap exceeds usize")?,
            )
            .await
    }

    async fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<SurfaceListPage> {
        anyhow::ensure!(
            limit > 0 && limit <= aos_hub_core::fetch::WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS,
            "invalid R2 listing page limit"
        );
        let listing_prefix = keymap::r2_key(&self.prefix, "");
        let page = self.contract.list(&listing_prefix, cursor, limit).await?;
        let mut entries = Vec::with_capacity(page.objects.len());
        for object in page.objects {
            if let Some(rel) = keymap::relative_key(&self.prefix, &object.key) {
                if !rel.is_empty() {
                    entries.push((
                        rel,
                        SurfaceListedEvidence {
                            size: i64::try_from(object.size)
                                .context("R2 listed object size exceeds i64")?,
                            strong_etag: object.etag,
                        },
                    ));
                }
            }
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        anyhow::ensure!(
            !entries.windows(2).any(|pair| pair[0].0 == pair[1].0),
            "R2 listing returned a duplicate relative key"
        );
        let paths = entries.iter().map(|(path, _)| path.clone()).collect();
        let evidence = entries.into_iter().collect();
        Ok(SurfaceListPage {
            paths,
            evidence,
            next_cursor: page.cursor,
        })
    }

    async fn inventory_evidence_bounded(
        &self,
        path: &str,
        maximum_bytes: u64,
    ) -> Result<Option<SurfaceObjectEvidence>> {
        use futures_util::TryStreamExt as _;

        // R2 binds the body, size, and ETag to one GET object snapshot. Hashing
        // that body is stronger and cheaper than issuing separate GETs before
        // and after it, whose bodies would be discarded merely to read ETags.
        let Some(read) = self.fetch_stream(path, None).await? else {
            return Ok(None);
        };
        let expected_size = read.total;
        anyhow::ensure!(
            expected_size <= maximum_bytes,
            "R2 object '{path}' declares {expected_size} bytes, exceeding the {maximum_bytes}-byte inventory limit"
        );
        let strong_etag = read.strong_etag;
        let mut stream = read.body.into_data_stream();
        let mut hasher = Sha256::new();
        let mut observed_size = 0_u64;
        while let Some(chunk) = stream.try_next().await? {
            observed_size = observed_size
                .checked_add(chunk.len() as u64)
                .with_context(|| format!("R2 object '{path}' size overflowed"))?;
            anyhow::ensure!(
                observed_size <= expected_size && observed_size <= maximum_bytes,
                "R2 object '{path}' exceeded its bounded inventory length while streaming"
            );
            hasher.update(&chunk);
        }
        anyhow::ensure!(
            observed_size == expected_size,
            "R2 object '{path}' snapshot declared {expected_size} bytes but streamed {observed_size}"
        );

        Ok(Some(SurfaceObjectEvidence {
            sha256: hasher.finalize().into(),
            size: i64::try_from(observed_size).context("R2 object size exceeds i64")?,
            strong_etag,
        }))
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        let key = keymap::r2_key(&self.prefix, path);
        Ok(self.contract.head(&key).await?.map(|object| object.etag))
    }

    async fn inventory_size(&self, path: &str) -> Result<Option<i64>> {
        let key = keymap::r2_key(&self.prefix, path);
        self.contract
            .head(&key)
            .await?
            .map(|object| i64::try_from(object.size).context("R2 object size exceeds i64"))
            .transpose()
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<aos_hub_core::fetch::StreamedRead>> {
        use futures_util::StreamExt as _;

        let key = keymap::r2_key(&self.prefix, path);
        // Construct range options through raw JS so absent fields are genuinely
        // absent: worker-rs 0.8.5 emits an invalid `suffix: undefined` alongside
        // offset/length. R2 returns the full object size on the same GET object,
        // keeping range metadata and the body on one object snapshot.
        let object = match range {
            Some((start, end)) if start <= end => {
                let length = end
                    .checked_sub(start)
                    .and_then(|span| span.checked_add(1))
                    .ok_or_else(|| {
                        aos_hub_core::placement_read::terminal_read_error(format!(
                            "R2 range length for {key} overflows u64"
                        ))
                    })?;
                r2_get_range(self.bucket.as_ref(), &key, start, length).await?
            }
            None => r2_get(self.bucket.as_ref(), &key).await?,
            Some(_) => r2_get(self.bucket.as_ref(), &key).await?,
        };
        let Some(object) = object else {
            return Ok(None);
        };
        let total_value = js_sys::Reflect::get(&object, &wasm_bindgen::JsValue::from_str("size"))
            .ok()
            .and_then(|value| value.as_f64())
            .filter(|value| {
                value.is_finite()
                    && *value >= 0.0
                    && value.fract() == 0.0
                    && *value <= ((1_u64 << 53) - 1) as f64
            })
            .ok_or_else(|| {
                aos_hub_core::placement_read::terminal_read_error(format!(
                    "R2 get {key} returned an invalid object size"
                ))
            })?;
        let total = total_value as u64;
        let served = match range {
            Some((start, end)) if start < total => Some((start, end.min(total.saturating_sub(1)))),
            _ => None,
        };
        let strong_etag = js_sys::Reflect::get(&object, &wasm_bindgen::JsValue::from_str("etag"))
            .ok()
            .and_then(|value| value.as_string())
            .map(|value| value.trim().to_string())
            .filter(|value| aos_hub_core::surface_write::strong_if_match_etag(value).is_ok());
        let body_js = js_sys::Reflect::get(&object, &wasm_bindgen::JsValue::from_str("body"))
            .unwrap_or(wasm_bindgen::JsValue::UNDEFINED);
        if body_js.is_null() || body_js.is_undefined() {
            // A bodyless R2 object is zero-length, so there is nothing to range
            // over — serve a whole-object empty body (`range: None`) regardless of
            // what was requested, so `cache_serve` emits `Content-Length: 0`
            // rather than a positive length against an empty body.
            return Ok(Some(aos_hub_core::fetch::StreamedRead {
                body: axum::body::Body::empty(),
                total,
                range: None,
                strong_etag,
                snapshot_lease_id: None,
            }));
        }
        let stream = r2_body_stream(body_js)?;
        // Bound a ranged R2 body to the exact requested length. The R2 read
        // already starts at `start`, so no leading bytes are discarded.
        let (skip, remaining) = match served {
            Some((start, end)) => (0, end - start + 1),
            None => (0, u64::MAX),
        };
        let trimmed = futures_util::stream::try_unfold(
            (stream.boxed_local(), skip, remaining),
            |(mut stream, mut skip, mut remaining)| async move {
                if remaining == 0 {
                    return Ok(None);
                }
                loop {
                    match stream.next().await {
                        None => return Ok(None),
                        Some(Err(err)) => return Err(err),
                        Some(Ok(mut chunk)) => {
                            if skip > 0 {
                                // `skip as usize` is sound on wasm32 (32-bit
                                // usize) because `.min(chunk.len())` bounds it
                                // below `usize::MAX` before the cast.
                                let drop = (skip as usize).min(chunk.len());
                                chunk.drain(..drop);
                                skip -= drop as u64;
                                if chunk.is_empty() {
                                    continue;
                                }
                            }
                            // Compare/clamp in `u64`: `remaining` can exceed
                            // `u32::MAX` for a multi-GiB range, so `remaining as
                            // usize` on wasm32 would truncate the high bits and
                            // wrongly truncate the chunk. `chunk.len()` fits a
                            // u32, so the *bounded* `take` casts back safely.
                            let take = remaining.min(chunk.len() as u64) as usize;
                            chunk.truncate(take);
                            remaining -= take as u64;
                            return Ok(Some((chunk, (stream, skip, remaining))));
                        }
                    }
                }
            },
        );
        // `axum::body::Body::from_stream` requires `Send`; the R2 `ByteStream` is
        // `!Send`. `SendWrapper` makes it `Send` (sound on the single-threaded
        // Worker), so the *same* `StreamedRead` the native file path returns
        // flows through the shared `cache_serve` and the streaming bridge.
        let body = axum::body::Body::from_stream(send_wrapper::SendWrapper::new(trimmed));
        Ok(Some(aos_hub_core::fetch::StreamedRead {
            body,
            total,
            range: served,
            strong_etag,
            snapshot_lease_id: None,
        }))
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        let key = keymap::r2_key(&self.prefix, path);
        Ok(self.contract.head(&key).await?.map(|object| object.size))
    }

    fn describe(&self) -> String {
        format!("r2://{}", self.prefix)
    }
}

/// A [`SurfaceFetch`] reading one resource's surface from an external
/// S3-compatible origin via per-object signed URLs.
///
/// The external-binding counterpart of [`R2SurfaceFetch`]: instead of an R2
/// `get`/`head`, each operation mints a short-lived presigned URL with
/// [`S3Surface::object_url`] and sends it through [`WorkerEgressClient`], whose
/// selected transport is Worker Fetch or the optional native router. Response
/// bodies stream through the isolate exactly like [`WorkerOriginFetch`] (so a
/// large NAR never buffers). A presigned URL signs only the `Host` header, so a
/// `Range` request header may be added freely on the streaming path.
struct S3SurfaceFetch {
    surface: S3Surface,
    egress: Arc<WorkerEgressClient>,
}

#[async_trait(?Send)]
impl SurfaceFetch for S3SurfaceFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Get, path, now)?;
        let mut response = self
            .egress
            .send(&url, "GET", None, None, None, None, None)
            .await
            .map_err(|err| {
                aos_hub_core::placement_read::retryable_read_error(format!(
                    "s3 GET {}: {err}",
                    self.surface.describe()
                ))
            })?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 GET {}", self.surface.describe()),
                status,
            ));
        }
        let bytes = crate::consoleports::read_response_capped(
            &mut response,
            aos_hub_core::s3surface::MAX_S3_BUFFERED_OBJECT_BYTES,
            "S3 object GET",
        )
        .await
        .map_err(|err| {
            aos_hub_core::placement_read::retryable_read_error(format!(
                "s3 read body {}: {err}",
                self.surface.describe()
            ))
        })?;
        Ok(Some(bytes))
    }

    async fn list_page(&self, cursor: Option<&str>, limit: usize) -> Result<SurfaceListPage> {
        anyhow::ensure!(
            limit > 0 && limit <= aos_hub_core::fetch::WORKER_MAX_SURFACE_LIST_PAGE_OBJECTS,
            "invalid S3 listing page limit"
        );
        anyhow::ensure!(
            cursor.is_none_or(|value| {
                value.len() <= aos_hub_core::fetch::WORKER_MAX_SURFACE_LIST_CURSOR_BYTES
            }),
            "S3 listing cursor is too large"
        );
        let mut parsed_keys = 0_usize;
        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.list_url(cursor, limit, now)?;
        let mut response = self
            .egress
            .send(&url, "GET", None, None, None, None, None)
            .await
            .map_err(|err| anyhow::anyhow!("s3 list {}: {err}", self.surface.describe()))?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 list {}", self.surface.describe()),
                status,
            ));
        }
        let body = crate::consoleports::read_response_capped(
            &mut response,
            aos_hub_core::s3surface::WORKER_MAX_S3_LIST_PAGE_BYTES,
            "S3 ListObjectsV2",
        )
        .await
        .map_err(|err| anyhow::anyhow!("s3 list body {}: {err}", self.surface.describe()))?;
        let body = String::from_utf8(body).context("S3 ListObjectsV2 response is not UTF-8")?;
        let mut paths = Vec::new();
        let (next, truncated) = aos_hub_core::s3surface::visit_list_objects_v2(&body, |key| {
            parsed_keys = parsed_keys
                .checked_add(1)
                .context("S3 inventory key count overflow")?;
            anyhow::ensure!(
                parsed_keys <= limit,
                "S3 listing page exceeds the requested key limit"
            );
            if let Some(rel) = self.surface.relative_from_key(&key) {
                if !rel.is_empty() {
                    paths.push(rel);
                }
            }
            Ok(())
        })?;
        paths.sort();
        paths.dedup();
        let next_cursor = if truncated {
            Some(next.context("truncated S3 inventory page has no continuation token")?)
        } else {
            None
        };
        Ok(SurfaceListPage {
            paths,
            evidence: Default::default(),
            next_cursor,
        })
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Head, path, now)?;
        let response = self
            .egress
            .send(&url, "HEAD", None, None, None, None, None)
            .await
            .map_err(|err| {
                anyhow::anyhow!("s3 inventory HEAD {}: {err}", self.surface.describe())
            })?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 inventory HEAD {}", self.surface.describe()),
                status,
            ));
        }
        let etag = response
            .headers()
            .get("etag")
            .ok()
            .flatten()
            .map(|value| value.trim().to_string());
        Ok(etag.filter(|value| aos_hub_core::surface_write::strong_if_match_etag(value).is_ok()))
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        use futures_util::TryStreamExt as _;
        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Get, path, now)?;

        // The presigned URL signs only the Host header, so a `Range` request
        // header travels unsigned and the origin honors it as a normal byte
        // range — the served range/total are re-derived from the response.
        let range = range.map(|(start, end)| {
            if end == u64::MAX {
                format!("bytes={start}-")
            } else {
                format!("bytes={start}-{end}")
            }
        });
        let mut response = self
            .egress
            .send(&url, "GET", None, None, range.as_deref(), None, None)
            .await
            .map_err(|err| {
                aos_hub_core::placement_read::retryable_read_error(format!(
                    "s3 GET {}: {err}",
                    self.surface.describe()
                ))
            })?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 GET {}", self.surface.describe()),
                status,
            ));
        }
        // A `206` carries the served range + total in `Content-Range`; a `200`
        // carries the size in `Content-Length` and serves the whole object.
        let served;
        let total;
        if status == 206 {
            let cr = response
                .headers()
                .get("content-range")
                .ok()
                .flatten()
                .and_then(|v| parse_content_range(&v))
                .ok_or_else(|| anyhow::anyhow!("s3 206 without a parseable Content-Range"))?;
            // Trust nothing from the origin: a malformed range would
            // underflow/overflow the downstream `Content-Length` arithmetic.
            if cr.0 > cr.1 || cr.1 >= cr.2 {
                anyhow::bail!(
                    "s3 malformed Content-Range bytes {}-{}/{}",
                    cr.0,
                    cr.1,
                    cr.2
                );
            }
            served = Some((cr.0, cr.1));
            total = cr.2;
        } else {
            served = None;
            total = response
                .headers()
                .get("content-length")
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| anyhow::anyhow!("s3 200 without a Content-Length"))?;
        }
        let strong_etag = response
            .headers()
            .get("etag")
            .ok()
            .flatten()
            .map(|value| value.trim().to_string())
            .filter(|value| aos_hub_core::surface_write::strong_if_match_etag(value).is_ok());
        let stream = response
            .stream()
            .map_err(|err| anyhow::anyhow!("s3 stream {}: {err}", self.surface.describe()))?
            .map_err(|err| std::io::Error::other(err.to_string()));
        // The `worker::Response` `ByteStream` is `!Send`; `SendWrapper` makes it
        // `Send` (sound on the single-threaded Worker) so the same
        // `StreamedRead` the R2/native paths return flows through `cache_serve`.
        let body = axum::body::Body::from_stream(send_wrapper::SendWrapper::new(stream));
        Ok(Some(StreamedRead {
            body,
            total,
            range: served,
            strong_etag,
            snapshot_lease_id: None,
        }))
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Head, path, now)?;
        let response = self
            .egress
            .send(&url, "HEAD", None, None, None, None, None)
            .await
            .map_err(|err| anyhow::anyhow!("s3 HEAD {}: {err}", self.surface.describe()))?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(aos_hub_core::placement_read::http_status_read_error(
                &format!("s3 HEAD {}", self.surface.describe()),
                status,
            ));
        }
        let len = response
            .headers()
            .get("content-length")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| anyhow::anyhow!("s3 HEAD without a Content-Length"))?;
        Ok(Some(len))
    }

    fn describe(&self) -> String {
        self.surface.describe()
    }
}

/// An [`OriginFetch`] over the fixed authenticated egress gateway.
///
/// The Worker counterpart of the native `ReqwestOriginFetch`: it streams a
/// private external origin's bytes through the isolate (the proxy-read
/// alternative to a `302` presigned redirect), forwarding a byte range as a
/// `Range` request header and re-deriving the served range/total from the
/// origin's `Content-Range`/`Content-Length` response headers. The body is the
/// `worker::Response` `ByteStream`, `SendWrapper`-wrapped into the axum body
/// exactly like the R2 read path, so a large NAR never buffers in the isolate.
pub struct WorkerOriginFetch {
    egress: Arc<WorkerEgressClient>,
}

impl WorkerOriginFetch {
    /// Creates an origin reader over the fixed authenticated gateway.
    #[must_use]
    pub fn new(egress: Arc<WorkerEgressClient>) -> Self {
        Self { egress }
    }
}

#[async_trait(?Send)]
impl OriginFetch for WorkerOriginFetch {
    async fn get_stream(
        &self,
        url: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        use futures_util::TryStreamExt as _;
        let range = range.map(|(start, end)| {
            if end == u64::MAX {
                format!("bytes={start}-")
            } else {
                format!("bytes={start}-{end}")
            }
        });
        let mut response = self
            .egress
            .send(url, "GET", None, None, range.as_deref(), None, None)
            .await
            .map_err(|err| anyhow::anyhow!("origin GET {url}: {err}"))?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            anyhow::bail!("origin GET {url}: status {status}");
        }
        // A `206` carries the served range + total in `Content-Range`; a `200`
        // carries the size in `Content-Length` and serves the whole object.
        let served;
        let total;
        if status == 206 {
            let cr = response
                .headers()
                .get("content-range")
                .ok()
                .flatten()
                .and_then(|v| parse_content_range(&v))
                .ok_or_else(|| anyhow::anyhow!("origin 206 without a parseable Content-Range"))?;
            // Trust nothing from the origin: a malformed range (`end < start` or
            // `end >= total`) would underflow/overflow the downstream
            // `Content-Length` arithmetic. Enforce `fetch_stream`'s invariant.
            if cr.0 > cr.1 || cr.1 >= cr.2 {
                anyhow::bail!(
                    "origin malformed Content-Range bytes {}-{}/{}",
                    cr.0,
                    cr.1,
                    cr.2
                );
            }
            served = Some((cr.0, cr.1));
            total = cr.2;
        } else {
            served = None;
            total = response
                .headers()
                .get("content-length")
                .ok()
                .flatten()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| anyhow::anyhow!("origin 200 without a Content-Length"))?;
        }
        let stream = response
            .stream()
            .map_err(|err| anyhow::anyhow!("origin stream {url}: {err}"))?
            .map_err(|err| std::io::Error::other(err.to_string()));
        let body = axum::body::Body::from_stream(send_wrapper::SendWrapper::new(stream));
        Ok(Some(StreamedRead {
            body,
            total,
            range: served,
            strong_etag: None,
            snapshot_lease_id: None,
        }))
    }
}

/// Parse a `Content-Range: bytes START-END/TOTAL` value into `(start, end, total)`.
///
/// Returns `None` for an unsatisfiable (`bytes */TOTAL`) or malformed value.
fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let rest = value.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    Some((
        start.trim().parse().ok()?,
        end.trim().parse().ok()?,
        total.trim().parse().ok()?,
    ))
}

/// A [`SurfaceWriteProvider`] that writes every registry into one R2 bucket, or
/// into an external S3/R2 origin when the resource names an `s3`/`r2` binding.
///
/// The write sibling of [`R2SurfaceProvider`]: holds the hub-owned bucket
/// binding plus the shared [`Database`] and [`SecretVersionResolver`] for resolving an
/// external binding, and scopes a writer to the requested registry's prefix —
/// signed `PUT`/`DELETE` against the external origin ([`S3Write`]) when the
/// binding is external, else the hub R2 bucket ([`R2Write`]). The shared
/// git-backed change-request flow ([`aos_hub_core::gitwrite`]) uses it to write
/// loose objects and draft refs.
pub struct R2SurfaceWriteProvider {
    bucket: Bucket,
    db: Arc<Database>,
    credentials: Arc<dyn StorageCredentialResolver>,
    egress: Arc<WorkerEgressClient>,
}

impl R2SurfaceWriteProvider {
    /// Wrap a bound R2 bucket (`env.bucket(binding)`) as a surface write
    /// provider, with the HubDb [`Database`] and [`SecretVersionResolver`] used to resolve
    /// external S3/R2 bindings.
    #[must_use]
    pub fn new(
        bucket: Bucket,
        db: Arc<Database>,
        secrets: Arc<dyn SecretVersionResolver>,
        egress: Arc<WorkerEgressClient>,
    ) -> R2SurfaceWriteProvider {
        let credentials = Arc::new(DatabaseStorageCredentialResolver::new(
            Arc::clone(&db),
            secrets,
        ));
        R2SurfaceWriteProvider {
            bucket,
            db,
            credentials,
            egress,
        }
    }
}

#[async_trait(?Send)]
impl SurfaceWriteProvider for R2SurfaceWriteProvider {
    async fn placement_writer(
        &self,
        placement: &SurfacePlacementRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        let revision = self
            .db
            .placement_publication_write_revision(placement.id)
            .await?
            .with_context(|| {
                format!(
                    "placement '{}' has no validated publication write capability",
                    placement.name
                )
            })?;
        self.placement_writer_at_revision(placement, &revision)
            .await
    }

    async fn placement_writer_at_revision(
        &self,
        placement: &SurfacePlacementRecord,
        revision: &BindingWriteRevisionRecord,
    ) -> Result<Box<dyn SurfaceWrite>> {
        anyhow::ensure!(
            placement.binding_id == revision.binding_id,
            "placement '{}' does not match frozen binding revision",
            placement.name
        );
        if let Some(surface) = placement_s3_surface(
            &self.db,
            self.credentials.as_ref(),
            placement,
            Some(revision),
        )
        .await?
        {
            return Ok(Box::new(S3Write {
                surface,
                egress: Arc::clone(&self.egress),
            }));
        }
        Ok(Box::new(R2Write {
            contract: R2Contract::new(WorkerR2BucketAdapter {
                bucket: self.bucket.as_ref().clone(),
            }),
            prefix: placement.prefix.clone(),
        }))
    }

    async fn placement_deleter(
        &self,
        placement: &SurfacePlacementRecord,
        expected_binding_resource_version: i64,
        delete_credential_generation: i64,
    ) -> Result<Box<dyn SurfaceWrite>> {
        let surface = placement_s3_delete_surface(
            &self.db,
            self.credentials.as_ref(),
            placement,
            expected_binding_resource_version,
            delete_credential_generation,
        )
        .await?;
        Ok(Box::new(S3Write {
            surface,
            egress: Arc::clone(&self.egress),
        }))
    }

    async fn frozen_placement_deleter(
        &self,
        access: &FrozenSurfaceAccess,
    ) -> Result<Box<dyn SurfaceWrite>> {
        let binding = frozen_access_binding(&self.db, access).await?;
        if binding.is_instance_default || binding.kind == "deployment_r2" {
            anyhow::bail!("deployment R2 cannot enforce atomic conditional deletion");
        }
        anyhow::ensure!(
            matches!(binding.kind.as_str(), "s3" | "r2"),
            "frozen placement uses unsupported Worker storage"
        );
        let credential = frozen_delete_credential(self.credentials.as_ref(), access)
            .await?
            .context("object-store frozen deletion requires exact credentials")?;
        let surface = S3Surface::from_binding(
            &binding,
            &access.placement_prefix,
            Some(credential.secret()?),
        )?
        .context("frozen deletion object-store binding cannot be resolved")?;
        Ok(Box::new(S3Write {
            surface,
            egress: Arc::clone(&self.egress),
        }))
    }
}

/// A [`SurfaceWrite`] writing one registry's prefix into an R2 bucket.
///
/// Logical surface paths map to R2 keys through the same
/// [`crate::keymap::r2_key`] mapping the read side
/// ([`R2SurfaceFetch`]) uses, so a draft written here is read back by the same
/// key. R2 puts are atomic per object, so no temp-file + rename dance is needed;
/// R2 keys are a flat namespace, so there is no traversal/symlink escape to
/// guard against (the key map normalizes the prefix join).
struct R2Write {
    contract: R2Contract<WorkerR2BucketAdapter>,
    prefix: String,
}

#[async_trait(?Send)]
impl SurfaceWrite for R2Write {
    fn multipart_protocol_version(&self) -> Option<u32> {
        Some(1)
    }

    fn abandoned_multipart_lifetime_secs(&self) -> Option<u64> {
        // The deployment reconciles an all-prefix lifecycle rule before this
        // Worker is installed, bounding an upload whose opaque creation
        // response never reached the caller.
        Some(7 * 24 * 60 * 60)
    }

    fn expected_multipart_etag(&self, parts: &[PartTag]) -> Result<Option<String>> {
        aos_hub_core::surface_write::md5_multipart_etag(parts)
    }

    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let key = keymap::r2_key(&self.prefix, path);
        self.contract.put(&key, bytes).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let key = keymap::r2_key(&self.prefix, path);
        self.contract.delete(&key).await
    }

    async fn create_multipart(&self, path: &str) -> Result<String> {
        let key = keymap::r2_key(&self.prefix, path);
        self.contract.create_multipart(&key).await
    }

    async fn upload_part(
        &self,
        path: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<PartTag> {
        let key = keymap::r2_key(&self.prefix, path);
        self.contract
            .upload_part(&key, upload_id, part_number, bytes)
            .await
    }

    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[PartTag],
    ) -> Result<String> {
        let key = keymap::r2_key(&self.prefix, path);
        self.contract
            .complete_multipart(&key, upload_id, parts)
            .await
    }

    async fn abort_multipart(&self, path: &str, upload_id: &str) -> Result<MultipartAbortOutcome> {
        let key = keymap::r2_key(&self.prefix, path);
        self.contract.abort_multipart(&key, upload_id).await
    }
}

/// Executes the production reflection adapter against an exact R2 JavaScript
/// object shape inside workerd.
///
/// Open-source workerd cannot provision a real R2 binding, so the `do-e2e`
/// artifact supplies the JavaScript methods and response objects that the
/// production adapter reflects. This catches method-name, argument-shape,
/// response-field, promise, and multipart-resume drift without substituting a
/// second Rust implementation of [`R2BucketAdapter`].
///
/// # Errors
///
/// Returns an error when the production adapter rejects the fixture shape or
/// emits any argument sequence other than the Cloudflare R2 contract.
#[cfg(feature = "do-e2e")]
pub(crate) async fn e2e_assert_r2_js_shape() -> Result<()> {
    use std::cell::RefCell;
    use std::rc::Rc;

    use futures_util::TryStreamExt as _;
    use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsValue;

    fn set_method(target: &Object, name: &str, value: &JsValue) -> Result<()> {
        Reflect::set(target, &JsValue::from_str(name), value)
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("R2 JS fixture {name}: {error:?}"))
    }

    let calls = Rc::new(RefCell::new(Vec::<String>::new()));
    let bucket = Object::new();

    let put_calls = Rc::clone(&calls);
    let put = Closure::wrap(Box::new(move |key: JsValue, body: JsValue| -> JsValue {
        let bytes = Uint8Array::new(&body).to_vec();
        put_calls.borrow_mut().push(format!(
            "put:{}:{bytes:?}",
            key.as_string().unwrap_or_default()
        ));
        Promise::resolve(&JsValue::UNDEFINED).into()
    }) as Box<dyn FnMut(JsValue, JsValue) -> JsValue>);
    set_method(&bucket, "put", put.as_ref())?;

    let delete_calls = Rc::clone(&calls);
    let delete = Closure::wrap(Box::new(move |key: JsValue| -> JsValue {
        delete_calls
            .borrow_mut()
            .push(format!("delete:{}", key.as_string().unwrap_or_default()));
        Promise::resolve(&JsValue::UNDEFINED).into()
    }) as Box<dyn FnMut(JsValue) -> JsValue>);
    set_method(&bucket, "delete", delete.as_ref())?;

    let list_calls = Rc::clone(&calls);
    let list = Closure::wrap(Box::new(move |options: JsValue| -> JsValue {
        let prefix = Reflect::get(&options, &JsValue::from_str("prefix"))
            .ok()
            .and_then(|value| value.as_string())
            .unwrap_or_default();
        let cursor_key = JsValue::from_str("cursor");
        let cursor = if Reflect::has(&options, &cursor_key).unwrap_or(true) {
            Reflect::get(&options, &cursor_key)
                .ok()
                .and_then(|value| value.as_string())
                .unwrap_or_else(|| "<non-string>".to_string())
        } else {
            "<absent>".to_string()
        };
        let limit = Reflect::get(&options, &JsValue::from_str("limit"))
            .ok()
            .and_then(|value| value.as_f64())
            .unwrap_or_default() as u32;
        list_calls
            .borrow_mut()
            .push(format!("list:{prefix}:{cursor}:{limit}"));
        let object = Object::new();
        let listed = Object::new();
        let _ = Reflect::set(
            &listed,
            &JsValue::from_str("key"),
            &JsValue::from_str("fixture/object"),
        );
        let _ = Reflect::set(&listed, &JsValue::from_str("size"), &JsValue::from_f64(3.0));
        let _ = Reflect::set(
            &listed,
            &JsValue::from_str("etag"),
            &JsValue::from_str("fixture-etag"),
        );
        let objects = Array::new();
        objects.push(&listed);
        let _ = Reflect::set(&object, &JsValue::from_str("objects"), &objects);
        let _ = Reflect::set(
            &object,
            &JsValue::from_str("truncated"),
            &JsValue::from_bool(true),
        );
        let _ = Reflect::set(
            &object,
            &JsValue::from_str("cursor"),
            &JsValue::from_str("cursor-2"),
        );
        Promise::resolve(&object).into()
    }) as Box<dyn FnMut(JsValue) -> JsValue>);
    set_method(&bucket, "list", list.as_ref())?;

    let head_calls = Rc::clone(&calls);
    let head = Closure::wrap(Box::new(move |key: JsValue| -> JsValue {
        head_calls
            .borrow_mut()
            .push(format!("head:{}", key.as_string().unwrap_or_default()));
        let object = Object::new();
        let _ = Reflect::set(&object, &JsValue::from_str("size"), &JsValue::from_f64(3.0));
        let _ = Reflect::set(
            &object,
            &JsValue::from_str("etag"),
            &JsValue::from_str("fixture-etag"),
        );
        Promise::resolve(&object).into()
    }) as Box<dyn FnMut(JsValue) -> JsValue>);
    set_method(&bucket, "head", head.as_ref())?;

    let buffer_calls = Rc::clone(&calls);
    let array_buffer = Closure::wrap(Box::new(move || -> JsValue {
        buffer_calls.borrow_mut().push("arrayBuffer".to_string());
        let bytes = Uint8Array::from(&[1_u8, 2, 3][..]);
        let buffer: JsValue = bytes.buffer().into();
        Promise::resolve(&buffer).into()
    }) as Box<dyn FnMut() -> JsValue>);
    let body = Object::new();
    set_method(&body, "arrayBuffer", array_buffer.as_ref())?;
    let get_calls = Rc::clone(&calls);
    let get_body = body.clone();
    let get = Closure::wrap(Box::new(move |key: JsValue, options: JsValue| -> JsValue {
        let rendered_range = if options.is_undefined() {
            "<absent>".to_string()
        } else {
            let range =
                Reflect::get(&options, &JsValue::from_str("range")).unwrap_or(JsValue::UNDEFINED);
            let offset = Reflect::get(&range, &JsValue::from_str("offset"))
                .ok()
                .and_then(|value| value.as_f64())
                .unwrap_or_default() as u64;
            let length = Reflect::get(&range, &JsValue::from_str("length"))
                .ok()
                .and_then(|value| value.as_f64())
                .unwrap_or_default() as u64;
            let suffix = Reflect::has(&range, &JsValue::from_str("suffix")).unwrap_or(true);
            format!("{offset}:{length}:suffix={suffix}")
        };
        get_calls.borrow_mut().push(format!(
            "get:{}:{rendered_range}",
            key.as_string().unwrap_or_default()
        ));
        Promise::resolve(&get_body).into()
    }) as Box<dyn FnMut(JsValue, JsValue) -> JsValue>);
    set_method(&bucket, "get", get.as_ref())?;

    let create_calls = Rc::clone(&calls);
    let create = Closure::wrap(Box::new(move |key: JsValue| -> JsValue {
        create_calls.borrow_mut().push(format!(
            "createMultipartUpload:{}",
            key.as_string().unwrap_or_default()
        ));
        let upload = Object::new();
        let _ = Reflect::set(
            &upload,
            &JsValue::from_str("uploadId"),
            &JsValue::from_str("upload-1"),
        );
        Promise::resolve(&upload).into()
    }) as Box<dyn FnMut(JsValue) -> JsValue>);
    set_method(&bucket, "createMultipartUpload", create.as_ref())?;

    let part_calls = Rc::clone(&calls);
    let upload_part = Closure::wrap(Box::new(
        move |part_number: JsValue, body: JsValue| -> JsValue {
            let bytes = Uint8Array::new(&body).to_vec();
            part_calls.borrow_mut().push(format!(
                "uploadPart:{}:{bytes:?}",
                part_number.as_f64().unwrap_or_default() as u32
            ));
            let part = Object::new();
            let _ = Reflect::set(
                &part,
                &JsValue::from_str("etag"),
                &JsValue::from_str("etag-2"),
            );
            Promise::resolve(&part).into()
        },
    ) as Box<dyn FnMut(JsValue, JsValue) -> JsValue>);

    let complete_calls = Rc::clone(&calls);
    let complete = Closure::wrap(Box::new(move |parts: JsValue| -> JsValue {
        let parts = Array::from(&parts);
        let rendered = parts
            .iter()
            .map(|part| {
                let number = Reflect::get(&part, &JsValue::from_str("partNumber"))
                    .ok()
                    .and_then(|value| value.as_f64())
                    .unwrap_or_default() as u32;
                let etag = Reflect::get(&part, &JsValue::from_str("etag"))
                    .ok()
                    .and_then(|value| value.as_string())
                    .unwrap_or_default();
                format!("{number}:{etag}")
            })
            .collect::<Vec<_>>()
            .join(",");
        complete_calls
            .borrow_mut()
            .push(format!("complete:[{rendered}]"));
        let object = Object::new();
        let _ = Reflect::set(
            &object,
            &JsValue::from_str("etag"),
            &JsValue::from_str("\"completed-etag\""),
        );
        Promise::resolve(&object).into()
    }) as Box<dyn FnMut(JsValue) -> JsValue>);

    let abort_calls = Rc::clone(&calls);
    let abort = Closure::wrap(Box::new(move || -> JsValue {
        abort_calls.borrow_mut().push("abort".to_string());
        Promise::resolve(&JsValue::UNDEFINED).into()
    }) as Box<dyn FnMut() -> JsValue>);

    let upload = Object::new();
    set_method(&upload, "uploadPart", upload_part.as_ref())?;
    set_method(&upload, "complete", complete.as_ref())?;
    set_method(&upload, "abort", abort.as_ref())?;
    let resume_calls = Rc::clone(&calls);
    let resumed_upload = upload.clone();
    let resume = Closure::wrap(
        Box::new(move |key: JsValue, upload_id: JsValue| -> JsValue {
            resume_calls.borrow_mut().push(format!(
                "resumeMultipartUpload:{}:{}",
                key.as_string().unwrap_or_default(),
                upload_id.as_string().unwrap_or_default()
            ));
            resumed_upload.clone().into()
        }) as Box<dyn FnMut(JsValue, JsValue) -> JsValue>,
    );
    set_method(&bucket, "resumeMultipartUpload", resume.as_ref())?;

    let bucket_value: JsValue = bucket.into();
    let contract = R2Contract::new(WorkerR2BucketAdapter {
        bucket: bucket_value.clone(),
    });
    contract.put("fixture/object", &[1, 2, 3]).await?;
    contract.delete("fixture/deleted").await?;
    let first_page = contract.list("fixture/", None, 2).await?;
    anyhow::ensure!(
        first_page.objects
            == vec![R2ListObject {
                key: "fixture/object".into(),
                size: 3,
                etag: "\"fixture-etag\"".into(),
            }]
            && first_page.cursor.as_deref() == Some("cursor-2"),
        "R2 first list response shape did not round-trip: objects={:?}, cursor={:?}",
        first_page.objects,
        first_page.cursor
    );
    let page = contract.list("fixture/", Some("cursor-1"), 2).await?;
    anyhow::ensure!(
        page.objects
            == vec![R2ListObject {
                key: "fixture/object".into(),
                size: 3,
                etag: "\"fixture-etag\"".into(),
            }]
            && page.cursor.as_deref() == Some("cursor-2"),
        "R2 list response shape did not round-trip"
    );
    anyhow::ensure!(
        contract.read_bounded("fixture/object", 3).await? == Some(vec![1, 2, 3]),
        "R2 HEAD/get/arrayBuffer shape did not round-trip"
    );
    anyhow::ensure!(
        r2_get_range(&bucket_value, "fixture/object", 7, 11)
            .await?
            .is_some(),
        "R2 ranged get response shape did not round-trip"
    );
    let response: worker::web_sys::Response = worker::Response::from_bytes(vec![7, 8, 9])?.into();
    let body = response
        .body()
        .context("workerd fixture response returned no ReadableStream")?;
    let streamed = r2_body_stream(body.into())?.try_concat().await?;
    anyhow::ensure!(
        streamed == vec![7, 8, 9],
        "R2 ReadableStream body did not round-trip through worker-rs"
    );
    anyhow::ensure!(
        contract.create_multipart("fixture/object").await? == "upload-1",
        "R2 createMultipartUpload response shape did not round-trip"
    );
    let part = contract
        .upload_part("fixture/object", "upload-1", 2, &[4, 5])
        .await?;
    contract
        .complete_multipart(
            "fixture/object",
            "upload-1",
            &[
                part,
                PartTag {
                    part_number: 1,
                    etag: "etag-1".to_string(),
                },
            ],
        )
        .await?;
    anyhow::ensure!(
        contract
            .abort_multipart("fixture/object", "upload-1")
            .await?
            == MultipartAbortOutcome::Aborted,
        "R2 abort promise did not round-trip"
    );

    let expected = vec![
        "put:fixture/object:[1, 2, 3]",
        "delete:fixture/deleted",
        "list:fixture/:<absent>:2",
        "list:fixture/:cursor-1:2",
        "head:fixture/object",
        "get:fixture/object:<absent>",
        "arrayBuffer",
        "get:fixture/object:7:11:suffix=false",
        "createMultipartUpload:fixture/object",
        "resumeMultipartUpload:fixture/object:upload-1",
        "uploadPart:2:[4, 5]",
        "resumeMultipartUpload:fixture/object:upload-1",
        "complete:[1:etag-1,2:etag-2]",
        "resumeMultipartUpload:fixture/object:upload-1",
        "abort",
    ];
    let actual = calls.borrow().clone();
    anyhow::ensure!(
        actual.iter().map(String::as_str).eq(expected),
        "production R2 adapter emitted the wrong JavaScript call shape: {:?}",
        actual
    );
    Ok(())
}

/// Reflect method `name` off the JS object `obj` as a callable `Function`.
fn js_method(obj: &wasm_bindgen::JsValue, name: &str) -> Result<js_sys::Function> {
    use wasm_bindgen::JsCast;
    js_sys::Reflect::get(obj, &wasm_bindgen::JsValue::from_str(name))
        .map_err(|e| anyhow::anyhow!("missing JS method {name}: {e:?}"))?
        .dyn_into::<js_sys::Function>()
        .map_err(|e| anyhow::anyhow!("JS {name} is not a function: {e:?}"))
}

/// Coerce a JS call result into a `Promise`, tagging errors with `key`/`op`.
fn js_promise(
    result: std::result::Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>,
    key: &str,
    op: &str,
) -> Result<js_sys::Promise> {
    use wasm_bindgen::JsCast;
    result
        .map_err(|e| anyhow::anyhow!("R2 {op} {key}: call: {e:?}"))?
        .dyn_into::<js_sys::Promise>()
        .map_err(|e| anyhow::anyhow!("R2 {op} {key}: did not return a promise: {e:?}"))
}

/// A [`SurfaceWrite`] writing one resource's surface to an external
/// S3-compatible origin via per-object signed URLs.
///
/// The external-binding counterpart of [`R2Write`]: each operation mints a
/// short-lived presigned `PUT`/`DELETE` URL with [`S3Surface::object_url`] and
/// sends it through the fixed authenticated gateway. A `DELETE` is idempotent — a
/// `404`/`204` (absent key) is treated as success — matching the R2 path's
/// no-op delete.
struct S3Write {
    surface: S3Surface,
    egress: Arc<WorkerEgressClient>,
}

#[async_trait(?Send)]
impl SurfaceWrite for S3Write {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Put, path, now)?;
        let response = self
            .egress
            .send(&url, "PUT", Some(bytes.to_vec()), None, None, None, None)
            .await
            .map_err(|err| anyhow::anyhow!("s3 PUT {}: {err}", self.surface.describe()))?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            anyhow::bail!("s3 PUT {}: status {status}", self.surface.describe());
        }
        Ok(())
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Delete, path, now)?;
        let response = self
            .egress
            .send(&url, "DELETE", None, None, None, None, None)
            .await
            .map_err(|err| anyhow::anyhow!("s3 DELETE {}: {err}", self.surface.describe()))?;
        let status = response.status_code();
        // Idempotent: deleting an absent object (404) succeeds, as does a 204
        // No Content or any other 2xx the origin returns.
        if status == 404 || (200..300).contains(&status) {
            return Ok(());
        }
        anyhow::bail!("s3 DELETE {}: status {status}", self.surface.describe());
    }

    async fn delete_if_matches(
        &self,
        path: &str,
        expected: &aos_hub_core::surface_write::SurfaceDeletePrecondition,
    ) -> Result<aos_hub_core::surface_write::SurfaceDeleteOutcome> {
        let etag = expected
            .etag
            .as_deref()
            .filter(|etag| !etag.is_empty())
            .context("s3 identity-checked deletion requires a strong ETag")?;
        let etag = aos_hub_core::surface_write::strong_if_match_etag(etag)?;
        let now = aos_hub_core::clock::now_unix_secs();
        let url = self.surface.object_url(S3Method::Delete, path, now)?;
        let response = self
            .egress
            .send(&url, "DELETE", None, None, None, Some(&etag), None)
            .await
            .map_err(|err| anyhow::anyhow!("s3 conditional DELETE: {err}"))?;
        match response.status_code() {
            200..=299 => Ok(
                aos_hub_core::surface_write::SurfaceDeleteOutcome::ConditionalDeleteAcknowledged {
                    etag,
                },
            ),
            404 => Ok(aos_hub_core::surface_write::SurfaceDeleteOutcome::NotFound),
            412 => Ok(
                aos_hub_core::surface_write::SurfaceDeleteOutcome::PreconditionFailed {
                    detail: "backend object identity changed after inventory".to_string(),
                },
            ),
            status => anyhow::bail!(
                "s3 conditional DELETE {}: status {status}",
                self.surface.describe()
            ),
        }
    }

    async fn create_multipart(&self, path: &str) -> Result<String> {
        let url = self.surface.multipart_url(
            "create",
            path,
            None,
            None,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let mut response = self
            .egress
            .send(&url, "POST", Some(Vec::new()), None, None, None, None)
            .await
            .context("S3 create multipart gateway request")?;
        anyhow::ensure!(
            (200..300).contains(&response.status_code()),
            "S3 create multipart failed: {}",
            response.status_code()
        );
        let body = crate::consoleports::read_response_capped(
            &mut response,
            1024 * 1024,
            "S3 create multipart response",
        )
        .await?;
        let body = String::from_utf8(body).context("S3 create multipart response is not UTF-8")?;
        aos_hub_core::s3surface::parse_multipart_upload_id(&body)
    }

    async fn upload_part(
        &self,
        path: &str,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<aos_hub_core::surface_write::PartTag> {
        let url = self.surface.multipart_url(
            "part",
            path,
            Some(upload_id),
            Some(part_number),
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let response = self
            .egress
            .send(&url, "PUT", Some(bytes.to_vec()), None, None, None, None)
            .await
            .context("S3 upload-part gateway request")?;
        anyhow::ensure!(
            (200..300).contains(&response.status_code()),
            "S3 upload part failed: {}",
            response.status_code()
        );
        let etag = response
            .headers()
            .get("etag")?
            .context("S3 upload-part response omitted ETag")?;
        Ok(aos_hub_core::surface_write::PartTag { part_number, etag })
    }

    async fn complete_multipart(
        &self,
        path: &str,
        upload_id: &str,
        parts: &[aos_hub_core::surface_write::PartTag],
    ) -> Result<String> {
        let url = self.surface.multipart_url(
            "complete",
            path,
            Some(upload_id),
            None,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let body = aos_hub_core::s3surface::complete_multipart_xml(parts)?.into_bytes();
        let mut response = self
            .egress
            .send(
                &url,
                "POST",
                Some(body),
                Some("application/xml"),
                None,
                None,
                None,
            )
            .await
            .context("S3 complete-multipart gateway request")?;
        anyhow::ensure!(
            (200..300).contains(&response.status_code()),
            "S3 complete multipart failed: {}",
            response.status_code()
        );
        let body = crate::consoleports::read_response_capped(
            &mut response,
            1024 * 1024,
            "S3 complete multipart response",
        )
        .await?;
        let body =
            String::from_utf8(body).context("S3 complete multipart response is not UTF-8")?;
        aos_hub_core::s3surface::complete_multipart_etag(&body)
    }

    async fn abort_multipart(
        &self,
        path: &str,
        upload_id: &str,
    ) -> Result<aos_hub_core::surface_write::MultipartAbortOutcome> {
        let url = self.surface.multipart_url(
            "abort",
            path,
            Some(upload_id),
            None,
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let response = self
            .egress
            .send(&url, "DELETE", None, None, None, None, None)
            .await
            .context("S3 abort-multipart gateway request")?;
        match response.status_code() {
            404 => Ok(aos_hub_core::surface_write::MultipartAbortOutcome::Absent),
            200..=299 => Ok(aos_hub_core::surface_write::MultipartAbortOutcome::Aborted),
            status => anyhow::bail!("S3 abort multipart failed: {status}"),
        }
    }
}
