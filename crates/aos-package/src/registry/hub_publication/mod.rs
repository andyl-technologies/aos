//! Shared descriptor-pinned Hub publication admission, transfer, and commit.

use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_net::retry::{RetryConfig, compute_retry_delay};
use aos_net::{
    MultipartAdmission, MultipartBackend, MultipartFailurePolicy, MultipartSessionState,
    MultipartSource, MultipartUploadRequest, TransferEvent, TransferManager, TransferManagerConfig,
    TransferObserver,
};
use aos_remote::{HubClient, hub_rpc as HubTopologyMethod, hub_types};
use futures_util::stream;
use futures_util::stream::{StreamExt as _, TryStreamExt as _};
use inventory::{
    MAX_PUBLICATION_OBJECTS, pinned_publication_from_root, publication_from_root,
    publication_manifest_request, snapshot_publication_object,
};

/// Identifies a Hub and optional explicit credentials for shared publication adapters.
#[derive(Clone, Debug, Default)]
pub struct PublicationAccess {
    /// Explicit Hub origin; absent selects the active renewable profile.
    pub hub: Option<String>,
    /// Explicit bearer credential; absent resolves the current profile per request.
    pub token: Option<String>,
}

/// Bounds each part to the publication service's 8 MiB wire contract.
const MAX_PUBLICATION_PART_BYTES: u64 = 8 * 1024 * 1024;

mod direct_upload;

/// Uploads and commits one exact registry surface without advancing a channel.
///
/// Release orchestration reuses this bounded publication primitive after it
/// has independently verified the destination deployment and closed bundle.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub async fn upload_registry_publication(
    access: &PublicationAccess,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
) -> Result<hub_types::RegistryPublication> {
    upload_registry_publication_with_commit(
        access,
        registry,
        manifest,
        root,
        printer,
        true,
        false,
        None,
        direct_upload::options(access),
    )
    .await
}

/// Uploads one exact registry surface while leaving its mutable commit to a
/// release-scoped compare-and-swap RPC.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub async fn prepare_registry_publication(
    access: &PublicationAccess,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
) -> Result<hub_types::RegistryPublication> {
    upload_registry_publication_with_commit(
        access,
        registry,
        manifest,
        root,
        printer,
        false,
        false,
        None,
        direct_upload::options(access),
    )
    .await
}

/// Registers, admits, and resumes an exact common candidate without exposing pointers.
///
/// The admitted publication id is attached before its first byte transfer, so
/// interrupted uploads remain visible in the shared administrative catalog.
///
/// # Errors
///
/// Returns an error for a stale revision, inconsistent inventory, admission,
/// transfer failure, or unavailable verified candidate state.
pub async fn stage_registry_candidate(
    access: &PublicationAccess,
    revision: &aos_registry_surface::staging::StageRevision,
    expected_revision: u64,
    root: &std::path::Path,
    printer: &Printer,
) -> Result<hub_types::RegistryPublication> {
    revision.validate()?;
    upload_registry_publication_with_commit(
        access,
        &revision.registry,
        None,
        root,
        printer,
        false,
        true,
        Some((revision, expected_revision)),
        direct_upload::options(access),
    )
    .await
}

/// Uploads and commits one exact publication using explicit Direct client options.
///
/// # Errors
/// Returns an error for invalid inventory, changed admission, refused transport,
/// transfer failure, or a failed final publication barrier.
pub async fn upload_registry_publication_with_options(
    access: &PublicationAccess,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
    options: aos_remote::DirectUploadOptions,
) -> Result<hub_types::RegistryPublication> {
    upload_registry_publication_with_commit(
        access, registry, manifest, root, printer, true, false, None, options,
    )
    .await
}

/// Prepares exact publication bytes while withholding the mutable publication commit.
///
/// # Errors
/// Returns an error for invalid inventory, changed admission, refused transport,
/// transfer failure, or inconsistent verified readback.
pub async fn prepare_registry_publication_with_options(
    access: &PublicationAccess,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
    options: aos_remote::DirectUploadOptions,
) -> Result<hub_types::RegistryPublication> {
    upload_registry_publication_with_commit(
        access, registry, manifest, root, printer, false, false, None, options,
    )
    .await
}

async fn upload_registry_publication_with_commit(
    access: &PublicationAccess,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
    commit: bool,
    immutable_only: bool,
    stage: Option<(&aos_registry_surface::staging::StageRevision, u64)>,
    options: aos_remote::DirectUploadOptions,
) -> Result<hub_types::RegistryPublication> {
    // Keep invocation counters through inventory, admission and final controls.
    let mut metrics_report = direct_upload::report_on_completion(&options);
    let mut pinned = match manifest {
        Some(manifest) => {
            let request = publication_manifest_request(manifest, registry)?;
            pinned_publication_from_root(root, request)?
        }
        None => publication_from_root(root, registry)?,
    };
    let stage_client = if let Some((revision, expected_revision)) = stage {
        let origin = access
            .hub
            .as_deref()
            .context("candidate registration requires an explicit Hub origin")?;
        let stage_client = super::hub_stage::HubStageClient::connect(
            origin,
            &revision.registry,
            access.token.as_deref(),
        )
        .await?;
        let objects = pinned
            .request
            .objects
            .iter()
            .filter(|object| object.kind != "mutable_pointer")
            .map(|object| {
                Ok(aos_registry_surface::staging::StageObject {
                    path: object.path.clone(),
                    sha256: format!("sha256:{}", object.sha256),
                    byte_size: u64::try_from(object.byte_size)?,
                    kind: "immutable".into(),
                    media_type: object.media_type.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let expected = revision
            .inventory
            .iter()
            .filter(|object| !object.path.starts_with("oci/"))
            .cloned()
            .collect::<Vec<_>>();
        anyhow::ensure!(
            objects.len() == expected.len()
                && objects
                    .iter()
                    .zip(&expected)
                    .all(|(actual, expected)| actual.path == expected.path
                        && actual.sha256 == expected.sha256
                        && actual.byte_size == expected.byte_size
                        && actual.media_type == expected.media_type),
            "candidate inventory differs from the pinned publication"
        );
        let inputs = pinned
            .request
            .objects
            .iter()
            .map(|object| (object.path.as_str(), object))
            .collect::<std::collections::BTreeMap<_, _>>();
        for pointer in &revision.publication {
            let input = inputs
                .get(pointer.path.as_str())
                .context("candidate pointer is absent from publication inventory")?;
            use sha2::Digest as _;
            anyhow::ensure!(
                input.kind == "mutable_pointer"
                    && input.byte_size == i64::try_from(pointer.bytes.len())?
                    && input.sha256 == hex::encode(sha2::Sha256::digest(&pointer.bytes)),
                "candidate pointer differs from the pinned publication"
            );
        }
        let pointers = pinned
            .request
            .objects
            .iter()
            .filter(|object| object.kind == "mutable_pointer")
            .count();
        anyhow::ensure!(
            pointers == revision.publication.len(),
            "candidate pointer inventory is incomplete"
        );
        stage_client
            .upsert(revision, expected_revision, None)
            .await?;
        Some(stage_client)
    } else {
        None
    };
    let client = publication_client(access).await?;
    let discovery = aos_remote::discover_publication_transport(&client, &options).await?;
    let direct_required = discovery.transfer_mode()
        == hub_types::direct_upload::DirectAdvertisedTransferMode::DirectRequired;
    if !direct_required {
        metrics_report.suppress();
    }
    let prepared = if direct_required {
        Some(
            aos_remote::prepare_direct_publication(&client, &pinned.request, &options, &discovery)
                .await?,
        )
    } else {
        None
    };
    let publication = match &prepared {
        Some(prepared) => prepared.publication.clone(),
        None => {
            bind_publication_parent(&client, &mut pinned.request).await?;
            begin_registry_publication_chunked(&client, &pinned.request).await?
        }
    };
    let publication_id = publication.publication_id.clone();
    if let (Some(client), Some((revision, _))) = (&stage_client, stage) {
        client
            .upsert(revision, revision.revision, Some(&publication_id))
            .await?;
        if let Some(container) = &revision.container {
            let topology = publication_client(access)
                .await?
                .call_topology(
                    HubTopologyMethod::GetRegistry,
                    &hub_types::GetRegistryRequest {
                        slug: revision.registry.clone(),
                    },
                )
                .await?;
            let registry = topology
                .registry
                .context("Hub registry topology is absent")?;
            let origin = registry.oci_distribution_origin;
            anyhow::ensure!(
                !origin.is_empty(),
                "registry has no acknowledged OCI Distribution route"
            );
            // The Hub reports the namespace the origin serves this registry
            // under; checkpoints key on the wire name the bytes travel to.
            let namespace = Some(registry.oci_repository_namespace.as_str())
                .filter(|namespace| !namespace.is_empty());
            let wire_repository =
                super::container_stage::namespaced_repository(namespace, &container.repository)?;
            let (_, token) =
                crate::hub_auth::resolve_access(access.hub.as_deref(), access.token.as_deref())?;
            let state_directory = super::container_stage::container_upload_state_directory(
                &origin,
                &wire_repository,
            )?;
            super::container_stage::upload_container_stage(
                revision,
                &root.join("oci/blobs/sha256"),
                &origin,
                namespace,
                token,
                &state_directory,
            )
            .await
            .context("uploading the exact staged OCI graph")?;
        }
    }

    let result: Result<hub_types::RegistryPublication> =
        async {
            anyhow::ensure!(
                publication.objects.len() == pinned.request.objects.len(),
                "Hub publication response changed the declared object count"
            );
            let paths = publication
                .objects
                .iter()
                .map(|object| object.path.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            anyhow::ensure!(
                paths.len() == pinned.request.objects.len(),
                "Hub publication response repeated a declared path"
            );
            let declared = pinned
                .request
                .objects
                .iter()
                .map(|input| (input.path.as_str(), input))
                .collect::<std::collections::BTreeMap<_, _>>();
            for object in &publication.objects {
                let expected = declared
                    .get(object.path.as_str())
                    .context("Hub publication response introduced an undeclared path")?;
                anyhow::ensure!(
                    expected.sha256 == object.sha256
                        && expected.byte_size == object.byte_size
                        && expected.kind == object.kind
                        && expected.media_type == object.media_type,
                    "Hub publication response changed the identity of {}",
                    object.path
                );
            }
            let objects = publication_objects_in_upload_order(&publication);
            let pointer_start = objects.partition_point(|object| object.kind != "mutable_pointer");
            let (immutable_objects, pointer_objects) = objects.split_at(pointer_start);

            let staged_direct = match &prepared {
                Some(prepared) => {
                    direct_upload::upload_if_required(
                        &options,
                        &client,
                        prepared,
                        &pinned.root,
                        &pinned.request.objects,
                        &objects,
                        immutable_only,
                    )
                    .await?
                }
                None => false,
            };
            if !staged_direct {
                upload_publication_object_class(
                    access,
                    &publication_id,
                    &pinned.root,
                    &pinned.request.objects,
                    immutable_objects,
                    printer,
                    "Uploading immutable publication objects",
                )
                .await?;
                if !immutable_only {
                    upload_publication_object_class(
                        access,
                        &publication_id,
                        &pinned.root,
                        &pinned.request.objects,
                        pointer_objects,
                        printer,
                        "Uploading publication pointers",
                    )
                    .await?;
                }
            }
            let client = publication_client(access).await?;
            if commit {
                match &prepared {
                    Some(prepared) => {
                        aos_remote::commit_direct_publication(&client, prepared, &options)
                            .await
                            .map_err(Into::into)
                    }
                    None => {
                        client
                            .call_topology(
                                HubTopologyMethod::CommitRegistryPublication,
                                &hub_types::CommitRegistryPublicationRequest {
                                    publication_id: publication_id.to_string(),
                                },
                            )
                            .await
                    }
                }
            } else {
                let result: hub_types::RegistryPublication = client
                    .call_topology(
                        HubTopologyMethod::GetRegistryPublication,
                        &hub_types::GetRegistryPublicationRequest {
                            publication_id: publication_id.to_string(),
                        },
                    )
                    .await?;
                let observed = result
                    .objects
                    .iter()
                    .map(|object| (object.path.as_str(), object))
                    .collect::<std::collections::BTreeMap<_, _>>();
                anyhow::ensure!(
                    result.publication_id == publication.publication_id
                        && result.registry == publication.registry
                        && result.generation == publication.generation
                        && result.manifest_digest == publication.manifest_digest
                        && result.refs_digest == publication.refs_digest
                        && result.default_commit == publication.default_commit
                        && result.parent_publication_id == publication.parent_publication_id,
                    "Hub changed the original prepared publication"
                );
                anyhow::ensure!(
                    observed.len() == declared.len()
                        && result.objects.len() == declared.len()
                        && declared
                            .iter()
                            .all(|(path, expected)| observed.get(path).is_some_and(
                                |actual| actual.sha256 == expected.sha256
                                    && actual.byte_size == expected.byte_size
                                    && actual.kind == expected.kind
                                    && actual.media_type == expected.media_type
                                    && (actual.kind == "mutable_pointer" || actual.verified)
                            )),
                    "Hub did not verify the exact complete immutable inventory"
                );
                if let (Some(client), Some((revision, _))) = (&stage_client, stage) {
                    let current = client
                        .upsert(revision, revision.revision, Some(&publication_id))
                        .await?;
                    anyhow::ensure!(
                        current.record.state == aos_registry_surface::staging::StageState::Ready
                            && current.missing_paths.is_empty(),
                        "Hub candidate inventory is not ready"
                    );
                }
                Ok(result)
            }
        }
        .await;
    result.with_context(|| {
        format!(
            "publication {publication_id} remains resumable; rerun this exact upload or abort it explicitly"
        )
    })
}

/// Uploads one publication class with bounded request concurrency.
async fn upload_publication_object_class<'objects>(
    access: &PublicationAccess,
    publication_id: &str,
    root: &std::os::fd::OwnedFd,
    inputs: &[hub_types::RegistryPublicationObjectInput],
    objects: &[&'objects hub_types::RegistryPublicationObject],
    printer: &Printer,
    label: &str,
) -> Result<()> {
    const CONCURRENT_IMMUTABLE_UPLOADS: usize = 32;
    const SNAPSHOT_PERMIT_BYTES: u64 = 1024 * 1024;
    // Cloudflare Durable Objects have a 128 MiB isolate limit. A request body
    // exists in both the Worker stream and the verified Rust buffer while R2
    // accepts it, so bounding client-side snapshots to 32 MiB leaves room for
    // the router, database transport, and provider SDK. Request count is also
    // bounded independently: even tiny uploads retain a Wasm request context
    // until R2 and the publication coordinator confirm the write. The keyed
    // publication-object lookup keeps each remote-SQL response constant-sized;
    // near-limit objects naturally serialize through the byte budget.
    const SNAPSHOT_BUDGET_PERMITS: u32 = 32;
    // Each multipart object sends one part at a time, so its Hub-side body is
    // one part. Four lanes keep the accounted bytes within the snapshot budget
    // while hiding most of the per-part request latency.
    const CONCURRENT_MULTIPART_UPLOADS: usize = 4;

    let snapshot_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(
        SNAPSHOT_BUDGET_PERMITS as usize,
    ));
    let multipart_budget =
        std::sync::Arc::new(tokio::sync::Semaphore::new(CONCURRENT_MULTIPART_UPLOADS));
    let total_bytes =
        objects
            .iter()
            .filter(|object| !object.verified)
            .try_fold(0_u64, |total, object| {
                let size = u64::try_from(object.byte_size)
                    .context("Hub publication response returned a negative object size")?;
                total
                    .checked_add(size)
                    .context("publication byte total overflow")
            })?;
    let progress = printer.transfer(label, total_bytes);
    let transfer_manager =
        std::sync::Arc::new(TransferManager::new(TransferManagerConfig::default()));
    // The first pointer upload opens the durable pointer phase and each
    // placement's pointer advance, so it runs alone. Later pointers refresh
    // the same publication lease and write independent per-object evidence;
    // watermarks move only at commit, which re-verifies every object. Each
    // pointer request costs many sequential Hub database round trips, so a
    // few concurrent requests hide that latency without crowding the Hub.
    const CONCURRENT_POINTER_UPLOADS: usize = 8;
    let pointers = objects
        .iter()
        .any(|object| object.kind == "mutable_pointer");
    let request_concurrency = if pointers {
        CONCURRENT_POINTER_UPLOADS
    } else {
        CONCURRENT_IMMUTABLE_UPLOADS
    };
    let leading = if pointers {
        objects.iter().position(|object| !object.verified)
    } else {
        None
    };

    let inputs = inputs
        .iter()
        .map(|input| (input.path.as_str(), input))
        .collect::<std::collections::BTreeMap<_, _>>();
    // The named lifetime keeps each upload future tied to the objects slice
    // rather than making the closure higher-ranked over its argument.
    let upload_one = |object: &'objects hub_types::RegistryPublicationObject| {
        let declared = inputs.get(object.path.as_str()).copied();
        let snapshot_budget = std::sync::Arc::clone(&snapshot_budget);
        let multipart_budget = std::sync::Arc::clone(&multipart_budget);
        let progress = &progress;
        let transfer_manager = std::sync::Arc::clone(&transfer_manager);
        async move {
            let declared =
                declared.context("Hub publication response introduced an undeclared path")?;
            anyhow::ensure!(
                declared.sha256 == object.sha256
                    && declared.byte_size == object.byte_size
                    && declared.kind == object.kind
                    && declared.media_type == object.media_type,
                "Hub publication response changed the identity of {}",
                object.path
            );
            if object.verified {
                return Ok(());
            }

            let byte_size = u64::try_from(object.byte_size)
                .context("Hub publication response returned a negative object size")?;
            // Multipart snapshots remain on disk. Reserve the one part body a
            // multipart object has in flight at the Hub; its parts are
            // sequential, and the client-side transport copy is local memory.
            let resident_bytes = if object.upload_url.is_empty() {
                byte_size.min(MAX_PUBLICATION_PART_BYTES)
            } else {
                byte_size
            };
            let snapshot_permits = u32::try_from(
                resident_bytes
                    .div_ceil(SNAPSHOT_PERMIT_BYTES)
                    .max(1)
                    .min(u64::from(SNAPSHOT_BUDGET_PERMITS)),
            )
            .context("publication snapshot permit count overflowed")?;
            // Hold the permit across snapshotting and upload so active request
            // buffers remain within the aggregate byte budget.
            let _snapshot_permit = snapshot_budget
                .acquire_many_owned(snapshot_permits)
                .await
                .context("publication snapshot budget closed unexpectedly")?;
            // Bound independent multipart objects as well as their buffers.
            // Each object's parts remain sequential for its SHA-256 state.
            let _multipart_permit = if object.upload_url.is_empty() {
                Some(
                    multipart_budget
                        .acquire_owned()
                        .await
                        .context("publication multipart budget closed unexpectedly")?,
                )
            } else {
                None
            };
            upload_declared_publication_object(
                access,
                publication_id,
                root,
                declared,
                object,
                progress,
                transfer_manager.as_ref(),
            )
            .await
        }
    };
    let result = async {
        if let Some(index) = leading {
            upload_one(objects[index]).await?;
        }
        stream::iter(
            objects
                .iter()
                .enumerate()
                .filter(|(index, _)| Some(*index) != leading)
                .map(|(_, object)| upload_one(*object)),
        )
        .buffer_unordered(request_concurrency)
        .try_collect::<Vec<()>>()
        .await
    }
    .await;
    progress.finish();
    result.map(|_| ())
}

async fn upload_declared_publication_object(
    access: &PublicationAccess,
    publication_id: &str,
    root: &std::os::fd::OwnedFd,
    declared: &hub_types::RegistryPublicationObjectInput,
    object: &hub_types::RegistryPublicationObject,
    progress: &aos_core::output::TransferProgress,
    transfer_manager: &TransferManager,
) -> Result<()> {
    if object.upload_url.is_empty() {
        let file = snapshot_publication_object(root, declared)?;
        upload_publication_multipart(
            transfer_manager,
            access,
            publication_id,
            object,
            file,
            progress,
        )
        .await
        .with_context(|| format!("uploading publication path {}", object.path))
    } else {
        upload_publication_single_object(access, root, declared, object)
            .await
            .with_context(|| format!("uploading publication path {}", object.path))?;
        progress.inc(u64::try_from(object.byte_size)?);
        Ok(())
    }
}

/// Retries transport failures without changing a declared object's bytes.
async fn upload_publication_single_object(
    access: &PublicationAccess,
    root: &std::os::fd::OwnedFd,
    declared: &hub_types::RegistryPublicationObjectInput,
    object: &hub_types::RegistryPublicationObject,
) -> Result<()> {
    let retry = RetryConfig::default();
    let mut attempt = 0;

    loop {
        // Each request owns an independent snapshot and resolves the current
        // profile, so retries neither share stream offsets nor reuse old tokens.
        let file = snapshot_publication_object(root, declared)?;
        let result = publication_client(access)
            .await?
            .upload_publication_object(&object.upload_url, file, &object.path)
            .await;

        match result {
            Ok(()) => return Ok(()),
            Err(error) => {
                attempt += 1;
                let transport_failure = error.chain().any(|cause| {
                    cause
                        .downcast_ref::<reqwest::Error>()
                        .is_some_and(|error| error.is_connect() || error.is_timeout())
                });
                if !transport_failure || attempt >= retry.max_attempts {
                    return Err(error);
                }

                // The declared object endpoint is idempotent even if the
                // previous request stored its bytes before the connection failed.
                tokio::time::sleep(compute_retry_delay(&retry, attempt - 1)).await;
            }
        }
    }
}

async fn publication_client(access: &PublicationAccess) -> Result<HubClient> {
    crate::hub_auth::hub_client(access.hub.as_deref(), access.token.as_deref()).await
}

/// Orders immutable publication objects before mutable entry-point objects.
pub fn publication_objects_in_upload_order(
    publication: &hub_types::RegistryPublication,
) -> Vec<&hub_types::RegistryPublicationObject> {
    let mut objects = publication.objects.iter().collect::<Vec<_>>();
    objects.sort_by_key(|object| object.kind == "mutable_pointer");
    objects
}

struct PublicationMultipartSession {
    upload_id: String,
    part_upload_url: String,
}

struct PublicationMultipartAdapter<'a> {
    access: &'a PublicationAccess,
    publication_id: &'a str,
    object: &'a hub_types::RegistryPublicationObject,
}

#[async_trait::async_trait]
impl MultipartBackend for PublicationMultipartAdapter<'_> {
    type Session = PublicationMultipartSession;
    type Part = ();

    async fn begin(&self, size: u64) -> Result<MultipartAdmission<Self::Session>> {
        anyhow::ensure!(
            u64::try_from(self.object.byte_size)? == size,
            "publication snapshot size changed before multipart admission"
        );
        let admission: hub_types::BeginRegistryPublicationMultipartUploadResponse =
            publication_client(self.access)
                .await?
                .call_topology(
                    HubTopologyMethod::BeginRegistryPublicationMultipartUpload,
                    &hub_types::BeginRegistryPublicationMultipartUploadRequest {
                        publication_id: self.publication_id.into(),
                        object_id: self.object.object_id,
                    },
                )
                .await?;
        let state = match admission.state.as_str() {
            "active" => MultipartSessionState::Active,
            "completing" => MultipartSessionState::Completing,
            _ => anyhow::bail!("Hub returned an invalid publication multipart state"),
        };
        Ok(MultipartAdmission {
            session: PublicationMultipartSession {
                upload_id: admission.upload_id,
                part_upload_url: admission.part_upload_url,
            },
            part_size: admission.part_size,
            next_part_number: admission.next_part_number,
            state,
        })
    }

    async fn upload_part(
        &self,
        session: &Self::Session,
        part_number: u32,
        _offset: u64,
        bytes: aos_net::Bytes,
    ) -> Result<Self::Part> {
        let part = publication_client(self.access)
            .await?
            .upload_publication_part(
                &session.part_upload_url,
                &session.upload_id,
                part_number,
                bytes.to_vec(),
            )
            .await?;
        anyhow::ensure!(
            part.part_number == part_number,
            "Hub returned a mismatched publication multipart part number"
        );
        Ok(())
    }

    async fn complete(&self, session: &Self::Session, _parts: &[Self::Part]) -> Result<()> {
        let _: hub_types::RegistryPublicationMultipartUploadResponse =
            publication_client(self.access)
                .await?
                .complete_registry_publication_multipart_upload(
                    &hub_types::CompleteRegistryPublicationMultipartUploadRequest {
                        upload_id: session.upload_id.clone(),
                        parts: Vec::new(),
                    },
                )
                .await
                .context("completing publication multipart upload")?;
        Ok(())
    }

    async fn abort(&self, session: &Self::Session) -> Result<()> {
        let _: hub_types::RegistryPublicationMultipartUploadResponse =
            publication_client(self.access)
                .await?
                .call_topology(
                    HubTopologyMethod::AbortRegistryPublicationMultipartUpload,
                    &hub_types::AbortRegistryPublicationMultipartUploadRequest {
                        upload_id: session.upload_id.clone(),
                    },
                )
                .await?;
        Ok(())
    }
}

struct PublicationMultipartObserver<'a> {
    progress: &'a aos_core::output::TransferProgress,
    position: std::sync::atomic::AtomicU64,
}

impl PublicationMultipartObserver<'_> {
    fn advance_to(&self, position: u64) {
        let previous = self
            .position
            .swap(position, std::sync::atomic::Ordering::Relaxed);
        self.progress.inc(position.saturating_sub(previous));
    }
}

impl TransferObserver for PublicationMultipartObserver<'_> {
    fn observe(&self, event: TransferEvent<'_>) {
        match event {
            TransferEvent::Started { resumed_bytes, .. } => self.advance_to(resumed_bytes),
            TransferEvent::Progress {
                transferred_bytes, ..
            }
            | TransferEvent::Completed {
                transferred_bytes, ..
            } => self.advance_to(transferred_bytes),
            TransferEvent::Retrying { delay, error, .. } => self.progress.warning(&format!(
                "publication transfer interrupted ({error:#}); retrying in {}s",
                delay.as_secs()
            )),
            TransferEvent::Verifying { .. } | TransferEvent::Failed { .. } => {}
        }
    }
}

async fn upload_publication_multipart(
    manager: &TransferManager,
    access: &PublicationAccess,
    publication_id: &str,
    object: &hub_types::RegistryPublicationObject,
    file: std::fs::File,
    progress: &aos_core::output::TransferProgress,
) -> Result<()> {
    const MAX_CLIENT_PARTS: u32 = 10_000;

    let adapter = PublicationMultipartAdapter {
        access,
        publication_id,
        object,
    };
    let request = MultipartUploadRequest::new(
        format!("hub-publication:{}", object.path),
        MultipartSource::file(file),
    )
    .with_concurrency(1)
    .with_maximum_in_flight_bytes(MAX_PUBLICATION_PART_BYTES)
    .with_part_limits(1, MAX_PUBLICATION_PART_BYTES, MAX_CLIENT_PARTS)
    .with_failure_policy(MultipartFailurePolicy::Preserve);
    let observer = PublicationMultipartObserver {
        progress,
        position: std::sync::atomic::AtomicU64::new(0),
    };
    manager
        .upload_multipart_observed(request, &adapter, &observer)
        .await?;
    Ok(())
}

async fn bind_publication_parent(
    client: &HubClient,
    request: &mut hub_types::BeginRegistryPublicationRequest,
) -> Result<()> {
    if !request.parent_publication_id.is_empty() {
        return Ok(());
    }
    let publications: hub_types::ListRegistryPublicationsResponse = client
        .call_topology(
            HubTopologyMethod::ListRegistryPublications,
            &hub_types::ListRegistryPublicationsRequest {
                registry: request.registry.clone(),
                state: "ready".into(),
                page_size: 100,
                page_token: String::new(),
            },
        )
        .await?;
    if let Some(existing) = publications
        .publications
        .iter()
        .find(|publication| publication.generation == request.generation)
    {
        request.parent_publication_id = existing.parent_publication_id.clone();
    } else if let Some(current) = publications.publications.first() {
        request.parent_publication_id = current.publication_id.clone();
    }
    Ok(())
}

pub async fn begin_registry_publication_chunked(
    client: &HubClient,
    request: &hub_types::BeginRegistryPublicationRequest,
) -> Result<hub_types::RegistryPublication> {
    const MANIFEST_CHUNK_OBJECTS: usize = 256;

    let mut objects = request.objects.clone();
    objects.sort_by(|left, right| left.path.cmp(&right.path));
    anyhow::ensure!(
        !objects.is_empty() && objects.len() <= MAX_PUBLICATION_OBJECTS,
        "publication manifest requires 1..={MAX_PUBLICATION_OBJECTS} objects"
    );
    let manifest_digest = publication_manifest_digest(&objects)?;
    let mut session: hub_types::RegistryPublicationManifestSession = client
        .call_topology(
            HubTopologyMethod::BeginRegistryPublicationManifest,
            &hub_types::BeginRegistryPublicationManifestRequest {
                registry: request.registry.clone(),
                generation: request.generation.clone(),
                refs_digest: request.refs_digest.clone(),
                default_commit: request.default_commit.clone(),
                parent_publication_id: request.parent_publication_id.clone(),
                manifest_digest,
                object_count: u32::try_from(objects.len())?,
            },
        )
        .await?;
    anyhow::ensure!(
        usize::try_from(session.object_count)? == objects.len(),
        "Hub publication session changed the declared object count"
    );
    let admitted = usize::try_from(session.admitted_object_count)?;
    anyhow::ensure!(
        admitted <= objects.len(),
        "Hub publication session has an invalid continuation cursor"
    );

    for chunk in objects[admitted..].chunks(MANIFEST_CHUNK_OBJECTS) {
        let expected_count = session
            .admitted_object_count
            .checked_add(u32::try_from(chunk.len())?)
            .context("publication manifest progress overflowed")?;
        session = client
            .call_topology(
                HubTopologyMethod::AppendRegistryPublicationManifest,
                &hub_types::AppendRegistryPublicationManifestRequest {
                    publication_id: session.publication_id.clone(),
                    lease_token: session.lease_token.clone(),
                    chunk_index: session.next_chunk_index,
                    chunk_digest: publication_manifest_chunk_digest(chunk)?,
                    objects: chunk.to_vec(),
                },
            )
            .await?;
        anyhow::ensure!(
            session.admitted_object_count == expected_count,
            "Hub publication session did not advance by the appended chunk"
        );
    }
    anyhow::ensure!(
        session.admitted_object_count == session.object_count,
        "Hub publication session remains incomplete"
    );
    client
        .call_topology(
            HubTopologyMethod::SealRegistryPublicationManifest,
            &hub_types::SealRegistryPublicationManifestRequest {
                publication_id: session.publication_id,
                lease_token: session.lease_token,
            },
        )
        .await
}

fn publication_manifest_digest(
    objects: &[hub_types::RegistryPublicationObjectInput],
) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    let mut canonical = objects
        .iter()
        .map(|object| {
            (
                &object.path,
                &object.sha256,
                object.byte_size,
                &object.kind,
                &object.media_type,
            )
        })
        .collect::<Vec<_>>();
    canonical.sort();
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical)?)
    ))
}

fn publication_manifest_chunk_digest(
    objects: &[hub_types::RegistryPublicationObjectInput],
) -> Result<String> {
    use sha2::{Digest as _, Sha256};

    let canonical = objects
        .iter()
        .map(|object| {
            (
                &object.path,
                &object.sha256,
                object.byte_size,
                &object.kind,
                &object.media_type,
            )
        })
        .collect::<Vec<_>>();
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&canonical)?)
    ))
}

pub mod inventory;

#[cfg(test)]
mod transport_tests;
