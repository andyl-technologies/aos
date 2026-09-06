//! Uploads registry publications through staged objects, multipart transfers, and commits.

use crate::cli::{HubAccessArgs, HubPublishCmd};
use crate::commands::hub::client::hub_client;
use crate::commands::hub::mutation::topology_read;
use crate::commands::hub::output::print_topology_message;
use crate::commands::hub::publication::inventory::{
    MAX_PUBLICATION_OBJECTS, pinned_publication_from_root, publication_from_root,
    publication_manifest_request, snapshot_publication_object,
};
use anyhow::{Context as _, Result};
use aos_core::output::Printer;
use aos_net::{
    MultipartAdmission, MultipartBackend, MultipartFailurePolicy, MultipartSessionState,
    MultipartSource, MultipartUploadRequest, TransferEvent, TransferManager, TransferManagerConfig,
    TransferObserver,
};
use aos_remote::{HubClient, hub_rpc as HubTopologyMethod, hub_types};
use futures_util::stream;
use futures_util::stream::{StreamExt as _, TryStreamExt as _};

/// Handles the hub publish command family through the public API.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(in crate::commands::hub) async fn publish(
    printer: &Printer,
    command: &HubPublishCmd,
) -> Result<()> {
    match command {
        HubPublishCmd::List {
            access,
            registry,
            state,
            pagination,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::ListRegistryPublicationsResponse>(
                printer,
                &client,
                HubTopologyMethod::ListRegistryPublications,
                &hub_types::ListRegistryPublicationsRequest {
                    registry: registry.clone(),
                    state: state.clone().unwrap_or_default(),
                    page_size: pagination.page_size.unwrap_or_default(),
                    page_token: pagination.page_token.clone().unwrap_or_default(),
                },
            )
            .await
        }
        HubPublishCmd::Upload {
            access,
            registry,
            manifest,
            root,
        } => {
            let committed =
                upload_registry_publication(access, registry, manifest.as_deref(), root, printer)
                    .await?;
            print_topology_message(printer, &committed)
        }
        HubPublishCmd::Begin {
            access,
            registry,
            manifest,
        } => {
            let request = publication_manifest_request(manifest, registry)?;
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            let publication = begin_registry_publication_chunked(&client, &request).await?;
            print_topology_message(printer, &publication)
        }
        HubPublishCmd::Show {
            access,
            publication_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::RegistryPublication>(
                printer,
                &client,
                HubTopologyMethod::GetRegistryPublication,
                &hub_types::GetRegistryPublicationRequest {
                    publication_id: publication_id.clone(),
                },
            )
            .await
        }
        HubPublishCmd::Commit {
            access,
            publication_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::RegistryPublication>(
                printer,
                &client,
                HubTopologyMethod::CommitRegistryPublication,
                &hub_types::CommitRegistryPublicationRequest {
                    publication_id: publication_id.clone(),
                },
            )
            .await
        }
        HubPublishCmd::Abort {
            access,
            publication_id,
        } => {
            let client = hub_client(&access.hub, access.token.as_deref()).await?;
            topology_read::<_, hub_types::RegistryPublication>(
                printer,
                &client,
                HubTopologyMethod::AbortRegistryPublication,
                &hub_types::AbortRegistryPublicationRequest {
                    publication_id: publication_id.clone(),
                },
            )
            .await
        }
    }
}

/// Uploads and commits one exact registry surface without advancing a channel.
///
/// Release orchestration reuses this bounded publication primitive after it
/// has independently verified the destination deployment and closed bundle.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(crate) async fn upload_registry_publication(
    access: &HubAccessArgs,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
) -> Result<hub_types::RegistryPublication> {
    upload_registry_publication_with_commit(access, registry, manifest, root, printer, true).await
}

/// Uploads one exact registry surface while leaving its mutable commit to a
/// release-scoped compare-and-swap RPC.
///
/// # Errors
///
/// Returns an error if request validation, credential resolution, or a hub API call fails.
pub(crate) async fn prepare_registry_publication(
    access: &HubAccessArgs,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
) -> Result<hub_types::RegistryPublication> {
    upload_registry_publication_with_commit(access, registry, manifest, root, printer, false).await
}

async fn upload_registry_publication_with_commit(
    access: &HubAccessArgs,
    registry: &str,
    manifest: Option<&std::path::Path>,
    root: &std::path::Path,
    printer: &Printer,
    commit: bool,
) -> Result<hub_types::RegistryPublication> {
    let mut pinned = match manifest {
        Some(manifest) => {
            let request = publication_manifest_request(manifest, registry)?;
            pinned_publication_from_root(root, request)?
        }
        None => publication_from_root(root, registry)?,
    };
    let client = publication_client(access).await?;
    bind_publication_parent(&client, &mut pinned.request).await?;
    let publication = begin_registry_publication_chunked(&client, &pinned.request).await?;
    let publication_id = publication.publication_id.clone();
    let result: Result<hub_types::RegistryPublication> = async {
        anyhow::ensure!(
            publication.objects.len() == pinned.request.objects.len(),
            "Hub publication response changed the declared object count"
        );
        let objects = publication_objects_in_upload_order(&publication);
        let pointer_start = objects.partition_point(|object| object.kind != "mutable_pointer");
        let (immutable_objects, pointer_objects) = objects.split_at(pointer_start);

        upload_publication_object_class(
            &client,
            access,
            &publication_id,
            &pinned.root,
            &pinned.request.objects,
            immutable_objects,
            printer,
            "Uploading immutable publication objects",
        )
        .await?;
        upload_publication_object_class(
            &client,
            access,
            &publication_id,
            &pinned.root,
            &pinned.request.objects,
            pointer_objects,
            printer,
            "Uploading publication pointers",
        )
        .await?;
        let client = publication_client(access).await?;
        if commit {
            client
                .call_topology(
                    HubTopologyMethod::CommitRegistryPublication,
                    &hub_types::CommitRegistryPublicationRequest {
                        publication_id: publication_id.to_string(),
                    },
                )
                .await
        } else {
            client
                .call_topology(
                    HubTopologyMethod::GetRegistryPublication,
                    &hub_types::GetRegistryPublicationRequest {
                        publication_id: publication_id.to_string(),
                    },
                )
                .await
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
async fn upload_publication_object_class(
    client: &HubClient,
    access: &HubAccessArgs,
    publication_id: &str,
    root: &std::os::fd::OwnedFd,
    inputs: &[hub_types::RegistryPublicationObjectInput],
    objects: &[&hub_types::RegistryPublicationObject],
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
    const CONCURRENT_MULTIPART_UPLOADS: usize = 1;

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
    // Mutable pointers share one publication lease and advance placement
    // watermarks. Serialize them so independent HTTP requests cannot race the
    // durable pointer-phase transition; immutable content remains parallel.
    let request_concurrency = if objects
        .iter()
        .any(|object| object.kind == "mutable_pointer")
    {
        1
    } else {
        CONCURRENT_IMMUTABLE_UPLOADS
    };

    let result = stream::iter(objects.iter().copied().map(|object| {
        let declared = inputs.iter().find(|declared| declared.path == object.path);
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
            let snapshot_permits = u32::try_from(
                byte_size
                    .div_ceil(SNAPSHOT_PERMIT_BYTES)
                    .max(1)
                    .min(u64::from(SNAPSHOT_BUDGET_PERMITS)),
            )
            .context("publication snapshot permit count overflowed")?;
            // The permit is held across snapshotting and upload. Objects larger
            // than the aggregate budget run exclusively; smaller snapshots can
            // overlap only while their declared sizes fit the byte budget.
            let _snapshot_permit = snapshot_budget
                .acquire_many_owned(snapshot_permits)
                .await
                .context("publication snapshot budget closed unexpectedly")?;
            // Multipart requests carry one bounded part buffer and load the
            // publication coordinator's durable state. Serialize them so a
            // large manifest cannot amplify coordinator memory use.
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
                client,
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
    }))
    .buffer_unordered(request_concurrency)
    .try_collect::<Vec<()>>()
    .await;
    progress.finish();
    result.map(|_| ())
}

async fn upload_declared_publication_object(
    client: &HubClient,
    access: &HubAccessArgs,
    publication_id: &str,
    root: &std::os::fd::OwnedFd,
    declared: &hub_types::RegistryPublicationObjectInput,
    object: &hub_types::RegistryPublicationObject,
    progress: &aos_core::output::TransferProgress,
    transfer_manager: &TransferManager,
) -> Result<()> {
    let file = snapshot_publication_object(root, declared)?;
    if object.upload_url.is_empty() {
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
        client
            .upload_publication_object(&object.upload_url, file, &object.path)
            .await
            .with_context(|| format!("uploading publication path {}", object.path))?;
        progress.inc(u64::try_from(object.byte_size)?);
        Ok(())
    }
}

async fn publication_client(access: &HubAccessArgs) -> Result<HubClient> {
    hub_client(&access.hub, access.token.as_deref()).await
}

/// Orders immutable publication objects before mutable entry-point objects.
pub(in crate::commands::hub) fn publication_objects_in_upload_order(
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
    access: &'a HubAccessArgs,
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
    access: &HubAccessArgs,
    publication_id: &str,
    object: &hub_types::RegistryPublicationObject,
    file: std::fs::File,
    progress: &aos_core::output::TransferProgress,
) -> Result<()> {
    const MAX_CLIENT_PART_BYTES: u64 = 20 * 1024 * 1024;
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
    .with_maximum_in_flight_bytes(MAX_CLIENT_PART_BYTES)
    .with_part_limits(1, MAX_CLIENT_PART_BYTES, MAX_CLIENT_PARTS)
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

async fn begin_registry_publication_chunked(
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

mod inventory;
