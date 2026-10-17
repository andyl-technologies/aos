//! Durable bounded publication manifest admission before direct provider work.
//!
//! Exact Begin replay resolves the existing registry+generation owner. Append
//! retries bind original chunk index/digest; sealed publication queries contain
//! inventory metadata only. Unknown admission never selects a new generation.

use aos_net::direct_upload::{DirectClientError, DirectPublicationHeader};
use aos_proto_types::direct_upload::encode_direct_control;
use aos_proto_types::*;
use sha2::{Digest as _, Sha256};

use super::publication_identity::{PublicationControl, PublicationTransferDiscovery};
use super::{
    super::{HubClient, HubTopologyMethod},
    DirectHubControl, DirectUploadCoordinator, DirectUploadOptions,
};

const MAX_OBJECTS: usize = 50_000;
const MAX_INVENTORY_REPLY: usize = 64 * 1024 * 1024;

/// Hashes the existing canonical sorted publication tuple manifest.
///
/// # Errors
/// Refuses empty/excessive inventory or invalid exact source/geometry/path fields.
pub fn publication_inventory_digest(
    objects: &[RegistryPublicationObjectInput],
) -> Result<String, DirectClientError> {
    if objects.is_empty() || objects.len() > MAX_OBJECTS {
        return Err(DirectClientError::Invalid);
    }
    let mut entries = Vec::with_capacity(objects.len());
    let mut names = std::collections::BTreeSet::new();
    for object in objects {
        if object.path.is_empty()
            || object.path.len() > 4096
            || object.path.starts_with('/')
            || object
                .path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || object.path.chars().any(char::is_control)
            || !names.insert(&object.path)
            || !direct_upload::valid_direct_digest(&object.sha256)
            || object.byte_size < 0
            || object.byte_size as u64 > direct_upload::MAX_DIRECT_OBJECT_BYTES
            || !matches!(object.kind.as_str(), "immutable" | "mutable_pointer")
            || object.media_type.len() > 255
        {
            return Err(DirectClientError::Invalid);
        }
        entries.push((
            &object.path,
            &object.sha256,
            object.byte_size,
            &object.kind,
            &object.media_type,
        ));
    }
    entries.sort();
    let mut digest = Sha256::new();
    serde_json::to_writer(&mut DigestWriter(&mut digest), &entries)
        .map_err(|_| DirectClientError::Invalid)?;
    Ok(hex::encode(digest.finalize()))
}

/// Retains a publication with its server-proved original pre-admission actor.
///
/// This is metadata admission only. It does not prove provider work, graph
/// closure or public visibility. Actor identifiers are never locally decoded JWTs.
pub struct PreparedDirectPublication {
    /// Original sealed metadata inventory and logical publication owner.
    pub publication: RegistryPublication,
    /// Server-proved original deployment namespace.
    pub deployment_id: String,
    /// Server-proved original immutable actor commitment.
    pub principal_id: String,
}

impl PreparedDirectPublication {
    /// Reconciles full target capabilities with the original admitted identity.
    ///
    /// # Errors
    /// Refuses another deployment, actor or publication owner before provider work.
    pub fn validate_capabilities(
        &self,
        capabilities: &direct_upload::DirectUploadCapabilities,
    ) -> Result<(), DirectClientError> {
        if capabilities.deployment_id != self.deployment_id
            || capabilities.principal_id != self.principal_id
            || capabilities.target
                != (direct_upload::DirectCapabilitiesTarget::Publication {
                    publication_id: self.publication.publication_id.clone(),
                })
        {
            return Err(DirectClientError::Invalid);
        }
        Ok(())
    }

    /// Opens provider staging only after fresh target discovery matches admission.
    ///
    /// The returned control owns the exact bearer whose target/actor was proved.
    /// Renewed authentication never changes the admitted logical publication.
    ///
    /// # Errors
    /// Refuses another origin, actor, deployment, target or transport policy,
    /// unavailable discovery, unsafe provider policy or private journal failure.
    pub async fn open_coordinator(
        &self,
        original: &HubClient,
        options: &DirectUploadOptions,
    ) -> Result<DirectUploadCoordinator, DirectClientError> {
        let hub = match &options.authentication {
            Some(provider) => provider.authenticate(&original.base).await?,
            None => original.clone(),
        };
        if hub.base != original.base {
            return Err(DirectClientError::Invalid);
        }
        let caps = DirectHubControl::new(&hub)?
            .with_metrics(options.metrics.clone())
            .capabilities(&direct_upload::DirectCapabilitiesTarget::Publication {
                publication_id: self.publication.publication_id.clone(),
            })
            .await?;
        self.validate_capabilities(&caps)?;
        options.open(&hub, caps).await
    }
}

impl std::fmt::Debug for PreparedDirectPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedDirectPublication([authenticated metadata])")
    }
}

struct DigestWriter<'a>(&'a mut Sha256);
impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Prepares one original full manifest with private before-effect retry custody.
///
/// Uses the existing metadata-only Native manifest APIs. No provider work or
/// public object visibility is authorized here. Inventory responses are bounded
/// at64 MiB before decoding; per-page requests are at most64 objects/256 KiB.
/// The final direct adapter still needs authenticated discovery and full closure.
///
/// # Errors
/// Refuses changed original source/parent/owner, malformed progress, unknown
/// admission, stale credentials, oversized controls or local journal failures.
pub async fn prepare_direct_publication(
    hub: &HubClient,
    request: &BeginRegistryPublicationRequest,
    options: &DirectUploadOptions,
    discovery: &PublicationTransferDiscovery,
) -> Result<PreparedDirectPublication, DirectClientError> {
    let control = PublicationControl::new(hub, options).await?;
    if !discovery.matches(&control.identity) {
        return Err(DirectClientError::Invalid);
    }
    let registry: GetRegistryResponse = control
        .call(
            HubTopologyMethod::GetRegistry,
            &GetRegistryRequest {
                slug: request.registry.clone(),
            },
            MAX_INVENTORY_REPLY,
        )
        .await?;
    let registry = registry.registry.ok_or(DirectClientError::Invalid)?;
    if !direct_upload::valid_direct_identity(&registry.stable_id) || registry.slug.is_empty() {
        return Err(DirectClientError::Invalid);
    }
    let manifest = publication_inventory_digest(&request.objects)?;
    let journal = options
        .publication_journal(hub, &request.registry, &request.generation)
        .await?;
    let mut header = DirectPublicationHeader {
        registry: registry.slug.clone(),
        registry_stable_id: registry.stable_id.clone(),
        deployment_id: control.identity.deployment.clone(),
        principal_id: control.identity.principal.clone(),
        generation: request.generation.clone(),
        refs_digest: request.refs_digest.clone(),
        default_commit: request.default_commit.clone(),
        parent_publication_id: request.parent_publication_id.clone(),
        manifest_digest: manifest,
        object_count: request.objects.len() as u32,
    };
    if let Some(original) = journal.publication_header().await? {
        if header.parent_publication_id.is_empty() {
            header.parent_publication_id = original.parent_publication_id;
        }
    } else if header.parent_publication_id.is_empty() {
        let existing: ListRegistryPublicationsResponse = control
            .call(
                HubTopologyMethod::ListRegistryPublications,
                &ListRegistryPublicationsRequest {
                    registry: request.registry.clone(),
                    state: "ready".into(),
                    page_size: 1,
                    page_token: String::new(),
                },
                MAX_INVENTORY_REPLY,
            )
            .await?;
        if let Some(current) = existing.publications.first() {
            header.parent_publication_id = current.publication_id.clone();
        }
    }
    journal.retain_publication_header(&header).await?;
    let begin = BeginRegistryPublicationManifestRequest {
        registry: header.registry.clone(),
        generation: header.generation.clone(),
        refs_digest: header.refs_digest.clone(),
        default_commit: header.default_commit.clone(),
        parent_publication_id: header.parent_publication_id.clone(),
        manifest_digest: header.manifest_digest.clone(),
        object_count: header.object_count,
    };
    let session: RegistryPublicationManifestSession = control
        .call(
            HubTopologyMethod::BeginRegistryPublicationManifest,
            &begin,
            direct_upload::MAX_DIRECT_CONTROL_BYTES,
        )
        .await?;
    let mut session = journal
        .retain_publication_admission(&session)
        .await?
        .reply();
    let mut objects = request.objects.clone();
    objects.sort_by(|left, right| left.path.cmp(&right.path));
    let mut admitted = session.admitted_object_count as usize;
    while admitted < objects.len() {
        let end = (admitted + 64).min(objects.len());
        let mut chunk = objects[admitted..end].to_vec();
        let mut append = AppendRegistryPublicationManifestRequest {
            publication_id: session.publication_id.clone(),
            lease_token: session.lease_token.clone(),
            chunk_index: session.next_chunk_index,
            chunk_digest: publication_inventory_digest(&chunk)?,
            objects: chunk.clone(),
        };
        while encode_direct_control(&append).is_err() {
            if chunk.len() <= 1 {
                return Err(DirectClientError::Invalid);
            }
            chunk.truncate(chunk.len() / 2);
            append.objects = chunk.clone();
            append.chunk_digest = publication_inventory_digest(&chunk)?;
        }
        let expected = admitted + chunk.len();
        let reply: RegistryPublicationManifestSession = control
            .call(
                HubTopologyMethod::AppendRegistryPublicationManifest,
                &append,
                direct_upload::MAX_DIRECT_CONTROL_BYTES,
            )
            .await?;
        if reply.admitted_object_count as usize != expected {
            return Err(DirectClientError::Invalid);
        }
        session = journal.retain_publication_admission(&reply).await?.reply();
        admitted = expected;
    }
    let publication: RegistryPublication = control
        .call(
            HubTopologyMethod::SealRegistryPublicationManifest,
            &SealRegistryPublicationManifestRequest {
                publication_id: session.publication_id.clone(),
                lease_token: session.lease_token,
            },
            MAX_INVENTORY_REPLY,
        )
        .await?;
    if publication.publication_id != session.publication_id
        || publication.manifest_digest != header.manifest_digest
        || publication.generation != header.generation
        || publication.registry != header.registry
        || publication.refs_digest != header.refs_digest
        || publication.default_commit != header.default_commit
        || publication.objects.len() != objects.len()
        || publication.parent_publication_id != header.parent_publication_id
    {
        return Err(DirectClientError::Invalid);
    }
    Ok(PreparedDirectPublication {
        publication,
        deployment_id: control.identity.deployment.clone(),
        principal_id: control.identity.principal.clone(),
    })
}

/// Commits the original publication only after the caller's staging barrier.
///
/// This repeats one metadata-only publication owner, never a new provider
/// effect or generation. Native remains responsible for final graph authority.
///
/// # Errors
/// Refuses changed owner, invalid final state, failed authentication or control.
pub async fn commit_direct_publication(
    hub: &HubClient,
    prepared: &PreparedDirectPublication,
    options: &DirectUploadOptions,
) -> Result<RegistryPublication, DirectClientError> {
    let control = PublicationControl::new(hub, options).await?;
    if control.identity.deployment != prepared.deployment_id
        || control.identity.principal != prepared.principal_id
    {
        return Err(DirectClientError::Invalid);
    }
    let publication_id = &prepared.publication.publication_id;
    let reply: RegistryPublication = control
        .call(
            HubTopologyMethod::CommitRegistryPublication,
            &CommitRegistryPublicationRequest {
                publication_id: publication_id.to_owned(),
            },
            MAX_INVENTORY_REPLY,
        )
        .await?;
    if reply.publication_id.as_str() != publication_id.as_str()
        || reply.state != "ready"
        || reply.registry != prepared.publication.registry
        || reply.generation != prepared.publication.generation
        || reply.manifest_digest != prepared.publication.manifest_digest
        || reply.refs_digest != prepared.publication.refs_digest
        || reply.default_commit != prepared.publication.default_commit
        || reply.parent_publication_id != prepared.publication.parent_publication_id
        || reply.objects.len() != prepared.publication.objects.len()
    {
        return Err(DirectClientError::Invalid);
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_of_small_metadata_objects_use_exact_server_tuple_digest_and_reject_duplicates() {
        let mut objects = (0..12_535)
            .map(|number| RegistryPublicationObjectInput {
                path: format!("cache/{number:05}.narinfo"),
                sha256: format!("{number:064x}"),
                byte_size: 128,
                kind: "mutable_pointer".into(),
                media_type: "text/x-nix-narinfo".into(),
            })
            .collect::<Vec<_>>();
        let original = publication_inventory_digest(&objects).unwrap();
        let expected = hex::encode(Sha256::digest(
            serde_json::to_vec(
                &objects
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
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        ));
        assert_eq!(original, expected);
        objects.reverse();
        assert_eq!(publication_inventory_digest(&objects).unwrap(), original);
        objects[0].sha256 = "ff".repeat(32);
        assert_ne!(publication_inventory_digest(&objects).unwrap(), original);
        objects.push(objects[0].clone());
        assert!(publication_inventory_digest(&objects).is_err());
    }
}
