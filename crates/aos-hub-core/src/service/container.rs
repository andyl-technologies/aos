//! Verified OCI container publication control plane.
//!
//! Standard Distribution uploads make bytes available to a repository. These
//! methods separately freeze the complete signed AOS release graph, its exact
//! placement evidence, and an optional tag compare-and-swap before exposing a
//! verified release root.

use aos_oci_types::{
    to_canonical_json, ContainerRelease, Descriptor, RepositoryName, Sha256Digest, Tag,
};
use aos_proto_types as pb;

use super::{clock, Permission, RpcError, RpcService};
use crate::db::{
    oci_blob_object_key, oci_catalog_declaration_digest, oci_publication_confirmation_hash,
    AddOciPublicationObject, BeginOciPublication, ContainerReleaseDescriptorRole, OciCatalogObject,
    OciCatalogProjection, OciPublicationRecord, OciPublicationRequiredPlacement,
    OCI_MAX_SESSION_SECONDS,
};

impl RpcService {
    /// Begins verified admission of one complete, already-uploaded container graph.
    ///
    /// # Errors
    ///
    /// Returns an authorization error when the caller lacks registry publish
    /// authority, an invalid-argument error for a noncanonical or unsupported
    /// release declaration, a failed-precondition error for an incomplete
    /// graph or placement, or an internal error for database failure.
    pub async fn begin_container_publication(
        &self,
        auth: Option<&str>,
        req: pb::BeginContainerPublicationRequest,
    ) -> Result<pb::ContainerPublication, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;

        let repository_name = RepositoryName::parse(&req.repository)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        if repository_name.as_str() != "aos" {
            return Err(RpcError::invalid(
                "the initial container catalog admits only repository 'aos'",
            ));
        }
        let repository = self
            .db
            .oci_repository(registry.id, &repository_name)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container repository"))?;
        let release = ContainerRelease::from_json(&req.container_release_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let canonical = to_canonical_json(&release).map_err(RpcError::internal)?;
        if canonical != req.container_release_json {
            return Err(RpcError::invalid(
                "container release declaration must use canonical JSON",
            ));
        }
        validate_initial_release(&release)?;
        let sidecar_sha256_hex = Sha256Digest::digest(&canonical).encoded();

        let target_tag = parse_optional_tag(&req.target_tag)?;
        let expected_tag_version = parse_optional_version(&req.expected_tag_resource_version)?;
        let expected_tag_digest = parse_optional_digest(&req.expected_tag_digest)?;
        if expected_tag_digest.is_some() && expected_tag_version.is_none() {
            return Err(RpcError::invalid(
                "expectedTagDigest requires expectedTagResourceVersion",
            ));
        }
        if req.idempotency_key.is_empty() || req.idempotency_key.len() > 128 {
            return Err(RpcError::invalid(
                "idempotencyKey must contain 1..128 bytes",
            ));
        }

        if !matches!(req.target_kind.as_str(), "release" | "channel") {
            return Err(RpcError::invalid("targetKind must be release or channel"));
        }
        let placements = self
            .db
            .registry_publication_write_placements(registry.id)
            .await
            .map_err(RpcError::internal)?;
        if placements.is_empty() {
            return Err(RpcError::FailedPrecondition(
                "container publication has no required ready write placements".to_string(),
            ));
        }
        let mut required_placements = Vec::with_capacity(placements.len());
        for placement in &placements {
            let revision = self
                .db
                .placement_publication_write_revision(placement.id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::FailedPrecondition(format!(
                        "container placement {} lost its validated write revision",
                        placement.name
                    ))
                })?;
            required_placements.push(OciPublicationRequiredPlacement {
                placement_id: placement.id,
                placement_resource_version: placement.resource_version,
                placement_write_spec_version: placement.write_spec_version,
                placement_observation_version: placement.observation_version.ok_or_else(|| {
                    RpcError::FailedPrecondition(format!(
                        "container placement {} lacks a ready observation",
                        placement.name
                    ))
                })?,
                binding_id: revision.binding_id,
                binding_write_revision: revision.revision,
                revision_fingerprint: revision.revision_fingerprint,
                capability_fingerprint: revision.capability_fingerprint,
            });
        }
        let roots = release_roots(&release);
        let graph = self
            .db
            .oci_repository_closed_graph(repository.id, &roots)
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        validate_release_graph(&release, &graph)?;
        let catalog_digest = oci_catalog_declaration_digest(release.oci.index.digest, &graph)
            .map_err(RpcError::internal)?;
        let current = clock::now_unix_secs();
        let begin = BeginOciPublication {
            registry_id: registry.id,
            repository_id: repository.id,
            writer_id: claims.sub.clone(),
            token_id: claims.sub.clone(),
            target_tag,
            expected_tag_version,
            expected_tag_digest,
            root_digest: release.oci.index.digest,
            catalog_digest,
            required_placements,
            source_kind: req.target_kind,
            release_tag: Some(release.identity.release.clone()),
            sidecar_sha256_hex: Some(sidecar_sha256_hex),
            idempotency_key: req.idempotency_key,
            now: current,
            expires_at: current + OCI_MAX_SESSION_SECONDS,
        };
        let mut publication = self
            .db
            .begin_oci_publication(&begin)
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;

        for object in &graph {
            for placement in &placements {
                let evidence = self
                    .db
                    .oci_release_descriptor_placement(
                        repository.id,
                        placement.id,
                        descriptor_role(&release, &object.descriptor),
                        &object.descriptor,
                    )
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::FailedPrecondition(format!(
                            "container object {} lacks exact evidence on required placement {}",
                            object.descriptor.digest, placement.name
                        ))
                    })?;
                publication = self
                    .db
                    .add_oci_publication_object(
                        &AddOciPublicationObject {
                            publication_id: publication.id.clone(),
                            writer_id: claims.sub.clone(),
                            token_id: claims.sub.clone(),
                            expected_resource_version: publication.resource_version,
                            descriptor: object.descriptor.clone(),
                            object_kind: if object.descriptor.media_type.is_image_manifest()
                                || object.descriptor.media_type.is_image_index()
                            {
                                "manifest".to_string()
                            } else {
                                "blob".to_string()
                            },
                            object_key: oci_blob_object_key(object.descriptor.digest),
                            projection_json: projection_json(object)?,
                            surface_object_id: evidence.surface_object_id,
                            placement_id: evidence.placement_id,
                            object_resource_version: evidence.object_resource_version,
                            placement_resource_version: evidence.placement_resource_version,
                            placement_observation_version: evidence.placement_observation_version,
                            observed_inventory_generation: evidence.observed_inventory_generation,
                            observed_etag: evidence.strong_etag,
                            observed_at: evidence.observed_at,
                        },
                        current,
                    )
                    .await
                    .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            }
        }

        self.container_publication_response(&registry.slug, &repository.name, &publication)
    }

    /// Returns one publication owned by the authenticated publisher.
    ///
    /// # Errors
    ///
    /// Returns authentication, authorization, not-found, or database errors.
    pub async fn get_container_publication(
        &self,
        auth: Option<&str>,
        req: pb::GetContainerPublicationRequest,
    ) -> Result<pb::ContainerPublication, RpcError> {
        if !req.registry.is_empty() {
            let registry = self
                .container_registry_for_publication_read(auth, &req.registry)
                .await?;
            let publication = self
                .db
                .oci_admin_publication(registry.id, &req.publication_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("container publication"))?;
            return Ok(super::container_admin::publication_message(
                &registry.slug,
                &publication,
            ));
        }
        let claims = self.require_claims(auth)?;
        let publication = self
            .db
            .oci_publication(
                &req.publication_id,
                &claims.sub,
                &claims.sub,
                clock::now_unix_secs(),
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container publication"))?;
        let (registry, repository) = self
            .authorize_container_publication(&claims, &publication)
            .await?;
        self.container_publication_response(&registry.slug, &repository.name, &publication)
    }

    /// Atomically commits a frozen graph, verified root, and optional tag.
    ///
    /// # Errors
    ///
    /// Returns an authorization or not-found error, an invalid-argument error
    /// for malformed concurrency inputs, a failed-precondition error when the
    /// reviewed graph or placement changed, or an internal database error.
    pub async fn commit_container_publication(
        &self,
        auth: Option<&str>,
        req: pb::CommitContainerPublicationRequest,
    ) -> Result<pb::ContainerPublication, RpcError> {
        let claims = self.require_claims(auth)?;
        validate_apply_identity(&req.idempotency_key, &req.confirmation_hash)?;
        let expected_version = parse_required_version(&req.expected_resource_version)?;
        let publication = self
            .db
            .oci_publication(
                &req.publication_id,
                &claims.sub,
                &claims.sub,
                clock::now_unix_secs(),
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container publication"))?;
        let (registry, repository) = self
            .authorize_container_publication(&claims, &publication)
            .await?;
        let confirmation_hash = Sha256Digest::parse(&req.confirmation_hash)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let expected_confirmation = oci_publication_confirmation_hash(&publication);
        if confirmation_hash != expected_confirmation {
            return Err(RpcError::FailedPrecondition(
                "container publication confirmation hash changed".to_string(),
            ));
        }
        let current = clock::now_unix_secs();
        let catalog = self
            .db
            .oci_publication_catalog(
                &publication.id,
                &claims.sub,
                &claims.sub,
                &claims.sub,
                current,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let committed = self
            .db
            .commit_oci_publication(
                &publication.id,
                &claims.sub,
                &claims.sub,
                expected_version,
                &req.idempotency_key,
                confirmation_hash,
                &catalog,
                current,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        self.container_publication_response(&registry.slug, &repository.name, &committed)
    }

    /// Aborts one incomplete verified-publication transaction.
    ///
    /// # Errors
    ///
    /// Returns an authorization or not-found error, malformed concurrency
    /// input, a failed precondition for a committed publication, or a database
    /// failure.
    pub async fn abort_container_publication(
        &self,
        auth: Option<&str>,
        req: pb::AbortContainerPublicationRequest,
    ) -> Result<pb::ContainerPublication, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.idempotency_key.is_empty() || req.idempotency_key.len() > 128 {
            return Err(RpcError::invalid(
                "idempotencyKey must contain 1..128 bytes",
            ));
        }
        let expected_version = parse_required_version(&req.expected_resource_version)?;
        let publication = self
            .db
            .oci_publication(
                &req.publication_id,
                &claims.sub,
                &claims.sub,
                clock::now_unix_secs(),
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container publication"))?;
        let (registry, repository) = self
            .authorize_container_publication(&claims, &publication)
            .await?;
        let aborted = self
            .db
            .abort_oci_publication(
                &publication.id,
                &claims.sub,
                &claims.sub,
                expected_version,
                &req.idempotency_key,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        self.container_publication_response(&registry.slug, &repository.name, &aborted)
    }

    async fn authorize_container_publication(
        &self,
        claims: &crate::auth::jwt::Claims,
        publication: &OciPublicationRecord,
    ) -> Result<(crate::db::RegistryRecord, OciRepositoryRecord), RpcError> {
        let registry = self
            .db
            .registry_by_id(publication.registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(claims, Permission::Publish, &scope)
            .await?;
        let repository = self
            .db
            .oci_repository_by_id(publication.repository_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("container repository"))?;
        Ok((registry, repository))
    }

    fn container_publication_response(
        &self,
        registry: &str,
        repository: &RepositoryName,
        publication: &OciPublicationRecord,
    ) -> Result<pb::ContainerPublication, RpcError> {
        let confirmation_hash = oci_publication_confirmation_hash(publication).to_string();
        Ok(pb::ContainerPublication {
            publication_id: publication.id.clone(),
            registry: registry.to_string(),
            repository: repository.to_string(),
            root_digest: publication.root_digest.to_string(),
            catalog_digest: publication.catalog_digest.to_string(),
            state: publication.state.clone(),
            target_tag: publication
                .target_tag
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            resource_version: publication.resource_version.to_string(),
            expires_at: publication.expires_at,
            created_at: publication.created_at,
            committed_at: publication.committed_at.unwrap_or_default(),
            confirmation_hash,
            verified_release_root: (publication.state == "ready")
                .then(|| publication.root_digest.to_string())
                .unwrap_or_default(),
            topology_digest: publication.topology_digest.to_string(),
            required_placement_count: publication.required_placement_count,
            source_kind: publication.source_kind.clone(),
        })
    }
}

use crate::db::OciRepositoryRecord;

fn validate_initial_release(release: &ContainerRelease) -> Result<(), RpcError> {
    if release.identity.package != "aos"
        || release.identity.image != "aos"
        || release.nix.definition.attribute != "containerImages.aos"
    {
        return Err(RpcError::invalid(
            "the initial catalog admits only the aos package and containerImages.aos definition",
        ));
    }
    Ok(())
}

fn release_roots(release: &ContainerRelease) -> Vec<Descriptor> {
    vec![
        release.oci.index.clone(),
        release.nix.closure.clone(),
        release.evidence.sbom.clone(),
        release.evidence.source.clone(),
        release.evidence.license.clone(),
        release.evidence.provenance.clone(),
        release.evidence.signature.clone(),
    ]
}

fn validate_release_graph(
    release: &ContainerRelease,
    graph: &[OciCatalogObject],
) -> Result<(), RpcError> {
    let index = graph
        .iter()
        .find(|object| object.descriptor.digest == release.oci.index.digest)
        .ok_or_else(|| RpcError::FailedPrecondition("release index is absent".to_string()))?;
    if index.descriptor != release.oci.index {
        return Err(RpcError::FailedPrecondition(
            "release index descriptor conflicts with the admitted catalog".to_string(),
        ));
    }
    let Some(OciCatalogProjection::Index(projected)) = &index.projection else {
        return Err(RpcError::FailedPrecondition(
            "release index projection is absent".to_string(),
        ));
    };
    if projected.manifests != release.oci.platform_manifests {
        return Err(RpcError::FailedPrecondition(
            "release platform descriptors do not exactly match the OCI index".to_string(),
        ));
    }
    for evidence in release_roots(release).into_iter().skip(1) {
        let object = graph
            .iter()
            .find(|object| object.descriptor.digest == evidence.digest)
            .ok_or_else(|| {
                RpcError::FailedPrecondition(format!(
                    "release evidence {} is absent",
                    evidence.digest
                ))
            })?;
        if object.descriptor != evidence {
            return Err(RpcError::FailedPrecondition(
                "release evidence descriptor conflicts with the admitted catalog".to_string(),
            ));
        }
        let Some(OciCatalogProjection::Manifest {
            document: projected,
            ..
        }) = &object.projection
        else {
            return Err(RpcError::FailedPrecondition(
                "release evidence manifest projection is absent".to_string(),
            ));
        };
        if projected.subject.as_ref() != Some(&release.oci.index)
            || projected.artifact_type != evidence.artifact_type
        {
            return Err(RpcError::FailedPrecondition(
                "release evidence does not refer to the exact OCI index and artifact role"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn descriptor_role(
    release: &ContainerRelease,
    descriptor: &Descriptor,
) -> ContainerReleaseDescriptorRole {
    if descriptor.digest == release.oci.index.digest {
        ContainerReleaseDescriptorRole::Index
    } else if release
        .oci
        .platform_manifests
        .iter()
        .any(|candidate| candidate.digest == descriptor.digest)
    {
        ContainerReleaseDescriptorRole::PlatformManifest
    } else if descriptor.digest == release.nix.closure.digest {
        ContainerReleaseDescriptorRole::NixClosure
    } else if descriptor.digest == release.evidence.sbom.digest {
        ContainerReleaseDescriptorRole::Sbom
    } else if descriptor.digest == release.evidence.source.digest {
        ContainerReleaseDescriptorRole::Source
    } else if descriptor.digest == release.evidence.license.digest {
        ContainerReleaseDescriptorRole::License
    } else if descriptor.digest == release.evidence.provenance.digest {
        ContainerReleaseDescriptorRole::Provenance
    } else if descriptor.digest == release.evidence.signature.digest {
        ContainerReleaseDescriptorRole::Signature
    } else {
        // Closure members are covered by the same signed release graph. The
        // role is descriptive only; descriptor identity and placement fences
        // are frozen independently for every object.
        ContainerReleaseDescriptorRole::Index
    }
}

fn projection_json(object: &OciCatalogObject) -> Result<Option<String>, RpcError> {
    let bytes = match &object.projection {
        Some(OciCatalogProjection::Manifest {
            document, platform, ..
        }) => Some(
            to_canonical_json(&serde_json::json!({
                "document": document,
                "platform": platform,
            }))
            .map_err(RpcError::internal)?,
        ),
        Some(OciCatalogProjection::Index(index)) => {
            Some(to_canonical_json(index).map_err(RpcError::internal)?)
        }
        None => None,
    };
    bytes
        .map(|bytes| String::from_utf8(bytes).map_err(RpcError::internal))
        .transpose()
}

fn parse_optional_tag(value: &str) -> Result<Option<Tag>, RpcError> {
    (!value.is_empty())
        .then(|| Tag::parse(value).map_err(|error| RpcError::invalid(error.to_string())))
        .transpose()
}

fn parse_optional_digest(value: &str) -> Result<Option<Sha256Digest>, RpcError> {
    (!value.is_empty())
        .then(|| Sha256Digest::parse(value).map_err(|error| RpcError::invalid(error.to_string())))
        .transpose()
}

fn parse_optional_version(value: &str) -> Result<Option<i64>, RpcError> {
    (!value.is_empty())
        .then(|| parse_required_version(value))
        .transpose()
}

fn parse_required_version(value: &str) -> Result<i64, RpcError> {
    value
        .parse::<i64>()
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| RpcError::invalid("resource version must be a positive integer"))
}

fn validate_apply_identity(idempotency_key: &str, confirmation_hash: &str) -> Result<(), RpcError> {
    if idempotency_key.is_empty() || idempotency_key.len() > 128 {
        return Err(RpcError::invalid(
            "idempotencyKey must contain 1..128 bytes",
        ));
    }
    Sha256Digest::parse(confirmation_hash)
        .map(|_| ())
        .map_err(|error| RpcError::invalid(error.to_string()))
}
