//! Verified OCI container publication control plane.
//!
//! Standard Distribution uploads make bytes available to a repository. These
//! methods separately freeze the complete signed AOS release graph, its exact
//! placement evidence, and an optional tag compare-and-swap before exposing a
//! verified release root.

use aos_oci_types::{
    ContainerRelease, Descriptor, RepositoryName, Sha256Digest, Tag, to_canonical_json,
};
use aos_proto_types as pb;

use super::{Permission, RpcError, RpcService, clock};
use crate::db::{
    AddOciPublicationObject, BeginOciPublication, ContainerReleaseDescriptorRole,
    OCI_MAX_SESSION_SECONDS, OciCatalogObject, OciCatalogProjection, OciPublicationRecord,
    OciPublicationRequiredPlacement, oci_blob_object_key, oci_catalog_declaration_digest,
    oci_publication_confirmation_hash,
};

impl RpcService {
    /// Verifies staged OCI membership and every required placement without tags.
    ///
    /// Partial server-confirmed offsets contribute to progress, but an object
    /// remains missing until its complete digest and placement are verified.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid candidate, inconsistent closed graph,
    /// unavailable topology, or database failure.
    pub(crate) async fn staged_container_progress(
        &self,
        registry: &crate::db::RegistryRecord,
        revision: &aos_registry_surface::staging::StageRevision,
    ) -> Result<(u64, u64, Vec<String>), RpcError> {
        let Some(container) = &revision.container else {
            return Ok((0, 0, Vec::new()));
        };
        container
            .validate(&revision.inventory, &revision.release_id)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        validate_initial_release(&container.release)?;
        let placements = self
            .db
            .registry_publication_write_placements(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let repository = self
            .db
            .oci_repository(registry.id, &container.repository)
            .await
            .map_err(RpcError::internal)?;
        let mut total = 0_u64;
        let mut uploaded = 0_u64;
        let mut missing = Vec::new();
        for descriptor in &container.descriptors {
            total = total
                .checked_add(descriptor.size)
                .ok_or_else(|| RpcError::invalid("OCI stage byte total overflows"))?;
            let path = oci_blob_object_key(descriptor.digest);
            let Some(repository) = &repository else {
                missing.push(path);
                continue;
            };
            let blob = self
                .db
                .oci_blob_for_repository(repository.id, descriptor.digest)
                .await
                .map_err(RpcError::internal)?;
            let mut complete = !placements.is_empty()
                && blob.as_ref().is_some_and(|blob| {
                    blob.byte_size == descriptor.size && blob.media_type == descriptor.media_type
                });
            if complete {
                for placement in &placements {
                    if self
                        .db
                        .oci_release_descriptor_placement(
                            repository.id,
                            placement.id,
                            descriptor_role(&container.release, descriptor),
                            descriptor,
                        )
                        .await
                        .map_err(RpcError::internal)?
                        .is_none()
                    {
                        complete = false;
                        break;
                    }
                }
            }
            let available = if complete {
                descriptor.size
            } else {
                missing.push(path);
                self.db
                    .staged_oci_descriptor_offset(repository.id, descriptor, clock::now_unix_secs())
                    .await
                    .map_err(RpcError::internal)?
                    .min(descriptor.size)
            };
            uploaded = uploaded
                .checked_add(available)
                .ok_or_else(|| RpcError::invalid("OCI stage progress overflows"))?;
        }
        if missing.is_empty() {
            let graph = self
                .db
                .oci_repository_closed_graph(
                    repository
                        .as_ref()
                        .ok_or_else(|| {
                            RpcError::FailedPrecondition("OCI repository is absent".into())
                        })?
                        .id,
                    &release_roots(&container.release),
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            validate_release_graph(&container.release, &graph)?;
            let declared = container
                .descriptors
                .iter()
                .map(|descriptor| (descriptor.digest, descriptor))
                .collect::<std::collections::BTreeMap<_, _>>();
            if graph.len() != declared.len()
                || graph.iter().any(|object| {
                    declared
                        .get(&object.descriptor.digest)
                        .is_none_or(|descriptor| {
                            descriptor.size != object.descriptor.size
                                || descriptor.media_type != object.descriptor.media_type
                        })
                })
            {
                return Err(RpcError::FailedPrecondition(
                    "staged OCI inventory differs from the admitted closed graph".into(),
                ));
            }
        }
        Ok((total, uploaded, missing))
    }

    /// Publishes the immutable OCI version tag bound to the indexed stage.
    ///
    /// The caller must have installed and indexed the exact signed Git release.
    /// This reuses the existing closed-graph publication transaction and its
    /// immutable tag preconditions, so retries cannot replace a version tag.
    ///
    /// # Errors
    ///
    /// Returns an error for failed authorization, missing graph placement,
    /// mismatched indexed release, or immutable publication conflicts.
    pub(crate) async fn finalize_staged_container_publications(
        &self,
        auth: Option<&str>,
        revision: &aos_registry_surface::staging::StageRevision,
    ) -> Result<(), RpcError> {
        let Some(container) = &revision.container else {
            return Ok(());
        };
        let registry = self.registry_or_not_found(&revision.registry).await?;
        let (_, _, missing) = self.staged_container_progress(&registry, revision).await?;
        if !missing.is_empty() {
            return Err(RpcError::FailedPrecondition(
                "staged OCI graph is incomplete".into(),
            ));
        }
        if !self
            .db
            .staged_release_commit_indexed(registry.id, &revision.release_id, &revision.commit)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::FailedPrecondition(
                "exact staged Git release has not been indexed".into(),
            ));
        }
        let canonical = to_canonical_json(&container.release).map_err(RpcError::internal)?;
        let key = Sha256Digest::digest(
            &aos_oci_types::to_canonical_json(revision).map_err(RpcError::internal)?,
        )
        .encoded();
        let publication = self
            .begin_container_publication(
                auth,
                pb::BeginContainerPublicationRequest {
                    registry: revision.registry.clone(),
                    repository: container.repository.to_string(),
                    container_release_json: canonical,
                    target_kind: "release".into(),
                    target_tag: revision.release_id.clone(),
                    idempotency_key: format!("stage-{key}"),
                    ..Default::default()
                },
            )
            .await?;
        self.commit_container_publication(
            auth,
            pb::CommitContainerPublicationRequest {
                publication_id: publication.publication_id,
                expected_resource_version: publication.resource_version,
                confirmation_hash: publication.confirmation_hash,
                idempotency_key: format!("stage-commit-{key}"),
            },
        )
        .await?;
        Ok(())
    }

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
        if !self.container_rollout.verified_publication {
            return Err(verified_publication_unavailable());
        }

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
        if !self.container_rollout.verified_publication {
            return Err(verified_publication_unavailable());
        }
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
        if !self.container_rollout.verified_publication {
            return Err(verified_publication_unavailable());
        }
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

fn verified_publication_unavailable() -> RpcError {
    RpcError::Unavailable("verified container publication rollout is disabled".to_string())
}

fn validate_initial_release(release: &ContainerRelease) -> Result<(), RpcError> {
    if !crate::container_catalog::admits_base_image_definition(
        &release.identity.package,
        &release.identity.image,
        &release.nix.definition.attribute,
    ) {
        return Err(RpcError::invalid(
            "the initial catalog admits only the aos package and server base-image definition",
        ));
    }
    Ok(())
}

fn release_roots(release: &ContainerRelease) -> Vec<Descriptor> {
    vec![
        release.oci.index.clone(),
        release.nix.closure.clone(),
        release.evidence.abilities.clone(),
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
    } else if descriptor.digest == release.evidence.abilities.digest {
        ContainerReleaseDescriptorRole::Abilities
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

#[cfg(test)]
mod staging_tests {
    use super::*;
    use aos_oci_types::*;
    use aos_registry_surface::staging::{
        STAGE_SCHEMA, StageContainerGraph, StageObject, StageRevision, inventory_digest,
    };

    fn descriptor(media_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            media_type,
            digest: Sha256Digest::digest(label.as_bytes()),
            size: u64::try_from(label.len()).expect("fixture size"),
            urls: Vec::new(),
            annotations: Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        }
    }

    fn evidence_descriptor(artifact_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            artifact_type: Some(artifact_type),
            ..descriptor(MediaType::OciImageManifest, label)
        }
    }

    fn qualification_fixture() -> ContainerEvidenceQualification {
        ContainerEvidenceQualification {
            schema: CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA.to_string(),
            mapping: ContainerEvidenceMappingQualification {
                complete: true,
                unknown_paths: Vec::new(),
            },
            corresponding_source: ContainerEvidenceQualificationCheck {
                complete: true,
                unknown_paths: Vec::new(),
            },
            licensing: ContainerEvidenceQualificationCheck {
                complete: true,
                unknown_paths: Vec::new(),
            },
            ready_for_verified_publication: true,
        }
    }

    fn release_fixture() -> ContainerRelease {
        let mut platform_manifest = descriptor(MediaType::OciImageManifest, "amd64-manifest");
        platform_manifest.platform = Some(Platform::linux_amd64());
        ContainerRelease {
            schema_version: CONTAINER_RELEASE_SCHEMA_VERSION,
            media_type: MediaType::AosContainerRelease,
            identity: ContainerReleaseIdentity {
                release: "1.0.0".to_string(),
                package: "aos".to_string(),
                package_version: "0.1.0".to_string(),
                image: "aos".to_string(),
            },
            oci: ContainerOciRelease {
                index: descriptor(MediaType::OciImageIndex, "index"),
                platform_manifests: vec![platform_manifest],
            },
            nix: ContainerNixProvenance {
                definition: NixDefinitionIdentity {
                    attribute: "containerImages.aos".to_string(),
                    derivation_path:
                        "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container.drv".to_string(),
                },
                output: NixOutputIdentity {
                    name: "out".to_string(),
                    store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container"
                        .to_string(),
                },
                closure: evidence_descriptor(MediaType::AosNixClosure, "closure"),
            },
            qualification: qualification_fixture(),
            evidence: ContainerReleaseEvidence {
                abilities: evidence_descriptor(MediaType::AosContainerStaticAbilities, "abilities"),
                sbom: evidence_descriptor(MediaType::SpdxJson, "sbom"),
                source: evidence_descriptor(MediaType::AosSourceClosure, "source"),
                license: evidence_descriptor(MediaType::AosLicenseReport, "license"),
                provenance: evidence_descriptor(MediaType::InTotoJson, "provenance"),
                signature: evidence_descriptor(MediaType::DsseEnvelope, "signature"),
            },
        }
    }

    #[tokio::test]
    async fn staged_container_missing_graph_stays_unready_and_cannot_finalize() {
        let (service, db, auth) = super::super::cache_upload_tests::release_test_service().await;
        let org_id = db
            .create_org("oci-candidate", "OCI Candidate")
            .await
            .unwrap();
        let registry_id = db
            .create_managed_registry(org_id, "", "containers", "private", &[], false)
            .await
            .unwrap();
        let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
        let release = release_fixture();
        release.validate().unwrap();
        let mut descriptors = release_roots(&release);
        descriptors.extend(release.oci.platform_manifests.iter().cloned());
        descriptors.sort_by_key(|descriptor| descriptor.digest);
        let container = StageContainerGraph {
            repository: RepositoryName::parse("aos").unwrap(),
            release,
            descriptors,
        };
        let mut inventory = container
            .descriptors
            .iter()
            .map(|descriptor| StageObject {
                path: oci_blob_object_key(descriptor.digest),
                sha256: descriptor.digest.to_string(),
                byte_size: descriptor.size,
                kind: "oci_manifest".into(),
                media_type: descriptor.media_type.to_string(),
            })
            .collect::<Vec<_>>();
        inventory.sort_by(|left, right| left.path.cmp(&right.path));
        let revision = StageRevision {
            schema: STAGE_SCHEMA.into(),
            id: "container-candidate".into(),
            registry: registry.slug.clone(),
            revision: 1,
            release_id: "1.0.0".into(),
            source_branch: "maintainer/candidate".into(),
            commit: "a".repeat(40),
            inventory_digest: inventory_digest(&inventory).unwrap(),
            inventory,
            publication: vec![],
            store_roots: vec![],
            container: Some(container),
        };
        revision.validate().unwrap();
        let epoch_sql = "SELECT COALESCE(state.mutation_epoch, 0)
            FROM registries registry LEFT JOIN oci_registry_state state
              ON state.registry_id = registry.id WHERE registry.id = ?1";
        let before_epoch: i64 = db
            .backend
            .query_opt(epoch_sql, &[crate::value::Value::Int(registry_id)])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        db.upsert_staged_release(registry_id, &revision, 0, None, clock::now_unix_secs())
            .await
            .unwrap();
        let after_epoch: i64 = db
            .backend
            .query_opt(epoch_sql, &[crate::value::Value::Int(registry_id)])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(
            after_epoch,
            before_epoch + 1,
            "typed stage admission must invalidate an earlier OCI GC review"
        );

        let (total, uploaded, missing) = service
            .staged_container_progress(&registry, &revision)
            .await
            .unwrap();
        assert_eq!(
            total,
            revision
                .inventory
                .iter()
                .map(|object| object.byte_size)
                .sum::<u64>()
        );
        assert_eq!(uploaded, 0);
        assert_eq!(missing.len(), revision.inventory.len());
        assert!(
            service
                .finalize_staged_container_publications(Some(&auth), &revision)
                .await
                .is_err()
        );
        assert!(
            db.oci_repository(registry_id, &RepositoryName::parse("aos").unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert!(db.list_releases(registry_id).await.unwrap().is_empty());

        let now = clock::now_unix_secs();
        let container = revision.container.as_ref().unwrap();
        let repository = db
            .ensure_oci_repository(registry_id, &container.repository, now)
            .await
            .unwrap();
        let descriptor = &container.descriptors[0];
        for (offset, tail) in [(1_i64, "61"), (2_i64, "6162")] {
            let upload = db
                .begin_oci_upload(&crate::db::BeginOciUpload {
                    registry_id,
                    repository_id: repository.id,
                    publication_id: None,
                    writer_id: "writer:staging-progress".into(),
                    token_id: "token:staging-progress".into(),
                    idempotency_key: format!("staging-progress-{offset}"),
                    expected_digest: Some(descriptor.digest),
                    expected_size: Some(descriptor.size),
                    maximum_size: descriptor.size,
                    now,
                    expires_at: now + 60,
                })
                .await
                .unwrap();
            // Seed the accepted SHA state of a short contiguous prefix. Two
            // retries for one digest must contribute their maximum, not sum.
            db.backend
                .execute(
                    "UPDATE oci_upload_sessions SET uploaded_size = ?2,
                       sha256_total_bytes = ?2, sha256_tail_hex = ?3 WHERE id = ?1",
                    &[
                        crate::value::Value::Text(upload.id),
                        crate::value::Value::Int(offset),
                        crate::value::Value::Text(tail.into()),
                    ],
                )
                .await
                .unwrap();
        }
        let (_, uploaded, missing) = service
            .staged_container_progress(&registry, &revision)
            .await
            .unwrap();
        let partial = db
            .staged_container_summary_partial_bytes(registry_id, &revision.id, 1, now)
            .await
            .unwrap();
        assert_eq!(uploaded, 2);
        assert_eq!(partial, uploaded, "List and detail accept the same offset");
        assert_eq!(missing.len(), revision.inventory.len());
        assert_eq!(
            db.staged_container_summary_progress(registry_id, &revision.id, 1)
                .await
                .unwrap(),
            (0, 0),
            "partial bytes never count as verified objects"
        );
        assert_eq!(
            db.staged_container_summary_partial_bytes(registry_id, &revision.id, 1, now + 60)
                .await
                .unwrap(),
            0,
            "expired upload offsets do not count as accepted progress"
        );
    }
}
