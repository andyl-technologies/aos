//! Configuration reads in the registries capability.

use super::*;

impl RpcService {
    /// `RegistryService.GetRegistry` — one registry by slug.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a soft-deleted
    /// owning org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn get_registry(
        &self,
        auth: Option<&str>,
        req: pb::GetRegistryRequest,
    ) -> Result<pb::GetRegistryResponse, RpcError> {
        let record = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &record).await?;
        let status = self
            .db
            .index_status(record.id)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GetRegistryResponse {
            registry: Some(self.registry_message(&record, status).await?),
        })
    }

    /// Returns registry-owned upstream synchronization configuration and status.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, not-found, or database error.
    pub async fn get_registry_mirror(
        &self,
        auth: Option<&str>,
        req: pb::GetRegistryMirrorRequest,
    ) -> Result<pb::RegistryMirrorResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry_id).await?;
        self.authorize_registry_mirror(auth, &registry).await?;
        let mirror = self
            .db
            .registry_mirror(registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry mirror"))?;
        let mut message = Self::registry_mirror_message(mirror);
        message.registry_id = registry.slug;
        Ok(pb::RegistryMirrorResponse {
            mirror: Some(message),
        })
    }

    /// Lists one registry's publication history in stable newest-first order.
    ///
    /// List entries omit per-object upload manifests. Call
    /// [`Self::get_registry_publication`] for one publication's complete object
    /// inventory.
    ///
    /// Page tokens are bound to the registry's immutable identity and exact
    /// state filter, so they cannot be replayed against another inventory.
    ///
    /// # Errors
    ///
    /// Returns an authorization error when the caller lacks `publish`, an
    /// invalid-argument error for an unsupported state or mismatched page
    /// token, or an internal error when durable inventory reads fail.
    pub async fn list_registry_publications(
        &self,
        auth: Option<&str>,
        req: pb::ListRegistryPublicationsRequest,
    ) -> Result<pb::ListRegistryPublicationsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;
        if !req.state.is_empty()
            && !matches!(
                req.state.as_str(),
                "preparing" | "writing_pointers" | "ready" | "failed" | "retired"
            )
        {
            return Err(RpcError::invalid("invalid publication state filter"));
        }

        let selector = format!("{}:{}", registry.stable_id, req.state);
        let selector_digest = hex::encode(Sha256::digest(selector.as_bytes()));
        let cursor = if req.page_token.is_empty() {
            None
        } else {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&req.page_token)
                .map_err(|_| RpcError::invalid("invalid publication page token"))?;
            let decoded = String::from_utf8(decoded)
                .map_err(|_| RpcError::invalid("invalid publication page token"))?;
            let mut fields = decoded.splitn(3, ':');
            let valid =
                fields.next() == Some("pub1") && fields.next() == Some(selector_digest.as_str());
            let ordinal = fields
                .next()
                .filter(|_| valid)
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    RpcError::invalid(
                        "publication page token belongs to another inventory or state filter",
                    )
                })?;
            Some(ordinal)
        };
        let page = self
            .db
            .list_registry_publications_page(
                registry.id,
                (!req.state.is_empty()).then_some(req.state.as_str()),
                req.page_size,
                cursor,
            )
            .await
            .map_err(|error| RpcError::invalid(format!("publication inventory: {error:#}")))?;
        let next_page_token = page
            .next_cursor
            .map(|ordinal| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(format!("pub1:{selector_digest}:{ordinal}"))
            })
            .unwrap_or_default();
        let mut publications = Vec::with_capacity(page.records.len());
        for publication in page.records {
            publications.push(
                self.registry_publication_response(&publication.publication_id, false)
                    .await?,
            );
        }
        Ok(pb::ListRegistryPublicationsResponse {
            publications,
            next_page_token,
        })
    }

    /// Returns one publication after enforcing registry publish authority.
    ///
    /// # Errors
    ///
    /// Returns the corresponding authorization, not-found, or database error.
    pub async fn get_registry_publication(
        &self,
        auth: Option<&str>,
        req: pb::GetRegistryPublicationRequest,
    ) -> Result<pb::RegistryPublication, RpcError> {
        let claims = self.require_claims(auth)?;
        let publication = self
            .db
            .registry_publication(&req.publication_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry publication"))?;
        let registry = self
            .db
            .registry_by_id(publication.registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;
        self.registry_publication_response(&publication.publication_id, true)
            .await
    }

    /// `RegistryService.ListRegistries` — the registries the caller may read.
    ///
    /// Visibility-filters every record through [`Self::can_read`]: anonymous
    /// callers see the public slice, members additionally see their orgs'
    /// registries; hidden records are dropped, not errored.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a present-but-invalid bearer
    /// JWT, [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_registries(
        &self,
        auth: Option<&str>,
        req: pb::ListRegistriesRequest,
    ) -> Result<pb::ListRegistriesResponse, RpcError> {
        let claims = self.optional_claims(auth)?;
        let records = self
            .db
            .list_registries()
            .await
            .map_err(RpcError::internal)?;
        let mut registries = Vec::with_capacity(records.len());
        for record in &records {
            if !self.can_read(claims.as_ref(), record).await {
                continue;
            }
            let status = self
                .db
                .index_status(record.id)
                .await
                .map_err(RpcError::internal)?;
            registries.push(self.registry_message(record, status).await?);
        }
        let (registries, next_page_token) = paginate(registries, req.page_size, &req.page_token)?;
        Ok(pb::ListRegistriesResponse {
            registries,
            next_page_token,
        })
    }
}
