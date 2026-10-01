//! Direct-only initial OCI allocation using current immutable account authority.
//!
//! Canonical control and original signed owner authority precede body polling.
//! Empty-body and catalog awaits are followed by fresh authorization before
//! repository or allocation writes. All provider staging belongs to the broker.

use super::*;
use crate::direct_upload::{DirectActorKind, DirectActorSlot, WireInteger};
use crate::domain::PrincipalKind;

impl RpcService {
    /// Handles initial direct control before creating a repository.
    pub(crate) async fn begin_direct_oci_allocation_request(
        &self,
        registry: &RegistryRecord,
        repository_name: &aos_oci_types::RepositoryName,
        authority: &str,
        headers: &HeaderMap,
        raw_query: Option<&str>,
        body: Body,
    ) -> Response {
        let query = match parse_start_query(raw_query.unwrap_or_default()) {
            Ok(query) => query,
            Err(_) => return direct_invalid_control(),
        };
        if self.deployment_id.is_none() || query.validate_direct_allocation().is_err() {
            return direct_invalid_control();
        }
        let (original_actor, _, original_expiry) = match self
            .current_direct_oci_actor(registry, repository_name, authority, headers)
            .await
        {
            Ok(proof) => proof,
            Err(response) => return response,
        };
        if !matches!(to_bytes(body, 1).await, Ok(bytes) if bytes.is_empty()) {
            return direct_invalid_control();
        }

        let repository = match self.db.oci_repository(registry.id, repository_name).await {
            Ok(Some(repository)) => repository,
            Ok(None) => {
                // This fence follows both the empty-body read and catalog lookup.
                // A denied actor cannot create even an empty logical repository.
                if let Err(response) = self
                    .same_direct_oci_actor(
                        registry,
                        repository_name,
                        authority,
                        headers,
                        &original_actor,
                        original_expiry,
                    )
                    .await
                {
                    return response;
                }
                match self
                    .db
                    .ensure_direct_oci_repository(
                        registry.id,
                        &registry.stable_id,
                        repository_name,
                        now(),
                    )
                    .await
                {
                    Ok(repository) => repository,
                    Err(_) => {
                        return unavailable_response(
                            "repository could not be created for push",
                            false,
                        )
                    }
                }
            }
            Err(_) => return unavailable_response("repository catalog is unavailable", false),
        };
        self.allocate_direct_blob_upload(
            registry,
            &repository,
            authority,
            headers,
            query,
            &original_actor,
            original_expiry,
        )
        .await
    }

    /// Handles direct allocation against an already-resolved logical repository.
    pub(crate) async fn begin_direct_blob_upload(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        authority: &str,
        headers: &HeaderMap,
        query: StartQuery,
        body: Body,
    ) -> Response {
        if self.deployment_id.is_none() || query.validate_direct_allocation().is_err() {
            return direct_invalid_control();
        }
        let (original_actor, _, original_expiry) = match self
            .current_direct_oci_actor(registry, &repository.name, authority, headers)
            .await
        {
            Ok(proof) => proof,
            Err(response) => return response,
        };
        if !matches!(to_bytes(body, 1).await, Ok(bytes) if bytes.is_empty()) {
            return direct_invalid_control();
        }
        self.allocate_direct_blob_upload(
            registry,
            repository,
            authority,
            headers,
            query,
            &original_actor,
            original_expiry,
        )
        .await
    }

    async fn allocate_direct_blob_upload(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        authority: &str,
        headers: &HeaderMap,
        query: StartQuery,
        original_actor: &DirectActorSlot,
        original_expiry: i64,
    ) -> Response {
        let Some(deployment) = self.deployment_id.as_deref() else {
            return unavailable_response("direct OCI deployment identity is unavailable", false);
        };
        let (Some(operation), Some(digest), Some(size)) =
            (query.operation_id, query.digest, query.size)
        else {
            return direct_invalid_control();
        };
        // This covers the awaited empty body or newly ensured repository. It
        // precedes the first allocation/quota/business-reservation transaction.
        let (actor, token_id, _) = match self
            .same_direct_oci_actor(
                registry,
                &repository.name,
                authority,
                headers,
                original_actor,
                original_expiry,
            )
            .await
        {
            Ok(proof) => proof,
            Err(response) => return response,
        };
        let current_time = now();
        let input = crate::db::BeginDirectOciUpload {
            deployment_id: deployment.to_owned(),
            actor,
            client_operation_id: operation,
            registry_id: registry.id,
            registry_stable_id: registry.stable_id.clone(),
            repository_id: repository.id,
            repository_name: repository.name.to_string(),
            expected_digest: digest,
            expected_size: size,
            authorization_token_id: token_id,
            now: current_time,
            expires_at: current_time + UPLOAD_SESSION_SECONDS,
        };
        let allocation = match self.db.begin_direct_oci_upload(&input).await {
            Ok(upload) => upload,
            Err(_) => {
                return upload_error(
                    StatusCode::CONFLICT,
                    DistributionErrorCode::BlobUploadInvalid,
                    "direct OCI operation changed or its retained allocation is unavailable",
                )
            }
        };
        // A committed reservation stays occupied even if authority expires,
        // cancellation or response loss prevents returning its original ID.
        if let Err(response) = self
            .same_direct_oci_actor(
                registry,
                &repository.name,
                authority,
                headers,
                original_actor,
                original_expiry,
            )
            .await
        {
            return response;
        }
        upload_progress_response(
            StatusCode::ACCEPTED,
            repository,
            &allocation.id,
            allocation.uploaded_size,
            false,
        )
    }

    async fn same_direct_oci_actor(
        &self,
        registry: &RegistryRecord,
        repository: &aos_oci_types::RepositoryName,
        authority: &str,
        headers: &HeaderMap,
        original_actor: &DirectActorSlot,
        original_expiry: i64,
    ) -> Result<(DirectActorSlot, String, i64), Response> {
        let proof = self
            .current_direct_oci_actor(registry, repository, authority, headers)
            .await?;
        if &proof.0 != original_actor || now() >= original_expiry {
            return Err(direct_unauthorized());
        }
        Ok(proof)
    }

    /// Resolves the real live credential after exact OCI-domain authorization.
    ///
    /// # Errors
    /// Returns a value-free denial for another authority/repository, expired
    /// grants, browser pseudo-subjects, revoked credentials, or current IAM denial.
    pub(crate) async fn current_direct_oci_actor(
        &self,
        registry: &RegistryRecord,
        repository: &aos_oci_types::RepositoryName,
        authority: &str,
        headers: &HeaderMap,
    ) -> Result<(DirectActorSlot, String, i64), Response> {
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(direct_unauthorized)?;
        let claims = self
            .jwt_keys
            .verify_oci(bearer, authority, &registry.stable_id, repository, "push")
            .map_err(|_| direct_unauthorized())?;
        let underlying = claims
            .sub
            .strip_prefix("token:")
            .or_else(|| claims.sub.strip_prefix("hub:"))
            .ok_or_else(direct_unauthorized)?;
        let auth = self
            .db
            .current_token_authority(underlying)
            .await
            .map_err(|_| direct_unauthorized())?
            .ok_or_else(direct_unauthorized)?;
        let incarnation = auth
            .owner_incarnation
            .as_ref()
            .ok_or_else(direct_unauthorized)?;
        if claims.owner_kind.as_deref() != Some(auth.owner.kind.as_str())
            || claims.owner_incarnation.as_ref() != Some(incarnation)
        {
            return Err(direct_unauthorized());
        }
        let actor = DirectActorSlot {
            kind: match auth.owner.kind {
                PrincipalKind::User => DirectActorKind::User,
                PrincipalKind::ServiceAccount => DirectActorKind::ServiceAccount,
            },
            numeric_id: WireInteger::new(
                u64::try_from(auth.owner.id).map_err(|_| direct_unauthorized())?,
            ),
            incarnation: incarnation.clone(),
        };
        actor.validate().map_err(|_| direct_unauthorized())?;

        // Use the existing two-sided registry IAM gate with genuine current
        // token authority. This local short-lived bridge is never returned.
        let current_hub = self
            .jwt_keys
            .mint(&auth, 60)
            .map_err(|_| direct_unauthorized())?;
        self.require_authenticated_registry_publish(
            Some(&format!("Bearer {current_hub}")),
            registry,
        )
        .await
        .map_err(|_| direct_unauthorized())?;
        // IAM resolution awaits current memberships. Repeat the original signed
        // owner pin after that work rather than returning a pre-await identity.
        let final_auth = self
            .db
            .current_token_authority(underlying)
            .await
            .map_err(|_| direct_unauthorized())?
            .ok_or_else(direct_unauthorized)?;
        if final_auth.owner != auth.owner
            || final_auth.owner_incarnation != auth.owner_incarnation
            || claims.owner_kind.as_deref() != Some(final_auth.owner.kind.as_str())
            || claims.owner_incarnation != final_auth.owner_incarnation
            || now() >= claims.exp
        {
            return Err(direct_unauthorized());
        }
        Ok((actor, auth.token_id, claims.exp))
    }
}

fn direct_unauthorized() -> Response {
    upload_error(
        StatusCode::UNAUTHORIZED,
        DistributionErrorCode::Unauthorized,
        "current OCI repository push authority is required",
    )
}

fn direct_invalid_control() -> Response {
    upload_error(
        StatusCode::BAD_REQUEST,
        DistributionErrorCode::BlobUploadInvalid,
        "direct OCI allocation requires canonical operation, digest, size and an empty body",
    )
}
