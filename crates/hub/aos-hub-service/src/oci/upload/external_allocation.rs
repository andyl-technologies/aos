//! Bodyless initial Distribution allocation for Worker-controlled OCI uploads.
//!
//! This selects no Direct upload session or provider permission. The current
//! OCI actor precedes repository creation and checked upload/quota allocation.

use super::*;

impl RpcService {
    pub(crate) async fn hybrid_external_oci_writer(
        &self,
        registry: &RegistryRecord,
    ) -> Result<bool, Response> {
        let placement = self
            .effective_surface_writer(SurfaceTarget::Registry(registry.id))
            .await
            .map_err(|_| unavailable_response("OCI writer is unavailable", false))?;
        let binding = self
            .db
            .binding(placement.binding_id)
            .await
            .map_err(|_| unavailable_response("OCI binding is unavailable", false))?
            .ok_or_else(|| unavailable_response("OCI binding disappeared", false))?;
        if binding.is_instance_default && binding.kind == "deployment_r2" {
            return Ok(false);
        }
        if !binding.is_instance_default && matches!(binding.kind.as_str(), "s3" | "r2") {
            return Ok(true);
        }
        Err(unavailable_response(
            "OCI writer kind is unsupported",
            false,
        ))
    }

    pub(crate) async fn begin_worker_oci_allocation_request(
        &self,
        registry: &RegistryRecord,
        name: &RepositoryName,
        authority: &str,
        headers: &HeaderMap,
        raw_query: Option<&str>,
        body: Body,
    ) -> Response {
        let query = match parse_start_query(raw_query.unwrap_or_default()) {
            Ok(query) if query.operation_id.is_none() => query,
            _ => {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::BlobUploadInvalid,
                    "Worker OCI allocation requires a Distribution upload request",
                );
            }
        };
        drop(query);
        let (actor, _, expiry) = match self
            .current_direct_oci_actor(registry, name, authority, headers)
            .await
        {
            Ok(current) => current,
            Err(response) => return response,
        };
        if !matches!(to_bytes(body, 1).await, Ok(bytes) if bytes.is_empty()) {
            return upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::BlobUploadInvalid,
                "upload creation body must be empty",
            );
        }
        let repository = match self.db.oci_repository(registry.id, name).await {
            Ok(Some(repository)) => repository,
            Ok(None) => {
                if let Err(response) = self
                    .same_direct_oci_actor(registry, name, authority, headers, &actor, expiry)
                    .await
                {
                    return response;
                }
                match self
                    .db
                    .ensure_direct_oci_repository(registry.id, &registry.stable_id, name, now())
                    .await
                {
                    Ok(repository) => repository,
                    Err(_) => {
                        return unavailable_response("OCI repository creation refused", false);
                    }
                }
            }
            Err(_) => return unavailable_response("OCI repository is unavailable", false),
        };
        if let Err(response) = self
            .same_direct_oci_actor(registry, name, authority, headers, &actor, expiry)
            .await
        {
            return response;
        }
        let owner = match upload_owner(self, headers) {
            Ok(owner) => owner,
            Err(response) => return response,
        };
        self.begin_blob_upload(
            registry,
            &repository,
            authority,
            &owner,
            headers,
            raw_query,
            Body::empty(),
        )
        .await
    }
}
