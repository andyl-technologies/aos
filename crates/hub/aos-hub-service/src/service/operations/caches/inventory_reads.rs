//! Inventory reads in the caches capability.

use super::*;

impl RpcService {
    /// `BinaryCacheService.GetCacheObject` — one object's narinfo metadata.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::Internal`] on database failure.
    pub async fn get_cache_object(
        &self,
        auth: Option<&str>,
        req: pb::GetCacheObjectRequest,
    ) -> Result<pb::GetCacheObjectResponse, RpcError> {
        let c = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_read(auth, &c).await?;
        let object = self
            .db
            .normalized_cache_object(c.id, &req.store_hash)
            .await
            .map_err(RpcError::internal)?
            .map(cache_object_message);
        Ok(pb::GetCacheObjectResponse { object })
    }
}
