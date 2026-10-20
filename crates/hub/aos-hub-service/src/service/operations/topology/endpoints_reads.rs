//! Endpoints reads in the topology capability.

use super::*;

impl RpcService {
    /// Lists endpoints in one exact owner scope.
    pub async fn list_endpoints(
        &self,
        auth: Option<&str>,
        req: pb::ListTopologyResourcesRequest,
    ) -> Result<pb::ListEndpointsResponse, RpcError> {
        self.require_delivery_scope(auth, &req.owner_scope_key, Permission::EndpointRead)
            .await?;
        let page = self
            .db
            .list_endpoints_page(
                &req.owner_scope_key,
                req.page_size,
                (!req.page_token.is_empty()).then_some(req.page_token.as_str()),
                req.include_granted,
            )
            .await
            .map_err(RpcError::internal)?;
        let mut endpoints = Vec::with_capacity(page.records.len());
        for record in page.records {
            endpoints.push(self.endpoint_message(record).await?);
        }
        Ok(pb::ListEndpointsResponse {
            endpoints,
            next_page_token: page.next_cursor.unwrap_or_default(),
        })
    }

    /// Returns one endpoint with desired and observed generations.
    pub async fn get_endpoint(
        &self,
        auth: Option<&str>,
        req: pb::GetTopologyResourceRequest,
    ) -> Result<pb::EndpointResponse, RpcError> {
        let record = self
            .managed_endpoint(auth, &req.stable_id, Permission::EndpointRead)
            .await?;
        Ok(pb::EndpointResponse {
            endpoint: Some(self.endpoint_message(record).await?),
        })
    }

    /// Lists immutable generations of one visible endpoint.
    pub async fn list_endpoint_generations(
        &self,
        auth: Option<&str>,
        req: pb::ListEndpointGenerationsRequest,
    ) -> Result<pb::ListEndpointGenerationsResponse, RpcError> {
        let endpoint = self
            .managed_endpoint(auth, &req.endpoint_id, Permission::EndpointRead)
            .await?;
        let after = if req.page_token.is_empty() {
            0
        } else {
            req.page_token
                .parse::<i64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| RpcError::invalid("invalid endpoint generation page token"))?
        };
        let page_size = if req.page_size == 0 {
            50usize
        } else {
            usize::try_from(req.page_size.min(200)).map_err(RpcError::internal)?
        };
        let records = self
            .db
            .endpoint_revisions(&endpoint.id)
            .await
            .map_err(RpcError::internal)?;
        let mut eligible = records
            .into_iter()
            .filter(|record| record.generation > after);
        let page = eligible.by_ref().take(page_size).collect::<Vec<_>>();
        let has_more = eligible.next().is_some();
        let next_page_token = if has_more {
            page.last()
                .map(|record| record.generation.to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        let mut generations = Vec::with_capacity(page.len());
        for revision in page {
            generations.push(
                self.endpoint_generation_message(&endpoint, revision)
                    .await?,
            );
        }
        Ok(pb::ListEndpointGenerationsResponse {
            generations,
            next_page_token,
        })
    }

    /// Returns one immutable generation of a visible endpoint.
    pub async fn get_endpoint_generation(
        &self,
        auth: Option<&str>,
        req: pb::GetEndpointGenerationRequest,
    ) -> Result<pb::EndpointGenerationResponse, RpcError> {
        if req.generation <= 0 {
            return Err(RpcError::invalid("generation must be positive"));
        }
        let endpoint = self
            .managed_endpoint(auth, &req.endpoint_id, Permission::EndpointRead)
            .await?;
        let revision = self
            .db
            .endpoint_revision(&endpoint.id, req.generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("endpoint generation"))?;
        Ok(pb::EndpointGenerationResponse {
            generation: Some(
                self.endpoint_generation_message(&endpoint, revision)
                    .await?,
            ),
        })
    }
}
