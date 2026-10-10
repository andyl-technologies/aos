//! Gateways reads in the topology capability.

use super::*;

impl RpcService {
    /// Lists authorized gateways, optionally filtered by binding.
    pub async fn list_gateways(
        &self,
        auth: Option<&str>,
        req: pb::ListGatewaysRequest,
    ) -> Result<pb::ListGatewaysResponse, RpcError> {
        if !req.owner_scope_key.is_empty() {
            if req.binding.is_some() {
                return Err(RpcError::invalid(
                    "scoped gateway requests cannot also specify a binding",
                ));
            }
            self.require_delivery_scope(auth, &req.owner_scope_key, Permission::GatewayRead)
                .await?;
            let page = self
                .db
                .list_gateways_page(
                    &req.owner_scope_key,
                    req.page_size,
                    (!req.page_token.is_empty()).then_some(req.page_token.as_str()),
                    req.include_granted,
                )
                .await
                .map_err(RpcError::internal)?;
            let mut gateways = Vec::with_capacity(page.records.len());
            for record in page.records {
                gateways.push(self.gateway_message(record).await?);
            }
            return Ok(pb::ListGatewaysResponse {
                gateways,
                next_page_token: page.next_cursor.unwrap_or_default(),
            });
        }
        if req.include_granted {
            return Err(RpcError::invalid("includeGranted requires ownerScopeKey"));
        }
        let claims = self.require_claims(auth)?;
        let binding_id = match req.binding {
            Some(reference) => Some(
                self.resolve_binding_reference(auth, Some(reference))
                    .await?
                    .id,
            ),
            None => None,
        };
        let records = self
            .db
            .list_gateways(binding_id)
            .await
            .map_err(RpcError::internal)?;
        let mut gateways = Vec::new();
        for record in records {
            let scope = Scope::try_parse(&record.owner_scope_key).ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("gateway has invalid owner scope"))
            })?;
            if self
                .claims_allow(Some(&claims), Permission::GatewayRead, &scope)
                .await
            {
                gateways.push(record);
            }
        }
        let (records, next_page_token) = paginate(gateways, req.page_size, &req.page_token)?;
        let mut gateways = Vec::with_capacity(records.len());
        for record in records {
            gateways.push(self.gateway_message(record).await?);
        }
        Ok(pb::ListGatewaysResponse {
            gateways,
            next_page_token,
        })
    }

    /// Returns one gateway with desired/observed generations.
    pub async fn get_gateway(
        &self,
        auth: Option<&str>,
        req: pb::GetTopologyResourceRequest,
    ) -> Result<pb::GatewayResponse, RpcError> {
        let record = self
            .authorized_gateway(auth, &req.stable_id, Permission::GatewayRead)
            .await?;
        Ok(pb::GatewayResponse {
            gateway: Some(self.gateway_message(record).await?),
        })
    }
}
