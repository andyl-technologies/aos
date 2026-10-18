//! Jobs reads in the administration capability.

use super::*;

impl RpcService {
    /// Returns one authorized durable operation.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, not-found, or database error.
    pub async fn get_operation(
        &self,
        auth: Option<&str>,
        req: pb::GetOperationRequest,
    ) -> Result<pb::OperationDetailResponse, RpcError> {
        let operation = self.authorized_operation(auth, &req.operation_id).await?;
        Ok(pb::OperationDetailResponse {
            operation: Some(self.operation_detail(&operation).await?),
        })
    }

    /// Lists durable operations for one target or authorization-scope closure.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, or database error.
    pub async fn list_operations(
        &self,
        auth: Option<&str>,
        req: pb::ListOperationsRequest,
    ) -> Result<pb::ListOperationsResponse, RpcError> {
        let target = req.target.and_then(|target| target.target);
        let scope_selector = (!req.authorization_scope_key.is_empty())
            .then_some(req.authorization_scope_key.as_str());
        if target.is_some() == scope_selector.is_some() {
            return Err(RpcError::invalid(
                "exactly one of target or authorization_scope_key is required",
            ));
        }
        if !req.state.is_empty()
            && !matches!(
                req.state.as_str(),
                "pending" | "running" | "succeeded" | "failed" | "cancelled"
            )
        {
            return Err(RpcError::invalid("state is not a closed operation state"));
        }

        let claims = self.require_claims(auth)?;
        let (target_selector, scope_selector) = match target {
            Some(target) => {
                let (target_kind, target_id) = match target {
                    pb::operation_resource_ref::Target::RegistryId(id) => ("registry", id),
                    pb::operation_resource_ref::Target::BinaryCacheId(id) => ("binary_cache", id),
                    pb::operation_resource_ref::Target::PlacementId(id) => ("placement", id),
                    pb::operation_resource_ref::Target::DomainId(id) => ("domain", id),
                    pb::operation_resource_ref::Target::NetworkPolicyId(id) => {
                        ("network_policy", id)
                    }
                    pb::operation_resource_ref::Target::EndpointId(id) => ("endpoint", id),
                    pb::operation_resource_ref::Target::GatewayId(id) => ("gateway", id),
                    pb::operation_resource_ref::Target::RouteId(id) => ("route", id),
                    pb::operation_resource_ref::Target::PlacementPolicyId(id) => {
                        ("placement_policy", id)
                    }
                    pb::operation_resource_ref::Target::RetentionSubscriptionId(id) => {
                        ("retention_subscription", id)
                    }
                    pb::operation_resource_ref::Target::PopulationTargetId(id) => {
                        ("population_target", id)
                    }
                    pb::operation_resource_ref::Target::CacheGcGenerationId(id) => {
                        ("cache_gc_generation", id)
                    }
                    pb::operation_resource_ref::Target::BindingId(id) => ("binding", id),
                };
                let authorization_scope_key = self
                    .db
                    .topology_operation_target_scope(target_kind, &target_id)
                    .await
                    .map_err(|error| RpcError::invalid(format!("operation target: {error:#}")))?
                    .ok_or_else(|| RpcError::not_found("operation target"))?;
                let scope = Scope::try_parse(&authorization_scope_key).ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!("target has invalid owner scope"))
                })?;
                let permission = topology_target_read_permission(target_kind);
                if self
                    .require_permission(&claims, permission, &scope)
                    .await
                    .is_err()
                {
                    return Err(RpcError::not_found("operation target"));
                }
                (Some((target_kind, target_id)), None)
            }
            None => {
                let scope_key = scope_selector
                    .ok_or_else(|| RpcError::invalid("authorization_scope_key is required"))?;
                let scope = Scope::try_parse(scope_key)
                    .ok_or_else(|| RpcError::invalid("authorization_scope_key is invalid"))?;
                self.require_permission(&claims, Permission::AuditRead, &scope)
                    .await?;
                (None, Some(scope_key.to_owned()))
            }
        };

        let selector = match (&target_selector, &scope_selector) {
            (Some((kind, id)), None) => format!("target:{kind}:{id}"),
            (None, Some(scope)) => format!("scope:{scope}"),
            _ => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "operation selector invariant failed"
                )));
            }
        };
        let selector_digest = format!("{:x}", Sha256::digest(selector.as_bytes()));
        let cursor = if req.page_token.is_empty() {
            None
        } else {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&req.page_token)
                .map_err(|_| RpcError::invalid("invalid operation page token"))?;
            let decoded = String::from_utf8(decoded)
                .map_err(|_| RpcError::invalid("invalid operation page token"))?;
            let mut fields = decoded.splitn(4, ':');
            let version = fields.next();
            let token_state = fields.next();
            let token_selector_digest = fields.next();
            let operation_id = fields.next();
            if version != Some("op2")
                || token_state != Some(req.state.as_str())
                || token_selector_digest != Some(selector_digest.as_str())
                || operation_id.is_none_or(str::is_empty)
            {
                return Err(RpcError::invalid(
                    "operation page token belongs to another inventory or state filter",
                ));
            }
            operation_id.map(str::to_owned)
        };
        let state = (!req.state.is_empty()).then_some(req.state.as_str());
        let page = match (&target_selector, &scope_selector) {
            (Some((target_kind, target_id)), None) => {
                self.db
                    .list_topology_operations_page(
                        target_kind,
                        target_id,
                        state,
                        req.page_size,
                        cursor.as_deref(),
                    )
                    .await
            }
            (None, Some(scope)) => {
                self.db
                    .list_scope_topology_operations_page(
                        scope,
                        state,
                        req.page_size,
                        cursor.as_deref(),
                    )
                    .await
            }
            _ => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "operation selector invariant failed"
                )));
            }
        }
        .map_err(|error| RpcError::invalid(format!("list operations: {error:#}")))?;
        let mut operations = Vec::with_capacity(page.records.len());
        for record in page.records {
            match self.authorized_operation(auth, &record.operation_id).await {
                Ok(authorized) => operations.push(self.operation_detail(&authorized).await?),
                Err(RpcError::NotFound(_) | RpcError::PermissionDenied(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(pb::ListOperationsResponse {
            operations,
            next_page_token: page
                .next_cursor
                .map(|operation_id| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
                        "op2:{}:{selector_digest}:{operation_id}",
                        req.state
                    ))
                })
                .unwrap_or_default(),
        })
    }
}
