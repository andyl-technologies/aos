//! Delivery mutations in the webhooks capability.

use super::*;

impl RpcService {
    /// Applies one webhook creation plan without resolving signing material.
    pub async fn apply_create_webhook(
        &self,
        auth: Option<&str>,
        req: pb::ApplyWebhookMutationRequest,
    ) -> Result<pb::CreateWebhookResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_webhook",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            "create_webhook",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, WebhookCreatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_webhook",
                Some(&req.confirmation_hash),
            )
            .await?;
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&input.request.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&input.owner_scope_key),
        )
        .await?;
        if org.id != input.org_id || org.stable_id != input.owner_scope_key {
            return Err(RpcError::FailedPrecondition(
                "webhook owner identity changed after planning".to_string(),
            ));
        }
        let record = if let Some(record) = self
            .db
            .webhook_by_creation_plan(&plan.plan_id)
            .await
            .map_err(RpcError::internal)?
        {
            record
        } else {
            let created = self
                .db
                .create_webhook_from_plan(
                    org.id,
                    &input.request.url,
                    &input.request.secret_version_ref,
                    &input.request.credential_fingerprint,
                    &input.request.events,
                    &plan.plan_id,
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                )
                .await;
            match created {
                Ok(id) => self
                    .db
                    .webhook(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("created webhook disappeared"))
                    })?,
                Err(insert_error) => self
                    .db
                    .webhook_by_creation_plan(&plan.plan_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::internal(insert_error))?,
            }
        };
        if record.org_id != org.id
            || record.url != input.request.url
            || record.events != input.request.events
            || record.secret_version_ref != input.request.secret_version_ref
            || record.credential_fingerprint != input.request.credential_fingerprint
        {
            return Err(RpcError::FailedPrecondition(
                "webhook plan result does not match the sealed request".to_string(),
            ));
        }
        let response = pb::CreateWebhookResponse {
            webhook: Some(webhook_message(
                record.id,
                org.slug,
                record.url,
                record.events,
                record.active,
                record.created_at,
                record.resource_version,
                record.updated_at,
                record.secret_version_ref,
                record.credential_fingerprint,
            )),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one webhook deletion plan exactly once.
    pub async fn apply_delete_webhook(
        &self,
        auth: Option<&str>,
        req: pb::ApplyWebhookMutationRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_webhook",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            "delete_webhook",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, WebhookDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_webhook",
                Some(&req.confirmation_hash),
            )
            .await?;
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_id(input.org_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("org"))?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&input.owner_scope_key),
        )
        .await?;
        if org.stable_id != input.owner_scope_key {
            return Err(RpcError::FailedPrecondition(
                "webhook owner identity changed after planning".to_string(),
            ));
        }
        if let Some(webhook) = self
            .db
            .webhook(input.webhook_id)
            .await
            .map_err(RpcError::internal)?
        {
            if webhook.org_id != input.org_id {
                return Err(RpcError::FailedPrecondition(
                    "webhook owner changed after planning".to_string(),
                ));
            }
            let deleted = self
                .db
                .delete_webhook_at_version(
                    webhook.id,
                    input.expected_resource_version,
                    &plan.plan_id,
                    &input.owner_scope_key,
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            if !deleted
                && (self
                    .db
                    .webhook(input.webhook_id)
                    .await
                    .map_err(RpcError::internal)?
                    .is_some()
                    || !self
                        .db
                        .list_revisions(&plan.plan_id)
                        .await
                        .map_err(RpcError::internal)?
                        .iter()
                        .any(|revision| {
                            revision.object_type == "webhook"
                                && revision.object_id == format!("webhook:{}", input.webhook_id)
                                && revision.op == "delete"
                        }))
            {
                return Err(RpcError::FailedPrecondition(
                    "webhook changed after planning".to_string(),
                ));
            }
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
