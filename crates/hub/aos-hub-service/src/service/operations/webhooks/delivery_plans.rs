//! Delivery plans in the webhooks capability.

use super::*;

impl RpcService {
    /// Plans an org webhook subscription using an immutable signing-secret reference.
    ///
    /// The webhook is created under the named org subscribed to `events` (an
    /// empty list subscribes to all event types). The request carries only an
    /// immutable operator-managed secret-provider reference and optional
    /// fingerprint; signing material never enters the control plan or API
    /// response. Requires [`Permission::MembersManage`] (admin+) on the org
    /// scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `members.manage` on
    /// the org, [`RpcError::NotFound`] for an unknown org,
    /// [`RpcError::InvalidArgument`] for an empty URL or a URL that fails the
    /// SSRF guard ([`aos_hub_model::url_guard::is_safe_remote_url`] — loopback/
    /// link-local/private/non-`http(s)` targets), and [`RpcError::Internal`] on
    /// database failure.
    pub async fn plan_create_webhook(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanCreateWebhookRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        require_absent_resource_version(&req.expected_resource_version)?;
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        if self
            .db
            .list_webhooks(org.id)
            .await
            .map_err(RpcError::internal)?
            .len()
            >= aos_hub_db::db::MAX_WEBHOOKS_PER_ORG
        {
            return Err(RpcError::FailedPrecondition(
                "organization webhook limit reached".to_string(),
            ));
        }
        req.url = req.url.trim().to_string();
        if req.url.is_empty() {
            return Err(RpcError::invalid("webhook url is required"));
        }
        // The delivery worker POSTs to this URL from inside the hub network, so
        // reject loopback/link-local/private/non-http(s) targets (create_webhook
        // re-checks; this surfaces a clear invalid-argument error).
        if let Err(err) = aos_hub_model::url_guard::is_safe_remote_url(&req.url) {
            return Err(RpcError::invalid(format!("rejecting webhook url: {err:#}")));
        }
        if req.events.iter().collect::<BTreeSet<_>>().len() != req.events.len() {
            return Err(RpcError::invalid("webhook events must be unique"));
        }
        if let Some(event) = req
            .events
            .iter()
            .find(|event| !crate::webhook::is_supported_event_type(event))
        {
            return Err(RpcError::invalid(format!(
                "unsupported webhook event type '{event}'"
            )));
        }
        req.secret_version_ref = req.secret_version_ref.trim().to_string();
        aos_hub_model::secret_version::validate_secret_version_ref(&req.secret_version_ref)
            .map_err(|error| RpcError::invalid(format!("invalid secret_version_ref: {error:#}")))?;
        req.credential_fingerprint = req.credential_fingerprint.trim().to_ascii_lowercase();
        if req.credential_fingerprint.len() != 64
            || !req
                .credential_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RpcError::invalid(
                "credential_fingerprint is required and must be a 64-character SHA-256 hex digest",
            ));
        }
        let secrets = self.secret_versions.as_deref().ok_or_else(|| {
            RpcError::FailedPrecondition("secret-version provider is not configured".to_string())
        })?;
        let resolved = secrets
            .resolve(&req.secret_version_ref)
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!(
                    "secret version cannot be resolved: {error:#}"
                ))
            })?;
        aos_hub_model::secret_version::verify_secret_fingerprint(
            &resolved,
            &req.credential_fingerprint,
        )
        .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        drop(resolved);
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = WebhookCreatePlanInput {
            request: req,
            org_id: org.id,
            owner_scope_key: org.stable_id.clone(),
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "create_webhook",
            &org.stable_id,
            &input,
            &idempotency_key,
            vec![format!(
                "create webhook subscription to '{}'",
                input.request.url
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// `WebhookService.DeleteWebhook` — remove a webhook (and its queued
    /// deliveries) by id.
    ///
    /// Requires [`Permission::MembersManage`] on the *owning org's* scope,
    /// resolved from the webhook's `org_id` so the check binds to the resource
    /// being deleted rather than a caller-supplied scope.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::NotFound`] for an unknown webhook id or its (vanished) org,
    /// [`RpcError::PermissionDenied`] when the caller lacks `members.manage` on
    /// the owning org, and [`RpcError::Internal`] on database failure.
    pub async fn plan_delete_webhook(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDeleteWebhookRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let webhook = self
            .db
            .webhook(req.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("webhook"))?;
        let org = self
            .db
            .org_by_id(webhook.org_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("org"))?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        if expected <= 0 || expected != webhook.resource_version {
            return Err(RpcError::FailedPrecondition(
                "webhook resource version is required and must be current".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = WebhookDeletePlanInput {
            webhook_id: webhook.id,
            org_id: org.id,
            owner_scope_key: org.stable_id.clone(),
            expected_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_webhook",
            &org.stable_id,
            &input,
            &idempotency_key,
            vec![format!("delete webhook subscription {}", webhook.id)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }
}
