//! Delivery mutations in the webhooks capability.

use super::*;

impl Database {
    // -- webhooks -----------------------------------------------------------

    /// Seeds a webhook subscription for a debug-build fixture.
    ///
    /// `events` is the set of event-type strings the hook subscribes to (an
    /// empty slice subscribes to *all* events). `secret_version_ref` is an
    /// opaque test-provider reference, never plaintext signing material.
    ///
    /// `url` is validated against the SSRF guard
    /// ([`aos_hub_model::url_guard::is_safe_remote_url`]) — the delivery worker `POST`s to
    /// it from inside the hub network, so a loopback/link-local/private or
    /// non-`http(s)` target is rejected here, just as mirror upstreams are.
    ///
    /// # Errors
    ///
    /// Returns an error when `url` fails the SSRF guard, or on database
    /// failure.
    #[cfg(any(test, debug_assertions, feature = "do-e2e-test-support"))]
    pub async fn seed_webhook_for_test(
        &self,
        org_id: i64,
        url: &str,
        secret_version_ref: &str,
        credential_fingerprint: &str,
        events: &[String],
    ) -> Result<i64> {
        aos_hub_model::url_guard::is_safe_remote_url(url).context("rejecting webhook URL")?;
        aos_hub_model::secret_version::validate_secret_version_ref(secret_version_ref)?;
        anyhow::ensure!(
            credential_fingerprint.len() == 64
                && credential_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "webhook credential fingerprint must be SHA-256 hex"
        );
        self.backend
            .execute_insert(
                "INSERT INTO webhooks
                 (org_id, url, secret_version_ref, credential_fingerprint, events,
                  active, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                &vals![
                    org_id,
                    url,
                    secret_version_ref,
                    credential_fingerprint,
                    serde_json::to_string(events)?,
                    unix_now()
                ],
            )
            .await
    }

    /// Creates one webhook through an actor-attributed control plan.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe URL, missing organization, duplicate
    /// plan, serialization failure, or checked transaction failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_webhook_from_plan(
        &self,
        org_id: i64,
        url: &str,
        secret_version_ref: &str,
        credential_fingerprint: &str,
        events: &[String],
        plan_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<i64> {
        aos_hub_model::url_guard::is_safe_remote_url(url).context("rejecting webhook URL")?;
        aos_hub_model::secret_version::validate_secret_version_ref(secret_version_ref)?;
        anyhow::ensure!(
            credential_fingerprint.len() == 64
                && credential_fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "webhook credential fingerprint must be SHA-256 hex"
        );
        let webhook_count = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM webhooks WHERE org_id = ?1",
                &vals![org_id],
            )
            .await?
            .context("webhook count query returned no row")?
            .get::<i64>(0)?;
        anyhow::ensure!(
            webhook_count < MAX_WEBHOOKS_PER_ORG as i64,
            "organization webhook limit reached"
        );
        let org_scope: String = self
            .backend
            .query_opt(
                "SELECT stable_id FROM orgs WHERE id = ?1 AND deleted_at IS NULL",
                &vals![org_id],
            )
            .await?
            .context("webhook owner organization does not exist")?
            .get(0)?;
        let id = portable_relational_id(uuid::Uuid::new_v4());
        let now = unix_now();
        let stable_id = format!("webhook:{id}");
        let event_id = uuid::Uuid::new_v4().simple().to_string();
        let new_json = serde_json::to_string(&serde_json::json!({
            "id": id,
            "url": url,
            "events": events,
            "secretVersionRef": secret_version_ref,
            "credentialFingerprint": credential_fingerprint,
            "active": true,
            "resourceVersion": 1,
        }))?;
        let payload_json = serde_json::to_string(&serde_json::json!({
            "changeId": plan_id,
            "webhookId": id,
            "resourceVersion": 1,
        }))?;
        self.backend
            .checked_batch(&[
                // Serialize the per-org cardinality guard on every SQL backend.
                // The update deliberately preserves the resource version: it is
                // an internal lock, not a user-visible organization mutation.
                Statement::new(
                    "UPDATE orgs SET updated_at = updated_at
                      WHERE id = ?1 AND deleted_at IS NULL",
                    vals![org_id],
                )
                .unchecked(),
                Statement::new(
                    format!(
                        "INSERT INTO webhooks
                         (id, org_id, url, secret_version_ref, credential_fingerprint,
                          events, active, created_at, updated_at, creation_plan_id)
                         SELECT ?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7, ?8
                          WHERE (SELECT COUNT(*) FROM webhooks WHERE org_id = ?2) < {}",
                        MAX_WEBHOOKS_PER_ORG
                    ),
                    vals![
                        id,
                        org_id,
                        url,
                        secret_version_ref,
                        credential_fingerprint,
                        serde_json::to_string(events)?,
                        now,
                        plan_id
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO change_requests
                     (change_id, actor_kind, actor_id, actor_label, scope, status,
                      summary, created_at, applied_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'applied', ?6, ?7, ?7)",
                    vals![
                        plan_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        org_scope,
                        format!("create webhook subscription {id}"),
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO change_request_revisions
                     (change_id, object_type, object_id, op, old_json, new_json, seq)
                     VALUES (?1, 'webhook', ?2, 'create', NULL, ?3, 0)",
                    vals![plan_id, stable_id, new_json],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO audit_log
                     (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                      action, scope, detail, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'webhook.created', ?6, ?7, ?8)",
                    vals![
                        event_id,
                        plan_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        org_scope,
                        payload_json,
                        now
                    ],
                )
                .expecting(1),
                Self::topology_event_statement(&NewTopologyEvent {
                    event_id: &event_id,
                    event_name: "webhook.created",
                    owner_scope_key: &org_scope,
                    resource_kind: "webhook",
                    resource_stable_id: &stable_id,
                    resource_generation_key: 1,
                    actor_kind,
                    actor_id,
                    actor_label,
                    payload_json: &payload_json,
                    occurred_at: now,
                }),
            ])
            .await?;
        Ok(id)
    }

    /// Load one webhook by id, regardless of org.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn webhook(&self, id: i64) -> Result<Option<WebhookRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, url, secret_version_ref, credential_fingerprint,
                        events, active, created_at, resource_version, updated_at
                 FROM webhooks WHERE id = ?1",
                &vals![id],
            )
            .await
            .context("loading webhook by id")?
            .map(|row| row_to_webhook(&row))
            .transpose()
    }

    /// Returns the webhook created by one exact control plan, if any.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn webhook_by_creation_plan(&self, plan_id: &str) -> Result<Option<WebhookRecord>> {
        self.backend
            .query_opt(
                "SELECT id, org_id, url, secret_version_ref, credential_fingerprint,
                        events, active, created_at, resource_version, updated_at
                   FROM webhooks WHERE creation_plan_id = ?1",
                &vals![plan_id],
            )
            .await?
            .map(|row| row_to_webhook(&row))
            .transpose()
    }

    /// Deletes a webhook fixture without producing lifecycle records.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[cfg(any(test, debug_assertions, feature = "do-e2e-test-support"))]
    pub async fn seed_delete_webhook_for_test(&self, id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute("DELETE FROM webhooks WHERE id = ?1", &vals![id])
            .await?;
        Ok(n > 0)
    }

    /// Deletes one webhook under an exact version and records the transition.
    ///
    /// # Errors
    ///
    /// Returns an error on serialization or checked transaction failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_webhook_at_version(
        &self,
        id: i64,
        expected_version: i64,
        change_id: &str,
        owner_scope_key: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<bool> {
        let Some(webhook) = self.webhook(id).await? else {
            return Ok(false);
        };
        if webhook.resource_version != expected_version {
            return Ok(false);
        }
        let now = unix_now();
        let stable_id = format!("webhook:{id}");
        let event_id = uuid::Uuid::new_v4().simple().to_string();
        let old_json = serde_json::to_string(&serde_json::json!({
            "id": id,
            "url": &webhook.url,
            "events": &webhook.events,
            "secretVersionRef": &webhook.secret_version_ref,
            "credentialFingerprint": &webhook.credential_fingerprint,
            "active": webhook.active,
            "resourceVersion": expected_version,
        }))?;
        let payload_json = serde_json::to_string(&serde_json::json!({
            "changeId": change_id,
            "webhookId": id,
            "resourceVersion": expected_version,
        }))?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO change_requests
                     (change_id, actor_kind, actor_id, actor_label, scope, status,
                      summary, created_at, applied_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'applied', ?6, ?7, ?7)",
                    vals![
                        change_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        owner_scope_key,
                        format!("delete webhook subscription {id}"),
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO change_request_revisions
                     (change_id, object_type, object_id, op, old_json, new_json, seq)
                     VALUES (?1, 'webhook', ?2, 'delete', ?3, NULL, 0)",
                    vals![change_id, stable_id, old_json],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO audit_log
                     (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                      action, scope, detail, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'webhook.deleted', ?6, ?7, ?8)",
                    vals![
                        event_id,
                        change_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        owner_scope_key,
                        payload_json,
                        now
                    ],
                )
                .expecting(1),
                Self::topology_event_statement(&NewTopologyEvent {
                    event_id: &event_id,
                    event_name: "webhook.deleted",
                    owner_scope_key,
                    resource_kind: "webhook",
                    resource_stable_id: &stable_id,
                    resource_generation_key: expected_version,
                    actor_kind,
                    actor_id,
                    actor_label,
                    payload_json: &payload_json,
                    occurred_at: now,
                }),
                Statement::new(
                    "DELETE FROM webhooks WHERE id = ?1 AND resource_version = ?2",
                    vals![id, expected_version],
                )
                .expecting(1),
            ])
            .await?;
        Ok(true)
    }

    /// Disables or enables a webhook fixture without a control-plane mutation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[cfg(any(test, debug_assertions))]
    pub async fn seed_set_webhook_active_for_test(&self, id: i64, active: bool) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "UPDATE webhooks SET active = ?2 WHERE id = ?1",
                &vals![id, active],
            )
            .await?;
        Ok(n > 0)
    }

    /// Commits one deduplicated registry event to the canonical topology outbox.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry/org identity is inconsistent, the
    /// event or payload violates delivery bounds, or persistence fails.
    pub async fn enqueue_operational_webhook_event(
        &self,
        org_id: i64,
        registry_slug: &str,
        event_name: &str,
        dedupe_key: &str,
        payload_json: &str,
    ) -> Result<bool> {
        anyhow::ensure!(
            aos_hub_model::webhook::is_supported_event_type(event_name)
                && aos_hub_model::webhook::is_safe_event_header_value(event_name),
            "unsupported webhook event"
        );
        anyhow::ensure!(
            payload_json.len() <= 1024 * 1024,
            "webhook event payload exceeds limit"
        );
        validate_json_value(payload_json, "webhook event payload")?;
        let registry = self
            .registry_by_slug(registry_slug)
            .await?
            .context("webhook event registry does not exist")?;
        anyhow::ensure!(
            registry.org_id == Some(org_id),
            "webhook event registry owner is inconsistent"
        );
        let event_id = hex::encode(sha2::Sha256::digest(
            format!(
                "aos-operational-webhook-v1\0{}\0{}\0{}",
                registry.stable_id, event_name, dedupe_key
            )
            .as_bytes(),
        ));
        let statement = Statement::new(
            "INSERT INTO topology_event_outbox
             (event_id, event_name, owner_scope_key, resource_kind,
              resource_stable_id, resource_generation_key, actor_kind, actor_id,
              actor_label, payload_json, occurred_at)
             SELECT ?1, ?2, scope_key, 'registry', ?4, ?5, 'system', NULL,
                    'registry-event-producer', ?6, ?7
               FROM authorization_scopes
              WHERE scope_key = ?3 AND retired_at IS NULL
                AND NOT EXISTS (SELECT 1 FROM topology_event_outbox WHERE event_id = ?1)",
            vals![
                event_id,
                event_name,
                registry.scope_key,
                registry.stable_id,
                registry.resource_version,
                payload_json,
                unix_now()
            ],
        );
        let inserted = self
            .backend
            .execute(&statement.sql, &statement.params)
            .await?;
        if inserted == 1 {
            return Ok(true);
        }
        anyhow::ensure!(
            self.backend
                .query_opt(
                    "SELECT 1 FROM topology_event_outbox
                      WHERE event_id = ?1 AND event_name = ?2
                        AND resource_stable_id = ?3",
                    &vals![event_id, event_name, registry.stable_id],
                )
                .await?
                .is_some(),
            "operational webhook event identity collision"
        );
        Ok(false)
    }
}
