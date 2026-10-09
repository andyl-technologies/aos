//! Domains mutations in the topology capability.

use super::*;

impl Database {
    // -- topology resources -------------------------------------------------

    /// Creates a normalized domain in instance or organization scope.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid hostname or access-provider document,
    /// a missing organization, a hostname collision, or a database failure.
    pub async fn create_domain(&self, input: &NewDomain) -> Result<DomainRecord> {
        let hostname = normalize_topology_hostname(&input.hostname)?;
        if let Some(provider) = input.desired_dns_provider.as_deref() {
            validate_key_bytes(provider, "DNS provider", 64)?;
        }
        if let Some(provider) = input.desired_tls_provider.as_deref() {
            validate_key_bytes(provider, "TLS provider", 64)?;
        }
        validate_json_object(&input.access_provider_json, "domain access provider")?;
        let now = unix_now();
        let affected = if let Some(org_id) = input.org_id {
            self.backend
                .execute(
                    "INSERT INTO domains (org_id, hostname, desired_dns_provider, desired_tls_provider,
                    access_provider_json, created_at, updated_at)
                 SELECT id, ?2, ?3, ?4, ?5, ?6, ?6 FROM orgs WHERE id = ?1",
                    &vals![
                        org_id,
                        hostname,
                        input.desired_dns_provider,
                        input.desired_tls_provider,
                        input.access_provider_json,
                        now
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO domains (org_id, hostname, desired_dns_provider, desired_tls_provider,
                    access_provider_json, created_at, updated_at)
                 VALUES (NULL, ?1, ?2, ?3, ?4, ?5, ?5)",
                    &vals![
                        hostname,
                        input.desired_dns_provider,
                        input.desired_tls_provider,
                        input.access_provider_json,
                        now
                    ],
                )
                .await?
        };
        if affected != 1 {
            bail!("domain organization does not exist");
        }
        self.domain_by_hostname(&hostname)
            .await?
            .context("created domain disappeared")
    }

    /// Returns a domain by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn domain(&self, id: i64) -> Result<Option<DomainRecord>> {
        let rows = self.backend.query(
            "SELECT id, org_id, hostname, desired_dns_provider, observed_dns_state, desired_tls_provider,
                observed_tls_state, access_provider_json, verified_at, created_at, updated_at, resource_version
             FROM domains WHERE id = ?1", &vals![id]).await?;
        rows.first().map(row_to_domain).transpose()
    }

    /// Returns a domain by its globally unique normalized hostname.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn domain_by_hostname(&self, hostname: &str) -> Result<Option<DomainRecord>> {
        let hostname = normalize_topology_hostname(hostname)?;
        let rows = self.backend.query(
            "SELECT id, org_id, hostname, desired_dns_provider, observed_dns_state, desired_tls_provider,
                observed_tls_state, access_provider_json, verified_at, created_at, updated_at, resource_version
             FROM domains WHERE hostname = ?1", &vals![hostname]).await?;
        rows.first().map(row_to_domain).transpose()
    }

    /// Updates a domain's desired provider and access configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid provider/JSON values, a stale version, a missing
    /// domain, or database failure.
    pub async fn update_domain(&self, id: i64, input: &UpdateDomain) -> Result<DomainRecord> {
        if let Some(provider) = input.desired_dns_provider.as_deref() {
            validate_key_bytes(provider, "DNS provider", 64)?;
        }
        if let Some(provider) = input.desired_tls_provider.as_deref() {
            validate_key_bytes(provider, "TLS provider", 64)?;
        }
        validate_json_object(&input.access_provider_json, "domain access provider")?;
        let affected = self
            .backend
            .execute(
                "UPDATE domains SET observed_dns_state = CASE
                      WHEN desired_dns_provider = ?3 OR
                        (desired_dns_provider IS NULL AND ?3 IS NULL)
                      THEN observed_dns_state
                      WHEN ?3 IS NULL THEN 'unconfigured' ELSE 'pending' END,
                    observed_tls_state = CASE
                      WHEN desired_tls_provider = ?4 OR
                        (desired_tls_provider IS NULL AND ?4 IS NULL)
                      THEN observed_tls_state
                      WHEN ?4 IS NULL THEN 'unconfigured' ELSE 'pending' END,
                    verified_at = CASE WHEN
                      (desired_dns_provider = ?3 OR
                        (desired_dns_provider IS NULL AND ?3 IS NULL)) AND
                      (desired_tls_provider = ?4 OR
                        (desired_tls_provider IS NULL AND ?4 IS NULL))
                      THEN verified_at ELSE NULL END,
                    desired_dns_provider = ?3, desired_tls_provider = ?4,
                    access_provider_json = ?5,
                    updated_at = ?6,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND resource_version = ?2",
                &vals![
                    id,
                    input.expected_version,
                    input.desired_dns_provider,
                    input.desired_tls_provider,
                    input.access_provider_json,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            bail!("domain is missing or its resource version is stale");
        }
        self.domain(id).await?.context("updated domain disappeared")
    }

    /// Records reconciler-observed DNS/TLS state separately from desired config.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or inconsistent observed state, a stale
    /// version, a missing domain, or database failure.
    pub async fn record_domain_observation(
        &self,
        id: i64,
        expected_version: i64,
        dns_state: &str,
        tls_state: &str,
        verified_at: Option<i64>,
    ) -> Result<DomainRecord> {
        if !matches!(
            dns_state,
            "unconfigured" | "pending" | "verified" | "failed"
        ) {
            bail!("invalid observed DNS state '{dns_state}'");
        }
        if !matches!(tls_state, "unconfigured" | "pending" | "active" | "failed") {
            bail!("invalid observed TLS state '{tls_state}'");
        }
        if verified_at.is_some() != (dns_state == "verified" && tls_state == "active") {
            bail!("verified_at requires verified DNS and active TLS, and vice versa");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE domains SET observed_dns_state = ?3, observed_tls_state = ?4,
                verified_at = ?5, updated_at = ?6,
                resource_version = resource_version + 1
             WHERE id = ?1 AND resource_version = ?2",
                &vals![
                    id,
                    expected_version,
                    dns_state,
                    tls_state,
                    verified_at,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            bail!("domain is missing or its resource version is stale");
        }
        self.domain(id)
            .await?
            .context("observed domain disappeared")
    }

    /// Deletes a domain when its optimistic-concurrency version matches.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when dependent routes/defaults exist.
    pub async fn delete_domain(&self, id: i64, expected_version: i64) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM domains WHERE id = ?1 AND resource_version = ?2",
                &vals![id, expected_version],
            )
            .await?
            == 1)
    }

    /// Lists domain-probe operations eligible for a controller claim.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn due_domain_probe_operations(
        &self,
        stale_before: i64,
        limit: usize,
    ) -> Result<Vec<TopologyOperationRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations o
                     WHERE o.operation_kind = 'domain_probe'
                       AND (o.state = 'pending'
                         OR (o.state = 'running' AND o.started_at <= ?1))
                     ORDER BY o.created_at, o.operation_id LIMIT ?2"
                ),
                &vals![stale_before, i64::try_from(limit)?],
            )
            .await?
            .iter()
            .map(row_to_topology_operation)
            .collect()
    }

    /// Claims a pending or stale-running domain probe under operation CAS.
    ///
    /// A running claim becomes stealable after `lease_seconds`, allowing a
    /// request terminated during external I/O to be retried without leaving the
    /// operation permanently stuck. A fresh running claim is left untouched.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lease, database failure, or malformed
    /// operation state.
    pub async fn claim_domain_probe_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        lease_seconds: i64,
    ) -> Result<Option<TopologyOperationRecord>> {
        if lease_seconds <= 0 {
            bail!("domain probe claim lease must be positive");
        }
        let now = unix_now();
        let changed = self
            .backend
            .execute(
                "UPDATE topology_operations SET state = 'running', started_at = ?3,
               finished_at = NULL, error = NULL, resource_version = resource_version + 1
             WHERE operation_id = ?1 AND operation_kind = 'domain_probe'
               AND resource_version = ?2
               AND (state = 'pending' OR (state = 'running' AND started_at <= ?4))",
                &vals![operation_id, expected_version, now, now - lease_seconds],
            )
            .await?;
        if changed == 0 {
            return Ok(None);
        }
        self.topology_operation(operation_id).await
    }

    /// Seeds a domain claim with a fresh DNS-TXT challenge for a test fixture.
    ///
    /// Returns the generated `txt_challenge` value the org must publish as a
    /// TXT record at the domain to prove control; the domain starts
    /// **unverified** (`verified_at` NULL) until [`Database::verify_org_domain`]
    /// stamps it. Re-claiming a domain *owned by the same org* rotates its
    /// challenge and resets it to unverified.
    ///
    /// A domain is a global, uniquely-keyed routing key (it steers
    /// domain-based SSO login), so it may belong to at most one org. Claiming
    /// a domain already held by a **different** org is refused — without this
    /// guard the `ON CONFLICT(domain)` upsert would silently re-point the row
    /// at the caller's org and reset its verification, letting one org seize
    /// another's verified domain (a cross-tenant claim theft / login DoS).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, or if the domain is already
    /// claimed by a different organization.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub async fn add_org_domain(&self, org_id: i64, domain: &str) -> Result<String> {
        let domain = domain.trim().to_lowercase();
        let challenge = format!(
            "aos-domain-verify={}",
            aos_hub_model::auth::session::new_session_secret()
        );
        // The ownership check and the upsert must be atomic: a check-then-act
        // split lets two org admins racing the same domain both read "no
        // conflict" and both upsert, the last writer re-pointing `org_id` and
        // wiping the victim's `verified_at` (a cross-tenant domain login-DoS).
        // sqlite/postgres do it in one guarded upsert (the `DO UPDATE … WHERE`
        // only fires when the row is already ours). MySQL has no WHERE on `ON
        // DUPLICATE KEY UPDATE`, so it reads the current owner first and bails
        // on a foreign claim, then upserts. NOTE: unlike the single-statement
        // guarded upsert, this read-then-write carries a small residual race —
        // two admins racing the *same* unclaimed domain could both read "no
        // owner" and both upsert, the last writer winning. The guarded upsert on
        // sqlite/postgres closes that window; mysql cannot express it, so this
        // path accepts the narrow race (a freshly-claimed domain is still
        // unverified until a DNS-TXT proof, which the loser would have to win
        // independently).
        if self.dialect() == Dialect::Mysql {
            let existing = self
                .backend
                .query_opt(
                    "SELECT org_id FROM org_domains WHERE domain = ?1",
                    &vals![domain],
                )
                .await?;
            if let Some(row) = existing {
                let owner_org: i64 = row.get(0)?;
                if owner_org != org_id {
                    anyhow::bail!("domain '{domain}' is already claimed by another organization");
                }
            }
            self.backend
                .execute(
                    "INSERT INTO org_domains (domain, org_id, txt_challenge, verified_at)
                     VALUES (?1, ?2, ?3, NULL)
                     ON CONFLICT(domain) DO UPDATE SET
                         org_id = excluded.org_id,
                         txt_challenge = excluded.txt_challenge,
                         verified_at = NULL,
                         resource_version = org_domains.resource_version + 1,
                         mutation_plan_id = NULL",
                    &vals![domain, org_id, challenge],
                )
                .await?;
        } else {
            // The `WHERE org_domains.org_id = excluded.org_id` guard makes the
            // upsert a no-op (0 rows) when a *different* org holds the claim, so
            // a single statement enforces the invariant atomically.
            let affected = self
                .backend
                .execute(
                    "INSERT INTO org_domains (domain, org_id, txt_challenge, verified_at)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT(domain) DO UPDATE SET
                     org_id = excluded.org_id,
                     txt_challenge = excluded.txt_challenge,
                     verified_at = NULL,
                     resource_version = org_domains.resource_version + 1,
                     mutation_plan_id = NULL
                 WHERE org_domains.org_id = excluded.org_id",
                    &vals![domain, org_id, challenge],
                )
                .await?;
            if affected == 0 {
                anyhow::bail!("domain '{domain}' is already claimed by another organization");
            }
        }
        Ok(challenge)
    }

    /// Look up a claimed domain (verified or not).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_domain(&self, domain: &str) -> Result<Option<OrgDomainRecord>> {
        let domain = domain.trim().to_lowercase();
        self.backend
            .query_opt(
                "SELECT domain, org_id, txt_challenge, verified_at,
                        resource_version, incarnation_id, mutation_plan_id
                   FROM org_domains WHERE domain = ?1",
                &vals![domain],
            )
            .await
            .context("loading org domain")?
            .map(|row| -> Result<OrgDomainRecord> {
                Ok(OrgDomainRecord {
                    domain: row.get(0)?,
                    org_id: row.get(1)?,
                    txt_challenge: row.get(2)?,
                    verified_at: row.get(3)?,
                    resource_version: row.get(4)?,
                    incarnation_id: row.get(5)?,
                    mutation_plan_id: row.get(6)?,
                })
            })
            .transpose()
    }

    /// Marks a fixture domain verified without resolving DNS.
    ///
    /// This is the **persistence hook**: the actual DNS-TXT lookup is the
    /// caller's responsibility (an ops tool or the CLI resolving the TXT
    /// record and matching it against [`OrgDomainRecord::txt_challenge`]).
    /// Keeping the lookup outside the database makes the capture flow
    /// offline-testable and lets a real resolver drop in without touching the
    /// store. Returns `Ok(false)` when no such domain is claimed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub async fn verify_org_domain(&self, domain: &str) -> Result<bool> {
        let domain = domain.trim().to_lowercase();
        let n = self
            .backend
            .execute(
                "UPDATE org_domains
                    SET verified_at = ?2,
                        resource_version = resource_version + 1,
                        mutation_plan_id = NULL
                  WHERE domain = ?1",
                &vals![domain, unix_now()],
            )
            .await?;
        Ok(n > 0)
    }

    /// Removes a domain row while constructing a test fixture.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub async fn delete_org_domain(&self, org_id: i64, domain: &str) -> Result<bool> {
        let domain = domain.trim().to_lowercase();
        let n = self
            .backend
            .execute(
                "DELETE FROM org_domains WHERE domain = ?1 AND org_id = ?2",
                &vals![domain, org_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Applies a domain claim or challenge rotation and completes its plan atomically.
    ///
    /// A new claim is an insert-only operation on every backend, including
    /// MySQL, so two organizations racing the same unclaimed domain cannot
    /// overwrite each other. A rotation is fenced by owner and resource version.
    ///
    /// # Errors
    ///
    /// Returns an error on a conflicting claim, changed revision, invalid plan
    /// metadata, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_org_domain_claim_plan(
        &self,
        record: &OrgDomainRecord,
        baseline_resource_version: Option<i64>,
        baseline_incarnation_id: Option<&str>,
        scope: &str,
        plan_id: &str,
        apply_idempotency_key: &str,
        result_json: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        audit_event_id: &str,
    ) -> Result<()> {
        validate_key_bytes(apply_idempotency_key, "apply idempotency key", 128)?;
        validate_key_bytes(audit_event_id, "audit event id", 64)?;
        validate_json_value(result_json, "apply result")?;
        let mutation = match baseline_resource_version {
            Some(version) => Statement::new(
                "UPDATE org_domains SET txt_challenge = ?3, verified_at = NULL,
                        resource_version = resource_version + 1,
                        incarnation_id = ?4, mutation_plan_id = ?5
                  WHERE domain = ?1 AND org_id = ?2 AND resource_version = ?6
                    AND (incarnation_id = ?7
                         OR (incarnation_id IS NULL AND ?7 IS NULL))",
                vals![
                    record.domain,
                    record.org_id,
                    record.txt_challenge,
                    record.incarnation_id,
                    plan_id,
                    version,
                    baseline_incarnation_id
                ],
            )
            .expecting(1),
            None => Statement::new(
                "INSERT INTO org_domains
                 (domain, org_id, txt_challenge, verified_at, resource_version,
                  incarnation_id, mutation_plan_id)
                 VALUES (?1, ?2, ?3, NULL, 1, ?4, ?5)",
                vals![
                    record.domain,
                    record.org_id,
                    record.txt_challenge,
                    record.incarnation_id,
                    plan_id
                ],
            )
            .expecting(1),
        };
        self.apply_org_domain_mutation_plan(
            mutation,
            "domain.claim",
            &record.domain,
            scope,
            plan_id,
            apply_idempotency_key,
            result_json,
            actor_kind,
            actor_id,
            actor_label,
            audit_event_id,
        )
        .await
    }

    /// Verifies an exact pending domain challenge and completes its plan atomically.
    ///
    /// # Errors
    ///
    /// Returns an error when ownership, challenge, revision, or plan state changed.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_org_domain_verify_plan(
        &self,
        record: &OrgDomainRecord,
        incarnation_id: &str,
        verified_at: i64,
        scope: &str,
        plan_id: &str,
        apply_idempotency_key: &str,
        result_json: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
        audit_event_id: &str,
    ) -> Result<()> {
        let mutation = Statement::new(
            "UPDATE org_domains SET verified_at = ?6,
                    resource_version = resource_version + 1,
                    incarnation_id = ?4, mutation_plan_id = ?5
              WHERE domain = ?1 AND org_id = ?2 AND txt_challenge = ?3
                AND resource_version = ?7 AND verified_at IS NULL
                AND (incarnation_id = ?8
                     OR (incarnation_id IS NULL AND ?8 IS NULL))",
            vals![
                record.domain,
                record.org_id,
                record.txt_challenge,
                incarnation_id,
                plan_id,
                verified_at,
                record.resource_version,
                record.incarnation_id
            ],
        )
        .expecting(1);
        self.apply_org_domain_mutation_plan(
            mutation,
            "domain.verify",
            &record.domain,
            scope,
            plan_id,
            apply_idempotency_key,
            result_json,
            actor_kind,
            actor_id,
            actor_label,
            audit_event_id,
        )
        .await
    }

    /// Resolve the org that owns a **verified** domain, if any.
    ///
    /// Only verified domains route logins; an unverified claim returns
    /// `Ok(None)` so a forged claim cannot capture another org's users.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn org_for_domain(&self, domain: &str) -> Result<Option<i64>> {
        let domain = domain.trim().to_lowercase();
        self.backend
            .query_opt(
                "SELECT org_id FROM org_domains WHERE domain = ?1 AND verified_at IS NOT NULL",
                &vals![domain],
            )
            .await
            .context("resolving org for verified domain")?
            .map(|row| row.get(0))
            .transpose()
    }
}
