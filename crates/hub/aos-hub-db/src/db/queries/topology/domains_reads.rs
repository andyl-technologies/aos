//! Domains reads in the topology capability.

use super::*;

impl Database {
    /// Lists instance-scoped domains or the domains owned by one organization.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_domains(&self, org_id: Option<i64>) -> Result<Vec<DomainRecord>> {
        let (sql, values) = match org_id {
            Some(id) => ("SELECT id, org_id, hostname, desired_dns_provider, observed_dns_state, desired_tls_provider,
                    observed_tls_state, access_provider_json, verified_at, created_at, updated_at, resource_version
                 FROM domains WHERE org_id = ?1 ORDER BY hostname", vals![id]),
            None => ("SELECT id, org_id, hostname, desired_dns_provider, observed_dns_state, desired_tls_provider,
                    observed_tls_state, access_provider_json, verified_at, created_at, updated_at, resource_version
                 FROM domains WHERE org_id IS NULL ORDER BY hostname", vals![]),
        };
        self.backend
            .query(sql, &values)
            .await?
            .iter()
            .map(row_to_domain)
            .collect()
    }

    /// List an org's claimed email domains (verified and pending), by domain.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_org_domains(&self, org_id: i64) -> Result<Vec<OrgDomainRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT domain, org_id, txt_challenge, verified_at,
                        resource_version, incarnation_id, mutation_plan_id
             FROM org_domains WHERE org_id = ?1 ORDER BY domain",
                &vals![org_id],
            )
            .await?;
        rows.iter()
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
            .collect()
    }
}
