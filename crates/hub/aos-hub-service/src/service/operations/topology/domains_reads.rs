//! Domains reads in the topology capability.

use super::*;

impl RpcService {
    /// Lists delivery domains in one exact, stable owner scope.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, pagination, or persistence error.
    pub async fn list_domains(
        &self,
        auth: Option<&str>,
        req: pb::ListDomainsRequest,
    ) -> Result<pb::ListDomainsResponse, RpcError> {
        self.require_delivery_scope(auth, &req.owner_scope_key, Permission::DomainRead)
            .await?;
        let page = self
            .db
            .list_delivery_domains_page(
                &req.owner_scope_key,
                req.page_size,
                (!req.page_token.is_empty()).then_some(req.page_token.as_str()),
            )
            .await
            .map_err(|error| RpcError::invalid(format!("list domains: {error:#}")))?;
        let domains = page
            .records
            .into_iter()
            .map(Self::delivery_domain_message)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(pb::ListDomainsResponse {
            domains,
            next_page_token: page.next_cursor.unwrap_or_default(),
        })
    }

    /// Reads one delivery domain by stable identity or canonical hostname.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, not-found, or persistence error.
    pub async fn get_domain(
        &self,
        auth: Option<&str>,
        req: pb::GetTopologyResourceRequest,
    ) -> Result<pb::DomainResponse, RpcError> {
        self.require_claims(auth)?;
        let domain = match self
            .db
            .delivery_domain(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
        {
            Some(domain) => Some(domain),
            None if aos_hub_db::db::canonical_delivery_hostname(&req.stable_id).is_ok() => self
                .db
                .delivery_domain_by_hostname(&req.stable_id)
                .await
                .map_err(RpcError::internal)?,
            None => None,
        }
        .ok_or_else(|| RpcError::not_found("domain"))?;
        if let Err(error) = self
            .require_delivery_scope(auth, &domain.owner_scope_key, Permission::DomainRead)
            .await
        {
            return match error {
                RpcError::Internal | RpcError::Unauthenticated(_) => Err(error),
                _ => Err(RpcError::not_found("domain")),
            };
        }
        Ok(pb::DomainResponse {
            domain: Some(Self::delivery_domain_message(domain)?),
        })
    }

    /// Lists organization email-domain claims without exposing credentials.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, paging, or persistence error.
    pub async fn list_organization_domains(
        &self,
        auth: Option<&str>,
        req: pb::ListOrganizationDomainsRequest,
    ) -> Result<pb::ListOrganizationDomainsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&org.stable_id))
            .await?;
        let domains = self
            .db
            .list_org_domains(org.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|record| organization_domain_message(&org.slug, record))
            .collect();
        let (domains, next_page_token) = paginate(domains, req.page_size, &req.page_token)?;
        Ok(pb::ListOrganizationDomainsResponse {
            domains,
            next_page_token,
        })
    }

    /// Reads one organization email-domain claim.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, lookup, or persistence error.
    pub async fn get_organization_domain(
        &self,
        auth: Option<&str>,
        req: pb::GetOrganizationDomainRequest,
    ) -> Result<pb::OrganizationDomainResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::parse(&org.stable_id))
            .await?;
        let domain = canonical_identity_domain(&req.domain)?;
        let record = self
            .db
            .org_domain(&domain)
            .await
            .map_err(RpcError::internal)?
            .filter(|record| record.org_id == org.id)
            .ok_or_else(|| RpcError::not_found("organization domain"))?;
        Ok(pb::OrganizationDomainResponse {
            domain: Some(organization_domain_message(&org.slug, record)),
        })
    }
}
