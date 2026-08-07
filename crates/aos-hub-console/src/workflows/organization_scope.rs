//! Immutable organization-scope resolution for scoped console workflows.
//!
//! Organization routes contain a human-facing slug. Authorization and
//! topology ownership never derive a scope from that slug; callers resolve the
//! typed organization response and use its non-reusable scope key.

use crate::transport::ApiClient;

/// Resolves an organization slug to its immutable authorization scope.
///
/// # Errors
///
/// Returns an error when the API request fails or the response omits the
/// organization or its immutable authorization scope.
pub(super) async fn organization_authorization_scope(
    client: &ApiClient,
    slug: String,
) -> Result<String, String> {
    let response = client
        .call::<_, aos_proto_types::OrganizationResponse>(
            aos_proto_types::ORGANIZATION_SERVICE_GET_ORGANIZATION_PATH,
            &aos_proto_types::GetOrganizationRequest { slug },
        )
        .await
        .map_err(|failure| failure.to_string())?;
    let organization = response
        .organization
        .ok_or_else(|| "the Hub omitted the organization".to_string())?;
    if organization.authorization_scope_key.is_empty() {
        return Err("the Hub omitted the immutable organization scope".to_string());
    }
    Ok(organization.authorization_scope_key)
}
