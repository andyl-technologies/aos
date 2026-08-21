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

/// Resolves the immutable owner scope for a typed registry or cache surface.
///
/// Organization-owned surface slugs begin with their organization slug. The
/// human-facing segment is used only to fetch the organization record; the
/// returned authorization scope always comes from that typed response.
///
/// # Errors
///
/// Returns an error when the surface is malformed or its organization cannot
/// be resolved.
pub(super) async fn surface_authorization_scope(
    client: &ApiClient,
    surface: &aos_proto_types::SurfaceRef,
) -> Result<(String, Option<String>), String> {
    use aos_proto_types::surface_ref::Target;

    let slug = match surface.target.as_ref() {
        Some(Target::RegistrySlug(slug) | Target::CacheSlug(slug)) if !slug.is_empty() => slug,
        _ => return Err("the surface has no canonical slug".to_string()),
    };
    let Some((organization, _)) = slug.split_once('/') else {
        return Ok(("instance".to_string(), None));
    };
    let organization = organization.to_string();
    let scope = organization_authorization_scope(client, organization.clone()).await?;
    Ok((scope, Some(organization)))
}
