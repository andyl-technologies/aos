//! Authenticated native release reference browsing and indexed search.
//!
//! A completed signed release catalog supplies every document coordinate.
//! Detail reads reverify the immutable directory and use the shared runtime
//! reader; generated search projections never replace signed artifact bytes.

use super::browse::{BrowseQuery, Rendered, browse_rate_limited, load_visible, session_indicator};
use super::release_browse::{ReleaseContext, unavailable_page};
use crate::clock::Instant;
use crate::service::RpcService;
use axum::http::HeaderMap;

/// Renders native indexed reference entries for the authorized release.
pub(crate) async fn browse(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    query: &BrowseQuery,
    children_only: bool,
) -> Rendered {
    if let Some(limited) = browse_rate_limited(svc, headers).await {
        return limited;
    }
    if children_only {
        return Rendered::NotFound;
    }
    let started = Instant::now();
    let Some((registry, status)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let context =
        match ReleaseContext::load(&svc.db, registry.id, query.release.as_deref(), false).await {
            Ok(context) => context,
            Err(error) => return error,
        };
    let session = session_indicator(svc, headers).await;
    let Some(release) = context.selected() else {
        return Rendered::Html(unavailable_page(
            &registry,
            status.as_ref(),
            &context,
            "docs",
            "No completed release documentation is available.",
            started,
            &session,
        ));
    };
    if let Some(redirect) = query.pin_release(&format!("/{slug}/-/docs"), &context) {
        return redirect;
    }
    match svc
        .db
        .native_documentation_at_release(registry.id, release)
        .await
    {
        Ok(documents) => native_index_page(
            slug,
            release,
            query,
            &documents,
            status.as_ref(),
            started,
            &session,
        ),
        Err(_) => Rendered::ServiceUnavailable,
    }
}

/// Resolves a coordinate URL to its exact native signed release reference.
pub(crate) async fn package_reference(
    svc: &RpcService,
    headers: &HeaderMap,
    slug: &str,
    package: &str,
    version: &str,
    platform: &str,
    query: &BrowseQuery,
) -> Rendered {
    if let Some(limited) = browse_rate_limited(svc, headers).await {
        return limited;
    }
    let Some((registry, _)) = load_visible(svc, headers, slug).await else {
        return Rendered::NotFound;
    };
    let locator = match svc
        .db
        .native_documentation_locator(
            registry.id,
            package,
            version,
            platform,
            query.release.as_deref(),
        )
        .await
    {
        Ok(Some(locator)) => locator,
        Ok(None) => return Rendered::NotFound,
        Err(_) => return Rendered::ServiceUnavailable,
    };
    match native_package_reference(
        svc,
        registry.id,
        slug,
        &locator.release,
        package,
        version,
        platform,
        query,
        headers,
    )
    .await
    {
        Ok(Some(rendered)) => rendered,
        Ok(None) => Rendered::NotFound,
        Err(error) => error,
    }
}

/// Reads native package documentation from the same completed signed release catalog.
#[allow(clippy::too_many_arguments)]
async fn native_package_reference(
    svc: &RpcService,
    registry_id: i64,
    slug: &str,
    release: &str,
    package: &str,
    version: &str,
    platform: &str,
    query: &BrowseQuery,
    headers: &HeaderMap,
) -> Result<Option<Rendered>, Rendered> {
    let locator = svc
        .db
        .native_documentation_locator(registry_id, package, version, platform, Some(release))
        .await
        .map_err(|_| Rendered::ServiceUnavailable)?;
    let Some(locator) = locator else {
        return Ok(None);
    };
    let artifact = &locator.artifact;
    if query
        .digest
        .as_deref()
        .is_some_and(|digest| digest != artifact.document_sha256)
    {
        return Err(Rendered::NotFound);
    }
    if query.release.as_deref() != Some(release)
        || query.digest.as_deref() != Some(&artifact.document_sha256)
    {
        use super::console_render::urlencode;
        return Ok(Some(Rendered::TemporaryRedirect(format!(
            "/{slug}/-/docs/{}/{}/{}?release={}&digest={}",
            urlencode(package),
            urlencode(version),
            urlencode(platform),
            urlencode(release),
            urlencode(&artifact.document_sha256)
        ))));
    }
    let fetch = crate::placement_read::TopologySurfaceFetch::new(
        std::sync::Arc::clone(&svc.db),
        std::sync::Arc::clone(&svc.surface),
        crate::db::SurfaceTarget::Registry(registry_id),
    );
    let document = crate::indexer::native_documentation::fetch_native_documentation(
        &fetch, package, version, platform, artifact,
    )
    .await
    .map_err(|_| Rendered::ServiceUnavailable)?;
    let session = session_indicator(svc, headers).await;
    let coordinates = format!(
        "<p>Release <code>{}</code>; package <code>{}</code> <code>{}</code>; platform <code>{}</code>.</p>",
        super::render::escape(release),
        super::render::escape(package),
        super::render::escape(version),
        super::render::escape(platform)
    );
    let body = format!("{coordinates}{}", document.render_html());
    Ok(Some(Rendered::Html(
        super::console_render::page_with_session(
            "Native package documentation",
            &super::browse_pages::registry_crumbs(slug, &[(String::new(), "documentation".into())]),
            &body,
            &super::browse_pages::state_line(None, Instant::now()),
            &session,
        ),
    )))
}

fn native_index_page(
    slug: &str,
    release: &str,
    query: &BrowseQuery,
    documents: &[crate::db::NativeDocumentationIndex],
    status: Option<&crate::db::IndexStatus>,
    started: Instant,
    session: &super::console_render::SessionIndicator,
) -> Rendered {
    use super::console_render::urlencode;
    use super::render::escape;
    let term = query.q.as_deref().unwrap_or_default();
    let terms = aos_doc_model::tokenize(term);
    if query
        .kind
        .as_deref()
        .is_some_and(|kind| !matches!(kind, "package" | "option" | "operation"))
    {
        return Rendered::BadRequest(
            "native documentation kind must be package, option, or operation",
        );
    }
    let mut body = format!(
        r#"<h1>Native module documentation</h1><p>Release <code>{}</code>. Declarations and configured uses; no live runtime state.</p><form method="get"><input type="hidden" name="release" value="{}"><label>Search reference <input name="q" value="{}"></label><button>Search</button></form><ul>"#,
        escape(release),
        escape(release),
        escape(term)
    );
    let mut count = 0;
    for document in documents {
        for row in &document.search {
            if query.kind.as_deref().is_some_and(|kind| kind != row.kind)
                || !terms.iter().all(|term| row.terms.contains_key(term))
            {
                continue;
            }
            if count == 1000 {
                break;
            }
            let href = format!(
                "/{slug}/-/docs/{}/{}/{}?release={}&digest={}",
                urlencode(&document.package),
                urlencode(&document.version),
                urlencode(&document.platform),
                urlencode(release),
                urlencode(&document.document_sha256)
            );
            body.push_str(&format!(
                r#"<li><a href="{}">{}</a> <code>{}</code><p>{}</p><p>{} {} ({})</p></li>"#,
                escape(&href),
                escape(&row.title),
                escape(&row.kind),
                escape(&row.summary),
                escape(&document.package),
                escape(&document.version),
                escape(&document.platform)
            ));
            count += 1;
        }
    }
    if count == 0 {
        body.push_str("<li>No matching native reference entries.</li>");
    }
    body.push_str("</ul>");
    if count == 1000 {
        body.push_str(
            "<p>Showing the first 1000 entries. Narrow the search for more specific results.</p>",
        );
    }
    Rendered::Html(super::console_render::page_with_session(
        "Native module documentation",
        &super::browse_pages::registry_crumbs(slug, &[(String::new(), "documentation".into())]),
        &body,
        &super::browse_pages::state_line(status, started),
        session,
    ))
}
