//! Release-pinned documentation requests with bounded lazy tree reads.
//!
//! Every page resolves one completed catalog generation. Expanding a folder
//! reads only its immediate children; loading an option fetches one authenticated
//! document. The JSON enhancement uses the same session visibility as HTML.

use super::browse::{browse_rate_limited, load_visible, session_indicator, BrowseQuery, Rendered};
use super::documentation_pages;
use super::release_browse::{unavailable_page, ReleaseContext};
use crate::clock::Instant;
use crate::db::documentation_node_key;
use crate::service::RpcService;
use axum::http::HeaderMap;

/// Renders a bounded release tree or its session-authorized child page.
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
            "Documentation for this release has not finished indexing.",
            started,
            &session,
        ));
    };
    if let Some(redirect) = query.pin_release(
        &format!(
            "/{slug}/-/docs{}",
            if children_only { "/children" } else { "" }
        ),
        &context,
    ) {
        return redirect;
    }
    let commit = match svc.db.documentation_tree_commit(registry.id, release).await {
        Ok(Some(commit)) => commit,
        Ok(None) => {
            return Rendered::Html(unavailable_page(
                &registry,
                status.as_ref(),
                &context,
                "docs",
                "Documentation for this release has not finished indexing.",
                started,
                &session,
            ))
        }
        Err(_) => return Rendered::ServiceUnavailable,
    };
    let selected = match query.entry.as_deref() {
        Some(key) => match svc
            .db
            .documentation_tree_entry(registry.id, &commit, key)
            .await
        {
            Ok(Some(entry)) => Some(entry),
            Ok(None) => return Rendered::NotFound,
            Err(_) => return Rendered::ServiceUnavailable,
        },
        None => None,
    };
    let root_key = documentation_node_key(&[]);
    let key = query
        .root
        .as_deref()
        .or_else(|| {
            selected
                .as_ref()
                .and_then(|entry| entry.node_key.as_deref())
        })
        .unwrap_or(&root_key);
    if selected
        .as_ref()
        .and_then(|entry| entry.node_key.as_deref())
        .is_some_and(|node| node != key)
    {
        return Rendered::NotFound;
    }
    let node = match svc
        .db
        .documentation_tree_node(registry.id, &commit, key)
        .await
    {
        Ok(Some(node)) => node,
        Ok(None) => return Rendered::NotFound,
        Err(_) => return Rendered::ServiceUnavailable,
    };
    let term = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|term| !term.is_empty());
    let children = match svc
        .db
        .documentation_tree_children(
            registry.id,
            &commit,
            key,
            if term.is_none() {
                query.cursor.as_deref()
            } else {
                None
            },
        )
        .await
    {
        Ok(page) => page,
        Err(error) => return query_error(error),
    };
    if children_only {
        return match serde_json::to_string(&children) {
            Ok(json) => Rendered::PrivateJson(json),
            Err(_) => Rendered::ServiceUnavailable,
        };
    }
    let results = if let Some(term) = term {
        match svc
            .db
            .search_documentation_tree(
                registry.id,
                &commit,
                (query.scope.as_deref() == Some("subtree")).then_some(key),
                term,
                query.kind.as_deref(),
                query.cursor.as_deref(),
            )
            .await
        {
            Ok(page) => Some(page),
            Err(error) => return query_error(error),
        }
    } else {
        None
    };
    let variants = match svc
        .db
        .documentation_tree_variants(registry.id, &commit, key, query.variant_cursor.as_deref())
        .await
    {
        Ok(page) => page,
        Err(error) => return query_error(error),
    };
    let selected = if term.is_some() {
        None
    } else {
        selected.or_else(|| variants.items.first().cloned())
    };
    let document = if let Some(entry) = &selected {
        let locator = match svc
            .db
            .package_documentation_locator_at_release(
                registry.id,
                release,
                &entry.package_name,
                &entry.package_version,
                &entry.platform,
            )
            .await
        {
            Ok(Some(locator)) if locator.artifact.document_sha256 == entry.document_sha256 => {
                locator
            }
            Ok(_) => return Rendered::NotFound,
            Err(_) => return Rendered::ServiceUnavailable,
        };
        match svc
            .load_package_documentation_locator(registry.id, &locator)
            .await
        {
            Ok(document) => Some(document),
            Err(_) => return Rendered::ServiceUnavailable,
        }
    } else {
        None
    };
    Rendered::Html(documentation_pages::page(
        &registry,
        status.as_ref(),
        &context,
        query,
        &node,
        &children,
        &variants,
        results.as_ref(),
        selected.as_ref(),
        document.as_ref(),
        started,
        &session,
    ))
}

/// Resolves older package documentation URLs into the same release tree.
pub(crate) async fn legacy(
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
    let requested_release = if let Some(release) = query.release.as_ref() {
        Some(release.clone())
    } else if query.digest.is_none() {
        let context = match ReleaseContext::load(&svc.db, registry.id, None, false).await {
            Ok(context) => context,
            Err(error) => return error,
        };
        let candidates = match svc
            .db
            .documentation_releases_for_package(registry.id, package, version, platform)
            .await
        {
            Ok(candidates) => candidates,
            Err(_) => return Rendered::ServiceUnavailable,
        };
        context
            .selected()
            .filter(|release| candidates.iter().any(|candidate| candidate == release))
            .map(str::to_string)
            .or_else(|| {
                context
                    .releases()
                    .iter()
                    .find(|release| candidates.contains(&release.semver))
                    .map(|release| release.semver.clone())
            })
    } else {
        None
    };
    if requested_release.is_none() && query.digest.is_none() {
        return Rendered::NotFound;
    }
    let locator = if let Some(release) = requested_release.as_deref() {
        svc.db
            .package_documentation_locator_at_release(
                registry.id,
                release,
                package,
                version,
                platform,
            )
            .await
    } else {
        super::browse::documentation_locator_for_page(
            &svc.db,
            registry.id,
            package,
            version,
            platform,
            query.digest.as_deref(),
        )
        .await
    };
    let locator = match locator {
        Ok(Some(locator))
            if query
                .digest
                .as_deref()
                .is_none_or(|digest| digest == locator.artifact.document_sha256) =>
        {
            locator
        }
        Ok(_) => return Rendered::NotFound,
        Err(_) => return Rendered::ServiceUnavailable,
    };
    let release = match requested_release.as_ref() {
        Some(release) => release.clone(),
        None => match svc
            .db
            .documentation_release_for_digest(registry.id, &locator.artifact.document_sha256)
            .await
        {
            Ok(Some(release)) => release,
            Ok(None) => return Rendered::NotFound,
            Err(_) => return Rendered::ServiceUnavailable,
        },
    };
    if query.release.as_deref() != Some(&release)
        || query.digest.as_deref() != Some(&locator.artifact.document_sha256)
    {
        use super::console_render::urlencode;
        let mut location = format!(
            "/{slug}/-/docs/{}/{}/{}?release={}&digest={}",
            urlencode(package),
            urlencode(version),
            urlencode(platform),
            urlencode(&release),
            urlencode(&locator.artifact.document_sha256)
        );
        for (name, value) in [("kind", &query.kind), ("doc_key", &query.doc_key)] {
            if let Some(value) = value {
                location.push_str(&format!("&{name}={}", urlencode(value)));
            }
        }
        return Rendered::TemporaryRedirect(location);
    }
    let kind = query.kind.as_deref().unwrap_or("package");
    let key = query.doc_key.as_deref().unwrap_or(package);
    let entry_key =
        match crate::db::documentation_entry_key(&locator.artifact.document_sha256, kind, key) {
            Ok(key) => key,
            Err(_) => return Rendered::ServiceUnavailable,
        };
    let selection = BrowseQuery {
        release: Some(release),
        entry: Some(entry_key),
        ..BrowseQuery::default()
    };
    // Keep the legacy address on the initial request so its fragment remains
    // available to the enhancement. Direct query links also work without JS.
    match browse(svc, headers, slug, &selection, false).await {
        Rendered::Html(html) => {
            Rendered::Html(html.replacen("data-doc-browser", "data-doc-legacy data-doc-browser", 1))
        }
        result => result,
    }
}

/// Separates malformed continuation requests from unavailable indexed data.
fn query_error(error: anyhow::Error) -> Rendered {
    match error.downcast_ref::<crate::db::InvalidDocumentationQuery>() {
        Some(error) => Rendered::BadRequest(error.0),
        None => Rendered::ServiceUnavailable,
    }
}
