//! Authenticated native operation declarations across one completed release.

use super::browse_pages::{registry_crumbs, state_line};
use super::console_render::{SessionIndicator, page_with_session, urlencode};
use super::release_browse::ReleaseContext;
use super::render::escape;
use crate::clock::Instant;
use crate::db::{IndexStatus, RegistryRecord};
use anyhow::Result;
use aos_doc_model::runtime::deployment::NativeReleaseGraph;
use std::fmt::Write as _;

/// Renders exact native references and links their package/operation declarations.
///
/// # Errors
/// Returns an error if a retained reference fails its checked identity.
#[allow(clippy::too_many_arguments)]
pub fn page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    context: &ReleaseContext,
    graph: &NativeReleaseGraph,
    platforms: &[String],
    digest: &str,
    started: Instant,
    session: &SessionIndicator,
) -> Result<String> {
    let slug = &registry.slug;
    let mut body = context.nav(slug, "abilities");
    body.push_str("<h1>Native ability declarations</h1><p>Authenticated release declarations describe desired operation contracts. They do not establish observed live state.</p>");
    body.push_str(&context.selector(slug, &format!("/{slug}/-/abilities"), &[]));
    for platform in platforms {
        let _ = write!(
            body,
            "<a href=\"/{}/-/abilities?release={}&amp;platform={}\">{}</a> ",
            escape(slug),
            urlencode(&graph.release),
            urlencode(platform),
            escape(platform)
        );
    }
    let _ = write!(
        body,
        "<p>Commit <code>{}</code>; reference graph digest <code>{}</code>.</p>",
        escape(&graph.registry_commit),
        escape(digest)
    );
    for reference in &graph.references {
        let document = reference.check()?;
        let _ = write!(
            body,
            "<p><a href=\"/{}/-/docs/{}/{}/{}?release={}&amp;digest={}\">Exact package reference</a></p>",
            escape(slug),
            urlencode(&reference.identity.package),
            urlencode(&reference.identity.version),
            urlencode(&reference.identity.platform),
            urlencode(&graph.release),
            urlencode(&reference.identity.document_sha256.to_string())
        );
        body.push_str(&document.render_html());
    }
    Ok(page_with_session(
        "Native ability declarations",
        &registry_crumbs(slug, &[(String::new(), "abilities".into())]),
        &body,
        &state_line(status, started),
        session,
    ))
}
