//! Progressive configuration-tree navigation beside a folder listing or one
//! selected documentation panel.
//!
//! The tree aside is the scope selector: it shows the current node's immediate
//! children and lazily expands branches. The reader shows the selected option
//! or guide, and beneath any branch a bounded folder listing of that node's
//! children or, with `view=all`, every documented option in the subtree.

use super::browse::BrowseQuery;
use super::browse_pages::{registry_crumbs, state_line};
use super::console_render::{page_with_session, urlencode, SessionIndicator};
use super::documentation_content::{node_href, option, prose};
use super::release_browse::ReleaseContext;
use super::render::escape;
use crate::clock::Instant;
use crate::db::{
    documentation_node_key, path_segment_label, DocumentationTreeEntry, DocumentationTreeNode,
    DocumentationTreePage, IndexStatus, RegistryRecord,
};
use aos_doc_model::PackageDocumentation;
use std::fmt::Write as _;

fn entry_href(slug: &str, release: &str, entry: &DocumentationTreeEntry) -> String {
    let mut href = format!(
        "/{slug}/-/docs?release={}&entry={}",
        urlencode(release),
        urlencode(&entry.key)
    );
    if let Some(node) = &entry.node_key {
        let _ = write!(href, "&root={}", urlencode(node));
    }
    href
}

fn children_html(
    slug: &str,
    release: &str,
    children: &DocumentationTreePage<DocumentationTreeNode>,
) -> String {
    let mut html = String::from("<ul class=\"doc-tree-list\">");
    for node in &children.items {
        let _ = write!(html, "<li data-node=\"{}\">", escape(&node.key));
        if node.child_count > 0 {
            let _ = write!(html, "<button class=\"doc-expand\" type=\"button\" aria-expanded=\"false\" aria-label=\"Expand {}\" data-doc-expand=\"{}\" hidden>+</button>", escape(&node.label), escape(&node.key));
        } else {
            html.push_str("<span class=\"doc-tree-spacer\"></span>");
        }
        let _ = write!(
            html,
            "<a href=\"{}\">{}</a><span class=\"dim doc-count\">{}</span></li>",
            escape(&node_href(slug, release, &node.key)),
            escape(&node.label),
            match (node.child_count, node.entry_count) {
                (1, _) => "1 child".to_string(),
                (children, _) if children > 0 => format!("{children} children"),
                (_, 1) => "1 variant".to_string(),
                (_, variants) => format!("{variants} variants"),
            }
        );
    }
    html.push_str("</ul>");
    html
}

/// Joins typed path segments into their dotted display form.
fn dotted(path: &[aos_doc_model::PathSegment]) -> String {
    path.iter()
        .map(path_segment_label)
        .collect::<Vec<_>>()
        .join(".")
}

/// Renders the folder listing of a branch: its children or its whole subtree.
///
/// Children keep their branch/option identity and counts; the flattened view
/// shows dotted paths relative to the current node so deep options read in one
/// pass. Both views share the release's 50-entry page bound and cursor links.
fn folder_html(
    slug: &str,
    release: &str,
    node: &DocumentationTreeNode,
    children: &DocumentationTreePage<DocumentationTreeNode>,
    descendants: Option<&DocumentationTreePage<DocumentationTreeNode>>,
) -> String {
    let base = node_href(slug, release, &node.key);
    let flattened = descendants.is_some();
    let listing = descendants.unwrap_or(children);
    let heading = if node.path.is_empty() {
        "Configuration".to_string()
    } else {
        dotted(&node.path)
    };
    let mut html = format!(
        "<section class=\"doc-folder\" data-doc-folder aria-labelledby=\"doc-folder-title\"><div class=\"doc-folder-head\"><h2 id=\"doc-folder-title\">{}</h2><nav class=\"doc-view-toggle\" aria-label=\"Listing\"><a href=\"{}\"{}>Children <span class=\"dim\">{}</span></a><a href=\"{}&amp;view=all\"{}>All options beneath</a></nav></div>",
        escape(&heading),
        escape(&base),
        if flattened { "" } else { " aria-current=\"true\"" },
        node.child_count,
        escape(&base),
        if flattened { " aria-current=\"true\"" } else { "" },
    );
    if listing.items.is_empty() {
        html.push_str("<p class=\"dim\">No documented options here.</p></section>");
        return html;
    }
    html.push_str("<table class=\"doc-folder-table\"><thead><tr><th>Option</th><th>Type</th><th>Description</th></tr></thead><tbody>");
    for child in &listing.items {
        let name = if flattened {
            dotted(&child.path[node.path.len().min(child.path.len())..])
        } else {
            child.label.clone()
        };
        let is_branch = child.child_count > 0;
        let detail = if is_branch {
            format!(
                "<span class=\"dim doc-folder-count\">{} {}</span>",
                child.child_count,
                if child.child_count == 1 {
                    "child"
                } else {
                    "children"
                }
            )
        } else {
            String::new()
        };
        let _ = write!(
            html,
            "<tr class=\"{}\" data-node=\"{}\"><td><a href=\"{}\">{}</a>{}</td><td>{}</td><td>{}</td></tr>",
            if is_branch { "doc-folder-branch" } else { "doc-folder-option" },
            escape(&child.key),
            escape(&node_href(slug, release, &child.key)),
            escape(&name),
            detail,
            child
                .type_signature
                .as_deref()
                .map(|signature| format!("<code>{}</code>", escape(signature)))
                .or_else(|| child.kind.as_deref().map(escape))
                .unwrap_or_default(),
            escape(child.summary.as_deref().unwrap_or_default())
        );
    }
    html.push_str("</tbody></table>");
    if let Some(cursor) = &listing.next_cursor {
        let _ = write!(
            html,
            "<a class=\"doc-more\" href=\"{}{}&amp;cursor={}\">Next options →</a>",
            escape(&base),
            if flattened { "&amp;view=all" } else { "" },
            urlencode(cursor)
        );
    }
    html.push_str("</section>");
    html
}

#[allow(clippy::too_many_arguments)]
pub(super) fn page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    context: &ReleaseContext,
    query: &BrowseQuery,
    node: &DocumentationTreeNode,
    children: &DocumentationTreePage<DocumentationTreeNode>,
    descendants: Option<&DocumentationTreePage<DocumentationTreeNode>>,
    variants: &DocumentationTreePage<DocumentationTreeEntry>,
    results: Option<&DocumentationTreePage<DocumentationTreeEntry>>,
    selected: Option<&DocumentationTreeEntry>,
    document: Option<&PackageDocumentation>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let release = context.selected().unwrap_or_default();
    let base = node_href(slug, release, &node.key);
    let mut html = context.nav(slug, "docs");
    html.push_str("<h1>Docs</h1>");
    html.push_str(&context.selector(slug, &format!("/{slug}/-/docs"), &[("root", &node.key)]));
    let _ = write!(html, "<div class=\"doc-browser\" data-doc-browser data-doc-base=\"/{}/-/docs\" data-doc-release=\"{}\" data-doc-root=\"{}\"><form class=\"doc-search\" action=\"/{}/-/docs\" method=\"get\" role=\"search\"><input type=\"hidden\" name=\"release\" value=\"{}\"><input type=\"hidden\" name=\"root\" value=\"{}\"><label for=\"doc-query\">Search documentation</label><input id=\"doc-query\" type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Option path, purpose, or package…\"><label>Within <select name=\"scope\"><option value=\"release\">Entire release</option><option value=\"subtree\"{}>This subtree</option></select></label><button type=\"submit\">Search</button></form>",
        escape(slug), escape(release), escape(&node.key), escape(slug), escape(release), escape(&node.key), escape(query.q.as_deref().unwrap_or_default()), if query.scope.as_deref() == Some("subtree") { " selected" } else { "" });
    html.push_str("<nav class=\"doc-breadcrumbs\" aria-label=\"Configuration path\">");
    let _ = write!(
        html,
        "<a href=\"{}\">Configuration</a>",
        escape(&node_href(slug, release, &documentation_node_key(&[])))
    );
    for depth in 1..=node.path.len() {
        let _ = write!(
            html,
            "<span>/</span><a href=\"{}\">{}</a>",
            escape(&node_href(
                slug,
                release,
                &documentation_node_key(&node.path[..depth])
            )),
            escape(&path_segment_label(&node.path[depth - 1]))
        );
    }
    // The tree filter is a JavaScript-only convenience over already loaded
    // labels; without scripts the search form above is the equivalent path.
    html.push_str("</nav><div class=\"doc-layout\"><aside class=\"doc-tree\" aria-label=\"Configuration subtree\"><h2>Configuration tree</h2><input type=\"search\" class=\"doc-tree-filter\" data-doc-tree-filter placeholder=\"Filter loaded tree\" aria-label=\"Filter loaded tree\" hidden>");
    if !node.path.is_empty() {
        let _ = write!(
            html,
            "<p><a href=\"{}\">← Parent subtree</a></p>",
            escape(&node_href(
                slug,
                release,
                &documentation_node_key(&node.path[..node.path.len() - 1])
            ))
        );
    }
    if children.items.is_empty() {
        html.push_str("<p class=\"dim\">No child options.</p>");
    } else {
        html.push_str(&children_html(slug, release, children));
    }
    if let Some(cursor) = &children.next_cursor {
        let _ = write!(
            html,
            "<a class=\"doc-more\" href=\"{}&amp;cursor={}\">Next child options →</a>",
            escape(&base),
            urlencode(cursor)
        );
    }
    html.push_str("</aside><div class=\"doc-reader\" data-doc-reader>");
    if let Some(results) = results {
        let _ = write!(
            html,
            "<section><h2>Search results</h2><p><a href=\"{}\">Clear search</a></p>",
            escape(&base)
        );
        if results.items.is_empty() {
            html.push_str("<p>No matching documentation in this scope.</p>");
        }
        for entry in &results.items {
            let _ = write!(html, "<article class=\"doc-result\"><h3><a href=\"{}\">{}</a></h3><p class=\"dim\">{} · {} · {}</p><p>{}</p></article>",
                escape(&entry_href(slug, release, entry)), escape(&entry.title), escape(&entry.kind), escape(&entry.package_name), escape(&entry.platform), escape(&entry.summary));
        }
        if let Some(cursor) = &results.next_cursor {
            let _ = write!(
                html,
                "<a href=\"{}&amp;q={}&amp;scope={}&amp;cursor={}{}\">Next results →</a>",
                escape(&base),
                urlencode(query.q.as_deref().unwrap_or_default()),
                urlencode(query.scope.as_deref().unwrap_or("release")),
                urlencode(cursor),
                query
                    .kind
                    .as_deref()
                    .map(|kind| format!("&amp;kind={}", urlencode(kind)))
                    .unwrap_or_default()
            );
        }
        html.push_str("</section>");
    } else if let (Some(entry), Some(document)) = (selected, document) {
        let _ = write!(
            html,
            "<div class=\"doc-context\"><span>{} {} · {}</span><a href=\"{}\">Permalink</a></div>",
            escape(&entry.package_name),
            escape(&entry.package_version),
            escape(&entry.platform),
            escape(&entry_href(slug, release, entry))
        );
        if variants.items.len() > 1
            || query.variant_cursor.is_some()
            || variants.next_cursor.is_some()
        {
            html.push_str("<details class=\"doc-variants\"><summary>Package and platform variants</summary><ul>");
            for variant in &variants.items {
                let _ = write!(
                    html,
                    "<li><a href=\"{}\"{}>{} {} · {}</a></li>",
                    escape(&entry_href(slug, release, variant)),
                    if variant.key == entry.key {
                        " aria-current=\"true\""
                    } else {
                        ""
                    },
                    escape(&variant.package_name),
                    escape(&variant.package_version),
                    escape(&variant.platform)
                );
            }
            html.push_str("</ul>");
            if let Some(cursor) = &variants.next_cursor {
                let _ = write!(
                    html,
                    "<a href=\"{}&amp;variant_cursor={}\">More variants →</a>",
                    escape(&base),
                    urlencode(cursor)
                );
            }
            html.push_str("</details>");
        }
        if entry.kind == "option" {
            if let Some(found) = document.options.iter().find(|option| {
                option.display_path == entry.document_key
                    && documentation_node_key(&option.path) == node.key
            }) {
                html.push_str(&option(found, slug, release));
            }
        } else {
            let _ = write!(
                html,
                "<article><h2>{}</h2><p>{}</p>",
                escape(&entry.title),
                escape(&entry.summary)
            );
            // Remove options before using the model's runtime renderer: the focused
            // browser must never emit the entire release option reference.
            let mut guide = document.clone();
            guide.options.clear();
            guide.sections.clear();
            html.push_str(&guide.render_html_fragment());
            for section in &document.sections {
                let _ = write!(
                    html,
                    "<section id=\"{}\"><h3>{}</h3>{}</section>",
                    escape(&section.id),
                    escape(&section.title),
                    prose(&section.blocks, slug, release)
                );
            }
            html.push_str("</article>");
        }
    }
    // A branch always lists what lies beneath it, even under a submodule
    // option's own panel, so readers never face an empty reader.
    if results.is_none() && (node.child_count > 0 || descendants.is_some()) {
        html.push_str(&folder_html(slug, release, node, children, descendants));
    } else if results.is_none() && selected.is_none() {
        let _ = write!(
            html,
            "<h2>{}</h2><p class=\"dim\">No documented options here. Search this release for an option or guide.</p>",
            escape(if node.path.is_empty() {
                "Configuration"
            } else {
                &node.label
            })
        );
    }
    html.push_str("</div></div></div>");
    page_with_session(
        "Docs",
        &registry_crumbs(slug, &[(String::new(), "docs".into())]),
        &html,
        &state_line(status, started),
        session,
    )
}
