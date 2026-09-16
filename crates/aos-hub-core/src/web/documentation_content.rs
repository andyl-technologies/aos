//! Focused structured documentation panels and safe, release-aware prose.

use super::console_render::urlencode;
use super::render::escape;
use crate::db::documentation_node_key;
use aos_doc_model::{DocumentedValue, LinkTarget, OptionDocument, OptionType, ProseBlock};
use std::fmt::Write as _;

pub(super) fn node_href(slug: &str, release: &str, key: &str) -> String {
    format!(
        "/{slug}/-/docs?release={}&root={}",
        urlencode(release),
        urlencode(key)
    )
}

/// Renders an inline link target, or `None` when it must not be linked.
fn link_href(target: &LinkTarget, slug: &str, release: &str) -> Option<String> {
    match target {
        LinkTarget::Package { package } => Some(format!(
            "/{slug}/-/packages/{}?release={}",
            urlencode(package),
            urlencode(release)
        )),
        LinkTarget::Option { path } => {
            Some(node_href(slug, release, &documentation_node_key(path)))
        }
        LinkTarget::Https { url }
            if url::Url::parse(url)
                .is_ok_and(|url| url.scheme() == "https" && url.host_str().is_some()) =>
        {
            Some(url.clone())
        }
        _ => None,
    }
}

pub(super) fn prose(blocks: &[ProseBlock], slug: &str, release: &str) -> String {
    aos_doc_model::render_prose_html_with_links(blocks, |target| link_href(target, slug, release))
}

fn value_panel(label: &str, value: &DocumentedValue) -> String {
    let text = match value {
        DocumentedValue::Literal { value } => {
            serde_json::to_string_pretty(value).unwrap_or_default()
        }
        DocumentedValue::Text { text } => text.clone(),
    };
    format!(
        "<section class=\"doc-value\"><h3>{label}</h3><pre><code>{}</code></pre></section>",
        escape(&text)
    )
}

pub(super) fn option(option: &OptionDocument, slug: &str, release: &str) -> String {
    let mut html = format!("<article class=\"doc-option\" id=\"{}\"><h2>{}</h2><div class=\"doc-badges\"><span>{}</span>{}{}</div>",
        aos_doc_model::documentation_anchor("option", &option.display_path), escape(&option.display_path), escape(&option.type_signature),
        if option.read_only { "<span>Read only</span>" } else { "" },
        if option.contributable { "<span>Accepts package contributions</span>" } else { "" });
    if let Some(notice) = &option.deprecated {
        let _ = write!(
            html,
            "<aside class=\"doc-note\"><strong>Deprecated</strong><p>{}</p></aside>",
            escape(notice)
        );
    }
    if let Some(path) = &option.replacement {
        let _ = write!(
            html,
            "<p>Replacement: <a href=\"{}\">{}</a></p>",
            escape(&node_href(slug, release, &documentation_node_key(path))),
            escape(
                &path
                    .iter()
                    .map(crate::db::path_segment_label)
                    .collect::<Vec<_>>()
                    .join(".")
            )
        );
    }
    html.push_str(&prose(&option.description, slug, release));
    html.push_str("<div class=\"doc-values\">");
    if let Some(value) = &option.default {
        html.push_str(&value_panel("Default", value));
    }
    if let Some(value) = &option.example {
        html.push_str(&value_panel("Example", value));
    }
    html.push_str("</div>");
    match &option.option_type {
        OptionType::Bool => html.push_str("<section><h3>Allowed values</h3><div class=\"doc-badges\"><code>true</code><code>false</code></div></section>"),
        OptionType::Enum { values } => {
            html.push_str("<section><h3>Allowed values</h3><div class=\"doc-enum\">");
            for value in values {
                let _ = write!(html, "<div><code>{}</code></div>", escape(&value.value));
            }
            html.push_str("</div></section>");
        }
        _ => {}
    }
    let _ = write!(html, "<details><summary>Declaration details</summary><dl><dt>Owner</dt><dd><a href=\"/{}/-/packages/{}?release={}\">{}</a></dd><dt>Visibility</dt><dd>{:?}</dd>",
        escape(slug), urlencode(&option.owner.package), urlencode(release), escape(&option.owner.package), option.visibility);
    if let Some(source) = &option.source {
        let _ = write!(
            html,
            "<dt>Source</dt><dd><code>{}</code></dd>",
            escape(source.path.as_str())
        );
    }
    html.push_str("</dl></details></article>");
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_doc_model::InlineSpan;

    fn paragraph(text: &str) -> Vec<ProseBlock> {
        vec![ProseBlock::Paragraph {
            spans: vec![InlineSpan::Text { text: text.into() }],
        }]
    }

    #[test]
    fn raw_descriptions_render_as_paragraphs_lists_and_code() {
        let text = "Operator keys for signed policy, baked\ninto the image as\n`/etc/apm/<op>.pub`.\n\nUse one of:\n- `rotate` for overlap\n- `replace` to drop\n  the old key\n\n```sh\napm switch --require-signed-host-nix\n```\n1. first\n2. second\n";
        let html = prose(&paragraph(text), "org/main", "1.0.0");
        assert_eq!(
            html,
            "<p>Operator keys for signed policy, baked into the image as <code>/etc/apm/&lt;op&gt;.pub</code>.</p>\
             <p>Use one of:</p><ul><li><code>rotate</code> for overlap</li><li><code>replace</code> to drop the old key</li></ul>\
             <pre><code data-language=\"sh\">apm switch --require-signed-host-nix</code></pre>\
             <ol><li>first</li><li>second</li></ol>"
        );
    }

    #[test]
    fn typed_spans_stay_inline_with_surrounding_text() {
        let blocks = vec![ProseBlock::Paragraph {
            spans: vec![
                InlineSpan::Text { text: "See".into() },
                InlineSpan::Code {
                    text: "host.nix".into(),
                },
                InlineSpan::Text {
                    text: "and the\nguide.".into(),
                },
                InlineSpan::Link {
                    label: "docs".into(),
                    target: LinkTarget::Https {
                        url: "https://example.com/".into(),
                    },
                },
            ],
        }];
        let html = prose(&blocks, "org/main", "1.0.0");
        assert_eq!(
            html,
            "<p>See <code>host.nix</code> and the guide. <a href=\"https://example.com/\">docs</a></p>"
        );
        assert_eq!(
            prose(&paragraph("an `unclosed tick"), "org/main", "1.0.0"),
            "<p>an `unclosed tick</p>"
        );
    }

    #[test]
    fn hosting_context_resolves_package_links_and_suppresses_source_links() {
        let blocks = vec![ProseBlock::Paragraph {
            spans: vec![
                InlineSpan::Link {
                    label: "nginx".into(),
                    target: LinkTarget::Package {
                        package: "nginx".into(),
                    },
                },
                InlineSpan::Link {
                    label: "module".into(),
                    target: LinkTarget::Source {
                        path: "module.nix".into(),
                    },
                },
            ],
        }];

        assert_eq!(
            prose(&blocks, "org/main", "1.0.0"),
            "<p><a href=\"/org/main/-/packages/nginx?release=1.0.0\">nginx</a> module</p>"
        );
    }
}
