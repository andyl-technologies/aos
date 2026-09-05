//! Focused structured documentation panels and safe, release-aware prose.

use super::console_render::urlencode;
use super::render::escape;
use crate::db::documentation_node_key;
use aos_doc_model::{
    DocumentedValue, InlineSpan, LinkTarget, OptionDocument, OptionType, ProseBlock,
};
use std::fmt::Write as _;

pub(super) fn node_href(slug: &str, release: &str, key: &str) -> String {
    format!(
        "/{slug}/-/docs?release={}&root={}",
        urlencode(release),
        urlencode(key)
    )
}

pub(super) fn prose(blocks: &[ProseBlock], slug: &str, release: &str) -> String {
    let mut html = String::new();
    for block in blocks {
        match block {
            ProseBlock::Paragraph { spans } => {
                html.push_str("<p>");
                for span in spans {
                    match span {
                        InlineSpan::Text { text } => html.push_str(&escape(text)),
                        InlineSpan::Code { text } => {
                            let _ = write!(html, "<code>{}</code>", escape(text));
                        }
                        InlineSpan::Link { label, target } => {
                            let href = match target {
                                LinkTarget::Package { package } => Some(format!(
                                    "/{slug}/-/packages/{}?release={}",
                                    urlencode(package),
                                    urlencode(release)
                                )),
                                LinkTarget::Option { path } => {
                                    Some(node_href(slug, release, &documentation_node_key(path)))
                                }
                                LinkTarget::Section { id } => Some(format!("#{}", urlencode(id))),
                                LinkTarget::Https { url }
                                    if url::Url::parse(url).is_ok_and(|url| {
                                        url.scheme() == "https" && url.host_str().is_some()
                                    }) =>
                                {
                                    Some(url.clone())
                                }
                                _ => None,
                            };
                            if let Some(href) = href {
                                let _ = write!(
                                    html,
                                    "<a href=\"{}\">{}</a>",
                                    escape(&href),
                                    escape(label)
                                );
                            } else {
                                html.push_str(&escape(label));
                            }
                        }
                    }
                }
                html.push_str("</p>");
            }
            ProseBlock::Code { language, text } => {
                let _ = write!(
                    html,
                    "<pre><code data-language=\"{}\">{}</code></pre>",
                    escape(language),
                    escape(text)
                );
            }
            ProseBlock::List { ordered, items } => {
                let tag = if *ordered { "ol" } else { "ul" };
                let _ = write!(html, "<{tag}>");
                for item in items {
                    let _ = write!(html, "<li>{}</li>", prose(item, slug, release));
                }
                let _ = write!(html, "</{tag}>");
            }
            ProseBlock::Note { severity, blocks } => {
                let _ = write!(
                    html,
                    "<aside class=\"doc-note\"><strong>{severity:?}</strong>{}</aside>",
                    prose(blocks, slug, release)
                );
            }
            ProseBlock::Definitions { entries } => {
                html.push_str("<dl>");
                for entry in entries {
                    let _ = write!(
                        html,
                        "<dt>{}</dt><dd>{}</dd>",
                        escape(&entry.term),
                        prose(&entry.body, slug, release)
                    );
                }
                html.push_str("</dl>");
            }
        }
    }
    html
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
            for value in values { let _ = write!(html, "<div><code>{}</code>{}</div>", escape(&value.value), prose(&value.description, slug, release)); }
            html.push_str("</div></section>");
        }
        _ => {}
    }
    if let Some(activation) = &option.activation {
        let _ = write!(
            html,
            "<section><h3>When changed</h3><p>{:?}</p>",
            activation.kind
        );
        for unit in &activation.units {
            let _ = write!(html, "<code>{}</code> ", escape(unit));
        }
        html.push_str("</section>");
    }
    let _ = write!(html, "<details><summary>Declaration details</summary><dl><dt>Owner</dt><dd><a href=\"/{}/-/packages/{}?release={}\">{}</a></dd><dt>Visibility</dt><dd>{:?}</dd>",
        escape(slug), urlencode(&option.owner.package), urlencode(release), escape(&option.owner.package), option.visibility);
    if let Some(source) = &option.source {
        let _ = write!(
            html,
            "<dt>Source</dt><dd><code>{}{}</code></dd>",
            escape(&source.path),
            source
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default()
        );
    }
    html.push_str("</dl></details></article>");
    html
}
