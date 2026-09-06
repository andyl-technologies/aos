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
        LinkTarget::Section { id } => Some(format!("#{}", urlencode(id))),
        LinkTarget::Https { url }
            if url::Url::parse(url)
                .is_ok_and(|url| url.scheme() == "https" && url.host_str().is_some()) =>
        {
            Some(url.clone())
        }
        _ => None,
    }
}

/// Renders inline text with backtick code spans; everything is escaped.
fn inline_text(text: &str) -> String {
    let mut html = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('`') {
        let (before, after) = rest.split_at(open);
        html.push_str(&escape(before));
        match after[1..].find('`') {
            Some(close) => {
                let _ = write!(html, "<code>{}</code>", escape(&after[1..1 + close]));
                rest = &after[close + 2..];
            }
            None => {
                html.push_str(&escape(after));
                rest = "";
            }
        }
    }
    html.push_str(&escape(rest));
    html
}

/// Streams a paragraph's spans into HTML blocks.
///
/// Producers publish option descriptions as one text span holding the raw
/// source prose: hard-wrapped lines, blank lines between paragraphs, backtick
/// code, bullet or numbered lines, and fenced code. Those conventions are
/// rendered structurally here so a description reads as paragraphs and lists
/// rather than one run of text. Typed code and link spans stay inline.
struct ParagraphWriter {
    html: String,
    current: String,
}

impl ParagraphWriter {
    fn new() -> Self {
        Self {
            html: String::new(),
            current: String::new(),
        }
    }

    fn inline(&mut self, fragment: &str) {
        if !self.current.is_empty() && !self.current.ends_with(' ') && !fragment.starts_with(' ') {
            self.current.push(' ');
        }
        self.current.push_str(fragment);
    }

    fn flush(&mut self) {
        let text = self.current.trim();
        if !text.is_empty() {
            let _ = write!(self.html, "<p>{text}</p>");
        }
        self.current.clear();
    }

    fn text(&mut self, text: &str) {
        let lines = text.lines().collect::<Vec<_>>();
        let mut index = 0;
        while index < lines.len() {
            let line = lines[index];
            let trimmed = line.trim();
            if trimmed.is_empty() {
                self.flush();
                index += 1;
            } else if let Some(fence) = trimmed.strip_prefix("```") {
                self.flush();
                let language = fence.trim();
                let mut body = Vec::new();
                index += 1;
                while index < lines.len() && lines[index].trim() != "```" {
                    body.push(lines[index]);
                    index += 1;
                }
                index += 1;
                let _ = write!(
                    self.html,
                    "<pre><code data-language=\"{}\">{}</code></pre>",
                    escape(language),
                    escape(&body.join("\n"))
                );
            } else if let Some((ordered, first)) = list_item(trimmed) {
                self.flush();
                let tag = if ordered { "ol" } else { "ul" };
                let _ = write!(self.html, "<{tag}>");
                let mut item = first.to_string();
                index += 1;
                loop {
                    let next = lines.get(index).map(|line| line.trim());
                    match next {
                        Some(next) if !next.is_empty() && list_item(next).is_none() => {
                            item.push(' ');
                            item.push_str(next);
                            index += 1;
                        }
                        _ => {
                            let _ = write!(self.html, "<li>{}</li>", inline_text(item.trim()));
                            match next.and_then(list_item) {
                                Some((_, first)) => {
                                    item = first.to_string();
                                    index += 1;
                                }
                                None => break,
                            }
                        }
                    }
                }
                let _ = write!(self.html, "</{tag}>");
            } else {
                self.inline(&inline_text(trimmed));
                index += 1;
            }
        }
        if text.ends_with(' ') {
            self.current.push(' ');
        }
    }
}

/// Recognizes `- item`, `* item`, or `1. item`, returning ordering and body.
fn list_item(line: &str) -> Option<(bool, &str)> {
    if let Some(rest) = line.strip_prefix("- ").or_else(|| line.strip_prefix("* ")) {
        return Some((false, rest));
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 {
        if let Some(rest) = line[digits..].strip_prefix(". ") {
            return Some((true, rest));
        }
    }
    None
}

pub(super) fn prose(blocks: &[ProseBlock], slug: &str, release: &str) -> String {
    let mut html = String::new();
    for block in blocks {
        match block {
            ProseBlock::Paragraph { spans } => {
                let mut writer = ParagraphWriter::new();
                for span in spans {
                    match span {
                        InlineSpan::Text { text } => writer.text(text),
                        InlineSpan::Code { text } => {
                            writer.inline(&format!("<code>{}</code>", escape(text)));
                        }
                        InlineSpan::Link { label, target } => {
                            match link_href(target, slug, release) {
                                Some(href) => writer.inline(&format!(
                                    "<a href=\"{}\">{}</a>",
                                    escape(&href),
                                    escape(label)
                                )),
                                None => writer.inline(&escape(label)),
                            }
                        }
                    }
                }
                writer.flush();
                html.push_str(&writer.html);
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(inline_text("an `unclosed tick"), "an `unclosed tick");
    }
}
