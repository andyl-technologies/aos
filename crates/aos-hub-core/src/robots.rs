//! Pure renderers for the hub's `robots.txt` and `llms.txt` documents.
//!
//! These functions own the on-the-wire text formats both shells serve from the
//! identical code: the native `aos-hub` binary and the Cloudflare Worker each
//! gather their data through the shared service and hand it to one of these
//! renderers, so an operator gets byte-identical output regardless of where the
//! hub runs. Everything here is pure (data in, `String` out) and wasm-clean —
//! no I/O, no clock, no randomness.
//!
//! Two document families live here:
//!
//! - **`robots.txt`** ([`render_robots`]) — the crawler-control file, driven by
//!   the three-valued [`CrawlPolicy`](crate::crawl::CrawlPolicy). The
//!   `allow_no_ai` posture emits an explicit `Disallow` block for every known AI
//!   crawler ([`AI_CRAWLERS`]).
//! - **`llms.txt`** ([`render_registry_llms`] / [`render_root_llms`]) — the
//!   [llmstxt.org](https://llmstxt.org) convention: a markdown summary of the
//!   registry (or instance) for language-model consumers, generated from the
//!   registry's indexed packages and channels (or the instance's public
//!   registries).
//!
//! # `robots.txt` format
//!
//! `allow_all`:
//!
//! ```text
//! User-agent: *
//! Allow: /
//! ```
//!
//! `deny_all`:
//!
//! ```text
//! User-agent: *
//! Disallow: /
//! ```
//!
//! `allow_no_ai` (the leading `Allow: /` group, then one disallow block per AI
//! crawler):
//!
//! ```text
//! User-agent: *
//! Allow: /
//!
//! User-agent: GPTBot
//! Disallow: /
//!
//! User-agent: ChatGPT-User
//! Disallow: /
//! ...
//! ```
//!
//! # `llms.txt` format (per registry)
//!
//! ```text
//! # acme/cdn
//!
//! > The Acme CDN registry.
//!
//! Registry served by AOS registry hub. Browse: https://hub.example.com/acme/cdn/
//!
//! ## Packages
//! - [hello](https://hub.example.com/acme/cdn/-/packages/hello): a friendly greeter
//!
//! ## Channels
//! - stable: 1.2.0
//! ```

use std::fmt::Write as _;

use crate::crawl::CrawlPolicy;

/// The user-agent tokens of crawlers operated for AI training, retrieval, or
/// assistant browsing, disallowed under [`CrawlPolicy::AllowNoAi`].
///
/// Each entry is matched verbatim against a `User-agent:` line. The list is
/// curated from the operators' published crawler documentation (OpenAI,
/// Anthropic, Google, Common Crawl, Perplexity, ByteDance, Amazon, Apple, Meta,
/// Cohere, Diffbot, and several others). It is intentionally explicit rather
/// than a wildcard so a registry that opts out of AI indexing keeps serving
/// ordinary search crawlers.
pub const AI_CRAWLERS: &[&str] = &[
    "GPTBot",
    "ChatGPT-User",
    "OAI-SearchBot",
    "ClaudeBot",
    "anthropic-ai",
    "Claude-Web",
    "Claude-User",
    "Claude-SearchBot",
    "Google-Extended",
    "CCBot",
    "PerplexityBot",
    "Perplexity-User",
    "Bytespider",
    "Amazonbot",
    "Applebot-Extended",
    "meta-externalagent",
    "FacebookBot",
    "cohere-ai",
    "Diffbot",
    "ImagesiftBot",
    "Omgilibot",
    "YouBot",
    "Timpibot",
    "DuckAssistBot",
    "PetalBot",
];

/// Render the `robots.txt` body for a [`CrawlPolicy`].
///
/// The output is the complete file body (a trailing newline included), ready to
/// serve as `text/plain`:
///
/// - [`CrawlPolicy::AllowAll`] permits every crawler everywhere.
/// - [`CrawlPolicy::DenyAll`] disallows every crawler everywhere.
/// - [`CrawlPolicy::AllowNoAi`] permits general crawlers and then emits one
///   explicit `Disallow: /` block per [`AI_CRAWLERS`] entry.
///
/// `llms_txt_url`, when present, is appended as a comment line (`robots.txt` has
/// no standard field for it) so a reader of the file can still discover the
/// machine-readable `llms.txt`. It is omitted entirely when `None`.
///
/// # Examples
///
/// ```
/// use aos_hub_core::crawl::CrawlPolicy;
/// use aos_hub_core::robots::render_robots;
///
/// assert_eq!(
///     render_robots(CrawlPolicy::DenyAll, None),
///     "User-agent: *\nDisallow: /\n",
/// );
/// ```
#[must_use]
pub fn render_robots(policy: CrawlPolicy, llms_txt_url: Option<&str>) -> String {
    let mut out = String::new();
    match policy {
        CrawlPolicy::AllowAll => {
            out.push_str("User-agent: *\nAllow: /\n");
        }
        CrawlPolicy::DenyAll => {
            out.push_str("User-agent: *\nDisallow: /\n");
        }
        CrawlPolicy::AllowNoAi => {
            out.push_str("User-agent: *\nAllow: /\n");
            for bot in AI_CRAWLERS {
                let _ = write!(out, "\nUser-agent: {bot}\nDisallow: /\n");
            }
        }
    }
    if let Some(url) = llms_txt_url {
        let _ = write!(out, "\n# llms.txt: {url}\n");
    }
    out
}

/// One package entry in a registry's [`llms.txt`](render_registry_llms).
#[derive(Debug, Clone)]
pub struct PackageView {
    /// Package name (the slug under `…/-/p/`).
    pub name: String,
    /// One-line package description (may be empty).
    pub description: String,
    /// Absolute browse URL for the package's page.
    pub browse_url: String,
}

/// One channel entry in a registry's [`llms.txt`](render_registry_llms).
#[derive(Debug, Clone)]
pub struct ChannelView {
    /// Channel name.
    pub name: String,
    /// Frontier (newest) release version the channel targets, when known.
    pub frontier: Option<String>,
}

/// The data a registry [`llms.txt`](render_registry_llms) is generated from.
///
/// A data-only projection both shells build from their own read methods, so the
/// renderer stays pure. The caller is responsible for short-circuiting a custom
/// override body; this struct describes only the *generated* document.
#[derive(Debug, Clone)]
pub struct RegistryView {
    /// URL slug the registry is served under (e.g. `acme/cdn`).
    pub slug: String,
    /// Committed display name, when indexed (falls back to the slug).
    pub name: Option<String>,
    /// Committed description, when indexed.
    pub description: Option<String>,
    /// The instance's externally reachable base URL, without a trailing slash.
    pub base_url: String,
    /// The registry's indexed packages.
    pub packages: Vec<PackageView>,
    /// The registry's channels.
    pub channels: Vec<ChannelView>,
}

/// One registry entry in the root [`llms.txt`](render_root_llms).
#[derive(Debug, Clone)]
pub struct RootRegistryView {
    /// URL slug the registry is served under.
    pub slug: String,
    /// Committed description, when indexed.
    pub description: Option<String>,
    /// Absolute browse URL for the registry's home page.
    pub browse_url: String,
}

/// Render a registry's `llms.txt` body from its [`RegistryView`].
///
/// Follows the [llmstxt.org](https://llmstxt.org) convention: an `# H1` title, a
/// `> summary` blockquote, a prose line linking the browse root, then a
/// `## Packages` list and a `## Channels` list. A package with an empty
/// description renders without the trailing `: …`. The output ends in a single
/// trailing newline.
///
/// This renders the *generated* document; a registry with a custom
/// `llms_txt_body` override is served verbatim by the caller and never reaches
/// this function.
#[must_use]
pub fn render_registry_llms(view: &RegistryView) -> String {
    let title = view
        .name
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&view.slug);
    let summary = view
        .description
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("An AOS registry.");
    let base = view.base_url.trim_end_matches('/');

    let mut out = String::new();
    let _ = writeln!(out, "# {title}\n");
    let _ = writeln!(out, "> {summary}\n");
    let _ = writeln!(
        out,
        "Registry served by AOS registry hub. Browse: {base}/{slug}/\n",
        slug = view.slug,
    );

    out.push_str("## Packages\n");
    if view.packages.is_empty() {
        out.push_str("(none indexed yet)\n");
    } else {
        for pkg in &view.packages {
            if pkg.description.is_empty() {
                let _ = writeln!(out, "- [{}]({})", pkg.name, pkg.browse_url);
            } else {
                let _ = writeln!(
                    out,
                    "- [{}]({}): {}",
                    pkg.name, pkg.browse_url, pkg.description
                );
            }
        }
    }

    out.push_str("\n## Channels\n");
    if view.channels.is_empty() {
        out.push_str("(none)\n");
    } else {
        for ch in &view.channels {
            match &ch.frontier {
                Some(frontier) => {
                    let _ = writeln!(out, "- {}: {}", ch.name, frontier);
                }
                None => {
                    let _ = writeln!(out, "- {}", ch.name);
                }
            }
        }
    }
    out
}

/// Render the instance-root `llms.txt` body listing the public registries.
///
/// An `# H1` of the hub's brand name, a `> summary` blockquote, then a
/// `## Registries` list linking each public registry's browse home. The output
/// ends in a single trailing newline.
#[must_use]
pub fn render_root_llms(hub_name: &str, registries: &[RootRegistryView]) -> String {
    let title = if hub_name.trim().is_empty() {
        "AOS registry hub"
    } else {
        hub_name.trim()
    };
    let mut out = String::new();
    let _ = writeln!(out, "# {title}\n");
    out.push_str("> AOS registry hub.\n\n");
    out.push_str("## Registries\n");
    if registries.is_empty() {
        out.push_str("(none public)\n");
    } else {
        for reg in registries {
            match reg.description.as_deref().filter(|s| !s.is_empty()) {
                Some(desc) => {
                    let _ = writeln!(out, "- [{}]({}): {}", reg.slug, reg.browse_url, desc);
                }
                None => {
                    let _ = writeln!(out, "- [{}]({})", reg.slug, reg.browse_url);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_permits_everything() {
        assert_eq!(
            render_robots(CrawlPolicy::AllowAll, None),
            "User-agent: *\nAllow: /\n",
        );
    }

    #[test]
    fn deny_all_disallows_everything() {
        assert_eq!(
            render_robots(CrawlPolicy::DenyAll, None),
            "User-agent: *\nDisallow: /\n",
        );
    }

    #[test]
    fn allow_no_ai_blocks_each_ai_crawler() {
        let out = render_robots(CrawlPolicy::AllowNoAi, None);
        // The leading general-allow group.
        assert!(out.starts_with("User-agent: *\nAllow: /\n"));
        // Every known AI crawler gets an explicit disallow block.
        for bot in AI_CRAWLERS {
            assert!(
                out.contains(&format!("User-agent: {bot}\nDisallow: /\n")),
                "missing disallow block for {bot}",
            );
        }
        // One disallow per crawler (plus none for the general group).
        assert_eq!(out.matches("Disallow: /").count(), AI_CRAWLERS.len());
    }

    #[test]
    fn llms_txt_url_appended_as_comment() {
        let out = render_robots(CrawlPolicy::AllowAll, Some("https://h/llms.txt"));
        assert!(out.ends_with("# llms.txt: https://h/llms.txt\n"));
    }

    #[test]
    fn registry_llms_renders_packages_and_channels() {
        let view = RegistryView {
            slug: "acme/cdn".into(),
            name: Some("Acme CDN".into()),
            description: Some("The Acme CDN registry.".into()),
            base_url: "https://hub.example.com/".into(),
            packages: vec![
                PackageView {
                    name: "hello".into(),
                    description: "a friendly greeter".into(),
                    browse_url: "https://hub.example.com/acme/cdn/-/p/hello".into(),
                },
                PackageView {
                    name: "bare".into(),
                    description: String::new(),
                    browse_url: "https://hub.example.com/acme/cdn/-/p/bare".into(),
                },
            ],
            channels: vec![
                ChannelView {
                    name: "stable".into(),
                    frontier: Some("1.2.0".into()),
                },
                ChannelView {
                    name: "edge".into(),
                    frontier: None,
                },
            ],
        };
        let out = render_registry_llms(&view);
        assert!(out.starts_with("# Acme CDN\n"));
        assert!(out.contains("> The Acme CDN registry.\n"));
        assert!(out.contains("Browse: https://hub.example.com/acme/cdn/\n"));
        assert!(out.contains(
            "- [hello](https://hub.example.com/acme/cdn/-/p/hello): a friendly greeter\n"
        ));
        // Empty description omits the trailing colon.
        assert!(out.contains("- [bare](https://hub.example.com/acme/cdn/-/p/bare)\n"));
        assert!(out.contains("- stable: 1.2.0\n"));
        assert!(out.contains("- edge\n"));
    }

    #[test]
    fn registry_llms_falls_back_to_slug_and_default_summary() {
        let view = RegistryView {
            slug: "cdn".into(),
            name: None,
            description: None,
            base_url: "https://h".into(),
            packages: vec![],
            channels: vec![],
        };
        let out = render_registry_llms(&view);
        assert!(out.starts_with("# cdn\n"));
        assert!(out.contains("> An AOS registry.\n"));
        assert!(out.contains("(none indexed yet)\n"));
        assert!(out.contains("(none)\n"));
    }

    #[test]
    fn root_llms_lists_registries() {
        let out = render_root_llms(
            "Acme Hub",
            &[
                RootRegistryView {
                    slug: "acme/cdn".into(),
                    description: Some("the CDN".into()),
                    browse_url: "https://h/acme/cdn/".into(),
                },
                RootRegistryView {
                    slug: "acme/tools".into(),
                    description: None,
                    browse_url: "https://h/acme/tools/".into(),
                },
            ],
        );
        assert!(out.starts_with("# Acme Hub\n"));
        assert!(out.contains("- [acme/cdn](https://h/acme/cdn/): the CDN\n"));
        assert!(out.contains("- [acme/tools](https://h/acme/tools/)\n"));
    }

    #[test]
    fn root_llms_default_title_and_empty() {
        let out = render_root_llms("  ", &[]);
        assert!(out.starts_with("# AOS registry hub\n"));
        assert!(out.contains("(none public)\n"));
    }
}
