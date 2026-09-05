//! Structured form model for a registry's committed `registry.toml`.
//!
//! The web console edits a registry's root config through an auto-generated
//! HTML form rather than a raw TOML textarea: each field of the
//! [`RegistryRootConfig`] schema maps to one control. This module is the pure,
//! wasm-clean bridge between that form and the committed file — it carries no
//! I/O, so the native hub and the Cloudflare Worker share it through the
//! console handlers.
//!
//! Two directions:
//!
//! - **Render** — [`parse_model`] reads the current committed `registry.toml`
//!   into a [`ConfigFormModel`] to pre-fill the form. An unparseable file
//!   returns `None`, signalling the handler to fall back to the raw-TOML
//!   editor.
//! - **Submit** — [`parse_submission`] decodes the posted form body into a
//!   [`Submission`], and [`build_toml`] merges it back into the existing
//!   document and re-serializes it. The merge edits the parsed
//!   [`toml::Value`] in place, so any keys the form does not model round-trip
//!   untouched; only the modeled fields change.
//!
//! The rebuilt file is validated against [`RegistryRootConfig`] before it is
//! returned, so the form can never propose a config the indexer would reject.
//!
//! # The `[caches]` cache stack
//!
//! The committed `[caches]` value is the unified RFC-0004 cache stack — the
//! single source of truth for the binary caches a registry advertises. The
//! form edits it as a simple ordered list of cache URLs (priority is the list
//! order). On write the list is serialized back as a `[caches]` stack:
//!
//! - a single URL becomes a bare endpoint:
//!
//!   ```toml
//!   [caches]
//!   endpoint = "https://cache.andyl.org"
//!   ```
//!
//! - several URLs become a `try` fall-through, highest preference first:
//!
//!   ```toml
//!   [caches]
//!   kind = "try"
//!   members = [
//!     { endpoint = "https://cache.andyl.org" },
//!     { endpoint = "https://mirror.andyl.org" },
//!   ]
//!   ```
//!
//! A registry whose committed `[caches]` is an *advanced* stack the flat list
//! cannot represent (a `mirror`, or any nesting) is left opaque: the form
//! reports it ([`ConfigFormModel::has_cache_stack`]) and asks the maintainer
//! to edit the raw TOML, never silently flattening it.
//!
//! TOML comments are not preserved across a form edit (the document is parsed
//! into values and re-serialized); the modeled values and any unmodeled keys
//! are.

use anyhow::{bail, Context, Result};
use aos_registry_surface::manifest::{CachesConfig, RegistryRootConfig};
use aos_registry_surface::stack::StackNode;

/// The base priority the flattened `[caches]` stack assigns its first entry
/// (mirrors the schema's `default_cache_priority`). Used only to display a
/// resolved priority next to each row.
const DEFAULT_CACHE_PRIORITY: u32 = 100;

/// One cache row as shown in the form: a cache URL and its resolved priority.
///
/// Priority is derived from list order (the first URL is highest), so the form
/// presents it read-only; reordering rows reorders preference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheRow {
    /// Base URL of the binary cache.
    pub url: String,
    /// Resolved selection priority — higher is tried first.
    pub priority: u32,
}

/// The field values to render into the config form.
///
/// Built from the committed file for the initial render ([`parse_model`]), or
/// from a rejected submission so the user's input survives a validation error
/// ([`model_from_submission`]).
#[derive(Debug, Clone, Default)]
pub struct ConfigFormModel {
    /// Canonical registry name (`[registry].name`); required.
    pub name: String,
    /// One-line description, empty when unset.
    pub description: String,
    /// Preferred initial public-browser release, empty for semantic newest.
    pub default_release: String,
    /// Longer README preamble, empty when unset.
    pub readme: String,
    /// Whether the registry records content addresses (`content_addressed`).
    pub content_addressed: bool,
    /// The flattened `[caches]` list, in preference order.
    pub caches: Vec<CacheRow>,
    /// Whether the committed `[caches]` is an advanced stack the flat list
    /// editor cannot represent (a `mirror`, or any nesting). The form preserves
    /// it untouched and shows a read-only "edit raw TOML" note when `true`.
    pub has_cache_stack: bool,
    /// A validation error to surface above the form, when re-rendering a
    /// rejected submission.
    pub error: Option<String>,
}

impl ConfigFormModel {
    /// Returns the blank model for a registry with no committed config yet.
    ///
    /// Defaults match the schema: content-addressing on, no caches, no
    /// description or readme.
    #[must_use]
    pub fn empty() -> ConfigFormModel {
        ConfigFormModel {
            content_addressed: true,
            ..ConfigFormModel::default()
        }
    }
}

/// Reads the current committed `registry.toml` into a [`ConfigFormModel`].
///
/// An empty input (a registry that has never been indexed) yields
/// [`ConfigFormModel::empty`]. A non-empty file that parses as a
/// [`RegistryRootConfig`] yields a populated model. A file that fails to parse
/// returns `None` — the caller should fall back to the raw-TOML editor so a
/// hand-written config the form can't represent is never silently dropped.
#[must_use]
pub fn parse_model(current_toml: &str) -> Option<ConfigFormModel> {
    if current_toml.trim().is_empty() {
        return Some(ConfigFormModel::empty());
    }
    let cfg: RegistryRootConfig = toml::from_str(current_toml).ok()?;
    let advanced = is_advanced_stack(&cfg);
    Some(ConfigFormModel {
        name: cfg.registry.name.clone(),
        description: cfg.registry.description.clone().unwrap_or_default(),
        default_release: cfg.registry.default_release.clone().unwrap_or_default(),
        readme: cfg.registry.readme.clone().unwrap_or_default(),
        content_addressed: cfg.registry.content_addressed,
        // Only populate the flat editor when the stack is simple-representable;
        // an advanced stack is shown opaquely instead.
        caches: if advanced {
            Vec::new()
        } else {
            cfg.cache_entries()
                .into_iter()
                .map(|c| CacheRow {
                    url: c.url,
                    priority: c.priority,
                })
                .collect()
        },
        has_cache_stack: advanced,
        error: None,
    })
}

/// Whether a committed `[caches]` is a stack the flat list editor cannot
/// represent — i.e. it contains a `mirror` or any nesting.
///
/// A single endpoint and a flat `try` of endpoints are representable as the
/// simple ordered-URL editor; everything else is "advanced" and edited as raw
/// TOML.
fn is_advanced_stack(cfg: &RegistryRootConfig) -> bool {
    match &cfg.caches {
        None => false,
        Some(CachesConfig(_)) => match cfg.cache_stack() {
            None => true, // unparseable: don't pretend the flat editor owns it
            Some(node) => !is_simple_stack(&node),
        },
    }
}

/// Whether `node` is an endpoint or a flat `try` of endpoints — the shapes the
/// simple ordered-URL editor round-trips.
fn is_simple_stack(node: &StackNode) -> bool {
    match node {
        StackNode::Endpoint(_) => true,
        StackNode::Try(members) => members.iter().all(|m| matches!(m, StackNode::Endpoint(_))),
        StackNode::Mirror(_) => false,
    }
}

/// One submitted cache row, with the priority kept as raw text until validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCacheRow {
    /// The submitted cache URL (untrimmed).
    pub url: String,
    /// The submitted priority text (untrimmed); parsed by [`build_toml`].
    pub priority: String,
}

/// A decoded config-form submission.
///
/// Field values are kept verbatim (untrimmed); [`build_toml`] normalizes and
/// validates them. The `csrf` token is carried through for the handler's
/// cross-site check.
#[derive(Debug, Clone, Default)]
pub struct Submission {
    /// The submitted CSRF token.
    pub csrf: String,
    /// The submitted registry name.
    pub name: String,
    /// The submitted description.
    pub description: String,
    /// The preferred initial public-browser release.
    pub default_release: String,
    /// The submitted readme.
    pub readme: String,
    /// Whether the content-addressed toggle was checked.
    pub content_addressed: bool,
    /// The submitted cache rows, paired by document order.
    pub caches: Vec<RawCacheRow>,
    /// The change-request title the proposer typed (untrimmed; empty falls back
    /// to the auto commit summary).
    pub title: String,
    /// The change-request description the proposer typed (untrimmed; optional).
    pub body: String,
}

/// Decodes an `application/x-www-form-urlencoded` config-form body.
///
/// Cache rows arrive as parallel repeated `cache_url` / `cache_priority`
/// fields; the browser submits them in DOM order, so this zips the two ordered
/// lists into [`RawCacheRow`]s. The `content_addressed` checkbox is treated as
/// set when present with any value (the unchecked box submits nothing).
#[must_use]
pub fn parse_submission(body: &str) -> Submission {
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let first = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let all = |key: &str| -> Vec<String> {
        pairs
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    };
    let urls = all("cache_url");
    let priorities = all("cache_priority");
    let caches = urls
        .into_iter()
        .zip(
            priorities
                .into_iter()
                .chain(std::iter::repeat(String::new())),
        )
        .map(|(url, priority)| RawCacheRow { url, priority })
        .collect();
    Submission {
        csrf: first("csrf"),
        name: first("name"),
        description: first("description"),
        readme: first("readme"),
        default_release: first("default_release"),
        content_addressed: pairs.iter().any(|(k, _)| k == "content_addressed"),
        caches,
        title: first("cr_title"),
        body: first("cr_body"),
    }
}

/// Builds the model to re-render when a submission is rejected.
///
/// Preserves the user's typed values (a blank-URL row is dropped) and attaches
/// `error`. Resolved priority is derived from row order (the unified `[caches]`
/// stack derives priority from order), so the first row is highest.
/// `has_cache_stack` cannot be known from the submission alone, so the caller
/// sets it from the current committed file.
#[must_use]
pub fn model_from_submission(sub: &Submission, error: String) -> ConfigFormModel {
    let caches = sub
        .caches
        .iter()
        .filter(|r| !r.url.trim().is_empty())
        .enumerate()
        .map(|(offset, r)| CacheRow {
            url: r.url.trim().to_string(),
            priority: DEFAULT_CACHE_PRIORITY.saturating_sub(offset as u32),
        })
        .collect();
    ConfigFormModel {
        name: sub.name.trim().to_string(),
        description: sub.description.clone(),
        readme: sub.readme.clone(),
        default_release: sub.default_release.clone(),
        content_addressed: sub.content_addressed,
        caches,
        has_cache_stack: false,
        error: Some(error),
    }
}

/// Merges a submission into the existing `registry.toml` and re-serializes it.
///
/// The existing document is parsed into a [`toml::Value`] and edited in place:
/// the `[registry]` metadata and the unified `[caches]` cache stack are
/// rewritten from the submission, while every other unmodeled key is left
/// untouched. The cache rows become a `[caches]` stack ordered by preference
/// (a single URL → a bare endpoint; several → a `try` group). Empty optional
/// fields are removed rather than written as blank, so the committed file stays
/// terse. The result is validated against [`RegistryRootConfig`] before being
/// returned.
///
/// Cache rows arrive blank-URL-dropped and in preference order; the per-row
/// priority text is ignored because the unified `[caches]` stack derives
/// priority from order.
///
/// # Errors
///
/// Returns an error when the registry name is empty, when the existing file is
/// malformed or not a TOML table, or when the rebuilt document fails schema
/// validation.
pub fn build_toml(existing: &str, sub: &Submission) -> Result<String> {
    let name = sub.name.trim();
    if name.is_empty() {
        bail!("registry name is required");
    }

    let mut doc: toml::Value = if existing.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(existing).context("parsing existing registry.toml")?
    };
    let root = doc
        .as_table_mut()
        .context("registry.toml is not a TOML table")?;

    // [registry] metadata — create the table if the file had none.
    let reg = root
        .entry("registry")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .context("[registry] is not a table")?;
    reg.insert("name".into(), toml::Value::String(name.to_string()));
    set_or_remove(reg, "description", sub.description.trim());
    set_or_remove(reg, "readme", sub.readme.trim());
    set_or_remove(reg, "default_release", sub.default_release.trim());
    // content_addressed defaults to true; only the false case is written.
    if sub.content_addressed {
        reg.remove("content_addressed");
    } else {
        reg.insert("content_addressed".into(), toml::Value::Boolean(false));
    }

    // [caches] — rebuilt entirely from the submitted rows in preference order
    // (blank URLs dropped). An empty list removes the key. An advanced stack
    // (a mirror or any nesting) the flat editor cannot represent is left
    // untouched: the form edits it as raw TOML, never through these rows, so
    // clobbering it here would silently flatten a maintainer's mirror.
    if !existing_caches_are_advanced(root) {
        let urls: Vec<String> = sub
            .caches
            .iter()
            .map(|row| row.url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect();
        match caches_stack_value(&urls) {
            Some(value) => {
                root.insert("caches".into(), value);
            }
            None => {
                root.remove("caches");
            }
        }
    }

    let rendered = toml::to_string_pretty(&doc).context("serializing registry.toml")?;
    // Fail closed: never propose a file the indexer would reject.
    toml::from_str::<RegistryRootConfig>(&rendered)
        .context("the rebuilt registry.toml is not valid")?;
    Ok(rendered)
}

/// Builds the `[caches]` stack [`toml::Value`] for an ordered list of URLs.
///
/// Returns `None` for an empty list (the caller removes the key), a bare
/// `endpoint` table for one URL, and a `kind = "try"` group of endpoint tables
/// for several — the simple-representable shapes [`parse_model`] reads back.
fn caches_stack_value(urls: &[String]) -> Option<toml::Value> {
    match urls {
        [] => None,
        [only] => {
            let mut table = toml::map::Map::new();
            table.insert("endpoint".into(), toml::Value::String(only.clone()));
            Some(toml::Value::Table(table))
        }
        many => {
            let members = many
                .iter()
                .map(|url| {
                    let mut member = toml::map::Map::new();
                    member.insert("endpoint".into(), toml::Value::String(url.clone()));
                    toml::Value::Table(member)
                })
                .collect();
            let mut table = toml::map::Map::new();
            table.insert("kind".into(), toml::Value::String("try".into()));
            table.insert("members".into(), toml::Value::Array(members));
            Some(toml::Value::Table(table))
        }
    }
}

/// Whether the document's existing `[caches]` is an advanced stack the flat
/// editor cannot represent (a `mirror`, or any nesting).
///
/// Reparses the document's `[caches]` table through [`RegistryRootConfig`] so
/// the advanced check matches [`parse_model`] exactly. A document with no
/// `[caches]` or a simple stack is not advanced.
fn existing_caches_are_advanced(root: &toml::map::Map<String, toml::Value>) -> bool {
    let Some(caches) = root.get("caches") else {
        return false;
    };
    // Wrap the value back into a minimal root config to reuse is_advanced_stack.
    let mut probe = toml::map::Map::new();
    let mut reg = toml::map::Map::new();
    reg.insert("name".into(), toml::Value::String("_probe".into()));
    probe.insert("registry".into(), toml::Value::Table(reg));
    probe.insert("caches".into(), caches.clone());
    match toml::Value::Table(probe).try_into::<RegistryRootConfig>() {
        Ok(cfg) => is_advanced_stack(&cfg),
        Err(_) => false,
    }
}

/// Inserts `key = value` into `table`, or removes `key` when `value` is empty.
fn set_or_remove(table: &mut toml::map::Map<String, toml::Value>, key: &str, value: &str) {
    if value.is_empty() {
        table.remove(key);
    } else {
        table.insert(key.into(), toml::Value::String(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_default_release_round_trips_without_changing_channel_policy() {
        let source = "[registry]\nname = \"demo\"\ndefault_release = \"1.2.3\"\n";
        let model = parse_model(source).unwrap();
        assert_eq!(model.default_release, "1.2.3");
        let submission =
            parse_submission("name=demo&default_release=2.0.0-rc.1&content_addressed=1");
        let updated = build_toml(source, &submission).unwrap();
        assert_eq!(parse_model(&updated).unwrap().default_release, "2.0.0-rc.1");
        assert!(!updated.contains("channel"));
        assert!(parse_model("[registry]\nname = \"demo\"\ndefault_release = \"HEAD\"\n").is_none());
    }

    #[test]
    fn empty_model_defaults_to_content_addressed() {
        let m = parse_model("").expect("empty parses");
        assert!(m.content_addressed);
        assert!(m.name.is_empty());
        assert!(m.caches.is_empty());
        assert!(!m.has_cache_stack);
    }

    #[test]
    fn parses_a_single_endpoint_stack() {
        let src = "[registry]\nname = \"andyl\"\ndescription = \"d\"\n\n\
                   [caches]\nendpoint = \"https://c\"\n";
        let m = parse_model(src).expect("parses");
        assert_eq!(m.name, "andyl");
        assert_eq!(m.description, "d");
        assert_eq!(
            m.caches,
            vec![CacheRow {
                url: "https://c".into(),
                priority: 100
            }]
        );
        assert!(!m.has_cache_stack);
    }

    #[test]
    fn parses_a_flat_try_stack_in_descending_priority() {
        let src = "[registry]\nname = \"andyl\"\n\n\
                   [caches]\nkind = \"try\"\n\
                   members = [{ endpoint = \"https://a\" }, { endpoint = \"https://b\" }]\n";
        let m = parse_model(src).expect("parses");
        assert_eq!(
            m.caches,
            vec![
                CacheRow {
                    url: "https://a".into(),
                    priority: 100
                },
                CacheRow {
                    url: "https://b".into(),
                    priority: 99
                },
            ]
        );
        assert!(!m.has_cache_stack);
    }

    #[test]
    fn advanced_mirror_stack_is_opaque() {
        let src = "[registry]\nname = \"andyl\"\n\n\
                   [caches]\nkind = \"mirror\"\n\
                   members = [{ endpoint = \"https://a\" }, { endpoint = \"https://b\" }]\n";
        let m = parse_model(src).expect("parses");
        // Flat editor cannot represent a mirror: shown opaquely, no rows.
        assert!(m.has_cache_stack);
        assert!(m.caches.is_empty());
    }

    #[test]
    fn malformed_config_returns_none_for_raw_fallback() {
        assert!(parse_model("this is not = = toml").is_none());
        // Missing the required [registry].name also can't form-model.
        assert!(parse_model("[registry]\ndescription = \"d\"\n").is_none());
    }

    #[test]
    fn parse_submission_zips_cache_rows() {
        let body = "csrf=t&name=andyl&description=d&content_addressed=1\
                    &cache_url=https%3A%2F%2Fa&cache_priority=100\
                    &cache_url=https%3A%2F%2Fb&cache_priority=20";
        let sub = parse_submission(body);
        assert_eq!(sub.csrf, "t");
        assert_eq!(sub.name, "andyl");
        assert!(sub.content_addressed);
        assert_eq!(sub.caches.len(), 2);
        assert_eq!(sub.caches[1].url, "https://b");
        assert_eq!(sub.caches[1].priority, "20");
    }

    #[test]
    fn unchecked_toggle_is_false() {
        let sub = parse_submission("csrf=t&name=andyl");
        assert!(!sub.content_addressed);
    }

    #[test]
    fn build_requires_a_name() {
        let sub = Submission {
            name: "  ".into(),
            ..Submission::default()
        };
        assert!(build_toml("", &sub).is_err());
    }

    #[test]
    fn build_writes_a_single_endpoint_stack() {
        let sub = Submission {
            name: "andyl".into(),
            caches: vec![RawCacheRow {
                url: "https://only".into(),
                priority: String::new(),
            }],
            ..Submission::default()
        };
        let out = build_toml("", &sub).expect("builds");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert_eq!(
            cfg.cache_stack(),
            Some(StackNode::Endpoint("https://only".into()))
        );
        let entries = cfg.cache_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "https://only");
    }

    #[test]
    fn build_writes_a_try_stack_for_several_urls() {
        let sub = Submission {
            name: "andyl".into(),
            description: "the registry".into(),
            readme: "preamble".into(),
            content_addressed: true,
            caches: vec![
                RawCacheRow {
                    url: "https://a".into(),
                    priority: String::new(),
                },
                RawCacheRow {
                    url: "https://b".into(),
                    priority: String::new(),
                },
            ],
            ..Submission::default()
        };
        let out = build_toml("", &sub).expect("builds");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert_eq!(cfg.registry.name, "andyl");
        assert_eq!(cfg.registry.description.as_deref(), Some("the registry"));
        assert!(cfg.registry.content_addressed);
        // Order is preference; flattened priority descends.
        let entries = cfg.cache_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            (entries[0].url.as_str(), entries[0].priority),
            ("https://a", 100)
        );
        assert_eq!(
            (entries[1].url.as_str(), entries[1].priority),
            ("https://b", 99)
        );
        assert!(matches!(cfg.cache_stack(), Some(StackNode::Try(_))));
    }

    #[test]
    fn build_with_no_caches_removes_the_key() {
        let existing = "[registry]\nname = \"andyl\"\n\n[caches]\nendpoint = \"https://a\"\n";
        let sub = Submission {
            name: "andyl".into(),
            ..Submission::default()
        };
        let out = build_toml(existing, &sub).expect("builds");
        assert!(!out.contains("caches"));
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert!(cfg.caches.is_none());
    }

    #[test]
    fn content_addressed_false_is_written() {
        let sub = Submission {
            name: "x".into(),
            content_addressed: false,
            ..Submission::default()
        };
        let out = build_toml("", &sub).expect("builds");
        assert!(out.contains("content_addressed = false"));
    }

    #[test]
    fn empty_optional_fields_are_removed_not_blanked() {
        let existing = "[registry]\nname = \"old\"\ndescription = \"gone\"\nreadme = \"gone\"\n";
        let sub = Submission {
            name: "new".into(),
            ..Submission::default()
        };
        let out = build_toml(existing, &sub).expect("builds");
        assert!(!out.contains("description"));
        assert!(!out.contains("readme"));
        assert!(out.contains("name = \"new\""));
    }

    #[test]
    fn advanced_stack_is_left_untouched_by_build() {
        // An advanced (mirror) [caches] the flat editor can't represent must
        // survive a metadata-only edit even when the submission carries no rows.
        let existing = "[registry]\nname = \"andyl\"\n\n\
                        [caches]\nkind = \"mirror\"\n\
                        members = [{ endpoint = \"https://a\" }, { endpoint = \"https://b\" }]\n";
        let sub = Submission {
            name: "andyl".into(),
            description: "edited".into(),
            ..Submission::default()
        };
        let out = build_toml(existing, &sub).expect("builds");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert_eq!(cfg.registry.description.as_deref(), Some("edited"));
        // The mirror stack is preserved verbatim.
        assert!(matches!(cfg.cache_stack(), Some(StackNode::Mirror(_))));
    }

    #[test]
    fn blank_cache_rows_are_dropped() {
        let sub = Submission {
            name: "x".into(),
            caches: vec![
                RawCacheRow {
                    url: "  ".into(),
                    priority: "100".into(),
                },
                RawCacheRow {
                    url: "https://a".into(),
                    priority: String::new(),
                },
            ],
            ..Submission::default()
        };
        let out = build_toml("", &sub).expect("builds");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        let entries = cfg.cache_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "https://a");
    }
}
