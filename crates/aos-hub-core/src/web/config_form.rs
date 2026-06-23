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
//!   [`toml::Value`] in place, so an advanced `[cache_stack]` and any keys the
//!   form does not model round-trip untouched; only the modeled fields change.
//!
//! The rebuilt file is validated against [`RegistryRootConfig`] before it is
//! returned, so the form can never propose a config the indexer would reject.
//!
//! ```toml
//! [registry]
//! name = "andyl"
//! description = "the andyl package registry"
//! readme = "A longer preamble…"
//! content_addressed = true
//!
//! [[caches]]
//! url = "https://cache.andyl.org"
//! priority = 100
//! ```
//!
//! TOML comments are not preserved across a form edit (the document is parsed
//! into values and re-serialized); the modeled values and any unmodeled keys
//! are.

use anyhow::{bail, Context, Result};
use aos_registry_surface::manifest::RegistryRootConfig;

/// The serde default for [`crate`]-modeled cache priority (mirrors the
/// schema's `default_cache_priority`). A row at this priority omits the key on
/// write to keep the committed file terse.
const DEFAULT_CACHE_PRIORITY: u32 = 100;

/// One `[[caches]]` row as shown in the form: a cache URL and its priority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheRow {
    /// Base URL of the binary cache.
    pub url: String,
    /// Cache selection priority — higher is tried first.
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
    /// Longer README preamble, empty when unset.
    pub readme: String,
    /// Whether the registry records content addresses (`content_addressed`).
    pub content_addressed: bool,
    /// The flat `[[caches]]` list, in committed order.
    pub caches: Vec<CacheRow>,
    /// Whether the file also defines an advanced `[cache_stack]`. The form
    /// preserves it untouched and shows a read-only note when `true`.
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
    Some(ConfigFormModel {
        name: cfg.registry.name.clone(),
        description: cfg.registry.description.clone().unwrap_or_default(),
        readme: cfg.registry.readme.clone().unwrap_or_default(),
        content_addressed: cfg.registry.content_addressed,
        caches: cfg
            .caches
            .iter()
            .map(|c| CacheRow {
                url: c.url.clone(),
                priority: c.priority,
            })
            .collect(),
        has_cache_stack: cfg.cache_stack.is_some(),
        error: None,
    })
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
    /// The submitted readme.
    pub readme: String,
    /// Whether the content-addressed toggle was checked.
    pub content_addressed: bool,
    /// The submitted cache rows, paired by document order.
    pub caches: Vec<RawCacheRow>,
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
        content_addressed: pairs.iter().any(|(k, _)| k == "content_addressed"),
        caches,
    }
}

/// Builds the model to re-render when a submission is rejected.
///
/// Preserves the user's typed values (a blank-URL row is dropped, an
/// unparseable priority falls back to the default for display) and attaches
/// `error`. `has_cache_stack` cannot be known from the submission alone, so the
/// caller sets it from the current committed file.
#[must_use]
pub fn model_from_submission(sub: &Submission, error: String) -> ConfigFormModel {
    ConfigFormModel {
        name: sub.name.trim().to_string(),
        description: sub.description.clone(),
        readme: sub.readme.clone(),
        content_addressed: sub.content_addressed,
        caches: sub
            .caches
            .iter()
            .filter(|r| !r.url.trim().is_empty())
            .map(|r| CacheRow {
                url: r.url.trim().to_string(),
                priority: r.priority.trim().parse().unwrap_or(DEFAULT_CACHE_PRIORITY),
            })
            .collect(),
        has_cache_stack: false,
        error: Some(error),
    }
}

/// Merges a submission into the existing `registry.toml` and re-serializes it.
///
/// The existing document is parsed into a [`toml::Value`] and edited in place:
/// the `[registry]` metadata and `[[caches]]` list are rewritten from the
/// submission, while every other key — notably an advanced `[cache_stack]` —
/// is left untouched. Empty optional fields are removed rather than written as
/// blank, and a cache row at the default priority omits the `priority` key, so
/// the committed file stays terse. The result is validated against
/// [`RegistryRootConfig`] before being returned.
///
/// # Errors
///
/// Returns an error when the registry name is empty, when a cache row carries
/// an unparseable priority, when the existing file is malformed or not a TOML
/// table, or when the rebuilt document fails schema validation.
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
    // content_addressed defaults to true; only the false case is written.
    if sub.content_addressed {
        reg.remove("content_addressed");
    } else {
        reg.insert("content_addressed".into(), toml::Value::Boolean(false));
    }

    // [[caches]] — rebuilt entirely from the submitted rows (blank URLs
    // dropped). An empty list removes the key.
    let mut caches = Vec::new();
    for row in &sub.caches {
        let url = row.url.trim();
        if url.is_empty() {
            continue;
        }
        let priority_text = row.priority.trim();
        let priority = if priority_text.is_empty() {
            DEFAULT_CACHE_PRIORITY
        } else {
            priority_text
                .parse::<u32>()
                .with_context(|| format!("invalid priority '{priority_text}' for cache {url}"))?
        };
        let mut entry = toml::map::Map::new();
        entry.insert("url".into(), toml::Value::String(url.to_string()));
        if priority != DEFAULT_CACHE_PRIORITY {
            entry.insert("priority".into(), toml::Value::Integer(i64::from(priority)));
        }
        caches.push(toml::Value::Table(entry));
    }
    if caches.is_empty() {
        root.remove("caches");
    } else {
        root.insert("caches".into(), toml::Value::Array(caches));
    }

    let rendered = toml::to_string_pretty(&doc).context("serializing registry.toml")?;
    // Fail closed: never propose a file the indexer would reject.
    toml::from_str::<RegistryRootConfig>(&rendered)
        .context("the rebuilt registry.toml is not valid")?;
    Ok(rendered)
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
    fn empty_model_defaults_to_content_addressed() {
        let m = parse_model("").expect("empty parses");
        assert!(m.content_addressed);
        assert!(m.name.is_empty());
        assert!(m.caches.is_empty());
        assert!(!m.has_cache_stack);
    }

    #[test]
    fn parses_a_populated_config() {
        let src = "[registry]\nname = \"andyl\"\ndescription = \"d\"\n\n\
                   [[caches]]\nurl = \"https://c\"\npriority = 50\n";
        let m = parse_model(src).expect("parses");
        assert_eq!(m.name, "andyl");
        assert_eq!(m.description, "d");
        assert_eq!(
            m.caches,
            vec![CacheRow {
                url: "https://c".into(),
                priority: 50
            }]
        );
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
    fn build_round_trips_through_the_schema() {
        let sub = Submission {
            name: "andyl".into(),
            description: "the registry".into(),
            readme: "preamble".into(),
            content_addressed: true,
            caches: vec![
                RawCacheRow {
                    url: "https://a".into(),
                    priority: "100".into(),
                },
                RawCacheRow {
                    url: "https://b".into(),
                    priority: "20".into(),
                },
            ],
            ..Submission::default()
        };
        let out = build_toml("", &sub).expect("builds");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert_eq!(cfg.registry.name, "andyl");
        assert_eq!(cfg.registry.description.as_deref(), Some("the registry"));
        assert!(cfg.registry.content_addressed);
        assert_eq!(cfg.caches.len(), 2);
        // Default priority is omitted from the file but defaults back on read.
        assert_eq!(cfg.caches[0].priority, 100);
        assert_eq!(cfg.caches[1].priority, 20);
        assert!(!out.contains("priority = 100"));
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
    fn cache_stack_and_unknown_keys_round_trip_untouched() {
        let existing = "[registry]\nname = \"andyl\"\n\n\
                        [cache_stack]\ntry = [\"https://a\", \"https://b\"]\n";
        let sub = Submission {
            name: "andyl".into(),
            caches: vec![RawCacheRow {
                url: "https://c".into(),
                priority: "".into(),
            }],
            ..Submission::default()
        };
        let out = build_toml(existing, &sub).expect("builds");
        // The advanced stack is preserved verbatim in value terms.
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert!(cfg.cache_stack.is_some());
        assert_eq!(cfg.caches.len(), 1);
        assert_eq!(cfg.caches[0].url, "https://c");
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
                    priority: "".into(),
                },
            ],
            ..Submission::default()
        };
        let out = build_toml("", &sub).expect("builds");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert_eq!(cfg.caches.len(), 1);
    }

    #[test]
    fn invalid_priority_is_rejected() {
        let sub = Submission {
            name: "x".into(),
            caches: vec![RawCacheRow {
                url: "https://a".into(),
                priority: "soon".into(),
            }],
            ..Submission::default()
        };
        assert!(build_toml("", &sub).is_err());
    }
}
