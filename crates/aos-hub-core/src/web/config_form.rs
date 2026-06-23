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

/// Parses `existing` into an editable document table, guaranteeing a
/// `[registry].name` so the result will pass [`RegistryRootConfig`] validation.
///
/// An empty input starts a fresh table; a missing or blank `[registry].name`
/// is seeded from `registry_name` (the registry record's name) so adding a
/// cache to a not-yet-configured registry still produces a valid file.
fn open_doc(existing: &str, registry_name: &str) -> Result<toml::Value> {
    let mut doc: toml::Value = if existing.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(existing).context("parsing existing registry.toml")?
    };
    let root = doc
        .as_table_mut()
        .context("registry.toml is not a TOML table")?;
    let reg = root
        .entry("registry")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .context("[registry] is not a table")?;
    let has_name = reg
        .get("name")
        .and_then(toml::Value::as_str)
        .is_some_and(|n| !n.trim().is_empty());
    if !has_name {
        reg.insert("name".into(), toml::Value::String(registry_name.to_string()));
    }
    Ok(doc)
}

/// Serializes an edited document and validates it against [`RegistryRootConfig`].
fn finalize(doc: &toml::Value) -> Result<String> {
    let rendered = toml::to_string_pretty(doc).context("serializing registry.toml")?;
    toml::from_str::<RegistryRootConfig>(&rendered)
        .context("the rebuilt registry.toml is not valid")?;
    Ok(rendered)
}

/// Returns the `[[caches]]` array of `root`, creating an empty one if absent.
///
/// # Errors
///
/// Returns an error when a `caches` key exists but is not an array.
fn caches_array(root: &mut toml::map::Map<String, toml::Value>) -> Result<&mut Vec<toml::Value>> {
    root.entry("caches")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .context("[[caches]] is not an array")
}

/// Whether `entry` is a `[[caches]]` table whose `url` equals `url`.
fn cache_entry_matches(entry: &toml::Value, url: &str) -> bool {
    entry.get("url").and_then(toml::Value::as_str) == Some(url)
}

/// Adds a `[[caches]]` entry for `url` to `existing`, preserving everything else.
///
/// This is the surgical counterpart to [`build_toml`] used by the cache-link
/// advertise flow: it edits the parsed [`toml::Value`] in place, so `[registry]`
/// metadata, an advanced `[cache_stack]`, and any unmodeled keys round-trip
/// untouched. The committed entry carries only the `url` — the cache's real nix
/// substituter priority travels in its own `nix-cache-info`, while the
/// `[[caches]].priority` is merely the registry's advertised-list ordering, so a
/// bare `url` (default priority) is the honest default.
///
/// Idempotent: returns `Ok(None)` when an entry for `url` is already present, so
/// the caller proposes no change. Otherwise returns `Ok(Some(rendered))`.
///
/// # Errors
///
/// Returns an error when the existing file is malformed or not a TOML table, or
/// when the rebuilt document fails schema validation.
pub fn add_cache_to_toml(
    existing: &str,
    registry_name: &str,
    url: &str,
) -> Result<Option<String>> {
    let mut doc = open_doc(existing, registry_name)?;
    let root = doc
        .as_table_mut()
        .context("registry.toml is not a TOML table")?;
    let caches = caches_array(root)?;
    if caches.iter().any(|e| cache_entry_matches(e, url)) {
        return Ok(None);
    }
    let mut entry = toml::map::Map::new();
    entry.insert("url".into(), toml::Value::String(url.to_string()));
    caches.push(toml::Value::Table(entry));
    Ok(Some(finalize(&doc)?))
}

/// Removes the `[[caches]]` entry for `url` from `existing`, preserving the rest.
///
/// The inverse of [`add_cache_to_toml`]. Idempotent: returns `Ok(None)` when no
/// entry for `url` is present (nothing to propose). When removing the last entry
/// the now-empty `caches` key is dropped so the file stays terse.
///
/// # Errors
///
/// Returns an error when the existing file is malformed or not a TOML table, or
/// when the rebuilt document fails schema validation.
pub fn remove_cache_from_toml(
    existing: &str,
    registry_name: &str,
    url: &str,
) -> Result<Option<String>> {
    let mut doc = open_doc(existing, registry_name)?;
    let root = doc
        .as_table_mut()
        .context("registry.toml is not a TOML table")?;
    let caches = caches_array(root)?;
    let before = caches.len();
    caches.retain(|e| !cache_entry_matches(e, url));
    if caches.len() == before {
        return Ok(None);
    }
    if caches.is_empty() {
        root.remove("caches");
    }
    Ok(Some(finalize(&doc)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_cache_appends_and_is_idempotent() {
        let existing = "[registry]\nname = \"andyl\"\n";
        let out = add_cache_to_toml(existing, "andyl", "https://c1")
            .expect("adds")
            .expect("changed");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert_eq!(cfg.caches.len(), 1);
        assert_eq!(cfg.caches[0].url, "https://c1");
        assert_eq!(cfg.caches[0].priority, 100); // omitted → schema default
        // Re-adding the same URL is a no-op (no change request).
        assert!(add_cache_to_toml(&out, "andyl", "https://c1")
            .expect("idempotent")
            .is_none());
    }

    #[test]
    fn add_cache_preserves_existing_caches_and_stack() {
        let existing = "[registry]\nname = \"andyl\"\n\n\
                        [[caches]]\nurl = \"https://ext\"\npriority = 50\n\n\
                        [cache_stack]\ntry = [\"https://a\"]\n";
        let out = add_cache_to_toml(existing, "andyl", "https://managed")
            .expect("adds")
            .expect("changed");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert_eq!(cfg.caches.len(), 2);
        assert!(cfg.caches.iter().any(|c| c.url == "https://ext" && c.priority == 50));
        assert!(cfg.caches.iter().any(|c| c.url == "https://managed"));
        assert!(cfg.cache_stack.is_some()); // advanced stack untouched
    }

    #[test]
    fn add_cache_seeds_name_on_bare_file() {
        // A registry with no committed config yet still yields a valid file.
        let out = add_cache_to_toml("", "demo-reg", "https://c")
            .expect("adds")
            .expect("changed");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert_eq!(cfg.registry.name, "demo-reg");
        assert_eq!(cfg.caches.len(), 1);
    }

    #[test]
    fn remove_cache_drops_entry_and_is_idempotent() {
        let existing = "[registry]\nname = \"andyl\"\n\n\
                        [[caches]]\nurl = \"https://keep\"\n\n\
                        [[caches]]\nurl = \"https://drop\"\n";
        let out = remove_cache_from_toml(existing, "andyl", "https://drop")
            .expect("removes")
            .expect("changed");
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert_eq!(cfg.caches.len(), 1);
        assert_eq!(cfg.caches[0].url, "https://keep");
        // Removing an absent URL is a no-op.
        assert!(remove_cache_from_toml(&out, "andyl", "https://drop")
            .expect("idempotent")
            .is_none());
    }

    #[test]
    fn remove_last_cache_drops_the_key() {
        let existing = "[registry]\nname = \"andyl\"\n\n[[caches]]\nurl = \"https://only\"\n";
        let out = remove_cache_from_toml(existing, "andyl", "https://only")
            .expect("removes")
            .expect("changed");
        assert!(!out.contains("caches"));
        let cfg: RegistryRootConfig = toml::from_str(&out).expect("valid");
        assert!(cfg.caches.is_empty());
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
