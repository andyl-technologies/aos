//! Serde models for the same-origin static snapshots the SPA consumes.
//!
//! These structs mirror, field-for-field, the JSON `apr web generate`
//! emits (see `aos_package::registry::webgen`): `web/config.json`,
//! `web/index.json`, and `web/packages/<name>.json`. Keeping the field
//! names identical is the data contract — the SPA reads exactly what the
//! generator wrote, with no transform layer in between.
//!
//! ```json
//! // web/config.json
//! { "name": "aos-core", "accent": "#7c4dbe", "hub_url": "https://hub…" }
//!
//! // web/index.json
//! {
//!   "name": "aos-core", "description": "…",
//!   "generator": "apr web generate", "generated_at": "2026-…Z",
//!   "packages": [ { "name": "curl", "latest_version": "8.5.0",
//!                   "description": "…", "license": "MIT" } ]
//! }
//!
//! // web/packages/curl.json
//! {
//!   "name": "curl", "description": "…", "homepage": "https://curl.se",
//!   "license": "MIT", "maintainer": "aos-team",
//!   "versions": [ { "version": "8.5.0", "platforms": [
//!     { "platform": "x86_64-linux", "store_path": "/…",
//!       "nar_hash": "sha256:…", "nar_size": 3145728,
//!       "closure_size": 52428800 } ] } ]
//! }
//! ```

use serde::Deserialize;

/// The `web/config.json` branding document.
///
/// Origin-only, unsigned content: it can never change what `apm` or Nix
/// accept, but the SPA treats it as same-origin-integrity-trusted for
/// branding and for the optional `hub_url` it dials.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Display name for the registry.
    pub name: String,
    /// Optional accent color (any CSS color token) for the SPA theme.
    #[serde(default)]
    pub accent: Option<String>,
    /// Optional hub base URL the SPA dials for search and other dynamic
    /// features. Absent means a fully standalone, same-origin surface.
    #[serde(default)]
    pub hub_url: Option<String>,
}

/// One package's newest version and summary, from `index.json`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IndexPackage {
    /// Package name.
    pub name: String,
    /// Newest published version.
    pub latest_version: String,
    /// One-line description.
    pub description: String,
    /// SPDX-ish license token.
    pub license: String,
}

/// The `web/index.json` registry snapshot.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IndexSnapshot {
    /// Registry display name.
    pub name: String,
    /// Registry description.
    #[serde(default)]
    pub description: String,
    /// The producer that generated this snapshot (`apr web generate` or the
    /// hub). Recorded so staleness and provenance are visible.
    #[serde(default)]
    pub generator: String,
    /// ISO 8601 generation timestamp.
    #[serde(default)]
    pub generated_at: String,
    /// Package summaries, in generator order.
    #[serde(default)]
    pub packages: Vec<IndexPackage>,
}

/// One platform artifact within a per-package snapshot.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PackagePlatform {
    /// Target platform (`x86_64-linux`, `aarch64-linux`).
    pub platform: String,
    /// Nix store path of the realized output.
    pub store_path: String,
    /// `sha256:…` NAR hash.
    #[serde(default)]
    pub nar_hash: String,
    /// NAR size in bytes.
    #[serde(default)]
    pub nar_size: u64,
    /// Whole-closure size in bytes.
    #[serde(default)]
    pub closure_size: u64,
}

/// One version (with its platforms) within a per-package snapshot.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PackageVersion {
    /// Version string.
    pub version: String,
    /// Per-platform artifacts, newest version first in the parent list.
    #[serde(default)]
    pub platforms: Vec<PackagePlatform>,
}

/// The `web/packages/<name>.json` per-package snapshot.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PackageSnapshot {
    /// Package name.
    pub name: String,
    /// Optional homepage URL declared by the package.
    #[serde(default)]
    pub homepage: Option<String>,
    /// One-line description.
    #[serde(default)]
    pub description: String,
    /// License token.
    #[serde(default)]
    pub license: String,
    /// Declared maintainer.
    #[serde(default)]
    pub maintainer: String,
    /// Versions newest-first, each with its platform set.
    #[serde(default)]
    pub versions: Vec<PackageVersion>,
}

/// Return a package homepage only when it is safe to render as a link.
///
/// A package-declared `homepage` is untrusted registry content. HTML-attribute
/// escaping (`& < > " '`) does not neutralize a dangerous URL *scheme*, so a
/// value like `javascript:alert(1)` would otherwise become a clickable,
/// script-executing `<a href>` on a CSP-less static frontend. This guard
/// mirrors the hub's server-rendered pages: only `http://` and `https://`
/// homepages yield an href; everything else returns [`None`] and the caller
/// renders the value as plain text instead.
///
/// # Examples
///
/// ```
/// use aos_registry_spa::model::homepage_href;
///
/// assert_eq!(
///     homepage_href(Some("https://curl.se")),
///     Some("https://curl.se".to_string())
/// );
/// assert_eq!(homepage_href(Some("javascript:alert(1)")), None);
/// assert_eq!(homepage_href(None), None);
/// ```
#[must_use]
pub fn homepage_href(homepage: Option<&str>) -> Option<String> {
    homepage
        .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn homepage_href_only_accepts_http_schemes() {
        assert_eq!(
            homepage_href(Some("https://curl.se")),
            Some("https://curl.se".to_string())
        );
        assert_eq!(
            homepage_href(Some("http://example.org")),
            Some("http://example.org".to_string())
        );
        // Dangerous and unknown schemes are rejected — rendered as text only.
        assert_eq!(homepage_href(Some("javascript:alert(1)")), None);
        assert_eq!(homepage_href(Some("data:text/html,<script>")), None);
        assert_eq!(homepage_href(Some("ftp://example.org")), None);
        assert_eq!(homepage_href(Some("")), None);
        assert_eq!(homepage_href(None), None);
    }

    #[test]
    fn config_parses_with_optional_fields_absent() {
        let cfg: Config = serde_json::from_str(r#"{ "name": "aos-core" }"#).unwrap();
        assert_eq!(cfg.name, "aos-core");
        assert!(cfg.accent.is_none());
        assert!(cfg.hub_url.is_none());
    }

    #[test]
    fn index_snapshot_parses_generator_shape() {
        let json = r#"{
            "name": "aos-core",
            "description": "The core AOS registry",
            "generator": "apr web generate",
            "generated_at": "2026-06-13T00:00:00Z",
            "packages": [
                { "name": "curl", "latest_version": "8.5.0",
                  "description": "URL transfers", "license": "MIT" }
            ]
        }"#;
        let index: IndexSnapshot = serde_json::from_str(json).unwrap();
        assert_eq!(index.name, "aos-core");
        assert_eq!(index.generator, "apr web generate");
        assert_eq!(index.packages.len(), 1);
        assert_eq!(index.packages[0].name, "curl");
        assert_eq!(index.packages[0].latest_version, "8.5.0");
    }

    #[test]
    fn package_snapshot_parses_versions_and_platforms() {
        let json = r#"{
            "name": "curl",
            "homepage": "https://curl.se",
            "description": "URL transfers",
            "license": "MIT",
            "maintainer": "aos-team",
            "versions": [
                { "version": "8.5.0", "platforms": [
                    { "platform": "x86_64-linux",
                      "store_path": "/var/lib/store/h7j-curl-8.5.0",
                      "nar_hash": "sha256:abc", "nar_size": 3145728,
                      "closure_size": 52428800 }
                ] }
            ]
        }"#;
        let pkg: PackageSnapshot = serde_json::from_str(json).unwrap();
        assert_eq!(pkg.name, "curl");
        assert_eq!(pkg.homepage.as_deref(), Some("https://curl.se"));
        assert_eq!(pkg.versions.len(), 1);
        assert_eq!(pkg.versions[0].platforms[0].platform, "x86_64-linux");
        assert_eq!(pkg.versions[0].platforms[0].closure_size, 52428800);
    }
}
