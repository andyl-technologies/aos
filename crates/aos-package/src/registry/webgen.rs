//! Static web-surface generation for a registry's own CDN bucket.
//!
//! Producer-side tooling that turns the committed registry tree
//! (`registry.toml` plus `packages/<x>/<name>.toml`) into the static,
//! no-JS web surface RFC-0004 calls the registry's *`web` surface*: a set
//! of content-bearing HTML pages and JSON snapshots a registry serves
//! directly from its own object store, with **zero hub in the serving
//! path**. The artifacts produced here are the *no-JS tier* (RFC-0004's
//! tier 3): real, content-bearing pages that the Leptos-CSR WASM SPA
//! (`aos-registry-spa`) progressively enhances when it is dropped in
//! alongside — the floor is always the deliverable.
//!
//! When [`WebConfig::spa_dist`] points at a built SPA dist (the output of
//! `trunk build --release` in `crates/aos-registry-spa`), the generator
//! also stages that dist's hash-named `web/app-<hash>_bg.wasm`,
//! `web/app-<hash>.js`, and `web/style-<hash>.css`, and injects a
//! same-origin `<script type="module">` loader plus stylesheet `<link>`
//! into every generated page so the CSR SPA mounts over the no-JS floor.
//! The SPA is built separately (Rust→wasm via `trunk`, not by this native
//! crate's build, to avoid a build-graph cycle); `apr web generate
//! --spa-dist <dir>` then ships it. The page bytes stay content-bearing
//! either way — curl and lynx always see real content.
//!
//! [`generate_web_surface`] writes the following layout under the output
//! directory, mirroring the upload classes in
//! [`crate::registry::static_upload`] (everything here is *mutable* — none
//! of it is hash-named yet):
//!
//! ```text
//! index.html                 registry home — packages table, channels,
//!                            trust note (self-contained inline CSS)
//! web/config.json            branding defaults (name, accent?, hub_url?)
//! web/index.json             registry meta + package summary snapshot
//! web/packages/<name>.json   per-package versions × platforms snapshot
//! browse/<name>.html         per-package static page (no-JS)
//! ```
//!
//! The JSON snapshots are stable data contracts the SPA reads. `index.json`
//! is shaped:
//!
//! ```json
//! {
//!   "name": "aos-core",
//!   "description": "The core AOS registry",
//!   "generator": "apr web generate",
//!   "generated_at": "2026-06-13T00:00:00Z",
//!   "packages": [
//!     { "name": "curl", "latest_version": "8.5.0",
//!       "description": "URL transfers", "license": "MIT" }
//!   ]
//! }
//! ```
//!
//! and `web/packages/<name>.json`:
//!
//! ```json
//! {
//!   "name": "curl",
//!   "description": "URL transfers",
//!   "homepage": "https://curl.se",
//!   "license": "MIT",
//!   "maintainer": "aos-team",
//!   "versions": [
//!     { "version": "8.5.0", "platforms": [
//!       { "platform": "x86_64-linux",
//!         "store_path": "/var/lib/store/h7j..-curl-8.5.0",
//!         "nar_hash": "sha256:..", "nar_size": 3145728,
//!         "closure_size": 52428800 }
//!     ] }
//!   ]
//! }
//! ```
//!
//! Every page is strictly first-party (RFC-0004's asset policy): inline
//! CSS, no external stylesheet, script, font, or analytics URL. All dynamic
//! text is HTML-escaped so a hostile package description cannot inject
//! markup. `config.json`'s `hub_url`, when set, is the *only* place an
//! absolute off-origin URL is recorded, and it is data the SPA reads — never
//! an asset reference baked into a page.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_cache::backend::{self, AuthOptions};
use aos_core::output::Printer;
use serde::Serialize;

use crate::registry::parse::parse_registry;
use crate::types::PackageMeta;

/// Platforms the generator snapshots when walking the committed registry.
///
/// The committed package TOML carries one artifact block per platform; the
/// web surface lists every platform a version was published for, so the
/// generator parses the registry once per platform and merges the results.
const SNAPSHOT_PLATFORMS: &[&str] = &["x86_64-linux", "aarch64-linux"];

/// Branding and wiring defaults for a generated web surface.
///
/// These values flow into `web/config.json` (consumed by the SPA at
/// runtime) and into the page chrome of the static HTML. They are unsigned,
/// origin-only content and never change what `apm` or Nix accept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebConfig {
    /// Display name for the registry, shown in page titles and headers.
    ///
    /// Defaults to the registry's `registry.toml` name when left empty by
    /// the caller; [`generate_web_surface`] fills it in.
    pub name: String,
    /// Optional accent color (any CSS color token) for the SPA theme.
    ///
    /// Recorded in `config.json` only; the no-JS pages use a neutral
    /// first-party palette regardless.
    pub accent: Option<String>,
    /// Optional hub base URL the SPA connects to for dynamic features
    /// (search, auth, publish status). Absent means a fully standalone,
    /// same-origin-only surface.
    pub hub_url: Option<String>,
    /// Optional path to a built SPA dist directory (the output of
    /// `trunk build --release` in `crates/aos-registry-spa`).
    ///
    /// When set, [`generate_web_surface`] copies the dist's hash-named
    /// `*_bg.wasm`, `*.js`, and `*.css` into `web/` (normalized to the
    /// RFC-0004 names `app-<hash>_bg.wasm`, `app-<hash>.js`,
    /// `style-<hash>.css`) and injects a same-origin `<script
    /// type="module">` loader and stylesheet `<link>` into every generated
    /// page, so the CSR SPA progressively enhances the no-JS floor. Absent,
    /// only the no-JS tier is emitted.
    pub spa_dist: Option<PathBuf>,
}

/// One package's newest version and summary, for `index.json`.
#[derive(Debug, Serialize)]
struct IndexPackage {
    name: String,
    latest_version: String,
    description: String,
    license: String,
}

/// The `index.json` registry snapshot.
#[derive(Debug, Serialize)]
struct IndexSnapshot {
    name: String,
    description: String,
    generator: &'static str,
    generated_at: String,
    packages: Vec<IndexPackage>,
}

/// The `web/config.json` branding document.
#[derive(Debug, Serialize)]
struct ConfigSnapshot {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    accent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hub_url: Option<String>,
}

/// One platform artifact within a per-package snapshot.
#[derive(Debug, Serialize)]
struct PackagePlatform {
    platform: String,
    store_path: String,
    nar_hash: String,
    nar_size: u64,
    closure_size: u64,
}

/// One version (with its platforms) within a per-package snapshot.
#[derive(Debug, Serialize)]
struct PackageVersion {
    version: String,
    platforms: Vec<PackagePlatform>,
}

/// The `web/packages/<name>.json` per-package snapshot.
#[derive(Debug, Serialize)]
struct PackageSnapshot {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    homepage: Option<String>,
    description: String,
    license: String,
    maintainer: String,
    versions: Vec<PackageVersion>,
}

/// The merged view of one package across every snapshot platform.
///
/// Keyed first by version (preserving the order versions first appear) and
/// then by platform, this is the intermediate the per-package JSON and the
/// `browse/<name>.html` page are both rendered from.
struct MergedPackage {
    /// Newest [`PackageMeta`] seen for this package (drives the summary).
    newest: PackageMeta,
    /// Version string -> (platform -> artifact metadata), insertion-ordered.
    versions: Vec<(String, BTreeMap<String, PackageMeta>)>,
}

/// Generate the static no-JS web surface for a committed registry.
///
/// Reads `registry_dir`'s `registry.toml` for branding fallbacks and walks
/// `packages/` (via [`parse_registry`] over each snapshot platform) to
/// collect every published version and platform, then writes `index.html`,
/// `web/config.json`, `web/index.json`, one `web/packages/<name>.json` per
/// package, and one `browse/<name>.html` per package into `output_dir`.
///
/// `config` supplies branding defaults; an empty [`WebConfig::name`] is
/// filled from `registry.toml`. The returned vector lists every file
/// written, in a deterministic order (`index.html`, the two top-level JSON
/// docs, then per-package JSON and HTML sorted by package name), so callers
/// can upload exactly the generated set.
///
/// Channels are summarized only when the git surface makes them trivially
/// available; this generator runs over the committed working tree without
/// surface access, so `index.json` omits channels — they are added when the
/// hub (or a surface-aware caller) regenerates the snapshot.
///
/// # Errors
///
/// Returns an error if `registry.toml` or a package TOML file cannot be read
/// or parsed, or if any output file or directory cannot be written.
pub fn generate_web_surface(
    registry_dir: &Path,
    output_dir: &Path,
    config: WebConfig,
) -> Result<Vec<PathBuf>> {
    let (registry_name, registry_description) = read_registry_meta(registry_dir)?;
    let packages = collect_packages(registry_dir)?;

    let mut config = config;
    if config.name.is_empty() {
        config.name = registry_name.clone();
    }

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating {}", output_dir.display()))?;
    std::fs::create_dir_all(output_dir.join("web").join("packages")).with_context(|| {
        format!(
            "creating {}",
            output_dir.join("web").join("packages").display()
        )
    })?;
    std::fs::create_dir_all(output_dir.join("browse"))
        .with_context(|| format!("creating {}", output_dir.join("browse").display()))?;

    let mut written = Vec::new();

    // Stage the Leptos CSR SPA dist (if provided) into web/ and resolve the
    // same-origin asset names the page loaders reference. Absent, every
    // page stays the strictly first-party no-JS floor.
    let spa = match &config.spa_dist {
        Some(dist) => Some(stage_spa_dist(dist, output_dir, &mut written)?),
        None => None,
    };

    // index.html — the content-bearing no-JS home page, progressively
    // enhanced by the SPA loader when `spa` is present.
    let index_html = render_index_html(
        &config.name,
        registry_description.as_deref(),
        &packages,
        spa.as_ref(),
    );
    written.push(write_file(output_dir, "index.html", &index_html)?);

    // web/config.json — branding defaults.
    let config_json = to_json_pretty(&ConfigSnapshot {
        name: config.name.clone(),
        accent: config.accent.clone(),
        hub_url: config.hub_url.clone(),
    })?;
    written.push(write_file(output_dir, "web/config.json", &config_json)?);

    // web/index.json — registry snapshot.
    let index_snapshot = IndexSnapshot {
        name: config.name.clone(),
        description: registry_description.clone().unwrap_or_default(),
        generator: GENERATOR,
        generated_at: iso8601_now(),
        packages: packages
            .iter()
            .map(|pkg| IndexPackage {
                name: pkg.newest.name.clone(),
                latest_version: pkg.newest.version.clone(),
                description: pkg.newest.description.clone(),
                license: pkg.newest.license.clone(),
            })
            .collect(),
    };
    written.push(write_file(
        output_dir,
        "web/index.json",
        &to_json_pretty(&index_snapshot)?,
    )?);

    // Per-package JSON snapshots and static browse pages.
    for pkg in &packages {
        let snapshot = package_snapshot(pkg);
        let rel = format!("web/packages/{}.json", pkg.newest.name);
        written.push(write_file(output_dir, &rel, &to_json_pretty(&snapshot)?)?);

        let html = render_browse_html(&config.name, pkg, spa.as_ref());
        let rel = format!("browse/{}.html", pkg.newest.name);
        written.push(write_file(output_dir, &rel, &html)?);
    }

    Ok(written)
}

/// `Cache-Control` for the mutable web-surface files (every file this
/// generator emits — none are hash-named yet).
const WEB_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

/// Upload a generated web surface directory to one destination.
///
/// Walks `output_dir` recursively and pushes every file through the cache
/// backend selected by `upload_url`'s scheme (`file://`, S3-style object
/// stores, …) with the per-file `Content-Type` the web surface expects and
/// the mutable `Cache-Control` (all generated files are pointers today, not
/// hash-named immutable assets — those arrive with the SPA dist).
///
/// # Errors
///
/// Returns an error if the backend cannot be constructed for `upload_url`,
/// a local file cannot be read, or any upload request fails.
pub async fn upload_web_surface(
    output_dir: &Path,
    upload_url: &str,
    auth: &AuthOptions,
    printer: &Printer,
) -> Result<()> {
    let backend = backend::from_url(upload_url, auth).await?;
    let mut files = Vec::new();
    collect_web_files(output_dir, output_dir, &mut files)?;
    files.sort();

    for relative_path in &files {
        let source = output_dir.join(relative_path);
        backend
            .put_static_file(
                relative_path,
                &source,
                Some(web_content_type(relative_path)),
                Some(WEB_CACHE_CONTROL),
                None,
                None,
            )
            .await
            .with_context(|| format!("uploading {relative_path}"))?;
    }

    printer.success(&format!("Uploaded web surface files to {upload_url}"));
    Ok(())
}

/// Upload a generated web surface to every destination URL.
///
/// Destinations are attempted independently; a failure on one does not stop
/// uploads to the others.
///
/// # Errors
///
/// Returns an error aggregating all per-destination failures when any
/// upload fails.
pub async fn upload_web_surface_to_all(
    output_dir: &Path,
    upload_urls: &[String],
    auth: &AuthOptions,
    printer: &Printer,
) -> Result<()> {
    let mut failures = Vec::new();
    for upload_url in upload_urls {
        if let Err(err) = upload_web_surface(output_dir, upload_url, auth, printer).await {
            failures.push(format!("{upload_url}: {err:#}"));
        }
    }
    if !failures.is_empty() {
        bail!(
            "web surface upload failed for {}/{} destination(s):\n{}",
            failures.len(),
            upload_urls.len(),
            failures.join("\n")
        );
    }
    Ok(())
}

/// Recursively collect every file under `dir` as a `/`-joined path relative
/// to `root`.
fn collect_web_files(root: &Path, dir: &Path, files: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_web_files(root, &path, files)?;
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
            let relative = relative
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("path is not UTF-8: {}", path.display()))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            files.push(relative);
        }
    }
    Ok(())
}

/// Pick a `Content-Type` for a generated web-surface file by extension.
fn web_content_type(relative_path: &str) -> &'static str {
    if relative_path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if relative_path.ends_with(".json") {
        "application/json"
    } else if relative_path.ends_with(".css") {
        "text/css"
    } else if relative_path.ends_with(".js") {
        "text/javascript"
    } else if relative_path.ends_with(".wasm") {
        "application/wasm"
    } else {
        "application/octet-stream"
    }
}

/// The `generator` field stamped into `index.json`.
const GENERATOR: &str = "apr web generate";

/// Read the registry's display name and description from `registry.toml`.
///
/// Falls back to the directory's basename as the name and `None` as the
/// description when the file is absent.
fn read_registry_meta(registry_dir: &Path) -> Result<(String, Option<String>)> {
    let path = registry_dir.join("registry.toml");
    if !path.exists() {
        let name = registry_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("registry")
            .to_string();
        return Ok((name, None));
    }
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let value: toml::Value =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    let registry = value.get("registry");
    let name = registry
        .and_then(|registry| registry.get("name"))
        .and_then(toml::Value::as_str)
        .unwrap_or("registry")
        .to_string();
    let description = registry
        .and_then(|registry| registry.get("description"))
        .and_then(toml::Value::as_str)
        .filter(|description| !description.is_empty())
        .map(str::to_string);
    Ok((name, description))
}

/// Walk the committed registry over every snapshot platform and merge the
/// results into one [`MergedPackage`] per package, sorted by package name.
fn collect_packages(registry_dir: &Path) -> Result<Vec<MergedPackage>> {
    // name -> (version -> (platform -> meta)), preserving version order.
    let mut merged: BTreeMap<String, MergedPackage> = BTreeMap::new();

    for platform in SNAPSHOT_PLATFORMS {
        let (_, hash_index) = parse_registry(registry_dir, platform)
            .with_context(|| format!("parsing registry for platform {platform}"))?;
        // The hash index carries every version (not just the newest), which
        // is exactly the set the web surface lists.
        for meta in hash_index.into_values() {
            insert_meta(&mut merged, meta);
        }
    }

    Ok(merged.into_values().collect())
}

/// Fold one [`PackageMeta`] into the merged map, tracking the newest version
/// and the per-version platform set.
fn insert_meta(merged: &mut BTreeMap<String, MergedPackage>, meta: PackageMeta) {
    let entry = merged
        .entry(meta.name.clone())
        .or_insert_with(|| MergedPackage {
            newest: meta.clone(),
            versions: Vec::new(),
        });

    if is_newer(&meta.version, &entry.newest.version) {
        entry.newest = meta.clone();
    }

    if let Some((_, platforms)) = entry
        .versions
        .iter_mut()
        .find(|(version, _)| version == &meta.version)
    {
        platforms.entry(meta.platform.clone()).or_insert(meta);
    } else {
        let mut platforms = BTreeMap::new();
        let version = meta.version.clone();
        platforms.insert(meta.platform.clone(), meta);
        entry.versions.push((version, platforms));
    }
}

/// Order two registry version strings: semver pairs compare semantically, a
/// semver version outranks a non-semver one, otherwise lexicographic.
///
/// Mirrors the resolver's ordering so the "latest" shown on the web surface
/// matches what `apm` would install.
fn is_newer(candidate: &str, current: &str) -> bool {
    use std::cmp::Ordering;
    let ordering = match (
        semver::Version::parse(candidate),
        semver::Version::parse(current),
    ) {
        (Ok(candidate), Ok(current)) => candidate.cmp(&current),
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Ok(_)) => Ordering::Less,
        (Err(_), Err(_)) => candidate.cmp(current),
    };
    ordering == Ordering::Greater
}

/// Build the serializable per-package snapshot from a merged package, with
/// versions ordered newest-first.
fn package_snapshot(pkg: &MergedPackage) -> PackageSnapshot {
    PackageSnapshot {
        name: pkg.newest.name.clone(),
        homepage: pkg.newest.homepage.clone(),
        description: pkg.newest.description.clone(),
        license: pkg.newest.license.clone(),
        maintainer: pkg.newest.maintainer.clone(),
        versions: sorted_versions(pkg)
            .into_iter()
            .map(|(version, platforms)| PackageVersion {
                version: version.clone(),
                platforms: platforms
                    .values()
                    .map(|meta| PackagePlatform {
                        platform: meta.platform.clone(),
                        store_path: meta.store_path.clone(),
                        nar_hash: meta.nar_hash.clone(),
                        nar_size: meta.nar_size,
                        closure_size: meta.closure_size,
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// Return a package's versions newest-first, each paired with its platform
/// map.
fn sorted_versions(pkg: &MergedPackage) -> Vec<&(String, BTreeMap<String, PackageMeta>)> {
    let mut versions: Vec<&(String, BTreeMap<String, PackageMeta>)> = pkg.versions.iter().collect();
    versions.sort_by(|a, b| {
        if is_newer(&a.0, &b.0) {
            std::cmp::Ordering::Less
        } else if is_newer(&b.0, &a.0) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
    versions
}

// ---------------------------------------------------------------------------
// HTML rendering
// ---------------------------------------------------------------------------

/// Self-contained, first-party page chrome shared by every generated page.
///
/// The release-engineering-paper aesthetic loosely: a monospace body,
/// hairline rules, and plain tables — no external stylesheet, script, or
/// font.
const PAGE_STYLE: &str = "\
:root{color-scheme:light dark}\
body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;\
max-width:60rem;margin:2rem auto;padding:0 1rem;line-height:1.5}\
h1,h2{font-weight:600;border-bottom:1px solid currentColor;padding-bottom:.25rem}\
table{border-collapse:collapse;width:100%;margin:1rem 0}\
th,td{text-align:left;padding:.3rem .6rem;border-bottom:1px solid #8884}\
th{font-weight:600}\
code{white-space:pre-wrap;word-break:break-all}\
a{color:inherit}\
.note{font-size:.85rem;opacity:.8;margin-top:2rem;border-top:1px solid #8884;padding-top:.5rem}";

/// Render the content-bearing `index.html` home page.
fn render_index_html(
    name: &str,
    description: Option<&str>,
    packages: &[MergedPackage],
    spa: Option<&SpaAssets>,
) -> String {
    let mut body = String::new();
    body.push_str(&format!("<h1>{}</h1>\n", escape(name)));
    if let Some(description) = description {
        body.push_str(&format!("<p>{}</p>\n", escape(description)));
    }

    body.push_str(&format!("<h2>Packages ({})</h2>\n", packages.len()));
    if packages.is_empty() {
        body.push_str("<p>No packages published yet.</p>\n");
    } else {
        body.push_str(
            "<table>\n<tr><th>Package</th><th>Version</th><th>License</th>\
             <th>Description</th></tr>\n",
        );
        for pkg in packages {
            body.push_str(&format!(
                "<tr><td><a href=\"browse/{name}.html\">{name}</a></td>\
                 <td>{version}</td><td>{license}</td><td>{description}</td></tr>\n",
                name = escape(&pkg.newest.name),
                version = escape(&pkg.newest.version),
                license = escape(&pkg.newest.license),
                description = escape(&pkg.newest.description),
            ));
        }
        body.push_str("</table>\n");
    }

    body.push_str(
        "<p class=\"note\">This registry is verified client-side: \
         signatures are checked against the committed roster, never trusted \
         from this page. This static page is the no-JS floor; when the web \
         app is present it progressively enhances this same URL.</p>\n",
    );

    page(&format!("{name} — registry"), &body, spa)
}

/// Render the per-package `browse/<name>.html` static page.
fn render_browse_html(registry_name: &str, pkg: &MergedPackage, spa: Option<&SpaAssets>) -> String {
    let name = &pkg.newest.name;
    let mut body = String::new();
    body.push_str(&format!(
        "<p><a href=\"../index.html\">&larr; {}</a></p>\n",
        escape(registry_name)
    ));
    body.push_str(&format!("<h1>{}</h1>\n", escape(name)));
    body.push_str(&format!("<p>{}</p>\n", escape(&pkg.newest.description)));

    body.push_str("<table>\n");
    if let Some(homepage) = &pkg.newest.homepage {
        // Homepage is a package-declared URL, not a page asset. Only http(s)
        // homepages become links; anything else (`javascript:`, `data:`, …)
        // renders as escaped text, since HTML-attribute escaping does not
        // neutralize a dangerous URL scheme.
        let cell = if homepage.starts_with("http://") || homepage.starts_with("https://") {
            format!("<a href=\"{href}\">{href}</a>", href = escape(homepage))
        } else {
            escape(homepage)
        };
        body.push_str(&format!("<tr><th>Homepage</th><td>{cell}</td></tr>\n"));
    }
    body.push_str(&format!(
        "<tr><th>License</th><td>{}</td></tr>\n",
        escape(&pkg.newest.license)
    ));
    body.push_str(&format!(
        "<tr><th>Maintainer</th><td>{}</td></tr>\n",
        escape(&pkg.newest.maintainer)
    ));
    body.push_str("</table>\n");

    body.push_str("<h2>Versions</h2>\n");
    body.push_str(
        "<table>\n<tr><th>Version</th><th>Platform</th><th>NAR size</th>\
         <th>Closure size</th><th>Store path</th><th>narinfo</th></tr>\n",
    );
    for (version, platforms) in sorted_versions(pkg) {
        for meta in platforms.values() {
            let hash = store_path_hash(&meta.store_path);
            body.push_str(&format!(
                "<tr><td>{version}</td><td>{platform}</td><td>{nar_size}</td>\
                 <td>{closure_size}</td><td><code>{store_path}</code></td>\
                 <td><a href=\"/{hash}.narinfo\">{hash}.narinfo</a></td></tr>\n",
                version = escape(version),
                platform = escape(&meta.platform),
                nar_size = meta.nar_size,
                closure_size = meta.closure_size,
                store_path = escape(&meta.store_path),
                hash = escape(hash),
            ));
        }
    }
    body.push_str("</table>\n");

    body.push_str(
        "<p class=\"note\">narinfo links resolve against this registry's \
         Nix binary cache surface on the same origin.</p>\n",
    );

    page(&format!("{} — {registry_name}", name), &body, spa)
}

/// Wrap rendered `body` HTML in the shared, first-party page shell.
///
/// When `spa` is present, the page's `<head>` additionally carries the
/// SPA's stylesheet `<link>` and a `<script type="module">` loader that
/// boots the WASM app from same-origin `web/` assets. The body content is
/// emitted unconditionally — the SPA mounts over the no-JS floor, never
/// replaces it as the served bytes — so curl, lynx, and a scripting-blocked
/// browser still see real content.
fn page(title: &str, body: &str, spa: Option<&SpaAssets>) -> String {
    let head_extra = spa.map(SpaAssets::head_markup).unwrap_or_default();
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{title}</title>\n<style>{PAGE_STYLE}</style>\n{head_extra}</head>\n<body>\n{body}</body>\n</html>\n",
        title = escape(title),
    )
}

/// The same-origin asset names of a staged SPA dist, referenced by the page
/// loaders.
///
/// All three are first-party files under the registry's own `web/` prefix —
/// never an off-origin URL — so they satisfy the strict asset policy and a
/// `default-src 'self'` CSP (the hub additionally allows
/// `'wasm-unsafe-eval'` on these paths to run the WASM; see
/// `aos_hub::compat`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpaAssets {
    /// The `web/app-<hash>.js` wasm-bindgen glue path (relative to root).
    js: String,
    /// The `web/app-<hash>_bg.wasm` module path (relative to root).
    wasm: String,
    /// The `web/style-<hash>.css` stylesheet path (relative to root).
    css: String,
}

impl SpaAssets {
    /// The `<head>` markup that loads the SPA: a same-origin stylesheet link
    /// and an ES-module loader that initializes the WASM and mounts the app.
    ///
    /// The module script is first-party (same-origin `web/`), so it needs no
    /// nonce under `default-src 'self'`; the hub permits `'wasm-unsafe-eval'`
    /// on the web-surface paths so the module's `WebAssembly` instantiation
    /// runs on Chromium.
    fn head_markup(&self) -> String {
        format!(
            "<link rel=\"stylesheet\" href=\"/{css}\">\n\
             <script type=\"module\">\n\
             import init from '/{js}';\n\
             init({{ module_or_path: '/{wasm}' }});\n\
             </script>\n",
            css = self.css,
            js = self.js,
            wasm = self.wasm,
        )
    }
}

/// Copy a built SPA dist into `output_dir/web/`, normalizing the filenames
/// to the RFC-0004 artifact shape and returning the same-origin paths the
/// page loaders reference.
///
/// `trunk build --release` emits hash-named `<bin>-<hash>.js`,
/// `<bin>-<hash>_bg.wasm`, and `<name>-<hash>.css` under its `dist/`. This
/// stages exactly those three into `web/app-<hash>.js`,
/// `web/app-<hash>_bg.wasm`, and `web/style-<hash>.css` (hash preserved so
/// they keep their immutable cache class), pushing each onto `written`.
///
/// # Errors
///
/// Returns an error when `dist` is unreadable or does not contain exactly
/// one `_bg.wasm`, one non-snippet `.js`, and one `.css` file.
fn stage_spa_dist(dist: &Path, output_dir: &Path, written: &mut Vec<PathBuf>) -> Result<SpaAssets> {
    let mut wasm_src = None;
    let mut js_src = None;
    let mut css_src = None;

    for entry in
        std::fs::read_dir(dist).with_context(|| format!("reading SPA dist {}", dist.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with("_bg.wasm") {
            wasm_src = Some((entry.path(), name));
        } else if name.ends_with(".css") {
            css_src = Some((entry.path(), name));
        } else if name.ends_with(".js") && !name.ends_with("snippets.js") {
            // The single wasm-bindgen glue module (Trunk emits exactly one
            // top-level `.js` alongside the `_bg.wasm`).
            js_src = Some((entry.path(), name));
        }
    }

    let (wasm_path, wasm_name) =
        wasm_src.context("SPA dist has no *_bg.wasm (did `trunk build` run?)")?;
    let (js_path, _) = js_src.context("SPA dist has no wasm-bindgen *.js glue")?;
    let (css_path, css_name) = css_src.context("SPA dist has no *.css stylesheet")?;

    // Reuse the wasm hash for the js name so the pair stays grouped, and the
    // css hash for the stylesheet. Hash extraction is best-effort: the names
    // are immutable regardless, so any unparsed name falls back to the
    // dist filename.
    let hash = wasm_name
        .strip_suffix("_bg.wasm")
        .and_then(|stem| stem.rsplit('-').next())
        .unwrap_or("spa");
    let css_hash = css_name
        .strip_suffix(".css")
        .and_then(|stem| stem.rsplit('-').next())
        .unwrap_or(hash);

    let wasm_rel = format!("web/app-{hash}_bg.wasm");
    let js_rel = format!("web/app-{hash}.js");
    let css_rel = format!("web/style-{css_hash}.css");

    copy_into(&wasm_path, output_dir, &wasm_rel, written)?;
    copy_into(&js_path, output_dir, &js_rel, written)?;
    copy_into(&css_path, output_dir, &css_rel, written)?;

    Ok(SpaAssets {
        js: js_rel,
        wasm: wasm_rel,
        css: css_rel,
    })
}

/// Copy one source file to `relative_path` under `output_dir`, recording it
/// in `written`.
fn copy_into(
    source: &Path,
    output_dir: &Path,
    relative_path: &str,
    written: &mut Vec<PathBuf>,
) -> Result<()> {
    let dest = output_dir.join(relative_path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::copy(source, &dest)
        .with_context(|| format!("copying {} to {}", source.display(), dest.display()))?;
    written.push(dest);
    Ok(())
}

/// Extract the hash component from a store path for narinfo permalinks.
fn store_path_hash(store_path: &str) -> &str {
    crate::registry::parse::store_path_hash(store_path)
}

/// HTML-escape dynamic text so package-controlled strings cannot inject
/// markup into a generated page.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// IO + serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a value to pretty JSON with a trailing newline.
fn to_json_pretty<T: Serialize>(value: &T) -> Result<String> {
    let mut json = serde_json::to_string_pretty(value).context("serializing JSON snapshot")?;
    json.push('\n');
    Ok(json)
}

/// Write `content` to `relative_path` under `output_dir`, returning the
/// absolute path written.
fn write_file(output_dir: &Path, relative_path: &str, content: &str) -> Result<PathBuf> {
    let path = output_dir.join(relative_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Render the current time as an RFC 3339 / ISO 8601 UTC timestamp.
fn iso8601_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let secs_per_day: i64 = 86400;
    let days = secs.div_euclid(secs_per_day);
    let day_secs = secs.rem_euclid(secs_per_day) as u32;

    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since the Unix epoch to a Gregorian `(year, month, day)`
/// using Howard Hinnant's civil-from-days algorithm.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use tempfile::TempDir;

    use crate::registry::parse::{CURL_TOML, MULTI_VERSION_TOML, ZLIB_TOML};

    /// Build a registry fixture directory: a `registry.toml` plus the given
    /// `packages/<first-letter>/<name>.toml` files.
    fn make_registry(meta: &str, packages: &[(&str, &str)]) -> TempDir {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("registry.toml"), meta).unwrap();
        for (name, content) in packages {
            let dir = tmp.path().join("packages").join(&name[..1]);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{name}.toml")), content).unwrap();
        }
        tmp
    }

    const REGISTRY_META: &str =
        "[registry]\nname = \"aos-core\"\ndescription = \"The core AOS registry\"\n";

    fn read(out: &Path, rel: &str) -> String {
        std::fs::read_to_string(out.join(rel)).unwrap()
    }

    #[test]
    fn generates_full_surface_with_expected_files() {
        let reg = make_registry(REGISTRY_META, &[("curl", CURL_TOML), ("zlib", ZLIB_TOML)]);
        let out = TempDir::new().unwrap();

        let written = generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        // Every promised file exists and is in the returned set.
        for rel in [
            "index.html",
            "web/config.json",
            "web/index.json",
            "web/packages/curl.json",
            "web/packages/zlib.json",
            "browse/curl.html",
            "browse/zlib.html",
        ] {
            assert!(out.path().join(rel).is_file(), "missing {rel}");
            assert!(
                written.iter().any(|p| p.ends_with(rel)),
                "{rel} not returned"
            );
        }
    }

    #[test]
    fn index_json_lists_packages_with_latest_version() {
        let reg = make_registry(REGISTRY_META, &[("curl", CURL_TOML)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let index: Value = serde_json::from_str(&read(out.path(), "web/index.json")).unwrap();
        assert_eq!(index["name"], "aos-core");
        assert_eq!(index["description"], "The core AOS registry");
        assert_eq!(index["generator"], "apr web generate");
        let pkgs = index["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0]["name"], "curl");
        assert_eq!(pkgs[0]["latest_version"], "8.5.0");
        assert_eq!(pkgs[0]["license"], "MIT");
    }

    #[test]
    fn package_json_has_versions_and_platforms() {
        let reg = make_registry(REGISTRY_META, &[("curl", CURL_TOML)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let pkg: Value = serde_json::from_str(&read(out.path(), "web/packages/curl.json")).unwrap();
        assert_eq!(pkg["name"], "curl");
        assert_eq!(pkg["homepage"], "https://curl.se");
        let versions = pkg["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["version"], "8.5.0");
        // CURL_TOML carries both x86_64-linux and aarch64-linux blocks.
        let platforms = versions[0]["platforms"].as_array().unwrap();
        let names: Vec<&str> = platforms
            .iter()
            .map(|p| p["platform"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"x86_64-linux"));
        assert!(names.contains(&"aarch64-linux"));
    }

    #[test]
    fn package_json_orders_versions_newest_first() {
        let reg = make_registry(REGISTRY_META, &[("tool", MULTI_VERSION_TOML)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let pkg: Value = serde_json::from_str(&read(out.path(), "web/packages/tool.json")).unwrap();
        let versions = pkg["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0]["version"], "2.0.0");
        assert_eq!(versions[1]["version"], "1.0.0");

        let index: Value = serde_json::from_str(&read(out.path(), "web/index.json")).unwrap();
        assert_eq!(index["packages"][0]["latest_version"], "2.0.0");
    }

    #[test]
    fn index_html_is_content_bearing_and_first_party() {
        let reg = make_registry(REGISTRY_META, &[("curl", CURL_TOML)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let html = read(out.path(), "index.html");
        assert!(html.contains("aos-core"));
        assert!(html.contains("curl"));
        assert!(html.contains("browse/curl.html"));
        // No external asset references: every http(s) URL would be off-origin.
        assert!(
            !html.contains("http://") && !html.contains("https://"),
            "index.html must not reference any external URL"
        );
        // No external script/stylesheet tags.
        assert!(!html.contains("<script"));
        assert!(!html.contains("<link"));
    }

    #[test]
    fn browse_html_has_platform_table_and_narinfo_links() {
        let reg = make_registry(REGISTRY_META, &[("curl", CURL_TOML)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let html = read(out.path(), "browse/curl.html");
        assert!(html.contains("x86_64-linux"));
        assert!(html.contains("aarch64-linux"));
        assert!(html.contains("MIT"));
        // narinfo permalink uses the store-path hash.
        assert!(html.contains("/h7j3k8l2m9n4.narinfo"));
        // The package homepage is the only external URL allowed (declared
        // data, rendered as an escaped link).
        assert!(html.contains("https://curl.se"));
    }

    #[test]
    fn browse_homepage_requires_http_scheme() {
        // A `javascript:` homepage must never become a clickable link —
        // HTML-attribute escaping does not neutralize the scheme.
        let evil = r#"
[package]
name = "evil"
description = "no markup here"
license = "MIT"
maintainer = "aos-team"
homepage = "javascript:alert(document.cookie)"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/evilhash00001-evil-1.0.0"
nar_hash = "sha256:abc"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#;
        let reg = make_registry(REGISTRY_META, &[("evil", evil)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let html = read(out.path(), "browse/evil.html");
        // Rendered as escaped plain text, not inside an href attribute.
        assert!(
            !html.contains("href=\"javascript:"),
            "javascript: homepage must not become a link: {html}"
        );
        assert!(
            html.contains("javascript:alert(document.cookie)"),
            "still shown as text: {html}"
        );

        // A normal https homepage IS rendered as a link.
        let good = r#"
[package]
name = "good"
description = "safe"
license = "MIT"
maintainer = "aos-team"
homepage = "https://curl.se"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/goodhash00001-good-1.0.0"
nar_hash = "sha256:abc"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#;
        let reg = make_registry(REGISTRY_META, &[("good", good)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let html = read(out.path(), "browse/good.html");
        assert!(
            html.contains("<a href=\"https://curl.se\">https://curl.se</a>"),
            "https homepage must be a link: {html}"
        );
    }

    #[test]
    fn package_description_is_html_escaped() {
        let xss = r#"
[package]
name = "evil"
description = "<script>alert('xss')</script> & <b>bold</b>"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/evilhash00001-evil-1.0.0"
nar_hash = "sha256:abc"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
"#;
        let reg = make_registry(REGISTRY_META, &[("evil", xss)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let index_html = read(out.path(), "index.html");
        assert!(!index_html.contains("<script>alert"));
        assert!(index_html.contains("&lt;script&gt;alert"));
        assert!(index_html.contains("&amp;"));

        let browse_html = read(out.path(), "browse/evil.html");
        assert!(!browse_html.contains("<script>alert"));
        assert!(browse_html.contains("&lt;script&gt;"));

        // The JSON snapshot carries the raw text (JSON has no markup hazard).
        let pkg: Value = serde_json::from_str(&read(out.path(), "web/packages/evil.json")).unwrap();
        assert_eq!(
            pkg["description"],
            "<script>alert('xss')</script> & <b>bold</b>"
        );
    }

    #[test]
    fn config_json_carries_branding_defaults() {
        let reg = make_registry(REGISTRY_META, &[]);
        let out = TempDir::new().unwrap();
        let config = WebConfig {
            name: "Acme Registry".to_string(),
            accent: Some("#3366ff".to_string()),
            hub_url: Some("https://hub.example.com".to_string()),
            spa_dist: None,
        };
        generate_web_surface(reg.path(), out.path(), config).unwrap();

        let cfg: Value = serde_json::from_str(&read(out.path(), "web/config.json")).unwrap();
        assert_eq!(cfg["name"], "Acme Registry");
        assert_eq!(cfg["accent"], "#3366ff");
        assert_eq!(cfg["hub_url"], "https://hub.example.com");
    }

    #[test]
    fn config_name_defaults_to_registry_name() {
        let reg = make_registry(REGISTRY_META, &[]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let cfg: Value = serde_json::from_str(&read(out.path(), "web/config.json")).unwrap();
        assert_eq!(cfg["name"], "aos-core");
        // Optional fields are omitted when unset.
        assert!(cfg.get("accent").is_none());
        assert!(cfg.get("hub_url").is_none());
    }

    #[test]
    fn empty_registry_still_generates_valid_surface() {
        let reg = make_registry(REGISTRY_META, &[]);
        let out = TempDir::new().unwrap();
        let written = generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        // index.html, config.json, index.json — three files, no packages.
        assert_eq!(written.len(), 3);
        let index: Value = serde_json::from_str(&read(out.path(), "web/index.json")).unwrap();
        assert!(index["packages"].as_array().unwrap().is_empty());
        assert!(read(out.path(), "index.html").contains("No packages published yet"));
    }

    #[tokio::test]
    async fn upload_web_surface_writes_filesystem_destination() {
        let reg = make_registry(REGISTRY_META, &[("curl", CURL_TOML)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();

        let dest = TempDir::new().unwrap();
        let printer = Printer::new(0, true, false);
        upload_web_surface_to_all(
            out.path(),
            &[format!("file://{}", dest.path().display())],
            &AuthOptions::default(),
            &printer,
        )
        .await
        .unwrap();

        for rel in [
            "index.html",
            "web/config.json",
            "web/index.json",
            "web/packages/curl.json",
            "browse/curl.html",
        ] {
            assert!(dest.path().join(rel).is_file(), "missing uploaded {rel}");
        }
        assert_eq!(
            read(out.path(), "web/index.json"),
            read(dest.path(), "web/index.json"),
        );
    }

    #[test]
    fn spa_dist_is_staged_and_pages_load_it() {
        let reg = make_registry(REGISTRY_META, &[("curl", CURL_TOML)]);
        let out = TempDir::new().unwrap();

        // A fake `trunk build` dist: the three hash-named artifacts.
        let dist = TempDir::new().unwrap();
        std::fs::write(
            dist.path().join("aos-registry-spa-deadbeef_bg.wasm"),
            b"\0asm",
        )
        .unwrap();
        std::fs::write(
            dist.path().join("aos-registry-spa-deadbeef.js"),
            "export default 1;",
        )
        .unwrap();
        std::fs::write(dist.path().join("app-cafef00d.css"), "body{}").unwrap();

        let config = WebConfig {
            spa_dist: Some(dist.path().to_path_buf()),
            ..WebConfig::default()
        };
        let written = generate_web_surface(reg.path(), out.path(), config).unwrap();

        // The three assets are staged into web/ with normalized names.
        for rel in [
            "web/app-deadbeef_bg.wasm",
            "web/app-deadbeef.js",
            "web/style-cafef00d.css",
        ] {
            assert!(out.path().join(rel).is_file(), "missing staged {rel}");
            assert!(
                written.iter().any(|p| p.ends_with(rel)),
                "{rel} not returned"
            );
        }

        // index.html still carries real content AND now loads the SPA from
        // same-origin web/ assets (no off-origin URL).
        let index = read(out.path(), "index.html");
        assert!(index.contains("curl"), "no-JS content preserved");
        assert!(index.contains("<script type=\"module\">"));
        assert!(index.contains("/web/app-deadbeef.js"));
        assert!(index.contains("/web/app-deadbeef_bg.wasm"));
        assert!(index.contains("/web/style-cafef00d.css"));
        // First-party only: the loader references no off-origin URL.
        assert!(!index.contains("http://") && !index.contains("https://"));

        // Browse pages get the loader too.
        let browse = read(out.path(), "browse/curl.html");
        assert!(browse.contains("/web/app-deadbeef.js"));
        assert!(browse.contains("curl"));
    }

    #[test]
    fn no_spa_dist_keeps_pure_no_js_floor() {
        let reg = make_registry(REGISTRY_META, &[("curl", CURL_TOML)]);
        let out = TempDir::new().unwrap();
        generate_web_surface(reg.path(), out.path(), WebConfig::default()).unwrap();
        let index = read(out.path(), "index.html");
        // No SPA loader and no stylesheet link when no dist is provided.
        assert!(!index.contains("<script"));
        assert!(!index.contains("<link"));
    }

    #[test]
    fn web_content_type_maps_extensions() {
        assert_eq!(web_content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(web_content_type("web/index.json"), "application/json");
        assert_eq!(web_content_type("web/style.css"), "text/css");
    }

    #[test]
    fn missing_registry_toml_falls_back_to_dir_name() {
        let tmp = TempDir::new().unwrap();
        let reg = tmp.path().join("my-registry");
        std::fs::create_dir_all(reg.join("packages")).unwrap();
        let out = TempDir::new().unwrap();

        generate_web_surface(&reg, out.path(), WebConfig::default()).unwrap();
        let cfg: Value = serde_json::from_str(&read(out.path(), "web/config.json")).unwrap();
        assert_eq!(cfg["name"], "my-registry");
    }
}
