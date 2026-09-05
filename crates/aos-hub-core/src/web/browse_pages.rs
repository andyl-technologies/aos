//! Rich, session-aware browse-page composition: data in, HTML documents out.
//!
//! RFC-0004 Phase 5 (console-dedup stage G) lifts the native hub's *rich* browse
//! renderer — the instance home, the registry home, the searchable/sortable
//! package index and the data-rich package detail, the channel partition grid
//! and bucket calculator, the releases list, and the per-registry health page —
//! out of `aos-hub` into shared core so the Cloudflare Worker serves
//! the **identical** branded, searchable, session-aware browse the native hub
//! does. The earlier (anonymous, public-only, proto-shaped) [`crate::web::render`]
//! builders are superseded by these.
//!
//! Every page here renders from index data alone (no live surface reads), works
//! without JavaScript — search, the channel-bucket calculator, and pagination
//! are plain GET forms and links — and carries the footer state line. URL space
//! (RFC-0004 "Sitemap"): the registry home lives at `/{slug}/`, all other human
//! pages (packages, images, channels, releases, health) under `/{slug}/-/…` — the
//! reserved namespace that can never collide with machine paths.
//!
//! These builders are **transport- and task-local-free**: the signed-in identity
//! rides in an explicit [`SessionIndicator`] argument (the masthead brand comes
//! from the shared editable site chrome), so the module compiles to
//! `wasm32-unknown-unknown` (no `axum`, no `tokio`, no `std::fs`). The pure
//! primitives — [`escape`], [`table`], `human_size`, `key_fingerprint`, and the
//! console chrome (`page_with_session`, [`Pager`], [`StateLine`]) — are reused
//! from [`crate::web::render`] and [`crate::web::console_render`] so the browse
//! surface, the producer console, and the worker render byte-identically.

use crate::clock::Instant;
use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::db::{
    CacheProbeRow, ChannelSummary, IndexStatus, IndexedSystemImage, PackageDetail, PackageRow,
    RegistryRecord, ReleaseRow, RepairJobRow, ValidationRunRow,
};
#[cfg(test)]
use crate::db::{PlatformDetail, VersionDetail};
use crate::stack::StackNode;
use crate::web::console_render::{
    ago, live_table, meter, page_with_session, table_raw_headers, urlencode, Pager,
    SessionIndicator, StateLine,
};
use crate::web::render::{
    escape, hash_value, hash_value_link, human_size, key_fingerprint, table, trust_key_value,
};
use aos_registry_surface::manifest::{ImageCompression, ImageTarget, ImageVerificationState};

/// Glyph palette for the partition grid: one glyph per release, assigned
/// in frontier-first order, so the encoding survives without color.
const GRID_GLYPHS: [char; 6] = ['■', '▣', '▥', '▤', '▧', '▢'];

/// Rows per page on the HTML package index.
pub const PACKAGES_PER_PAGE: usize = 100;

/// Rows per page in the richer system-image catalog.
pub const IMAGES_PER_PAGE: usize = 25;

/// Rows per page on the general management lists (registries, organizations,
/// members, audit) — smaller than the package index, since these are scanned
/// rather than searched.
pub const LIST_PER_PAGE: usize = 50;

pub(crate) fn state_line(status: Option<&IndexStatus>, started: Instant) -> StateLine {
    match status {
        Some(status) => StateLine {
            surface_commit: status.last_indexed_commit.clone(),
            indexed_at: status.indexed_at,
            state: Some(status.state.clone()),
            started: Some(started),
        },
        None => StateLine::timed(started),
    }
}

pub(crate) fn registry_crumbs(slug: &str, tail: &[(String, String)]) -> Vec<(String, String)> {
    let mut crumbs = vec![
        ("/".to_string(), "registries".to_string()),
        (format!("/{slug}/"), slug.to_string()),
    ];
    crumbs.extend_from_slice(tail);
    crumbs
}

pub(crate) fn registry_nav(slug: &str, active: &str) -> String {
    let items = [
        ("overview", format!("/{slug}/"), "Overview"),
        ("packages", format!("/{slug}/-/packages"), "Packages"),
        ("docs", format!("/{slug}/-/docs"), "Docs"),
        ("images", format!("/{slug}/-/images"), "Images"),
        ("containers", format!("/{slug}/-/containers"), "Containers"),
        ("channels", format!("/{slug}/-/channels"), "Channels"),
        ("releases", format!("/{slug}/-/releases"), "Releases"),
        ("health", format!("/{slug}/-/health"), "Health"),
    ];
    let mut nav = String::from("<nav aria-label=\"registry\" class=\"local-nav\">");
    for (key, href, label) in items {
        let current = (key == active)
            .then_some(" aria-current=\"page\"")
            .unwrap_or("");
        let _ = write!(
            nav,
            "<a href=\"{}\"{}>{}</a>",
            escape(&href),
            current,
            label,
        );
    }
    nav.push_str("</nav>\n");
    nav
}

/// Split a `name:Ed25519:<base64>` trust anchor into `(name, base64)`.
///
/// Tolerates other shapes by returning the whole string for both parts.
fn key_name_and_blob(key: &str) -> (&str, &str) {
    let name = key.split(':').next().unwrap_or(key);
    let blob = key.rsplit(':').next().unwrap_or(key);
    (name, blob)
}

/// Copy-pasteable consumer configuration shared by registry browse pages.
///
/// The canonical Git URL, signed client identity, trust anchors, and committed
/// cache stack are resolved once by the request handler so overview and package
/// pages cannot advertise different installation instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySetup {
    registry_url: Option<String>,
    client_name: String,
    trust_keys: Vec<String>,
    substituters: Vec<String>,
}

impl RegistrySetup {
    /// Builds setup instructions from one resolved registry URL and cache stack.
    #[must_use]
    pub fn new(
        registry: &RegistryRecord,
        status: Option<&IndexStatus>,
        registry_url: Option<&str>,
        caches: &[(String, u32)],
    ) -> Self {
        let display_name = status
            .and_then(|value| value.name.as_deref())
            .unwrap_or(&registry.slug);
        let client_name = registry
            .trust_keys
            .first()
            .map(|key| key_name_and_blob(key).0)
            .filter(|name| !name.is_empty())
            .unwrap_or(display_name)
            .to_string();
        let registry_url = registry_url.map(|url| format!("{}/", url.trim_end_matches('/')));
        let substituters = if let Some(url) = &registry_url {
            // The canonical registry facade is deliberately also its Git
            // origin and Nix binary cache. Physical cache routes remain in the
            // signed topology below, but consumer setup needs only this one
            // stable URL.
            vec![url.trim_end_matches('/').to_string()]
        } else {
            let mut ordered: Vec<&(String, u32)> = caches.iter().collect();
            ordered.sort_by_key(|(_, priority)| std::cmp::Reverse(*priority));
            ordered
                .into_iter()
                .map(|(url, _)| url.trim_end_matches('/').to_string())
                .collect()
        };

        Self {
            registry_url,
            client_name,
            trust_keys: registry.trust_keys.clone(),
            substituters,
        }
    }

    fn add_command(&self) -> Option<String> {
        let url = self.registry_url.as_deref()?;
        let mut command = format!("apr add {url} --name {}", self.client_name);
        for key in &self.trust_keys {
            let _ = write!(command, " --trust-key {key}");
        }
        Some(command)
    }

    fn module_stanza(&self) -> Option<String> {
        let url = self.registry_url.as_deref()?;
        let mut stanza = format!(
            "aos.apm.registries.\"{}\" = {{\n  url = \"{url}\";\n  trustKeys = [\n",
            self.client_name,
        );
        for key in &self.trust_keys {
            let _ = writeln!(stanza, "    \"{key}\"");
        }
        stanza.push_str("  ];\n};");
        Some(stanza)
    }

    fn plain_nix(&self) -> String {
        let mut plain = format!("substituters = {}", self.substituters.join(" "));
        if !self.trust_keys.is_empty() {
            let _ = write!(
                plain,
                "\ntrusted-public-keys = {}",
                self.trust_keys.join(" ")
            );
        }
        plain
    }

    /// Resolves one binary-cache object against the highest-priority
    /// configured substituter.
    fn cache_object_url(&self, object: &str) -> Option<String> {
        self.substituters
            .first()
            .map(|base| format!("{}/{}", base.trim_end_matches('/'), object))
    }
}

/// The store hash of a store path: the basename text before the first `-`.
fn store_hash(store_path: &str) -> Option<&str> {
    let basename = store_path.rsplit('/').next().unwrap_or(store_path);
    basename.split_once('-').map(|(hash, _)| hash)
}

/// Parse a partition bucket from user input: decimal first, then hex
/// (with or without a `0x` prefix), 0..=255.
fn parse_bucket(text: &str) -> Option<u8> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u8::from_str_radix(hex, 16).ok();
    }
    text.parse::<u8>()
        .ok()
        .or_else(|| u8::from_str_radix(text, 16).ok())
}

/// A narinfo permalink for one store hash on the configured cache delivery
/// endpoint.
fn narinfo_link(setup: &RegistrySetup, hash: &str) -> String {
    match setup.cache_object_url(&format!("{hash}.narinfo")) {
        Some(href) => hash_value_link(hash, &href),
        None => hash_value(hash),
    }
}

fn store_path_link(setup: &RegistrySetup, path: &str) -> String {
    match store_hash(path).and_then(|hash| setup.cache_object_url(&format!("{hash}.narinfo"))) {
        Some(href) => format!(
            "<a href=\"{}\"><code>{}</code></a>",
            escape(&href),
            escape(path),
        ),
        None => format!("<code>{}</code>", escape(path)),
    }
}

/// The status / coverage / checked / probed cells for one cache row.
fn validation_cells(run: Option<&ValidationRunRow>) -> [String; 4] {
    let Some(run) = run else {
        return [
            "<span class=\"dim\">not yet validated</span>".to_string(),
            "—".to_string(),
            "—".to_string(),
            "—".to_string(),
        ];
    };
    let status = if !run.reachable {
        "<span class=\"bad\">✗ unreachable</span>".to_string()
    } else if run.missing == 0 {
        "<span class=\"ok\">✓ ok</span>".to_string()
    } else {
        format!("<span class=\"warn\">⚠ {} missing</span>", run.missing)
    };
    let coverage = if run.checked > 0 {
        format!(
            "{}%",
            run.checked.saturating_sub(run.missing) * 100 / run.checked
        )
    } else {
        "—".to_string()
    };
    [
        status,
        coverage,
        run.checked.to_string(),
        ago(run.finished_at),
    ]
}

/// The instance home: every registered registry and its index state, with
/// an optional `?q=` substring filter over slugs, names, and descriptions.
///
/// `session` renders the masthead identity (signed-in email + logout, or a
/// log-in link), so the same builder serves the native hub's session-aware
/// browse and the Cloudflare Worker's.
pub fn instance_home(
    rows: &[(RegistryRecord, Option<IndexStatus>)],
    query: Option<&str>,
    page_number: usize,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let needle = query.map(str::to_lowercase);
    let matches: Vec<&(RegistryRecord, Option<IndexStatus>)> = rows
        .iter()
        .filter(|(reg, status)| match &needle {
            None => true,
            Some(needle) => {
                let name = status
                    .as_ref()
                    .and_then(|s| s.name.as_deref())
                    .unwrap_or("");
                let desc = status
                    .as_ref()
                    .and_then(|s| s.description.as_deref())
                    .unwrap_or("");
                reg.slug.to_lowercase().contains(needle)
                    || name.to_lowercase().contains(needle)
                    || desc.to_lowercase().contains(needle)
            }
        })
        .collect();

    // Paginate the filtered set. The live-search enhancement only filters the
    // visible page, so it bows out (in app.js) when a pager is present and the
    // `?q=` server filter takes over for cross-page search.
    let pager = Pager::new(page_number, LIST_PER_PAGE, matches.len());
    let body_rows: Vec<Vec<String>> = pager
        .slice(&matches)
        .iter()
        .map(|(reg, status)| {
            let (state, class, detail) = match status.as_ref().map(|s| s.state.as_str()) {
                Some("fresh" | "empty") => ("live", "ok", "Index is current".to_string()),
                Some("failed") => ("outdated", "bad", "Index refresh failed".to_string()),
                Some("indexing") => (
                    "outdated",
                    "warn",
                    "Index refresh is in progress".to_string(),
                ),
                Some("stale") => (
                    "outdated",
                    "warn",
                    "Index is behind the registry surface".to_string(),
                ),
                Some(other) => ("outdated", "warn", format!("Index state: {other}")),
                None => ("outdated", "warn", "Index is not registered".to_string()),
            };
            vec![
                format!("<a href=\"/{0}/\">{0}</a>", escape(&reg.slug)),
                escape(
                    status
                        .as_ref()
                        .and_then(|s| s.name.as_deref())
                        .unwrap_or("—"),
                ),
                format!(
                    "<span class=\"{class}\" title=\"{}\">{}</span>",
                    escape(&detail),
                    escape(state)
                ),
            ]
        })
        .collect();

    // No page-title <h1>: the masthead/title already say "registries".
    let mut body = String::new();
    let _ = writeln!(
        body,
        "<form method=\"get\" data-live><input type=\"search\" name=\"q\" value=\"{}\" \
         placeholder=\"search registries\"> <button>search</button></form>",
        escape(query.unwrap_or("")),
    );
    // The count is always rendered (JS updates it live as you type); with JS
    // off it reflects the server-side `?q=` filter for the current request.
    let count = match query {
        Some(q) => format!(
            "{} of {} registries matching \"{}\"",
            matches.len(),
            rows.len(),
            escape(q),
        ),
        None => format!("{} registries", rows.len()),
    };
    let _ = writeln!(body, "<p class=\"dim\" data-live-count>{count}</p>");
    if rows.is_empty() {
        body.push_str(
            "<p class=\"dim\">No registries registered. Add one with \
             <code>aos-hub registry add &lt;slug&gt; &lt;url&gt;</code>.</p>",
        );
    } else if body_rows.is_empty() {
        body.push_str("<p class=\"dim\">No registries match.</p>");
    } else {
        body.push_str(&live_table(
            &["slug", "name", "index"],
            &body_rows,
            "registries",
        ));
        let query_str = query
            .map(|q| format!("q={}", urlencode(q)))
            .unwrap_or_default();
        body.push_str(&pager.nav("/", &query_str));
    }
    page_with_session(
        "registries",
        &[(String::new(), "registries".into())],
        &body,
        &StateLine::timed(started),
        session,
    )
}

/// The registry home: trust anchors with fingerprints, channels, cache
/// validation health, package count, and the three setup snippets.
#[allow(clippy::too_many_arguments)]
pub fn registry_home(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channels: &[ChannelSummary],
    package_count: usize,
    caches: &[(String, u32)],
    roster: &[(String, String, String)],
    validations: &[ValidationRunRow],
    setup: &RegistrySetup,
    manage_link: bool,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let mut body = registry_nav(slug, "overview");

    let display_name = status
        .and_then(|s| s.name.as_deref())
        .unwrap_or(slug.as_str());
    let _ = write!(body, "<h1>Registry {}</h1>", escape(display_name));
    // A signed-in caller holding `registry.configure` here gets a link to the
    // management landing page (the no-JS console's entry point for editing
    // this registry); anonymous and unauthorized readers never see it.
    if manage_link {
        let _ = write!(
            body,
            "\n<p><a href=\"/{}/-/settings\">manage this registry →</a></p>",
            escape(slug),
        );
    }
    if let Some(at) = status.and_then(|s| s.indexed_at) {
        let _ = write!(body, "\n<p class=\"dim\">indexed {}</p>", ago(at));
    }
    if let Some(desc) = status.and_then(|s| s.description.as_deref()) {
        let _ = write!(body, "<p>{}</p>", escape(desc));
    }
    // The longer README-style preamble (committed `[registry] readme`): blank
    // lines separate paragraphs, each rendered as its own escaped <p>.
    if let Some(readme) = status.and_then(|s| s.readme.as_deref()) {
        body.push_str("<div class=\"readme\">");
        for para in readme.split("\n\n") {
            let para = para.trim();
            if !para.is_empty() {
                let _ = write!(body, "<p>{}</p>", escape(para));
            }
        }
        body.push_str("</div>\n");
    }
    if let Some(status) = status {
        match status.state.as_str() {
            "failed" => {
                let _ = write!(
                    body,
                    "<p class=\"bad\">index failed: {}</p>",
                    escape(status.error.as_deref().unwrap_or("unknown error")),
                );
            }
            // A freshly-created registry with no surface published yet, or one
            // still awaiting its first index pass — not an error. `empty` is the
            // terminal "indexed, nothing published" state; `pending`/`indexing`
            // are its transient cousins. All read the same to a visitor.
            "empty" | "pending" | "indexing" => {
                body.push_str("<p class=\"dim\">No releases published to this registry yet.</p>\n");
            }
            _ => {}
        }
    }

    body.push_str("<h2>Trust</h2>\n");
    if registry.trust_keys.is_empty() && roster.is_empty() {
        body.push_str(
            "<p class=\"warn\">No trust anchors pinned — content is displayed unverified.</p>\n",
        );
    } else {
        let rows: Vec<Vec<String>> = registry
            .trust_keys
            .iter()
            .map(|key| {
                let (name, blob) = key_name_and_blob(key);
                vec![
                    format!("pinned {}", escape(name)),
                    hash_value(&key_fingerprint(blob)),
                    trust_key_value(key),
                ]
            })
            .chain(roster.iter().map(|(id, key, status)| {
                let (fingerprint, label) = if key.is_empty() {
                    ("—".to_string(), "—".to_string())
                } else {
                    let (_, blob) = key_name_and_blob(key);
                    (hash_value(&key_fingerprint(blob)), trust_key_value(key))
                };
                vec![
                    format!("roster {} ({})", escape(id), escape(status)),
                    fingerprint,
                    label,
                ]
            }))
            .collect();
        body.push_str(&table(&["anchor", "fingerprint", "key"], &rows));
    }

    body.push_str("<h2>Channels</h2>\n");
    if channels.is_empty() {
        body.push_str("<p class=\"dim\">No channels resolved.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = channels
            .iter()
            .map(|channel| {
                let assigned = channel.partitions.iter().flatten().count();
                let at_frontier = channel
                    .frontier
                    .as_ref()
                    .map(|f| {
                        channel
                            .partitions
                            .iter()
                            .flatten()
                            .filter(|r| *r == f)
                            .count()
                    })
                    .unwrap_or(0);
                let percent = at_frontier * 100 / 256;
                vec![
                    format!(
                        "<a href=\"/{}/-/channels/{}\">{}</a>",
                        escape(slug),
                        escape(&channel.name),
                        escape(&channel.name),
                    ),
                    escape(channel.frontier.as_deref().unwrap_or("—")),
                    format!("{} {percent}%", meter(percent)),
                    format!("{assigned}/256 assigned"),
                ]
            })
            .collect();
        body.push_str(&table(
            &["channel", "frontier", "rollout", "partitions"],
            &rows,
        ));
    }

    let _ = write!(
        body,
        "<h2>Packages ({count})</h2>\n<p><a href=\"/{slug}/-/packages\">Browse the package index →</a></p>\n",
        count = package_count,
        slug = escape(slug),
    );

    body.push_str("<h2>Caches</h2>\n");
    if caches.is_empty() {
        body.push_str("<p class=\"dim\">No committed caches.</p>\n");
    } else {
        let runs_by_url: BTreeMap<&str, &ValidationRunRow> = validations
            .iter()
            .map(|run| (run.cache_url.as_str(), run))
            .collect();
        let rows: Vec<Vec<String>> = caches
            .iter()
            .map(|(url, priority)| {
                let [status, coverage, checked, probed] =
                    validation_cells(runs_by_url.get(url.as_str()).copied());
                vec![
                    format!("<code class=\"cache-url\">{}</code>", escape(url)),
                    priority.to_string(),
                    status,
                    coverage,
                    checked,
                    probed,
                ]
            })
            .collect();
        body.push_str(&table(
            &["url", "priority", "status", "coverage", "checked", "probed"],
            &rows,
        ));
    }
    let _ = writeln!(
        body,
        "<p><a href=\"/{}/-/health\">health →</a></p>",
        escape(slug),
    );

    body.push_str("<h2>Setup</h2>\n");
    let Some(add_command) = setup.add_command() else {
        body.push_str(
            "<p class=\"dim\">No canonical Git route is ready. Configure delivery before adding this registry to a client.</p>\n",
        );
        return page_with_session(
            display_name,
            &registry_crumbs(slug, &[]),
            &body,
            &state_line(status, started),
            session,
        );
    };
    let _ = write!(
        body,
        "<p class=\"dim\">apm:</p>\n<pre>{}</pre>\n",
        escape(&add_command),
    );
    if let Some(stanza) = setup.module_stanza() {
        let _ = write!(
            body,
            "<p class=\"dim\">AOS module:</p>\n<pre>{}</pre>\n",
            escape(&stanza),
        );
    }
    let plain = setup.plain_nix();
    let _ = write!(
        body,
        "<p class=\"dim\">plain Nix (substitute from the advertised cache):</p>\n<pre>{}</pre>\n",
        escape(&plain),
    );

    page_with_session(
        display_name,
        &registry_crumbs(slug, &[]),
        &body,
        &state_line(status, started),
        session,
    )
}

/// A sortable package-index column.
///
/// Selected by `?sort=<token>` and paired with a [`SortDir`]; the column
/// headers cycle through unsorted → descending → ascending as the no-JS sort
/// control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    /// Package name.
    Name,
    /// Latest version (semver-aware).
    Version,
    /// Published license metadata.
    License,
    /// Latest version's closure size.
    Closure,
    /// Published platform list.
    Platforms,
}

impl SortColumn {
    /// The `?sort=` token for this column.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Version => "version",
            Self::License => "license",
            Self::Closure => "closure",
            Self::Platforms => "platforms",
        }
    }

    /// Parse a `?sort=` token into a column.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "name" => Some(Self::Name),
            "version" => Some(Self::Version),
            "license" => Some(Self::License),
            "closure" | "size" => Some(Self::Closure),
            "platforms" | "platform" => Some(Self::Platforms),
            _ => None,
        }
    }
}

/// A sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir {
    /// Ascending (A→Z, smallest first, oldest first).
    Asc,
    /// Descending (Z→A, largest first, newest first).
    Desc,
}

impl SortDir {
    /// The `?dir=` token for this direction.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }

    /// Parse a `?dir=` token; anything but `asc` is descending (the first
    /// click on a column sorts descending).
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some("asc") => Self::Asc,
            _ => Self::Desc,
        }
    }
}

/// The package-index browse state: the active filter expression, the active
/// sort, the counts, and the page number.
///
/// The handler computes this from the request's `?filter=`/`?sort=`/`?dir=`/
/// `?page=` parameters and renders the controls, the result line, and the
/// pager from it. The filter is a Wireshark-style display-filter expression
/// (see [`crate::filter`]); `filter_error` carries a parse error to surface.
#[derive(Debug, Clone, Copy)]
pub struct PackageBrowse<'a> {
    /// Selected verified release tag or exact release commit; `None` means the indexed HEAD.
    pub snapshot: Option<&'a str>,
    /// Commit of the current indexed HEAD, shown for an explicit default identity.
    pub head_commit: Option<&'a str>,
    /// Verified `(tag, commit)` choices available for snapshot selection.
    pub snapshots: &'a [(String, String)],
    /// The raw `?filter=` expression text (repopulates the box), if any.
    pub filter: Option<&'a str>,
    /// A filter parse-error message to display, if the expression was invalid.
    pub filter_error: Option<&'a str>,
    /// The active sort column and direction, or `None` for the default
    /// (name, ascending) order.
    pub sort: Option<(SortColumn, SortDir)>,
    /// The clamped 1-based page number.
    pub page_number: usize,
    /// Count of packages matching the filter (across all pages).
    pub total_matches: usize,
    /// Count of packages in the registry, before filtering.
    ///
    /// When [`PackageBrowse::truncated`] is set this is the number actually
    /// loaded (the browse cap), not the registry's true package count.
    pub total_all: usize,
    /// Whether the package set was capped at the browse limit.
    ///
    /// `true` when the registry holds more packages than the hub loads for the
    /// browse UI (see `MAX_BROWSE_PACKAGES`); the page then shows a "first N of
    /// many" notice and the filter/sort operate over the capped set only.
    pub truncated: bool,
    /// Distinct package names, for the filter autocomplete (capped, sorted).
    pub names: &'a [String],
    /// Distinct latest versions, for the filter autocomplete.
    pub versions: &'a [String],
    /// Distinct licenses, for the filter autocomplete.
    pub licenses: &'a [String],
    /// Distinct platforms, for the filter autocomplete.
    pub platforms: &'a [String],
}

/// Returns the compact identifier displayed inside a package license pill.
///
/// Package metadata retains the complete SPDX-style expression for filtering
/// and the hover title. This presentation map keeps the inventory scannable;
/// an unknown or already-short value passes through unchanged.
fn license_pill_label(license: &str) -> &str {
    match license {
        "AFL-2.1" => "AFL",
        "AGPL-3.0" => "AGPLv3",
        "Apache-2.0" => "Apache",
        "Artistic-1.0-Perl" => "Artistic",
        "BSD-2-Clause" => "BSD-2",
        "BSD-2-Clause-Patent" => "BSD-2-Patent",
        "BSD-3-Clause" => "BSD-3",
        "BSD-3-Clause OR GPL-2.0-only" => "BSD-3/GPLv2",
        "BSL-1.0" => "BSL",
        "CC0-1.0" => "CC0",
        "CDDL-1.0" => "CDDL",
        "EPL-1.0" => "EPL",
        "FTL OR GPL-2.0-or-later" => "FTL/GPLv2+",
        "GPL-2.0" | "GPL-2.0-only" => "GPLv2",
        "GPL-2.0-only AND GPL-2.0-or-later AND MIT" => "GPLv2/MIT",
        "GPL-2.0-only WITH GCC-exception-3.1" => "GPLv2+GCC",
        "GPL-2.0-or-later" => "GPLv2+",
        "GPL-2.0-or-later OR Apache-2.0" => "GPLv2+/Apache",
        "GPL-2.0-with-classpath-exception" => "GPLv2+Classpath",
        "GPL-3.0-only" => "GPLv3",
        "GPL-3.0-or-later" => "GPLv3+",
        "GPL-3.0-or-later WITH GCC-exception-3.1" => "GPLv3+GCC",
        "IPL-1.0" => "IPL",
        "Intel-ACPI OR GPL-2.0-only OR BSD-3-Clause" => "ACPI/GPL2/BSD3",
        "LGPL-2.1-only" => "LGPLv2.1",
        "LGPL-2.1-only OR BSD-2-Clause" => "LGPLv2.1/BSD-2",
        "LGPL-2.1-or-later" => "LGPLv2.1+",
        "LGPL-3.0-or-later" => "LGPLv3+",
        "Linux-firmware" => "Linux FW",
        "MIT OR Apache-2.0" => "MIT/Apache",
        "MIT OR GPL-2.0-only" => "MIT/GPLv2",
        "MPL-2.0" => "MPLv2",
        "NVIDIA-Software-License" => "NVIDIA",
        "PSF-2.0" => "PSF",
        "Public Domain" | "public-domain" => "Public domain",
        "Python-2.0" => "Python",
        "bzip2-1.0.6" => "bzip2",
        _ => license,
    }
}

/// Render a sortable column header as a tri-state sort link.
///
/// The displayed glyph reflects this column's *current* state (▼ descending,
/// ▲ ascending, ⇅ unsorted); the link advances to the *next* state in the
/// cycle unsorted → descending → ascending → unsorted. `filter_query` is the
/// already-encoded `filter=…` parameter to preserve (empty when none); paging
/// resets on a sort change.
fn sort_header(
    slug: &str,
    label: &str,
    col: SortColumn,
    current: Option<(SortColumn, SortDir)>,
    filter_query: &str,
) -> String {
    // (next sort state, glyph for the current state).
    let (next, glyph): (Option<(SortColumn, SortDir)>, &str) = match current {
        Some((c, SortDir::Desc)) if c == col => (Some((col, SortDir::Asc)), " ▼"),
        Some((c, SortDir::Asc)) if c == col => (None, " ▲"),
        _ => (Some((col, SortDir::Desc)), " ⇅"),
    };
    let mut query = String::new();
    if !filter_query.is_empty() {
        query.push_str(filter_query);
    }
    if let Some((c, dir)) = next {
        if !query.is_empty() {
            query.push('&');
        }
        let _ = write!(query, "sort={}&dir={}", c.token(), dir.token());
    }
    let href = if query.is_empty() {
        format!("/{slug}/-/packages")
    } else {
        format!("/{slug}/-/packages?{query}")
    };
    let active = matches!(current, Some((c, _)) if c == col);
    let class = if active { " class=\"sorted\"" } else { "" };
    format!(
        "<a href=\"{}\"{class}>{}<span class=\"sort-glyph\">{glyph}</span></a>",
        escape(&href),
        escape(label),
    )
}

/// Render the `#filter-meta` JSON data island that drives the filter box's
/// autocomplete: the field names, the operators, and the registry's distinct
/// values per value-suggestable field.
///
/// Emitted as a non-executable `<script type="application/json">` block (inert
/// data, so it loads under the strict `default-src 'self'` CSP). `<` is escaped
/// to `<` so a value can never close the script element early.
fn filter_meta_json(
    names: &[String],
    versions: &[String],
    licenses: &[String],
    platforms: &[String],
) -> String {
    let meta = serde_json::json!({
        "fields": crate::filter::FIELD_NAMES,
        "operators": ["==", "!=", "~", ">", "<", ">=", "<="],
        "connectives": ["and", "or", "not"],
        "values": {
            "name": names,
            "version": versions,
            "license": licenses,
            "platform": platforms,
        },
    });
    let json = meta.to_string().replace('<', "\\u003c");
    format!("<script type=\"application/json\" id=\"filter-meta\">{json}</script>\n")
}

/// The package index page: one pre-filtered, pre-sorted, pre-sliced page.
///
/// `rows` is the current page after the handler applies the filter expression
/// in [`PackageBrowse`], the sort order, and the `?page=` slice. Each row shows
/// the package name, latest version, license (a link that filters to that
/// license), the latest version's closure size, its platform list, and the
/// description, so the index reads like a release-engineering inventory. The
/// filter box, the click-to-sort column headers, and the pagination links are
/// plain GET controls that preserve the filter across navigation.
pub fn package_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    rows: &[PackageRow],
    browse: &PackageBrowse<'_>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let PackageBrowse {
        snapshot,
        head_commit,
        snapshots,
        filter,
        filter_error,
        sort,
        page_number,
        total_matches,
        total_all,
        truncated,
        names,
        versions,
        licenses,
        platforms,
    } = *browse;
    let slug = &registry.slug;
    let snapshot_query = snapshot
        .map(|value| format!("release={}", urlencode(value)))
        .unwrap_or_default();

    // The encoded `filter=…` parameter, preserved across sort and pagination.
    let filter_query = filter
        .map(|f| format!("filter={}", urlencode(f)))
        .unwrap_or_default();

    let body_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|p| {
            let size = p
                .closure_size
                .map(human_size)
                .unwrap_or_else(|| "—".to_string());
            let platforms = if p.platforms.is_empty() {
                "—".to_string()
            } else {
                p.platforms
                    .iter()
                    .map(|platform| {
                        format!(
                            "<a class=\"platform-pill\" title=\"Filter by platform: {}\" href=\"/{}/-/packages?{}filter={}\">{}</a>",
                            escape(platform),
                            escape(slug),
                            if snapshot_query.is_empty() { "".to_string() } else { format!("{}&", snapshot_query) },
                            urlencode(&format!("platform == \"{platform}\"")),
                            escape(platform),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            // The license cell links to a `license == "…"` filter, so a click
            // narrows the index to that license — a no-JS facet.
            let license_cell = if p.license.is_empty() {
                "—".to_string()
            } else {
                format!(
                    "<a class=\"license-pill\" title=\"Filter by license: {}\" href=\"/{}/-/packages?{}filter={}\">{}</a>",
                    escape(&p.license),
                    escape(slug),
                    if snapshot_query.is_empty() { "".to_string() } else { format!("{}&", snapshot_query) },
                    urlencode(&format!("license == \"{}\"", p.license)),
                    escape(license_pill_label(&p.license)),
                )
            };
            vec![
                format!(
                    "<a href=\"/{}/-/packages/{}{}\">{}</a>",
                    escape(slug),
                    escape(&p.name),
                    snapshot.map(|value| format!("?release={}", urlencode(value))).unwrap_or_default(),
                    escape(&p.name),
                ),
                escape(p.latest_version.as_deref().unwrap_or("—")),
                license_cell,
                size,
                platforms,
                escape(&p.description),
            ]
        })
        .collect();

    let mut body = registry_nav(slug, "packages");
    let _ = writeln!(body, "<h1>Packages ({total_all})</h1>");

    body.push_str("<form method=\"get\" class=\"snapshot-selector\"><label>registry snapshot <select name=\"release\">");
    let _ = write!(
        body,
        "<option value=\"\"{}>indexed HEAD{}</option>",
        if snapshot.is_none() { " selected" } else { "" },
        head_commit
            .map(|commit| format!(" · {}", escape(&commit[..commit.len().min(12)])))
            .unwrap_or_default(),
    );
    for (tag, commit) in snapshots {
        let _ = write!(
            body,
            "<option value=\"{}\"{}>{} · {}</option>",
            escape(tag),
            if snapshot == Some(tag.as_str()) || snapshot == Some(commit.as_str()) {
                " selected"
            } else {
                ""
            },
            escape(tag),
            escape(&commit[..commit.len().min(12)]),
        );
    }
    body.push_str("</select></label> <button>Show snapshot</button></form>\n");
    let _ = writeln!(
        body,
        "<p class=\"dim\">Showing package membership at <strong>{}</strong>.</p>",
        snapshot.map(escape).unwrap_or_else(|| head_commit
            .map(|commit| format!("indexed HEAD {}", hash_value(commit)))
            .unwrap_or_else(|| "indexed HEAD".to_string())),
    );

    // The filter box is a Wireshark-style display-filter expression: every
    // attribute is queryable with operators and boolean connectives. A bare
    // word still matches any field, so simple searches keep working.
    //
    // The plain `<input>` is the no-JS floor (a server `?filter=` submit). When
    // app.js loads it wraps the input in `.filter-field` with a syntax-
    // highlight overlay and a custom autocomplete dropdown driven by the
    // `#filter-meta` JSON below — the field names, operators, and the
    // registry's distinct values per field. (No native `<datalist>`: its popup
    // can't be themed.)
    body.push_str("<form method=\"get\" class=\"pkg-search\">");
    if let Some(snapshot) = snapshot {
        let _ = write!(
            body,
            "<input type=\"hidden\" name=\"release\" value=\"{}\">",
            escape(snapshot)
        );
    }
    let _ = write!(
        body,
        "<span class=\"filter-field\" data-filter-widget>\
         <pre class=\"filter-highlight\" aria-hidden=\"true\"><code></code></pre>\
         <input type=\"text\" name=\"filter\" value=\"{}\" class=\"filter-box\" \
         autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\" \
         placeholder=\"filter e.g. license == MIT and platform ~ linux\">\
         <div class=\"filter-suggest\" hidden></div></span> ",
        escape(filter.unwrap_or("")),
    );
    body.push_str("<button>apply</button></form>\n");
    body.push_str(&filter_meta_json(names, versions, licenses, platforms));
    body.push_str(
        "<p class=\"dim filter-help\">Fields: <code>name</code> <code>version</code> \
         <code>license</code> <code>platform</code> <code>size</code> \
         <code>description</code>. Operators: <code>==</code> <code>!=</code> \
         <code>~</code> <code>&gt;</code> <code>&lt;</code> <code>&gt;=</code> \
         <code>&lt;=</code>, combine with <code>and</code> <code>or</code> \
         <code>not</code>.</p>\n",
    );

    // A parse error is surfaced inline; the unfiltered list is shown so the
    // expression can be corrected against the full set.
    if let Some(error) = filter_error {
        let _ = writeln!(
            body,
            "<p class=\"bad\">filter error: {} — showing all packages</p>",
            escape(error),
        );
    }

    // The result line: a count, plus the active filter (clearable).
    if filter_error.is_none() && filter.is_some() {
        let _ = writeln!(
            body,
            "<p class=\"dim\">{total_matches} of {total_all} packages matching \
             <code>{}</code> · <a href=\"/{}/-/packages{}\">clear filter</a></p>",
            escape(filter.unwrap_or("")),
            escape(slug),
            snapshot
                .map(|value| format!("?release={}", urlencode(value)))
                .unwrap_or_default(),
        );
    } else {
        let _ = writeln!(body, "<p class=\"dim\">{total_all} packages</p>");
    }

    // A pathologically large registry is capped at the browse limit; tell the
    // viewer the filter/sort only see the first N packages.
    if truncated {
        let _ = writeln!(
            body,
            "<p class=\"dim\">showing the first {total_all} packages of a larger \
             registry · filtering and sorting apply to this subset</p>",
        );
    }

    if body_rows.is_empty() {
        body.push_str("<p class=\"dim\">No packages.</p>\n");
    } else {
        let preserved_query = [snapshot_query.as_str(), filter_query.as_str()]
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join("&");
        let headers = vec![
            sort_header(slug, "name", SortColumn::Name, sort, &preserved_query),
            sort_header(slug, "version", SortColumn::Version, sort, &preserved_query),
            sort_header(slug, "license", SortColumn::License, sort, &preserved_query),
            sort_header(slug, "closure", SortColumn::Closure, sort, &preserved_query),
            sort_header(
                slug,
                "platforms",
                SortColumn::Platforms,
                sort,
                &preserved_query,
            ),
            "description".to_string(),
        ];
        body.push_str(&table_raw_headers(&headers, &body_rows));
    }

    // Carry the filter and sort across pagination so paging never re-sorts or
    // drops the filter. The query has no leading separator; Pager::nav appends
    // `&page=N` itself.
    let mut params: Vec<String> = Vec::new();
    if !snapshot_query.is_empty() {
        params.push(snapshot_query);
    }
    if !filter_query.is_empty() {
        params.push(filter_query.clone());
    }
    if let Some((col, dir)) = sort {
        params.push(format!("sort={}", col.token()));
        params.push(format!("dir={}", dir.token()));
    }
    let pager = Pager::new(page_number, PACKAGES_PER_PAGE, total_matches);
    body.push_str(&pager.nav(&format!("/{slug}/-/packages"), &params.join("&")));

    page_with_session(
        &format!("{slug} packages"),
        &registry_crumbs(slug, &[(String::new(), "packages".into())]),
        &body,
        &state_line(status, started),
        session,
    )
}

/// One resolved closure edge for the package detail page.
///
/// Maps a `refs` store-hash prefix to the registry package that publishes it,
/// when resolvable. `name`/`version` are `None` for a hash that belongs to a
/// store path outside this registry's package set (e.g. a stdenv closure
/// dependency), which renders as a narinfo link rather than a package link.
#[derive(Debug, Clone)]
pub struct ResolvedDependency {
    /// The referenced store-hash prefix.
    pub hash: String,
    /// The publishing package's name, when the hash resolves.
    pub name: Option<String>,
    /// The publishing package's version, when the hash resolves.
    pub version: Option<String>,
}

/// The closure neighborhood of a package, resolved against the registry.
///
/// Bundles the forward dependencies of the latest version's primary platform
/// (the `refs` edges, resolved to package names where possible) and the set of
/// packages whose closures reference this one. Both are computed by the
/// handler via [`crate::db::Database::resolve_reference_names`] and
/// [`crate::db::Database::reverse_dependencies`] so the renderer stays a pure
/// function of its inputs.
#[derive(Debug, Clone, Default)]
pub struct PackageClosure {
    /// The platform the forward dependencies were resolved for.
    pub platform: Option<String>,
    /// Forward dependencies of the latest version's primary platform.
    pub dependencies: Vec<ResolvedDependency>,
    /// Packages that reference this one, as `(name, version)`, capped by the
    /// handler. [`PackageClosure::reverse_total`] carries the uncapped count.
    pub reverse: Vec<(String, String)>,
    /// The total number of reverse dependents before the display cap.
    pub reverse_total: usize,
}

/// Canonical documentation rendered beside one package selection.
#[derive(Debug, Clone)]
pub struct PackageDocumentationPanel {
    /// Reverified closed-schema document.
    pub document: aos_doc_model::PackageDocumentation,
    /// Exact signed Nix store object carrying the JSON bytes.
    pub store_path: String,
    /// Exact canonical document digest.
    pub document_sha256: String,
    /// NAR identity of the store object.
    pub nar_hash: String,
}

/// Signed indexed documentation reference, without loading the document bytes.
#[derive(Debug, Clone)]
pub struct PackageDocumentationReference {
    /// Exact package identity.
    pub package: String,
    /// Displayed package version.
    pub version: String,
    /// Displayed platform.
    pub platform: String,
    /// Referenced Nix store object.
    pub store_path: String,
    /// Signed canonical document digest.
    pub document_sha256: String,
    /// Signed NAR identity of the referenced object.
    pub nar_hash: String,
}

impl From<crate::db::PackageDocumentationLocator> for PackageDocumentationReference {
    fn from(locator: crate::db::PackageDocumentationLocator) -> Self {
        Self {
            package: locator.package_name,
            version: locator.package_version,
            platform: locator.platform,
            store_path: locator.artifact.store_path,
            document_sha256: locator.artifact.document_sha256,
            nar_hash: locator.artifact.nar_hash,
        }
    }
}

/// One package's detail page — the data-rich closure browser.
///
/// Renders, in order: a header with name + latest version + the prominent
/// description; "available platforms" chips; a metadata definition table
/// (license, maintainer, homepage, platforms, sysroot, latest version,
/// version count); an `apm` install snippet; the resolved dependency list
/// (the `refs` closure edges of the latest version's primary platform, linked
/// to their package pages where resolvable); the "required by" reverse-dep
/// list; the per-version × platform artifact tables with narinfo + source
/// derivation links; sysroot images; and a `<details>` raw-metadata dump.
///
/// `closure` carries the resolved forward and reverse dependencies the handler
/// computed; `setup` is the same canonical consumer configuration rendered on
/// the registry overview.
pub fn package_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    detail: &PackageDetail,
    closure: &PackageClosure,
    setup: &RegistrySetup,
    snapshot: Option<&str>,
    documentation: Option<&PackageDocumentationReference>,
    documentation_unavailable: bool,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;

    // Header: name, latest version, then the description prominently.
    let latest = detail.versions.first().map(|v| v.version.as_str());
    let mut body = registry_nav(slug, "packages");
    let _ = write!(body, "<h1 id=\"overview\">{}", escape(&detail.name));
    if let Some(latest) = latest {
        let _ = write!(body, " <span class=\"dim\">{}</span>", escape(latest));
    }
    body.push_str("</h1>\n");
    if let Some(snapshot) = snapshot {
        let _ = writeln!(
            body,
            "<p class=\"dim\">Package state authenticated by registry snapshot <strong>{}</strong> · <a href=\"/{}/-/packages?release={}\">back to this snapshot</a></p>",
            escape(snapshot),
            escape(slug),
            urlencode(snapshot),
        );
    }
    if !detail.description.is_empty() {
        let _ = writeln!(
            body,
            "<p class=\"lede\">{}</p>",
            escape(&detail.description)
        );
    }
    body.push_str(
        "<nav class=\"package-section-nav\" aria-label=\"Package documentation sections\"><a href=\"#overview\">Overview</a><a href=\"#install\">Install</a><a href=\"#versions\">Versions</a><a href=\"#configure\">Documentation</a><a href=\"#dependencies\">Dependencies</a><a href=\"#integrity\">Integrity</a></nav>",
    );

    // The union of every version's platforms, as chips near the top.
    let mut all_platforms: Vec<&str> = detail
        .versions
        .iter()
        .flat_map(|v| v.platforms.iter().map(|p| p.platform.as_str()))
        .collect();
    all_platforms.sort_unstable();
    all_platforms.dedup();
    if !all_platforms.is_empty() {
        body.push_str("<p class=\"chips\">");
        for platform in &all_platforms {
            let _ = write!(body, "<span class=\"chip\">{}</span> ", escape(platform));
        }
        body.push_str("</p>\n");
    }

    // Metadata definition table.
    let mut meta_rows = vec![vec!["license".to_string(), escape(&detail.license)]];
    if !detail.maintainer.is_empty() {
        meta_rows.push(vec!["maintainer".to_string(), escape(&detail.maintainer)]);
    }
    if let Some(homepage) = &detail.homepage {
        // Only http(s) homepages become links; anything else (javascript:,
        // data:, …) renders as escaped text.
        let cell = if homepage.starts_with("http://") || homepage.starts_with("https://") {
            format!("<a href=\"{0}\">{0}</a>", escape(homepage))
        } else {
            escape(homepage)
        };
        meta_rows.push(vec!["homepage".to_string(), cell]);
    }
    if !all_platforms.is_empty() {
        meta_rows.push(vec![
            "platforms".to_string(),
            escape(&all_platforms.join(", ")),
        ]);
    }
    if let Some(latest) = latest {
        meta_rows.push(vec!["latest version".to_string(), escape(latest)]);
    }
    meta_rows.push(vec![
        "versions".to_string(),
        detail.versions.len().to_string(),
    ]);
    if detail.sysroot {
        meta_rows.push(vec![
            "sysroot".to_string(),
            "yes (system toplevel)".to_string(),
        ]);
    }
    body.push_str(&table(&["field", "value"], &meta_rows));

    // Install snippet: apm is the consumer CLI; the registry-add and
    // substituter lines mirror the registry home setup, package-focused.
    body.push_str("<h2 id=\"install\">Install</h2>\n");
    if let Some(add_command) = setup.add_command() {
        let snippet = format!(
            "{add_command}\napm install {name}\n\n# or as a plain Nix substituter:\n{plain}",
            name = detail.name,
            plain = setup.plain_nix(),
        );
        let _ = write!(
            body,
            "<p class=\"dim\">apm is the consumer CLI; add the registry, then install:</p>\n<pre>{}</pre>\n",
            escape(&snippet),
        );
    } else {
        body.push_str(
            "<p class=\"dim\">No canonical Git route is ready. Configure delivery before adding this registry to a client.</p>\n",
        );
    }

    body.push_str("<h2 id=\"versions\">Versions</h2>\n");
    body.push_str(
        "<div class=\"table-scroll\" role=\"region\" aria-label=\"Package artifacts\" tabindex=\"0\">\n\
         <table class=\"artifact-table\"><thead><tr><th>version</th><th>platform</th><th>NAR</th><th>closure</th></tr></thead>\n",
    );
    for version in &detail.versions {
        for platform in &version.platforms {
            body.push_str("<tbody class=\"artifact\">\n<tr class=\"artifact-summary\">");
            let _ = write!(body, "<td>{}", escape(&version.version));
            if let Some(previous) = &version.previous {
                let _ = write!(
                    body,
                    "<div class=\"subline\">upgrades {}</div>",
                    escape(previous)
                );
            }
            let _ = writeln!(
                body,
                "</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&platform.platform),
                human_size(platform.nar_size),
                human_size(platform.closure_size),
            );
            let _ = writeln!(
                body,
                "<tr class=\"artifact-detail\"><th scope=\"row\">store path</th><td colspan=\"3\">{}</td></tr>",
                store_path_link(setup, &platform.store_path),
            );
            let source = if platform.source_drv.is_empty() {
                "—".to_string()
            } else {
                store_path_link(setup, &platform.source_drv)
            };
            let _ = writeln!(
                body,
                "<tr class=\"artifact-detail\"><th scope=\"row\">source drv</th><td colspan=\"3\">{source}</td></tr>"
            );
            let _ = writeln!(
                body,
                "<tr class=\"artifact-detail\"><th scope=\"row\">NAR hash</th><td colspan=\"3\">{}</td></tr>",
                hash_value(&platform.nar_hash),
            );
            if !platform.refs.is_empty() {
                body.push_str(
                    "<tr class=\"artifact-detail\"><th scope=\"row\">references</th><td colspan=\"3\" class=\"artifact-references\">",
                );
                for (index, reference) in platform.refs.iter().enumerate() {
                    if index > 0 {
                        body.push(' ');
                    }
                    body.push_str(&narinfo_link(setup, reference));
                }
                body.push_str("</td></tr>\n");
            }
            body.push_str("</tbody>\n");
        }
    }
    body.push_str("</table></div>\n");

    body.push_str("<section id=\"configure\" class=\"package-docs\"><div class=\"section-heading\"><div><p class=\"eyebrow\">Canonical reference</p><h2>Configuration &amp; runtime</h2></div>");
    let _ = write!(
        body,
        "<a class=\"button secondary\" href=\"/{}/-/docs?q={}\">Search all docs</a></div>",
        escape(slug),
        escape(&detail.name),
    );
    if let Some(documentation) = documentation {
        let _ = write!(
            body,
            "<p id=\"integrity\" class=\"dim docs-provenance\">Signed reference to <code>{}</code> · document {} · NAR {}</p>",
            escape(&documentation.store_path),
            hash_value(&documentation.document_sha256),
            hash_value(&documentation.nar_hash),
        );
        body.push_str("<p>Read configuration options, service behavior, and examples in the versioned package documentation.</p>");
        let _ = write!(
            body,
            "<p><a href=\"/{}/-/docs/{}/{}/{}?digest={}\">Read configuration &amp; service documentation</a> · <a href=\"/{}/-/api/v1/documentation/{}\">canonical JSON</a></p>",
            escape(slug),
            escape(&documentation.package),
            escape(&documentation.version),
            escape(&documentation.platform),
            urlencode(&documentation.document_sha256),
            escape(slug),
            escape(&documentation.document_sha256),
        );
    } else if documentation_unavailable {
        body.push_str("<aside class=\"notice warning\"><strong>Documentation temporarily unavailable.</strong> The indexed documentation reference could not be read. Package versions and runtime metadata remain available.</aside>");
    } else {
        body.push_str("<p class=\"dim\">No structured documentation reference is indexed for this package version and platform.</p>");
    }
    body.push_str("</section>");

    // Dependencies: the closure edges of the latest primary platform, made
    // legible — resolvable hashes link to their package page, the rest fall
    // back to a narinfo permalink.
    let _ = writeln!(
        body,
        "<h2 id=\"dependencies\">Dependencies ({})</h2>",
        closure.dependencies.len(),
    );
    if closure.dependencies.is_empty() {
        body.push_str("<p class=\"dim\">No runtime dependencies recorded.</p>\n");
    } else {
        if let Some(platform) = &closure.platform {
            let _ = writeln!(
                body,
                "<p class=\"dim\">runtime closure of the latest version on {}:</p>",
                escape(platform),
            );
        }
        body.push_str("<ul class=\"deps\">\n");
        for dep in &closure.dependencies {
            match (&dep.name, &dep.version) {
                (Some(name), version) => {
                    let _ = write!(
                        body,
                        "<li><a href=\"/{}/-/packages/{}\">{}</a>",
                        escape(slug),
                        escape(name),
                        escape(name),
                    );
                    if let Some(version) = version {
                        let _ = write!(body, " <span class=\"dim\">{}</span>", escape(version));
                    }
                    body.push_str("</li>\n");
                }
                (None, _) => {
                    let _ = writeln!(body, "<li>{}</li>", narinfo_link(setup, &dep.hash));
                }
            }
        }
        body.push_str("</ul>\n");
    }

    // Reverse dependencies: who requires this package.
    let _ = writeln!(body, "<h2>Required by ({})</h2>", closure.reverse_total);
    if closure.reverse.is_empty() {
        body.push_str("<p class=\"dim\">No packages in this registry require it.</p>\n");
    } else {
        body.push_str("<ul class=\"deps\">\n");
        for (name, version) in &closure.reverse {
            let _ = writeln!(
                body,
                "<li><a href=\"/{}/-/packages/{}\">{}</a> <span class=\"dim\">{}</span></li>",
                escape(slug),
                escape(name),
                escape(name),
                escape(version),
            );
        }
        body.push_str("</ul>\n");
        if closure.reverse_total > closure.reverse.len() {
            let _ = writeln!(
                body,
                "<p class=\"dim\">… and {} more</p>",
                closure.reverse_total - closure.reverse.len(),
            );
        }
    }

    for version in &detail.versions {
        let image_rows: Vec<Vec<String>> = version
            .platforms
            .iter()
            .flat_map(|p| {
                p.images.iter().map(|image| {
                    vec![
                        escape(&p.platform),
                        escape(&image.format),
                        escape(&image.delivery.architecture),
                        human_size(image.delivery.byte_size),
                        format!(
                            "<a href=\"/{}/{}\" download=\"{}\">Download</a>",
                            escape(slug),
                            escape(&image.delivery.object_key),
                            escape(&image.delivery.filename),
                        ),
                    ]
                })
            })
            .collect();
        if !image_rows.is_empty() {
            body.push_str("<p class=\"dim\">sysroot images:</p>\n");
            body.push_str(&table(
                &["platform", "format", "architecture", "size", "disk image"],
                &image_rows,
            ));
        }
    }

    // Raw metadata: a no-JS native disclosure showing the underlying index
    // record, so the page never hides the data it renders.
    body.push_str("<details class=\"raw-metadata\">\n<summary>Raw metadata</summary>\n<pre>");
    let _ = writeln!(body, "name         {}", escape(&detail.name));
    let _ = writeln!(body, "description  {}", escape(&detail.description));
    let _ = writeln!(body, "license      {}", escape(&detail.license));
    let _ = writeln!(body, "maintainer   {}", escape(&detail.maintainer));
    if let Some(homepage) = &detail.homepage {
        let _ = writeln!(body, "homepage     {}", escape(homepage));
    }
    let _ = writeln!(body, "sysroot      {}", detail.sysroot);
    for version in &detail.versions {
        let _ = writeln!(body, "\n[[versions]]");
        let _ = writeln!(body, "version      {}", escape(&version.version));
        if let Some(previous) = &version.previous {
            let _ = writeln!(body, "previous     {}", escape(previous));
        }
        for p in &version.platforms {
            let _ = writeln!(body, "  [{}]", escape(&p.platform));
            let _ = writeln!(body, "  store_path    {}", escape(&p.store_path));
            let _ = writeln!(body, "  nar_hash      {}", escape(&p.nar_hash));
            let _ = writeln!(body, "  nar_size      {}", p.nar_size);
            let _ = writeln!(body, "  closure_size  {}", p.closure_size);
            if !p.source_drv.is_empty() {
                let _ = writeln!(body, "  source_drv    {}", escape(&p.source_drv));
            }
            if !p.refs.is_empty() {
                let _ = writeln!(body, "  references    {}", escape(&p.refs.join(" ")));
            }
        }
    }
    body.push_str("</pre>\n</details>\n");

    page_with_session(
        &detail.name,
        &registry_crumbs(
            slug,
            &[
                (format!("/{slug}/-/packages"), "packages".into()),
                (String::new(), detail.name.clone()),
            ],
        ),
        &body,
        &state_line(status, started),
        session,
    )
}

/// Renders the searchable package-documentation index.
pub fn documentation_index_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    results: &[crate::db::PackageDocumentationSearchResult],
    query: Option<&str>,
    kind: Option<&str>,
    page_number: usize,
    total_results: usize,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let mut body = registry_nav(slug, "docs");
    let _ = write!(
        body,
        "<form method=\"get\" class=\"docs-search\" role=\"search\">\
         <label><span>Search documentation</span><input autofocus type=\"search\" name=\"q\" value=\"{}\" placeholder=\"TLS, listen port, restart, credential…\"></label>\
         <label><span>Kind</span><select name=\"kind\">",
        escape(query.unwrap_or("")),
    );
    for (value, label) in [
        ("", "Everything"),
        ("package", "Packages"),
        ("option", "Options"),
        ("service", "Services"),
        ("credential", "Credentials"),
        ("capability", "Capabilities"),
    ] {
        let selected = (kind == Some(value)).then_some(" selected").unwrap_or("");
        let _ = write!(
            body,
            "<option value=\"{}\"{}>{}</option>",
            value, selected, label
        );
    }
    body.push_str("</select></label><button>Search</button></form>");

    if query.is_some_and(|query| !query.trim().is_empty()) {
        let _ = write!(
            body,
            "<p class=\"dim\">{} ranked result{} for <strong>{}</strong></p>",
            total_results,
            if total_results == 1 { "" } else { "s" },
            escape(query.unwrap_or_default()),
        );
    } else if results.is_empty() {
        body.push_str("<p class=\"dim\">No indexed package documentation is available.</p>");
    } else {
        let _ = write!(
            body,
            "<p class=\"dim\">Browse {} indexed documentation entr{}.</p>",
            total_results,
            if total_results == 1 { "y" } else { "ies" },
        );
    }

    if !results.is_empty() {
        body.push_str("<ol class=\"docs-results\">");
        for result in results {
            let _ = write!(
                body,
                "<li><a href=\"/{}/-/docs/{}/{}/{}\"><span class=\"doc-kind\">{}</span><strong>{}</strong><span>{}</span><code>{} {} · {}</code></a></li>",
                escape(slug),
                escape(&result.package_name),
                escape(&result.package_version),
                escape(&result.platform),
                escape(&result.kind),
                escape(&result.title),
                escape(&result.summary),
                escape(&result.package_name),
                escape(&result.package_version),
                escape(&result.platform),
            );
        }
        body.push_str("</ol>");
    }
    let mut params = Vec::new();
    if let Some(query) = query.filter(|query| !query.trim().is_empty()) {
        params.push(format!("q={}", urlencode(query)));
    }
    if let Some(kind) = kind {
        params.push(format!("kind={}", urlencode(kind)));
    }
    let pager = Pager::new(page_number, PACKAGES_PER_PAGE, total_results);
    body.push_str(&pager.nav(&format!("/{slug}/-/docs"), &params.join("&")));
    let _ = write!(
        body,
        "<p class=\"docs-tools\"><a href=\"/{}/-/api/docs/schema\">JSON Schema</a> · <code>apm docs search &lt;query&gt;</code> · editor completion via <code>apm docs lsp</code></p>",
        escape(slug),
    );
    page_with_session(
        "Package documentation",
        &registry_crumbs(slug, &[(format!("/{slug}/-/docs"), "documentation".into())]),
        &body,
        &state_line(status, started),
        session,
    )
}

/// Renders one permanent exact package/version/platform documentation page.
pub fn documentation_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    documentation: &PackageDocumentationPanel,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let document = &documentation.document;
    let mut body = registry_nav(slug, "docs");
    body.push_str("<div class=\"docs-detail-toolbar\">");
    let _ = write!(
        body,
        "<a href=\"/{}/-/docs\">← Search documentation</a><span><a href=\"/{}/-/api/v1/documentation/{}\">Canonical JSON</a> · <a href=\"/{}/-/api/docs/schema\">JSON Schema</a></span>",
        escape(slug),
        escape(slug),
        escape(&documentation.document_sha256),
        escape(slug),
    );
    body.push_str("</div>");
    let _ = write!(
        body,
        "<div class=\"docs-provenance-card\"><div><span>Version</span><strong>{}</strong></div><div><span>Platform</span><strong>{}</strong></div><div><span>Document</span>{}</div><div><span>Semantic schema</span>{}</div><details><summary>Signed Nix object</summary><code>{}</code><p>NAR {}</p></details></div>",
        escape(&document.package.version),
        escape(&document.package.platform),
        hash_value(&documentation.document_sha256),
        hash_value(&document.identity.semantic_schema_sha256),
        escape(&documentation.store_path),
        hash_value(&documentation.nar_hash),
    );
    body.push_str(&document.render_html_fragment());
    body.push_str("<section class=\"docs-offline\"><h2>Use offline</h2><p>This same object is retained with the installed package profile.</p><pre>");
    let _ = write!(
        body,
        "apm docs show {}\napm docs show {} --format man\napm docs schema",
        escape(&document.package.name),
        escape(&document.package.name),
    );
    body.push_str("</pre></section>");
    page_with_session(
        &format!("{} documentation", document.package.name),
        &registry_crumbs(
            slug,
            &[
                (format!("/{slug}/-/docs"), "documentation".into()),
                (String::new(), document.package.name.clone()),
            ],
        ),
        &body,
        &state_line(status, started),
        session,
    )
}

/// Assign a grid glyph index to each release a channel targets,
/// frontier-first, so the newest release is always glyph `0` (`■`).
fn release_glyphs(channel: &ChannelSummary) -> (Vec<String>, BTreeMap<String, usize>) {
    let mut release_order: Vec<String> = Vec::new();
    if let Some(frontier) = &channel.frontier {
        release_order.push(frontier.clone());
    }
    for release in channel.partitions.iter().flatten() {
        if !release_order.contains(release) {
            release_order.push(release.clone());
        }
    }
    let class_for: BTreeMap<String, usize> = release_order
        .iter()
        .enumerate()
        .map(|(i, release)| (release.clone(), i.min(GRID_GLYPHS.len() - 1)))
        .collect();
    (release_order, class_for)
}

/// The managed-cache home: `nix-cache-info` summary, storage usage, GC state,
/// and the substituter setup snippet. No-JS, index-data only.
#[allow(clippy::too_many_arguments)]
pub fn cache_home(
    cache: &crate::db::BinaryCache,
    usage: &crate::db::CacheUsage,
    policy: Option<&crate::db::CacheGcPolicyRecord>,
    subscription_count: usize,
    root_count: usize,
    external_url: &str,
    pubkey: Option<&str>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &cache.slug;
    let mut body = String::new();
    let _ = write!(body, "<h1>Cache {}</h1>\n", escape(&cache.name));
    let _ = write!(
        body,
        "<p class=\"dim\">{} · priority {} · {} compression</p>\n",
        escape(&cache.visibility),
        cache.priority,
        escape(&cache.compression),
    );

    body.push_str("<h2>nix-cache-info</h2>\n");
    let info = vec![
        vec!["StoreDir".to_string(), "/nix/store".to_string()],
        vec!["Priority".to_string(), cache.priority.to_string()],
        vec![
            "WantMassQuery".to_string(),
            if cache.want_mass_query { "1" } else { "0" }.to_string(),
        ],
        vec![
            "Signed".to_string(),
            if pubkey.is_some() { "yes" } else { "no" }.to_string(),
        ],
    ];
    body.push_str(&table(&["field", "value"], &info));

    body.push_str("<h2>Storage</h2>\n");
    let _ = write!(
        body,
        "<p>{} across {} objects</p>\n",
        human_size(usage.used_bytes.max(0) as u64),
        usage.object_count,
    );
    let _ = write!(
        body,
        "<p class=\"dim\">{} retention subscriptions · {} manual retention roots · GC policy {}</p>\n",
        subscription_count,
        root_count,
        if policy.is_some() {
            "configured"
        } else {
            "default (no age sweep)"
        },
    );

    body.push_str("<h2>Use this cache</h2>\n");
    let base = external_url.trim_end_matches('/');
    // A signed cache also needs its public key pinned as a trusted key.
    let trusted_line = match pubkey {
        Some(key) => format!("  extra-trusted-public-keys = {}\n", escape(key)),
        None => String::new(),
    };
    let _ = write!(
        body,
        "<pre>nix.conf:\n  extra-substituters = {}/{}\n{}</pre>\n",
        escape(base),
        escape(slug),
        trusted_line,
    );

    let _ = write!(
        body,
        "<p><a href=\"/{}/-/objects\">browse objects →</a></p>\n",
        escape(slug),
    );

    page_with_session(
        &format!("cache {slug}"),
        &[(String::new(), slug.clone())],
        &body,
        &StateLine::timed(started),
        session,
    )
}

/// A managed cache's object list, with a server-side search box (`?q=`).
pub fn cache_objects(
    cache: &crate::db::BinaryCache,
    objects: &[crate::db::CacheObjectRecord],
    query: Option<&str>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &cache.slug;
    let mut body = String::new();
    let _ = write!(body, "<h1>Objects · {}</h1>\n", escape(&cache.name));
    let _ = write!(
        body,
        "<form method=\"get\" action=\"/{}/-/objects\">\
         <input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"name / hash / deriver\">\
         <button type=\"submit\">search</button></form>\n",
        escape(slug),
        escape(query.unwrap_or("")),
    );
    let rows: Vec<Vec<String>> = objects
        .iter()
        .map(|o| {
            vec![
                format!(
                    "<a href=\"/{}/-/objects/{}\">{}</a>",
                    escape(slug),
                    escape(&o.store_hash),
                    escape(&o.store_name),
                ),
                escape(&o.compression),
                human_size(o.file_size.max(0) as u64),
            ]
        })
        .collect();
    body.push_str(&live_table(
        &["store path", "compression", "size"],
        &rows,
        "objects",
    ));
    page_with_session(
        &format!("objects · {slug}"),
        &[
            (format!("/{slug}/"), slug.clone()),
            (String::new(), "objects".into()),
        ],
        &body,
        &StateLine::timed(started),
        session,
    )
}

/// One cache object's narinfo metadata and its immediate references.
pub fn cache_object(
    cache: &crate::db::BinaryCache,
    object: &crate::db::CacheObjectRecord,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &cache.slug;
    let mut body = String::new();
    let _ = write!(body, "<h1>{}</h1>\n", escape(&object.store_name));
    let mut fields = vec![
        vec!["StoreHash".to_string(), hash_value(&object.store_hash)],
        vec!["URL".to_string(), escape(&object.nar_url)],
        vec!["Compression".to_string(), escape(&object.compression)],
        vec!["NarHash".to_string(), hash_value(&object.nar_hash)],
        vec![
            "NarSize".to_string(),
            human_size(object.nar_size.max(0) as u64),
        ],
        vec!["FileHash".to_string(), hash_value(&object.file_hash)],
        vec![
            "FileSize".to_string(),
            human_size(object.file_size.max(0) as u64),
        ],
    ];
    if let Some(d) = &object.deriver {
        fields.push(vec![
            "Deriver".to_string(),
            format!("<code>{}</code>", escape(d)),
        ]);
    }
    if let Some(s) = &object.signature {
        fields.push(vec![
            "Sig".to_string(),
            format!("<code>{}</code>", escape(s)),
        ]);
    }
    body.push_str(&table(&["field", "value"], &fields));

    body.push_str("<h2>References</h2>\n");
    if object.references.is_empty() {
        body.push_str("<p class=\"dim\">none</p>\n");
    } else {
        let rows: Vec<Vec<String>> = object
            .references
            .iter()
            .map(|r| {
                vec![format!(
                    "<a href=\"/{}/-/objects/{}\"><code>{}</code></a>",
                    escape(slug),
                    escape(r),
                    escape(r),
                )]
            })
            .collect();
        body.push_str(&table(&["store hash"], &rows));
    }
    let _ = write!(
        body,
        "<p><a href=\"/{}/-/closure/{}\">full transitive closure →</a></p>\n",
        escape(slug),
        escape(&object.store_hash),
    );
    // The NAR explorer is a native-hub feature (it decompresses + parses the
    // archive); on a worker deployment this link downloads the NAR instead.
    if !object.nar_url.is_empty() {
        let _ = write!(
            body,
            "<p><a href=\"/{}/{}?explore=1\">explore NAR files →</a></p>\n",
            escape(slug),
            escape(&object.nar_url),
        );
    }
    page_with_session(
        &format!("{} · {slug}", object.store_name),
        &[
            (format!("/{slug}/"), slug.clone()),
            (format!("/{slug}/-/objects"), "objects".into()),
            (String::new(), object.store_hash.clone()),
        ],
        &body,
        &StateLine::timed(started),
        session,
    )
}

/// A cache object's full transitive closure as a no-JS table (the dependency
/// "graph" in flat form); each present node links to its own object page.
pub fn cache_closure(
    cache: &crate::db::BinaryCache,
    root_hash: &str,
    nodes: &[aos_proto_types::CacheClosureNode],
    total_size: i64,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &cache.slug;
    let mut body = String::new();
    let _ = write!(body, "<h1>Closure of {}</h1>\n", hash_value(root_hash));
    let _ = write!(
        body,
        "<p>{} paths · {} total</p>\n",
        nodes.len(),
        human_size(total_size.max(0) as u64),
    );
    let rows: Vec<Vec<String>> = nodes
        .iter()
        .map(|n| {
            let hash_cell = if n.present {
                hash_value_link(
                    &n.store_hash,
                    &format!("/{slug}/-/objects/{}", n.store_hash),
                )
            } else {
                hash_value(&n.store_hash)
            };
            let size_cell = if n.present {
                human_size(n.file_size.max(0) as u64)
            } else {
                "missing".to_string()
            };
            vec![hash_cell, escape(&n.store_name), size_cell]
        })
        .collect();
    body.push_str(&table(&["store hash", "name", "size"], &rows));
    page_with_session(
        &format!("closure · {slug}"),
        &[
            (format!("/{slug}/"), slug.clone()),
            (format!("/{slug}/-/objects"), "objects".into()),
            (String::new(), "closure".into()),
        ],
        &body,
        &StateLine::timed(started),
        session,
    )
}

/// Render the 16×16 partition grid as a `<pre>` block plus its legend table.
///
/// Shared by the consumer [`channel_page`] and the producer channel rollout
/// console ([`crate::web::console_render::channel_console`]) so both show the
/// identical glyph + color grid — RFC-0004's "ASCII diagrams are content".
#[must_use]
pub fn channel_grid_pre(channel: &ChannelSummary) -> String {
    let (release_order, class_for) = release_glyphs(channel);
    let mut grid = String::new();
    for row in 0..16 {
        for col in 0..16 {
            let bucket = row * 16 + col;
            let cell = match channel.partitions[bucket].as_deref() {
                Some(release) => {
                    let i = class_for
                        .get(release)
                        .copied()
                        .unwrap_or(GRID_GLYPHS.len() - 1);
                    format!("<span class=\"r{i}\">{}</span>", GRID_GLYPHS[i])
                }
                None => "<span class=\"dim\">·</span>".to_string(),
            };
            grid.push_str(&cell);
        }
        grid.push('\n');
    }
    let mut out = format!("<pre class=\"partition-grid\">{grid}</pre>\n");
    let legend_rows: Vec<Vec<String>> = release_order
        .iter()
        .map(|release| {
            let count = channel
                .partitions
                .iter()
                .flatten()
                .filter(|r| *r == release)
                .count();
            let i = class_for
                .get(release)
                .copied()
                .unwrap_or(GRID_GLYPHS.len() - 1);
            vec![
                format!("<span class=\"r{i}\">{}</span>", GRID_GLYPHS[i]),
                escape(release),
                format!("{count} partitions ({}%)", count * 100 / 256),
            ]
        })
        .collect();
    out.push_str(&table(&["glyph", "release", "coverage"], &legend_rows));
    out
}

/// The channel page with the 16×16 partition grid, the anti-rollback
/// floor, and the no-JS `?bucket=` calculator.
pub fn channel_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channel: &ChannelSummary,
    floor: Option<&str>,
    bucket_query: Option<&str>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;

    // Assign glyphs frontier-first so the newest release is always '■'.
    let mut release_order: Vec<String> = Vec::new();
    if let Some(frontier) = &channel.frontier {
        release_order.push(frontier.clone());
    }
    for release in channel.partitions.iter().flatten() {
        if !release_order.contains(release) {
            release_order.push(release.clone());
        }
    }
    let class_for: BTreeMap<&str, usize> = release_order
        .iter()
        .enumerate()
        .map(|(i, release)| (release.as_str(), i.min(GRID_GLYPHS.len() - 1)))
        .collect();

    let hit = bucket_query.and_then(parse_bucket);
    let mut grid = String::new();
    for row in 0..16 {
        for col in 0..16 {
            let bucket = row * 16 + col;
            let cell = match channel.partitions[bucket].as_deref() {
                Some(release) => {
                    let i = class_for
                        .get(release)
                        .copied()
                        .unwrap_or(GRID_GLYPHS.len() - 1);
                    format!("<span class=\"r{i}\">{}</span>", GRID_GLYPHS[i])
                }
                None => "<span class=\"dim\">·</span>".to_string(),
            };
            if hit == Some(bucket as u8) {
                let _ = write!(grid, "<strong class=\"hit\">{cell}</strong>");
            } else {
                grid.push_str(&cell);
            }
        }
        grid.push('\n');
    }

    let mut body = registry_nav(slug, "channels");
    let _ = writeln!(body, "<h1>Channel {}</h1>", escape(&channel.name));
    let frontier = channel.frontier.as_deref().map_or_else(
        || "—".to_string(),
        |release| {
            format!(
                "<strong><a href=\"/{}/-/releases#release-{}\">{}</a></strong> · <a href=\"/{}/-/images?release={}\">images</a>",
                escape(slug),
                urlencode(release),
                escape(release),
                escape(slug),
                urlencode(release),
            )
        },
    );
    let _ = writeln!(
        body,
        "<p>frontier {frontier} · floor {} · {} of 256 partitions assigned</p>",
        match floor {
            Some(floor) => format!(
                "<strong><a href=\"/{}/-/releases#release-{}\">{}</a></strong>",
                escape(slug),
                urlencode(floor),
                escape(floor),
            ),
            None => "<span class=\"dim\">—</span>".to_string(),
        },
        channel.partitions.iter().flatten().count(),
    );

    let _ = writeln!(
        body,
        "<form method=\"get\"><label>which version will my host get? bucket \
         <input name=\"bucket\" value=\"{}\" size=\"6\"></label> <button>resolve</button></form>",
        escape(bucket_query.unwrap_or("")),
    );
    if let Some(raw) = bucket_query {
        match parse_bucket(raw) {
            Some(bucket) => {
                let target = match channel.partitions[bucket as usize].as_deref() {
                    Some(release) => format!(
                        "release <strong><a href=\"/{}/-/releases#release-{}\">{}</a></strong> · <a href=\"/{}/-/images?release={}\">images</a>",
                        escape(slug),
                        urlencode(release),
                        escape(release),
                        escape(slug),
                        urlencode(release),
                    ),
                    None => "<span class=\"dim\">unassigned</span>".to_string(),
                };
                let _ = writeln!(
                    body,
                    "<p>bucket <strong>0x{bucket:02X}</strong> ({bucket}) → {target}</p>",
                );
            }
            None => {
                let _ = writeln!(
                    body,
                    "<p class=\"bad\">unrecognized bucket \"{}\" (decimal or hex, 0..255)</p>",
                    escape(raw),
                );
            }
        }
    }

    let _ = writeln!(body, "<pre class=\"partition-grid\">{grid}</pre>");

    let legend_rows: Vec<Vec<String>> = release_order
        .iter()
        .map(|release| {
            let count = channel
                .partitions
                .iter()
                .flatten()
                .filter(|r| *r == release)
                .count();
            let i = class_for
                .get(release.as_str())
                .copied()
                .unwrap_or(GRID_GLYPHS.len() - 1);
            vec![
                format!("<span class=\"r{i}\">{}</span>", GRID_GLYPHS[i]),
                format!(
                    "<a href=\"/{}/-/releases#release-{}\">{}</a> · <a href=\"/{}/-/images?release={}\">images</a>",
                    escape(slug),
                    urlencode(release),
                    escape(release),
                    escape(slug),
                    urlencode(release),
                ),
                format!("{count} partitions ({}%)", count * 100 / 256),
            ]
        })
        .collect();
    body.push_str(&table(&["glyph", "release", "coverage"], &legend_rows));
    body.push_str(
        "<p class=\"dim\">Your bucket is the low byte of sha256(registry‑name \\0 salt) — see \
         <code>[registry.state] bucket</code> in your registries.d entry, or resolve it with the \
         form above (row = bucket / 16, column = bucket % 16).</p>\n",
    );

    page_with_session(
        &format!("{} channel", channel.name),
        &registry_crumbs(
            slug,
            &[
                (format!("/{slug}/-/channels"), "channels".into()),
                (String::new(), channel.name.clone()),
            ],
        ),
        &body,
        &state_line(status, started),
        session,
    )
}

/// The channels index page.
pub fn channels_index(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channels: &[ChannelSummary],
    page_number: usize,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    let pager = Pager::new(page_number, LIST_PER_PAGE, channels.len());
    let rows: Vec<Vec<String>> = pager
        .slice(channels)
        .iter()
        .map(|channel| {
            vec![
                format!(
                    "<a href=\"/{}/-/channels/{}\">{}</a>",
                    escape(slug),
                    escape(&channel.name),
                    escape(&channel.name),
                ),
                channel.frontier.as_deref().map_or_else(
                    || "—".to_string(),
                    |release| {
                        format!(
                            "<a href=\"/{}/-/releases#release-{}\">{}</a>",
                            escape(slug),
                            urlencode(release),
                            escape(release),
                        )
                    },
                ),
                format!("{}/256", channel.partitions.iter().flatten().count()),
            ]
        })
        .collect();
    let mut body = registry_nav(slug, "channels");
    body.push_str("<h1>Channels</h1>\n");
    body.push_str(&table(&["channel", "frontier", "assigned"], &rows));
    body.push_str(&pager.nav(&format!("/{slug}/-/channels"), ""));
    page_with_session(
        &format!("{slug} channels"),
        &registry_crumbs(slug, &[(String::new(), "channels".into())]),
        &body,
        &state_line(status, started),
        session,
    )
}

fn image_target_label(target: ImageTarget) -> &'static str {
    match target {
        ImageTarget::BareMetal => "bare metal",
        ImageTarget::QemuKvm => "QEMU/KVM",
        ImageTarget::Openstack => "OpenStack",
        ImageTarget::Vmware => "VMware",
        ImageTarget::HyperV => "Hyper-V",
    }
}

fn image_target_token(target: ImageTarget) -> &'static str {
    match target {
        ImageTarget::BareMetal => "bare-metal",
        ImageTarget::QemuKvm => "qemu-kvm",
        ImageTarget::Openstack => "openstack",
        ImageTarget::Vmware => "vmware",
        ImageTarget::HyperV => "hyper-v",
    }
}

fn image_verification_label(
    state: ImageVerificationState,
) -> (&'static str, &'static str, &'static str) {
    match state {
        ImageVerificationState::Unsigned => (
            "UKI unsigned",
            "warn",
            "The unified kernel image has no Authenticode signature.",
        ),
        ImageVerificationState::SignedUnverified => (
            "UKI signed, policy unverified",
            "warn",
            "The unified kernel image is signed, but no committed active-certificate policy verified its signer.",
        ),
        ImageVerificationState::PolicyVerified => (
            "UKI policy verified",
            "ok",
            "The unified kernel image signer was verified against committed Secure Boot certificate policy.",
        ),
    }
}

fn image_compression_label(compression: ImageCompression) -> &'static str {
    match compression {
        ImageCompression::None => "none",
        ImageCompression::Zstd => "zstd",
    }
}

/// Simultaneous structured and free-text image-catalog filters.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImageBrowse<'a> {
    /// Requested 1-based result page.
    pub page_number: usize,
    /// Search fallback across package, release, channel, architecture, format, and target.
    pub query: Option<&'a str>,
    /// Exact release identity.
    pub release: Option<&'a str>,
    /// Exact channel identity.
    pub channel: Option<&'a str>,
    /// Exact architecture identity.
    pub architecture: Option<&'a str>,
    /// Exact disk format.
    pub format: Option<&'a str>,
    /// Exact end-user target token.
    pub target: Option<&'a str>,
}

fn selected(value: &str, current: Option<&str>) -> &'static str {
    if current == Some(value) {
        " selected"
    } else {
        ""
    }
}

fn image_select(
    name: &str,
    all_label: &str,
    values: &[(String, String)],
    current: Option<&str>,
) -> String {
    let mut html = format!(
        "<label>{}<select name=\"{}\"><option value=\"\">{}</option>",
        escape(name),
        escape(name),
        escape(all_label),
    );
    for (value, label) in values {
        let _ = write!(
            html,
            "<option value=\"{}\"{}>{}</option>",
            escape(value),
            selected(value, current),
            escape(label),
        );
    }
    html.push_str("</select></label>");
    html
}

/// The signed system-image catalog with end-user disk download actions.
pub fn images_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    images: &[IndexedSystemImage],
    channels: &[ChannelSummary],
    download_base: Option<&str>,
    browse: &ImageBrowse<'_>,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;
    fn normalize(value: Option<&str>) -> Option<&str> {
        value.map(str::trim).filter(|value| !value.is_empty())
    }
    let query = normalize(browse.query);
    let needle = query.map(str::to_lowercase);
    let release = normalize(browse.release);
    let channel = normalize(browse.channel);
    let architecture = normalize(browse.architecture);
    let format = normalize(browse.format);
    let target = normalize(browse.target);

    let mut release_values = images
        .iter()
        .map(|image| image.release.clone())
        .collect::<Vec<_>>();
    release_values.sort();
    release_values.dedup();
    let mut architecture_values = images
        .iter()
        .map(|image| image.delivery.architecture.clone())
        .collect::<Vec<_>>();
    architecture_values.sort();
    architecture_values.dedup();
    let mut format_values = images
        .iter()
        .map(|image| image.format.clone())
        .collect::<Vec<_>>();
    format_values.sort();
    format_values.dedup();
    let mut sorted = images.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| {
        right
            .release
            .cmp(&left.release)
            .then_with(|| left.package.cmp(&right.package))
            .then_with(|| left.delivery.architecture.cmp(&right.delivery.architecture))
            .then_with(|| left.format.cmp(&right.format))
    });
    let mut rows = Vec::new();
    for image in sorted {
        let channel_names = channels
            .iter()
            .filter(|channel| {
                channel.frontier.as_deref() == Some(image.release.as_str())
                    || channel
                        .partitions
                        .iter()
                        .flatten()
                        .any(|release| release == &image.release)
            })
            .map(|channel| channel.name.as_str())
            .collect::<Vec<_>>();
        let targets = image
            .delivery
            .compatible_targets
            .iter()
            .copied()
            .map(image_target_label)
            .collect::<Vec<_>>()
            .join(", ");
        let target_tokens = image
            .delivery
            .compatible_targets
            .iter()
            .copied()
            .map(image_target_token)
            .collect::<Vec<_>>();
        if release.is_some_and(|value| value != image.release)
            || channel.is_some_and(|value| !channel_names.contains(&value))
            || architecture.is_some_and(|value| value != image.delivery.architecture)
            || format.is_some_and(|value| value != image.format)
            || target.is_some_and(|value| !target_tokens.contains(&value))
        {
            continue;
        }
        let searchable = format!(
            "{} {} {} {} {} {} {} {}",
            image.package,
            image.release,
            channel_names.join(" "),
            image.delivery.architecture,
            image.format,
            targets,
            image.delivery.sha256,
            image.delivery.filename,
        )
        .to_lowercase();
        if needle
            .as_ref()
            .is_some_and(|needle| !searchable.contains(needle))
        {
            continue;
        }
        let (boot_verification, boot_class, boot_explanation) =
            image_verification_label(image.delivery.uki.verification);
        let channel_cell = if channel_names.is_empty() {
            "—".to_string()
        } else {
            channel_names
                .iter()
                .map(|name| {
                    format!(
                        "<a href=\"/{}/-/channels/{}\">{}</a>",
                        escape(slug),
                        urlencode(name),
                        escape(name),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        let download = if image.store_path.is_empty() {
            download_base.map_or_else(
                || "<span class=\"dim\">route unavailable</span>".to_string(),
                |base| {
                    format!(
                        "<a href=\"{}/{}\" download=\"{}\">Download</a>",
                        escape(base.trim_end_matches('/')),
                        escape(&image.delivery.object_key),
                        escape(&image.delivery.filename),
                    )
                },
            )
        } else {
            "<span class=\"ok\" title=\"Delivered from the registry cache with aos image download\">CDN / CLI</span>".to_string()
        };
        let (store_path, nar_identity) = if image.store_path.is_empty() {
            (
                "<span class=\"dim\">not store-backed</span>".to_string(),
                "—".to_string(),
            )
        } else {
            (
                format!(
                    "<code class=\"image-store-path\">{}</code>",
                    escape(&image.store_path),
                ),
                format!(
                    "{} <span class=\"dim\">{}</span>",
                    hash_value(&image.nar_hash),
                    human_size(image.nar_size),
                ),
            )
        };
        let verification = format!(
            "<span class=\"ok\">release verified</span> · \
             <span class=\"{boot_class}\" title=\"{boot_explanation}\">{boot_verification}</span>"
        );
        let encoding = format!(
            "{} · {}",
            escape(&image.delivery.media_type),
            image_compression_label(image.delivery.compression),
        );
        let uki = format!(
            "{} · <code>{}</code> · {}",
            escape(&image.delivery.uki.filename),
            escape(&image.delivery.uki.esp_path),
            human_size(image.delivery.uki.byte_size),
        );
        let image_info = format!(
            "{} · {}",
            escape(&image.delivery.image_info.filename),
            hash_value(&image.delivery.image_info.sha256),
        );
        rows.push(format!(
            "<tbody class=\"image-artifact\">\
             <tr class=\"image-summary\"><td>{release}<div class=\"subline\">{package}</div></td>\
             <td>{channel}</td><td>{architecture}</td><td>{format}</td><td>{size}</td><td>{download}</td></tr>\
             <tr class=\"image-detail\"><th scope=\"row\">details</th><td colspan=\"5\">\
             <table class=\"image-facts\" aria-label=\"Details for {filename}\"><tbody>\
             <tr><th scope=\"row\">targets</th><td>{targets}</td><th scope=\"row\">verification</th><td>{verification}</td></tr>\
             <tr><th scope=\"row\">file</th><td>{filename}</td><th scope=\"row\">encoding</th><td>{encoding}</td></tr>\
             <tr><th scope=\"row\">file SHA-256</th><td>{checksum}</td><th scope=\"row\">logical disk</th><td>{logical_checksum}</td></tr>\
             <tr><th scope=\"row\">rootfs SHA-256</th><td>{rootfs_checksum}</td><th scope=\"row\">UKI SHA-256</th><td>{uki_checksum}</td></tr>\
             <tr><th scope=\"row\">store path</th><td>{store_path}</td><th scope=\"row\">NAR</th><td>{nar_identity}</td></tr>\
             <tr><th scope=\"row\">UKI</th><td>{uki}</td><th scope=\"row\">image info</th><td>{image_info}</td></tr>\
             </tbody></table></td></tr></tbody>\n",
            release = format!(
                "<a href=\"/{}/-/releases#release-{}\">{}</a>",
                escape(slug),
                urlencode(&image.release),
                escape(&image.release),
            ),
            package = escape(&image.package),
            channel = channel_cell,
            architecture = escape(&image.delivery.architecture),
            format = escape(&image.format),
            size = human_size(image.delivery.byte_size),
            targets = escape(&targets),
            checksum = hash_value(&image.delivery.sha256),
            logical_checksum = hash_value(&image.delivery.logical_disk_sha256),
            rootfs_checksum = hash_value(&image.delivery.rootfs_sha256),
            uki_checksum = hash_value(&image.delivery.uki.sha256),
            filename = escape(&image.delivery.filename),
        ));
    }

    let total_matches = rows.len();
    let pager = Pager::new(browse.page_number, IMAGES_PER_PAGE, total_matches);
    let pager_query = [
        ("q", query),
        ("release", release),
        ("channel", channel),
        ("architecture", architecture),
        ("format", format),
        ("target", target),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| format!("{name}={}", urlencode(value))))
    .collect::<Vec<_>>()
    .join("&");

    let mut body = registry_nav(slug, "images");
    body.push_str("<h1>Images</h1>\n");
    let release_options = release_values
        .into_iter()
        .map(|value| (value.clone(), value))
        .collect::<Vec<_>>();
    let channel_options = channels
        .iter()
        .map(|channel| (channel.name.clone(), channel.name.clone()))
        .collect::<Vec<_>>();
    let architecture_options = architecture_values
        .into_iter()
        .map(|value| (value.clone(), value))
        .collect::<Vec<_>>();
    let format_options = format_values
        .into_iter()
        .map(|value| (value.clone(), value))
        .collect::<Vec<_>>();
    let target_options = [
        ("bare-metal".to_string(), "Bare metal".to_string()),
        ("qemu-kvm".to_string(), "QEMU/KVM".to_string()),
        ("openstack".to_string(), "OpenStack".to_string()),
        ("vmware".to_string(), "VMware".to_string()),
        ("hyper-v".to_string(), "Hyper-V".to_string()),
    ];
    let _ = write!(
        body,
        "<form method=\"get\" data-live class=\"image-filters\"><div class=\"image-filter-fields\">{}{}{}{}{}\
         <label>search<input type=\"search\" name=\"q\" value=\"{}\" \
         placeholder=\"package, checksum, or filename\"></label></div>\
         <div class=\"image-filter-actions\"><button>filter</button>\
         <a href=\"/{}/-/images\">clear</a></div></form>",
        image_select("release", "all releases", &release_options, release),
        image_select("channel", "all channels", &channel_options, channel),
        image_select(
            "architecture",
            "all architectures",
            &architecture_options,
            architecture
        ),
        image_select("format", "all formats", &format_options, format),
        image_select("target", "all targets", &target_options, target),
        escape(browse.query.unwrap_or("")),
        escape(slug),
    );
    if total_matches == 0 {
        body.push_str("<p class=\"dim\">No matching signed disk images are published.</p>\n");
    } else {
        let _ = writeln!(
            body,
            "<p class=\"dim\">{total_matches} images · page {} of {}</p>",
            pager.page(),
            pager.pages(),
        );
        body.push_str(
            "<div class=\"table-scroll\" role=\"region\" aria-label=\"System images\" tabindex=\"0\">\n\
             <table class=\"images-table\"><thead><tr><th>release</th><th>channel</th>\
             <th>architecture</th><th>format</th><th>size</th><th>download</th></tr></thead>\n",
        );
        for row in pager.slice(&rows) {
            body.push_str(row);
        }
        body.push_str("</table></div>\n");
        body.push_str(&pager.nav(&format!("/{slug}/-/images"), &pager_query));
    }
    page_with_session(
        &format!("{slug} images"),
        &registry_crumbs(slug, &[(String::new(), "images".into())]),
        &body,
        &state_line(status, started),
        session,
    )
}

/// The releases page: every verified signed tag, newest first by semver.
pub fn releases_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    releases: &[ReleaseRow],
    package_counts: &[(String, usize)],
    image_counts: &[(String, usize)],
    page_number: usize,
    started: Instant,
    session: &SessionIndicator,
) -> String {
    let slug = &registry.slug;

    // Sort newest-first by parsed semver (ties by tag time); rows whose
    // version does not parse sort last, ordered lexically.
    let mut sorted: Vec<&ReleaseRow> = releases.iter().collect();
    sorted.sort_by(|a, b| {
        match (
            semver::Version::parse(&a.semver),
            semver::Version::parse(&b.semver),
        ) {
            (Ok(va), Ok(vb)) => vb.cmp(&va).then_with(|| b.tagged_at.cmp(&a.tagged_at)),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => b.semver.cmp(&a.semver),
        }
    });

    let pager = Pager::new(page_number, LIST_PER_PAGE, sorted.len());
    let rows: Vec<Vec<String>> = pager
        .slice(&sorted)
        .iter()
        .map(|release| {
            let package_count = package_counts
                .iter()
                .find_map(|(version, count)| (version == &release.semver).then_some(*count))
                .unwrap_or_default();
            let image_count = image_counts
                .iter()
                .find_map(|(version, count)| (version == &release.semver).then_some(*count))
                .unwrap_or_default();
            vec![
                format!(
                    "<span id=\"release-{}\">{}</span>",
                    urlencode(&release.semver),
                    escape(&release.semver),
                ),
                format!(
                    "<span class=\"release-shortlinks\">\
                     <a class=\"release-count-pill\" href=\"/{}/-/images?release={}\">images <strong>{image_count}</strong></a>\
                     <a class=\"release-count-pill\" href=\"/{}/-/packages?release={}\">packages <strong>{package_count}</strong></a>\
                     </span>",
                    escape(slug),
                    urlencode(&release.semver),
                    escape(slug),
                    urlencode(&release.semver),
                ),
                hash_value(&release.commit_oid),
                match &release.signer {
                    Some(signer) => format!(
                        "<span class=\"ok\">✓ signed</span> <span class=\"dim\">{}…</span>",
                        escape(&signer[..signer.len().min(20)]),
                    ),
                    None => "<span class=\"dim\">unverified</span>".to_string(),
                },
                if release.pack_present {
                    "<span class=\"ok\">✓ pack</span>".to_string()
                } else {
                    "<span class=\"dim\">— none</span>".to_string()
                },
                release
                    .tagged_at
                    .map(|t| format!("{} <span class=\"dim\">(unix {t})</span>", ago(t)))
                    .unwrap_or_else(|| "—".to_string()),
            ]
        })
        .collect();
    let mut body = registry_nav(slug, "releases");
    body.push_str("<h1>Releases</h1>\n");
    body.push_str(&table(
        &[
            "release",
            "contents",
            "commit",
            "signature",
            "pack",
            "tagged",
        ],
        &rows,
    ));
    body.push_str(&pager.nav(&format!("/{slug}/-/releases"), ""));
    page_with_session(
        &format!("{slug} releases"),
        &registry_crumbs(slug, &[(String::new(), "releases".into())]),
        &body,
        &state_line(status, started),
        session,
    )
}

/// Render a committed cache stack as an ASCII tree of `try`/`mirror`/endpoint
/// nodes, annotating each endpoint with the coverage its latest run reported.
///
/// `coverage_by_url` maps a cache URL to a short coverage label (e.g.
/// `"100%"`, `"50%"`, `"unreachable"`); endpoints absent from the map render
/// without an annotation. Mirror groups are labeled so a member shortfall
/// reads as a replication failure rather than a fall-through.
fn render_cache_stack(stack: &StackNode, coverage_by_url: &BTreeMap<&str, String>) -> String {
    fn walk(
        node: &StackNode,
        prefix: &str,
        coverage_by_url: &BTreeMap<&str, String>,
        out: &mut String,
    ) {
        match node {
            StackNode::Endpoint(url) => {
                let note = coverage_by_url
                    .get(url.as_str())
                    .map(|c| format!("  [{}]", escape(c)))
                    .unwrap_or_default();
                let _ = writeln!(out, "{prefix}{}{note}", escape(url));
            }
            StackNode::Try(members) | StackNode::Mirror(members) => {
                let kind = if matches!(node, StackNode::Mirror(_)) {
                    "mirror (every member must be complete)"
                } else {
                    "try (fall-through; first hit wins)"
                };
                let _ = writeln!(out, "{prefix}{kind}");
                let child_prefix = format!("{prefix}  ");
                for member in members {
                    walk(member, &child_prefix, coverage_by_url, out);
                }
            }
        }
    }
    let mut out = String::from("<h2>Cache stack</h2>\n<pre class=\"cache-stack\">");
    walk(stack, "", coverage_by_url, &mut out);
    out.push_str("</pre>\n");
    out
}

/// The health page: the cache × coverage validation matrix plus the
/// missing-hash drill-down for each cache with gaps.
///
/// When the registry committed a `[caches]` stack, the stack is rendered as an
/// ASCII tree with per-endpoint coverage, and any `mirror` group whose
/// members are not individually complete is flagged as a replication
/// shortfall above the matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteHealthRow {
    /// Stable route identity.
    pub id: String,
    /// Exact endpoint identity.
    pub endpoint_id: String,
    /// Canonical base path.
    pub base_path: String,
    /// Serving mode.
    pub mode: String,
    /// Enabled desired state.
    pub enabled: bool,
    /// Capabilities selected by the immutable current route snapshot.
    pub capabilities: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn health_page(
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    runs: &[(ValidationRunRow, Vec<String>, Vec<String>)],
    stack: Option<&StackNode>,
    cache_probes: &[CacheProbeRow],
    repair_jobs: &[RepairJobRow],
    routes: &[RouteHealthRow],
    started: Instant,
    session: &SessionIndicator,
) -> String {
    /// Missing hashes shown per cache before collapsing to "and N more".
    const MISSING_DISPLAY_CAP: usize = 100;

    let slug = &registry.slug;
    let mut body = registry_nav(slug, "health");
    body.push_str("<h1>Health</h1>\n");

    let (index_state, index_detail) = match status {
        Some(status) => {
            let class = match status.state.as_str() {
                "fresh" => "ok",
                "indexing" | "stale" => "warn",
                _ => "bad",
            };
            let detail = status.error.clone().unwrap_or_else(|| {
                let commit = status
                    .last_indexed_commit
                    .as_deref()
                    .map(hash_value)
                    .unwrap_or_else(|| "no indexed commit".to_string());
                status.indexed_at.map_or(commit.clone(), |indexed_at| {
                    format!("{commit}, indexed {}", ago(indexed_at))
                })
            });
            (
                format!("<span class=\"{class}\">{}</span>", escape(&status.state)),
                detail,
            )
        }
        None => (
            "<span class=\"bad\">unavailable</span>".to_string(),
            "No registry index status is available.".to_string(),
        ),
    };
    let enabled_routes = routes.iter().filter(|route| route.enabled).count();
    let validation_state = if runs.is_empty() {
        "<span class=\"warn\">not run</span>".to_string()
    } else if runs
        .iter()
        .any(|(run, _, _)| !run.reachable || run.missing > 0)
    {
        "<span class=\"warn\">findings</span>".to_string()
    } else {
        "<span class=\"ok\">passing</span>".to_string()
    };
    let summary_rows = vec![
        vec![
            "Registry index".to_string(),
            index_state,
            escape(&index_detail),
        ],
        vec![
            "Cache stack".to_string(),
            if stack.is_some() {
                "<span class=\"ok\">configured</span>".to_string()
            } else {
                "<span class=\"warn\">not configured</span>".to_string()
            },
            if stack.is_some() {
                "Committed consumer cache policy is available.".to_string()
            } else {
                "No consumer cache endpoints are configured.".to_string()
            },
        ],
        vec![
            "Cache validation".to_string(),
            validation_state,
            if runs.is_empty() {
                "No validation job has recorded a result.".to_string()
            } else {
                format!("Latest results for {} cache endpoint(s).", runs.len())
            },
        ],
        vec![
            "Delivery routes".to_string(),
            if enabled_routes > 0 {
                "<span class=\"ok\">configured</span>".to_string()
            } else {
                "<span class=\"warn\">not configured</span>".to_string()
            },
            format!("{enabled_routes} enabled of {} total.", routes.len()),
        ],
    ];
    body.push_str("<h2>Summary</h2>\n");
    body.push_str(&table(&["component", "state", "detail"], &summary_rows));

    // Per-cache coverage labels, keyed by URL, drawn from the latest runs.
    let coverage_by_url: BTreeMap<&str, String> = runs
        .iter()
        .map(|(run, _, _)| {
            let label = if !run.reachable {
                "unreachable".to_string()
            } else if run.checked == 0 {
                "n/a".to_string()
            } else {
                let covered = run.checked.saturating_sub(run.missing);
                format!("{:.0}%", covered as f64 * 100.0 / run.checked as f64)
            };
            (run.cache_url.as_str(), label)
        })
        .collect();

    if let Some(stack) = stack {
        body.push_str(&render_cache_stack(stack, &coverage_by_url));
        // Flag mirror groups whose members are not all complete.
        let missing_by_url: BTreeMap<&str, u64> = runs
            .iter()
            .map(|(run, _, _)| (run.cache_url.as_str(), run.missing))
            .collect();
        let mut shortfalls = String::new();
        for (group_index, group) in stack.mirror_groups().iter().enumerate() {
            for member in group {
                let missing = missing_by_url.get(member.as_str()).copied().unwrap_or(0);
                if missing > 0 {
                    let _ = writeln!(
                        shortfalls,
                        "<li>mirror group {group_index}: <code>{}</code> missing {missing}</li>",
                        escape(member),
                    );
                }
            }
        }
        if !shortfalls.is_empty() {
            body.push_str("<h2>Mirror replication shortfalls</h2>\n<ul class=\"shortfall\">\n");
            body.push_str(&shortfalls);
            body.push_str("</ul>\n");
        }
    }

    if runs.is_empty() {
        body.push_str("<h2>Cache validation</h2>\n");
        if stack.is_some() {
            body.push_str(
                "<p class=\"warn\">Not yet validated. No validation job has recorded a result \n\
                 for the current cache stack.</p>\n",
            );
        } else {
            body.push_str(
                "<p class=\"dim\">No cache stack is configured, so there is nothing to \n\
                 validate.</p>\n",
            );
        }
    } else {
        body.push_str("<h2>Cache validation</h2>\n");
        let rows: Vec<Vec<String>> = runs
            .iter()
            .map(|(run, _, corrupt)| {
                let [status, coverage, checked, probed] = validation_cells(Some(run));
                // Missing here is the *absent* count (total problems minus
                // corruption), so the two columns read independently.
                let corrupt_count = corrupt.len() as u64;
                let absent = run.missing.saturating_sub(corrupt_count);
                let corrupt_cell = if corrupt_count > 0 {
                    format!("<span class=\"bad\">{corrupt_count}</span>")
                } else {
                    "0".to_string()
                };
                vec![
                    format!("<code>{}</code>", escape(&run.cache_url)),
                    escape(&run.depth),
                    checked,
                    absent.to_string(),
                    corrupt_cell,
                    coverage,
                    status,
                    probed,
                ]
            })
            .collect();
        body.push_str(&table(
            &[
                "cache", "depth", "checked", "missing", "corrupt", "coverage", "status", "finished",
            ],
            &rows,
        ));

        for (run, missing, corrupt) in runs {
            if !missing.is_empty() {
                let _ = write!(
                    body,
                    "<h2>Missing from {}</h2>\n<pre>",
                    escape(&run.cache_url),
                );
                for hash in missing.iter().take(MISSING_DISPLAY_CAP) {
                    let _ = writeln!(body, "{}", escape(hash));
                }
                if missing.len() > MISSING_DISPLAY_CAP {
                    let _ = writeln!(body, "… and {} more", missing.len() - MISSING_DISPLAY_CAP);
                }
                body.push_str("</pre>\n");
            }
            // Deep-validation corruption is flagged distinctly: these hashes
            // are *present* but their bytes do not match — a copy cannot
            // repair them, the cache must be re-uploaded from a good source.
            if !corrupt.is_empty() {
                let _ = write!(
                    body,
                    "<h2 class=\"bad\">Corrupt in {}</h2>\n\
                     <p class=\"dim\">Content hash mismatch — re-upload required \
                     (not repairable by copy).</p>\n<pre>",
                    escape(&run.cache_url),
                );
                for hash in corrupt.iter().take(MISSING_DISPLAY_CAP) {
                    let _ = writeln!(body, "{}", escape(hash));
                }
                if corrupt.len() > MISSING_DISPLAY_CAP {
                    let _ = writeln!(body, "… and {} more", corrupt.len() - MISSING_DISPLAY_CAP);
                }
                body.push_str("</pre>\n");
            }
        }
    }

    if !repair_jobs.is_empty() {
        body.push_str("<h2>Repair history</h2>\n");
        let rows: Vec<Vec<String>> = repair_jobs
            .iter()
            .map(|job| {
                let class = match job.status.as_str() {
                    "done" => "ok",
                    "plan_only" => "warn",
                    _ => "bad",
                };
                vec![
                    hash_value(&job.store_hash),
                    format!("<code>{}</code>", escape(&job.cache_url)),
                    format!("<code>{}</code>", escape(&job.source_cache_url)),
                    format!("<span class=\"{class}\">{}</span>", escape(&job.status)),
                    escape(job.error.as_deref().unwrap_or("")),
                    ago(job.created_at),
                ]
            })
            .collect();
        body.push_str(&table(
            &["hash", "target", "source", "status", "error", "when"],
            &rows,
        ));
    }

    if !cache_probes.is_empty() {
        body.push_str("<h2>Cache freshness</h2>\n");
        let rows: Vec<Vec<String>> = cache_probes
            .iter()
            .map(|probe| {
                let class = match probe.status.as_str() {
                    "ok" => "ok",
                    "stale" => "warn",
                    _ => "bad",
                };
                vec![
                    format!("<code>{}</code>", escape(&probe.cache_url)),
                    format!("<span class=\"{class}\">{}</span>", escape(&probe.status)),
                    format!("{} ms", probe.latency_ms),
                    ago(probe.checked_at),
                ]
            })
            .collect();
        body.push_str(&table(&["cache", "status", "latency", "checked"], &rows));
    }

    if !routes.is_empty() {
        body.push_str("<h2>Routes</h2>\n");
        let rows: Vec<Vec<String>> = routes
            .iter()
            .map(|route| {
                vec![
                    format!("<code>{}</code>", escape(&route.id)),
                    format!("<code>{}</code>", escape(&route.endpoint_id)),
                    format!("<code>{}</code>", escape(&route.base_path)),
                    escape(&route.mode),
                    route.capabilities.join("+"),
                    if route.enabled { "enabled" } else { "disabled" }.to_string(),
                ]
            })
            .collect();
        body.push_str(&table(
            &[
                "route",
                "endpoint",
                "base path",
                "mode",
                "audiences",
                "desired",
            ],
            &rows,
        ));
    }

    page_with_session(
        &format!("{slug} health"),
        &registry_crumbs(slug, &[(String::new(), "health".into())]),
        &body,
        &state_line(status, started),
        session,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An anonymous session indicator for the page-builder tests.
    fn anon() -> SessionIndicator {
        SessionIndicator::default()
    }

    fn registry() -> RegistryRecord {
        RegistryRecord {
            id: 1,
            stable_id: "registry:00000000000000000000000000000001".into(),
            scope_key: "registry:00000000000000000000000000000001".into(),
            owner_scope_key: "instance".into(),
            slug: "demo".into(),
            trust_keys: vec!["demo:Ed25519:AAAA".into()],
            require_signatures: true,
            org_id: None,
            project_path: String::new(),
            visibility: "public".into(),
            crawl_policy: "allow_all".into(),
            llms_txt_body: None,
            resource_version: 1,
            updated_at: 0,
        }
    }

    fn setup(registry: &RegistryRecord, url: &str, caches: &[(String, u32)]) -> RegistrySetup {
        RegistrySetup::new(registry, None, Some(url), caches)
    }

    fn documentation_panel(summary: &str) -> PackageDocumentationPanel {
        let mut document = aos_doc_model::PackageDocumentation {
            schema: aos_doc_model::DOCUMENT_SCHEMA.into(),
            package: aos_doc_model::DocumentedPackage {
                name: "nginx".into(),
                version: "1.30.4".into(),
                platform: "x86_64-linux".into(),
                summary: summary.into(),
                homepage: Some("https://nginx.org/".into()),
                license: "BSD-2-Clause".into(),
            },
            identity: aos_doc_model::DocumentationIdentity {
                semantic_schema_sha256: format!("sha256:{}", "0".repeat(64)),
                runtime_nar_hash: format!("sha256:{}", "1".repeat(64)),
                config_module_nar_hash: None,
                system_module_nar_hash: None,
                expose_artifact_nar_hash: None,
                source_nar_hash: format!("sha256:{}", "2".repeat(64)),
            },
            sections: Vec::new(),
            options: Vec::new(),
            runtime: aos_doc_model::RuntimeSurface::default(),
        };
        document.identity.semantic_schema_sha256 = document
            .computed_semantic_schema_sha256()
            .expect("semantic schema");
        PackageDocumentationPanel {
            document,
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-nginx-docs.json".into(),
            document_sha256: format!("sha256:{}", "3".repeat(64)),
            nar_hash: format!("sha256:{}", "4".repeat(64)),
        }
    }

    fn indexed_image(format: &str, release: &str) -> IndexedSystemImage {
        use aos_registry_surface::manifest::{
            immutable_image_info_object_key, immutable_image_object_key, ImageCompression,
            ImageDelivery, ImageInfoReference, ImageUkiIdentity,
        };

        let (sha256, extension, media_type, targets) = match format {
            "raw" => (
                "a".repeat(64),
                "img.zst",
                "application/vnd.aos.disk-image.raw+zstd",
                vec![ImageTarget::BareMetal],
            ),
            "qcow2" => (
                "b".repeat(64),
                "qcow2",
                "application/vnd.aos.disk-image.qcow2",
                vec![ImageTarget::QemuKvm, ImageTarget::Openstack],
            ),
            other => panic!("unsupported image fixture {other}"),
        };
        let filename = format!("aos-{release}.{extension}");
        let info_sha256 = "c".repeat(64);
        IndexedSystemImage {
            package: "aos-system".into(),
            release: release.into(),
            platform: "x86_64-linux".into(),
            format: format.into(),
            store_path: format!("/nix/store/{}-aos-image", "0".repeat(32)),
            nar_hash: format!("sha256:{}", "0".repeat(52)),
            nar_size: 8192,
            delivery: ImageDelivery {
                schema_version: 1,
                release: release.into(),
                platform: "x86_64-linux".into(),
                architecture: "x86_64".into(),
                logical_image_id: "d".repeat(64),
                logical_disk_sha256: "a".repeat(64),
                rootfs_sha256: "e".repeat(64),
                filename: filename.clone(),
                object_key: immutable_image_object_key(&sha256, &filename),
                media_type: media_type.into(),
                compression: if format == "raw" {
                    ImageCompression::Zstd
                } else {
                    ImageCompression::None
                },
                byte_size: 4096,
                sha256: sha256.clone(),
                compatible_targets: targets,
                uki: ImageUkiIdentity {
                    filename: "aos.efi".into(),
                    esp_path: "EFI/Linux/aos.efi".into(),
                    byte_size: 1024,
                    sha256: "f".repeat(64),
                    verification: ImageVerificationState::PolicyVerified,
                    signer_cert_sha256: Some("1".repeat(64)),
                    sbat: vec![aos_registry_surface::manifest::SbatEntry {
                        component: "aos".into(),
                        generation: 1,
                    }],
                    measured: false,
                    expected_pcr11: None,
                },
                image_info: ImageInfoReference {
                    filename: "image-info.json".into(),
                    object_key: immutable_image_info_object_key(&sha256, &info_sha256),
                    store_path: String::new(),
                    nar_hash: String::new(),
                    nar_size: 0,
                    media_type: "application/vnd.aos.image-info+json".into(),
                    byte_size: 512,
                    sha256: info_sha256,
                },
                update_payload: None,
            },
        }
    }

    fn image_channels() -> Vec<ChannelSummary> {
        vec![
            ChannelSummary {
                name: "stable".into(),
                frontier: Some("2026.08".into()),
                partitions: vec![Some("2026.08".into()); 256],
            },
            ChannelSummary {
                name: "edge".into(),
                frontier: Some("2026.09".into()),
                partitions: vec![Some("2026.09".into()); 256],
            },
        ]
    }

    #[test]
    fn images_are_discoverable_and_structured_filters_compose() {
        let images = vec![
            indexed_image("raw", "2026.08"),
            indexed_image("qcow2", "2026.09"),
        ];
        let channels = image_channels();
        let default = images_page(
            &registry(),
            None,
            &images,
            &channels,
            Some("https://download.example/demo"),
            &ImageBrowse::default(),
            Instant::now(),
            &anon(),
        );
        assert!(default.contains("aria-current=\"page\">Images"));
        assert!(default.contains("name=\"release\""));
        assert!(default.contains("name=\"channel\""));
        assert!(default.contains("name=\"architecture\""));
        assert!(default.contains("name=\"format\""));
        assert!(default.contains("name=\"target\""));
        assert!(default.contains("class=\"image-filter-fields\""));
        assert!(default.contains("class=\"image-filter-actions\""));
        assert!(default.contains("class=\"image-summary\""));
        assert!(default.contains("class=\"image-facts\""));
        assert!(default.contains("<th scope=\"row\">file SHA-256</th>"));
        assert!(default.contains("<th scope=\"row\">UKI SHA-256</th>"));
        assert!(default.contains("class=\"hash-control\""));
        assert!(default.contains("UKI policy verified"));
        assert!(!default.contains("boot verified"));
        assert!(default.contains(&format!("data-copy-value=\"{}\"", "a".repeat(64))));
        assert!(default.contains("aos-2026.08.img.zst"));
        assert!(default.contains("aos-2026.09.qcow2"));

        let filtered = images_page(
            &registry(),
            None,
            &images,
            &channels,
            Some("https://download.example/demo"),
            &ImageBrowse {
                page_number: 1,
                release: Some("2026.08"),
                channel: Some("stable"),
                architecture: Some("x86_64"),
                format: Some("raw"),
                target: Some("bare-metal"),
                query: Some("aos-system"),
            },
            Instant::now(),
            &anon(),
        );
        assert!(filtered.contains("aos-2026.08.img.zst"));
        assert!(!filtered.contains("aos-2026.09.qcow2"));
        assert!(filtered.contains("value=\"bare-metal\" selected"));

        let mut unsigned = indexed_image("raw", "2026.10");
        unsigned.delivery.uki.verification = ImageVerificationState::Unsigned;
        unsigned.delivery.uki.signer_cert_sha256 = None;
        let unsigned_html = images_page(
            &registry(),
            None,
            &[unsigned],
            &[],
            Some("https://download.example/demo"),
            &ImageBrowse::default(),
            Instant::now(),
            &anon(),
        );
        assert!(unsigned_html.contains("UKI unsigned"));
        assert!(unsigned_html.contains("has no Authenticode signature"));
        assert!(!unsigned_html.contains("boot unsigned"));
    }

    #[test]
    fn images_page_paginates_and_preserves_filters() {
        let images = (0..26)
            .map(|index| indexed_image("raw", &format!("release-{index:02}")))
            .collect::<Vec<_>>();
        let html = images_page(
            &registry(),
            None,
            &images,
            &image_channels(),
            Some("https://download.example/demo"),
            &ImageBrowse {
                page_number: 2,
                query: Some("aos-system"),
                ..ImageBrowse::default()
            },
            Instant::now(),
            &anon(),
        );

        assert!(html.contains("26 images"));
        assert!(html.contains("page 2 of 2"));
        assert!(html.contains("q=aos-system&amp;page=1"));
        assert!(html.contains("aos-release-00.img.zst"));
        assert!(!html.contains("aos-release-25.img.zst"));
    }

    #[test]
    fn images_page_has_clear_empty_state_and_canonical_downloads() {
        let image = indexed_image("raw", "2026.08");
        let empty = images_page(
            &registry(),
            None,
            std::slice::from_ref(&image),
            &image_channels(),
            Some("https://download.example/demo"),
            &ImageBrowse {
                target: Some("qemu-kvm"),
                ..ImageBrowse::default()
            },
            Instant::now(),
            &anon(),
        );
        assert!(empty.contains("No matching signed disk images are published."));

        let mut private = registry();
        private.visibility = "private".into();
        let html = images_page(
            &private,
            None,
            &[image],
            &image_channels(),
            Some("https://download.example/demo"),
            &ImageBrowse::default(),
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("CDN / CLI"));
        assert!(!html.contains("href=\"https://download.example/demo/images/sha256/"));
        assert!(!html.contains("access_token="));
        assert!(!html.contains("Authorization="));
    }

    #[tokio::test]
    async fn channel_grid_is_16_by_16() {
        let channel = ChannelSummary {
            name: "stable".into(),
            frontier: Some("1.2.0".into()),
            partitions: {
                let mut p = vec![Some("1.1.0".to_string()); 256];
                for slot in p.iter_mut().take(64) {
                    *slot = Some("1.2.0".to_string());
                }
                p
            },
        };
        let html = channel_page(
            &registry(),
            None,
            &channel,
            None,
            None,
            Instant::now(),
            &anon(),
        );
        let grid = html
            .split("partition-grid\">")
            .nth(1)
            .unwrap()
            .split("</pre>")
            .next()
            .unwrap();
        assert_eq!(grid.lines().count(), 16);
        assert!(grid.lines().all(|l| l.matches("</span>").count() == 16));
        // Frontier glyph appears exactly 64 times, in the frontier class.
        assert_eq!(grid.matches('■').count(), 64);
        assert_eq!(grid.matches("<span class=\"r0\">■</span>").count(), 64);
        assert!(html.contains(
            "frontier <strong><a href=\"/demo/-/releases#release-1.2.0\">1.2.0</a></strong>"
        ));
        assert!(html.contains("/demo/-/images?release=1.2.0"));
    }

    #[tokio::test]
    async fn channel_calculator_resolves_hex_and_decimal_buckets() {
        let channel = ChannelSummary {
            name: "stable".into(),
            frontier: Some("1.2.0".into()),
            partitions: vec![Some("1.2.0".to_string()); 256],
        };
        let html = channel_page(
            &registry(),
            None,
            &channel,
            Some("1.1.0"),
            Some("0a"),
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("bucket <strong>0x0A</strong> (10)"), "{html}");
        assert!(html.contains(
            "release <strong><a href=\"/demo/-/releases#release-1.2.0\">1.2.0</a></strong>"
        ));
        assert!(html.contains("<strong class=\"hit\">"));
        assert!(html.contains(
            "floor <strong><a href=\"/demo/-/releases#release-1.1.0\">1.1.0</a></strong>"
        ));

        assert_eq!(parse_bucket("10"), Some(10), "decimal wins when both parse");
        assert_eq!(parse_bucket("0x10"), Some(16));
        assert_eq!(parse_bucket("ff"), Some(255));
        assert_eq!(parse_bucket("zz"), None);
        assert_eq!(parse_bucket("256"), None);

        let html = channel_page(
            &registry(),
            None,
            &channel,
            None,
            Some("zz"),
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("unrecognized bucket"));
        assert!(!html.contains("<strong class=\"hit\">"));
    }

    #[tokio::test]
    async fn registry_home_escapes_and_links() {
        let registry = registry();
        let caches = [("https://cache.example".into(), 40)];
        let setup = setup(&registry, "http://127.0.0.1:8420/demo", &caches);
        let html = registry_home(
            &registry,
            None,
            &[],
            0,
            &caches,
            &[("alice".into(), "demo:Ed25519:<k>".into(), "active".into())],
            &[],
            &setup,
            false,
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("&lt;k&gt;"));
        assert!(html.contains(
            "apr add http://127.0.0.1:8420/demo/ --name demo --trust-key demo:Ed25519:AAAA"
        ));
        assert!(!html.contains("<k>"));
        // Fingerprints, the module stanza, and the plain-Nix snippet.
        assert!(html.contains("SHA256:"));
        assert!(html.contains("aos.apm.registries.&quot;demo&quot;"));
        assert!(html.contains("trustKeys"));
        // One canonical registry URL serves Git, AOS, and stock-Nix clients;
        // physical cache routes remain visible in the signed topology table.
        assert!(html.contains("substituters = http://127.0.0.1:8420/demo"));
        assert!(html.contains("trusted-public-keys = demo:Ed25519:AAAA"));
        // Unvalidated caches say so; the health page is linked.
        assert!(html.contains("not yet validated"));
        assert!(html.contains("/demo/-/health"));
        assert!(html.contains("aria-label=\"Copy full trust key\""));
        assert!(html.contains("class=\"cache-url\""));
    }

    #[tokio::test]
    async fn registry_home_uses_signed_identity_and_all_bootstrap_keys() {
        let mut registry = registry();
        registry.slug = "andyl/main".into();
        registry.trust_keys = vec![
            "andyl-main:Ed25519:AAAA".into(),
            "andyl-main:Ed25519:BBBB".into(),
        ];

        let setup = setup(&registry, "https://cdn.example/andyl/main", &[]);
        let html = registry_home(
            &registry,
            None,
            &[],
            0,
            &[],
            &[],
            &[],
            &setup,
            false,
            Instant::now(),
            &anon(),
        );

        assert!(html.contains(
            "apr add https://cdn.example/andyl/main/ --name andyl-main \
             --trust-key andyl-main:Ed25519:AAAA"
        ));
        assert!(html.contains("--trust-key andyl-main:Ed25519:BBBB"));
        assert!(html.contains("aos.apm.registries.&quot;andyl-main&quot;"));
        assert!(html.contains("andyl-main:Ed25519:BBBB"));
    }

    /// A platform artifact fixture with the given refs.
    fn platform(name: &str, store_path: &str, refs: &[&str]) -> PlatformDetail {
        PlatformDetail {
            platform: name.into(),
            store_path: store_path.into(),
            nar_hash: "sha256:aa".into(),
            nar_size: 1024,
            closure_size: 4096,
            source_drv: format!("/var/lib/store/{name}drv-x.drv"),
            refs: refs.iter().map(|r| (*r).to_string()).collect(),
            images: Vec::new(),
        }
    }

    #[tokio::test]
    async fn package_homepage_requires_http_scheme() {
        let mut detail = PackageDetail {
            name: "curl".into(),
            description: "URL transfers".into(),
            homepage: Some("javascript:alert(1)".into()),
            license: "MIT".into(),
            maintainer: "aos".into(),
            sysroot: false,
            versions: Vec::new(),
        };
        let closure = PackageClosure::default();
        let registry = registry();
        let setup = setup(&registry, "http://hub.example/demo", &[]);
        let html = package_page(
            &registry,
            None,
            &detail,
            &closure,
            &setup,
            None,
            None,
            false,
            Instant::now(),
            &anon(),
        );
        assert!(
            !html.contains("href=\"javascript:"),
            "javascript: homepage must not become a link: {html}"
        );
        assert!(html.contains("javascript:alert(1)"), "still shown as text");

        detail.homepage = Some("https://curl.se".into());
        let html = package_page(
            &registry,
            None,
            &detail,
            &closure,
            &setup,
            None,
            None,
            false,
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("<a href=\"https://curl.se\">"));
    }

    #[tokio::test]
    async fn package_page_is_data_rich() {
        let detail = PackageDetail {
            name: "curl".into(),
            description: "URL transfers".into(),
            homepage: Some("https://curl.se".into()),
            license: "MIT".into(),
            maintainer: "aos".into(),
            sysroot: false,
            versions: vec![VersionDetail {
                version: "8.5.0".into(),
                previous: None,
                platforms: vec![platform(
                    "x86_64-linux",
                    "/var/lib/store/aaaa-curl-8.5.0",
                    &["bbbb", "cccc"],
                )],
            }],
        };
        let closure = PackageClosure {
            platform: Some("x86_64-linux".into()),
            dependencies: vec![
                ResolvedDependency {
                    hash: "bbbb".into(),
                    name: Some("zlib".into()),
                    version: Some("1.3.1".into()),
                },
                ResolvedDependency {
                    hash: "cccc".into(),
                    name: None,
                    version: None,
                },
            ],
            reverse: vec![("git".into(), "2.43.0".into())],
            reverse_total: 1,
        };
        let registry = registry();
        let caches = [("https://cache.example/demo".into(), 40)];
        let setup = setup(&registry, "http://hub.example/demo", &caches);
        let html = package_page(
            &registry,
            None,
            &detail,
            &closure,
            &setup,
            None,
            None,
            false,
            Instant::now(),
            &anon(),
        );
        // Header carries the latest version and a prominent description.
        assert!(html.contains("<h1 id=\"overview\">curl <span class=\"dim\">8.5.0</span>"));
        assert!(html.contains("class=\"lede\">URL transfers"));
        // Platform chips near the top.
        assert!(html.contains("class=\"chip\">x86_64-linux"));
        // Install snippet: apm is the consumer CLI.
        assert!(html.contains("apm install curl"));
        assert!(html.contains("apr add http://hub.example/demo/ --name demo"));
        assert!(html.contains("substituters = http://hub.example/demo"));
        assert!(html.contains("trusted-public-keys = demo:Ed25519:AAAA"));
        // A resolved dependency links to its package page; an unresolved one
        // falls back to its narinfo permalink.
        assert!(html.contains("Dependencies (2)"));
        assert!(html.contains("<a href=\"/demo/-/packages/zlib\">zlib</a>"));
        assert!(html.contains("href=\"http://hub.example/demo/cccc.narinfo\""));
        // Reverse dependency.
        assert!(html.contains("Required by (1)"));
        assert!(html.contains("<a href=\"/demo/-/packages/git\">git</a>"));
        // Bounded summary columns sit above full-width download rows for the
        // output and source derivation.
        assert!(html.contains("class=\"artifact-summary\""));
        assert!(html.contains("<th scope=\"row\">store path</th>"));
        assert!(html.contains("<th scope=\"row\">source drv</th>"));
        assert!(html.contains("<th scope=\"row\">NAR hash</th>"));
        assert!(html.contains("href=\"http://hub.example/demo/aaaa.narinfo\""));
        assert!(html.contains("colspan=\"3\""));
        // Raw-metadata disclosure block.
        assert!(html.contains("<details class=\"raw-metadata\">"));
        assert!(html.contains("<summary>Raw metadata</summary>"));
    }

    #[test]
    fn package_page_uses_the_registry_setup_identity_and_cache_stack() {
        let mut registry = registry();
        registry.slug = "andyl/main".into();
        registry.trust_keys = vec![
            "andyl-main:Ed25519:AAAA".into(),
            "andyl-main:Ed25519:BBBB".into(),
        ];
        let caches = [
            ("https://cache.example/secondary/".into(), 50),
            ("https://cache.example/primary/".into(), 100),
        ];
        let setup = setup(&registry, "https://cdn.example/andyl/main/", &caches);
        let detail = PackageDetail {
            name: "minisign".into(),
            description: "sign files".into(),
            homepage: None,
            license: "ISC".into(),
            maintainer: "Andyl, Inc.".into(),
            sysroot: false,
            versions: Vec::new(),
        };

        let html = package_page(
            &registry,
            None,
            &detail,
            &PackageClosure::default(),
            &setup,
            None,
            None,
            false,
            Instant::now(),
            &anon(),
        );

        assert!(html.contains(
            "apr add https://cdn.example/andyl/main/ --name andyl-main \
             --trust-key andyl-main:Ed25519:AAAA"
        ));
        assert!(html.contains("--trust-key andyl-main:Ed25519:BBBB"));
        assert!(html.contains("apm install minisign"));
        assert!(html.contains("substituters = https://cdn.example/andyl/main"));
        assert!(!html.contains("substituters = https://cache.example"));
        assert!(!html.contains("apr add https://hub.example"));
    }

    #[tokio::test]
    async fn package_page_escapes_html_in_name_and_description() {
        let detail = PackageDetail {
            name: "<script>x</script>".into(),
            description: "<img src=x onerror=1>".into(),
            homepage: None,
            license: "MIT".into(),
            maintainer: "aos".into(),
            sysroot: false,
            versions: Vec::new(),
        };
        let registry = registry();
        let setup = setup(&registry, "http://hub.example/demo", &[]);
        let html = package_page(
            &registry,
            None,
            &detail,
            &PackageClosure::default(),
            &setup,
            None,
            None,
            false,
            Instant::now(),
            &anon(),
        );
        assert!(!html.contains("<script>x</script>"));
        assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
        assert!(!html.contains("<img src=x onerror=1>"));
        assert!(html.contains("&lt;img src=x onerror=1&gt;"));
    }

    #[test]
    fn documentation_pages_render_verified_content_and_escape_search_rows() {
        let registry = registry();
        let panel = documentation_panel("HTTP <proxy> service");
        let detail = PackageDetail {
            name: "nginx".into(),
            description: "HTTP server".into(),
            homepage: None,
            license: "BSD-2-Clause".into(),
            maintainer: "aos".into(),
            sysroot: false,
            versions: Vec::new(),
        };
        let setup = setup(&registry, "https://hub.example/demo", &[]);
        let reference = PackageDocumentationReference {
            package: panel.document.package.name.clone(),
            version: panel.document.package.version.clone(),
            platform: panel.document.package.platform.clone(),
            store_path: panel.store_path.clone(),
            document_sha256: panel.document_sha256.clone(),
            nar_hash: panel.nar_hash.clone(),
        };
        let package_html = package_page(
            &registry,
            None,
            &detail,
            &PackageClosure::default(),
            &setup,
            None,
            Some(&reference),
            false,
            Instant::now(),
            &anon(),
        );
        assert!(package_html.contains("Configuration &amp; runtime"));
        assert!(package_html.contains("Signed reference to"));
        assert!(!package_html.contains("Verified from"));
        assert!(package_html.contains("aria-label=\"Package documentation sections\""));
        assert!(package_html.contains("href=\"#integrity\""));
        assert!(!package_html.contains("HTTP &lt;proxy&gt; service"));
        assert!(package_html.contains("Read configuration &amp; service documentation"));
        assert!(
            package_html.find("id=\"versions\"").unwrap()
                < package_html.find("id=\"configure\"").unwrap()
        );
        assert!(!package_html.contains("HTTP <proxy> service"));
        assert!(package_html.contains("/-/docs/nginx/1.30.4/x86_64-linux?digest=sha256%3A"));
        assert!(package_html.contains("/-/api/v1/documentation/sha256:"));

        let detail_html = documentation_page(&registry, None, &panel, Instant::now(), &anon());
        assert!(
            detail_html.contains("Exact installable reference")
                || detail_html.contains("Canonical JSON")
        );
        assert!(detail_html.contains("apm docs show nginx"));

        let search_html = documentation_index_page(
            &registry,
            None,
            &[crate::db::PackageDocumentationSearchResult {
                package_name: "nginx".into(),
                package_version: "1.30.4".into(),
                platform: "x86_64-linux".into(),
                kind: "option".into(),
                key: "nginx.enable".into(),
                title: "<script>option</script>".into(),
                summary: "Enable & start".into(),
                score: 100,
            }],
            Some("enable"),
            Some("option"),
            1,
            1,
            Instant::now(),
            &anon(),
        );
        assert!(!search_html.contains("<script>option</script>"));
        assert!(search_html.contains("&lt;script&gt;option&lt;/script&gt;"));
        assert!(search_html.contains("Enable &amp; start"));
        assert!(!search_html.contains("Exact installable reference"));
        assert!(!search_html.contains("<h1>Package documentation</h1>"));

        let browse_html = documentation_index_page(
            &registry,
            None,
            &[crate::db::PackageDocumentationSearchResult {
                package_name: "nginx".into(),
                package_version: "1.30.4".into(),
                platform: "x86_64-linux".into(),
                kind: "package".into(),
                key: "nginx".into(),
                title: "nginx".into(),
                summary: "HTTP server".into(),
                score: 0,
            }],
            Some(""),
            None,
            1,
            1,
            Instant::now(),
            &anon(),
        );
        assert!(browse_html.contains("Browse 1 indexed documentation entry."));
        assert!(browse_html.contains("HTTP server"));

        let paged_html = documentation_index_page(
            &registry,
            None,
            &[],
            Some("tls proxy"),
            Some("option"),
            2,
            150,
            Instant::now(),
            &anon(),
        );
        assert!(paged_html.contains("150 ranked results"));
        assert!(paged_html.contains("page 2 of 2"));
        assert!(paged_html.contains("q=tls+proxy"));
        assert!(paged_html.contains("kind=option"));
        assert!(paged_html.contains("page=1"));
    }

    #[tokio::test]
    async fn releases_sort_by_semver_with_pack_column() {
        let release = |semver: &str, tagged_at: i64, pack: bool| ReleaseRow {
            semver: semver.into(),
            tag_oid: "t".repeat(64),
            commit_oid: "c".repeat(64),
            signer: None,
            tagged_at: Some(tagged_at),
            pack_present: pack,
        };
        // String order would put 1.10.0 before 1.9.0; semver order must not.
        let releases = vec![
            release("1.9.0", 300, false),
            release("1.10.0", 100, true),
            release("0.9.0", 200, false),
        ];
        let html = releases_page(
            &registry(),
            None,
            &releases,
            &[("1.10.0".into(), 258)],
            &[("1.10.0".into(), 3)],
            1,
            Instant::now(),
            &anon(),
        );
        let first = html.find("1.10.0").unwrap();
        let second = html.find("1.9.0").unwrap();
        let third = html.find("0.9.0").unwrap();
        assert!(first < second && second < third, "{html}");
        assert!(html.contains("✓ pack"));
        assert!(html.contains("— none"));
        assert!(html.contains("(unix 100)"));
        assert!(html.contains("/demo/-/images?release=1.10.0\">images <strong>3</strong>"));
        assert!(html.contains("/demo/-/packages?release=1.10.0\">packages <strong>258</strong>"));
        assert!(html.contains("/demo/-/images?release=1.9.0\">images <strong>0</strong>"));
        assert!(!html.contains("/demo/-/images?release=1.10.0\">1.10.0</a>"));
    }

    #[tokio::test]
    async fn short_commit_oids_do_not_panic() {
        let releases = vec![ReleaseRow {
            semver: "1.0.0".into(),
            tag_oid: "t".into(),
            commit_oid: "abc".into(), // shorter than the 12-char display slice
            signer: None,
            tagged_at: None,
            pack_present: false,
        }];
        let html = releases_page(
            &registry(),
            None,
            &releases,
            &[],
            &[],
            1,
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("<code aria-label=\"abc\">abc</code>"));
    }

    #[tokio::test]
    async fn instance_home_filters_and_escapes_state() {
        let rows = vec![(
            registry(),
            Some(IndexStatus {
                state: "<bad&state>".into(),
                error: None,
                last_indexed_commit: None,
                name: Some("Demo".into()),
                description: Some("Fixture registry".into()),
                readme: None,
                indexed_at: None,
                generation: 0,
                content_digest: None,
            }),
        )];
        let html = instance_home(&rows, None, 1, Instant::now(), &anon());
        assert!(html.contains("&lt;bad&amp;state&gt;"));
        assert!(html.contains(">outdated</span>"));
        assert!(!html.contains("<bad&state>"));

        let html = instance_home(&rows, Some("fixture"), 1, Instant::now(), &anon());
        assert!(html.contains("1 of 1 registries match"));
        let html = instance_home(&rows, Some("zzz"), 1, Instant::now(), &anon());
        assert!(html.contains("0 of 1 registries match"));
        assert!(html.contains("No registries match."));
    }

    #[tokio::test]
    async fn package_index_paginates_and_counts() {
        let rows: Vec<PackageRow> = (0..3)
            .map(|i| PackageRow {
                name: format!("pkg{i}"),
                description: "desc".into(),
                license: "MIT".into(),
                latest_version: Some("1.0.0".into()),
                closure_size: Some(2 * 1024 * 1024),
                platforms: vec!["x86_64-linux".into()],
            })
            .collect();
        let names = vec!["curl".to_string()];
        let versions = vec!["1.0.0".to_string()];
        let licenses = vec!["MIT".to_string()];
        let platforms = vec!["x86_64-linux".to_string()];
        // 250 matches across 3 pages; this is page 2, sorted by closure desc.
        let html = package_index(
            &registry(),
            None,
            &rows,
            &PackageBrowse {
                snapshot: None,
                head_commit: Some("abc123"),
                snapshots: &[],
                filter: Some("license == MIT"),
                filter_error: None,
                sort: Some((SortColumn::Closure, SortDir::Desc)),
                page_number: 2,
                total_matches: 250,
                total_all: 300,
                truncated: false,
                names: &names,
                versions: &versions,
                licenses: &licenses,
                platforms: &platforms,
            },
            Instant::now(),
            &anon(),
        );
        // The total count leads the page; the result line names the filter.
        assert!(html.contains("<h1>Packages (300)</h1>"));
        assert!(html.contains("250 of 300 packages matching"));
        // Closure size + platform list per row.
        assert!(html.contains("2.0 MiB"));
        assert!(html.contains("x86_64-linux"));
        // The filter widget and its autocomplete data island are present.
        assert!(html.contains("class=\"filter-box\""));
        assert!(html.contains("data-filter-widget"));
        assert!(html.contains("id=\"filter-meta\""));
        // The sorted column header is marked and shows the descending glyph;
        // clicking it advances to ascending.
        assert!(html.contains("class=\"sorted\""));
        assert!(html.contains("▼"));
        assert!(html.contains("sort=closure&amp;dir=asc"));
        assert!(html.contains("page 2 of 3"));
        // Pagination preserves the filter + sort across the prev/next links
        // (HTML-escaped in the href, with `page` appended last).
        assert!(html.contains("filter=license+%3D%3D+MIT&amp;sort=closure&amp;dir=desc&amp;page=1"));
        assert!(html.contains("&amp;page=3"));

        // A single page in default order renders no pager and a clean count.
        let html = package_index(
            &registry(),
            None,
            &rows,
            &PackageBrowse {
                snapshot: None,
                head_commit: Some("abc123"),
                snapshots: &[],
                filter: None,
                filter_error: None,
                sort: None,
                page_number: 1,
                total_matches: 3,
                total_all: 3,
                truncated: false,
                names: &names,
                versions: &versions,
                licenses: &licenses,
                platforms: &platforms,
            },
            Instant::now(),
            &anon(),
        );
        assert!(!html.contains("class=\"pager\""));
        assert!(html.contains("<p class=\"dim\">3 packages</p>"));
        // The license cell links to a license-filter expression.
        assert!(html.contains("filter=license+%3D%3D+%22MIT%22"));
        assert!(html.contains("class=\"license-pill\""));
        assert!(html.contains("title=\"Filter by license: MIT\""));
        assert!(html.contains("class=\"platform-pill\""));
        assert!(html.contains("filter=platform+%3D%3D+%22x86_64-linux%22"));

        // An active filter is named in the result line and is clearable; a
        // parse error is surfaced and does not name a count.
        let html = package_index(
            &registry(),
            None,
            &rows,
            &PackageBrowse {
                snapshot: None,
                head_commit: Some("abc123"),
                snapshots: &[],
                filter: Some("license == MIT"),
                filter_error: None,
                sort: None,
                page_number: 1,
                total_matches: 3,
                total_all: 3,
                truncated: false,
                names: &names,
                versions: &versions,
                licenses: &licenses,
                platforms: &platforms,
            },
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("matching <code>license == MIT</code>"));
        assert!(html.contains("clear filter"));

        let html = package_index(
            &registry(),
            None,
            &rows,
            &PackageBrowse {
                snapshot: None,
                head_commit: Some("abc123"),
                snapshots: &[],
                filter: Some("license =="),
                filter_error: Some("expected a value after `license ==`"),
                sort: None,
                page_number: 1,
                total_matches: 3,
                total_all: 3,
                truncated: false,
                names: &names,
                versions: &versions,
                licenses: &licenses,
                platforms: &platforms,
            },
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("filter error:"));
    }

    #[test]
    fn package_license_pills_use_short_mapped_labels() {
        assert_eq!(license_pill_label("Apache-2.0"), "Apache");
        assert_eq!(license_pill_label("LGPL-2.1-or-later"), "LGPLv2.1+");
        assert_eq!(
            license_pill_label("Intel-ACPI OR GPL-2.0-only OR BSD-3-Clause"),
            "ACPI/GPL2/BSD3"
        );
        assert_eq!(license_pill_label("custom-license"), "custom-license");
    }

    #[test]
    fn health_page_empty_validation_state_still_summarizes_live_health() {
        let status = IndexStatus {
            state: "fresh".into(),
            error: None,
            last_indexed_commit: Some("a".repeat(64)),
            name: None,
            description: None,
            readme: None,
            indexed_at: Some(0),
            generation: 1,
            content_digest: None,
        };
        let stack = StackNode::Endpoint("https://cache.example".into());
        let routes = [RouteHealthRow {
            id: "route:primary".into(),
            endpoint_id: "endpoint:cdn".into(),
            base_path: "/demo".into(),
            mode: "hub_proxy".into(),
            enabled: true,
            capabilities: vec!["git".into(), "cache".into(), "web".into()],
        }];

        let html = health_page(
            &registry(),
            Some(&status),
            &[],
            Some(&stack),
            &[],
            &[],
            &routes,
            Instant::now(),
            &anon(),
        );

        assert!(html.contains("<h2>Summary</h2>"));
        assert!(html.contains("Registry index"));
        assert!(html.contains("Cache validation"));
        assert!(html.contains("No validation job has recorded a result."));
        assert!(html.contains("1 enabled of 1 total."));
        assert!(html.contains("Not yet validated"));
        assert!(!html.contains("No validation runs recorded yet"));
    }

    #[tokio::test]
    async fn health_page_caps_missing_drilldown() {
        let run = ValidationRunRow {
            id: 1,
            cache_url: "https://cache.example".into(),
            depth: "presence".into(),
            checked: 200,
            missing: 150,
            reachable: true,
            finished_at: 0,
        };
        let missing: Vec<String> = (0..150).map(|i| format!("hash{i:03}")).collect();
        let html = health_page(
            &registry(),
            None,
            &[(run, missing, Vec::new())],
            None,
            &[],
            &[],
            &[],
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("Missing from https://cache.example"));
        assert!(html.contains("hash000"));
        assert!(html.contains("hash099"));
        assert!(!html.contains("hash100"), "capped at 100 entries");
        assert!(html.contains("… and 50 more"));
        assert!(html.contains("⚠ 150 missing"));
    }

    #[tokio::test]
    async fn health_page_renders_stack_tree_and_mirror_shortfall() {
        let runs = vec![
            (
                ValidationRunRow {
                    id: 1,
                    cache_url: "https://a".into(),
                    depth: "presence".into(),
                    checked: 2,
                    missing: 0,
                    reachable: true,
                    finished_at: 0,
                },
                Vec::new(),
                Vec::new(),
            ),
            (
                ValidationRunRow {
                    id: 2,
                    cache_url: "https://b".into(),
                    depth: "presence".into(),
                    checked: 2,
                    missing: 1,
                    reachable: true,
                    finished_at: 0,
                },
                vec!["xyz".into()],
                Vec::new(),
            ),
        ];
        let stack = StackNode::Try(vec![
            StackNode::Mirror(vec![
                StackNode::Endpoint("https://a".into()),
                StackNode::Endpoint("https://b".into()),
            ]),
            StackNode::Endpoint("https://c".into()),
        ]);
        let probes = vec![
            CacheProbeRow {
                cache_url: "https://a".into(),
                status: "ok".into(),
                observed_nix_cache_info: true,
                latency_ms: 12,
                checked_at: 0,
            },
            CacheProbeRow {
                cache_url: "https://c".into(),
                status: "unreachable".into(),
                observed_nix_cache_info: false,
                latency_ms: 0,
                checked_at: 0,
            },
        ];
        let html = health_page(
            &registry(),
            None,
            &runs,
            Some(&stack),
            &probes,
            &[],
            &[],
            Instant::now(),
            &anon(),
        );
        assert!(html.contains("Cache stack"));
        assert!(html.contains("try (fall-through"));
        assert!(html.contains("mirror (every member must be complete)"));
        // Per-endpoint coverage annotations.
        assert!(html.contains("https://a  [100%]"));
        assert!(html.contains("https://b  [50%]"));
        // The incomplete mirror member is flagged as a shortfall.
        assert!(html.contains("Mirror replication shortfalls"));
        assert!(html.contains("mirror group 0: <code>https://b</code> missing 1"));
        // The cache-freshness table surfaces each probe's status.
        assert!(html.contains("Cache freshness"));
        assert!(html.contains("12 ms"));
        assert!(html.contains("unreachable"));
    }

    #[tokio::test]
    async fn health_page_flags_corruption_and_repair_history() {
        let run = ValidationRunRow {
            id: 1,
            cache_url: "https://cache.example".into(),
            depth: "deep".into(),
            checked: 10,
            missing: 2,
            reachable: true,
            finished_at: 0,
        };
        // One missing, one corrupt — the page must distinguish them.
        let missing = vec!["miss000".to_string()];
        let corrupt = vec!["bad000".to_string()];
        let repair_jobs = vec![
            RepairJobRow {
                id: 1,
                cache_url: "https://cache.example".into(),
                store_hash: "miss000".into(),
                source_cache_url: "file:///srv/good".into(),
                status: "done".into(),
                error: None,
                created_at: 0,
                finished_at: Some(1),
            },
            RepairJobRow {
                id: 2,
                cache_url: "https://external.example".into(),
                store_hash: "miss001".into(),
                source_cache_url: "file:///srv/good".into(),
                status: "plan_only".into(),
                error: None,
                created_at: 0,
                finished_at: Some(1),
            },
        ];
        let html = health_page(
            &registry(),
            None,
            &[(run, missing, corrupt)],
            None,
            &[],
            &repair_jobs,
            &[],
            Instant::now(),
            &anon(),
        );
        // Corruption is flagged distinctly from absence.
        assert!(html.contains("Corrupt in https://cache.example"));
        assert!(html.contains("bad000"));
        assert!(html.contains("re-upload required"));
        assert!(html.contains("Missing from https://cache.example"));
        assert!(html.contains("miss000"));
        // The validation table carries a corrupt column.
        assert!(html.contains("<th scope=\"col\">corrupt</th>"));
        // The repair history surfaces both a done and a plan-only job.
        assert!(html.contains("Repair history"));
        assert!(html.contains("done"));
        assert!(html.contains("plan_only"));
    }
}
