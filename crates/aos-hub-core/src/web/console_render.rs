//! Transport-neutral HTML rendering for the authenticated producer console.
//!
//! RFC-0004 Phase 5 (console-dedup) lifts the console's *foundation* — the
//! shared page chrome and every console page builder — out of the native
//! `aos-hub` crate so the Cloudflare Worker can eventually serve the
//! identical console from one code path. The builders are pure string-building
//! over the `aos.hub.v1` read shapes ([`crate::db`] record types) and the
//! callers' explicitly-passed identity, so the module is **transport- and
//! task-local-free**: the signed-in email, the per-session CSRF token, and the
//! masthead brand are all passed in (the brand via a process-wide [`set_brand`]
//! seam, never a tokio task-local), and the module compiles to
//! `wasm32-unknown-unknown` (no `axum` server, no `tokio`, no `std::fs`).
//!
//! # Module map
//!
//! - The chrome — [`page_with_session`], [`StateLine`], [`SessionIndicator`],
//!   [`Pager`], [`csrf_field`], [`brand`], [`ago`], [`urlencode`], and the
//!   small table variants — is the shared layout every console page renders in.
//! - The page builders ([`login_page`], [`account_page`], [`org_dashboard`],
//!   [`tokens_page`], [`channel_console`], …) each return a complete document.
//!
//! The pure primitives ([`escape`], [`table`],
//! [`human_size`](crate::web::render::human_size), [`key_fingerprint`]) live in
//! [`crate::web::render`] and are re-used here so the console and the shared
//! browse surface render byte-identically.

use crate::binding::RuntimeKind;
use crate::clock::Instant;
use std::fmt::Write as _;
use std::sync::{OnceLock, RwLock};

use crate::db::{
    AuditRow, Cache, CacheGcRun, CacheUsage, ChangesetRow, ChannelSummary, FrontendRecord,
    HostedKeyRecord, IdpConfigRecord, IndexStatus, MirrorSource, OrgDomainRecord, OrgRecord,
    ProjectRecord, RegistryRecord, ReleaseRow, SignupPolicy, StorageBindingRecord,
    WebauthnCredentialRecord, WebhookRecord,
};
use crate::domain::{iam, Permission, Role, Scope};
use crate::web::help;
use crate::web::render::{escape, human_size, key_fingerprint, table};

/// Items per page for the console's paginated lists (orgs, members, tokens,
/// keys, audit). Mirrors the browse tier's list size so both paginate alike.
pub const LIST_PER_PAGE: usize = 50;

// -- brand + app version chrome --------------------------------------------

/// The operator-configurable masthead brand (company/instance name).
///
/// Set once at server startup via [`set_brand`]; defaults to empty. When
/// empty the masthead shows only the page crumbs (e.g. "log in"); when set,
/// the name leads the masthead and titles every page.
static BRAND: OnceLock<String> = OnceLock::new();

/// The footer application label, e.g. `"aos-hub 0.1.0"`.
///
/// Set once at startup via [`set_app_version`]; defaults to this crate's own
/// `aos-hub <version>` string so the native hub's footer is unchanged
/// when the hub does not override it (the hub and core share a version).
static APP_VERSION: OnceLock<String> = OnceLock::new();

/// Set the masthead brand once, at startup.
///
/// A no-op if called more than once (the first value wins), so it is safe
/// to call unconditionally from `serve`.
pub fn set_brand(name: impl Into<String>) {
    let _ = BRAND.set(name.into());
}

/// The configured brand, or `""` when unset.
#[must_use]
pub fn brand() -> &'static str {
    BRAND.get().map(String::as_str).unwrap_or("")
}

/// The editable, D1-backed site chrome overlaid on the deploy brand: the site
/// title (overrides [`brand`] in the masthead), the global announcement banner,
/// and the footer legal/contact links.
///
/// Unlike [`BRAND`] (a write-once deploy default), this is a mutable cell so an
/// instance admin's edit takes effect immediately for the serving process. Each
/// shell seeds it from `instance_config` at startup (native) or isolate init
/// (Worker); a save updates both D1 and this cell.
#[derive(Default)]
struct SiteChrome {
    title: Option<String>,
    tagline: Option<String>,
    announcement: Option<String>,
    tos_url: Option<String>,
    privacy_url: Option<String>,
    support_url: Option<String>,
}

static SITE_CHROME: RwLock<SiteChrome> = RwLock::new(SiteChrome {
    title: None,
    tagline: None,
    announcement: None,
    tos_url: None,
    privacy_url: None,
    support_url: None,
});

/// Sets the editable site chrome (title, tagline, announcement, footer links).
///
/// Called at startup to seed from `instance_config`, and on a branding save so
/// the change is live without a restart. A poisoned lock is recovered (the
/// chrome is advisory presentation state, never a correctness invariant).
pub fn set_site_chrome(
    title: Option<&str>,
    tagline: Option<&str>,
    announcement: Option<&str>,
    tos_url: Option<&str>,
    privacy_url: Option<&str>,
    support_url: Option<&str>,
) {
    let mut chrome = SITE_CHROME.write().unwrap_or_else(|e| e.into_inner());
    *chrome = SiteChrome {
        title: title.map(str::to_string),
        tagline: tagline.map(str::to_string),
        announcement: announcement.map(str::to_string),
        tos_url: tos_url.map(str::to_string),
        privacy_url: privacy_url.map(str::to_string),
        support_url: support_url.map(str::to_string),
    };
}

/// The configured tagline (empty when unset) — a short dim subtitle beside the
/// masthead brand.
fn site_tagline() -> String {
    let chrome = SITE_CHROME.read().unwrap_or_else(|e| e.into_inner());
    chrome.tagline.clone().unwrap_or_default()
}

/// The effective masthead brand: the editable site title if set, else the
/// deploy [`brand`].
fn effective_brand() -> String {
    let chrome = SITE_CHROME.read().unwrap_or_else(|e| e.into_inner());
    match &chrome.title {
        Some(t) if !t.is_empty() => t.clone(),
        _ => brand().to_string(),
    }
}

/// The announcement-banner HTML (empty when no banner is set).
fn announcement_html() -> String {
    let chrome = SITE_CHROME.read().unwrap_or_else(|e| e.into_inner());
    match &chrome.announcement {
        Some(a) if !a.is_empty() => {
            format!("<div class=\"announce\">{}</div>\n", escape(a))
        }
        _ => String::new(),
    }
}

/// The footer legal/contact links HTML (empty when none are set).
fn footer_links_html() -> String {
    let chrome = SITE_CHROME.read().unwrap_or_else(|e| e.into_inner());
    let mut links = Vec::new();
    for (label, url) in [
        ("terms", &chrome.tos_url),
        ("privacy", &chrome.privacy_url),
        ("support", &chrome.support_url),
    ] {
        if let Some(u) = url {
            if !u.is_empty() {
                links.push(format!("<a href=\"{}\">{}</a>", escape(u), label));
            }
        }
    }
    if links.is_empty() {
        String::new()
    } else {
        format!("<span class=\"footer-links\">{}</span>", links.join(" · "))
    }
}

/// Whether the binary-caches surface (the masthead **caches** tab, the global
/// caches list, and direct cache pages) is visible to **logged-out** visitors.
///
/// Seeded from the `caches_public` instance setting (default `false`: caches are
/// a signed-in-only surface). Like [`SITE_CHROME`], a mutable cell so an admin's
/// change takes effect immediately for the serving process. Signed-in users
/// always see caches regardless of this flag.
static CACHES_PUBLIC: RwLock<bool> = RwLock::new(false);

/// Sets whether the caches surface is visible to anonymous visitors (the
/// `caches_public` instance setting). Seeded at startup and updated on save.
pub fn set_caches_public(public: bool) {
    *CACHES_PUBLIC.write().unwrap_or_else(|e| e.into_inner()) = public;
}

/// Whether the caches surface is shown to logged-out visitors.
#[must_use]
pub fn caches_public() -> bool {
    *CACHES_PUBLIC.read().unwrap_or_else(|e| e.into_inner())
}

/// Set the footer application label once, at startup.
///
/// The deploying shell (native hub or Worker) passes its own
/// `<name> <version>` string so the footer reflects the serving binary. A no-op
/// after the first call.
pub fn set_app_version(label: impl Into<String>) {
    let _ = APP_VERSION.set(label.into());
}

/// The footer application label, defaulting to `aos-hub <version>`.
#[must_use]
fn app_version() -> &'static str {
    APP_VERSION
        .get()
        .map(String::as_str)
        .unwrap_or(concat!("aos-hub ", env!("CARGO_PKG_VERSION")))
}

/// The masthead brand element for `brand`: a home link, or empty when unset.
fn brand_span(brand: &str) -> String {
    if brand.is_empty() {
        String::new()
    } else {
        format!("<a class=\"brand\" href=\"/\">{}</a>", escape(brand))
    }
}

/// The `<title>` text: `"<page> — <brand>"`, or `"<page> — Registry Hub"`
/// when no brand is configured.
fn page_title(brand: &str, title: &str) -> String {
    if brand.is_empty() {
        format!("{} — Registry Hub", escape(title))
    } else {
        format!("{} — {}", escape(title), escape(brand))
    }
}

/// The hidden CSRF synchronizer field every console `POST` form embeds.
///
/// `token` is the value from [`mint_csrf_token`](crate::web::csrf::mint_csrf_token)
/// for the current session; the
/// `POST` handler verifies it with
/// [`connect_or_csrf_ok`](crate::web::csrf::connect_or_csrf_ok) and rejects a
/// mismatch with `403`.
#[must_use]
pub fn csrf_field(token: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        escape(token)
    )
}

/// A session indicator for the signed-in `email`.
fn indicator(email: &str) -> SessionIndicator {
    SessionIndicator::signed_in(email)
}

// -- state line + session indicator ----------------------------------------

/// Data for the footer state line ("expose state" — every page carries
/// the surface commit, index freshness, render time, and hub version).
#[derive(Debug, Default, Clone)]
pub struct StateLine {
    /// Indexed surface commit (short form is rendered).
    pub surface_commit: Option<String>,
    /// Unix time of the last successful index.
    pub indexed_at: Option<i64>,
    /// Index state when not `fresh`.
    pub state: Option<String>,
    /// Handler entry time; when set, the footer shows "rendered NNms".
    pub started: Option<Instant>,
}

impl StateLine {
    /// A state line that only carries the render-time clock.
    #[must_use]
    pub fn timed(started: Instant) -> Self {
        Self {
            started: Some(started),
            ..Self::default()
        }
    }
}

/// The masthead session indicator: the logged-in email plus a logout link,
/// or a "log in" link for an anonymous visitor.
///
/// Passed to [`page_with_session`] so every authenticated producer-console
/// page shows who is signed in (RFC-0004's masthead "[log in]" affordance).
/// `None` renders the anonymous indicator; the browse pages pass `None` and
/// remain unchanged.
#[derive(Debug, Default, Clone)]
pub struct SessionIndicator {
    /// The signed-in user's email, or `None` when anonymous.
    pub email: Option<String>,
}

impl SessionIndicator {
    /// A session indicator for the signed-in user `email`.
    #[must_use]
    pub fn signed_in(email: impl Into<String>) -> Self {
        Self {
            email: Some(email.into()),
        }
    }

    /// The anonymous session indicator (the home + log-in masthead).
    #[must_use]
    pub fn anonymous() -> Self {
        Self { email: None }
    }

    /// Renders the indicator as the right-hand masthead HTML fragment.
    ///
    /// It always leads with a "registries" home link (so there is always a
    /// way back to the instance home). When signed in it continues as the
    /// primary navigation — the caller's organizations and account profile
    /// (the entry points to all management pages) plus the email and a
    /// log-out link; when anonymous it is the home link plus log-in.
    fn render(&self) -> String {
        // Signed-in users always see the caches tab; logged-out visitors see it
        // only when the instance opts caches into anonymous visibility.
        let caches = "<a href=\"/-/caches\">caches</a> · ";
        match &self.email {
            Some(email) => format!(
                "<span class=\"session\">\
                 <a href=\"/\">registries</a> · {caches}\
                 <a href=\"/-/orgs\">organizations</a> · \
                 <a href=\"/-/account\">account</a> · \
                 <span class=\"who\">{}</span> · \
                 <a href=\"/logout\">log out</a></span>",
                escape(email),
            ),
            None => format!(
                "<span class=\"session\">\
                 <a href=\"/\">registries</a> · {}\
                 <a href=\"/login\">log in</a></span>",
                if caches_public() { caches } else { "" },
            ),
        }
    }
}

/// Render a complete page, threading a masthead session indicator.
///
/// `crumbs` is the masthead trail as `(href, label)` pairs; the final crumb
/// should be the current page (empty href renders unlinked). `session` renders
/// on the right of the masthead — the signed-in email and a logout link, or the
/// anonymous "log in" link. The brand (from [`brand`]) leads the masthead when
/// configured; the footer carries the surface commit, index freshness, the app
/// version, and the render time.
#[must_use]
pub fn page_with_session(
    title: &str,
    crumbs: &[(String, String)],
    body: &str,
    state: &StateLine,
    session: &SessionIndicator,
) -> String {
    let mut crumb_html = String::new();
    for (i, (href, label)) in crumbs.iter().enumerate() {
        if i > 0 {
            crumb_html.push_str(" / ");
        }
        if href.is_empty() {
            let _ = write!(crumb_html, "{}", escape(label));
        } else {
            let _ = write!(
                crumb_html,
                "<a href=\"{}\">{}</a>",
                escape(href),
                escape(label)
            );
        }
    }

    let mut statline = String::new();
    if let Some(commit) = &state.surface_commit {
        let _ = write!(
            statline,
            "surface {}",
            escape(&commit[..commit.len().min(12)])
        );
    }
    if let Some(at) = state.indexed_at {
        if !statline.is_empty() {
            statline.push_str(" · ");
        }
        let _ = write!(statline, "indexed at unix {at}");
    }
    if let Some(s) = &state.state {
        if s != "fresh" {
            if !statline.is_empty() {
                statline.push_str(" · ");
            }
            let _ = write!(statline, "index state: {}", escape(s));
        }
    }
    if !statline.is_empty() {
        statline.push_str(" · ");
    }
    statline.push_str(app_version());
    if let Some(started) = state.started {
        // A page that does no I/O renders in sub-millisecond time — and on the
        // Cloudflare Worker the wall clock (`Date.now()`) only advances across
        // I/O, so an I/O-free page always measures exactly 0. Render that as
        // "<1ms" so the footer reads as "instant" rather than looking broken.
        let ms = started.elapsed().as_millis();
        if ms == 0 {
            statline.push_str(" · rendered <1ms");
        } else {
            let _ = write!(statline, " · rendered {ms}ms");
        }
    }

    // The brand is operator-configurable: the editable site title (when set)
    // overrides the deploy brand, leading the masthead and titling every page.
    let brand = effective_brand();
    let mut brand_span = brand_span(&brand);
    // A configured tagline rides beside the brand as a dim subtitle.
    let tagline = site_tagline();
    if !brand_span.is_empty() && !tagline.is_empty() {
        let _ = write!(
            brand_span,
            "<span class=\"tagline\">{}</span>",
            escape(&tagline)
        );
    }
    let page_title = page_title(&brand, title);
    // The announcement banner (when set) sits above the content on every page;
    // the footer carries the configured legal/contact links beside the statline.
    let announcement = announcement_html();
    let footer_links = footer_links_html();

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{page_title}</title>\n\
         <link rel=\"stylesheet\" href=\"/_assets/style.css?v={ver}\">\n\
         <script src=\"/_assets/app.js?v={ver}\" defer></script>\n</head>\n<body>\n\
         <header class=\"masthead\">{brand_span}\
         <span class=\"crumbs\">{crumb_html}</span>{session}</header>\n\
         {announcement}\
         <main>\n{body}\n</main>\n\
         <footer class=\"statline\">{statline}{footer_links}</footer>\n</body>\n</html>\n",
        session = session.render(),
        ver = crate::web::assets::asset_version(),
    )
}

// -- table variants + small primitives -------------------------------------

/// Render a table whose header cells are pre-rendered HTML.
///
/// Identical to [`table`] but each header is inserted into its `<th>` as-is
/// (not escaped), so callers can embed sort links or other markup; body cells
/// follow the same as-is contract as [`table`].
#[must_use]
pub fn table_raw_headers(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut out = String::from("<table>\n<thead><tr>");
    for header in headers {
        let _ = write!(out, "<th>{header}</th>");
    }
    out.push_str("</tr></thead>\n<tbody>\n");
    for row in rows {
        out.push_str("<tr>");
        for cell in row {
            let _ = write!(out, "<td>{cell}</td>");
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody>\n</table>\n");
    out
}

/// Render a table tagged for the live-search enhancement (`search.js`).
///
/// Identical to [`table`] but adds `data-live-list` and a `data-live-noun`
/// so the client script can filter the `<tbody>` rows in place; `noun` is
/// the plural label shown in the result count ("registries", "packages").
#[must_use]
pub fn live_table(headers: &[&str], rows: &[Vec<String>], noun: &str) -> String {
    let plain = table(headers, rows);
    plain.replacen(
        "<table>",
        &format!("<table data-live-list data-live-noun=\"{}\">", escape(noun)),
        1,
    )
}

/// Percent-encode a string for safe inclusion in a URL query value.
#[must_use]
pub fn urlencode(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

/// Render a solid horizontal progress meter filled to `percent` (0–100).
///
/// A bordered track with a fill element whose width is a `pct-N` class (CSS,
/// in 5% steps) rather than an inline `style="width:…"` — the strict
/// `default-src 'self'` CSP forbids inline styles. Drawing the bar as a styled
/// box rather than repeated block glyphs avoids the hairline gaps that
/// `█`-tiling leaves between cells.
#[must_use]
pub fn meter(percent: usize) -> String {
    let pct = (percent.min(100) + 2) / 5 * 5; // nearest 5%
    format!("<span class=\"meter\"><span class=\"meter-fill pct-{pct}\"></span></span>")
}

/// Render a `<datalist id="…">` of `<option>`s for native input autocomplete.
///
/// An `<input list="id">` bound to this list gets browser-native suggestions
/// with no JavaScript. Empty values are skipped; every value is escaped.
#[must_use]
pub fn datalist(id: &str, values: &[String]) -> String {
    let mut out = format!("<datalist id=\"{}\">", escape(id));
    for value in values {
        if value.is_empty() {
            continue;
        }
        let _ = write!(out, "<option value=\"{}\">", escape(value));
    }
    out.push_str("</datalist>\n");
    out
}

/// A one-based pagination window over a list of `total` items.
///
/// Construct with [`Pager::new`], which clamps the requested page into
/// `1..=pages()`; slice the current page's items with [`Pager::slice`] and
/// render the prev/next navigation with [`Pager::nav`]. The same type backs
/// every paginated list (registries, organizations, packages, audit) so they
/// share one off-by-one-free implementation and one look.
///
/// ```no_run
/// use aos_hub_core::web::console_render::Pager;
/// let items: Vec<u32> = (0..250).collect();
/// let pager = Pager::new(2, 100, items.len());
/// assert_eq!(pager.page(), 2);
/// assert_eq!(pager.pages(), 3);
/// assert_eq!(pager.slice(&items).len(), 100);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Pager {
    page: usize,
    per_page: usize,
    total: usize,
}

impl Pager {
    /// Build a pager, clamping `requested_page` (1-based) into the valid
    /// range and `per_page` to at least 1.
    #[must_use]
    pub fn new(requested_page: usize, per_page: usize, total: usize) -> Self {
        let per_page = per_page.max(1);
        let pages = total.div_ceil(per_page).max(1);
        let page = requested_page.max(1).min(pages);
        Self {
            page,
            per_page,
            total,
        }
    }

    /// The clamped, 1-based current page.
    #[must_use]
    pub fn page(self) -> usize {
        self.page
    }

    /// The total number of pages (at least 1, even when `total` is 0).
    #[must_use]
    pub fn pages(self) -> usize {
        self.total.div_ceil(self.per_page).max(1)
    }

    /// The current page's half-open item range `start..end`.
    #[must_use]
    pub fn range(self) -> (usize, usize) {
        let start = (self.page - 1) * self.per_page;
        let end = start.saturating_add(self.per_page).min(self.total);
        (start.min(self.total), end)
    }

    /// Slice `items` to the current page, tolerating a slice shorter than
    /// `total` (returns an empty slice if the window is past the end).
    #[must_use]
    pub fn slice<T>(self, items: &[T]) -> &[T] {
        let (start, end) = self.range();
        let start = start.min(items.len());
        let end = end.min(items.len());
        &items[start..end]
    }

    /// Render the `‹ first · prev · page N of M · next · last ›` navigation,
    /// or an empty string when there is only one page.
    ///
    /// `path` is the page's own path; `query` is the already-encoded query
    /// string to preserve across navigation (search terms, sort, facets),
    /// without a leading `?`/`&` and without any `page=` pair — empty when
    /// there is nothing to preserve. Each link appends `page=N`.
    #[must_use]
    pub fn nav(self, path: &str, query: &str) -> String {
        self.nav_with(path, query, "page")
    }

    /// Like [`Pager::nav`] but with a custom page-parameter name, so several
    /// independent paginators can coexist on one page (e.g. a dashboard's
    /// `members_page` and `registries_page`).
    #[must_use]
    pub fn nav_with(self, path: &str, query: &str, page_param: &str) -> String {
        let pages = self.pages();
        if pages <= 1 {
            return String::new();
        }
        let href = |n: usize| -> String {
            let raw = if query.is_empty() {
                format!("{path}?{page_param}={n}")
            } else {
                format!("{path}?{query}&{page_param}={n}")
            };
            escape(&raw)
        };
        let mut out = String::from("<p class=\"pager\">");
        if self.page > 1 {
            let _ = write!(out, "<a href=\"{}\">⏮ first</a> ", href(1));
            let _ = write!(out, "<a href=\"{}\">← prev</a> ", href(self.page - 1));
        }
        let _ = write!(
            out,
            "<span class=\"of\">page {} of {pages}</span>",
            self.page
        );
        if self.page < pages {
            let _ = write!(out, " <a href=\"{}\">next →</a>", href(self.page + 1));
            let _ = write!(out, " <a href=\"{}\">last ⏭</a>", href(pages));
        }
        out.push_str("</p>\n");
        out
    }
}

/// Format a Unix timestamp as a coarse relative age ("38s ago",
/// "4m ago", "3h ago", "2d ago").
///
/// Timestamps in the future (clock skew) render as "0s ago".
#[must_use]
pub fn ago(unix: i64) -> String {
    // Use the cross-platform clock: `std::time::SystemTime::now()` PANICS on the
    // Worker (wasm32 has no system clock), which would crash every page that
    // renders a relative time (e.g. the audit feed calls this per row). See
    // `crate::clock`.
    let now = crate::clock::now_unix_secs();
    let delta = (now - unix).max(0);
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

// -- partition grid (shared with the consumer channel page) -----------------

/// The glyph ramp for the 16×16 partition grid (newest release first).
const GRID_GLYPHS: [char; 6] = ['■', '▣', '▥', '▤', '▧', '▢'];

/// Assign a stable glyph index to each release in a channel, frontier-first.
fn release_glyphs(
    channel: &ChannelSummary,
) -> (Vec<String>, std::collections::BTreeMap<String, usize>) {
    let mut release_order: Vec<String> = Vec::new();
    if let Some(frontier) = &channel.frontier {
        release_order.push(frontier.clone());
    }
    for release in channel.partitions.iter().flatten() {
        if !release_order.contains(release) {
            release_order.push(release.clone());
        }
    }
    let class_for: std::collections::BTreeMap<String, usize> = release_order
        .iter()
        .enumerate()
        .map(|(i, release)| (release.clone(), i.min(GRID_GLYPHS.len() - 1)))
        .collect();
    (release_order, class_for)
}

/// Render the 16×16 partition grid as a `<pre>` block plus its legend table.
///
/// The producer channel rollout console ([`channel_console`]) renders the
/// identical glyph + color grid the consumer channel page shows — RFC-0004's
/// "ASCII diagrams are content".
#[must_use]
pub fn channel_grid_pre(channel: &ChannelSummary) -> String {
    let (release_order, class_for) = release_glyphs(channel);
    let mut grid = String::new();
    for row in 0..16 {
        for col in 0..16 {
            let bucket = row * 16 + col;
            let cell = match channel.partitions.get(bucket).and_then(|p| p.as_deref()) {
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

// -- console page builders --------------------------------------------------

/// The login page: an email + password form, a one-time email-link form, and
/// an optional "Sign in with a passkey" button.
///
/// `error` renders an inline error (e.g. a malformed address or a failed
/// password attempt). The forms `POST` anonymously — `/login/password` for the
/// password sign-in, `/login` for the magic link — and carry no CSRF token
/// because the caller is anonymous (no ambient cookie to forge against).
///
/// Three no-JS sign-in routes are offered side by side so the page is clear:
///
/// - **password** — email + password fields posting to `/login/password`.
///   When a user has no password set the attempt fails generically, never
///   revealing whether the email exists.
/// - **email link** — the email-only magic-link form posting to `/login`.
/// - **passkey** — only when `passkey_nonce` is `Some` (see below).
///
/// `passkey_nonce` is `Some(nonce)` on the canonical `GET /login` render, where
/// the handler also sets a `script-src 'nonce-…'` CSP: it adds a passkey button
/// and the first-party inline script that drives `navigator.credentials.get`.
/// It is `None` on no-JS error re-renders, which still show the password and
/// email forms (a plain reload restores the passkey button).
#[must_use]
pub fn login_page(error: Option<&str>, passkey_nonce: Option<&str>, started: Instant) -> String {
    let mut body = String::from("<h1>Log in</h1>\n");
    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }
    // Email + password sign-in.
    body.push_str(
        "<p class=\"dim\">Sign in with your email and password.</p>\n\
         <form class=\"console\" method=\"post\" action=\"/login/password\">\n\
         <label>email <input type=\"email\" name=\"email\" required \
         placeholder=\"you@example.com\"></label>\n\
         <label>password <input type=\"password\" name=\"password\" required \
         autocomplete=\"current-password\"></label>\n\
         <button>sign in with password</button>\n</form>\n",
    );
    // One-time email-link sign-in (no password required).
    body.push_str(
        "<p class=\"dim\">Or have us email you a one-time sign-in link instead.</p>\n\
         <form class=\"console\" method=\"post\" action=\"/login\">\n\
         <label>email <input type=\"email\" name=\"email\" required \
         placeholder=\"you@example.com\"></label>\n\
         <button>send sign-in link</button>\n</form>\n",
    );
    if let Some(nonce) = passkey_nonce {
        body.push_str(
            "<p class=\"dim\">Already set up a passkey?</p>\n\
             <p><button type=\"button\" id=\"passkey-login\">sign in with a passkey</button></p>\n\
             <p id=\"passkey-error\" class=\"bad\"></p>\n",
        );
        let _ = write!(body, "{}", passkey_login_script(nonce));
    }
    page_with_session(
        "log in",
        &[(String::new(), "log in".into())],
        &body,
        &StateLine::timed(started),
        &SessionIndicator::default(),
    )
}

/// The "confirm your identity" (sudo re-authentication) page.
///
/// The most destructive console actions (registry/org deletion, password
/// change, credential minting) require a *recently* re-authenticated session
/// (a "sudo" window). When a logged-in user attempts one outside that window,
/// this page lets them re-confirm in place — re-enter their password — rather
/// than dead-ending on a bare `403`. `return_to` is the path to send them back
/// to afterwards (the page they were on), carried through the form and the
/// passwordless fallback link. `error` shows a failed attempt.
#[must_use]
pub fn reauth_page(
    email: &str,
    csrf: &str,
    return_to: &str,
    error: Option<&str>,
    started: Instant,
) -> String {
    let mut body = String::from("<h1>Confirm your identity</h1>\n");
    body.push_str(
        "<p class=\"dim\">For your security, this action needs a recent sign-in. \
         Re-enter your password to continue — you'll return to where you were.</p>\n",
    );
    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/reauth\">\n{csrf}\
         <input type=\"hidden\" name=\"return_to\" value=\"{rt}\">\n\
         <label>password <input type=\"password\" name=\"password\" required \
         autocomplete=\"current-password\"></label>\n\
         <button>confirm and continue</button>\n</form>\n",
        csrf = csrf_field(csrf),
        rt = escape(return_to),
    );
    // Passwordless accounts (SSO / magic-link) re-authenticate through the login
    // flow, which mints a fresh sudo session and honors `next`.
    let next_q: String = url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect();
    let _ = write!(
        body,
        "<p class=\"dim\">No password set? \
         <a href=\"/login?next={next_q}\">re-authenticate with your sign-in provider →</a></p>\n",
    );
    page_with_session(
        "confirm identity",
        &[(String::new(), "confirm identity".into())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The "check your email" confirmation after a magic link is issued.
///
/// In dev mode the page also shows the link itself (the [`LogMailer`] does
/// not send mail), gated by `dev_link`; in production `dev_link` is `None`
/// and the operator follows the logged link.
///
/// [`LogMailer`]: crate::auth::magic::LogMailer
#[must_use]
pub fn login_sent_page(email: &str, dev_link: Option<&str>, started: Instant) -> String {
    let mut body = String::from("<h1>Check your email</h1>\n");
    let _ = writeln!(
        body,
        "<p>If <code>{}</code> has an account, a sign-in link is on its way. \
         The link expires in 15 minutes.</p>",
        escape(email),
    );
    if let Some(link) = dev_link {
        let _ = writeln!(
            body,
            "<p class=\"notice\">dev mode: <a href=\"{0}\">{0}</a></p>",
            escape(link),
        );
    }
    page_with_session(
        "check your email",
        &[(String::new(), "log in".into())],
        &body,
        &StateLine::timed(started),
        &SessionIndicator::default(),
    )
}

/// The two-step "single sign-on available" page (domain capture, not
/// enforced).
///
/// Shown after `POST /login` when the typed email's domain is captured by an
/// org that has an OIDC IdP but does *not* enforce SSO: it offers a "Sign in
/// with SSO" button (`POST /auth/sso` with the org slug — no-JS) alongside a
/// fall-back link to request a magic link. `start_url` is the
/// `/auth/oidc/start?org=…` link the GET entry point uses.
#[must_use]
pub fn login_sso_page(email: &str, org_slug: &str, start_url: &str, started: Instant) -> String {
    let mut body = String::from("<h1>Single sign-on available</h1>\n");
    let _ = writeln!(
        body,
        "<p><code>{}</code> signs in through <strong>{}</strong>'s identity \
         provider.</p>",
        escape(email),
        escape(org_slug),
    );
    let _ = writeln!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/auth/sso\">\n\
         <input type=\"hidden\" name=\"org\" value=\"{}\">\n\
         <button>sign in with SSO</button>\n</form>",
        escape(org_slug),
    );
    let _ = writeln!(
        body,
        "<p class=\"dim\">Or <a href=\"/login\">use a one-time email link</a> \
         instead. (<a href=\"{}\">direct SSO link</a>)</p>",
        escape(start_url),
    );
    page_with_session(
        "single sign-on",
        &[(String::new(), "log in".into())],
        &body,
        &StateLine::timed(started),
        &SessionIndicator::default(),
    )
}

/// The first-party inline script that drives passkey **login**
/// (`navigator.credentials.get`), nonced for the page's CSP.
///
/// The script POSTs `/auth/passkey/begin` for the options, runs the WebAuthn
/// `get` ceremony, base64url-encodes the binary response fields, and POSTs them
/// to `/auth/passkey/finish`; on success the server set a session cookie and the
/// script navigates to `/`. It is the one first-party inline script the no-JS
/// console serves, gated by `script-src 'nonce-…'`.
fn passkey_login_script(nonce: &str) -> String {
    format!(
        "<script nonce=\"{nonce}\">\n{}\n</script>\n",
        PASSKEY_LOGIN_FLOW
    )
}

/// The first-party inline script that drives passkey **registration**
/// (`navigator.credentials.create`), nonced for the page's CSP.
///
/// The script reads the CSRF token from the page, POSTs
/// `/-/account/passkeys/begin` for the options, runs the WebAuthn `create`
/// ceremony, base64url-encodes the response, and POSTs it to
/// `/-/account/passkeys/finish`; on success it reloads to show the new passkey.
fn passkey_register_script(nonce: &str) -> String {
    format!(
        "<script nonce=\"{nonce}\">\n{}\n</script>\n",
        PASSKEY_REGISTER_FLOW
    )
}

/// The passkey login ceremony flow (includes the shared b64 helpers, so each
/// script is fully self-contained and dependency-free).
const PASSKEY_LOGIN_FLOW: &str = r#"
function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');var p=s.length%4;if(p)s+='='.repeat(4-p);var bin=atob(s);var b=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)b[i]=bin.charCodeAt(i);return b.buffer;}
function bufToB64u(buf){var b=new Uint8Array(buf);var s='';for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
document.getElementById('passkey-login').addEventListener('click', async function(){
  var err=document.getElementById('passkey-error'); err.textContent='';
  try{
    var opts=await (await fetch('/auth/passkey/begin',{method:'POST',headers:{'connect-protocol-version':'1'}})).json();
    var cred=await navigator.credentials.get({publicKey:{challenge:b64uToBuf(opts.challenge),rpId:opts.rp_id,userVerification:'preferred',timeout:60000}});
    var body={credential_id:bufToB64u(cred.rawId),client_data_json:bufToB64u(cred.response.clientDataJSON),authenticator_data:bufToB64u(cred.response.authenticatorData),signature:bufToB64u(cred.response.signature)};
    var r=await fetch('/auth/passkey/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(r.ok){window.location='/';return;}
    var j=null;try{j=await r.json();}catch(e){}
    if(j&&j.redirect){window.location=j.redirect;return;}
    err.textContent='Passkey sign-in failed.';
  }catch(e){err.textContent='Passkey sign-in was cancelled or failed.';}
});
"#;

/// The passkey registration ceremony flow.
const PASSKEY_REGISTER_FLOW: &str = r#"
function b64uToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');var p=s.length%4;if(p)s+='='.repeat(4-p);var bin=atob(s);var b=new Uint8Array(bin.length);for(var i=0;i<bin.length;i++)b[i]=bin.charCodeAt(i);return b.buffer;}
function bufToB64u(buf){var b=new Uint8Array(buf);var s='';for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
document.getElementById('passkey-add').addEventListener('click', async function(){
  var err=document.getElementById('passkey-error'); err.textContent='';
  var csrf=document.getElementById('passkey-csrf').value;
  var label=document.getElementById('passkey-label').value;
  try{
    var opts=await (await fetch('/-/account/passkeys/begin',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf='+encodeURIComponent(csrf)})).json();
    var ex=(opts.exclude_credentials||[]).map(function(id){return {type:'public-key',id:b64uToBuf(id)};});
    var cred=await navigator.credentials.create({publicKey:{
      challenge:b64uToBuf(opts.challenge),
      rp:{id:opts.rp_id,name:opts.rp_name},
      user:{id:b64uToBuf(opts.user_handle),name:opts.user_name,displayName:opts.user_name},
      pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-8},{type:'public-key',alg:-257}],
      authenticatorSelection:{residentKey:'required',userVerification:'preferred'},
      attestation:'none',
      excludeCredentials:ex,
      timeout:60000
    }});
    var body={csrf:csrf,label:label,client_data_json:bufToB64u(cred.response.clientDataJSON),attestation_object:bufToB64u(cred.response.attestationObject)};
    var r=await fetch('/-/account/passkeys/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(r.ok){window.location.reload();}else{err.textContent='Could not register the passkey.';}
  }catch(e){err.textContent='Passkey registration was cancelled or failed.';}
});
"#;

/// The passkey management page: the user's registered passkeys and an add form.
///
/// `creds` are the user's registered credentials. `nonce` gates the inline
/// registration script (the handler sets the matching `script-src 'nonce-…'`
/// CSP). `csrf` is the per-session synchronizer token both begin and finish
/// verify.
#[must_use]
pub fn passkeys_page(
    email: &str,
    csrf: &str,
    creds: &[WebauthnCredentialRecord],
    nonce: &str,
    started: Instant,
) -> String {
    let mut body = String::from("<h1>Passkeys</h1>\n");
    body.push_str(
        "<p class=\"dim\">Passkeys sign you in with your device — no password, \
         no one-time link. Add one per device or browser.</p>\n",
    );

    if creds.is_empty() {
        body.push_str("<p class=\"dim\">No passkeys registered yet.</p>\n");
    } else {
        // The WebAuthn signature counter is deliberately not shown: synced
        // passkeys (iCloud Keychain, Google Password Manager, …) report it as 0
        // by spec, so it is meaningless to a human. The useful facts are the
        // label, when it was added, and when it last signed you in.
        let rows: Vec<Vec<String>> = creds
            .iter()
            .map(|c| {
                let label = c.label.as_deref().unwrap_or("passkey");
                let last = c.last_used_at.map_or_else(|| "never".to_string(), ago);
                let remove = format!(
                    "<form class=\"console\" method=\"post\" \
                     action=\"/-/account/passkeys/remove\" style=\"display:inline\">{csrf}\
                     <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                     <button class=\"danger\">remove</button></form>",
                    csrf = csrf_field(csrf),
                    id = c.id,
                );
                vec![escape(label), ago(c.created_at), escape(&last), remove]
            })
            .collect();
        body.push_str(&table(&["label", "added", "last used", ""], &rows));
    }

    // The add-passkey control. The CSRF token and label are read by the inline
    // script; the button has no <form> because the ceremony is script-driven.
    let _ = write!(
        body,
        "<h2>Add a passkey</h2>\n\
         <input type=\"hidden\" id=\"passkey-csrf\" value=\"{}\">\n\
         <p><label>label (optional) <input type=\"text\" id=\"passkey-label\" \
         placeholder=\"work laptop\"></label></p>\n\
         <p><button type=\"button\" id=\"passkey-add\">add passkey</button></p>\n\
         <p id=\"passkey-error\" class=\"bad\"></p>\n",
        escape(csrf),
    );
    body.push_str(&passkey_register_script(nonce));

    page_with_session(
        "passkeys",
        &[(String::new(), "passkeys".into())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The account profile page: email, password, sessions, tokens, passkeys.
///
/// `tokens` are `(id, scope, permissions)` tuples across every scope the
/// user owns. `password_set` reflects whether the account currently has a
/// password configured (it controls the heading and copy of the
/// set/change-password form). `error` renders an inline error banner above
/// the password form (e.g. a rejected set-password attempt). The sessions
/// section offers a "sign out everywhere" button; the passkeys section links
/// to the dedicated management page ([`passkeys_page`]).
#[must_use]
pub fn account_page(
    email: &str,
    csrf: &str,
    tokens: &[(String, String, Vec<Permission>)],
    password_set: bool,
    error: Option<&str>,
    started: Instant,
) -> String {
    // No page-title <h1>: the masthead/title already say "account".
    let mut body = format!("<p>signed in as <code>{}</code></p>\n", escape(email));

    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }

    // Password: set one, or change an existing one. The CSRF-protected form
    // posts the new password to /-/account/password for the logged-in user.
    body.push_str("<h2>Password</h2>\n");
    if password_set {
        body.push_str(
            "<p class=\"dim\">A password is set for this account. \
             Enter a new one to change it.</p>\n",
        );
    } else {
        body.push_str(
            "<p class=\"dim\">No password is set. Set one to sign in with \
             your email and password.</p>\n",
        );
    }
    body.push_str("<form class=\"console\" method=\"post\" action=\"/-/account/password\">\n");
    body.push_str(&csrf_field(csrf));
    let _ = write!(
        body,
        "<label>new password <input type=\"password\" name=\"password\" required \
         autocomplete=\"new-password\"></label>\n<button>{}</button>\n</form>\n",
        if password_set {
            "change password"
        } else {
            "set password"
        },
    );

    body.push_str("<h2>Sessions</h2>\n");
    body.push_str(
        "<p class=\"dim\">Sign out of every browser, including this one.</p>\n\
         <form class=\"console\" method=\"post\" action=\"/-/account/sessions/revoke-all\">\n",
    );
    body.push_str(&csrf_field(csrf));
    body.push_str("<button>sign out everywhere</button>\n</form>\n");

    body.push_str("<h2>Tokens</h2>\n");
    if tokens.is_empty() {
        body.push_str("<p class=\"dim\">No provisioning tokens.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = tokens
            .iter()
            .map(|(id, scope, perms)| {
                vec![
                    format!("<code>{}</code>", escape(id)),
                    format!("<code>{}</code>", escape(scope)),
                    escape(
                        &perms
                            .iter()
                            .map(|p| p.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                    format!(
                        "<a href=\"/{}/-/settings/tokens\">manage →</a>",
                        escape(scope)
                    ),
                ]
            })
            .collect();
        body.push_str(&table(&["id", "scope", "permissions", ""], &rows));
    }

    body.push_str(
        "<h2>Passkeys</h2>\n\
         <p class=\"dim\">Sign in with your device instead of an email link. \
         <a href=\"/-/account/passkeys\">Manage passkeys →</a></p>\n",
    );

    page_with_session(
        "account",
        &[(String::new(), "account".into())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The device-authorization approval page (`/activate`, RFC 8628).
///
/// Shows the requested scope and permissions for a pending device grant and
/// an approve/deny form. `user_code` prefills the field (from
/// `?user_code=`); `request` is `Some((scope, permissions))` once a code
/// resolves to a live grant, or `None` to show only the entry field.
/// `message` renders an inline result (approved/denied/expired).
#[must_use]
pub fn activate_page(
    email: &str,
    csrf: &str,
    user_code: &str,
    request: Option<(&str, &[String])>,
    message: Option<&str>,
    started: Instant,
) -> String {
    let mut body = String::from("<h1>Approve a device</h1>\n");
    body.push_str(
        "<p class=\"dim\">A command-line tool is asking to sign in as you. \
         Enter the code it printed.</p>\n",
    );
    if let Some(message) = message {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(message));
    }

    // The code-entry form (GET) prefills from ?user_code= so a copy-pasted
    // verification URL lands straight on the request.
    let _ = write!(
        body,
        "<form class=\"console\" method=\"get\" action=\"/activate\">\n\
         <label>code <input type=\"text\" name=\"user_code\" value=\"{}\" \
         placeholder=\"ABCD-1234\"></label>\n<button>look up</button>\n</form>\n",
        escape(user_code),
    );

    if let Some((scope, perms)) = request {
        let scope_label = if scope.is_empty() {
            "the whole instance".to_string()
        } else {
            format!("<code>{}</code>", escape(scope))
        };
        let perm_label = if perms.is_empty() {
            "(none requested)".to_string()
        } else {
            escape(&perms.join(", "))
        };
        let _ = writeln!(
            body,
            "<p class=\"confirm\">This grants a token for {scope_label} \
             with permissions <strong>{perm_label}</strong>, clamped to your own grants.</p>",
        );
        body.push_str("<form class=\"console\" method=\"post\" action=\"/activate\">\n");
        body.push_str(&csrf_field(csrf));
        let _ = write!(
            body,
            "<input type=\"hidden\" name=\"user_code\" value=\"{}\">\n\
             <button name=\"decision\" value=\"approve\">approve</button> \
             <button name=\"decision\" value=\"deny\">deny</button>\n</form>\n",
            escape(user_code),
        );
    }

    page_with_session(
        "activate",
        &[(String::new(), "activate".into())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The user's org list, derived from their memberships.
///
/// `can_create` reveals the "create an organization" link to a caller the
/// instance signup policy permits to create one (open signup, an existing
/// member, an invitee, or an instance admin); the link targets the
/// [`new_org_page`] form at `/new`.
#[must_use]
pub fn orgs_page(
    email: &str,
    orgs: &[OrgRecord],
    can_create: bool,
    is_instance_admin: bool,
    page_number: usize,
    started: Instant,
) -> String {
    // No page-title <h1>: the masthead/title already say "organizations".
    let mut body = String::new();
    if can_create {
        body.push_str("<p><a href=\"/new\">+ create an organization</a></p>\n");
    }
    if orgs.is_empty() {
        body.push_str("<p class=\"dim\">You are not a member of any organization.</p>\n");
    } else {
        let pager = Pager::new(page_number, LIST_PER_PAGE, orgs.len());
        let rows: Vec<Vec<String>> = pager
            .slice(orgs)
            .iter()
            .map(|org| {
                vec![
                    format!(
                        "<a href=\"/-/org/{0}\">{1}</a>",
                        escape(&org.slug),
                        escape(&org.name)
                    ),
                    format!("<code>{}</code>", escape(&org.slug)),
                ]
            })
            .collect();
        body.push_str(&table(&["organization", "slug"], &rows));
        body.push_str(&pager.nav("/-/orgs", ""));
    }
    // Instance administration is deployment-wide, distinct from "your orgs", so
    // it is its own clearly-labelled section rather than a stray link up top.
    if is_instance_admin {
        body.push_str("<h2>Instance administration</h2>\n");
        body.push_str(
            "<p class=\"dim\">Deployment-wide settings for instance admins — the signup \
             policy and the default storage backend.</p>\n\
             <p><a href=\"/-/instance\">instance settings →</a></p>\n",
        );
    }
    page_with_session(
        "organizations",
        &[(String::new(), "organizations".into())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The "create an organization" form (`/new`).
///
/// A CSRF-protected `POST /new` form taking a slug and a display name. The
/// page is only reached by a caller the signup policy permits (the handler
/// gates `GET`/`POST` identically); `error` renders an inline rejection (a bad
/// slug, a taken slug, or a policy denial re-rendered as a message).
#[must_use]
pub fn new_org_page(email: &str, csrf: &str, error: Option<&str>, started: Instant) -> String {
    let mut body = String::from("<h1>Create an organization</h1>\n");
    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }
    body.push_str("<form class=\"console\" method=\"post\" action=\"/new\">\n");
    body.push_str(&csrf_field(csrf));
    // The slug placeholder shows the format; the only non-obvious fact is that it
    // is permanent, kept as a terse field hint rather than a paragraph.
    body.push_str(
        "<label>slug <input type=\"text\" name=\"slug\" required \
         placeholder=\"acme\"> <span class=\"dim\">permanent</span></label>\n\
         <label>display name <input type=\"text\" name=\"name\" required \
         placeholder=\"Acme, Inc.\"></label>\n\
         <button>create organization</button>\n</form>\n",
    );
    page_with_session(
        "create organization",
        &[
            ("/-/orgs".into(), "organizations".into()),
            (String::new(), "new".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// A member row for the org dashboard: principal label, kind, and role.
#[derive(Debug, Clone)]
pub struct MemberRow {
    /// Display label (email for users, `sa:org/name`-style for accounts).
    pub label: String,
    /// Principal kind wire string (`user`/`service_account`).
    pub kind: String,
    /// Principal row id (used by the remove form).
    pub id: i64,
    /// Granted role name at the org scope.
    pub role: String,
}

/// A binary cache row for the org dashboard list: identity, access, and usage.
pub struct CacheSummary {
    /// URL slug the cache is served under.
    pub slug: String,
    /// Display name.
    pub name: String,
    /// Access scope (`public`/`internal`/`private`).
    pub visibility: String,
    /// Whether the cache signs its `.narinfo` with a hosted key.
    pub signed: bool,
    /// `nix-cache-info` priority (lower = preferred substituter).
    pub priority: i64,
    /// Sum of object sizes in bytes.
    pub used_bytes: i64,
    /// Number of indexed objects.
    pub object_count: i64,
}

/// A linked registry shown on a cache's detail page.
pub struct CacheLinkRow {
    /// The linked registry's slug.
    pub registry_slug: String,
    /// The registry's live store paths pin GC roots in this cache.
    pub roots_packages: bool,
    /// A non-blocking visibility warning for this link (e.g. a private
    /// registry's closures rooted into this more-visible cache), or `None`.
    pub warning: Option<String>,
}

/// A manual GC pin shown on a cache's detail page (one `cache_gc_roots` row of
/// `root_kind = 'manual'`), enriched with its store-path closure summary.
///
/// A pin is a manual GC root: it keeps `store_hash` and its transitive closure
/// from being reclaimed by garbage collection. The closure figures
/// ([`closure_size`](Self::closure_size) / [`closure_count`](Self::closure_count))
/// are computed by BFS-walking [`crate::db::CacheObject::refs`] from the pinned
/// root, so an operator can see what each pin actually retains before unpinning.
pub struct CachePinRow {
    /// The pinned store-path hash component (the `.narinfo` key).
    pub store_hash: String,
    /// The pinned path's `<hash>-<name>` store name, or `""` when the object is
    /// not (or no longer) indexed in this cache (a dangling pin).
    pub store_name: String,
    /// Sum of `file_size` (compressed NAR bytes) over the present closure nodes.
    pub closure_size: u64,
    /// Number of present (indexed) objects in the closure, including the root.
    pub closure_count: u64,
    /// Whether the pinned root object itself is present in the cache index.
    /// `false` marks a pin whose target has not been uploaded (or was purged).
    pub present: bool,
    /// Pin deadline (unix seconds); `None` pins indefinitely. Past it, the pin
    /// stops rooting and the closure becomes collectable.
    pub expires_at: Option<i64>,
    /// When the pin was created (unix seconds).
    pub created_at: i64,
}

/// A linked binary cache classified against the registry's committed
/// `[caches]`, shown on the registry's caches reconciliation tab.
pub struct RegistryCacheRow {
    /// The linked cache's slug.
    pub cache_slug: String,
    /// The cache's consumer-facing URL (a bucket-direct frontend, else the
    /// hub-served `{external_url}/{cache_slug}`) — what the committed `[caches]`
    /// is matched against.
    pub consumer_url: String,
    /// The registry's live store paths pin GC roots in this cache.
    pub roots_packages: bool,
    /// The committed `[caches]` priority when this cache's [`consumer_url`] is
    /// served from config, or `None` when the link exists but the cache is not
    /// advertised in the committed config.
    ///
    /// [`consumer_url`]: Self::consumer_url
    pub config_priority: Option<u32>,
}

/// A registry's DB-linked cache offered as a config-editor autofill suggestion.
///
/// The config editor lists these so an admin can one-click insert a linked
/// cache's correct consumer URL into the `[caches]` editor, with a live
/// present/missing indicator against the current config.
pub struct LinkedCacheSuggestion {
    /// The linked cache's slug.
    pub cache_slug: String,
    /// The cache's consumer-facing URL (bucket-direct frontend, else the
    /// hub-served `{external_url}/{cache_slug}`) — what is inserted.
    pub consumer_url: String,
    /// Whether this URL is already present in the editor's current `[caches]`.
    pub present: bool,
}

/// A read-only, public-safe placement summary shown on a surface overview.
///
/// Database ids and backend-specific partition rules are deliberately absent;
/// handlers resolve the storage binding to its scope-local name before render.
pub struct PlacementOverviewRow {
    /// Stable placement name within the registry or cache.
    pub name: String,
    /// Scope-local storage binding name.
    pub binding_name: String,
    /// Binding-relative object prefix.
    pub prefix: String,
    /// Placement role (`primary`, `replica`, `shard`, or `archive`).
    pub role: String,
    /// Lifecycle state.
    pub state: String,
    /// Whether reads may select this placement.
    pub read_enabled: bool,
    /// Whether writes may select this placement.
    pub write_enabled: bool,
}

fn placement_overview(rows: &[PlacementOverviewRow]) -> String {
    let mut body = String::from("<h2>Physical placements</h2>\n");
    if rows.is_empty() {
        body.push_str(
            "<p class=\"dim\">No physical placements are registered for this surface.</p>\n",
        );
        return body;
    }
    let table_rows = rows
        .iter()
        .map(|placement| {
            vec![
                escape(&placement.name),
                escape(&placement.role),
                escape(&placement.state),
                escape(&placement.binding_name),
                if placement.prefix.is_empty() {
                    "<span class=\"dim\">root</span>".to_string()
                } else {
                    format!("<code>{}</code>", escape(&placement.prefix))
                },
                if placement.read_enabled {
                    "<span class=\"ok\">read</span>".to_string()
                } else {
                    "<span class=\"dim\">read off</span>".to_string()
                },
                if placement.write_enabled {
                    "<span class=\"ok\">write</span>".to_string()
                } else {
                    "<span class=\"dim\">write off</span>".to_string()
                },
            ]
        })
        .collect::<Vec<_>>();
    body.push_str(&table(
        &[
            "placement",
            "role",
            "state",
            "binding",
            "prefix",
            "reads",
            "writes",
        ],
        &table_rows,
    ));
    body
}

/// The org dashboard: projects, registries, members, bindings, audit link.
///
/// `can_manage_members` gates the member-management controls (invite/remove)
/// to admins; a viewer sees the lists without the forms. `can_configure` gates
/// registry, project, and cache creation. `can_manage_storage` separately
/// gates binding mutations and backend locations. `can_delete` gates the
/// typed-confirmation org-delete form to an org owner. `owner_count` is the
/// number of org owners, used to hard-block removing the last one.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn org_dashboard(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    projects: &[ProjectRecord],
    registries: &[RegistryRecord],
    members: &[MemberRow],
    bindings: &[StorageBindingRecord],
    caches: &[CacheSummary],
    can_manage_members: bool,
    // Retained for the caller's signature; the audit link is now an always-present
    // sidebar tab whose page enforces `audit.read` itself.
    _can_read_audit: bool,
    can_configure: bool,
    // Backend locations and binding mutations require the narrower storage
    // authority used by the binding-detail handlers. Registry configuration
    // alone must not reveal host paths or object-store endpoints.
    can_manage_storage: bool,
    can_delete: bool,
    owner_count: usize,
    registries_page: usize,
    members_page: usize,
    // Which org section to render. `overview` is the read-only landing page;
    // resource inventories and mutation controls live in their named sections.
    active: &str,
    started: Instant,
) -> String {
    // The registries and members inventories paginate independently on their
    // own routes.
    let reg_pager = Pager::new(registries_page, LIST_PER_PAGE, registries.len());
    let mem_pager = Pager::new(members_page, LIST_PER_PAGE, members.len());
    let slug = &org.slug;
    // The shared settings layout supplies the contextual section <h1>. This
    // identity line adds the organization's display name and canonical slug.
    let mut body = format!(
        "<p class=\"dim\">{} · <code>{}</code></p>\n",
        escape(&org.name),
        escape(slug),
    );

    // -- Overview (the default route) ----------------------------------------
    if active == "overview" {
        body.push_str(
            "<h2>Organization topology</h2>\n\
             <p class=\"dim\">Resources, storage, and access owned by this organization.</p>\n\
             <div class=\"settings-overview-grid\">\n",
        );
        let cards = [
            ("registries", "Registries", registries.len()),
            ("projects", "Projects", projects.len()),
            ("caches", "Caches", caches.len()),
            ("storage", "Storage bindings", bindings.len()),
            ("members", "Members", members.len()),
        ];
        for (path, label, count) in cards {
            let _ = write!(
                body,
                "<a class=\"settings-overview-card\" href=\"/-/org/{slug}/{path}\">\
                 <strong>{count}</strong><span>{label}</span></a>\n",
                slug = escape(slug),
                path = escape(path),
                label = escape(label),
            );
        }
        body.push_str("</div>\n");
    }

    // -- Registries ----------------------------------------------------------
    if active == "registries" {
        if registries.is_empty() {
            body.push_str("<p class=\"dim\">No registries.</p>\n");
        } else {
            let rows: Vec<Vec<String>> = reg_pager
                .slice(registries)
                .iter()
                .map(|reg| {
                    let s = escape(&reg.slug);
                    // The name links to management (the row's primary action);
                    // the right column carries an explicit View → (public home)
                    // and, for a configurer, Manage →. A non-configurer can't
                    // manage, so the name falls back to the home and only View →
                    // shows.
                    let (name, actions) = if can_configure {
                        (
                            format!("<a href=\"/{s}/-/settings\">{s}</a>"),
                            format!(
                                "<a href=\"/{s}/\">View →</a> · \
                                 <a href=\"/{s}/-/settings\">Manage →</a>"
                            ),
                        )
                    } else {
                        (
                            format!("<a href=\"/{s}/\">{s}</a>"),
                            format!("<a href=\"/{s}/\">View →</a>"),
                        )
                    };
                    vec![name, escape(&reg.visibility), actions]
                })
                .collect();
            body.push_str(&table(&["registry", "visibility", ""], &rows));
            body.push_str(&reg_pager.nav_with(
                &format!("/-/org/{slug}/registries"),
                "",
                "registries_page",
            ));
        }
        if can_configure {
            let _ = writeln!(
                body,
                "<p><a href=\"/-/org/{}/registries/new\">+ create a registry</a></p>",
                escape(slug),
            );
        }
    }

    // -- Binary caches -------------------------------------------------------
    if active == "caches" {
        if caches.is_empty() {
            body.push_str("<p class=\"dim\">No caches.</p>\n");
        } else {
            let rows: Vec<Vec<String>> = caches
                .iter()
                .map(|c| {
                    let signed = if c.signed {
                        "<span class=\"chip\">signed</span>".to_string()
                    } else {
                        String::new()
                    };
                    vec![
                        format!(
                            "<a href=\"/-/org/{org}/caches/{slug}\">{slug}</a>",
                            org = escape(slug),
                            slug = escape(&c.slug),
                        ),
                        escape(&c.visibility),
                        signed,
                        c.priority.to_string(),
                        c.object_count.to_string(),
                        human_size(c.used_bytes.max(0) as u64),
                    ]
                })
                .collect();
            body.push_str(&table(
                &["cache", "visibility", "", "priority", "objects", "size"],
                &rows,
            ));
        }
        if can_configure {
            // A cache uses the deployment's default storage unless a custom
            // binding is selected — the first option, mirroring registry create.
            let mut binding_options = String::from("<option value=\"\">default storage</option>");
            for b in bindings {
                let _ = write!(
                    binding_options,
                    "<option value=\"{name}\">{name}</option>",
                    name = escape(&b.name),
                );
            }
            body.push_str("<h4>Create a binary cache</h4>\n");
            let _ = write!(
                body,
                "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches\">\n{csrf}\
                 <label>slug <input type=\"text\" name=\"slug\" required placeholder=\"cache\"></label>\n\
                 <label>name <input type=\"text\" name=\"name\" placeholder=\"Build cache\"> \
                 <span class=\"dim\">optional</span></label>\n\
                 <label>storage binding <select name=\"binding\">{bindings}</select></label>\n\
                 <label><span class=\"lbl\">visibility{vis}</span> <select name=\"visibility\">\
                 <option value=\"private\">private</option>\
                 <option value=\"internal\">internal</option>\
                 <option value=\"public\">public</option></select></label>\n\
                 <label><span class=\"lbl\">priority{prio}</span> <input type=\"number\" name=\"priority\" value=\"40\"></label>\n\
                 <label><span class=\"lbl\">compression{comp}</span> <select name=\"compression\">\
                 <option value=\"zstd\">zstd</option>\
                 <option value=\"xz\">xz</option>\
                 <option value=\"none\">none</option></select></label>\n\
                 <label><span class=\"lbl\">advertise mass-query{mq}</span> \
                 <input type=\"checkbox\" name=\"want_mass_query\" value=\"1\" checked></label>\n\
                 <button>create cache</button>\n</form>\n",
                org = escape(slug),
                csrf = csrf_field(csrf),
                bindings = binding_options,
                vis = help::marker("cache.visibility"),
                prio = help::marker("cache.priority"),
                comp = help::marker("cache.compression"),
                mq = help::marker("cache.mass_query"),
            );
        }
    }

    // -- Projects ------------------------------------------------------------
    if active == "projects" {
        if projects.is_empty() {
            body.push_str("<p class=\"dim\">No projects.</p>\n");
        } else {
            let rows: Vec<Vec<String>> = projects
                .iter()
                .map(|p| {
                    let action = if can_configure {
                        format!(
                            "<form class=\"console\" method=\"post\" \
                         action=\"/-/org/{org}/projects/delete\" style=\"display:inline\">{csrf}\
                         <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                         <button class=\"danger\">delete</button></form>",
                            org = escape(slug),
                            csrf = csrf_field(csrf),
                            id = p.id,
                        )
                    } else {
                        String::new()
                    };
                    vec![
                        escape(if p.path.is_empty() { "(root)" } else { &p.path }),
                        escape(&p.name),
                        action,
                    ]
                })
                .collect();
            body.push_str(&table(&["path", "name", ""], &rows));
        }
        if can_configure {
            body.push_str("<h4>Create a project</h4>\n");
            let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/projects\">\n{csrf}\
             <label>path <input type=\"text\" name=\"path\" placeholder=\"infra/prod\"> \
             <span class=\"dim\">optional</span></label>\n\
             <label>name <input type=\"text\" name=\"name\" required placeholder=\"Production\"></label>\n\
             <button>create project</button>\n</form>\n",
            org = escape(slug),
            csrf = csrf_field(csrf),
        );
        }
    }

    // -- Storage -------------------------------------------------------------
    if active == "storage" {
        // The deployment's default storage is always present and is what new
        // registries use with no binding at all. Render it as the first row — a
        // `default` chip, no delete — so it is *apparent* that storage already works
        // and any custom binding is purely additive (no prose needed to say so). Its
        // concrete location is a deployment-global setting shown on instance
        // settings, so the location cell links there rather than repeating it.
        // Render bindings as a compact stacked list (see `.binding` in the
        // stylesheet), not a 4-column table: a long object-store endpoint URL
        // gets the full content width to wrap into rather than squeezing the
        // name/kind columns until a name spans two lines and the delete button
        // hyphenates. The deployment default is always the first block (a
        // `default` chip, no delete) so it is apparent storage already works and
        // a binding is additive; its concrete location lives on instance
        // settings, so the location links there.
        body.push_str("<div class=\"bindings\">\n");
        let _ = write!(
            body,
            "<div class=\"binding\"><div class=\"binding-head\">\
             <span class=\"binding-name\"><span class=\"chip\">default</span></span>\
             <span class=\"chip\">{kind}</span></div>\
             <div class=\"binding-loc\"><a href=\"/-/instance/storage\">deployment default →</a></div>\
             </div>\n",
            kind = escape(RuntimeKind::current().default_storage_kind()),
        );
        for b in bindings.iter() {
            // The name links to the binding's serving page (public access +
            // frontends) only for callers with storage management authority.
            let name_cell = if can_manage_storage {
                format!(
                    "<a href=\"/-/org/{org}/bindings/{id}\">{name}</a>",
                    org = escape(slug),
                    id = b.id,
                    name = escape(&b.name),
                )
            } else {
                escape(&b.name)
            };
            let delete = if can_manage_storage {
                format!(
                    "<form class=\"console\" method=\"post\" \
                     action=\"/-/org/{org}/bindings/delete\">{csrf}\
                     <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                     <button class=\"danger\">delete</button></form>",
                    org = escape(slug),
                    csrf = csrf_field(csrf),
                    id = b.id,
                )
            } else {
                String::new()
            };
            // Object stores carry an access chip in the head and the
            // endpoint+bucket on the wrapping location line; never the sealed
            // credential. local_fs shows its host path.
            let (access_chip, location) = if !can_manage_storage {
                (
                    String::new(),
                    "<span class=\"dim\">location hidden · storage management required</span>"
                        .to_string(),
                )
            } else if b.kind == "local_fs" {
                (String::new(), format!("<code>{}</code>", escape(&b.root)))
            } else {
                let endpoint = b.endpoint.as_deref().unwrap_or("");
                (
                    format!("<span class=\"chip\">{}</span>", escape(&b.access)),
                    format!(
                        "<code>{endpoint}/{bucket}</code>",
                        endpoint = escape(endpoint.trim_end_matches('/')),
                        bucket = escape(&b.root),
                    ),
                )
            };
            let _ = write!(
                body,
                "<div class=\"binding\"><div class=\"binding-head\">\
                 <span class=\"binding-name\">{name}</span>\
                 <span class=\"chip\">{kind}</span>{access}{delete}</div>\
                 <div class=\"binding-loc\">{location}</div></div>\n",
                name = name_cell,
                kind = escape(&b.kind),
                access = access_chip,
                delete = delete,
                location = location,
            );
        }
        body.push_str("</div>\n");
        if can_manage_storage {
            let creatable = RuntimeKind::current().creatable_binding_kinds();
            body.push_str("<h4>Add a storage binding</h4>\n");
            let mut kind_options = String::new();
            for kind in &creatable {
                let _ = write!(
                    kind_options,
                    "<option value=\"{value}\">{label}</option>",
                    value = escape(kind.as_str()),
                    label = escape(kind.label()),
                );
            }
            let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/bindings\" \
             data-binding-kind>\n{csrf}\
             <label>name <input type=\"text\" name=\"name\" required placeholder=\"primary\"></label>\n\
             <label><span class=\"lbl\">kind{kind_help}</span> <select name=\"kind\">{kinds}</select></label>\n\
             <label><span><span class=\"local-only\">path</span><span class=\"s3-only\">bucket</span></span> \
             <input type=\"text\" name=\"root\" required placeholder=\"/srv/registries/acme\"></label>\n\
             <div class=\"s3-only\">\n\
             <label><span class=\"lbl\">endpoint{endpoint_help}</span> <input type=\"text\" name=\"endpoint\" \
             placeholder=\"https://&lt;account&gt;.r2.cloudflarestorage.com\"></label>\n\
             <label><span class=\"lbl\">region{region_help}</span> <input type=\"text\" name=\"region\" value=\"auto\"></label>\n\
             <label><span class=\"lbl\">access{access_help}</span> <select name=\"access\">\
             <option value=\"private\">private (read/write, credentialed)</option>\
             <option value=\"public\">public (read-only, no credentials)</option></select></label>\n\
             <label class=\"private-only\">access key id \
             <input type=\"text\" name=\"access_key_id\" autocomplete=\"off\"></label>\n\
             <label class=\"private-only\">secret access key \
             <input type=\"password\" name=\"secret_access_key\" autocomplete=\"off\"></label>\n\
             </div>\n\
             <button>create binding</button>\n</form>\n",
            org = escape(slug),
            csrf = csrf_field(csrf),
            kinds = kind_options,
            kind_help = help::marker("binding.kind"),
            access_help = help::marker("binding.access"),
            endpoint_help = help::marker("binding.endpoint"),
            region_help = help::marker("binding.region"),
        );
        }
    }

    // -- Members -------------------------------------------------------------
    if active == "members" {
        let rows: Vec<Vec<String>> = mem_pager
            .slice(members)
            .iter()
            .map(|m| {
                let mut action = String::new();
                if can_manage_members {
                    // A role-change form: a select of the five roles (current one
                    // pre-selected). Demoting the last owner is blocked server-side.
                    let mut options = String::new();
                    for role in ["owner", "admin", "maintainer", "developer", "viewer"] {
                        let sel = if role == m.role { " selected" } else { "" };
                        let _ = write!(options, "<option value=\"{role}\"{sel}>{role}</option>");
                    }
                    let _ = write!(
                        action,
                        "<form class=\"console\" method=\"post\" \
                     action=\"/-/org/{org}/members/role\" style=\"display:inline\">{csrf}\
                     <input type=\"hidden\" name=\"principal_kind\" value=\"{kind}\">\
                     <input type=\"hidden\" name=\"principal_id\" value=\"{id}\">\
                     <select name=\"role\">{options}</select> <button>set role</button></form> ",
                        org = escape(&org.slug),
                        csrf = csrf_field(csrf),
                        kind = escape(&m.kind),
                        id = m.id,
                    );
                    // The remove form, unless this is the final owner.
                    let is_last_owner = m.role == "owner" && owner_count <= 1;
                    if is_last_owner {
                        action.push_str("<span class=\"dim\">last owner</span>");
                    } else {
                        let _ = write!(
                            action,
                            "<form class=\"console\" method=\"post\" \
                         action=\"/-/org/{}/members/remove\" style=\"display:inline\">{}\
                         <input type=\"hidden\" name=\"principal_kind\" value=\"{}\">\
                         <input type=\"hidden\" name=\"principal_id\" value=\"{}\">\
                         <button class=\"danger\">remove</button></form>",
                            escape(&org.slug),
                            csrf_field(csrf),
                            escape(&m.kind),
                            m.id,
                        );
                    }
                }
                vec![escape(&m.label), escape(&m.role), action]
            })
            .collect();
        body.push_str(&table(&["member", "role", ""], &rows));
        body.push_str(&mem_pager.nav_with(&format!("/-/org/{slug}/members"), "", "members_page"));

        if can_manage_members {
            body.push_str("<h4>Invite a member</h4>\n");
            let _ = write!(
                body,
                "<form class=\"console\" method=\"post\" action=\"/-/org/{}/members\">\n{}\
             <label>email <input type=\"email\" name=\"email\" required></label>\n\
             <label>role <select name=\"role\">\
             <option value=\"viewer\">viewer</option>\
             <option value=\"developer\">developer</option>\
             <option value=\"maintainer\">maintainer</option>\
             <option value=\"admin\">admin</option>\
             <option value=\"owner\">owner</option></select></label>\n\
             <button>send invitation</button>\n</form>\n",
                escape(&org.slug),
                csrf_field(csrf),
            );
        }
    }

    // -- Danger zone: delete the org -----------------------------------------
    if active == "danger" {
        if can_delete {
            body.push_str("<h2 class=\"danger\">Delete organization</h2>\n");
            let _ = write!(
            body,
            "<p class=\"dim\">Soft-deletes the org and everything it owns, opening a 30-day grace \
             window before permanent purge. The org stops serving immediately. Type the slug \
             <code>{slug}</code> to confirm.</p>\n\
             <form class=\"console\" method=\"post\" action=\"/-/org/{slug}/delete\">\n{csrf}\
             <label>confirm slug <input type=\"text\" name=\"confirm\" required \
             placeholder=\"{slug}\"></label>\n\
             <button class=\"danger\">delete organization</button>\n</form>\n",
            slug = escape(slug),
            csrf = csrf_field(csrf),
        );
        } else {
            body.push_str(
                "<p class=\"dim\">You do not have permission to delete this organization.</p>\n",
            );
        }
    }

    org_settings_chrome(email, slug, active, &body, started)
}

/// A managed binary cache's detail page: configuration, usage, linked
/// registries, and (for an admin) the update / link / GC / delete controls.
///
/// `can_admin` gates every mutating form; a plain member sees the read-only
/// configuration and usage. `linkable` is the org's registries available to link
/// (already-linked ones are omitted). `pins` are the cache's manual GC pins
/// (admin-only), each with its closure summary. `notice` renders the outcome of
/// the last action (e.g. a GC sweep summary or a pin add/remove).
/// One row of the global caches list ([`caches_page`]): a cache and its owning
/// organization.
pub struct CacheListRow {
    /// Owning org slug (empty for an org-less / instance cache).
    pub org_slug: String,
    /// The cache slug.
    pub slug: String,
    /// The cache's display name (falls back to the slug when empty).
    pub name: String,
    /// Visibility: `public` | `internal` | `private`.
    pub visibility: String,
}

/// The global binary-caches list — the masthead **caches** tab.
///
/// Lists every cache the viewer may see (a signed-in user: caches readable on
/// their orgs, plus public caches; an anonymous viewer, only when the instance
/// has opted caches public: public caches only), each linking to its cache page.
/// `email` is `Some` for a signed-in viewer.
#[must_use]
pub fn caches_page(email: Option<&str>, caches: &[CacheListRow], started: Instant) -> String {
    let mut body = String::from("<h1>Caches</h1>\n");
    body.push_str("<p class=\"dim\">Binary caches across organizations.</p>\n");
    if caches.is_empty() {
        body.push_str("<p class=\"dim\">No caches.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = caches
            .iter()
            .map(|c| {
                let label = if c.name.is_empty() {
                    escape(&c.slug)
                } else {
                    escape(&c.name)
                };
                let link = format!(
                    "<a href=\"/-/org/{org}/caches/{slug}\">{label}</a>",
                    org = escape(&c.org_slug),
                    slug = escape(&c.slug),
                    label = label,
                );
                let org = if c.org_slug.is_empty() {
                    "<span class=\"dim\">—</span>".to_string()
                } else {
                    format!(
                        "<a href=\"/-/org/{org}\">{org}</a>",
                        org = escape(&c.org_slug)
                    )
                };
                vec![
                    link,
                    org,
                    format!("<span class=\"chip\">{}</span>", escape(&c.visibility)),
                ]
            })
            .collect();
        body.push_str(&table(&["cache", "organization", "visibility"], &rows));
    }
    let session = match email {
        Some(e) => indicator(e),
        None => SessionIndicator::anonymous(),
    };
    page_with_session(
        "caches",
        &[(String::new(), "caches".to_string())],
        &body,
        &StateLine::timed(started),
        &session,
    )
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn cache_page(
    email: &str,
    org_slug: &str,
    csrf: &str,
    cache: &Cache,
    binding_name: &str,
    placements: &[PlacementOverviewRow],
    bindings: &[String],
    usage: &CacheUsage,
    links: &[CacheLinkRow],
    linkable: &[(String, String)],
    pins: &[CachePinRow],
    // Recent GC runs (newest first), shown as history on the GC & pins tab.
    gc_runs: &[CacheGcRun],
    can_admin: bool,
    // Whether this cache advertises its inherited storage-binding frontend
    // (RFC-0004 §12) — the serving tab's opt-out checkbox.
    advertise_storage_frontend: bool,
    // The active settings section: "overview", "general", "storage",
    // "serving", "links", "pins", or "danger".
    active: &str,
    notice: Option<&str>,
    started: Instant,
) -> String {
    let mut body = String::new();
    // The action-result notice shows on whichever tab the action returned to.
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }

    // -- Overview: read-only identity, topology, and usage -------------------
    if active == "overview" {
        let _ = write!(body, "<h1>Cache · {}</h1>\n", escape(&cache.slug));
        // Usage + identity chips.
        let signed = if cache.hosted_key_id.is_some() {
            " · <span class=\"chip\">signed</span>"
        } else {
            ""
        };
        let _ = write!(
            body,
            "<p class=\"chips\"><span class=\"chip\">{vis}</span>\
             <span class=\"chip\">priority {prio}</span>\
             <span class=\"chip\">{comp}</span>{signed}</p>\n\
             <p class=\"dim\">{objects} objects · {size} · {links} linked · created {ago}</p>\n",
            vis = escape(&cache.visibility),
            prio = cache.priority,
            comp = escape(&cache.compression),
            signed = signed,
            objects = usage.object_count,
            size = human_size(usage.used_bytes.max(0) as u64),
            links = links.len(),
            ago = ago(cache.created_at),
        );
        let _ = write!(
            body,
            "<div class=\"settings-overview-grid\">\
             <a class=\"settings-overview-card\" href=\"/-/org/{org}/caches/{slug}/storage\">\
             <strong>{binding}</strong><span>Storage</span></a>\
             <a class=\"settings-overview-card\" href=\"/-/org/{org}/caches/{slug}/links\">\
             <strong>{links}</strong><span>Registry relationships</span></a>\
             <a class=\"settings-overview-card\" href=\"/-/org/{org}/caches/{slug}/pins\">\
             <strong>{objects}</strong><span>Objects under GC</span></a></div>\n",
            org = escape(org_slug),
            slug = escape(&cache.slug),
            binding = escape(binding_name),
            links = links.len(),
            objects = usage.object_count,
        );
        body.push_str(&placement_overview(placements));
    }

    // -- Storage tab: binding location + change storage ---------------------
    if active == "storage" {
        body.push_str("<h2>Current storage</h2>\n");
        let _ = write!(
            body,
            "<p class=\"dim\">binding <code>{binding}</code>{prefix}</p>\n",
            binding = escape(binding_name),
            prefix = if cache.prefix.is_empty() {
                String::new()
            } else {
                format!(" · prefix <code>{}</code>", escape(&cache.prefix))
            },
        );
    }
    if active == "storage" && can_admin {
        // Change storage: copy every object to a new backend, then re-point.
        let on_default = cache.storage_binding_id.is_none();
        let mut options = String::new();
        if !on_default {
            options.push_str("<option value=\"\">default storage</option>");
        }
        for b in bindings {
            if b != binding_name {
                let _ = write!(options, "<option value=\"{b}\">{b}</option>", b = escape(b));
            }
        }
        if !options.is_empty() {
            let _ = write!(
                body,
                "<h3>Change storage{help}</h3>\n\
                 <form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/storage\">{csrf}\
                 <label>move to <select name=\"binding\">{options}</select></label>\n\
                 <button>move storage</button>\n</form>\n",
                help = help::marker("storage.change"),
                org = escape(org_slug),
                slug = escape(&cache.slug),
                csrf = csrf_field(csrf),
                options = options,
            );
        }
    }

    // -- Serving tab: advertise the inherited bucket frontend ---------------
    if active == "serving" {
        body.push_str("<h2>Delivery status</h2>\n");
        let status = if advertise_storage_frontend {
            "advertised"
        } else {
            "hub-served"
        };
        let _ = writeln!(
            body,
            "<p>delivery <span class=\"chip\">{}</span></p>",
            status,
        );
    }
    if active == "serving" && can_admin {
        // Advertise the inherited storage-binding frontend (RFC-0004 §12): when
        // the bucket is public with a direct frontend, this cache's advertised
        // URL points consumers straight at the bucket.
        let _ = write!(
            body,
            "<h3>Bucket-direct serving</h3>\n\
             <p class=\"dim\">When this cache's storage bucket is public and has a direct \
             frontend, advertise it so the cache's URL points consumers straight at the \
             bucket.</p>\n\
             <form class=\"console\" method=\"post\" \
             action=\"/-/org/{org}/caches/{slug}/advertise-frontend\">{csrf}\
             <label><span class=\"lbl\">advertise the inherited bucket frontend</span> \
             <input type=\"checkbox\" name=\"advertise\" value=\"1\"{checked}></label>\n\
             <button>save</button>\n</form>\n",
            org = escape(org_slug),
            slug = escape(&cache.slug),
            csrf = csrf_field(csrf),
            checked = if advertise_storage_frontend {
                " checked"
            } else {
                ""
            },
        );
    }

    if active == "general" {
        body.push_str("<h2>Cache policy</h2>\n");
        let _ = write!(
            body,
            "<p class=\"dim\">Cache <code>{}</code> · created {}</p>\n",
            escape(&cache.slug),
            ago(cache.created_at),
        );
    }
    if active == "general" && can_admin {
        // -- Mutable cache policy -------------------------------------------
        let opt = |value: &str, current: &str, label: &str| {
            let sel = if value == current { " selected" } else { "" };
            format!("<option value=\"{value}\"{sel}>{label}</option>")
        };
        let mass = if cache.want_mass_query {
            " checked"
        } else {
            ""
        };
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/general\">{csrf}\
             <label>name <input type=\"text\" name=\"name\" value=\"{name}\"></label>\n\
             <label>visibility <select name=\"visibility\">{vis_pub}{vis_int}{vis_priv}</select></label>\n\
             <label>priority <input type=\"number\" name=\"priority\" value=\"{prio}\"></label>\n\
             <label>compression <select name=\"compression\">{c_zstd}{c_xz}{c_none}</select></label>\n\
             <label><span class=\"lbl\">advertise mass-query</span> \
             <input type=\"checkbox\" name=\"want_mass_query\" value=\"1\"{mass}></label>\n\
             <button>save</button>\n</form>\n",
            org = escape(org_slug),
            slug = escape(&cache.slug),
            csrf = csrf_field(csrf),
            name = escape(&cache.name),
            prio = cache.priority,
            vis_pub = opt("public", &cache.visibility, "public"),
            vis_int = opt("internal", &cache.visibility, "internal"),
            vis_priv = opt("private", &cache.visibility, "private"),
            c_zstd = opt("zstd", &cache.compression, "zstd"),
            c_xz = opt("xz", &cache.compression, "xz"),
            c_none = opt("none", &cache.compression, "none"),
            mass = mass,
        );
    } else if active == "general" {
        body.push_str(
            "<p class=\"dim\">Changing cache policy requires cache administration.</p>\n",
        );
    }

    // -- Linked registries (Links tab) --------------------------------------
    if active == "links" {
        body.push_str("<h2>Registry relationships</h2>\n");
        if links.is_empty() {
            body.push_str("<p class=\"dim\">No linked registries.</p>\n");
        } else {
            let rows: Vec<Vec<String>> = links
            .iter()
            .map(|l| {
                let mut flags: Vec<String> = Vec::new();
                if l.roots_packages {
                    flags.push("<span class=\"chip\">gc roots</span>".to_string());
                }
                let mut flags_cell = flags.join(" ");
                if let Some(warning) = &l.warning {
                    let _ = write!(
                        flags_cell,
                        "<span class=\"chip warn\">⚠ closure exposure</span>\
                         <div class=\"warn\">{}</div>",
                        escape(warning),
                    );
                }
                let action = if can_admin {
                    format!(
                        "<form class=\"console\" method=\"post\" \
                         action=\"/-/org/{org}/caches/{slug}/unlink\" style=\"display:inline\">{csrf}\
                         <input type=\"hidden\" name=\"registry\" value=\"{reg}\">\
                         <button class=\"danger\">unlink</button></form>",
                        org = escape(org_slug),
                        slug = escape(&cache.slug),
                        csrf = csrf_field(csrf),
                        reg = escape(&l.registry_slug),
                    )
                } else {
                    String::new()
                };
                vec![escape(&l.registry_slug), flags_cell, action]
            })
            .collect();
            body.push_str(&table(&["registry", "", ""], &rows));
        }
        if can_admin && !linkable.is_empty() {
            // Linking is operational only (GC-root pinning + config autofill);
            // advertising a cache to a registry's consumers is an explicit
            // `[caches]` config edit on the registry, so no advertise toggle here.
            let mut reg_options = String::new();
            for (slug, vis) in linkable {
                let _ = write!(
                    reg_options,
                    "<option value=\"{s}\">{s} · {v}</option>",
                    s = escape(slug),
                    v = escape(vis),
                );
            }
            let _ = write!(
                body,
                "<h3>Link a registry</h3>\n\
             <p class=\"dim\">Pins GC roots and lists this cache for the registry's config \
             autofill. It does not advertise the cache — do that in the registry's Config.</p>\n\
             <form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/link\">{csrf}\
             <label>registry <select name=\"registry\">{regs}</select></label>\n\
             <label><span class=\"lbl\">pin GC roots from its packages{roots_help}</span> \
             <input type=\"checkbox\" name=\"roots_packages\" value=\"1\" checked></label>\n\
             <button>link</button>\n</form>\n",
                org = escape(org_slug),
                slug = escape(&cache.slug),
                csrf = csrf_field(csrf),
                regs = reg_options,
                roots_help = help::marker("link.roots_packages"),
            );
        }
    } // end Links tab

    // -- Garbage collection + manual pins (Pins tab) ------------------------
    if active == "pins" {
        if can_admin {
            body.push_str("<h2>Garbage collection</h2>\n");
            let _ = write!(
                body,
                "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/gc\" \
                 style=\"display:inline\">{csrf}\
                 <input type=\"hidden\" name=\"dry_run\" value=\"1\"><button>preview (dry run)</button></form>\n\
                 <form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/gc\" \
                 style=\"display:inline\">{csrf}<button class=\"danger\">collect now</button></form>\n",
                org = escape(org_slug),
                slug = escape(&cache.slug),
                csrf = csrf_field(csrf),
            );
            body.push_str(&cache_gc_history_section(gc_runs));
            body.push_str(&cache_pins_section(org_slug, csrf, cache, pins));
        } else {
            body.push_str(
                "<p class=\"dim\">Garbage collection and pins are available to cache admins.</p>\n",
            );
        }
    }

    // -- Delete the cache (Danger tab) --------------------------------------
    // Mirrors the registry/org "Remove" pages: a danger heading, an explicit
    // warning, then a name-confirmation form gating the destructive button.
    if active == "danger" {
        if can_admin {
            body.push_str("<h2 class=\"danger\">Delete cache</h2>\n");
            let _ = write!(
                body,
                "<p class=\"warn\">Permanently deletes this cache and its index. Stored objects are \
                 not removed from the bucket. This cannot be undone — type the cache name \
                 <code>{slug}</code> to confirm.</p>\n\
                 <form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/delete\">{csrf}\
                 <label>confirm name <input type=\"text\" name=\"confirm\" required \
                 autocomplete=\"off\" spellcheck=\"false\"></label>\n\
                 <button class=\"danger\">delete cache</button>\n</form>\n",
                org = escape(org_slug),
                slug = escape(&cache.slug),
                csrf = csrf_field(csrf),
            );
        } else {
            body.push_str("<p class=\"dim\">Deleting a cache is available to cache admins.</p>\n");
        }
    }

    // Render inside the cache settings chrome (its own left-tabs sidebar) with
    // the active section highlighted and a `caches / {slug}` breadcrumb.
    cache_settings_chrome(email, org_slug, cache, active, &body, started)
}

/// Render the "Recent runs" garbage-collection history for a cache.
///
/// One row per recent run (newest first): when it started + its status, the
/// outcome (objects deleted/retained/scanned, or the error for a failed run, or
/// "running…" for one still in flight), and the bytes reclaimed.
fn cache_gc_history_section(gc_runs: &[CacheGcRun]) -> String {
    let mut body = String::from("<h3>Recent runs</h3>\n");
    if gc_runs.is_empty() {
        body.push_str("<p class=\"dim\">No garbage-collection runs recorded yet.</p>\n");
        return body;
    }
    body.push_str(
        "<table class=\"pins\">\n<thead><tr>\
         <th>when</th><th>result</th><th>freed</th></tr></thead>\n<tbody>\n",
    );
    for run in gc_runs {
        let status_class = match run.status.as_str() {
            "ok" => "ok",
            "failed" => "bad",
            _ => "dim",
        };
        let result = if run.status == "failed" {
            run.error
                .as_deref()
                .map_or_else(|| "<span class=\"bad\">failed</span>".to_string(), escape)
        } else if run.finished_at.is_none() {
            "<span class=\"dim\">running…</span>".to_string()
        } else {
            format!(
                "{} deleted · {} retained · {} scanned",
                run.deleted_objects, run.retained, run.scanned
            )
        };
        let _ = write!(
            body,
            "<tr>\
             <td><div>{when}</div>\
               <div class=\"subline\"><span class=\"{sc}\">{status}</span></div></td>\
             <td>{result}</td>\
             <td>{freed}</td></tr>\n",
            when = ago(run.started_at),
            sc = status_class,
            status = escape(&run.status),
            result = result,
            freed = human_size(run.freed_bytes.max(0) as u64),
        );
    }
    body.push_str("</tbody>\n</table>\n");
    body
}

/// Render the "Pins (manual GC roots)" section of a cache's detail page.
///
/// Lists each manual pin with its closure summary (package name, human-readable
/// closure size, object count, expiry, and age), a per-row **unpin** button, and
/// an **add pin** form. Re-adding an already-pinned hash renews it in place
/// (`pin_cache_path` upserts), so the form doubles as a renew control.
///
/// The whole section is admin-only; callers gate it on `can_admin`.
fn cache_pins_section(org_slug: &str, csrf: &str, cache: &Cache, pins: &[CachePinRow]) -> String {
    let org = escape(org_slug);
    let slug = escape(&cache.slug);
    let mut body = String::new();
    body.push_str("<h2>Pins (manual GC roots)</h2>\n");
    body.push_str(
        "<p class=\"dim\">A pin keeps a store path and its entire closure from \
         being reclaimed by garbage collection. Use a pin to retain a release or \
         a known-good build indefinitely (or until an expiry you set).</p>\n",
    );

    if pins.is_empty() {
        body.push_str("<p class=\"dim\">No manual pins. Add one below to root a store path.</p>\n");
    } else {
        // Four columns. The store name already begins with the hash, so the
        // package cell shows just the human name on its primary line and the hash
        // (with the pin's age) once, on a dim sub-line — no duplication. The
        // expiry column is editable in place: its form re-submits to `pin/add`,
        // which renews the pin, so a pin's lifetime can be changed without
        // re-typing its hash (blank = no expiry).
        body.push_str(
            "<table class=\"pins\">\n<thead><tr>\
             <th>package</th><th>closure</th><th>expiry</th><th></th></tr></thead>\n<tbody>\n",
        );
        for pin in pins {
            // The store name is "<hash>-<name>"; strip the hash prefix so the
            // primary line reads as the package name and the hash appears once.
            let pkg = pin
                .store_name
                .strip_prefix(pin.store_hash.as_str())
                .and_then(|rest| rest.strip_prefix('-'))
                .unwrap_or(pin.store_name.as_str());
            // A short, scannable prefix of the 32-char hash; the title carries
            // the full value for copy/inspection.
            let short_hash: String = pin.store_hash.chars().take(12).collect();
            let name = if pkg.is_empty() {
                if pin.present {
                    "<span class=\"dim\">(unnamed)</span>".to_string()
                } else {
                    "<span class=\"warn\">(not in cache)</span>".to_string()
                }
            } else {
                escape(pkg)
            };
            let closure = if pin.present {
                format!(
                    "{size} · {count} object{plural}",
                    size = human_size(pin.closure_size),
                    count = pin.closure_count,
                    plural = if pin.closure_count == 1 { "" } else { "s" },
                )
            } else {
                "<span class=\"dim\">unknown</span>".to_string()
            };
            let current_expiry = match pin.expires_at {
                Some(at) => format!("expires <span title=\"{}\">{}</span>", at, ago(at)),
                None => "<span class=\"dim\">no expiry</span>".to_string(),
            };
            let _ = write!(
                body,
                "<tr>\
                 <td><div>{name}</div>\
                   <div class=\"subline\"><code title=\"{full}\">{short}\u{2026}</code> · pinned {created}</div></td>\
                 <td>{closure}</td>\
                 <td><form class=\"console\" method=\"post\" \
                 action=\"/-/org/{org}/caches/{slug}/pin/add\" style=\"display:inline\">{csrf}\
                 <input type=\"hidden\" name=\"store_hash\" value=\"{full}\">\
                 <input type=\"number\" name=\"expires_days\" min=\"1\" autocomplete=\"off\" \
                 placeholder=\"days\"> <button>set</button></form>\
                 <div class=\"subline\">{current}</div></td>\
                 <td><form class=\"console\" method=\"post\" \
                 action=\"/-/org/{org}/caches/{slug}/pin/remove\" style=\"display:inline\">{csrf}\
                 <input type=\"hidden\" name=\"store_hash\" value=\"{full}\">\
                 <button class=\"danger\">unpin</button></form></td></tr>\n",
                name = name,
                full = escape(&pin.store_hash),
                short = escape(&short_hash),
                closure = closure,
                created = ago(pin.created_at),
                current = current_expiry,
                org = org,
                slug = slug,
                csrf = csrf_field(csrf),
            );
        }
        body.push_str("</tbody>\n</table>\n");
    }

    // -- Add / renew pin -----------------------------------------------------
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/pin/add\">{csrf}\
         <label>store hash \
         <input type=\"text\" name=\"store_hash\" autocomplete=\"off\" spellcheck=\"false\" \
         placeholder=\"32-char hash or full /nix/store/&hellip; path\" required></label>\n\
         <label>expires in \
         <input type=\"number\" name=\"expires_days\" min=\"1\" autocomplete=\"off\" \
         placeholder=\"days\"> days <span class=\"dim\">(empty = unlimited)</span></label>\n\
         <button>add pin</button>\n</form>\n",
        org = org,
        slug = slug,
        csrf = csrf_field(csrf),
    );
    body
}

/// The org audit feed page.
#[must_use]
pub fn audit_page(
    email: &str,
    org: &OrgRecord,
    rows: &[AuditRow],
    page_number: usize,
    started: Instant,
) -> String {
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    if rows.is_empty() {
        body.push_str("<p class=\"dim\">No audit entries.</p>\n");
    } else {
        let pager = Pager::new(page_number, LIST_PER_PAGE, rows.len());
        let table_rows: Vec<Vec<String>> = pager
            .slice(rows)
            .iter()
            .map(|row| {
                vec![
                    format!(
                        "{} <span class=\"dim\">({})</span>",
                        ago(row.created_at),
                        row.created_at
                    ),
                    escape(&row.actor_label),
                    format!("<code>{}</code>", escape(&row.action)),
                    format!("<code>{}</code>", escape(&row.scope)),
                    escape(row.detail.as_deref().unwrap_or("—")),
                ]
            })
            .collect();
        body.push_str(&table(
            &["when", "actor", "action", "scope", "detail"],
            &table_rows,
        ));
        body.push_str(&pager.nav(&format!("/-/org/{}/audit", org.slug), ""));
    }
    org_settings_chrome(email, &org.slug, "audit", &body, started)
}

/// The "create a registry" form (`/-/org/{org}/registries/new`).
///
/// The full create form for an org admin: a name, a project `<select>` from
/// the org's projects, a storage-binding `<select>`, a visibility `<select>`,
/// a trust-anchors textarea (one `name:Ed25519:<base64>` line each), and a
/// require-signatures checkbox. The storage-binding `<select>` always offers a
/// **Default storage** first option (the deployment's own storage — the single
/// R2 bucket on the Worker, the configured default root on the native hub), so
/// a registry can be created with zero storage configuration; each of the org's
/// custom bindings follows as an explicit choice. `error` renders an inline
/// rejection.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn new_registry_page(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    projects: &[ProjectRecord],
    bindings: &[StorageBindingRecord],
    error: Option<&str>,
    started: Instant,
) -> String {
    let org_slug = &org.slug;
    let mut body = format!("<h1>Create a registry · {}</h1>\n", escape(&org.name));
    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }

    // Project options: an org-root choice plus every materialized-path project.
    let mut project_options = String::from("<option value=\"\">(org root)</option>");
    for p in projects {
        if p.path.is_empty() {
            continue;
        }
        let _ = write!(
            project_options,
            "<option value=\"{path}\">{path}</option>",
            path = escape(&p.path),
        );
    }
    // The first option is the deployment default (binding-less storage); its
    // label names the runtime's own store so the operator knows where a
    // default-storage registry lands.
    let default_label = match RuntimeKind::current() {
        RuntimeKind::Worker => "Cloudflare R2 (this deployment)",
        RuntimeKind::Native => "default storage",
    };
    let mut binding_options = format!(
        "<option value=\"\">Default storage — {}</option>",
        escape(default_label),
    );
    for b in bindings {
        let _ = write!(
            binding_options,
            "<option value=\"{name}\">{name} ({kind})</option>",
            name = escape(&b.name),
            kind = escape(&b.kind),
        );
    }

    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/registries\">\n{csrf}\
         <label>name <input type=\"text\" name=\"name\" required placeholder=\"cdn\"></label>\n\
         <label>project <select name=\"project_path\">{projects}</select></label>\n\
         <label>storage binding <select name=\"binding\">{bindings}</select></label>\n\
         <label><span class=\"lbl\">visibility{vis_help}</span> <select name=\"visibility\">\
         <option value=\"private\">private</option>\
         <option value=\"internal\">internal</option>\
         <option value=\"public\">public</option></select></label>\n\
         <label><span class=\"lbl\">prefix{prefix_help}</span> \
         <input type=\"text\" name=\"prefix\" placeholder=\"defaults to the registry slug\"> \
         <span class=\"dim\">optional</span></label>\n\
         <label><span class=\"lbl\">trust anchors{trust_help}</span> \
         <textarea name=\"trust_keys\" rows=\"4\" cols=\"80\" \
         placeholder=\"release:Ed25519:base64...&#10;(one per line)\"></textarea> \
         <span class=\"dim\">optional</span></label>\n\
         <label><span class=\"lbl\">require signatures{sig_help}</span> \
         <input type=\"checkbox\" name=\"require_signatures\" value=\"1\" checked></label>\n\
         <button>create registry</button>\n</form>\n",
        org = escape(org_slug),
        csrf = csrf_field(csrf),
        vis_help = help::marker("registry.visibility"),
        trust_help = help::marker("registry.trust_anchors"),
        sig_help = help::marker("registry.require_signatures"),
        prefix_help = help::marker("registry.prefix"),
        projects = project_options,
        bindings = binding_options,
    );

    page_with_session(
        &format!("{org_slug} · new registry"),
        &[
            ("/-/orgs".into(), "organizations".into()),
            (format!("/-/org/{org_slug}"), org_slug.clone()),
            (String::new(), "new registry".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// One destination in a grouped settings navigation model.
struct SettingsNavItem {
    key: &'static str,
    label: &'static str,
    href: String,
}

impl SettingsNavItem {
    fn new(key: &'static str, label: &'static str, href: String) -> Self {
        Self { key, label, href }
    }
}

/// A related set of settings destinations.
struct SettingsNavGroup {
    label: &'static str,
    items: Vec<SettingsNavItem>,
}

impl SettingsNavGroup {
    fn new(label: &'static str, items: Vec<SettingsNavItem>) -> Self {
        Self { label, items }
    }
}

/// The complete navigation model for one settings scope.
struct SettingsNavigation<'a> {
    active: &'a str,
    context: String,
    groups: Vec<SettingsNavGroup>,
}

impl<'a> SettingsNavigation<'a> {
    fn new(active: &'a str, context: String, groups: Vec<SettingsNavGroup>) -> Self {
        Self {
            active,
            context,
            groups,
        }
    }
}

/// Wraps settings `content` in the shared grouped left-sidebar layout.
///
/// Renders a vertical nav of `tabs` (the active one highlighted) beside the
/// content, so the registry, org, and instance settings scopes share one
/// information architecture. The page heading lives at the top of `content`
/// (in the content column, beside the nav — the GitHub settings convention).
/// On a narrow viewport the sidebar stacks above the content (see the
/// `.settings` rules in `style.css`).
fn settings_layout(navigation: &SettingsNavigation<'_>, content: &str) -> String {
    let selected = navigation
        .groups
        .iter()
        .flat_map(|group| group.items.iter())
        .find(|item| item.key == navigation.active)
        .or_else(|| {
            navigation
                .groups
                .iter()
                .find_map(|group| group.items.first())
        });
    let selected_key = selected.map(|item| item.key);
    let mut nav = String::from("<nav class=\"settings-nav\" aria-label=\"Settings sections\">\n");
    for group in &navigation.groups {
        let _ = writeln!(
            nav,
            "<div class=\"settings-nav-group\"{}>",
            if group.label.is_empty() {
                String::new()
            } else {
                format!(" role=\"group\" aria-label=\"{}\"", escape(group.label))
            },
        );
        if !group.label.is_empty() {
            let _ = writeln!(
                nav,
                "<span class=\"settings-nav-label\" aria-hidden=\"true\">{}</span>",
                escape(group.label),
            );
        }
        for item in &group.items {
            let _ = write!(
                nav,
                "<a href=\"{href}\"{active}>{label}</a>\n",
                href = escape(&item.href),
                active = if Some(item.key) == selected_key {
                    " class=\"active\" aria-current=\"page\""
                } else {
                    ""
                },
                label = escape(item.label),
            );
        }
        nav.push_str("</div>\n");
    }
    nav.push_str("</nav>\n");
    let heading = if content.contains("<h1") {
        String::new()
    } else {
        let section = selected.map_or("Settings", |item| item.label);
        format!(
            "<h1>{section} · {context}</h1>\n",
            section = escape(section),
            context = escape(&navigation.context),
        )
    };
    format!(
        "<div class=\"settings\">\n{nav}<div class=\"settings-body\">\n{heading}{content}</div>\n</div>\n"
    )
}

/// The registry-scope settings sidebar (one of the management pages active).
///
/// `active` is the key of the current page. An unknown key safely falls back
/// to Overview so the navigation always exposes exactly one current page.
fn registry_settings_navigation<'a>(slug: &str, active: &'a str) -> SettingsNavigation<'a> {
    SettingsNavigation::new(
        active,
        slug.to_string(),
        vec![
            SettingsNavGroup::new(
                "",
                vec![SettingsNavItem::new(
                    "overview",
                    "Overview",
                    format!("/{slug}/-/settings"),
                )],
            ),
            SettingsNavGroup::new(
                "Configuration",
                vec![
                    SettingsNavItem::new(
                        "general",
                        "General",
                        format!("/{slug}/-/settings/general"),
                    ),
                    SettingsNavItem::new(
                        "storage",
                        "Storage",
                        format!("/{slug}/-/settings/storage"),
                    ),
                    SettingsNavItem::new(
                        "serving",
                        "Serving",
                        format!("/{slug}/-/settings/serving"),
                    ),
                    SettingsNavItem::new(
                        "caches",
                        "Binary caches",
                        format!("/{slug}/-/settings/caches"),
                    ),
                ],
            ),
            SettingsNavGroup::new(
                "Access",
                vec![
                    SettingsNavItem::new("keys", "Keys", format!("/{slug}/-/keys")),
                    SettingsNavItem::new("tokens", "Tokens", format!("/{slug}/-/settings/tokens")),
                ],
            ),
            SettingsNavGroup::new(
                "Operations",
                vec![
                    SettingsNavItem::new(
                        "config",
                        "Registry config",
                        format!("/{slug}/-/settings/config"),
                    ),
                    SettingsNavItem::new(
                        "changes",
                        "Change requests",
                        format!("/{slug}/-/changes"),
                    ),
                    SettingsNavItem::new("publishes", "Publishes", format!("/{slug}/-/publishes")),
                ],
            ),
            SettingsNavGroup::new(
                "",
                vec![SettingsNavItem::new(
                    "danger",
                    "Danger zone",
                    format!("/{slug}/-/settings/danger"),
                )],
            ),
        ],
    )
}

/// Renders a registry management page: the shared sidebar (with `active`
/// highlighted) beside `content`, under a `Manage · {slug}` heading, in the
/// standard session chrome. Every per-registry settings sub-page funnels
/// through here so the left nav is identical across them.
pub fn registry_settings_chrome(
    email: &str,
    slug: &str,
    active: &str,
    content: &str,
    started: Instant,
) -> String {
    // Each page supplies its own section `<h1>` (e.g. "Tokens · {slug}"); the
    // chrome adds only the sidebar, so no scope title is repeated across tabs.
    let body = settings_layout(&registry_settings_navigation(slug, active), content);
    page_with_session(
        &format!("manage · {slug}"),
        &registry_crumbs(slug),
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The org-scope settings sidebar (one of the org management pages active).
///
/// Resources, access, and operations are visually grouped below Overview; the
/// destructive section remains isolated at the end.
fn org_settings_navigation<'a>(org_slug: &str, active: &'a str) -> SettingsNavigation<'a> {
    SettingsNavigation::new(
        active,
        org_slug.to_string(),
        vec![
            SettingsNavGroup::new(
                "",
                vec![SettingsNavItem::new(
                    "overview",
                    "Overview",
                    format!("/-/org/{org_slug}"),
                )],
            ),
            SettingsNavGroup::new(
                "Resources",
                vec![
                    SettingsNavItem::new(
                        "registries",
                        "Registries",
                        format!("/-/org/{org_slug}/registries"),
                    ),
                    SettingsNavItem::new(
                        "projects",
                        "Projects",
                        format!("/-/org/{org_slug}/projects"),
                    ),
                    SettingsNavItem::new("caches", "Caches", format!("/-/org/{org_slug}/caches")),
                    SettingsNavItem::new(
                        "storage",
                        "Storage",
                        format!("/-/org/{org_slug}/storage"),
                    ),
                ],
            ),
            SettingsNavGroup::new(
                "Access",
                vec![
                    SettingsNavItem::new(
                        "members",
                        "Members",
                        format!("/-/org/{org_slug}/members"),
                    ),
                    SettingsNavItem::new("keys", "Hosted keys", format!("/-/org/{org_slug}/keys")),
                    SettingsNavItem::new("sso", "SSO", format!("/-/org/{org_slug}/sso")),
                ],
            ),
            SettingsNavGroup::new(
                "Operations",
                vec![
                    SettingsNavItem::new(
                        "webhooks",
                        "Webhooks",
                        format!("/-/org/{org_slug}/webhooks"),
                    ),
                    SettingsNavItem::new("audit", "Audit log", format!("/-/org/{org_slug}/audit")),
                ],
            ),
            SettingsNavGroup::new(
                "",
                vec![SettingsNavItem::new(
                    "danger",
                    "Danger zone",
                    format!("/-/org/{org_slug}/danger"),
                )],
            ),
        ],
    )
}

/// Renders an org management page: the shared sidebar (with `active`
/// highlighted) beside `content`, supplying a contextual `<h1>` when needed.
/// standard session chrome. Mirrors [`registry_settings_chrome`] so the org and
/// registry settings IAs are identical.
fn org_settings_chrome(
    email: &str,
    org_slug: &str,
    active: &str,
    content: &str,
    started: Instant,
) -> String {
    let body = settings_layout(&org_settings_navigation(org_slug, active), content);
    page_with_session(
        &format!("{org_slug} · settings"),
        &[
            ("/-/orgs".into(), "organizations".into()),
            (format!("/-/org/{org_slug}"), org_slug.to_string()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The cache-scope settings sidebar (one of a cache's sections active).
///
/// Configuration, topology relationships, and lifecycle controls are grouped
/// below Overview. An unknown key safely falls back to Overview.
fn cache_settings_navigation<'a>(
    org_slug: &str,
    cache_slug: &str,
    active: &'a str,
) -> SettingsNavigation<'a> {
    let base = format!("/-/org/{org_slug}/caches/{cache_slug}");
    SettingsNavigation::new(
        active,
        cache_slug.to_string(),
        vec![
            SettingsNavGroup::new(
                "",
                vec![SettingsNavItem::new("overview", "Overview", base.clone())],
            ),
            SettingsNavGroup::new(
                "Configuration",
                vec![
                    SettingsNavItem::new("general", "General", format!("{base}/general")),
                    SettingsNavItem::new("storage", "Storage", format!("{base}/storage")),
                    SettingsNavItem::new("serving", "Serving", format!("{base}/serving")),
                ],
            ),
            SettingsNavGroup::new(
                "Topology",
                vec![SettingsNavItem::new(
                    "links",
                    "Registries",
                    format!("{base}/links"),
                )],
            ),
            SettingsNavGroup::new(
                "Lifecycle",
                vec![SettingsNavItem::new(
                    "pins",
                    "GC & retention",
                    format!("{base}/pins"),
                )],
            ),
            SettingsNavGroup::new(
                "",
                vec![SettingsNavItem::new(
                    "danger",
                    "Danger zone",
                    format!("{base}/danger"),
                )],
            ),
        ],
    )
}

/// Renders a cache management page: the cache-scope sidebar (with `active`
/// highlighted) beside `content`, under a `caches / {slug}` breadcrumb, in the
/// standard session chrome. Mirrors [`registry_settings_chrome`] so a cache's
/// settings share the left-tabs IA of registries and orgs. The breadcrumb leads
/// with `caches` (not the org), since a cache is addressed by its own slug.
fn cache_settings_chrome(
    email: &str,
    org_slug: &str,
    cache: &Cache,
    active: &str,
    content: &str,
    started: Instant,
) -> String {
    let body = settings_layout(
        &cache_settings_navigation(org_slug, &cache.slug, active),
        content,
    );
    page_with_session(
        &format!("cache {}", cache.slug),
        &[
            (format!("/-/org/{org_slug}/caches"), "caches".to_string()),
            (String::new(), cache.slug.clone()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// Renders one section of a registry's grouped management interface.
///
/// The default `overview` section is read-only. General policy, storage,
/// serving, cache topology, and destructive operations each render in their
/// own destination while sharing one navigation model.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn registry_settings_page(
    email: &str,
    registry: &RegistryRecord,
    org_slug: &str,
    csrf: &str,
    binding: Option<(&str, &str, &str)>,
    placements: &[PlacementOverviewRow],
    bindings: &[String],
    caches: &[RegistryCacheRow],
    // Committed `[caches]` URLs that match no linked managed cache (third-party
    // or non-hosted), as `(url, priority)`.
    external_caches: &[(String, u32)],
    linkable_caches: &[(String, String)],
    can_delete: bool,
    // Whether this registry advertises its inherited storage-binding frontend
    // (RFC-0004 §12), summarized on Overview and edited under Serving.
    advertise_storage_frontend: bool,
    result: Option<&str>,
    // Which registry settings section to render. `overview` is the read-only
    // landing page; mutations live under General, Storage, Serving, and Danger.
    active: &str,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    // The shared settings layout supplies a contextual <h1> for sections that
    // do not already carry a more specific one.
    let mut body = String::new();

    if let Some(change_id) = result {
        let _ = writeln!(
            body,
            "<p class=\"good\">Registry policy updated · change <code>{}</code>.</p>",
            escape(change_id),
        );
    }

    // -- Overview: read-only registry topology -------------------------------
    if active == "overview" {
        let storage_label = binding.map_or_else(
            || {
                if registry.source_url.is_empty() {
                    "default storage"
                } else {
                    "source mirror"
                }
            },
            |(name, _, _)| name,
        );
        let advertised_caches = caches
            .iter()
            .filter(|cache| cache.config_priority.is_some())
            .count()
            + external_caches.len();
        let _ = write!(
            body,
            "<h1>Registry · {slug}</h1>\n\
             <p class=\"chips\"><span class=\"chip\">{visibility}</span>\
             <span class=\"chip\">{crawl}</span></p>\n\
             <div class=\"settings-overview-grid\">\
             <a class=\"settings-overview-card\" href=\"/{slug}/-/settings/general\">\
             <strong>{visibility}</strong><span>General policy</span></a>\
             <a class=\"settings-overview-card\" href=\"/{slug}/-/settings/storage\">\
             <strong>{storage}</strong><span>Storage placement</span></a>\
             <a class=\"settings-overview-card\" href=\"/{slug}/-/settings/serving\">\
             <strong>{serving}</strong><span>Serving path</span></a>\
             <a class=\"settings-overview-card\" href=\"/{slug}/-/settings/caches\">\
             <strong>{cache_count}</strong><span>Advertised caches</span></a></div>\n",
            slug = escape(slug),
            visibility = escape(&registry.visibility),
            crawl = escape(&registry.crawl_policy),
            storage = escape(storage_label),
            serving = if advertise_storage_frontend {
                "storage-direct"
            } else {
                "hub / configured routes"
            },
            cache_count = advertised_caches,
        );
        body.push_str(&placement_overview(placements));
    }

    // -- General: visibility + crawl policy ----------------------------------
    if active == "general" {
        // Visibility: the one in-place edit on this page.
        body.push_str("<h2>Visibility</h2>\n");
        let _ = writeln!(
            body,
            "<p>current <strong>{}</strong></p>",
            escape(&registry.visibility),
        );
        let mut options = String::new();
        for v in ["public", "internal", "private"] {
            let selected = if v == registry.visibility {
                " selected"
            } else {
                ""
            };
            let _ = write!(options, "<option value=\"{v}\"{selected}>{v}</option>");
        }
        let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/{slug}/-/settings/visibility\">\n{csrf}\
         <label>visibility <select name=\"visibility\">{options}</select></label>\n\
         <button>change visibility</button>\n</form>\n",
        slug = escape(slug),
        csrf = csrf_field(csrf),
        options = options,
    );
        body.push_str(
            "<p class=\"dim\">A confirmation-gated change-set, recorded in the audit feed. \
         <strong>public</strong> exposes every package and channel to anonymous consumers; \
         <strong>private</strong> breaks anonymous reads (consumers need a read token).</p>\n",
        );

        // Crawl policy: the generated robots.txt posture for this registry.
        body.push_str("<h2>Crawl policy</h2>\n");
        let _ = writeln!(
            body,
            "<p>current <strong>{}</strong></p>",
            escape(&registry.crawl_policy),
        );
        let mut crawl_options = String::new();
        for p in ["allow_all", "allow_no_ai", "deny_all"] {
            let selected = if p == registry.crawl_policy {
                " selected"
            } else {
                ""
            };
            let _ = write!(
                crawl_options,
                "<option value=\"{p}\"{selected}>{p}</option>"
            );
        }
        let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/{slug}/-/settings/crawl\">\n{csrf}\
         <label><span class=\"lbl\">policy{policy_help}</span> <select name=\"policy\">{crawl_options}</select></label>\n\
         <button>change crawl policy</button>\n</form>\n",
        slug = escape(slug),
        csrf = csrf_field(csrf),
        crawl_options = crawl_options,
        policy_help = help::marker("registry.crawl_policy"),
    );
    }

    // -- Storage: current backend + change storage ---------------------------
    if active == "storage" {
        // Storage (read-only). Three cases: a custom binding, the deployment's
        // default storage (a managed registry with no binding), or a phase-1
        // source-URL mirror (read-only upstream, no writable surface here).
        body.push_str("<h2>Current storage</h2>\n");
        match binding {
            Some((name, root, prefix)) => {
                let _ = writeln!(
                body,
                "<p>binding <code>{}</code> · root <code>{}</code> · prefix <code>{}</code></p>",
                escape(name),
                escape(root),
                escape(if prefix.is_empty() { "(none)" } else { prefix }),
            );
            }
            None if !registry.source_url.is_empty() => {
                let _ = writeln!(
                    body,
                    "<p><span class=\"chip\">source mirror</span> serves a read-only upstream \
                 surface · <code>{}</code></p>",
                    escape(&registry.source_url),
                );
            }
            None => {
                let prefix = if registry.prefix.is_empty() {
                    registry.slug.as_str()
                } else {
                    registry.prefix.as_str()
                };
                let _ = writeln!(
                    body,
                    "<p><span class=\"chip\">default storage</span> · prefix <code>{}</code> · \
                 <a href=\"/-/instance/storage\">deployment default →</a></p>",
                    escape(prefix),
                );
            }
        }
        // Change storage — only for a managed registry (a source-mirror has no
        // writable surface here). Lists every target other than the current one
        // (default storage, plus each org binding); moving copies every object to
        // the new backend, then re-points.
        if registry.source_url.is_empty() {
            let current = binding.map(|(name, _, _)| name);
            let mut options = String::new();
            if current.is_some() {
                options.push_str("<option value=\"\">default storage</option>");
            }
            for b in bindings {
                if Some(b.as_str()) != current {
                    let _ = write!(options, "<option value=\"{b}\">{b}</option>", b = escape(b));
                }
            }
            if !options.is_empty() {
                let _ = write!(
                body,
                "<h3>Change storage{help}</h3>\n\
                 <form class=\"console\" method=\"post\" action=\"/{slug}/-/settings/storage\">{csrf}\
                 <label>move to <select name=\"binding\">{options}</select></label>\n\
                 <button>move storage</button>\n</form>\n",
                help = help::marker("storage.change"),
                slug = escape(slug),
                csrf = csrf_field(csrf),
                options = options,
            );
            }
        }
    }

    // -- Binary caches serving this registry ---------------------------------
    if active == "caches" {
        // A reconciliation view over the committed `[caches]` (the single source
        // of truth a consumer resolves) versus the registry's DB cache links
        // (operational: GC-root pinning + config-editor autofill). Caches are
        // not advertised by linking — advertisement is an explicit `[caches]`
        // config edit (Settings -> Config). Three groups are shown:
        //   1. served from config (link present, URL in `[caches]`),
        //   2. linked but not in config (link present, URL absent),
        //   3. in config but external (URL present, no linked managed cache).
        body.push_str("<h2>Binary caches</h2>\n");
        body.push_str(
            "<p class=\"dim\">The committed <code>[caches]</code> config is the source of \
             truth for what this registry advertises. A cache serves the whole registry \
             (all channels), not a single channel. Linking a cache is operational only \
             (GC roots + config autofill); to advertise it, add its URL in \
             <a href=\"config\">Settings · Config</a>.</p>\n",
        );

        let served: Vec<&RegistryCacheRow> = caches
            .iter()
            .filter(|c| c.config_priority.is_some())
            .collect();
        let unconfigured: Vec<&RegistryCacheRow> = caches
            .iter()
            .filter(|c| c.config_priority.is_none())
            .collect();

        let cache_label = |c: &RegistryCacheRow| {
            if org_slug.is_empty() {
                escape(&c.cache_slug)
            } else {
                format!(
                    "<a href=\"/-/org/{org}/caches/{slug}\">{slug}</a>",
                    org = escape(org_slug),
                    slug = escape(&c.cache_slug),
                )
            }
        };

        // 1. Served from config.
        body.push_str("<h3>Served from config</h3>\n");
        if served.is_empty() {
            body.push_str(
                "<p class=\"dim\">No linked cache's URL appears in the committed config.</p>\n",
            );
        } else {
            body.push_str("<div class=\"linktable\">\n");
            body.push_str(
                "<span class=\"linktable-h\">cache</span>\
                 <span class=\"linktable-h\">consumer URL</span>\
                 <span class=\"linktable-h\">priority</span>\
                 <span class=\"linktable-h\"></span>\n",
            );
            for c in &served {
                let _ = write!(
                    body,
                    "<form class=\"linkrow\" method=\"post\" action=\"/{slug}/-/settings/cache-unlink\">{csrf}\
                     <input type=\"hidden\" name=\"cache\" value=\"{cache}\">\
                     <span class=\"linkrow-name\">{label}</span>\
                     <span><code>{url}</code></span>\
                     <span>{priority}</span>\
                     <span class=\"linkrow-actions\">\
                     <button class=\"danger\">unlink</button></span></form>\n",
                    slug = escape(slug),
                    csrf = csrf_field(csrf),
                    cache = escape(&c.cache_slug),
                    label = cache_label(c),
                    url = escape(&c.consumer_url),
                    priority = c.config_priority.unwrap_or(0),
                );
            }
            body.push_str("</div>\n");
        }

        // 2. Linked but not in config — offer a deep-link to the config editor.
        body.push_str("<h3>Linked but not advertised</h3>\n");
        if unconfigured.is_empty() {
            body.push_str("<p class=\"dim\">Every linked cache is advertised in the config.</p>\n");
        } else {
            body.push_str("<div class=\"linktable\">\n");
            body.push_str(
                "<span class=\"linktable-h\">cache</span>\
                 <span class=\"linktable-h\">consumer URL</span>\
                 <span class=\"linktable-h\"></span>\
                 <span class=\"linktable-h\"></span>\n",
            );
            for c in &unconfigured {
                let _ = write!(
                    body,
                    "<form class=\"linkrow\" method=\"post\" action=\"/{slug}/-/settings/cache-unlink\">{csrf}\
                     <input type=\"hidden\" name=\"cache\" value=\"{cache}\">\
                     <span class=\"linkrow-name\">{label}</span>\
                     <span><code>{url}</code></span>\
                     <span><a href=\"config\">add to config</a></span>\
                     <span class=\"linkrow-actions\">\
                     <button class=\"danger\">unlink</button></span></form>\n",
                    slug = escape(slug),
                    csrf = csrf_field(csrf),
                    cache = escape(&c.cache_slug),
                    label = cache_label(c),
                    url = escape(&c.consumer_url),
                );
            }
            body.push_str("</div>\n");
        }

        // 3. In config but external (no linked managed cache).
        if !external_caches.is_empty() {
            body.push_str("<h3>In config, external</h3>\n");
            body.push_str(
                "<p class=\"dim\">Advertised in <code>[caches]</code> but not a linked managed \
                 cache (third-party or non-hosted).</p>\n",
            );
            body.push_str("<ul class=\"dim\">\n");
            for (url, priority) in external_caches {
                let _ = write!(
                    body,
                    "<li><code>{url}</code> · priority {priority}</li>\n",
                    url = escape(url),
                    priority = priority,
                );
            }
            body.push_str("</ul>\n");
        }

        // Link another of the org's caches to this registry (operational only).
        if !linkable_caches.is_empty() {
            let mut options = String::new();
            for (slug, vis) in linkable_caches {
                let _ = write!(
                    options,
                    "<option value=\"{s}\">{s} · {v}</option>",
                    s = escape(slug),
                    v = escape(vis),
                );
            }
            let _ = write!(
                body,
                "<h3>Link a cache</h3>\n\
                 <p class=\"dim\">Pins GC roots and lists the cache for config autofill. \
                 It does not advertise the cache — do that in \
                 <a href=\"config\">Config</a>.</p>\n\
                 <form class=\"console\" method=\"post\" action=\"/{slug}/-/settings/cache-link\">{csrf}\
                 <label>cache <select name=\"cache\">{options}</select></label>\n\
                 <label><span class=\"lbl\">pin GC roots from its packages{roots_help}</span> \
                 <input type=\"checkbox\" name=\"roots_packages\" value=\"1\" checked></label>\n\
                 <button>link</button>\n</form>\n",
                slug = escape(slug),
                csrf = csrf_field(csrf),
                options = options,
                roots_help = help::marker("link.roots_packages"),
            );
        }
    }

    // -- Danger zone: remove the registry ------------------------------------
    if active == "danger" {
        if can_delete {
            body.push_str("<h2 class=\"danger\">Remove registry</h2>\n");
            let _ = write!(
                body,
                "<p class=\"dim\">Unregisters this registry and drops its rebuildable index. The \
             surface content on the storage binding is left in place. Type the registry name \
             <code>{slug}</code> to confirm.</p>\n\
             <form class=\"console\" method=\"post\" action=\"/{slug}/-/settings/delete\">\n{csrf}\
             <label>confirm name <input type=\"text\" name=\"confirm\" required \
             placeholder=\"{slug}\"></label>\n\
             <button class=\"danger\">remove registry</button>\n</form>\n",
                slug = escape(slug),
                csrf = csrf_field(csrf),
            );
        } else {
            body.push_str(
                "<p class=\"dim\">You do not have permission to remove this registry.</p>\n",
            );
        }
    }

    registry_settings_chrome(email, slug, active, &body, started)
}

/// The per-registry token management page.
///
/// `tokens` is the caller's own tokens at this registry scope; `can_create`
/// gates the create form (developer+); `result` is `Some((label, secret))`
/// right after a create or rotate, showing the secret exactly once.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn tokens_page(
    email: &str,
    registry: &RegistryRecord,
    csrf: &str,
    tokens: &[(String, String, Vec<Permission>)],
    can_create: bool,
    result: Option<(&str, &str)>,
    page_number: usize,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();

    if let Some((label, secret)) = result {
        let _ = write!(
            body,
            "<p class=\"notice\">{} — copy it now, it is shown only once:</p>\n\
             <code class=\"secret\">{}</code>\n",
            escape(label),
            escape(secret),
        );
    }

    let pager = Pager::new(page_number, LIST_PER_PAGE, tokens.len());
    if tokens.is_empty() {
        body.push_str("<p class=\"dim\">You hold no tokens at this registry.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = pager
            .slice(tokens)
            .iter()
            .map(|(id, _scope, perms)| {
                let perm_label = perms
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let revoke = format!(
                    "<form class=\"console\" method=\"post\" \
                     action=\"/{slug}/-/settings/tokens/revoke\" style=\"display:inline\">{csrf}\
                     <input type=\"hidden\" name=\"token_id\" value=\"{id}\">\
                     <button>revoke</button></form>",
                    slug = escape(slug),
                    csrf = csrf_field(csrf),
                    id = escape(id),
                );
                let rotate = format!(
                    "<form class=\"console\" method=\"post\" \
                     action=\"/{slug}/-/settings/tokens/rotate\" style=\"display:inline\">{csrf}\
                     <input type=\"hidden\" name=\"token_id\" value=\"{id}\">\
                     <button>rotate</button></form>",
                    slug = escape(slug),
                    csrf = csrf_field(csrf),
                    id = escape(id),
                );
                vec![
                    format!("<code>{}</code>", escape(id)),
                    escape(&perm_label),
                    format!("{revoke} {rotate}"),
                ]
            })
            .collect();
        body.push_str(&table(&["id", "permissions", ""], &rows));
        body.push_str(&pager.nav(&format!("/{slug}/-/settings/tokens"), ""));
    }

    if can_create {
        body.push_str("<h2>Create a token</h2>\n");
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/{}/-/settings/tokens\">\n{}\
             <label><span class=\"lbl\">read</span> <input type=\"checkbox\" name=\"perm_read\" value=\"1\" checked></label>\n\
             <label><span class=\"lbl\">publish</span> <input type=\"checkbox\" name=\"perm_publish\" value=\"1\"></label>\n\
             <button>create token</button>\n</form>\n",
            escape(slug),
            csrf_field(csrf),
        );
        body.push_str(
            "<p class=\"dim\">The token is scoped to this registry and owned by you; \
             its effective permissions are intersected with your current grants.</p>\n",
        );
    } else {
        body.push_str("<p class=\"dim\">You need a developer role here to mint tokens.</p>\n");
    }

    registry_settings_chrome(email, slug, "tokens", &body, started)
}

/// The channel rollout console.
///
/// Shows the partition grid (reusing the consumer channel page's rendering)
/// and, for a maintainer, a rollout form that produces a **prepared
/// operation** — the exact `apr channel advance --from-hub <id>` command —
/// because signing is client-side until hosted keys arrive (phase 4). A
/// read-only viewer (`can_advance = false`) sees the grid without the form.
/// `prepared` is `Some((change_id, command))` right after a preparation.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn channel_console(
    email: &str,
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    channel: &ChannelSummary,
    csrf: &str,
    can_advance: bool,
    hosted_key: Option<&str>,
    prepared: Option<(&str, &str)>,
    advanced: Option<&str>,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let assigned = channel.partitions.iter().flatten().count();
    let mut body = format!(
        "<h1>Rollout console · {}</h1>\n<p>frontier <strong>{}</strong> · {assigned} of 256 \
         partitions assigned</p>\n",
        escape(&channel.name),
        escape(channel.frontier.as_deref().unwrap_or("—")),
    );

    // Mode banner: which signing path this registry uses.
    match hosted_key {
        Some(key_id) => {
            let _ = writeln!(
                body,
                "<p class=\"notice\">Signing with hosted key <code>{}</code>: a web advance is \
                 signed and applied directly by the hub.</p>",
                escape(key_id),
            );
        }
        None => body.push_str(
            "<p class=\"dim\">Prepared for CLI signing: this registry has no hosted key, so a web \
             advance records a prepared operation you sign and push locally.</p>\n",
        ),
    }

    if let Some(message) = advanced {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(message));
    }

    if let Some((change_id, command)) = prepared {
        let _ = write!(
            body,
            "<p class=\"notice\">Prepared operation <code>{}</code>. Run it locally to sign and \
             push the partition tags:</p>\n<pre>{}</pre>\n",
            escape(change_id),
            escape(command),
        );
    }

    if can_advance {
        let action_path = if hosted_key.is_some() {
            "advance"
        } else {
            "console"
        };
        let button = if hosted_key.is_some() {
            "advance"
        } else {
            "prepare advance"
        };
        body.push_str("<h2>Advance</h2>\n");
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/{slug}/-/channels/{name}/{action}\">\n{csrf}\
             <label>release <input type=\"text\" name=\"release\" required \
             placeholder=\"1.4.2\"></label>\n\
             <label>partitions (1–256) <input type=\"text\" name=\"partitions\" value=\"256\"></label>\n\
             <button>{button}</button>\n</form>\n",
            slug = escape(slug),
            name = escape(&channel.name),
            action = action_path,
            csrf = csrf_field(csrf),
        );
        if hosted_key.is_some() {
            body.push_str(
                "<p class=\"dim\">The hub signs the partition tags with the registry's hosted key \
                 and writes them to the surface, then re-indexes. Every advance is audited.</p>\n",
            );
        } else {
            body.push_str(
                "<p class=\"dim\">Web edits are change requests: this records a prepared operation \
                 and renders the <code>apr channel advance --from-hub</code> command. The \
                 maintainer signs the partition tags locally and pushes. A direct web-button \
                 advance needs a hosted signing key.</p>\n",
            );
        }
    } else {
        body.push_str("<p class=\"dim\">Read-only: you need a maintainer role to advance.</p>\n");
    }

    // Reuse the consumer channel grid renderer for the partition view.
    let grid = channel_grid_pre(channel);
    let _ = write!(body, "{grid}");

    let state = match status {
        Some(s) => StateLine {
            surface_commit: s.last_indexed_commit.clone(),
            indexed_at: s.indexed_at,
            state: Some(s.state.clone()),
            started: Some(started),
        },
        None => StateLine::timed(started),
    };
    page_with_session(
        &format!("{} rollout", channel.name),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/"), slug.clone()),
            (format!("/{slug}/-/channels"), "channels".into()),
            (String::new(), channel.name.clone()),
        ],
        &body,
        &state,
        &indicator(email),
    )
}

/// The key roster management page.
///
/// The roster is signed tree content, so there is no raw web mutation: the
/// page shows active/revoked keys with fingerprints and links to the
/// rotation wizard. `can_manage` reveals the wizard link to a maintainer.
#[must_use]
pub fn keys_page(
    email: &str,
    registry: &RegistryRecord,
    roster: &[(String, String, String)],
    can_manage: bool,
    page_number: usize,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    body.push_str(
        "<p class=\"dim\">The roster is signed tree content. Keys are added and retired by \
         client-side signing, never by a raw web mutation.</p>\n",
    );

    let pager = Pager::new(page_number, LIST_PER_PAGE, roster.len());
    if roster.is_empty() {
        body.push_str("<p class=\"dim\">No roster keys indexed.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = pager
            .slice(roster)
            .iter()
            .map(|(id, key, status)| {
                let fingerprint = if key.is_empty() {
                    "—".to_string()
                } else {
                    let blob = key.rsplit(':').next().unwrap_or(key);
                    format!("<code>{}</code>", escape(&key_fingerprint(blob)))
                };
                let status_cell = match status.as_str() {
                    "active" => "<span class=\"ok\">active</span>".to_string(),
                    other => format!("<span class=\"dim\">{}</span>", escape(other)),
                };
                vec![escape(id), fingerprint, status_cell]
            })
            .collect();
        body.push_str(&table(&["key id", "fingerprint", "status"], &rows));
        body.push_str(&pager.nav(&format!("/{slug}/-/keys"), ""));
    }

    if can_manage {
        let _ = writeln!(
            body,
            "<p><a href=\"/{}/-/keys/rotate\">rotation wizard →</a></p>",
            escape(slug),
        );
    }

    // Trust anchors (read-only — editing is the signed keys.toml flow). Shown
    // alongside the roster since both concern this registry's signing identity.
    body.push_str("<h2>Trust anchors</h2>\n");
    if registry.trust_keys.is_empty() {
        body.push_str("<p class=\"warn\">No pinned trust anchors.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = registry
            .trust_keys
            .iter()
            .map(|k| vec![format!("<code>{}</code>", escape(k))])
            .collect();
        body.push_str(&table(&["pinned anchor"], &rows));
    }
    let _ = writeln!(
        body,
        "<p class=\"dim\">Editing the roster is the signed <code>keys.toml</code> flow: propose \
         roster edits as a <a href=\"/{slug}/-/settings/config\">config change request</a>.</p>",
        slug = escape(slug),
    );

    registry_settings_chrome(email, slug, "keys", &body, started)
}

/// The key rotation wizard page.
///
/// Explains the add → overlap → retire(`--vouched-by`) sequence and renders
/// the exact `apr keys add` / `apr keys retire` commands as prepared
/// operations (signing is client-side; there is no raw roster mutation).
#[must_use]
pub fn keys_rotate_page(email: &str, registry: &RegistryRecord, started: Instant) -> String {
    let slug = &registry.slug;
    let mut body = String::from("<h1>Key rotation wizard</h1>\n");
    body.push_str(
        "<p>Rotation is a three-step, client-signed sequence. The roster is signed tree content, \
         so the hub never mutates it for you — it renders the commands; you run and sign them.</p>\n",
    );
    body.push_str("<h2>1 · Add the new key</h2>\n");
    let _ = write!(
        body,
        "<pre>apr keys add --registry {url}/ \\\n  --id &lt;new-key-id&gt; --key &lt;name:Ed25519:…&gt;</pre>\n",
        url = escape(slug),
    );
    body.push_str(
        "<h2>2 · Overlap</h2>\n\
         <p class=\"dim\">Publish a release signed by both keys so consumers learn the new anchor \
         before the old one retires. Wait out your <code>max_staleness_seconds</code> window.</p>\n",
    );
    body.push_str("<h2>3 · Retire the old key</h2>\n");
    let _ = write!(
        body,
        "<pre>apr keys retire --registry {url}/ \\\n  --id &lt;old-key-id&gt; --vouched-by &lt;new-key-id&gt;</pre>\n",
        url = escape(slug),
    );
    body.push_str(
        "<p class=\"dim\">The <code>--vouched-by</code> flag is mandatory: a retirement must be \
         signed by a key that remains in the roster, so consumers can verify the transition.</p>\n",
    );
    registry_settings_chrome(email, slug, "keys", &body, started)
}

/// The org hosted-key enrollment page.
///
/// Hosted keys are an explicit org opt-in (RFC-0004 Open Question 1): the hub
/// holds an Ed25519 signing key so it can advance channels and re-sign tags
/// directly from the web. This page lists the org's enrolled keys (showing the
/// public trusted-key line to publish/pin), offers a create form, and — per
/// owned registry — an attach form binding a key to a registry. `created`
/// echoes the public line of a just-created key so it can be copied once.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn org_hosted_keys_page(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    keys: &[HostedKeyRecord],
    registries: &[RegistryRecord],
    created: Option<&str>,
    started: Instant,
) -> String {
    let org_slug = &org.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    body.push_str(
        "<p class=\"dim\">A hosted key lets the hub sign channel advances and tag re-signs \
         directly from the web. The seed is held sealed and every use is audited. Pin the public \
         line below as a registry trust anchor so the hub's signatures verify.</p>\n",
    );

    if let Some(line) = created {
        let _ = write!(
            body,
            "<p class=\"notice\">Key created. Publish and pin this trusted-key line as a registry \
             anchor:</p>\n<pre>{}</pre>\n",
            escape(line),
        );
    }

    if keys.is_empty() {
        body.push_str("<p class=\"dim\">No hosted keys enrolled.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = keys
            .iter()
            .map(|k| {
                vec![
                    escape(&k.key_id),
                    format!("<code>{}</code>", escape(&k.public_key)),
                ]
            })
            .collect();
        body.push_str(&table(&["key id", "public trusted-key line"], &rows));
    }

    body.push_str("<h2>Enroll a key</h2>\n");
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/keys\">\n{csrf}\
         <input type=\"hidden\" name=\"op\" value=\"create\">\n\
         <label>key id <input type=\"text\" name=\"key_id\" required placeholder=\"acme-release\"></label>\n\
         <button>enroll</button>\n</form>\n",
        org = escape(org_slug),
        csrf = csrf_field(csrf),
    );

    body.push_str("<h2>Attach to a registry</h2>\n");
    if registries.is_empty() {
        body.push_str("<p class=\"dim\">No registries owned by this org.</p>\n");
    } else if keys.is_empty() {
        body.push_str("<p class=\"dim\">Enroll a key first, then attach it to a registry.</p>\n");
    } else {
        let mut key_options = String::new();
        for k in keys {
            let _ = write!(
                key_options,
                "<option value=\"{id}\">{label}</option>",
                id = k.id,
                label = escape(&k.key_id),
            );
        }
        for registry in registries {
            let attached = match registry.hosted_key_id {
                Some(id) => keys
                    .iter()
                    .find(|k| k.id == id)
                    .map(|k| format!(" · attached: {}", k.key_id))
                    .unwrap_or_default(),
                None => String::new(),
            };
            let _ = write!(
                body,
                "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/keys\">\n{csrf}\
                 <input type=\"hidden\" name=\"op\" value=\"attach\">\n\
                 <input type=\"hidden\" name=\"registry\" value=\"{slug}\">\n\
                 <label>{slug_label}{attached} <select name=\"hosted_key_id\">{options}\
                 <option value=\"\">— detach —</option></select></label>\n\
                 <button>attach</button>\n</form>\n",
                org = escape(org_slug),
                csrf = csrf_field(csrf),
                slug = escape(&registry.slug),
                slug_label = escape(&registry.slug),
                attached = escape(&attached),
                options = key_options,
            );
        }
    }

    org_settings_chrome(email, org_slug, "keys", &body, started)
}

/// The subscribable webhook event types, with a short human label each.
///
/// The empty subscription means *all* events (see [`WebhookRecord::events`]);
/// these are the boxes the create form offers to narrow it.
pub const WEBHOOK_EVENT_TYPES: &[(&str, &str)] = &[
    ("index.completed", "an index run finished"),
    ("channel.advanced", "a channel rolled forward"),
    (
        "registry.visibility_changed",
        "a registry's visibility changed",
    ),
    ("release.published", "a release was published"),
];

/// The org webhooks management page: list, create, and delete subscriptions.
///
/// A webhook `POST`s a signed JSON body to its URL for each subscribed event.
/// `created_secret` echoes a just-generated signing secret once (it is stored
/// but never shown again). Deletion and creation are CSRF-checked `POST`s.
#[must_use]
pub fn org_webhooks_page(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    webhooks: &[WebhookRecord],
    created_secret: Option<&str>,
    started: Instant,
) -> String {
    let org_slug = &org.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    body.push_str(
        "<p class=\"dim\">Each subscription receives an HMAC-SHA256-signed JSON \
         <code>POST</code> for the events you select (none selected means every event). \
         The signature uses the per-hook secret in the <code>X-AOS-Signature</code> header.</p>\n",
    );

    if let Some(secret) = created_secret {
        let _ = write!(
            body,
            "<p class=\"notice\">Webhook created. Copy its signing secret now — it is shown \
             only once:</p>\n<code class=\"secret\">{}</code>\n",
            escape(secret),
        );
    }

    if webhooks.is_empty() {
        body.push_str("<p class=\"dim\">No webhooks configured.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = webhooks
            .iter()
            .map(|w| {
                let events = if w.events.is_empty() {
                    "<span class=\"dim\">all events</span>".to_string()
                } else {
                    w.events
                        .iter()
                        .map(|e| format!("<code>{}</code>", escape(e)))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                let status = if w.active {
                    "<span class=\"ok\">active</span>".to_string()
                } else {
                    "<span class=\"dim\">disabled</span>".to_string()
                };
                let delete = format!(
                    "<form class=\"console\" method=\"post\" \
                     action=\"/-/org/{org}/webhooks\" style=\"display:inline\">{csrf}\
                     <input type=\"hidden\" name=\"op\" value=\"delete\">\
                     <input type=\"hidden\" name=\"webhook_id\" value=\"{id}\">\
                     <button class=\"danger\">delete</button></form>",
                    org = escape(org_slug),
                    csrf = csrf_field(csrf),
                    id = w.id,
                );
                vec![
                    format!("<code>{}</code>", escape(&w.url)),
                    events,
                    status,
                    ago(w.created_at),
                    delete,
                ]
            })
            .collect();
        body.push_str(&table(&["url", "events", "status", "created", ""], &rows));
    }

    body.push_str("<h2>Add a webhook</h2>\n");
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/webhooks\">\n{csrf}\
         <input type=\"hidden\" name=\"op\" value=\"create\">\n\
         <label>url <input type=\"url\" name=\"url\" required \
         placeholder=\"https://ci.example.com/hooks/aos\"></label>\n",
        org = escape(org_slug),
        csrf = csrf_field(csrf),
    );
    body.push_str("<fieldset><legend>events (none = all)</legend>\n");
    for (event, label) in WEBHOOK_EVENT_TYPES {
        let _ = write!(
            body,
            "<label><span class=\"lbl\"><code>{event}</code> — {label}</span> \
             <input type=\"checkbox\" name=\"events\" value=\"{event}\"></label>\n",
        );
    }
    body.push_str("</fieldset>\n");
    let _ = write!(
        body,
        "<label><span class=\"lbl\">secret{secret_help}</span> <input type=\"text\" name=\"secret\" \
         placeholder=\"leave blank to generate\"></label>\n\
         <button>add webhook</button>\n</form>\n",
        secret_help = help::marker("webhook.secret"),
    );

    org_settings_chrome(email, org_slug, "webhooks", &body, started)
}

/// The org single-sign-on page: the OIDC IdP configuration and the captured
/// email domains that route logins to it.
///
/// The client secret is **write-only** — the sealed value is never rendered;
/// the form shows whether one is set and lets an admin replace it. `notice`
/// echoes the result of the last action (e.g. a domain's DNS-TXT challenge).
#[must_use]
pub fn org_sso_page(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    idp: Option<&IdpConfigRecord>,
    domains: &[OrgDomainRecord],
    can_verify_domains: bool,
    notice: Option<&str>,
    started: Instant,
) -> String {
    let org_slug = &org.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    body.push_str(
        "<p class=\"dim\">Configure an OIDC identity provider and capture the email domains \
         whose users sign in through it. The client secret is sealed at rest and never shown \
         again. Only <strong>verified</strong> domains route logins.</p>\n",
    );

    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }

    // --- IdP configuration ---
    body.push_str("<h2>Identity provider</h2>\n");
    let val = |s: &str| escape(s);
    let secret_hint = match idp {
        Some(c) if c.client_secret_enc.is_some() => {
            "a secret is set — leave blank to keep it, or enter a new one to replace"
        }
        _ => "leave blank for a public client",
    };
    let cur = |get: &dyn Fn(&IdpConfigRecord) -> String| idp.map(get).unwrap_or_default();
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/sso\">\n{csrf}\
         <input type=\"hidden\" name=\"op\" value=\"set-idp\">\n\
         <label><span class=\"lbl\">issuer{endpoints_help}</span> \
         <input type=\"text\" name=\"issuer\" required value=\"{issuer}\" \
         placeholder=\"https://idp.example.com\"></label>\n\
         <label>authorization endpoint <input type=\"url\" name=\"auth_url\" required value=\"{auth}\"></label>\n\
         <label>token endpoint <input type=\"url\" name=\"token_url\" required value=\"{token}\"></label>\n\
         <label>JWKS URI <input type=\"url\" name=\"jwks_uri\" required value=\"{jwks}\"></label>\n\
         <label>client id <input type=\"text\" name=\"client_id\" required value=\"{client}\"></label>\n\
         <label>client secret <input type=\"password\" name=\"client_secret\" \
         autocomplete=\"new-password\" placeholder=\"{secret_hint}\"></label>\n\
         <label>scopes <input type=\"text\" name=\"scopes\" value=\"{scopes}\"></label>\n\
         <label>groups claim <input type=\"text\" name=\"groups_claim\" value=\"{groups}\" \
         placeholder=\"groups\"></label>\n\
         <label>group → role map (JSON) <input type=\"text\" name=\"role_map\" value=\"{rolemap}\" \
         placeholder=\"{{&quot;admins&quot;:&quot;admin&quot;}}\"></label>\n",
        org = escape(org_slug),
        csrf = csrf_field(csrf),
        endpoints_help = help::marker("sso.endpoints"),
        issuer = val(&cur(&|c| c.issuer.clone())),
        auth = val(&cur(&|c| c.authorization_endpoint.clone())),
        token = val(&cur(&|c| c.token_endpoint.clone())),
        jwks = val(&cur(&|c| c.jwks_uri.clone())),
        client = val(&cur(&|c| c.client_id.clone())),
        scopes = val(&idp.map_or("openid email profile".to_string(), |c| c.scopes.clone())),
        groups = val(&cur(&|c| c.groups_claim.clone().unwrap_or_default())),
        rolemap = val(&idp.map_or("{}".to_string(), |c| c.role_map_json.clone())),
    );
    // default-role select
    let default_role = idp.map_or("viewer".to_string(), |c| c.default_role.clone());
    body.push_str("<label>default role for JIT users <select name=\"default_role\">");
    for role in ["owner", "admin", "maintainer", "developer", "viewer"] {
        let sel = if role == default_role {
            " selected"
        } else {
            ""
        };
        let _ = write!(body, "<option value=\"{role}\"{sel}>{role}</option>");
    }
    body.push_str("</select></label>\n");
    let jit = idp.map_or(true, |c| c.allow_jit);
    let enforce = idp.is_some_and(|c| c.enforce_sso);
    let _ = write!(
        body,
        "<label><span class=\"lbl\">just-in-time provision unknown users{jit_help}</span> \
         <input type=\"checkbox\" name=\"allow_jit\" value=\"1\"{jit}></label>\n\
         <label><span class=\"lbl\">force org members through SSO{enforce_help}</span> \
         <input type=\"checkbox\" name=\"enforce_sso\" value=\"1\"{enforce}></label>\n\
         <button>save identity provider</button>\n</form>\n",
        jit_help = help::marker("sso.jit"),
        enforce_help = help::marker("sso.enforce"),
        jit = if jit { " checked" } else { "" },
        enforce = if enforce { " checked" } else { "" },
    );
    if idp.is_some() {
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/sso\">{csrf}\
             <input type=\"hidden\" name=\"op\" value=\"remove-idp\">\
             <button class=\"danger\">remove identity provider</button></form>\n",
            org = escape(org_slug),
            csrf = csrf_field(csrf),
        );
    }

    // --- Domains ---
    body.push_str("<h2>Email domains</h2>\n");
    if domains.is_empty() {
        body.push_str("<p class=\"dim\">No domains captured.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = domains
            .iter()
            .map(|d| {
                let status = if d.verified_at.is_some() {
                    "<span class=\"ok\">verified</span>".to_string()
                } else {
                    format!(
                        "<span class=\"warn\">pending</span> · publish TXT \
                         <code>{}</code>",
                        escape(&d.txt_challenge)
                    )
                };
                let mut actions = String::new();
                // Verifying a domain routes other people's logins, so it is an
                // instance-operator action (a trusted DNS check), never org
                // self-service. Org admins capture; an operator verifies.
                if d.verified_at.is_none() && can_verify_domains {
                    let _ = write!(
                        actions,
                        "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/sso\" \
                         style=\"display:inline\">{csrf}\
                         <input type=\"hidden\" name=\"op\" value=\"verify-domain\">\
                         <input type=\"hidden\" name=\"domain\" value=\"{dom}\">\
                         <button>verify (operator)</button></form> ",
                        org = escape(org_slug),
                        csrf = csrf_field(csrf),
                        dom = escape(&d.domain),
                    );
                }
                let _ = write!(
                    actions,
                    "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/sso\" \
                     style=\"display:inline\">{csrf}\
                     <input type=\"hidden\" name=\"op\" value=\"remove-domain\">\
                     <input type=\"hidden\" name=\"domain\" value=\"{dom}\">\
                     <button class=\"danger\">remove</button></form>",
                    org = escape(org_slug),
                    csrf = csrf_field(csrf),
                    dom = escape(&d.domain),
                );
                vec![escape(&d.domain), status, actions]
            })
            .collect();
        body.push_str(&table(&["domain", "status", ""], &rows));
    }
    if !can_verify_domains {
        body.push_str(
            "<p class=\"dim\">Publish the TXT challenge above, then an instance operator \
             verifies the domain (a trusted DNS check) — verification is not org self-service \
             because a verified domain routes its users' logins.</p>\n",
        );
    }
    let _ = write!(
        body,
        "<h3>Capture a domain</h3>\n\
         <form class=\"console\" method=\"post\" action=\"/-/org/{org}/sso\">{csrf}\
         <input type=\"hidden\" name=\"op\" value=\"add-domain\">\n\
         <label>domain <input type=\"text\" name=\"domain\" required placeholder=\"acme.com\"></label>\n\
         <button>capture</button>\n</form>\n",
        org = escape(org_slug),
        csrf = csrf_field(csrf),
    );

    org_settings_chrome(email, org_slug, "sso", &body, started)
}

/// The instance-scope settings sidebar (`general`, `branding`, `serving`, or
/// `storage` active).
fn instance_settings_navigation(active: &str) -> SettingsNavigation<'_> {
    SettingsNavigation::new(
        active,
        "Instance".to_string(),
        vec![SettingsNavGroup::new(
            "Configuration",
            vec![
                SettingsNavItem::new("general", "General", "/-/instance".to_string()),
                SettingsNavItem::new("branding", "Branding", "/-/instance/branding".to_string()),
                SettingsNavItem::new("storage", "Storage", "/-/instance/storage".to_string()),
                SettingsNavItem::new("serving", "Serving", "/-/instance/serving".to_string()),
            ],
        )],
    )
}

/// Renders an instance settings page: the shared sidebar beside `content`
/// in the standard chrome, supplying a contextual `<h1>` when needed.
fn instance_settings_chrome(email: &str, active: &str, content: &str, started: Instant) -> String {
    let body = settings_layout(&instance_settings_navigation(active), content);
    page_with_session(
        "instance settings",
        &[(String::new(), "instance settings".into())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The instance-settings "General" page (instance admins only): signup and
/// identity policy — who may create orgs, the signup email-domain allowlist,
/// whether local password login is offered, and the session lifetime.
#[must_use]
pub fn instance_settings_page(
    email: &str,
    csrf: &str,
    settings: &crate::db::InstanceSettings,
    notice: Option<&str>,
    started: Instant,
) -> String {
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    let open_sel = if matches!(settings.signup_policy, SignupPolicy::Open) {
        " checked"
    } else {
        ""
    };
    let invite_sel = if matches!(settings.signup_policy, SignupPolicy::InviteOnly) {
        " checked"
    } else {
        ""
    };
    let pw = if settings.password_login {
        " checked"
    } else {
        ""
    };
    let caches_pub = if settings.caches_public {
        " checked"
    } else {
        ""
    };
    let lifetime = settings
        .session_lifetime_secs
        .map(|s| s.to_string())
        .unwrap_or_default();
    let _ = write!(
        body,
        "<h2>Signup &amp; identity</h2>\n\
         <form class=\"console\" method=\"post\" action=\"/-/instance\">{csrf}\
         <label><span class=\"lbl\">org signup{help}</span> <select name=\"signup_policy\">\
         <option value=\"invite_only\"{invite_sel}>invite only</option>\
         <option value=\"open\"{open_sel}>open</option></select></label>\n\
         <label><span class=\"lbl\">signup domain allowlist{domains_help}</span> \
         <input type=\"text\" name=\"signup_domains\" value=\"{domains}\" \
         placeholder=\"acme.com, example.org\"> \
         <span class=\"dim\">comma-separated; empty allows any domain</span></label>\n\
         <label><span class=\"lbl\">offer password login{pw_help}</span> \
         <input type=\"checkbox\" name=\"password_login\" value=\"1\"{pw}></label>\n\
         <label><span class=\"lbl\">show caches to logged-out visitors</span> \
         <input type=\"checkbox\" name=\"caches_public\" value=\"1\"{caches_pub}> \
         <span class=\"dim\">off: the caches tab + cache pages require login</span></label>\n\
         <label><span class=\"lbl\">session lifetime (seconds){life_help}</span> \
         <input type=\"number\" name=\"session_lifetime_secs\" value=\"{lifetime}\" min=\"0\"> \
         <span class=\"dim\">empty uses the built-in default</span></label>\n\
         <button>save</button>\n</form>\n",
        csrf = csrf_field(csrf),
        help = help::marker("instance.signup_policy"),
        domains_help = help::marker("instance.signup_domains"),
        pw_help = help::marker("instance.password_login"),
        life_help = help::marker("instance.session_lifetime"),
        domains = escape(&settings.signup_domains.join(", ")),
    );
    instance_settings_chrome(email, "general", &body, started)
}

/// The instance-settings "Branding" page (instance admins only): the site
/// title, tagline, announcement banner, and footer legal/contact links.
///
/// All are D1-backed and editable here; the deploy only seeds initial values.
/// An empty field resets to the default (the title falls back to the deploy
/// `--brand`).
#[must_use]
pub fn instance_branding_page(
    email: &str,
    csrf: &str,
    settings: &crate::db::InstanceSettings,
    notice: Option<&str>,
    started: Instant,
) -> String {
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    let val = |o: &Option<String>| escape(o.as_deref().unwrap_or(""));
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/instance/branding\">{csrf}\
         <label><span class=\"lbl\">site title</span> \
         <input type=\"text\" name=\"site_title\" value=\"{title}\" placeholder=\"AOS Hub\"> \
         <span class=\"dim\">shown in the masthead; empty uses the deploy brand</span></label>\n\
         <label><span class=\"lbl\">tagline</span> \
         <input type=\"text\" name=\"tagline\" value=\"{tagline}\"></label>\n\
         <label><span class=\"lbl\">announcement banner{announce_help}</span> \
         <textarea name=\"announcement\" rows=\"2\" cols=\"60\">{announce}</textarea> \
         <span class=\"dim\">shown on every page; empty for none</span></label>\n\
         <h2>Footer links</h2>\n\
         <label><span class=\"lbl\">terms of service URL</span> \
         <input type=\"text\" name=\"tos_url\" value=\"{tos}\" placeholder=\"https://…\"></label>\n\
         <label><span class=\"lbl\">privacy policy URL</span> \
         <input type=\"text\" name=\"privacy_url\" value=\"{privacy}\" placeholder=\"https://…\"></label>\n\
         <label><span class=\"lbl\">support URL</span> \
         <input type=\"text\" name=\"support_url\" value=\"{support}\" placeholder=\"https://…\"></label>\n\
         <button>save</button>\n</form>\n",
        csrf = csrf_field(csrf),
        announce_help = help::marker("instance.announcement"),
        title = val(&settings.site_title),
        tagline = val(&settings.tagline),
        announce = val(&settings.announcement),
        tos = val(&settings.tos_url),
        privacy = val(&settings.privacy_url),
        support = val(&settings.support_url),
    );
    instance_settings_chrome(email, "branding", &body, started)
}

/// The instance-settings "Serving" page (instance admins only): the
/// instance-wide defaults new registries/caches inherit — the default crawl
/// policy and the maximum surface upload size.
#[must_use]
pub fn instance_serving_page(
    email: &str,
    csrf: &str,
    settings: &crate::db::InstanceSettings,
    notice: Option<&str>,
    started: Instant,
) -> String {
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    let mut crawl_options = String::new();
    for p in ["allow_all", "allow_no_ai", "deny_all"] {
        let sel = if p == settings.default_crawl_policy {
            " selected"
        } else {
            ""
        };
        let _ = write!(crawl_options, "<option value=\"{p}\"{sel}>{p}</option>");
    }
    let max_upload = settings
        .max_upload_bytes
        .map(|b| b.to_string())
        .unwrap_or_default();
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/instance/serving\">{csrf}\
         <label><span class=\"lbl\">default crawl policy{help}</span> \
         <select name=\"default_crawl_policy\">{crawl}</select> \
         <span class=\"dim\">new registries inherit this robots.txt posture</span></label>\n\
         <label><span class=\"lbl\">max upload (bytes){upload_help}</span> \
         <input type=\"number\" name=\"max_upload_bytes\" value=\"{max_upload}\" min=\"0\"> \
         <span class=\"dim\">empty uses the built-in default</span></label>\n\
         <button>save</button>\n</form>\n",
        csrf = csrf_field(csrf),
        help = help::marker("registry.crawl_policy"),
        upload_help = help::marker("instance.max_upload"),
        crawl = crawl_options,
    );
    instance_settings_chrome(email, "serving", &body, started)
}

/// The instance-settings "Storage" page (instance admins only): the
/// deployment's default storage backend.
///
/// Read-only: the default store is the Worker's R2 bucket binding (or the
/// native hub's storage root), fixed when the hub is deployed and not
/// runtime-editable from the web. The actionable lever — pushing a registry or
/// cache elsewhere — is an org-scoped storage binding, linked from here.
/// The shared frontend field set (domain, base path, mode, serves-*, advertise,
/// priority) with attached help, used by every "add a frontend" form and its
/// per-row "edit" form. When `f` is `Some`, the inputs are pre-filled for an
/// edit; when `None`, sensible add-defaults apply. The `domain` input is a bare
/// host (no scheme) — that is validated server-side.
fn frontend_form_fields(f: Option<&FrontendRecord>) -> String {
    let ck = |on: bool| if on { " checked" } else { "" };
    let mode = f.map_or("direct", |x| x.mode.as_str());
    format!(
        "<label>domain <input type=\"text\" name=\"domain\" required value=\"{domain}\" \
         placeholder=\"cdn.acme.com\"> <span class=\"dim\">host only — no https://</span></label>\n\
         <label>base path <input type=\"text\" name=\"base_path\" value=\"{base_path}\" \
         placeholder=\"(domain root)\"></label>\n\
         <label><span class=\"lbl\">mode{mode_help}</span> <select name=\"mode\">\
         <option value=\"direct\"{dsel}>direct</option>\
         <option value=\"proxied\"{psel}>proxied</option></select></label>\n\
         <label><span class=\"lbl\">serves git{git_help}</span> \
         <input type=\"checkbox\" name=\"serves_git\" value=\"1\"{g}></label>\n\
         <label><span class=\"lbl\">serves cache{cache_help}</span> \
         <input type=\"checkbox\" name=\"serves_cache\" value=\"1\"{ca}></label>\n\
         <label><span class=\"lbl\">serves web{web_help}</span> \
         <input type=\"checkbox\" name=\"serves_web\" value=\"1\"{w}></label>\n\
         <label><span class=\"lbl\">advertise to consumers{adv_help}</span> \
         <input type=\"checkbox\" name=\"advertised\" value=\"1\"{adv}></label>\n\
         <label><span class=\"lbl\">consumer priority{prio_help}</span> \
         <input type=\"text\" name=\"consumer_priority\" value=\"{prio}\"></label>\n",
        domain = escape(f.map_or("", |x| x.domain.as_str())),
        base_path = escape(f.map_or("", |x| x.base_path.as_str())),
        mode_help = help::marker("frontend.mode"),
        dsel = if mode == "direct" { " selected" } else { "" },
        psel = if mode == "proxied" { " selected" } else { "" },
        git_help = help::marker("frontend.serves_git"),
        g = ck(f.map_or(true, |x| x.serves_git)),
        cache_help = help::marker("frontend.serves_cache"),
        ca = ck(f.map_or(true, |x| x.serves_cache)),
        web_help = help::marker("frontend.serves_web"),
        w = ck(f.map_or(true, |x| x.serves_web)),
        adv_help = help::marker("frontend.advertised"),
        adv = ck(f.map_or(true, |x| x.advertised)),
        prio_help = help::marker("frontend.priority"),
        prio = f.map_or(100, |x| x.consumer_priority),
    )
}

#[must_use]
/// Render the shared storage-binding serving controls — public-access settings
/// plus inherited-frontend management — used by both the instance default
/// storage page and an org's custom-binding pages (RFC-0004 §12), so both share
/// one interface. `post_action` is the form target; it dispatches `op` values
/// `set-public` / `add-frontend` / `edit-frontend` / `delete-frontend` for this
/// `binding`.
pub fn storage_binding_serving_section(
    post_action: &str,
    csrf: &str,
    binding: &StorageBindingRecord,
    frontends: &[FrontendRecord],
) -> String {
    let mut body = String::new();
    let action = escape(post_action);

    // --- Access & endpoint ---
    body.push_str("<h2>Access &amp; endpoint</h2>\n");
    body.push_str(
        "<p class=\"dim\">The <strong>endpoint</strong> is the S3/R2 API the hub writes objects \
         through and presigns reads against (e.g. \
         <code>https://&lt;account&gt;.r2.cloudflarestorage.com</code>) — the bucket's \
         origin, <em>not</em> a consumer-facing URL. Where consumers read from is a \
         <strong>serving frontend</strong> below. A <code>public</code> binding may carry a \
         <code>direct</code> frontend consumers fetch from straight, bypassing the hub; a \
         <code>private</code> binding is hub-only (proxied or presigned) and can never be \
         Direct.</p>\n",
    );
    let sel = |v: &str| if binding.access == v { " selected" } else { "" };
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"{action}\">{csrf}\
         <input type=\"hidden\" name=\"op\" value=\"set-public\">\n\
         <label><span class=\"lbl\">access{access_help}</span> <select name=\"access\">\
         <option value=\"private\"{psel}>private</option>\
         <option value=\"public\"{usel}>public</option></select></label>\n\
         <label><span class=\"lbl\">endpoint{base_help}</span> \
         <input type=\"text\" name=\"endpoint\" value=\"{base}\" \
         placeholder=\"https://&lt;account&gt;.r2.cloudflarestorage.com\"></label>\n\
         <button>save</button>\n</form>\n",
        action = action,
        csrf = csrf_field(csrf),
        access_help = help::marker("binding.access"),
        base_help = help::marker("binding.endpoint"),
        psel = sel("private"),
        usel = sel("public"),
        base = escape(binding.endpoint.as_deref().unwrap_or("")),
    );

    // --- Frontends (inherited by every registry/cache stored here) ---
    body.push_str("<h2>Serving frontends</h2>\n");
    body.push_str(
        "<p class=\"dim\">A frontend is a domain that serves this bucket. Every registry and \
         cache stored in this binding inherits it, with its own objects under its \
         <code>prefix</code>; a <code>direct</code>, advertised frontend over a \
         <code>public</code> binding makes consumers pull straight from the bucket.</p>\n",
    );
    if frontends.is_empty() {
        body.push_str("<p class=\"dim\">No frontends configured.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = frontends
            .iter()
            .map(|f| {
                let mut serves = Vec::new();
                if f.serves_git {
                    serves.push("git");
                }
                if f.serves_cache {
                    serves.push("cache");
                }
                if f.serves_web {
                    serves.push("web");
                }
                // Per-row actions: an inline "edit" disclosure (pre-filled form)
                // and a delete button.
                let actions = format!(
                    "<details><summary>edit</summary>\
                     <form class=\"console\" method=\"post\" action=\"{action}\">{csrf}\
                     <input type=\"hidden\" name=\"op\" value=\"edit-frontend\">\
                     <input type=\"hidden\" name=\"id\" value=\"{id}\">\n{fields}\
                     <button>save changes</button></form></details>\n\
                     <form class=\"console\" method=\"post\" action=\"{action}\" \
                     style=\"display:inline\">{csrf}\
                     <input type=\"hidden\" name=\"op\" value=\"delete-frontend\">\
                     <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                     <button class=\"danger\">delete</button></form>",
                    action = action,
                    csrf = csrf_field(csrf),
                    id = f.id,
                    fields = frontend_form_fields(Some(f)),
                );
                vec![
                    format!("<code>{}{}</code>", escape(&f.domain), escape(&f.base_path)),
                    escape(&f.mode),
                    escape(&serves.join(", ")),
                    if f.advertised {
                        "<span class=\"ok\">advertised</span>".to_string()
                    } else {
                        "<span class=\"dim\">no</span>".to_string()
                    },
                    actions,
                ]
            })
            .collect();
        body.push_str(&table(
            &["domain", "mode", "serves", "advertised", ""],
            &rows,
        ));
    }
    let _ = write!(
        body,
        "<h3>Add a frontend</h3>\n\
         <form class=\"console\" method=\"post\" action=\"{action}\">{csrf}\
         <input type=\"hidden\" name=\"op\" value=\"add-frontend\">\n{fields}\
         <button>add frontend</button>\n</form>\n",
        action = action,
        csrf = csrf_field(csrf),
        fields = frontend_form_fields(None),
    );
    body
}

pub fn instance_storage_page(
    email: &str,
    default_storage_location: Option<&str>,
    binding: Option<&StorageBindingRecord>,
    frontends: &[FrontendRecord],
    csrf: &str,
    notice: Option<&str>,
    started: Instant,
) -> String {
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    body.push_str(
        "<p>Registries and caches with no explicit storage binding push to the \
         deployment's own default storage.</p>\n",
    );
    let kind = RuntimeKind::current().default_storage_kind();
    let location = match default_storage_location {
        Some(loc) if !loc.trim().is_empty() => format!("<code>{}</code>", escape(loc)),
        _ => "<span class=\"dim\">configured at deploy time</span>".to_string(),
    };
    let _ = writeln!(
        body,
        "<p>kind <span class=\"chip\">{kind}</span> · location {location}</p>",
        kind = escape(kind),
        location = location,
    );
    body.push_str(
        "<p class=\"dim\">The default store's <em>backend</em> is fixed at deploy time (the \
         Worker's R2 bucket, or the native hub's storage root). Its public domain and frontends \
         below are editable — publish the bucket so binding-less registries/caches advertise a \
         direct, edge-served URL (RFC-0004 §12).</p>\n",
    );
    match binding {
        Some(binding) => body.push_str(&storage_binding_serving_section(
            "/-/instance/storage",
            csrf,
            binding,
            frontends,
        )),
        None => body.push_str(
            "<p class=\"dim\">The instance default binding has not been seeded yet (run \
             <code>aos-hub init</code> to apply the latest migrations).</p>\n",
        ),
    }
    instance_settings_chrome(email, "storage", &body, started)
}

/// An org custom storage binding's serving page: edit its public access and
/// frontends through the same [`storage_binding_serving_section`] the instance
/// default storage uses, so custom + default bindings share one interface
/// (RFC-0004 §12).
pub fn org_binding_page(
    email: &str,
    org_slug: &str,
    binding: &StorageBindingRecord,
    frontends: &[FrontendRecord],
    csrf: &str,
    notice: Option<&str>,
    started: Instant,
) -> String {
    let mut body = format!("<h1>Storage binding · {}</h1>\n", escape(&binding.name));
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    let _ = writeln!(
        body,
        "<p>kind <span class=\"chip\">{}</span> · root <code>{}</code></p>",
        escape(&binding.kind),
        escape(&binding.root),
    );
    let action = format!("/-/org/{}/bindings/{}", org_slug, binding.id);
    body.push_str(&storage_binding_serving_section(
        &action, csrf, binding, frontends,
    ));
    let _ = write!(
        body,
        "<p class=\"dim\"><a href=\"/-/org/{}/storage\">&larr; back to storage</a></p>\n",
        escape(org_slug),
    );
    org_settings_chrome(email, org_slug, "storage", &body, started)
}

/// The registry "serving & mirror" page: the serving frontends (domains) and
/// the optional upstream mirror configuration.
///
/// Frontends and mirror config are registry metadata, not signed surface
/// content, so they are direct mutations. (Triggering a mirror *sync* is a
/// scheduled background job / a CLI action, not a web button.)
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn serving_page(
    email: &str,
    registry: &RegistryRecord,
    csrf: &str,
    frontends: &[FrontendRecord],
    // Frontends inherited from the storage binding this registry lives on (or the
    // instance-default binding when unbound): read-only here, edited at the
    // binding. `inherited_label`/`inherited_href` name + link to that binding.
    inherited: &[FrontendRecord],
    inherited_label: &str,
    inherited_href: &str,
    advertise_storage_frontend: bool,
    mirror: Option<&MirrorSource>,
    notice: Option<&str>,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }

    // --- Frontends ---
    body.push_str("<h2>Serving frontends</h2>\n");
    body.push_str(
        "<p class=\"dim\">A frontend is a domain that serves this registry's surfaces. \
         <code>direct</code> means the hub is not in the path (probe-only); <code>proxied</code> \
         means the hub's facade serves it.</p>\n",
    );
    if frontends.is_empty() {
        body.push_str("<p class=\"dim\">No frontends configured.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = frontends
            .iter()
            .map(|f| {
                let mut serves = Vec::new();
                if f.serves_git {
                    serves.push("git");
                }
                if f.serves_cache {
                    serves.push("cache");
                }
                if f.serves_web {
                    serves.push("web");
                }
                let actions = format!(
                    "<details><summary>edit</summary>\
                     <form class=\"console\" method=\"post\" \
                     action=\"/{slug}/-/settings/serving\">{csrf}\
                     <input type=\"hidden\" name=\"op\" value=\"edit-frontend\">\
                     <input type=\"hidden\" name=\"id\" value=\"{id}\">\n{fields}\
                     <button>save changes</button></form></details>\n\
                     <form class=\"console\" method=\"post\" \
                     action=\"/{slug}/-/settings/serving\" style=\"display:inline\">{csrf}\
                     <input type=\"hidden\" name=\"op\" value=\"delete-frontend\">\
                     <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                     <button class=\"danger\">delete</button></form>",
                    slug = escape(slug),
                    csrf = csrf_field(csrf),
                    id = f.id,
                    fields = frontend_form_fields(Some(f)),
                );
                vec![
                    format!("<code>{}{}</code>", escape(&f.domain), escape(&f.base_path)),
                    escape(&f.mode),
                    escape(&serves.join(", ")),
                    if f.advertised {
                        "<span class=\"ok\">advertised</span>".to_string()
                    } else {
                        "<span class=\"dim\">no</span>".to_string()
                    },
                    actions,
                ]
            })
            .collect();
        body.push_str(&table(
            &["domain", "mode", "serves", "advertised", ""],
            &rows,
        ));
    }
    let _ = write!(
        body,
        "<h3>Add a frontend</h3>\n\
         <form class=\"console\" method=\"post\" action=\"/{slug}/-/settings/serving\">{csrf}\
         <input type=\"hidden\" name=\"op\" value=\"add-frontend\">\n{fields}\
         <button>add frontend</button>\n</form>\n",
        slug = escape(slug),
        csrf = csrf_field(csrf),
        fields = frontend_form_fields(None),
    );

    // --- Inherited frontends (from the storage binding) ---
    // A registry with no direct frontend of its own is still served through the
    // frontends of the storage binding it lives on (the instance-default binding
    // when unbound). Show them read-only, with a link to edit them at the binding.
    if !inherited.is_empty() {
        let _ = write!(
            body,
            "<h3>Inherited from {label}</h3>\n\
             <p class=\"dim\">Frontends on this registry's storage binding also serve it \
             (under this registry's prefix). Edit them at <a href=\"{href}\">{label}</a>.</p>\n",
            label = escape(inherited_label),
            href = escape(inherited_href),
        );
        let rows: Vec<Vec<String>> = inherited
            .iter()
            .map(|f| {
                let mut serves = Vec::new();
                if f.serves_git {
                    serves.push("git");
                }
                if f.serves_cache {
                    serves.push("cache");
                }
                if f.serves_web {
                    serves.push("web");
                }
                vec![
                    format!("<code>{}{}</code>", escape(&f.domain), escape(&f.base_path)),
                    escape(&f.mode),
                    escape(&serves.join(", ")),
                    if f.advertised {
                        "<span class=\"ok\">advertised</span>".to_string()
                    } else {
                        "<span class=\"dim\">no</span>".to_string()
                    },
                ]
            })
            .collect();
        body.push_str(&table(&["domain", "mode", "serves", "advertised"], &rows));
    }

    // --- Inherited-route selection ---
    let _ = write!(
        body,
        "<h3>Storage-direct serving</h3>\n\
         <p class=\"dim\">Use an advertised direct frontend from this registry's storage \
         binding as the consumer-facing route. Disable it to keep traffic on the hub or on \
         registry-specific frontends.</p>\n\
         <form class=\"console\" method=\"post\" \
         action=\"/{slug}/-/settings/advertise-frontend\">{csrf}\
         <label><span class=\"lbl\">advertise an inherited storage frontend</span> \
         <input type=\"checkbox\" name=\"advertise\" value=\"1\"{checked}></label>\n\
         <button>save serving route</button></form>\n",
        slug = escape(slug),
        csrf = csrf_field(csrf),
        checked = if advertise_storage_frontend {
            " checked"
        } else {
            ""
        },
    );

    // --- Mirror ---
    body.push_str("<h2>Upstream mirror</h2>\n");
    if let Some(m) = mirror {
        let status = match m.last_sync_status.as_deref() {
            Some("ok") => "<span class=\"ok\">ok</span>".to_string(),
            Some("failed") => format!(
                "<span class=\"bad\">failed</span> {}",
                escape(m.last_sync_error.as_deref().unwrap_or(""))
            ),
            _ => "<span class=\"dim\">never synced</span>".to_string(),
        };
        let _ = write!(
            body,
            "<p class=\"dim\">Mirroring <code>{}</code> in <strong>{}</strong> mode \
             (verify {}, every {}s). Last sync: {}{}.</p>\n",
            escape(&m.upstream_url),
            escape(&m.mode),
            if m.verify { "on" } else { "off" },
            m.schedule_secs,
            status,
            m.last_sync_at
                .map(|t| format!(" · {}", ago(t)))
                .unwrap_or_default(),
        );
        body.push_str(
            "<p class=\"dim\">Syncs run on the schedule above (or via \
             <code>aos mirror sync</code>); there is no web trigger.</p>\n",
        );
    } else {
        body.push_str(
            "<p class=\"dim\">This registry is not a mirror. Marking it one makes the hub \
             replicate an upstream surface here.</p>\n",
        );
    }
    let cur_url = mirror.map(|m| m.upstream_url.clone()).unwrap_or_default();
    let cur_secs = mirror.map_or(3600, |m| m.schedule_secs);
    let full_sel = mirror.is_none_or(|m| m.mode == "full");
    let verify_on = mirror.is_none_or(|m| m.verify);
    let _ = write!(
        body,
        "<h3>{}</h3>\n\
         <form class=\"console\" method=\"post\" action=\"/{slug}/-/settings/serving\">{csrf}\
         <input type=\"hidden\" name=\"op\" value=\"set-mirror\">\n\
         <label>upstream URL <input type=\"text\" name=\"upstream_url\" required value=\"{url}\" \
         placeholder=\"https://upstream.example/registry\"></label>\n\
         <label>mode <select name=\"mode\"><option value=\"full\"{full}>full (scheduled copy)</option>\
         <option value=\"pullthrough\"{pull}>pullthrough (fetch-on-miss)</option></select></label>\n\
         <label><span class=\"lbl\">verify upstream signatures</span> <input type=\"checkbox\" name=\"verify\" value=\"1\"{verify}></label>\n\
         <label>schedule (seconds) <input type=\"text\" name=\"schedule_secs\" value=\"{secs}\"></label>\n\
         <button>save mirror</button>\n</form>\n",
        if mirror.is_some() { "Update mirror" } else { "Mark as mirror" },
        slug = escape(slug),
        csrf = csrf_field(csrf),
        url = escape(&cur_url),
        full = if full_sel { " selected" } else { "" },
        pull = if !full_sel { " selected" } else { "" },
        verify = if verify_on { " checked" } else { "" },
        secs = cur_secs,
    );
    if mirror.is_some() {
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/{slug}/-/settings/serving\">{csrf}\
             <input type=\"hidden\" name=\"op\" value=\"remove-mirror\">\
             <button class=\"danger\">stop mirroring</button></form>\n",
            slug = escape(slug),
            csrf = csrf_field(csrf),
        );
    }

    registry_settings_chrome(email, slug, "serving", &body, started)
}

/// The publish-pipeline status view.
///
/// Derived (no live job stream yet): the index state, last indexed commit,
/// the verified releases as a timeline, and recent `publish`/`index` audit
/// entries. A full live pipeline stream is a later phase (RFC-0004).
#[must_use]
pub fn publishes_page(
    email: &str,
    registry: &RegistryRecord,
    status: Option<&IndexStatus>,
    releases: &[ReleaseRow],
    audit: &[AuditRow],
    started: Instant,
) -> String {
    let slug = &registry.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();

    body.push_str("<h2>Index</h2>\n");
    let (state, commit) = match status {
        Some(s) => (
            s.state.clone(),
            s.last_indexed_commit.clone().unwrap_or_else(|| "—".into()),
        ),
        None => ("unindexed".into(), "—".into()),
    };
    let class = match state.as_str() {
        "fresh" => "ok",
        "failed" => "bad",
        // Indexed, nothing published yet — benign, not a warning.
        "empty" => "dim",
        _ => "warn",
    };
    let _ = writeln!(
        body,
        "<p>state <span class=\"{class}\">{}</span> · last commit <code>{}</code></p>",
        escape(&state),
        escape(&commit[..commit.len().min(12)]),
    );

    body.push_str("<h2>Releases</h2>\n");
    if releases.is_empty() {
        body.push_str("<p class=\"dim\">No verified releases yet.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = releases
            .iter()
            .map(|r| {
                vec![
                    escape(&r.semver),
                    if r.signer.is_some() {
                        "<span class=\"ok\">✓ signed</span>".to_string()
                    } else {
                        "<span class=\"dim\">unverified</span>".to_string()
                    },
                    if r.pack_present {
                        "<span class=\"ok\">✓ pack</span>".to_string()
                    } else {
                        "<span class=\"dim\">—</span>".to_string()
                    },
                    r.tagged_at.map(ago).unwrap_or_else(|| "—".into()),
                ]
            })
            .collect();
        body.push_str(&table(&["release", "signature", "pack", "tagged"], &rows));
    }

    body.push_str("<h2>Recent activity</h2>\n");
    if audit.is_empty() {
        body.push_str("<p class=\"dim\">No publish or index activity recorded.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = audit
            .iter()
            .map(|a| {
                vec![
                    ago(a.created_at),
                    escape(&a.actor_label),
                    format!("<code>{}</code>", escape(&a.action)),
                ]
            })
            .collect();
        body.push_str(&table(&["when", "actor", "action"], &rows));
    }
    body.push_str(
        "<p class=\"dim\">Derived from the index status, verified releases, and the audit feed. \
         A live phase-by-phase pipeline stream is a later phase.</p>\n",
    );

    // Keep the index-aware footer state line, but render the body inside the
    // shared registry settings sidebar for a uniform IA.
    let state_line = match status {
        Some(s) => StateLine {
            surface_commit: s.last_indexed_commit.clone(),
            indexed_at: s.indexed_at,
            state: Some(s.state.clone()),
            started: Some(started),
        },
        None => StateLine::timed(started),
    };
    let content = settings_layout(&registry_settings_navigation(slug, "publishes"), &body);
    page_with_session(
        &format!("manage · {slug}"),
        &registry_crumbs(slug),
        &content,
        &state_line,
        &indicator(email),
    )
}

/// Whether `grants` authorize `perm` at the registry/org `scope`.
///
/// A small wrapper over [`iam::allow`] used by the console handlers to gate
/// management controls in templates.
#[must_use]
pub fn grants_allow(grants: &[(Scope, Role)], perm: Permission, scope: &Scope) -> bool {
    iam::allow(grants, perm, scope)
}

/// Renders a list of prepared/applied change-sets for a scope (used by the
/// channel console's prepared-operation history).
#[must_use]
pub fn changeset_rows(changesets: &[ChangesetRow]) -> Vec<Vec<String>> {
    changesets
        .iter()
        .map(|cs| {
            vec![
                format!("<code>{}</code>", escape(&cs.change_id)),
                escape(&cs.status),
                escape(cs.summary.as_deref().unwrap_or("—")),
            ]
        })
        .collect()
}

/// The git-backed config-edit page for a registry (RFC-0004 "Configuration
/// management").
///
/// Renders a textarea pre-filled with the current committed `registry.toml`
/// and a submit button that posts the edit as a *change request* — the hub
/// commits the edit, draft-signed, to `refs/hub/changes/<id>` for a maintainer
/// to review and promote with `apr change merge`. After a submit, `result`
/// carries the new change id and the merge command to echo. `can_edit` gates
/// the form behind `registry.configure`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn config_edit_page(
    email: &str,
    registry: &RegistryRecord,
    csrf: &str,
    current_toml: &str,
    can_edit: bool,
    result: Option<(&str, &str)>,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    body.push_str(
        "<p class=\"dim\">Web edits to committed config are <strong>change \
         requests</strong>. The hub commits the edit, draft-signed by a key \
         that is not in the roster, to <code>refs/hub/changes/&lt;id&gt;</code>. \
         A maintainer reviews and promotes it locally with \
         <code>apr change merge</code>; roster keys never leave their machine.</p>\n",
    );

    if let Some((change_id, merge_command)) = result {
        let _ = write!(
            body,
            "<p class=\"good\">Change request <code>{}</code> created. Promote it with:</p>\n\
             <pre>{}</pre>\n\
             <p><a href=\"/{}/-/changes\">view change requests</a></p>\n",
            escape(change_id),
            escape(merge_command),
            escape(slug),
        );
    }

    if can_edit {
        // The label is its own block above the editor (an inline label next
        // to a tall textarea baseline-aligns to the bottom and reads as a
        // stray word). The `.code-editor` wrapper is the no-JS textarea plus
        // an empty highlight overlay that `app.js` activates if it loads.
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/{}/-/settings/config\">\n{}\
             <span class=\"field-label\">registry.toml</span>\n\
             <div class=\"code-editor\" data-lang=\"toml\">\
             <pre class=\"code-highlight\" aria-hidden=\"true\"><code></code></pre>\
             <textarea name=\"contents\" rows=\"18\" spellcheck=\"false\" required>{}</textarea>\
             </div>\n\
             <label>title <input type=\"text\" name=\"cr_title\" \
             placeholder=\"summarize this change\"></label>\n\
             <label><span class=\"lbl\">description</span> \
             <textarea name=\"cr_body\" rows=\"3\"></textarea> \
             <span class=\"dim\">optional</span></label>\n\
             <button>submit change request</button>\n</form>\n",
            escape(slug),
            csrf_field(csrf),
            escape(current_toml),
        );
    } else {
        body.push_str(
            "<p class=\"dim\">You need <code>registry.configure</code> to propose a change.</p>\n",
        );
        let _ = writeln!(body, "<pre>{}</pre>", escape(current_toml));
    }

    registry_settings_chrome(email, slug, "config", &body, started)
}

/// Renders one editable `[caches]` row (URL + remove button).
///
/// The unified `[caches]` stack derives priority from order (the first row is
/// highest), so the row carries only the URL. `app.js` clones the trailing row
/// to add more and wires the remove button; with no JS the server-rendered rows
/// (existing entries plus one blank) are still fully editable.
fn cache_row_html(url: &str) -> String {
    format!(
        "<div class=\"cache-row\">\
         <input type=\"text\" name=\"cache_url\" value=\"{url}\" \
         placeholder=\"https://cache.example.org\" aria-label=\"cache URL\">\
         <button type=\"button\" class=\"row-del\" aria-label=\"remove cache\">&times;</button>\
         </div>",
        url = escape(url),
    )
}

/// The auto-generated structured config-edit page (`/{slug}/-/settings/config`).
///
/// Replaces the raw-TOML textarea with one control per
/// [`RegistryRootConfig`](aos_registry_surface::manifest::RegistryRootConfig)
/// field: name, description, readme, the content-addressed toggle, and the
/// ordered `[caches]` list. On submit the handler rebuilds the committed
/// `registry.toml` and proposes it as the same git-backed change request the
/// raw editor used, so `result` (the new change id and merge command) and the
/// `registry.configure` `can_edit` gate behave identically. `model` carries the
/// current field values (and, on a rejected submission, a preserved-input
/// [`ConfigFormModel::error`](crate::web::config_form::ConfigFormModel::error)).
///
/// A file the form cannot represent is never shown here — the handler falls
/// back to [`config_edit_page`] for that case.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn registry_config_form_page(
    email: &str,
    registry: &RegistryRecord,
    csrf: &str,
    model: &crate::web::config_form::ConfigFormModel,
    can_edit: bool,
    // The registry's DB-linked caches, offered as one-click autofill into the
    // `[caches]` editor with a live present/missing indicator.
    linked_caches: &[LinkedCacheSuggestion],
    result: Option<(&str, &str)>,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    body.push_str(
        "<p class=\"dim\">Web edits to committed config are <strong>change \
         requests</strong>. The hub commits the edit, draft-signed by a key \
         that is not in the roster, to <code>refs/hub/changes/&lt;id&gt;</code>. \
         A maintainer reviews and promotes it locally with \
         <code>apr change merge</code>; roster keys never leave their machine.</p>\n",
    );

    if let Some((change_id, merge_command)) = result {
        let _ = write!(
            body,
            "<p class=\"good\">Change request <code>{}</code> created. Promote it with:</p>\n\
             <pre>{}</pre>\n\
             <p><a href=\"/{}/-/changes\">view change requests</a></p>\n",
            escape(change_id),
            escape(merge_command),
            escape(slug),
        );
    }

    if !can_edit {
        body.push_str(
            "<p class=\"dim\">You need <code>registry.configure</code> to propose a change.</p>\n",
        );
        return registry_settings_chrome(email, slug, "config", &body, started);
    }

    if let Some(err) = &model.error {
        let _ = write!(body, "<p class=\"bad\">{}</p>\n", escape(err));
    }

    // Existing cache rows, then one trailing blank row so a no-JS user can add
    // one and `app.js` has a row to clone.
    let mut cache_rows = String::new();
    for cache in &model.caches {
        cache_rows.push_str(&cache_row_html(&cache.url));
    }
    cache_rows.push_str(&cache_row_html(""));

    let cache_stack_note = if model.has_cache_stack {
        "<p class=\"dim\">This registry defines an advanced \
         <code>[caches]</code> stack (a mirror or nesting) the list editor \
         cannot represent; it is preserved unchanged. Edit the stack expression \
         via raw TOML with <code>apr</code>.</p>\n"
    } else {
        ""
    };

    // Autofill panel: the registry's DB-linked caches, each with a live
    // present/missing indicator against the editor's current `[caches]` and a
    // one-click "add" that inserts its consumer URL. Hidden for an advanced
    // stack (the list editor is inactive then).
    let autofill_panel = if model.has_cache_stack || linked_caches.is_empty() {
        String::new()
    } else {
        let mut panel = String::from(
            "<details class=\"autofill\" open><summary>Linked caches</summary>\n\
             <p class=\"dim\">Caches linked to this registry. Add a linked cache's URL \
             to advertise it to consumers.</p>\n<ul class=\"autofill-list\">\n",
        );
        for cache in linked_caches {
            let action = if cache.present {
                "<span class=\"chip\">in config</span>".to_string()
            } else {
                format!(
                    "<span class=\"chip warn\">missing</span> \
                     <button type=\"button\" class=\"row-add\" \
                     data-add-cache-url=\"{url}\">add</button>",
                    url = escape(&cache.consumer_url),
                )
            };
            let _ = write!(
                panel,
                "<li><span class=\"autofill-name\">{slug}</span> \
                 <code>{url}</code> {action}</li>\n",
                slug = escape(&cache.cache_slug),
                url = escape(&cache.consumer_url),
                action = action,
            );
        }
        panel.push_str("</ul></details>\n");
        panel
    };

    let _ = write!(
        body,
        "<form class=\"console\" data-config-form method=\"post\" \
         action=\"/{slug}/-/settings/config\">\n{csrf}\
         <label>name <input type=\"text\" name=\"name\" value=\"{name}\" required></label>\n\
         <label><span class=\"lbl\">description</span> \
         <input type=\"text\" name=\"description\" value=\"{description}\"> \
         <span class=\"dim\">optional</span></label>\n\
         <label><span class=\"lbl\">readme{readme_help}</span> \
         <textarea name=\"readme\" rows=\"6\" cols=\"80\">{readme}</textarea> \
         <span class=\"dim\">optional</span></label>\n\
         <label><span class=\"lbl\">content-addressed{ca_help}</span> \
         <input type=\"checkbox\" name=\"content_addressed\" value=\"1\"{ca}></label>\n\
         <span class=\"field-label\">binary caches{caches_help}</span>\n\
         <div class=\"cache-rows\" data-cache-rows>\n{cache_rows}</div>\n\
         <button type=\"button\" class=\"row-add\" data-add-cache>+ add cache</button>\n\
         {autofill_panel}\
         {cache_stack_note}\
         <label>title <input type=\"text\" name=\"cr_title\" \
         placeholder=\"summarize this change\"></label>\n\
         <label><span class=\"lbl\">description</span> \
         <textarea name=\"cr_body\" rows=\"3\"></textarea> \
         <span class=\"dim\">optional</span></label>\n\
         <button>submit change request</button>\n</form>\n\
         <p class=\"dim\">Submitting rebuilds <code>registry.toml</code> from these \
         fields; comments in the committed file are not preserved.</p>\n",
        csrf = csrf_field(csrf),
        name = escape(&model.name),
        description = escape(&model.description),
        readme = escape(&model.readme),
        readme_help = help::marker("registry.readme"),
        ca_help = help::marker("registry.content_addressed"),
        ca = if model.content_addressed {
            " checked"
        } else {
            ""
        },
        caches_help = help::marker("registry.caches"),
        cache_rows = cache_rows,
        autofill_panel = autofill_panel,
        cache_stack_note = cache_stack_note,
    );

    registry_settings_chrome(email, slug, "config", &body, started)
}

/// Which slice of a registry's change requests the list page shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangesFilter {
    /// Open drafts (`status = draft` and not closed).
    Open,
    /// Everything terminal or withdrawn (merged, reverted, or closed).
    Closed,
    /// Every change request, regardless of state.
    All,
}

impl ChangesFilter {
    /// Parses the `?state=` query value, defaulting to [`ChangesFilter::Open`].
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        match raw {
            Some("closed") => Self::Closed,
            Some("all") => Self::All,
            _ => Self::Open,
        }
    }

    /// The `?state=` value naming this filter.
    fn slug(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::All => "all",
        }
    }
}

/// Whether a change request reads as "open" (an active draft) for the list/badge
/// split: `status = draft` and not withdrawn.
#[must_use]
pub fn change_is_open(status: &str, closed: bool) -> bool {
    status == "draft" && !closed
}

/// The PR-style lifecycle label (glyph + word) and CSS badge class for a change.
///
/// Color is reinforcement only — the glyph and word carry the state on their
/// own (monochrome-safe). A terminal `status` (merged/reverted) wins over the
/// orthogonal closed flag.
#[must_use]
pub fn change_badge(status: &str, closed: bool) -> (&'static str, &'static str) {
    match status {
        "applied" => ("\u{2713} Merged", "badge-merged"),
        "reverted" => ("\u{21a9} Reverted", "badge-reverted"),
        _ if closed => ("\u{2298} Closed", "badge-closed"),
        _ => ("\u{25cf} Open", "badge-open"),
    }
}

/// A single row on the change-request list page.
pub struct ChangeListRow {
    /// The change-set id (also the detail-page path suffix).
    pub change_id: String,
    /// Display heading: the proposer's title, or the auto summary as fallback.
    pub title: String,
    /// Lifecycle status: `draft` | `applied` | `reverted`.
    pub status: String,
    /// Whether an open draft has been withdrawn (`closed_at` set).
    pub closed: bool,
    /// Human label of the actor that opened it.
    pub actor_label: String,
    /// Unix time the change was opened.
    pub created_at: i64,
    /// Number of discussion comments accrued.
    pub comment_count: usize,
}

/// The change-requests list page for a registry: GitHub-style Open/Closed/All
/// tabs with counts, status badges, and a dense bordered table linking to each
/// change's detail page (RFC-0004 web change requests).
#[must_use]
pub fn changes_page(
    email: &str,
    registry: &RegistryRecord,
    rows: &[ChangeListRow],
    filter: ChangesFilter,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let open_count = rows
        .iter()
        .filter(|r| change_is_open(&r.status, r.closed))
        .count();
    let closed_count = rows.len() - open_count;

    let mut body = String::new();
    // Header line + the "open a change request" action, in the paper idiom.
    let _ = write!(
        body,
        "<div class=\"change-list-head\">\
         <p class=\"dim\">{open} open \u{b7} {closed} closed</p>\
         <a class=\"button\" href=\"/{slug}/-/settings/config\">Propose a change</a></div>\n",
        open = open_count,
        closed = closed_count,
        slug = escape(slug),
    );

    // The Open / Closed / All tab strip (server-rendered `?state=` links).
    body.push_str("<nav class=\"change-tabs\" aria-label=\"change request state\">\n");
    for (f, label, count) in [
        (ChangesFilter::Open, "Open", open_count),
        (ChangesFilter::Closed, "Closed", closed_count),
        (ChangesFilter::All, "All", rows.len()),
    ] {
        let active = if f == filter { " active" } else { "" };
        let current = if f == filter {
            " aria-current=\"page\""
        } else {
            ""
        };
        let _ = write!(
            body,
            "<a class=\"tab{active}\"{current} href=\"/{slug}/-/changes?state={state}\">{label} \
             <span class=\"dim\">{count}</span></a>\n",
            slug = escape(slug),
            state = f.slug(),
        );
    }
    body.push_str("</nav>\n");

    let shown: Vec<&ChangeListRow> = rows
        .iter()
        .filter(|r| match filter {
            ChangesFilter::Open => change_is_open(&r.status, r.closed),
            ChangesFilter::Closed => !change_is_open(&r.status, r.closed),
            ChangesFilter::All => true,
        })
        .collect();

    if shown.is_empty() {
        body.push_str("<p class=\"dim\">No change requests here.</p>\n");
    } else {
        body.push_str("<table class=\"change-table\">\n<tbody>\n");
        for r in shown {
            let (badge_label, badge_class) = change_badge(&r.status, r.closed);
            let short = &r.change_id[..r.change_id.len().min(8)];
            let comments = if r.comment_count > 0 {
                format!(" <span class=\"dim\">\u{1f4ac} {}</span>", r.comment_count)
            } else {
                String::new()
            };
            let _ = write!(
                body,
                "<tr>\
                 <td class=\"change-status\"><span class=\"badge {badge_class}\">{badge_label}</span></td>\
                 <td class=\"change-title\">\
                 <a href=\"/{slug}/-/changes/{id}\">{title}</a>{comments}<br>\
                 <span class=\"dim\">#{short} \u{b7} opened by {actor} {age}</span></td>\
                 </tr>\n",
                slug = escape(slug),
                id = escape(&r.change_id),
                title = escape(&r.title),
                short = escape(short),
                actor = escape(&r.actor_label),
                age = escape(&ago(r.created_at)),
            );
        }
        body.push_str("</tbody>\n</table>\n");
    }

    registry_settings_chrome(email, slug, "changes", &body, started)
}

/// Which panel of the change-request detail page is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    /// The description, event timeline, comment/review forms, and merge box.
    Conversation,
    /// The per-file syntax-highlighted diff.
    Diff,
    /// The recomputed validation checks.
    Checks,
}

impl DetailTab {
    /// Parses the `?view=` query value, defaulting to
    /// [`DetailTab::Conversation`].
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        match raw {
            Some("diff") => Self::Diff,
            Some("checks") => Self::Checks,
            _ => Self::Conversation,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Conversation => "conversation",
            Self::Diff => "diff",
            Self::Checks => "checks",
        }
    }
}

/// One recomputed validation check shown on the Checks panel.
pub struct CheckRow {
    /// Whether the check passed.
    pub ok: bool,
    /// Short check name (e.g. `schema valid`).
    pub label: String,
    /// Optional detail (an error message, or the observed value).
    pub note: String,
}

/// A synthesized conversation-timeline event kind.
pub enum TimelineKind {
    /// The change was opened.
    Opened,
    /// A discussion comment.
    Comment,
    /// An approving review.
    Approved,
    /// A change-requesting review.
    RequestedChanges,
    /// The draft was withdrawn (closed).
    Closed,
    /// The roster-signed commit landed and the change merged.
    Merged,
    /// A later change reverted this one.
    Reverted,
}

/// One event on the conversation timeline.
pub struct TimelineItem {
    /// What happened.
    pub kind: TimelineKind,
    /// Human label of the actor.
    pub actor: String,
    /// Unix time of the event.
    pub when: i64,
    /// Free-text body (a comment or review note); empty for lifecycle events.
    pub body: String,
}

/// Everything the change-request detail page renders.
pub struct ChangeDetailView {
    /// The change-set id.
    pub change_id: String,
    /// Display heading (proposer's title, or the auto summary).
    pub title: String,
    /// The proposer's description (may be empty).
    pub body: String,
    /// Lifecycle status: `draft` | `applied` | `reverted`.
    pub status: String,
    /// Whether the draft is withdrawn (`closed_at` set).
    pub closed: bool,
    /// Human label of the actor that opened it.
    pub actor_label: String,
    /// Unix time the change was opened.
    pub created_at: i64,
    /// The draft (or, once merged, the promoting) commit oid.
    pub git_commit: String,
    /// The tracked branch the change targets (display only).
    pub base_branch: String,
    /// Per-edited-file `(path, raw unified diff)`; highlighted at render time.
    pub file_diffs: Vec<(String, String)>,
    /// The recomputed validation checks.
    pub checks: Vec<CheckRow>,
    /// The synthesized, time-ordered event timeline.
    pub timeline: Vec<TimelineItem>,
    /// The `apr change merge` command that promotes the draft.
    pub merge_command: String,
    /// Which panel to render.
    pub view: DetailTab,
    /// Whether the viewer may comment/review (audit.read).
    pub can_review: bool,
    /// Whether the viewer may close/reopen (registry.configure).
    pub can_close: bool,
    /// The session CSRF token for the action forms.
    pub csrf: String,
}

/// The change-request detail page — a GitHub pull-request-style review surface
/// rendered in the paper idiom, no-JS-complete (RFC-0004 web change requests).
#[must_use]
pub fn change_detail_page(
    email: &str,
    registry: &RegistryRecord,
    view: &ChangeDetailView,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let short = &view.change_id[..view.change_id.len().min(8)];
    let (badge_label, badge_class) = change_badge(&view.status, view.closed);
    let short_commit = &view.git_commit[..view.git_commit.len().min(10)];

    let mut body = String::new();

    // Header: "#id  title" + status badge, then a dim submeta line.
    let _ = write!(
        body,
        "<div class=\"change-head\">\
         <h1 class=\"change-h1\"><span class=\"dim\">#{short}</span> {title} \
         <span class=\"badge {badge_class}\">{badge_label}</span></h1>\
         <p class=\"dim\">opened by {actor} {age} \u{b7} base <code>{base}</code> \
         \u{b7} commit <code>{commit}</code></p></div>\n",
        short = escape(short),
        title = escape(&view.title),
        actor = escape(&view.actor_label),
        age = escape(&ago(view.created_at)),
        base = escape(&view.base_branch),
        commit = escape(short_commit),
    );

    // Tab strip: Conversation / Diff / Checks (server-rendered `?view=` links).
    body.push_str("<nav class=\"change-tabs\" aria-label=\"change request views\">\n");
    let check_fails = view.checks.iter().filter(|c| !c.ok).count();
    for (tab, label, count) in [
        (DetailTab::Conversation, "Conversation", view.timeline.len()),
        (DetailTab::Diff, "Diff", view.file_diffs.len()),
        (DetailTab::Checks, "Checks", view.checks.len()),
    ] {
        let active = if tab == view.view { " active" } else { "" };
        let current = if tab == view.view {
            " aria-current=\"page\""
        } else {
            ""
        };
        // The Checks tab flags failures with a danger dot.
        let badge = if matches!(tab, DetailTab::Checks) && check_fails > 0 {
            format!(" <span class=\"bad\">\u{2717}{check_fails}</span>")
        } else {
            format!(" <span class=\"dim\">{count}</span>")
        };
        let _ = write!(
            body,
            "<a class=\"tab{active}\"{current} \
             href=\"/{slug}/-/changes/{id}?view={view_slug}\">{label}{badge}</a>\n",
            slug = escape(slug),
            id = escape(&view.change_id),
            view_slug = tab.slug(),
        );
    }
    body.push_str("</nav>\n");

    match view.view {
        DetailTab::Conversation => render_conversation(&mut body, slug, view),
        DetailTab::Diff => render_diff_panel(&mut body, view),
        DetailTab::Checks => render_checks_panel(&mut body, view),
    }

    registry_settings_chrome(email, slug, "changes", &body, started)
}

/// Renders the Conversation panel: description, timeline, merge box, and the
/// comment/review/close action forms (all gated by permission).
fn render_conversation(body: &mut String, slug: &str, view: &ChangeDetailView) {
    if !view.body.trim().is_empty() {
        let _ = write!(
            body,
            "<section class=\"change-body\"><p>{}</p></section>\n",
            escape(&view.body).replace('\n', "<br>"),
        );
    }

    // The event timeline.
    body.push_str("<ul class=\"timeline\">\n");
    for item in &view.timeline {
        let (glyph, verb, cls) = match item.kind {
            TimelineKind::Opened => ("\u{25cf}", "opened this change", "tl-open"),
            TimelineKind::Comment => ("\u{1f4ac}", "commented", "tl-comment"),
            TimelineKind::Approved => ("\u{2713}", "approved", "tl-approve"),
            TimelineKind::RequestedChanges => ("\u{2717}", "requested changes", "tl-reject"),
            TimelineKind::Closed => ("\u{2298}", "closed this change", "tl-closed"),
            TimelineKind::Merged => ("\u{2713}", "merged \u{2014} commit landed", "tl-merged"),
            TimelineKind::Reverted => ("\u{21a9}", "reverted this change", "tl-reverted"),
        };
        let note = if item.body.trim().is_empty() {
            String::new()
        } else {
            format!(
                "<div class=\"tl-note\">{}</div>",
                escape(&item.body).replace('\n', "<br>")
            )
        };
        // Lifecycle events (merged/closed/reverted) carry no recorded actor; the
        // verb stands alone then.
        let who = if item.actor.trim().is_empty() {
            String::new()
        } else {
            format!("<strong>{}</strong> ", escape(&item.actor))
        };
        let _ = write!(
            body,
            "<li class=\"tl-item {cls}\"><span class=\"tl-glyph\">{glyph}</span> \
             <span class=\"tl-head\">{who}{verb} \
             <span class=\"dim\">{age}</span></span>{note}</li>\n",
            age = escape(&ago(item.when)),
        );
    }
    body.push_str("</ul>\n");

    // The merge box: promotion is CLI-only, so this is the copy-paste command.
    let mergeable = view.status == "draft";
    if mergeable {
        let closed_note = if view.closed {
            "<p class=\"dim\">This change is closed. Reopen it to surface it as \
             open again; the draft ref still exists and can be promoted.</p>"
        } else {
            ""
        };
        let _ = write!(
            body,
            "<section class=\"merge-box\">\
             <p class=\"dim\">Promotion is by the CLI \u{2014} a maintainer re-signs the \
             draft with a roster key and pushes it. Status flips to <strong>Merged</strong> \
             automatically once the commit lands.</p>{closed_note}\
             <div class=\"copy-row\"><pre class=\"merge-cmd\" id=\"merge-cmd\">{cmd}</pre>\
             <button type=\"button\" class=\"button copy-btn\" data-copy-target=\"merge-cmd\" \
             hidden>copy</button></div></section>\n",
            cmd = escape(&view.merge_command),
        );
    } else if view.status == "applied" {
        body.push_str(
            "<section class=\"merge-box merged\"><p class=\"ok\">\u{2713} Merged \u{2014} the \
             roster-signed commit has landed on the tracked branch.</p></section>\n",
        );
    } else if view.status == "reverted" {
        body.push_str(
            "<section class=\"merge-box\"><p class=\"dim\">This change was reverted by a \
             later change.</p></section>\n",
        );
    }

    // The action forms (comment, review, close/reopen), gated by permission.
    if view.can_review {
        let _ = write!(
            body,
            "<form class=\"console change-action\" method=\"post\" \
             action=\"/{slug}/-/changes/{id}/comment\">{csrf}\
             <span class=\"field-label\">Comment</span>\
             <textarea name=\"body\" rows=\"3\" required \
             placeholder=\"Leave a comment\u{2026}\"></textarea>\
             <button>Comment</button></form>\n",
            slug = escape(slug),
            id = escape(&view.change_id),
            csrf = csrf_field(&view.csrf),
        );
        // Reviews are advisory in a CLI-promotion model; say so plainly.
        let _ = write!(
            body,
            "<form class=\"console change-action\" method=\"post\" \
             action=\"/{slug}/-/changes/{id}/review\">{csrf}\
             <span class=\"field-label\">Review <span class=\"dim\">(advisory \u{2014} \
             promotion is via the CLI)</span></span>\
             <label class=\"inline\"><input type=\"radio\" name=\"verdict\" value=\"approve\" \
             checked> approve</label>\
             <label class=\"inline\"><input type=\"radio\" name=\"verdict\" \
             value=\"request_changes\"> request changes</label>\
             <textarea name=\"body\" rows=\"2\" placeholder=\"Optional note\u{2026}\"></textarea>\
             <button>Submit review</button></form>\n",
            slug = escape(slug),
            id = escape(&view.change_id),
            csrf = csrf_field(&view.csrf),
        );
    }
    if view.can_close && view.status == "draft" {
        let (action, label) = if view.closed {
            ("reopen", "Reopen change")
        } else {
            ("close", "Close change")
        };
        let _ = write!(
            body,
            "<form class=\"console change-action\" method=\"post\" \
             action=\"/{slug}/-/changes/{id}/{action}\">{csrf}\
             <button class=\"button-quiet\">{label}</button></form>\n",
            slug = escape(slug),
            id = escape(&view.change_id),
            csrf = csrf_field(&view.csrf),
        );
    }
}

/// Renders the Diff panel: each edited file's TOML-aware highlighted diff.
fn render_diff_panel(body: &mut String, view: &ChangeDetailView) {
    if view.file_diffs.is_empty() {
        body.push_str("<p class=\"dim\">No file changes.</p>\n");
        return;
    }
    for (path, diff) in &view.file_diffs {
        let _ = write!(
            body,
            "<h3 class=\"diff-file\">{}</h3>\n{}\n",
            escape(path),
            crate::web::toml_highlight::render_toml_diff(diff),
        );
    }
}

/// Renders the Checks panel: recomputed validation plus the honest
/// draft-signature note (never claimed as roster-verified).
fn render_checks_panel(body: &mut String, view: &ChangeDetailView) {
    body.push_str("<ul class=\"checks\">\n");
    for check in &view.checks {
        let (glyph, cls) = if check.ok {
            ("\u{2713}", "ok")
        } else {
            ("\u{2717}", "bad")
        };
        let note = if check.note.is_empty() {
            String::new()
        } else {
            format!(" <span class=\"dim\">{}</span>", escape(&check.note))
        };
        let _ = write!(
            body,
            "<li><span class=\"{cls}\">{glyph}</span> {label}{note}</li>\n",
            label = escape(&check.label),
        );
    }
    body.push_str("</ul>\n");
    let short_commit = &view.git_commit[..view.git_commit.len().min(10)];
    let _ = write!(
        body,
        "<p class=\"dim\">Draft commit <code>{}</code> is signed by the hub's \
         <strong>draft</strong> key, which is not in the roster \u{2014} it is not \
         consumption-trusted. A roster signature is applied when a maintainer runs \
         <code>apr change merge</code>.</p>\n",
        escape(short_commit),
    );
}

/// Breadcrumbs for a per-registry console page: the registry home plus the
/// current page is appended by the caller's title.
fn registry_crumbs(slug: &str) -> Vec<(String, String)> {
    vec![
        // Link "registries" to the instance home, matching the browse pages.
        ("/".to_string(), "registries".to_string()),
        (format!("/{slug}/"), slug.to_string()),
    ]
}

#[cfg(test)]
mod cache_render_tests {
    use super::*;

    #[test]
    fn scoped_settings_navigation_is_grouped_overview_first_and_single_current() {
        let navigations = [
            settings_layout(&org_settings_navigation("acme", "overview"), ""),
            settings_layout(&registry_settings_navigation("acme/main", "overview"), ""),
            settings_layout(&cache_settings_navigation("acme", "build", "overview"), ""),
        ];
        for html in navigations {
            assert_eq!(html.matches("aria-current=\"page\"").count(), 1);
            assert!(html.find(">Overview</a>").unwrap() < html.find("settings-nav-label").unwrap());
            assert!(html.contains("class=\"settings-nav-group\""));
        }
        assert!(navigations_unavailable_active_falls_back_to_overview());
    }

    #[test]
    fn settings_navigation_supplies_one_contextual_h1_for_every_section() {
        let cases = [
            (
                settings_layout(&org_settings_navigation("acme", "storage"), "<p>body</p>"),
                "<h1>Storage · acme</h1>",
            ),
            (
                settings_layout(
                    &registry_settings_navigation("acme/main", "serving"),
                    "<p>body</p>",
                ),
                "<h1>Serving · acme/main</h1>",
            ),
            (
                settings_layout(
                    &cache_settings_navigation("acme", "build", "pins"),
                    "<p>body</p>",
                ),
                "<h1>GC &amp; retention · build</h1>",
            ),
        ];
        for (html, heading) in cases {
            assert!(html.contains(heading), "missing {heading}");
            assert_eq!(html.matches("<h1").count(), 1);
        }

        let existing = settings_layout(
            &registry_settings_navigation("acme/main", "overview"),
            "<h1>Registry · acme/main</h1>",
        );
        assert_eq!(existing.matches("<h1").count(), 1);
    }

    fn navigations_unavailable_active_falls_back_to_overview() -> bool {
        let html = settings_layout(&cache_settings_navigation("acme", "build", "missing"), "");
        html.matches("aria-current=\"page\"").count() == 1
            && html.contains(
                "href=\"/-/org/acme/caches/build\" class=\"active\" aria-current=\"page\"",
            )
    }

    fn cache() -> Cache {
        Cache {
            id: 1,
            org_id: Some(1),
            slug: "build".into(),
            name: "Build cache".into(),
            storage_binding_id: Some(1),
            prefix: String::new(),
            hosted_key_id: Some(7),
            visibility: "public".into(),
            priority: 40,
            compression: "zstd".into(),
            want_mass_query: true,
            created_at: 1_700_000_000,
            deleted_at: None,
            purge_after: None,
        }
    }

    fn usage() -> CacheUsage {
        CacheUsage {
            used_bytes: 2 * 1024 * 1024,
            object_count: 3,
            updated_at: 0,
        }
    }

    #[test]
    fn admin_sees_every_control() {
        let pins = [CachePinRow {
            store_hash: "abcdefghijklmnopqrstuvwxyz012345".into(),
            store_name: "abcdefghijklmnopqrstuvwxyz012345-hello-2.12".into(),
            closure_size: 3 * 1024 * 1024,
            closure_count: 4,
            present: true,
            expires_at: None,
            created_at: 1_700_000_000,
        }];
        let gc_runs = [crate::db::CacheGcRun {
            id: 1,
            cache_id: 1,
            started_at: 1_700_000_500,
            finished_at: Some(1_700_000_600),
            status: "ok".into(),
            error: None,
            scanned: 20,
            retained: 15,
            deleted_objects: 5,
            freed_bytes: 1024 * 1024,
        }];
        let placements = [PlacementOverviewRow {
            name: "primary".into(),
            binding_name: "primary".into(),
            prefix: "caches/build".into(),
            role: "primary".into(),
            state: "ready".into(),
            read_enabled: true,
            write_enabled: true,
        }];
        let render = |active: &str| {
            cache_page(
                "a@b.com",
                "acme",
                "csrf-tok",
                &cache(),
                "primary",
                &placements,
                &["cold".to_string()],
                &usage(),
                &[],
                &[("cdn".to_string(), "public".to_string())],
                &pins,
                &gc_runs,
                true,
                true,
                active,
                None,
                Instant::now(),
            )
        };

        // Every section renders inside the cache settings chrome. Overview is
        // the first destination and the only current item on the default page.
        let overview = render("overview");
        assert!(overview.contains("class=\"settings-nav\""));
        assert!(overview.contains("Registry relationships"));
        assert!(overview.contains("Danger zone"));
        assert!(overview.contains("caches"));
        assert!(overview.contains("Cache · build"));
        assert!(overview.contains("2.0 MiB"));
        assert!(overview.contains("<span class=\"chip\">signed</span>"));
        assert!(overview.contains("Physical placements"));
        assert!(overview.contains("caches/build"));
        assert!(overview.contains("<span class=\"ok\">write</span>"));
        assert!(!overview.contains("<button>save</button>"));
        assert_eq!(overview.matches("aria-current=\"page\"").count(), 1);
        assert!(overview.find(">Overview</a>").unwrap() < overview.find(">General</a>").unwrap());

        // General owns mutable cache policy and no longer overloads Overview.
        let general = render("general");
        assert!(general.contains("<h1>General · build</h1>"));
        assert!(general.contains("<h2>Cache policy</h2>"));
        assert!(general.contains("<button>save</button>"));
        assert!(general.contains("action=\"/-/org/acme/caches/build/general\""));
        assert!(general.contains("csrf-tok"));
        assert_eq!(general.matches("aria-current=\"page\"").count(), 1);
        assert!(general.contains("Storage"));
        assert!(general.contains("Serving"));
        assert!(!general.contains("Change storage"));
        assert!(!general.contains("Bucket-direct serving"));

        // The base cache route is a read-only overview; its content never owns
        // a mutation form or points a form action back at the base route.
        assert!(!overview.contains("<form"));
        assert!(!overview.contains("action=\"/-/org/acme/caches/build\""));

        // Storage tab: the binding + change-storage form.
        let storage = render("storage");
        assert!(storage.contains("Change storage"));
        assert!(storage.contains("action=\"/-/org/acme/caches/build/storage\""));

        // Serving tab: the bucket-direct frontend control.
        let serving = render("serving");
        assert!(serving.contains("Bucket-direct serving"));
        assert!(serving.contains("/-/org/acme/caches/build/advertise-frontend"));

        // Links tab: the link form (the `\"` guards against matching the
        // sidebar's `/links` tab href).
        let links = render("links");
        assert!(links.contains("action=\"/-/org/acme/caches/build/link\""));

        // GC & pins tab: the GC controls + the redesigned 4-column pins table
        // (a plain `<table class="pins">` with the hash on a sub-line — never the
        // 4-column `.linktable` grid that crushed the columns).
        let pins_tab = render("pins");
        assert!(pins_tab.contains("/-/org/acme/caches/build/gc"));
        assert!(pins_tab.contains("Pins (manual GC roots)"));
        assert!(pins_tab.contains("/-/org/acme/caches/build/pin/add"));
        assert!(pins_tab.contains("/-/org/acme/caches/build/pin/remove"));
        // The package name is shown without its hash prefix (the hash lives once,
        // on the sub-line) — no duplicated "<hash>-<name>" / "<hash>…" pair.
        assert!(pins_tab.contains("<div>hello-2.12</div>"));
        assert!(!pins_tab.contains("012345-hello-2.12"));
        assert!(pins_tab.contains("3.0 MiB · 4 objects"));
        assert!(pins_tab.contains("no expiry"));
        // The expiry is editable in place (the per-row form re-submits to pin/add).
        assert!(pins_tab.contains("name=\"expires_days\""));
        assert!(pins_tab.contains("<table class=\"pins\">"));
        assert!(pins_tab.contains("class=\"subline\""));
        assert!(!pins_tab.contains("class=\"linktable\""));
        // GC run history (newest first) with the outcome + reclaimed bytes.
        assert!(pins_tab.contains("Recent runs"));
        assert!(pins_tab.contains("5 deleted · 15 retained · 20 scanned"));
        assert!(pins_tab.contains("1.0 MiB"));
        // The removed "Re-adding an existing hash renews…" line is gone.
        assert!(!pins_tab.contains("Re-adding an existing hash"));

        // Danger tab: the delete form, styled like the registry/org remove pages.
        let danger = render("danger");
        assert!(danger.contains("<h2 class=\"danger\">Delete cache</h2>"));
        assert!(danger.contains("/-/org/acme/caches/build/delete"));
        assert!(danger.contains("class=\"warn\""));
    }

    #[test]
    fn member_sees_no_mutating_forms() {
        let render = |active: &str| {
            cache_page(
                "a@b.com",
                "acme",
                "csrf-tok",
                &cache(),
                "primary",
                &[],
                &["cold".to_string()],
                &usage(),
                &[],
                &[("cdn".to_string(), "public".to_string())],
                &[],
                &[],
                false,
                true,
                active,
                None,
                Instant::now(),
            )
        };
        // Overview remains useful to a plain member; General exposes no form.
        let overview = render("overview");
        assert!(overview.contains("Cache · build"));
        let general = render("general");
        assert!(!general.contains("<h2>Settings</h2>"));
        assert!(general.contains("requires cache administration"));
        // The privileged tabs show an admins-only notice, not the controls.
        let pins = render("pins");
        assert!(!pins.contains("/caches/build/pin/"));
        assert!(!pins.contains("Pins (manual GC roots)"));
        assert!(pins.contains("available to cache admins"));
        assert!(!render("danger").contains("/caches/build/delete"));
        assert!(!render("links").contains("action=\"/-/org/acme/caches/build/link\""));
    }

    #[test]
    fn gc_notice_is_surfaced() {
        // A GC run returns to the Pins tab with its notice.
        let html = cache_page(
            "a@b.com",
            "acme",
            "csrf-tok",
            &cache(),
            "primary",
            &[],
            &["cold".to_string()],
            &usage(),
            &[],
            &[],
            &[],
            &[],
            true,
            true,
            "pins",
            Some("Collected 5 objects, reclaimed 1.0 MiB (3 retained)."),
            Instant::now(),
        );
        assert!(html.contains("Collected 5 objects"));
        // With no pins, the editor shows its empty-state hint.
        assert!(html.contains("No manual pins"));
    }

    fn settings_registry() -> RegistryRecord {
        RegistryRecord {
            id: 1,
            slug: "demo".into(),
            source_url: String::new(),
            trust_keys: vec![],
            require_signatures: true,
            org_id: Some(1),
            project_path: String::new(),
            visibility: "public".into(),
            storage_binding_id: None,
            prefix: String::new(),
            hosted_key_id: None,
            crawl_policy: "allow_all".into(),
            llms_txt_body: None,
        }
    }

    #[test]
    fn registry_overview_is_read_only_and_general_owns_policy_forms() {
        let render = |active: &str| {
            registry_settings_page(
                "a@b.com",
                &settings_registry(),
                "acme",
                "csrf-tok",
                None,
                &[],
                &[],
                &[],
                &[],
                &[],
                false,
                false,
                None,
                active,
                Instant::now(),
            )
        };
        let overview = render("overview");
        assert!(overview.contains("Registry · demo"));
        assert!(overview.contains("Storage placement"));
        assert!(!overview.contains("change visibility"));
        assert_eq!(overview.matches("aria-current=\"page\"").count(), 1);

        let general = render("general");
        assert!(general.contains("<h1>General · demo</h1>"));
        assert!(general.contains("change visibility"));
        assert!(general.contains("change crawl policy"));
        assert!(!general.contains("Storage placement"));
        assert_eq!(general.matches("aria-current=\"page\"").count(), 1);

        let storage = render("storage");
        assert!(storage.contains("<h1>Storage · demo</h1>"));
        assert!(!storage.contains("advertise an inherited storage frontend"));
    }

    #[test]
    fn registry_storage_direct_control_lives_under_serving() {
        let html = serving_page(
            "a@b.com",
            &settings_registry(),
            "csrf-tok",
            &[],
            &[],
            "default storage",
            "/-/instance/storage",
            true,
            None,
            None,
            Instant::now(),
        );
        assert!(html.contains("Storage-direct serving"));
        assert!(html.contains("advertise an inherited storage frontend"));
        assert!(html.contains("name=\"advertise\" value=\"1\" checked"));
        assert_eq!(html.matches("aria-current=\"page\"").count(), 1);
    }

    fn org() -> OrgRecord {
        OrgRecord {
            id: 1,
            slug: "acme".into(),
            name: "Acme Systems".into(),
            created_at: 1_700_000_000,
        }
    }

    fn storage_bindings() -> Vec<StorageBindingRecord> {
        vec![
            StorageBindingRecord {
                id: 10,
                org_id: Some(1),
                name: "local-primary".into(),
                kind: "local_fs".into(),
                root: "/srv/private/acme".into(),
                access: "private".into(),
                endpoint: None,
                credential_ref: None,
                is_instance_default: false,
                created_at: 1_700_000_000,
            },
            StorageBindingRecord {
                id: 11,
                org_id: Some(1),
                name: "object-replica".into(),
                kind: "s3".into(),
                root: "private-bucket/tenant-prefix".into(),
                access: "private".into(),
                endpoint: Some("https://origin.internal.example".into()),
                credential_ref: Some("sealed:never-render".into()),
                is_instance_default: false,
                created_at: 1_700_000_000,
            },
        ]
    }

    fn render_org_storage(can_configure: bool, can_manage_storage: bool) -> String {
        org_dashboard(
            "viewer@acme.example",
            &org(),
            "csrf-tok",
            &[],
            &[],
            &[],
            &storage_bindings(),
            &[],
            false,
            false,
            can_configure,
            can_manage_storage,
            false,
            1,
            1,
            1,
            "storage",
            Instant::now(),
        )
    }

    #[test]
    fn org_storage_redacts_locations_without_storage_manage() {
        // Deliberately grant registry configuration but not storage management:
        // the two permissions must not be conflated by the renderer.
        let redacted = render_org_storage(true, false);
        assert!(redacted.contains("<h1>Storage · acme</h1>"));
        assert!(redacted.contains("location hidden · storage management required"));
        for secret_location in [
            "/srv/private/acme",
            "https://origin.internal.example",
            "private-bucket/tenant-prefix",
            "sealed:never-render",
        ] {
            assert!(
                !redacted.contains(secret_location),
                "leaked {secret_location}"
            );
        }
        assert!(!redacted.contains("/-/org/acme/bindings/10"));
        assert!(!redacted.contains("action=\"/-/org/acme/bindings\""));
        assert!(!redacted.contains("action=\"/-/org/acme/bindings/delete\""));

        let privileged = render_org_storage(false, true);
        assert!(privileged.contains("/srv/private/acme"));
        assert!(privileged.contains("https://origin.internal.example/private-bucket/tenant-prefix"));
        assert!(privileged.contains("/-/org/acme/bindings/10"));
        assert!(privileged.contains("action=\"/-/org/acme/bindings\""));
        assert!(!privileged.contains("sealed:never-render"));
    }

    #[test]
    fn settings_route_matrix_uses_section_destinations() {
        let cache_nav =
            settings_layout(&cache_settings_navigation("acme", "build", "overview"), "");
        for route in [
            "/-/org/acme/caches/build",
            "/-/org/acme/caches/build/general",
            "/-/org/acme/caches/build/storage",
            "/-/org/acme/caches/build/serving",
            "/-/org/acme/caches/build/links",
            "/-/org/acme/caches/build/pins",
            "/-/org/acme/caches/build/danger",
        ] {
            assert!(cache_nav.contains(&format!("href=\"{route}\"")), "{route}");
        }

        let registry_nav =
            settings_layout(&registry_settings_navigation("acme/main", "overview"), "");
        for route in [
            "/acme/main/-/settings",
            "/acme/main/-/settings/general",
            "/acme/main/-/settings/storage",
            "/acme/main/-/settings/serving",
            "/acme/main/-/settings/caches",
            "/acme/main/-/settings/danger",
        ] {
            assert!(
                registry_nav.contains(&format!("href=\"{route}\"")),
                "{route}"
            );
        }
    }

    #[test]
    fn caches_tab_reconciles_config_against_links() {
        let caches = [
            RegistryCacheRow {
                cache_slug: "served".into(),
                consumer_url: "https://served.example.com".into(),
                roots_packages: true,
                config_priority: Some(100),
            },
            RegistryCacheRow {
                cache_slug: "orphan".into(),
                consumer_url: "https://orphan.example.com".into(),
                roots_packages: false,
                config_priority: None,
            },
        ];
        let external = [("https://thirdparty.example.com".to_string(), 50u32)];
        let html = registry_settings_page(
            "a@b.com",
            &settings_registry(),
            "acme",
            "csrf-tok",
            None,
            &[],
            &[],
            &caches,
            &external,
            &[("free".to_string(), "public".to_string())],
            false,
            true,
            None,
            "caches",
            Instant::now(),
        );
        // The three reconciliation groups, with their wording.
        assert!(html.contains("Served from config"));
        assert!(html.contains("https://served.example.com"));
        assert!(html.contains("Linked but not advertised"));
        assert!(html.contains("add to config"));
        assert!(html.contains("https://orphan.example.com"));
        assert!(html.contains("In config, external"));
        assert!(html.contains("https://thirdparty.example.com"));
        // Registry-level advertisement note and the config deep-link.
        assert!(html.contains("serves the whole registry"));
        assert!(html.contains("href=\"config\""));
        // The inert advertise toggle is gone from the link controls.
        assert!(!html.contains("name=\"advertised\""));
        assert!(!html.contains("advertise to consumers"));
        // The operational "Link a cache" control still renders.
        assert!(html.contains("/demo/-/settings/cache-link"));
        assert!(html.contains("roots_packages"));
    }

    #[test]
    fn config_form_autofill_marks_present_and_missing() {
        use crate::web::config_form::{CacheRow, ConfigFormModel};
        let model = ConfigFormModel {
            name: "demo".into(),
            content_addressed: true,
            caches: vec![CacheRow {
                url: "https://served.example.com".into(),
                priority: 100,
            }],
            ..ConfigFormModel::default()
        };
        let linked = [
            LinkedCacheSuggestion {
                cache_slug: "served".into(),
                consumer_url: "https://served.example.com".into(),
                present: true,
            },
            LinkedCacheSuggestion {
                cache_slug: "missing".into(),
                consumer_url: "https://missing.example.com".into(),
                present: false,
            },
        ];
        let html = registry_config_form_page(
            "a@b.com",
            &settings_registry(),
            "csrf-tok",
            &model,
            true,
            &linked,
            None,
            Instant::now(),
        );
        // The autofill panel lists both linked caches.
        assert!(html.contains("Linked caches"));
        assert!(html.contains("https://served.example.com"));
        assert!(html.contains("https://missing.example.com"));
        // Present one shows "in config"; missing one offers a one-click add.
        assert!(html.contains("in config"));
        assert!(html.contains("data-add-cache-url=\"https://missing.example.com\""));
        // The existing cache row is rendered in the editor.
        assert!(html.contains("value=\"https://served.example.com\""));
    }

    #[test]
    fn config_form_autofill_hidden_for_advanced_stack() {
        use crate::web::config_form::ConfigFormModel;
        let model = ConfigFormModel {
            name: "demo".into(),
            content_addressed: true,
            has_cache_stack: true,
            ..ConfigFormModel::default()
        };
        let linked = [LinkedCacheSuggestion {
            cache_slug: "c".into(),
            consumer_url: "https://c.example.com".into(),
            present: false,
        }];
        let html = registry_config_form_page(
            "a@b.com",
            &settings_registry(),
            "csrf-tok",
            &model,
            true,
            &linked,
            None,
            Instant::now(),
        );
        // The list editor is inactive for an advanced stack, so no autofill.
        assert!(!html.contains("Linked caches"));
        assert!(html.contains("advanced"));
    }
}
