//! Transport-neutral HTML rendering for browser authentication and account security.
//!
//! The retained ceremony pages and their shared chrome are pure string-building
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
//!   [`Pager`], [`csrf_field`], [`brand`], [`ago`], and [`urlencode`] — is the
//!   shared layout for retained identity pages.
//! - Login, account, invitation, and device-approval builders each return a
//!   complete document.
//!
//! The pure primitives ([`escape`], [`table`],
//! [`human_size`](crate::web::render::human_size), [`key_fingerprint`]) live in
//! [`crate::web::render`] and are re-used here so the console and the shared
//! browse surface render byte-identically.

use crate::clock::Instant;
use std::fmt::Write as _;
use std::sync::{OnceLock, RwLock};

use crate::db::{ChannelSummary, WebauthnCredentialRecord};
use crate::domain::Permission;
use crate::web::render::{escape, table as render_table};

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

/// The editable, database-backed site chrome overlaid on the deploy brand: the
/// site title (overrides [`brand`] in the masthead), the global announcement
/// banner, and the footer legal/contact links.
///
/// Unlike [`BRAND`] (a write-once deploy default), this is a mutable cell so an
/// instance admin's edit takes effect immediately for the serving process. Each
/// shell seeds it from `instance_config` at startup (native) or isolate init
/// (Worker); a save updates both the system-of-record database and this cell.
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
/// Passed to [`page_with_session`] so every authenticated identity page shows
/// who is signed in (RFC-0004's masthead "[log in]" affordance).
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

/// Renders a non-mutating logout confirmation with a CSRF-protected POST.
#[must_use]
pub fn logout_page(email: &str, csrf: &str, started: Instant) -> String {
    let body = format!(
        "<h1>Log out</h1>\n<p>End the current Hub session?</p>\n<form class=\"console\" method=\"post\" action=\"/logout\">{}<button>log out</button></form>\n",
        csrf_field(csrf),
    );
    page_with_session(
        "log out",
        &[(String::new(), "log out".to_string())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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
         <a class=\"skip-link\" href=\"#main-content\">Skip to content</a>\
         <header class=\"masthead\">{brand_span}\
         <span class=\"crumbs\">{crumb_html}</span>{session}</header>\n\
         {announcement}\
         <main id=\"main-content\">\n{body}\n</main>\n\
         <footer class=\"statline\">{statline}{footer_links}</footer>\n</body>\n</html>\n",
        session = session.render(),
        ver = crate::web::assets::asset_version(),
    )
}

// -- table variants + small primitives -------------------------------------

/// Renders a semantic table in a keyboard-accessible horizontal scroll region.
///
/// Cell content, font metrics, zoom, translations, and viewport size determine
/// whether a table actually overflows; column count does not. Every wrapper is
/// therefore a named focus target so keyboard users can scroll it whenever the
/// CSS `overflow-x: auto` region becomes scrollable, without JavaScript.
fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let subject = headers.first().copied().unwrap_or("Data");
    let label = format!("{subject} table");
    let table = render_table(headers, rows)
        .replacen(
            "<table>",
            &format!(
                "<table><caption class=\"visually-hidden\">{}</caption>",
                escape(&label)
            ),
            1,
        )
        .replace("<th>", "<th scope=\"col\">");
    format!(
        "<div class=\"table-scroll\" role=\"region\" aria-label=\"{}\" tabindex=\"0\">{table}</div>",
        escape(&format!("Scrollable {label}")),
    )
}

/// Render a table whose header cells are pre-rendered HTML.
///
/// Identical to [`table`] but each header is inserted into its `<th>` as-is
/// (not escaped), so callers can embed sort links or other markup; body cells
/// follow the same as-is contract as [`table`].
#[must_use]
pub fn table_raw_headers(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut out = String::from(
        "<div class=\"table-scroll\" role=\"region\" aria-label=\"Scrollable sortable data table\" tabindex=\"0\"><table>\n<caption class=\"visually-hidden\">Sortable data table</caption><thead><tr>",
    );
    for header in headers {
        let _ = write!(out, "<th scope=\"col\">{header}</th>");
    }
    out.push_str("</tr></thead>\n<tbody>\n");
    for row in rows {
        out.push_str("<tr>");
        for cell in row {
            let _ = write!(out, "<td>{cell}</td>");
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody>\n</table></div>\n");
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
/// email forms (a plain reload restores the passkey button). `next` is a
/// handler-validated same-origin path carried by every sign-in method.
#[must_use]
pub fn login_page(
    error: Option<&str>,
    passkey_nonce: Option<&str>,
    next: Option<&str>,
    started: Instant,
) -> String {
    let mut body = String::from("<h1>Log in</h1>\n");
    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }
    // Email + password sign-in.
    let next_field = next.map_or_else(String::new, |path| {
        format!(
            "<input type=\"hidden\" name=\"next\" value=\"{}\">\n",
            escape(path)
        )
    });
    let _ = write!(
        body,
        "<p class=\"dim\">Sign in with your email and password.</p>\n\
         <form class=\"console\" method=\"post\" action=\"/login/password\">\n\
         {next_field}\
         <label>email <input type=\"email\" name=\"email\" required \
         placeholder=\"you@example.com\"></label>\n\
         <label>password <input type=\"password\" name=\"password\" required \
         autocomplete=\"current-password\"></label>\n\
         <button>sign in with password</button>\n</form>\n",
    );
    // One-time email-link sign-in (no password required).
    let _ = write!(
        body,
        "<p class=\"dim\">Or have us email you a one-time sign-in link instead.</p>\n\
         <form class=\"console\" method=\"post\" action=\"/login\">\n\
         {next_field}\
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
        let _ = write!(body, "{}", passkey_login_script(nonce, next));
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
pub fn login_sso_page(
    email: &str,
    org_slug: &str,
    start_url: &str,
    next: Option<&str>,
    started: Instant,
) -> String {
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
         {}\
         <button>sign in with SSO</button>\n</form>",
        escape(org_slug),
        next.map_or_else(String::new, |path| format!(
            "<input type=\"hidden\" name=\"next\" value=\"{}\">",
            escape(path)
        )),
    );
    let login_fallback = next.map_or_else(
        || "/login".to_string(),
        |path| {
            let encoded: String = url::form_urlencoded::byte_serialize(path.as_bytes()).collect();
            format!("/login?next={encoded}")
        },
    );
    let _ = writeln!(
        body,
        "<p class=\"dim\">Or <a href=\"{}\">use a one-time email link</a> \
         instead. (<a href=\"{}\">direct SSO link</a>)</p>",
        escape(&login_fallback),
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
fn passkey_login_script(nonce: &str, next: Option<&str>) -> String {
    let target = serde_json::to_string(next.unwrap_or("/"))
        .unwrap_or_else(|_| "\"/\"".into())
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    format!(
        "<script nonce=\"{nonce}\">\nconst aosLoginNext={target};\n{}\n</script>\n",
        PASSKEY_LOGIN_FLOW,
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
    if(r.ok){window.location=aosLoginNext;return;}
    var j=null;try{j=await r.json();}catch(e){}
    if(j&&j.redirect){var sep=j.redirect.indexOf('?')<0?'?':'&';window.location=j.redirect+sep+'next='+encodeURIComponent(aosLoginNext);return;}
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

/// Renders the authenticated invitation-acceptance ceremony.
#[must_use]
pub fn invitation_acceptance_page(
    email: &str,
    org_slug: &str,
    csrf: &str,
    started: Instant,
) -> String {
    let body = format!(
        "<h1>Accept invitation</h1>\n\
         <p>You are signed in as <code>{email}</code>. Accepting joins organization <code>{org}</code> with the exact role and scope recorded by the invitation.</p>\n\
         <form class=\"console\" method=\"post\" action=\"/-/org/{org}/invitations/accept\">\n{csrf}\
         <button>accept invitation</button>\n</form>\n\
         <p class=\"dim\">The invitation works only for this account's exact email address and can be used once.</p>\n",
        email = escape(email),
        org = escape(org_slug),
        csrf = csrf_field(csrf),
    );
    page_with_session(
        "accept invitation",
        &[(String::new(), "accept invitation".into())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}
