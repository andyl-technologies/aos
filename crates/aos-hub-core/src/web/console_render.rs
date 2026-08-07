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
    AuditRow, BinaryCache, CacheUsage, ChangesetRow, ChannelSummary, ConsumerScopeGrantRecord,
    IdpConfigRecord, IndexStatus, MirrorSource, OrgDomainRecord, OrgRecord, ProjectRecord,
    RegistryRecord, ReleaseRow, SignupPolicy, StorageBindingCredentialRevisionRecord,
    StorageBindingReadDetail, StorageBindingReadSummary, StorageBindingRecord,
    StorageBindingWriteObservationRecord, StorageBindingWriteRevisionRecord,
    WebauthnCredentialRecord, WebhookRecord,
};
use crate::domain::{iam, Permission, Role, Scope};
use crate::web::console::ia::{
    BindingPage, CachePage, NavigationPermissions, OrgPage, PageSpec, RegistryPage, BINDING_PAGES,
    CACHE_PAGES, ORG_PAGES, REGISTRY_PAGES,
};
use crate::web::help;
use crate::web::render::{escape, human_size, key_fingerprint, table as render_table};

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
        body.push_str("<p><a href=\"/-/orgs/new\">+ create an organization</a></p>\n");
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

/// The "create an organization" form (`/-/orgs/new`).
///
/// A CSRF-protected `POST /-/orgs/new` form taking a slug and a display name. The
/// page is only reached by a caller the signup policy permits (the handler
/// gates `GET`/`POST` identically); `error` renders an inline rejection (a bad
/// slug, a taken slug, or a policy denial re-rendered as a message).
#[must_use]
pub fn new_org_page(email: &str, csrf: &str, error: Option<&str>, started: Instant) -> String {
    let mut body = String::from("<h1>Create an organization</h1>\n");
    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }
    body.push_str("<form class=\"console\" method=\"post\" action=\"/-/orgs/new\">\n");
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
    /// Whether the cache requires `.narinfo` verification by a selected key.
    pub signed: bool,
    /// `nix-cache-info` priority (lower = preferred substituter).
    pub priority: i64,
    /// Sum of object sizes in bytes.
    pub used_bytes: i64,
    /// Number of indexed objects.
    pub object_count: i64,
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
    /// Operator-requested lifecycle state.
    pub desired_state: String,
    /// Inventory completeness (`complete`, `partial`, or `unknown`).
    pub completeness: String,
    /// Whether reads may select this placement.
    pub read_enabled: bool,
    /// Operator-requested read-selection switch.
    pub desired_read_enabled: bool,
    /// Operator-requested read ordering value.
    pub read_order: i64,
    /// Whether writes may select this placement.
    pub write_enabled: bool,
    /// Whether the desired authority points at this placement.
    pub desired_authority: bool,
    /// Whether reconciliation currently confirms this placement as authority.
    pub observed_authority: bool,
    /// Requested write-authority generation.
    pub desired_generation: Option<i64>,
    /// Reconciled write-authority generation.
    pub observed_generation: Option<i64>,
    /// Reconciliation state of the surface write authority.
    pub authority_state: Option<String>,
    /// Optimistic resource version used when planning a mutation.
    pub resource_version: i64,
}

/// One stable placement policy and the state of its revision stream.
pub struct PlacementPolicyOverviewRow {
    /// Stable policy identity.
    pub id: String,
    /// Surface-local display name.
    pub name: String,
    /// Kind of the newest revision, or `unconfigured` before the first revision.
    pub kind: String,
    /// Current published revision number.
    pub current_revision: Option<i64>,
    /// Number of immutable revisions, including revisions still being built.
    pub revision_count: usize,
    /// State of the newest revision.
    pub latest_state: Option<String>,
    /// Digest of the current published revision.
    pub current_digest: Option<String>,
    /// Optimistic resource version of the stable policy head.
    pub resource_version: i64,
}

/// One operator-confirmed equivalence between exact placements.
pub struct PlacementEquivalenceOverviewRow {
    /// Stable equivalence identity.
    pub id: String,
    /// First stable placement name.
    pub placement_a: String,
    /// Second stable placement name.
    pub placement_b: String,
    /// Digest of the evidence reviewed at confirmation time.
    pub evidence_digest: String,
    /// Lifecycle state.
    pub state: String,
    /// Optimistic resource version.
    pub resource_version: i64,
}

/// One normalized delivery route rendered for either surface kind.
pub struct DeliveryRouteOverviewRow {
    /// Stable route id.
    pub id: String,
    /// Rendered client URL.
    pub url: String,
    /// Delivery mode.
    pub mode: String,
    /// Capability labels in protocol order.
    pub capabilities: Vec<&'static str>,
    /// Reconciliation/readiness state.
    pub readiness: String,
    /// Whether request matching may select the route.
    pub enabled: bool,
    /// Canonical audiences selecting this route, in protocol order.
    pub canonical_audiences: Vec<String>,
}

/// One registry retention subscription owned by a cache.
pub struct RetentionSubscriptionOverviewRow {
    /// Stable subscription id.
    pub id: i64,
    /// Registry slug supplying roots.
    pub registry: String,
    /// Refresh lifecycle.
    pub state: String,
    /// Serialized typed selector displayed for auditability.
    pub selector: String,
    /// Last successfully materialized registry revision.
    pub revision: Option<String>,
}

/// One operator-created cache root and its current lease head.
pub struct ManualRetentionRootOverviewRow {
    /// Stable root id.
    pub id: String,
    /// Root Nix store hash.
    pub store_hash: String,
    /// `indefinite` or `leased`.
    pub protection_kind: String,
    /// Human reason supplied at creation.
    pub reason: String,
    /// Current lease id for a leased root.
    pub lease_id: Option<String>,
    /// Current lease lifecycle state.
    pub lease_state: Option<String>,
    /// Exclusive current lease expiry.
    pub lease_expires_at: Option<i64>,
    /// Logical deletion time.
    pub deleted_at: Option<i64>,
    /// Root optimistic resource version.
    pub resource_version: i64,
}

/// One registry-driven population target owned by a cache.
pub struct PopulationTargetOverviewRow {
    /// Stable target id.
    pub id: i64,
    /// Registry slug supplying artifacts.
    pub registry: String,
    /// Population trigger kind.
    pub trigger: String,
    /// Whether publish must wait for this target.
    pub required: bool,
    /// Whether new work may be enqueued.
    pub enabled: bool,
}

/// Renders the shared registry/cache route inventory.
fn delivery_route_inventory(rows: &[DeliveryRouteOverviewRow]) -> String {
    let mut body = String::new();
    if rows.is_empty() {
        body.push_str("<p class=\"dim\">No delivery routes. Add a route to make this surface reachable.</p>\n");
    } else {
        let table_rows: Vec<Vec<String>> = rows
            .iter()
            .map(|row| {
                vec![
                    format!(
                        "<code>{}</code>{}",
                        escape(&row.url),
                        if row.canonical_audiences.is_empty() {
                            String::new()
                        } else {
                            format!(
                                " <span class=\"chip\">canonical · {}</span>",
                                escape(&row.canonical_audiences.join(", "))
                            )
                        }
                    ),
                    escape(&row.mode),
                    escape(&row.capabilities.join(", ")),
                    format!(
                        "<span class=\"chip\">{}</span>{}",
                        escape(&row.readiness),
                        if row.enabled {
                            ""
                        } else {
                            " <span class=\"dim\">disabled</span>"
                        }
                    ),
                ]
            })
            .collect();
        body.push_str(&table(
            &["URL", "mode", "capabilities", "status"],
            &table_rows,
        ));
    }
    body
}

fn canonical_audience_inventory(rows: &[DeliveryRouteOverviewRow]) -> String {
    let table_rows = rows
        .iter()
        .flat_map(|route| {
            route.canonical_audiences.iter().map(|audience| {
                vec![
                    escape(audience),
                    format!("<code>{}</code>", escape(&route.id)),
                    format!("<code>{}</code>", escape(&route.url)),
                ]
            })
        })
        .collect::<Vec<_>>();
    if table_rows.is_empty() {
        "<p class=\"dim\">No canonical audience is selected.</p>\n".to_string()
    } else {
        table(&["audience", "route", "URL"], &table_rows)
    }
}

fn delivery_local_navigation(base: &str, active: &str) -> String {
    format!(
        "<nav class=\"local-nav\" aria-label=\"Delivery route views\"><a href=\"{base}\"{routes}>Routes</a><a href=\"{base}/canonical-audiences\"{audiences}>Canonical audiences</a></nav>",
        base = escape(base),
        routes = if active == "routes" { " aria-current=\"page\"" } else { "" },
        audiences = if active == "audiences" { " aria-current=\"page\"" } else { "" },
    )
}

fn placement_overview(rows: &[PlacementOverviewRow]) -> String {
    let mut body = String::from("<h2>Physical placements</h2>\n");
    if rows.is_empty() {
        body.push_str(
            "<p class=\"dim\">No physical placements are registered for this surface.</p>\n",
        );
        return body;
    }
    let mut rows = rows.iter().collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .observed_authority
            .cmp(&left.observed_authority)
            .then_with(|| right.desired_authority.cmp(&left.desired_authority))
            .then_with(|| left.name.cmp(&right.name))
    });
    let table_rows = rows
        .iter()
        .map(|placement| {
            let authority = if placement.observed_authority {
                "<span class=\"chip\">observed authority</span>".to_string()
            } else if placement.desired_authority {
                "<span class=\"chip\">desired authority · writes blocked</span>".to_string()
            } else {
                String::new()
            };
            let generation = match (placement.desired_generation, placement.observed_generation) {
                (Some(desired), Some(observed)) if desired == observed => {
                    format!("<code>{desired}</code>")
                }
                (Some(desired), observed) => format!(
                    "<span class=\"warn\">desired {desired} · observed {}</span>",
                    observed.map_or_else(|| "none".to_string(), |value| value.to_string())
                ),
                _ => "<span class=\"dim\">none</span>".to_string(),
            };
            vec![
                format!("{} {authority}", escape(&placement.name)),
                escape(&placement.role),
                format!(
                    "{} · {}{}",
                    escape(&placement.state),
                    escape(&placement.completeness),
                    placement
                        .authority_state
                        .as_deref()
                        .map_or_else(String::new, |state| { format!(" · {}", escape(state)) })
                ),
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
                    "<span class=\"warn\">writes blocked</span>".to_string()
                },
                generation,
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
            "authority generation",
        ],
        &table_rows,
    ));
    body
}

fn placement_policy_overview(
    policies: &[PlacementPolicyOverviewRow],
    equivalences: &[PlacementEquivalenceOverviewRow],
) -> String {
    let mut body = String::from(
        "<h2>Selection policies</h2>\n<p class=\"dim\">Policies select among named placements through immutable revisions. Routes pin an exact published revision rather than following the mutable policy head.</p>\n",
    );
    if policies.is_empty() {
        body.push_str("<p class=\"dim\">No placement policies.</p>\n");
    } else {
        let rows = policies
            .iter()
            .map(|policy| {
                vec![
                    format!(
                        "{}<br><code>{}</code>",
                        escape(&policy.name),
                        escape(&policy.id)
                    ),
                    escape(&policy.kind),
                    policy.current_revision.map_or_else(
                        || "<span class=\"dim\">not published</span>".to_string(),
                        |revision| revision.to_string(),
                    ),
                    policy.latest_state.as_deref().map_or_else(
                        || "<span class=\"dim\">no revisions</span>".to_string(),
                        escape,
                    ),
                    policy.revision_count.to_string(),
                    policy.current_digest.as_deref().map_or_else(
                        || "<span class=\"dim\">none</span>".to_string(),
                        |digest| format!("<code>{}</code>", escape(digest)),
                    ),
                    policy.resource_version.to_string(),
                ]
            })
            .collect::<Vec<_>>();
        body.push_str(&table(
            &[
                "policy",
                "kind",
                "current revision",
                "latest state",
                "revisions",
                "current digest",
                "version",
            ],
            &rows,
        ));
    }

    body.push_str(
        "<h2>Confirmed equivalences</h2>\n<p class=\"dim\">An equivalence is explicit, evidence-bound permission to treat two complete placements as interchangeable. It never follows placement names across recreation.</p>\n",
    );
    if equivalences.is_empty() {
        body.push_str("<p class=\"dim\">No placement equivalences.</p>\n");
    } else {
        let rows = equivalences
            .iter()
            .map(|equivalence| {
                vec![
                    format!("<code>{}</code>", escape(&equivalence.id)),
                    escape(&equivalence.placement_a),
                    escape(&equivalence.placement_b),
                    format!("<code>{}</code>", escape(&equivalence.evidence_digest)),
                    escape(&equivalence.state),
                    equivalence.resource_version.to_string(),
                ]
            })
            .collect::<Vec<_>>();
        body.push_str(&table(
            &[
                "equivalence",
                "placement A",
                "placement B",
                "evidence",
                "state",
                "version",
            ],
            &rows,
        ));
    }
    body
}

fn placement_plan_actions(rows: &[PlacementOverviewRow], csrf: &str, base: &str) -> String {
    let mut body = String::from("<h2>Authority workflows</h2>\n");
    let _ = write!(
        body,
        "<p><a href=\"{}/new\">Add placement</a></p>\n",
        escape(base),
    );
    for placement in rows {
        let active = if placement.desired_state == "active" {
            " selected"
        } else {
            ""
        };
        let offline = if placement.desired_state == "offline" {
            " selected"
        } else {
            ""
        };
        let checked = if placement.desired_read_enabled {
            " checked"
        } else {
            ""
        };
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"{base}/{name}/plan-update\">{csrf}\
             <input type=\"hidden\" name=\"expected_resource_version\" value=\"{version}\">\
             <label>desired state <select name=\"desired_state\"><option value=\"active\"{active}>active</option><option value=\"offline\"{offline}>offline</option></select></label>\
             <label>read order <input type=\"number\" name=\"read_order\" value=\"{read_order}\"></label>\
             <label><input type=\"checkbox\" name=\"desired_read_enabled\" value=\"1\"{checked}> eligible for reads</label>\
             <button>Review update of {label}</button></form>\n",
            base = escape(base),
            name = urlencode(&placement.name),
            csrf = csrf_field(csrf),
            version = placement.resource_version,
            active = active,
            offline = offline,
            read_order = placement.read_order,
            checked = checked,
            label = escape(&placement.name),
        );
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"{base}/{name}/plan-promote\">{csrf}\
             <input type=\"hidden\" name=\"expected_resource_version\" value=\"{version}\">\
             <button>Review promotion of {label}</button></form>\n",
            base = escape(base),
            name = urlencode(&placement.name),
            csrf = csrf_field(csrf),
            version = placement.resource_version,
            label = escape(&placement.name),
        );
        for (operation, label, class) in [
            ("drain", "drain", ""),
            ("delete", "delete", " class=\"danger\""),
        ] {
            let _ = write!(
                body,
                "<form class=\"console\" method=\"post\" action=\"{base}/{name}/plan-{operation}\">{csrf}\
                 <input type=\"hidden\" name=\"expected_resource_version\" value=\"{version}\">\
                 <button{class}>Review {label} of {placement}</button></form>\n",
                base = escape(base),
                name = urlencode(&placement.name),
                operation = operation,
                csrf = csrf_field(csrf),
                version = placement.resource_version,
                class = class,
                label = label,
                placement = escape(&placement.name),
            );
        }
    }
    if rows.iter().any(|placement| {
        placement.desired_generation != placement.observed_generation
            || placement.authority_state.as_deref() == Some("pending")
    }) {
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"{base}/plan-cancel-promotion\">{csrf}\
             <button class=\"danger\">Review cancellation of pending promotion</button></form>\n",
            base = escape(base),
            csrf = csrf_field(csrf),
        );
    }
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"{base}/plan-remove-write-authority\">{csrf}\
         <button class=\"danger\">Review removal of write authority</button></form>\n",
        base = escape(base),
        csrf = csrf_field(csrf),
    );
    body
}

/// Renders an immutable topology plan and its single confirmation-bound apply.
#[must_use]
pub fn topology_plan_page(
    email: &str,
    title: &str,
    apply_action: &str,
    csrf: &str,
    plan: &crate::web::console::ports::ReviewedPlan,
    started: Instant,
) -> String {
    topology_plan_page_with_operation(email, title, apply_action, csrf, plan, None, started)
}

/// Renders a signing-control plan while preserving its closed operation kind.
#[must_use]
pub fn signing_topology_plan_page(
    email: &str,
    title: &str,
    apply_action: &str,
    csrf: &str,
    plan: &crate::web::console::ports::ReviewedPlan,
    operation: &str,
    started: Instant,
) -> String {
    topology_plan_page_with_operation(
        email,
        title,
        apply_action,
        csrf,
        plan,
        Some(operation),
        started,
    )
}

fn topology_plan_page_with_operation(
    email: &str,
    title: &str,
    apply_action: &str,
    csrf: &str,
    plan: &crate::web::console::ports::ReviewedPlan,
    operation: Option<&str>,
    started: Instant,
) -> String {
    let mut body = format!(
        "<h1>{}</h1><p>Plan <code>{}</code> · expires {}</p>",
        escape(title),
        escape(&plan.plan_id),
        plan.expires_at,
    );
    body.push_str("<h2>Effects</h2><ol>");
    for effect in &plan.effects {
        let _ = write!(body, "<li>{}</li>", escape(effect));
    }
    body.push_str("</ol>");
    if !plan.warnings.is_empty() {
        body.push_str("<aside class=\"warn\"><strong>Warnings</strong><ul>");
        for warning in &plan.warnings {
            let _ = write!(body, "<li>{}</li>", escape(warning));
        }
        body.push_str("</ul></aside>");
    }
    let operation = operation.map_or_else(String::new, |operation| {
        format!(
            "<input type=\"hidden\" name=\"operation\" value=\"{}\">",
            escape(operation)
        )
    });
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"{}\">{}\
         <input type=\"hidden\" name=\"plan_id\" value=\"{}\">\
         <input type=\"hidden\" name=\"confirmation_hash\" value=\"{}\">\
         {}<button class=\"danger\">Apply reviewed plan</button></form>",
        escape(apply_action),
        csrf_field(csrf),
        escape(&plan.plan_id),
        escape(plan.confirmation_hash.as_deref().unwrap_or("")),
        operation,
    );
    page_with_session(
        title,
        &[(String::new(), "topology plan".to_string())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// Renders the complete desired-spec form used to plan a placement creation.
#[must_use]
pub fn new_placement_page(
    email: &str,
    title: &str,
    plan_action: &str,
    csrf: &str,
    bindings: &[StorageBindingReadSummary],
    started: Instant,
) -> String {
    let mut options = String::new();
    for binding in bindings {
        let _ = write!(
            options,
            "<option value=\"{}\">{} · {}</option>",
            escape(&binding.stable_id),
            escape(&binding.name),
            escape(&binding.kind),
        );
    }
    let body = format!(
        "<h1>{title}</h1><p class=\"dim\">Creation is reviewed as an immutable topology plan before any metadata changes.</p>\
         <form class=\"console\" method=\"post\" action=\"{action}\">{csrf}\
         <label>name <input name=\"name\" required></label>\
         <label>storage binding <select name=\"storage_binding_id\" required>{options}</select></label>\
         <label>prefix <input name=\"prefix\" required></label>\
         <label>kind <select name=\"kind\"><option value=\"complete\">complete</option><option value=\"shard\">shard</option><option value=\"archive\">archive</option></select></label>\
         <label>desired state <select name=\"desired_state\"><option value=\"active\">active</option><option value=\"offline\">offline</option></select></label>\
         <label>read order <input type=\"number\" name=\"read_order\" value=\"0\"></label>\
         <label><input type=\"checkbox\" name=\"desired_read_enabled\" value=\"1\" checked> eligible for reads</label>\
         <label>shard start <input type=\"number\" min=\"0\" max=\"65535\" name=\"hash_range_start\"></label>\
         <label>shard end <input type=\"number\" min=\"1\" max=\"65536\" name=\"hash_range_end\"></label>\
         <label><input type=\"checkbox\" name=\"requires_conditional_writes\" value=\"1\"> require conditional writes</label>\
         <button>Review placement creation</button></form>",
        title = escape(title),
        action = escape(plan_action),
        csrf = csrf_field(csrf),
        options = options,
    );
    page_with_session(
        title,
        &[(String::new(), "new placement".to_string())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The org dashboard: projects, registries, members, bindings, audit link.
///
/// `can_manage_members` gates the member-management controls (invite/remove)
/// to admins; a viewer sees the lists without the forms. `can_configure` gates
/// guidance to the reviewed API/CLI creation flows. `can_manage_storage` separately
/// gates binding mutations and backend locations. `can_delete` gates the
/// typed-confirmation org-delete form to an org owner. `owner_count` is the
/// number of org owners, used to hard-block removing the last one.
#[allow(clippy::too_many_arguments)]
#[must_use]
fn storage_binding_endpoint(binding: &StorageBindingRecord) -> Option<String> {
    let scheme = binding.endpoint_scheme.as_deref()?;
    let bytes = binding.endpoint_host_bytes.as_deref()?;
    let host = match binding.endpoint_host_kind.as_deref()? {
        "dns" => std::str::from_utf8(bytes).ok()?.to_string(),
        "ipv4" if bytes.len() == 4 => {
            std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
        }
        "ipv6" if bytes.len() == 16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            format!("[{}]", std::net::Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    let authority = binding
        .endpoint_port
        .map_or(host.clone(), |port| format!("{host}:{port}"));
    Some(format!("{scheme}://{authority}"))
}

pub fn org_dashboard(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    projects: &[ProjectRecord],
    registries: &[RegistryRecord],
    members: &[MemberRow],
    invitations: &[aos_proto_types::Invitation],
    bindings: &[StorageBindingReadSummary],
    managed_bindings: Option<&[StorageBindingRecord]>,
    caches: &[CacheSummary],
    domains: &[crate::db::DeliveryDomainRecord],
    boundaries: &[crate::db::NetworkBoundaryRecord],
    endpoints: &[crate::db::DeliveryEndpointRecord],
    gateways: &[crate::db::StorageGatewayRecord],
    topology_defaults: Option<&crate::web::console::ports::TopologyDefaultsOverview>,
    can_manage_members: bool,
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
    navigation_permissions: &NavigationPermissions,
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
        for spec in ORG_PAGES.iter().filter(|spec| {
            navigation_permissions.contains(&spec.permission)
                && matches!(
                    spec.key,
                    OrgPage::Projects
                        | OrgPage::Registries
                        | OrgPage::Caches
                        | OrgPage::StorageBindings
                        | OrgPage::Members
                )
        }) {
            let count = match spec.key {
                OrgPage::Projects => projects.len(),
                OrgPage::Registries => registries.len(),
                OrgPage::Caches => caches.len(),
                OrgPage::StorageBindings => bindings.len(),
                OrgPage::Members => members.len(),
                _ => 0,
            };
            let _ = write!(
                body,
                "<a class=\"settings-overview-card\" href=\"{href}\">\
                 <strong>{count}</strong><span>{label}</span></a>\n",
                href = escape(&spec.href(&format!("/-/org/{slug}"))),
                label = escape(spec.label),
            );
        }
        body.push_str("</div>\n");
    }

    // -- Registries ----------------------------------------------------------
    if active == "registries" {
        if can_configure {
            let _ = write!(
                body,
                "<aside class=\"callout\"><strong>Create a registry</strong><p>Registry creation uses the same reviewed plan/apply contract as the Hub API. Run <code>aos hub registry create --org {} --name NAME</code>, review the plan, then apply it with the returned confirmation hash.</p></aside>\n",
                escape(slug),
            );
        }
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
    }

    // -- Binary caches -------------------------------------------------------
    if active == "caches" {
        if can_configure {
            let _ = write!(
                body,
                "<aside class=\"callout\"><strong>Create a binary cache</strong><p>Cache creation uses the reviewed Hub API/CLI flow. Run <code>aos hub cache create {}/CACHE --name NAME</code>, review the plan, then apply it with the returned confirmation hash.</p></aside>\n",
                escape(slug),
            );
        }
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
    }

    // -- Projects ------------------------------------------------------------
    if active == "projects" {
        if can_configure {
            let _ = write!(
                body,
                "<aside class=\"callout\"><strong>Create a project</strong><p>Project creation uses the reviewed Hub API/CLI flow. Run <code>aos hub org project create {} --name NAME</code>, review the plan, then apply it with the returned confirmation hash.</p></aside>\n",
                escape(slug),
            );
        }
        if projects.is_empty() {
            body.push_str("<p class=\"dim\">No projects.</p>\n");
        } else {
            let rows: Vec<Vec<String>> = projects
                .iter()
                .map(|p| {
                    vec![
                        escape(if p.path.is_empty() { "(root)" } else { &p.path }),
                        escape(&p.name),
                        p.resource_version.to_string(),
                    ]
                })
                .collect();
            body.push_str(&table(&["path", "name", "version"], &rows));
        }
    }

    // -- Storage -------------------------------------------------------------
    if active == "storage-bindings" {
        // Render bindings as a compact stacked list (see `.binding` in the
        // stylesheet), not a 4-column table: a long object-store endpoint URL
        // gets the full content width to wrap into rather than squeezing the
        // name/kind columns until a name spans two lines and the delete button
        // hyphenates.
        body.push_str("<div class=\"bindings\">\n");
        for binding in bindings {
            let managed = managed_bindings
                .and_then(|records| records.iter().find(|record| record.id == binding.id));
            // Read authority exposes the redacted detail page; locations and
            // mutation controls still require storage management authority.
            let name_cell = format!(
                "<a href=\"/-/org/{org}/storage-bindings/{binding}\">{name}</a>",
                org = escape(slug),
                binding = escape(&binding.stable_id),
                name = escape(&binding.name),
            );
            let delete = if can_manage_storage {
                format!(
                    "<form class=\"console\" method=\"post\" \
                     action=\"/-/org/{org}/storage-bindings/{binding}/plan-delete\">{csrf}\
                     <button class=\"danger\">delete</button></form>",
                    org = escape(slug),
                    binding = escape(&binding.stable_id),
                    csrf = csrf_field(csrf),
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
            } else if let Some(managed) = managed.filter(|record| record.kind == "local_fs") {
                (
                    String::new(),
                    format!(
                        "<code>{}</code>",
                        escape(
                            managed
                                .local_root_path
                                .as_deref()
                                .unwrap_or("invalid local binding")
                        )
                    ),
                )
            } else {
                let endpoint = managed
                    .and_then(storage_binding_endpoint)
                    .unwrap_or_else(|| "invalid object-store endpoint".to_string());
                let bucket = managed
                    .and_then(|record| record.object_bucket.as_deref())
                    .unwrap_or("invalid bucket");
                let prefix = managed
                    .and_then(|record| record.object_prefix.as_deref())
                    .unwrap_or("");
                (
                    format!(
                        "<span class=\"chip\">{}</span>",
                        escape(
                            managed
                                .and_then(|record| record.access_mode.as_deref())
                                .unwrap_or("invalid")
                        )
                    ),
                    format!(
                        "<code>{endpoint}/{bucket}{prefix}</code>",
                        endpoint = escape(&endpoint),
                        bucket = escape(bucket),
                        prefix = if prefix.is_empty() {
                            String::new()
                        } else {
                            format!("/{}", escape(prefix))
                        },
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
                kind = escape(&binding.kind),
                access = access_chip,
                delete = delete,
                location = location,
            );
        }
        body.push_str("</div>\n");
        if can_manage_storage {
            let _ = write!(
                body,
                "<p><a href=\"/-/org/{}/storage-bindings/new\">Add a storage binding</a></p>",
                escape(slug)
            );
        }
    }

    if matches!(active, "identity-and-access" | "operations") {
        body.push_str(
            "<div class=\"settings-summary\"><p>Topology configuration is managed as \
             reviewed plans. Inventory, current observations, and replacement progress \
             remain visible while an operation is running.</p></div>\n",
        );
    }

    if active == "topology-defaults" {
        body.push_str("<p class=\"dim\">Defaults are creation-time choices only. Existing placements, routes, endpoints, and gateways retain their exact pinned identities.</p>\n");
        if let Some(defaults) = topology_defaults {
            let value = |stable_id: &str, generation: Option<i64>| {
                if stable_id.is_empty() {
                    return "<span class=\"dim\">none</span>".to_string();
                }
                generation.map_or_else(
                    || format!("<code>{}</code>", escape(stable_id)),
                    |generation| format!("<code>{}#{generation}</code>", escape(stable_id)),
                )
            };
            let rows = vec![
                vec![
                    "storage binding".to_string(),
                    value(&defaults.storage_binding_id, None),
                ],
                vec!["domain".to_string(), value(&defaults.domain_id, None)],
                vec![
                    "delivery endpoint".to_string(),
                    value(
                        &defaults.delivery_endpoint_id,
                        Some(defaults.delivery_endpoint_generation),
                    ),
                ],
                vec![
                    "storage gateway".to_string(),
                    value(
                        &defaults.storage_gateway_id,
                        Some(defaults.storage_gateway_generation),
                    ),
                ],
            ];
            body.push_str(&table(&["default", "stable identity"], &rows));
            let _ = write!(
                body,
                "<p class=\"dim\">Scope <code>{}</code> · resource version {}</p>\n",
                escape(&defaults.scope_key),
                escape(&defaults.resource_version),
            );
        } else if can_manage_storage {
            body.push_str("<p class=\"dim\">No organization defaults.</p>\n");
        } else {
            body.push_str(
                "<p class=\"dim\">Reading topology defaults requires storage management.</p>\n",
            );
        }
    }

    if active == "domains" {
        body.push_str("<p class=\"dim\">Domains are verified host identities. Delivery endpoints reference them; routes remain independently replaceable mappings.</p>\n");
        if domains.is_empty() {
            body.push_str("<p class=\"dim\">No domains.</p>\n");
        } else {
            let rows = domains
                .iter()
                .map(|domain| {
                    vec![
                        format!("<code>{}</code>", escape(&domain.hostname)),
                        if domain.dns_configuration_json.is_some() {
                            "managed".to_string()
                        } else {
                            "external".to_string()
                        },
                        escape(&domain.dns_state),
                        if domain.certificate_configuration_json.is_some() {
                            "managed".to_string()
                        } else {
                            "external".to_string()
                        },
                        escape(&domain.certificate_state),
                        if domain.verified_at.is_some() {
                            "verified".to_string()
                        } else {
                            "pending".to_string()
                        },
                        domain.resource_version.to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &[
                    "hostname",
                    "DNS owner",
                    "DNS",
                    "TLS owner",
                    "TLS",
                    "verification",
                    "version",
                ],
                &rows,
            ));
        }
    }

    if active == "network-boundaries" {
        body.push_str("<p class=\"dim\">A boundary is a stable network-realm identity. Consumers pin an exact immutable revision.</p>\n");
        if boundaries.is_empty() {
            body.push_str("<p class=\"dim\">No network boundaries.</p>\n");
        } else {
            let rows = boundaries
                .iter()
                .map(|boundary| {
                    vec![
                        format!(
                            "{}<br><code>{}</code>",
                            escape(&boundary.name),
                            escape(&boundary.id)
                        ),
                        escape(&boundary.kind),
                        boundary.default_revision.map_or_else(
                            || "<span class=\"dim\">none</span>".to_string(),
                            |revision| revision.to_string(),
                        ),
                        boundary.default_revision_state.as_deref().map_or_else(
                            || "<span class=\"dim\">unconfigured</span>".to_string(),
                            escape,
                        ),
                        boundary.resource_version.to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &["boundary", "kind", "default revision", "state", "version"],
                &rows,
            ));
        }
    }

    if active == "delivery-endpoints" {
        body.push_str("<p class=\"dim\">Endpoints own listener identity and pin a boundary. Delivery routes attach surface paths and capabilities separately.</p>\n");
        if endpoints.is_empty() {
            body.push_str("<p class=\"dim\">No delivery endpoints.</p>\n");
        } else {
            let rows = endpoints
                .iter()
                .map(|endpoint| {
                    let host = endpoint
                        .domain_id
                        .and_then(|domain_id| {
                            domains
                                .iter()
                                .find(|domain| domain.id == domain_id)
                                .map(|domain| domain.hostname.clone())
                        })
                        .or_else(|| {
                            endpoint.ipv4_bytes.as_deref().and_then(|bytes| {
                                <[u8; 4]>::try_from(bytes)
                                    .ok()
                                    .map(std::net::Ipv4Addr::from)
                                    .map(|address| address.to_string())
                            })
                        })
                        .or_else(|| {
                            endpoint.ipv6_bytes.as_deref().and_then(|bytes| {
                                <[u8; 16]>::try_from(bytes)
                                    .ok()
                                    .map(std::net::Ipv6Addr::from)
                                    .map(|address| format!("[{address}]"))
                            })
                        })
                        .unwrap_or_else(|| "invalid host".to_string());
                    vec![
                        format!("<code>{}</code>", escape(&endpoint.id)),
                        format!(
                            "<code>{}://{}:{}</code>",
                            escape(&endpoint.scheme),
                            escape(&host),
                            endpoint.effective_port,
                        ),
                        format!("<code>{}</code>", escape(&endpoint.network_boundary_id)),
                        endpoint.desired_generation.map_or_else(
                            || "<span class=\"dim\">none</span>".to_string(),
                            |generation| generation.to_string(),
                        ),
                        endpoint.resource_version.to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &[
                    "endpoint",
                    "listener",
                    "boundary",
                    "desired generation",
                    "version",
                ],
                &rows,
            ));
        }
    }

    if active == "storage-gateways" {
        body.push_str("<p class=\"dim\">Gateways publish a binding and prefix directly through an exact endpoint generation. Hub-proxied routes are separate delivery routes.</p>\n");
        if gateways.is_empty() {
            body.push_str("<p class=\"dim\">No storage gateways.</p>\n");
        } else {
            let rows = gateways
                .iter()
                .map(|gateway| {
                    vec![
                        format!("<code>{}</code>", escape(&gateway.id)),
                        if gateway.enabled {
                            "enabled"
                        } else {
                            "disabled"
                        }
                        .to_string(),
                        gateway.desired_generation.map_or_else(
                            || "<span class=\"dim\">none</span>".to_string(),
                            |generation| generation.to_string(),
                        ),
                        gateway.observed_generation.map_or_else(
                            || "<span class=\"dim\">none</span>".to_string(),
                            |generation| generation.to_string(),
                        ),
                        escape(&gateway.reconciliation_state),
                        gateway.resource_version.to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &[
                    "gateway",
                    "selection",
                    "desired",
                    "observed",
                    "reconciliation",
                    "version",
                ],
                &rows,
            ));
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
                     action=\"/-/org/{org}/members/{kind}:{id}/role\" style=\"display:inline\">{csrf}\
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
                         action=\"/-/org/{}/members/{}:{}/remove\" style=\"display:inline\">{}\
                         <button class=\"danger\">remove</button></form>",
                            escape(&org.slug),
                            escape(&m.kind),
                            m.id,
                            csrf_field(csrf),
                        );
                    }
                }
                vec![escape(&m.label), escape(&m.role), action]
            })
            .collect();
        body.push_str(&table(&["member", "role", ""], &rows));
        body.push_str(&mem_pager.nav_with(&format!("/-/org/{slug}/members"), "", "members_page"));

        if can_manage_members {
            let _ = write!(
                body,
                "<p><a href=\"/-/org/{}/members/invitations/new\">Invite a member</a></p>",
                escape(&org.slug)
            );
            if !invitations.is_empty() {
                body.push_str("<h2>Invitations</h2>\n");
                let rows = invitations
                    .iter()
                    .map(|invitation| {
                        let action = if invitation.state == "pending" {
                            format!(
                                "<form class=\"console\" method=\"post\" action=\"/-/org/{}/members/invitations/{}/cancel\">{}<input type=\"hidden\" name=\"if_version\" value=\"{}\"><button class=\"danger\">cancel</button></form>",
                                escape(&org.slug),
                                invitation.invitation_id,
                                csrf_field(csrf),
                                escape(&invitation.resource_version),
                            )
                        } else {
                            String::new()
                        };
                        vec![
                            invitation.invitation_id.to_string(),
                            escape(&invitation.email),
                            escape(&invitation.scope),
                            escape(&invitation.role),
                            escape(&invitation.state),
                            invitation.expires_at.to_string(),
                            action,
                        ]
                    })
                    .collect::<Vec<_>>();
                body.push_str(&table(
                    &["id", "email", "scope", "role", "state", "expires", ""],
                    &rows,
                ));
            }
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
             <form class=\"console\" method=\"post\" action=\"/-/org/{slug}/danger/delete\">\n{csrf}\
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

    org_settings_chrome(email, slug, active, &body, navigation_permissions, started)
}

/// Renders the dedicated member invitation workflow.
#[must_use]
pub fn org_new_member_invitation_page(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let body = format!(
        "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/members/invitations\">\n{csrf}\
         <label>email <input type=\"email\" name=\"email\" required></label>\n\
         <label>role <select name=\"role\">\
         <option value=\"viewer\">viewer</option><option value=\"developer\">developer</option>\
         <option value=\"maintainer\">maintainer</option><option value=\"admin\">admin</option>\
         <option value=\"owner\">owner</option></select></label>\n\
         <button>send invitation</button>\n</form>\n",
        org = escape(&org.slug),
        csrf = csrf_field(csrf),
    );
    org_settings_chrome(
        email,
        &org.slug,
        "members",
        &body,
        navigation_permissions,
        started,
    )
}

/// Renders the one-time invitation delivery result after reviewed creation.
#[must_use]
pub fn invitation_created_page(
    email: &str,
    org_slug: &str,
    invitation: &aos_proto_types::Invitation,
    acceptance_url: &str,
    delivery_error: Option<&str>,
    started: Instant,
) -> String {
    let mut body = String::from("<h1>Invitation created</h1>\n");
    let _ = writeln!(
        body,
        "<p><code>{}</code> may join <code>{}</code> as <strong>{}</strong> after accepting.</p>",
        escape(&invitation.email),
        escape(org_slug),
        escape(&invitation.role),
    );
    if delivery_error.is_some() {
        body.push_str(
            "<p class=\"bad\">Email delivery failed. Copy the one-time link below and deliver it securely.</p>\n",
        );
    } else {
        body.push_str("<p class=\"good\">The invitation email was submitted for delivery.</p>\n");
    }
    let _ = write!(
        body,
        "<label>one-time acceptance link <input type=\"text\" readonly value=\"{}\"></label>\n\
         <p class=\"dim\">This secret is shown once. Creating the invitation did not create a user or membership.</p>\n\
         <p><a href=\"/-/org/{}/members\">Return to members →</a></p>\n",
        escape(acceptance_url),
        escape(org_slug),
    );
    page_with_session(
        "invitation created",
        &[
            (format!("/-/org/{org_slug}/members"), "members".into()),
            (String::new(), "invitation created".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// Renders the authenticated invitation acceptance ceremony.
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

/// Renders the dedicated storage-binding creation workflow.
#[must_use]
pub fn org_new_storage_binding_page(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let mut kinds = String::new();
    for kind in RuntimeKind::current().creatable_binding_kinds() {
        let _ = write!(
            kinds,
            "<option value=\"{}\">{}</option>",
            escape(kind.as_str()),
            escape(kind.label()),
        );
    }
    let body = format!(
        "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/storage-bindings/plan-create\" data-binding-kind>\n{csrf}\
         <label>name <input type=\"text\" name=\"name\" required></label>\n\
         <label>kind <select name=\"kind\">{kinds}</select></label>\n\
         <label>path or bucket <input type=\"text\" name=\"root\" required></label>\n\
         <label>endpoint <input type=\"url\" name=\"endpoint\"></label>\n\
         <label>region <input type=\"text\" name=\"region\" value=\"auto\"></label>\n\
         <label>access <select name=\"access\"><option>private</option><option>public</option></select></label>\n\
         <p class=\"hint\">Private credentials are attached as immutable credential revisions after creation.</p>\n\
         <button>create binding</button>\n</form>\n",
        org = escape(&org.slug),
        csrf = csrf_field(csrf),
        kinds = kinds,
    );
    org_settings_chrome(
        email,
        &org.slug,
        "storage-bindings",
        &body,
        navigation_permissions,
        started,
    )
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
    /// Whether the current principal may enter this cache's management pages.
    pub management_access: bool,
}

/// The global binary-caches list — the masthead **caches** tab.
///
/// Lists every cache the viewer may see (a signed-in user: caches readable on
/// their orgs, plus public caches; an anonymous viewer, only when the instance
/// has opted caches public: public caches only). A row links to management pages
/// only when `management_access` is true; public discovery never implies
/// management access. `email` is `Some` for a signed-in viewer.
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
                let cache = if c.management_access {
                    format!(
                        "<a href=\"/-/org/{org}/caches/{slug}\">{label}</a>",
                        org = escape(&c.org_slug),
                        slug = escape(&c.slug),
                        label = label,
                    )
                } else {
                    label
                };
                let org = if c.org_slug.is_empty() {
                    "<span class=\"dim\">—</span>".to_string()
                } else if c.management_access {
                    format!(
                        "<a href=\"/-/org/{org}\">{org}</a>",
                        org = escape(&c.org_slug)
                    )
                } else {
                    escape(&c.org_slug)
                };
                vec![
                    cache,
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
    cache: &BinaryCache,
    placements: &[PlacementOverviewRow],
    policies: &[PlacementPolicyOverviewRow],
    equivalences: &[PlacementEquivalenceOverviewRow],
    routes: &[DeliveryRouteOverviewRow],
    retention: &[RetentionSubscriptionOverviewRow],
    manual_roots: &[ManualRetentionRootOverviewRow],
    population: &[PopulationTargetOverviewRow],
    usage: &CacheUsage,
    signed: bool,
    signing_usage: Option<&crate::db::SigningKeyUsageRecord>,
    signing_keys: &[aos_proto_types::SigningKey],
    can_admin: bool,
    // The active settings section follows the canonical cache IA.
    active: &str,
    notice: Option<&str>,
    navigation_permissions: &NavigationPermissions,
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
        let signed = if signed {
            " · <span class=\"chip\">signed</span>"
        } else {
            ""
        };
        let _ = write!(
            body,
            "<p class=\"chips\"><span class=\"chip\">{vis}</span>\
             <span class=\"chip\">Nix priority {prio}</span>\
             <span class=\"chip\">{comp}</span>{signed}</p>\n\
             <p class=\"dim\">{objects} objects · {size} · {links} linked · created {ago}</p>\n",
            vis = escape(&cache.visibility),
            prio = cache.priority,
            comp = escape(&cache.compression),
            signed = signed,
            objects = usage.object_count,
            size = human_size(usage.used_bytes.max(0) as u64),
            links = "review",
            ago = ago(cache.created_at),
        );
        body.push_str("<div class=\"settings-overview-grid\">");
        let base = format!("/-/org/{org_slug}/caches/{}", cache.slug);
        for spec in CACHE_PAGES.iter().filter(|spec| {
            navigation_permissions.contains(&spec.permission)
                && matches!(
                    spec.key,
                    CachePage::Placements
                        | CachePage::RetentionSubscriptions
                        | CachePage::GarbageCollection
                )
        }) {
            let value = match spec.key {
                CachePage::Placements => placements
                    .first()
                    .map(|placement| placement.binding_name.clone())
                    .unwrap_or_else(|| "unplaced".to_string()),
                CachePage::RetentionSubscriptions => retention.len().to_string(),
                CachePage::GarbageCollection => usage.object_count.to_string(),
                _ => String::new(),
            };
            let _ = write!(body, "<a class=\"settings-overview-card\" href=\"{href}\"><strong>{value}</strong><span>{label}</span></a>", href=escape(&spec.href(&base)), value=escape(&value), label=escape(spec.label));
        }
        body.push_str("</div>\n");
        body.push_str(&placement_overview(placements));
    }

    // -- Placement inventory ------------------------------------------------
    if active == "placements" {
        body.push_str(&placement_overview(placements));
        if can_admin {
            body.push_str(&placement_plan_actions(
                placements,
                csrf,
                &format!("/-/org/{org_slug}/caches/{}/placements", cache.slug),
            ));
        }
    }
    // -- Delivery routes -----------------------------------------------------
    if active == "delivery-routes" {
        body.push_str(&delivery_local_navigation(
            &format!("/-/org/{org_slug}/caches/{}/delivery-routes", cache.slug),
            "routes",
        ));
        body.push_str(&delivery_route_inventory(routes));
    }

    if active == "canonical-audiences" {
        body.push_str(&delivery_local_navigation(
            &format!("/-/org/{org_slug}/caches/{}/delivery-routes", cache.slug),
            "audiences",
        ));
        body.push_str(&canonical_audience_inventory(routes));
    }

    if active == "placement-policies" {
        body.push_str(&placement_policy_overview(policies, &[]));
    }

    if active == "placement-equivalences" {
        body.push_str(&placement_policy_overview(&[], equivalences));
    }

    if active == "access" {
        body.push_str("<h2>Cache policy</h2>\n");
        let _ = write!(
            body,
            "<p class=\"dim\">Cache <code>{}</code> · created {}</p>\n",
            escape(&cache.slug),
            ago(cache.created_at),
        );
    }
    if active == "access" && can_admin {
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
            "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/access/plan-update\">{csrf}\
             <input type=\"hidden\" name=\"expected_resource_version\" value=\"{version}\">\
             <label>name <input type=\"text\" name=\"name\" value=\"{name}\"></label>\n\
             <label>visibility <select name=\"visibility\">{vis_pub}{vis_int}{vis_priv}</select></label>\n\
             <label>Nix priority <input type=\"number\" name=\"nix_priority\" value=\"{prio}\"></label>\n\
             <label>compression <select name=\"compression\">{c_zstd}{c_xz}{c_none}</select></label>\n\
             <label><span class=\"lbl\">advertise mass-query</span> \
             <input type=\"checkbox\" name=\"want_mass_query\" value=\"1\"{mass}></label>\n\
             <button>Review policy update</button>\n</form>\n",
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
            version = cache.resource_version,
        );
    } else if active == "access" {
        body.push_str(
            "<p class=\"dim\">Changing cache policy requires cache administration.</p>\n",
        );
    }

    // -- Independent cache/registry relationships ---------------------------
    if active == "population-targets" {
        body.push_str("<p class=\"dim\">Population targets are cache-owned instructions. They do not imply retention or consumer advertisement.</p>\n");
        if !population.is_empty() {
            let rows = population
                .iter()
                .map(|row| {
                    vec![
                        escape(&row.registry),
                        escape(&row.trigger),
                        if row.required { "required" } else { "optional" }.to_string(),
                        if row.enabled { "enabled" } else { "disabled" }.to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &["registry", "trigger", "publishing", "state"],
                &rows,
            ));
        } else {
            body.push_str("<p class=\"dim\">No population targets.</p>\n");
        }
    }

    // -- Manual retention roots and leases ----------------------------------
    if active == "manual-roots" {
        body.push_str("<h2>Manual roots and leases</h2>\n");
        if manual_roots.is_empty() {
            body.push_str("<p class=\"dim\">No manual retention roots.</p>\n");
        } else {
            let rows = manual_roots
                .iter()
                .map(|root| {
                    let lease = root.lease_id.as_deref().map_or_else(
                        || {
                            if root.protection_kind == "indefinite" {
                                "indefinite".to_string()
                            } else {
                                "<span class=\"warn\">missing lease head</span>".to_string()
                            }
                        },
                        |lease_id| {
                            format!(
                                "<code>{}</code> · {} · expires {}",
                                escape(lease_id),
                                escape(root.lease_state.as_deref().unwrap_or("unknown")),
                                root.lease_expires_at.map_or_else(
                                    || "unknown".to_string(),
                                    |expires_at| expires_at.to_string(),
                                ),
                            )
                        },
                    );
                    vec![
                        format!("<code>{}</code>", escape(&root.id)),
                        format!("<code>{}</code>", escape(&root.store_hash)),
                        escape(&root.reason),
                        lease,
                        if root.deleted_at.is_some() {
                            "deleted".to_string()
                        } else {
                            "active".to_string()
                        },
                        root.resource_version.to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &[
                    "root",
                    "store hash",
                    "reason",
                    "protection",
                    "state",
                    "version",
                ],
                &rows,
            ));
        }
    }

    if active == "retention-subscriptions" {
        body.push_str("<p class=\"dim\">Registry retention is an independent cache-owned relationship. Each selector preserves a bounded signed history; it does not change the consumer cache stack or population policy.</p>\n");
        if retention.is_empty() {
            body.push_str("<p class=\"dim\">No retention subscriptions.</p>\n");
        } else {
            let rows = retention
                .iter()
                .map(|row| {
                    vec![
                        escape(&row.registry),
                        escape(&row.state),
                        format!("<code>{}</code>", escape(&row.selector)),
                        row.revision
                            .as_deref()
                            .map(escape)
                            .unwrap_or_else(|| "<span class=\"dim\">none</span>".to_string()),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &["registry", "refresh", "selector", "revision"],
                &rows,
            ));
        }
    }

    if active == "objects" {
        let _ = write!(
            body,
            "<p>{} indexed objects · {}</p>",
            usage.object_count,
            human_size(usage.used_bytes.max(0) as u64)
        );
    }
    if active == "signing-key" {
        body.push_str(
            "<p class=\"dim\">Narinfo verification pins this cache to one exact immutable public-key generation. Private key bytes remain outside AOS Hub.</p>\n",
        );
        if let Some(selected) = signing_usage {
            let _ = write!(
                body,
                "<p>Current usage: <code>{}</code> generation {} · {} · revision {}</p>",
                escape(&selected.signing_key_id),
                selected.signing_key_generation,
                escape(&selected.state),
                selected.resource_version,
            );
            if selected.state == "active" && can_admin {
                let _ = write!(
                    body,
                    "<form class=\"console\" method=\"post\" action=\"/-/org/{}/caches/{}/signing-key\">{}<input type=\"hidden\" name=\"state\" value=\"detached\"><input type=\"hidden\" name=\"signing_key_stable_id\" value=\"{}\"><input type=\"hidden\" name=\"signing_key_generation\" value=\"{}\"><input type=\"hidden\" name=\"expected_resource_version\" value=\"{}\"><button class=\"danger\">Review detachment</button></form>",
                    escape(org_slug),
                    escape(&cache.slug),
                    csrf_field(csrf),
                    escape(&selected.signing_key_id),
                    selected.signing_key_generation,
                    selected.resource_version,
                );
            }
        } else {
            body.push_str("<p class=\"dim\">No narinfo signing usage is configured.</p>");
        }
        if can_admin {
            let options = signing_keys
                .iter()
                .filter_map(|key| {
                    let generation = key.latest_generation.as_ref()?;
                    (generation.state == "active").then(|| {
                        format!(
                            "<option value=\"{}:{}\">{} · generation {}</option>",
                            escape(&key.stable_id),
                            generation.generation,
                            escape(&key.name),
                            generation.generation,
                        )
                    })
                })
                .collect::<String>();
            if options.is_empty() {
                let _ = write!(
                    body,
                    "<p class=\"dim\">Enroll an active organization signing key before configuring this usage.</p>"
                );
            } else {
                let _ = write!(
                    body,
                    "<h2>Select generation</h2><form class=\"console\" method=\"post\" action=\"/-/org/{}/caches/{}/signing-key\">{}<input type=\"hidden\" name=\"state\" value=\"active\"><label>Signing key <select name=\"key_generation\" required>{}</select></label><input type=\"hidden\" name=\"expected_resource_version\" value=\"{}\"><button>Review usage change</button></form>",
                    escape(org_slug),
                    escape(&cache.slug),
                    csrf_field(csrf),
                    options,
                    signing_usage.map_or_else(|| "absent".to_string(), |usage| usage.resource_version.to_string()),
                );
            }
        }
    }
    if active == "operations" {
        body.push_str(
            "<p class=\"dim\">Population, refresh, and garbage-collection operations for this cache.</p>\n",
        );
    }
    if matches!(
        active,
        "garbage-collection" | "gc-plans" | "gc-runs" | "gc-jobs"
    ) {
        body.push_str(
            "<p class=\"dim\">Collection policy, immutable plans, runs, and deletion jobs \
             are reviewed as separate resources.</p>\n",
        );
        let base = format!(
            "/-/org/{}/caches/{}/garbage-collection",
            escape(org_slug),
            escape(&cache.slug)
        );
        let current = |key| {
            if active == key {
                " aria-current=\"page\""
            } else {
                ""
            }
        };
        let _ = write!(body, "<nav class=\"local-nav\" aria-label=\"Garbage collection\"><a href=\"{base}\"{policy}>Policy</a><a href=\"{base}/plans\"{plans}>Plans</a><a href=\"{base}/runs\"{runs}>Runs</a><a href=\"{base}/jobs\"{jobs}>Jobs</a></nav>", policy=current("garbage-collection"), plans=current("gc-plans"), runs=current("gc-runs"), jobs=current("gc-jobs"));
        match active {
            "gc-plans" => body.push_str("<p class=\"dim\">Immutable collection plans and their root snapshots appear here.</p>\n"),
            "gc-runs" => body.push_str("<p class=\"dim\">Applied plan outcomes appear here.</p>\n"),
            "gc-jobs" => body.push_str("<p class=\"dim\">Deletion jobs, retry state, and terminal outcomes appear here.</p>\n"),
            _ => {}
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
                "<p class=\"warn\">Deletes this cache identity only after a reviewed impact plan \
                 proves that no placements, routes, retention subscriptions, or population targets \
                 still reference it. Stored objects are not removed from their bindings.</p>\n\
                 <form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/danger/plan-delete\">{csrf}\
                 <button class=\"danger\">Review cache deletion</button>\n</form>\n",
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
    let navigation_active = match active {
        "canonical-audiences" => "delivery-routes",
        "gc-plans" | "gc-runs" | "gc-jobs" => "garbage-collection",
        _ => active,
    };
    cache_settings_chrome(
        email,
        org_slug,
        cache,
        navigation_active,
        &body,
        navigation_permissions,
        started,
    )
}

/// Render the "Recent runs" garbage-collection history for a cache.
///
/// One row per recent run (newest first): when it started + its status, the
/// outcome (objects deleted/retained/scanned, or the error for a failed run, or
/// "running…" for one still in flight), and the bytes reclaimed.
pub fn audit_page(
    email: &str,
    org: &OrgRecord,
    rows: &[AuditRow],
    page_number: usize,
    navigation_permissions: &NavigationPermissions,
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
        body.push_str(&pager.nav(&format!("/-/org/{}/audit-log", org.slug), ""));
    }
    org_settings_chrome(
        email,
        &org.slug,
        "audit-log",
        &body,
        navigation_permissions,
        started,
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

/// Read model for a durable delivery-route replacement operation.
pub struct RouteReplacementProgress<'a> {
    /// Stable operation id used to resume the workflow.
    pub operation_id: &'a str,
    /// URL that remains live during the overlap window.
    pub current_url: &'a str,
    /// Disabled successor URL being verified.
    pub successor_url: &'a str,
    /// Ordered replacement steps and their current states.
    pub steps: &'a [(&'a str, &'a str)],
    /// References that prevent the next destructive transition.
    pub blockers: &'a [&'a str],
}

/// Renders resumable route-replacement progress without requiring JavaScript.
pub fn route_replacement_progress(progress: &RouteReplacementProgress<'_>) -> String {
    let mut html = format!(
        "<section class=\"operation-progress\" aria-labelledby=\"route-replacement-title\">\
         <h2 id=\"route-replacement-title\">Replace route</h2>\
         <p><code>{}</code> remains live while <code>{}</code> is prepared.</p>\
         <p class=\"dim\">operation <code>{}</code></p><ol>",
        escape(progress.current_url),
        escape(progress.successor_url),
        escape(progress.operation_id),
    );
    for (label, state) in progress.steps {
        let _ = write!(
            html,
            "<li><span class=\"chip\">{}</span> {}</li>",
            escape(state),
            escape(label),
        );
    }
    html.push_str("</ol>");
    if !progress.blockers.is_empty() {
        html.push_str("<aside class=\"warn\"><strong>Blocking references</strong><ul>");
        for blocker in progress.blockers {
            let _ = write!(html, "<li>{}</li>", escape(blocker));
        }
        html.push_str("</ul></aside>");
    }
    html.push_str("</section>");
    html
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
        .find(|item| item.key == navigation.active);
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
    let invalid = selected.is_none();
    let heading = if invalid {
        format!(
            "<h1>Invalid settings destination</h1>\n<p class=\"bad\" role=\"alert\">The undeclared settings key <code>{}</code> cannot be rendered.</p>\n",
            escape(navigation.active),
        )
    } else if content.contains("<h1") {
        String::new()
    } else {
        let section = selected.map_or("Invalid settings destination", |item| item.label);
        format!(
            "<h1>{section} · {context}</h1>\n",
            section = escape(section),
            context = escape(&navigation.context),
        )
    };
    format!(
        "<div class=\"settings\">\n<details class=\"settings-nav-disclosure\" open><summary>Settings sections</summary>{nav}</details><div class=\"settings-body\">\n{heading}{content}</div>\n</div>\n"
    )
}

/// Builds grouped navigation from a scope's typed IA declarations.
fn navigation_from_specs<'a, K: Copy>(
    base: &str,
    context: String,
    active: &'a str,
    specs: &[PageSpec<K>],
    key: impl Fn(K) -> &'static str,
    visible: impl Fn(PageSpec<K>) -> bool,
) -> SettingsNavigation<'a> {
    let mut groups = Vec::<SettingsNavGroup>::new();
    for spec in specs.iter().copied().filter(|spec| visible(*spec)) {
        let item = SettingsNavItem::new(key(spec.key), spec.label, spec.href(base));
        if let Some(group) = groups.last_mut().filter(|group| group.label == spec.group) {
            group.items.push(item);
        } else {
            groups.push(SettingsNavGroup::new(spec.group, vec![item]));
        }
    }
    SettingsNavigation::new(active, context, groups)
}

/// The registry-scope settings sidebar (one of the management pages active).
///
fn registry_settings_navigation<'a>(
    slug: &str,
    active: &'a str,
    permissions: &NavigationPermissions,
) -> SettingsNavigation<'a> {
    navigation_from_specs(
        &format!("/{slug}/-/settings"),
        slug.to_string(),
        active,
        REGISTRY_PAGES,
        RegistryPage::as_str,
        |spec| permissions.contains(&spec.permission),
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
    permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    // Each page supplies its own section `<h1>` (e.g. "Tokens · {slug}"); the
    // chrome adds only the sidebar, so no scope title is repeated across tabs.
    let body = settings_layout(
        &registry_settings_navigation(slug, active, permissions),
        content,
    );
    page_with_session(
        &format!("manage · {slug}"),
        &registry_crumbs(slug),
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// Renders the registry's channel inventory in the canonical settings shell.
#[must_use]
pub fn registry_channels_page(
    email: &str,
    registry: &RegistryRecord,
    channels: &[crate::db::ChannelSummary],
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let rows = channels
        .iter()
        .map(|channel| {
            let assigned = channel
                .partitions
                .iter()
                .filter(|release| release.is_some())
                .count();
            vec![
                format!(
                    "<a href=\"/{}/-/settings/channels/{}\">{}</a>",
                    escape(&registry.slug),
                    urlencode(&channel.name),
                    escape(&channel.name),
                ),
                channel
                    .frontier
                    .as_deref()
                    .map(escape)
                    .unwrap_or_else(|| "<span class=\"dim\">none</span>".to_string()),
                format!("{assigned} / {}", channel.partitions.len()),
            ]
        })
        .collect::<Vec<_>>();
    let mut content = String::from(
        "<p class=\"dim\">Channels map each of the 256 deterministic consumer buckets to a signed release. Open a channel to review its rollout or prepare an advance.</p>\n",
    );
    content.push_str(&table(&["channel", "frontier", "assigned buckets"], &rows));
    registry_settings_chrome(
        email,
        &registry.slug,
        "channels",
        &content,
        navigation_permissions,
        started,
    )
}

/// The org-scope settings sidebar (one of the org management pages active).
///
/// Resources, access, and operations are visually grouped below Overview; the
/// destructive section remains isolated at the end.
fn org_settings_navigation<'a>(
    org_slug: &str,
    active: &'a str,
    permissions: &NavigationPermissions,
) -> SettingsNavigation<'a> {
    navigation_from_specs(
        &format!("/-/org/{org_slug}"),
        org_slug.to_string(),
        active,
        ORG_PAGES,
        OrgPage::as_str,
        |spec| permissions.contains(&spec.permission),
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
    permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let body = settings_layout(
        &org_settings_navigation(org_slug, active, permissions),
        content,
    );
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
fn cache_settings_navigation<'a>(
    org_slug: &str,
    cache_slug: &str,
    active: &'a str,
    permissions: &NavigationPermissions,
) -> SettingsNavigation<'a> {
    let base = format!("/-/org/{org_slug}/caches/{cache_slug}");
    navigation_from_specs(
        &base,
        cache_slug.to_string(),
        active,
        CACHE_PAGES,
        CachePage::as_str,
        |spec| permissions.contains(&spec.permission),
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
    cache: &BinaryCache,
    active: &str,
    content: &str,
    permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let body = settings_layout(
        &cache_settings_navigation(org_slug, &cache.slug, active, permissions),
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
/// The default `overview` section is read-only. General policy, access,
/// delivery routes, cache placements, and destructive operations each render
/// in their own destination while sharing one navigation model.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn registry_settings_page(
    email: &str,
    registry: &RegistryRecord,
    csrf: &str,
    placements: &[PlacementOverviewRow],
    policies: &[PlacementPolicyOverviewRow],
    equivalences: &[PlacementEquivalenceOverviewRow],
    can_delete: bool,
    result: Option<&str>,
    // Which registry settings section to render. `overview` is the read-only
    // landing page; mutations live under General, Storage, Serving, and Danger.
    active: &str,
    navigation_permissions: &NavigationPermissions,
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
        let storage_label = placements
            .first()
            .map_or("unplaced", |placement| placement.binding_name.as_str());
        let _ = write!(body, "<h1>Registry · {slug}</h1>\n<p class=\"chips\"><span class=\"chip\">{visibility}</span><span class=\"chip\">{crawl}</span></p>\n<div class=\"settings-overview-grid\">", slug=escape(slug), visibility=escape(&registry.visibility), crawl=escape(&registry.crawl_policy));
        let base = format!("/{slug}/-/settings");
        for spec in REGISTRY_PAGES.iter().filter(|spec| {
            navigation_permissions.contains(&spec.permission)
                && matches!(
                    spec.key,
                    RegistryPage::Placements
                        | RegistryPage::DeliveryRoutes
                        | RegistryPage::CacheStack
                        | RegistryPage::Access
                )
        }) {
            let value = match spec.key {
                RegistryPage::Placements => storage_label,
                RegistryPage::DeliveryRoutes => "review routes",
                RegistryPage::CacheStack => "review stack",
                RegistryPage::Access => registry.visibility.as_str(),
                _ => "",
            };
            let _ = write!(body, "<a class=\"settings-overview-card\" href=\"{href}\"><strong>{value}</strong><span>{label}</span></a>", href=escape(&spec.href(&base)), value=escape(value), label=escape(spec.label));
        }
        body.push_str("</div>\n");
        body.push_str(&placement_overview(placements));
    }

    // -- Access: read-only until the console owns a sealed plan/apply flow ---
    if active == "access" {
        body.push_str("<h2>Visibility</h2>\n");
        let _ = writeln!(
            body,
            "<p>current <strong>{}</strong></p>",
            escape(&registry.visibility),
        );
        body.push_str(
            "<p class=\"dim\"><strong>public</strong> exposes every package and channel to anonymous consumers; \
         <strong>private</strong> breaks anonymous reads (consumers need a read token).</p>\n",
        );

        // Crawl policy: the generated robots.txt posture for this registry.
        body.push_str("<h2>Crawl policy</h2>\n");
        let _ = writeln!(
            body,
            "<p>current <strong>{}</strong></p>",
            escape(&registry.crawl_policy),
        );
        body.push_str(
            "<p class=\"dim\">Registry configuration changes require a sealed plan and exact resource version. \
             Use the Registry API or CLI until this page exposes that review step.</p>\n",
        );
    }

    // -- Placement inventory ------------------------------------------------
    if active == "placements" {
        body.push_str(&placement_overview(placements));
        body.push_str(&placement_plan_actions(
            placements,
            csrf,
            &format!("/{slug}/-/settings/placements"),
        ));
    }

    if active == "placement-policies" {
        body.push_str(&placement_policy_overview(policies, &[]));
    }

    if active == "placement-equivalences" {
        body.push_str(&placement_policy_overview(&[], equivalences));
    }

    if active == "cache-stack" {
        body.push_str(
            "<p class=\"dim\">The ordered consumer cache stack is signed registry configuration. Editing it creates a reviewable registry change request; retention and population remain independent cache-owned resources.</p>\n",
        );
        let _ = write!(
            body,
            "<p><a href=\"/{}/-/settings/configuration\">Edit signed configuration</a></p>",
            escape(slug)
        );
    }

    if active == "retention-consumers" {
        body.push_str(
            "<p class=\"dim\">Caches that retain signed versions from this registry appear here. The cache owns each subscription and its bounded selector.</p>\n<p class=\"dim\">No retention consumers are currently visible.</p>\n",
        );
    }

    if active == "population-targets" {
        body.push_str(
            "<p class=\"dim\">Cache-owned population targets that react to this registry's publication events appear here. They are independent from retention and consumer advertisement.</p>\n<p class=\"dim\">No population targets are currently visible.</p>\n",
        );
    }

    if active == "operations" {
        body.push_str(
            "<p class=\"dim\">Long-running topology and publication operations appear here \
             with their immutable plans, progress, and terminal outcomes.</p>\n",
        );
    }

    // -- Danger zone: remove the registry ------------------------------------
    if active == "danger" {
        if can_delete {
            body.push_str("<h2 class=\"danger\">Remove registry</h2>\n");
            let _ = write!(
                body,
                "<p class=\"dim\">Deleting <code>{slug}</code> requires a sealed Registry API \
                 plan and exact resource version. The physical surface remains independently \
                 managed by its placements.</p>\n",
                slug = escape(slug),
            );
        } else {
            body.push_str(
                "<p class=\"dim\">You do not have permission to remove this registry.</p>\n",
            );
        }
    }

    registry_settings_chrome(email, slug, active, &body, navigation_permissions, started)
}

/// The per-registry view of scoped access-token management.
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
    navigation_permissions: &NavigationPermissions,
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
                     action=\"/{slug}/-/settings/tokens/{id}/revoke\" style=\"display:inline\">{csrf}\
                     <button>revoke</button></form>",
                    slug = escape(slug),
                    csrf = csrf_field(csrf),
                    id = escape(id),
                );
                vec![
                    format!("<code>{}</code>", escape(id)),
                    escape(&perm_label),
                    revoke,
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
            "<p class=\"dim\">The reviewed token plan is scoped to this registry and \
             cannot exceed the selected owner's current grants.</p>\n",
        );
    } else {
        body.push_str("<p class=\"dim\">You need registry IAM administration authority to issue tokens.</p>\n");
    }

    registry_settings_chrome(
        email,
        slug,
        "tokens",
        &body,
        navigation_permissions,
        started,
    )
}

/// The channel rollout console.
///
/// Shows the partition grid using the consumer channel renderer. Mutation is
/// deliberately absent until channel advance has a normalized plan/apply API;
/// the hard-cut console never calls the former direct database/signing path.
#[must_use]
pub fn channel_console(
    email: &str,
    registry: &RegistryRecord,
    channel: &ChannelSummary,
    navigation_permissions: &NavigationPermissions,
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

    body.push_str(
        "<p class=\"dim\">Channel changes are read-only in the Web console until the normalized, reviewable channel plan/apply contract is available.</p>\n",
    );

    // Reuse the consumer channel grid renderer for the partition view.
    let grid = channel_grid_pre(channel);
    let _ = write!(body, "{grid}");

    registry_settings_chrome(
        email,
        slug,
        "channels",
        &body,
        navigation_permissions,
        started,
    )
}

/// One channel and its independently selected frontier-verification usage.
#[must_use]
pub struct ChannelSigningUsageRow {
    /// Stable channel name within the registry.
    pub name: String,
    /// Current typed usage, when configured.
    pub usage: Option<crate::db::SigningKeyUsageRecord>,
}

/// The registry signing topology and signed catalog roster page.
#[must_use]
pub fn keys_page(
    email: &str,
    registry: &RegistryRecord,
    csrf: &str,
    roster: &[(String, String, String)],
    signing_usage: Option<&crate::db::SigningKeyUsageRecord>,
    signing_keys: &[aos_proto_types::SigningKey],
    channel_usages: &[ChannelSigningUsageRow],
    can_manage: bool,
    page_number: usize,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    body.push_str(
        "<p class=\"dim\">Publication verification combines the signed catalog roster with an optional exact retained-key generation. The roster remains signed tree content; private key material never enters AOS Hub.</p>\n",
    );

    body.push_str("<h2>Publication key usage</h2>");
    if let Some(selected) = signing_usage {
        let _ = write!(
            body,
            "<p><code>{}</code> generation {} · {} · revision {}</p>",
            escape(&selected.signing_key_id),
            selected.signing_key_generation,
            escape(&selected.state),
            selected.resource_version
        );
        if selected.state == "active" && can_manage {
            let _ = write!(body, "<form class=\"console\" method=\"post\" action=\"/{}/-/settings/signing-keys\">{}<input type=\"hidden\" name=\"state\" value=\"detached\"><input type=\"hidden\" name=\"signing_key_stable_id\" value=\"{}\"><input type=\"hidden\" name=\"signing_key_generation\" value=\"{}\"><input type=\"hidden\" name=\"expected_resource_version\" value=\"{}\"><button class=\"danger\">Review detachment</button></form>", escape(slug), csrf_field(csrf), escape(&selected.signing_key_id), selected.signing_key_generation, selected.resource_version);
        }
    } else {
        body.push_str("<p class=\"dim\">No retained publication key is selected.</p>");
    }
    if can_manage {
        let options = signing_keys
            .iter()
            .filter_map(|key| {
                let generation = key.latest_generation.as_ref()?;
                (generation.state == "active").then(|| {
                    format!(
                        "<option value=\"{}:{}\">{} · generation {}</option>",
                        escape(&key.stable_id),
                        generation.generation,
                        escape(&key.name),
                        generation.generation
                    )
                })
            })
            .collect::<String>();
        if !options.is_empty() {
            let _ = write!(body, "<form class=\"console\" method=\"post\" action=\"/{}/-/settings/signing-keys\">{}<input type=\"hidden\" name=\"state\" value=\"active\"><label>Publication key <select name=\"key_generation\" required>{}</select></label><input type=\"hidden\" name=\"expected_resource_version\" value=\"{}\"><button>Review usage change</button></form>", escape(slug), csrf_field(csrf), options, signing_usage.map_or_else(|| "absent".to_string(), |usage| usage.resource_version.to_string()));
        }
    }

    body.push_str("<h2>Channel frontier usages</h2><p class=\"dim\">Each channel may independently require one exact key generation for all frontier partitions.</p>");
    if channel_usages.is_empty() {
        body.push_str("<p class=\"dim\">No indexed channels.</p>");
    } else {
        for channel in channel_usages {
            let current = channel.usage.as_ref();
            let _ = write!(body, "<section><h3>{}</h3>", escape(&channel.name));
            if let Some(selected) = current {
                let _ = write!(
                    body,
                    "<p><code>{}</code> generation {} · {} · revision {}</p>",
                    escape(&selected.signing_key_id),
                    selected.signing_key_generation,
                    escape(&selected.state),
                    selected.resource_version
                );
                if selected.state == "active" && can_manage {
                    let _ = write!(body, "<form class=\"console\" method=\"post\" action=\"/{}/-/settings/signing-keys\">{}<input type=\"hidden\" name=\"purpose\" value=\"channel_frontier\"><input type=\"hidden\" name=\"channel_name\" value=\"{}\"><input type=\"hidden\" name=\"state\" value=\"detached\"><input type=\"hidden\" name=\"signing_key_stable_id\" value=\"{}\"><input type=\"hidden\" name=\"signing_key_generation\" value=\"{}\"><input type=\"hidden\" name=\"expected_resource_version\" value=\"{}\"><button class=\"danger\">Review detachment</button></form>", escape(slug), csrf_field(csrf), escape(&channel.name), escape(&selected.signing_key_id), selected.signing_key_generation, selected.resource_version);
                }
            } else {
                body.push_str("<p class=\"dim\">No retained frontier key selected.</p>");
            }
            if can_manage {
                let options = signing_keys
                    .iter()
                    .filter_map(|key| {
                        let generation = key.latest_generation.as_ref()?;
                        (generation.state == "active").then(|| {
                            format!(
                                "<option value=\"{}:{}\">{} · generation {}</option>",
                                escape(&key.stable_id),
                                generation.generation,
                                escape(&key.name),
                                generation.generation
                            )
                        })
                    })
                    .collect::<String>();
                if !options.is_empty() {
                    let _ = write!(body, "<form class=\"console\" method=\"post\" action=\"/{}/-/settings/signing-keys\">{}<input type=\"hidden\" name=\"purpose\" value=\"channel_frontier\"><input type=\"hidden\" name=\"channel_name\" value=\"{}\"><input type=\"hidden\" name=\"state\" value=\"active\"><label>Frontier key <select name=\"key_generation\" required>{}</select></label><input type=\"hidden\" name=\"expected_resource_version\" value=\"{}\"><button>Review channel usage</button></form>", escape(slug), csrf_field(csrf), escape(&channel.name), options, current.map_or_else(|| "absent".to_string(), |usage| usage.resource_version.to_string()));
                }
            }
            body.push_str("</section>");
        }
    }

    body.push_str("<h2>Signed catalog roster</h2>");

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
        body.push_str(&pager.nav(&format!("/{slug}/-/settings/signing-keys"), ""));
    }

    if can_manage {
        let _ = writeln!(
            body,
            "<p><a href=\"/{}/-/settings/signing-keys/rotate\">rotation wizard →</a></p>",
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
         roster edits as a <a href=\"/{slug}/-/settings/configuration\">config change request</a>.</p>",
        slug = escape(slug),
    );

    registry_settings_chrome(
        email,
        slug,
        "signing-keys",
        &body,
        navigation_permissions,
        started,
    )
}

/// The key rotation wizard page.
///
/// Explains the add → overlap → retire(`--vouched-by`) sequence and renders
/// the exact `apr keys add` / `apr keys retire` commands as prepared
/// operations (signing is client-side; there is no raw roster mutation).
#[must_use]
pub fn keys_rotate_page(
    email: &str,
    registry: &RegistryRecord,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
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
    registry_settings_chrome(
        email,
        slug,
        "signing-keys",
        &body,
        navigation_permissions,
        started,
    )
}

/// The organization-owned signing-key generation inventory and enrollment page.
#[must_use]
pub fn org_signing_keys_page(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    keys: &[aos_proto_types::SigningKey],
    notice: Option<&str>,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let org_slug = &org.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    body.push_str(
        "<p class=\"dim\">Signing keys contain public verification material only. Private keys \
         remain outside AOS Hub; each registry, cache, or channel usage pins an exact immutable \
         generation.</p>\n",
    );

    if let Some(notice) = notice {
        let _ = write!(body, "<p class=\"notice\">{}</p>\n", escape(notice));
    }

    if keys.is_empty() {
        body.push_str("<p class=\"dim\">No signing keys enrolled.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = keys
            .iter()
            .map(|k| {
                let actions = k.latest_generation.as_ref().map_or_else(
                    || "<span class=\"dim\">unavailable</span>".to_string(),
                    |generation| {
                        if generation.state != "active" {
                            return "<span class=\"dim\">retired</span>".to_string();
                        }
                        format!(
                            "<details><summary>Rotate</summary><form class=\"console\" method=\"post\" action=\"/-/org/{org}/signing-keys\">{csrf}<input type=\"hidden\" name=\"operation\" value=\"rotate\"><input type=\"hidden\" name=\"key_id\" value=\"{name}\"><input type=\"hidden\" name=\"expected_resource_version\" value=\"{version}\"><label>Ed25519 public key <input name=\"public_key\" required autocomplete=\"off\"></label><label>SHA-256 fingerprint <input name=\"public_key_fingerprint\" required autocomplete=\"off\"></label><button>Review rotation</button></form></details><form class=\"console\" method=\"post\" action=\"/-/org/{org}/signing-keys\">{csrf}<input type=\"hidden\" name=\"operation\" value=\"retire\"><input type=\"hidden\" name=\"key_id\" value=\"{name}\"><input type=\"hidden\" name=\"expected_resource_version\" value=\"{version}\"><button class=\"danger\">Review retirement</button></form>",
                            org = escape(org_slug),
                            csrf = csrf_field(csrf),
                            name = escape(&k.name),
                            version = escape(&k.resource_version),
                        )
                    },
                );
                vec![
                    escape(&k.name),
                    k.latest_generation.as_ref().map_or_else(
                        || "<span class=\"dim\">missing generation</span>".to_string(),
                        |generation| {
                            format!(
                                "<code>{}</code> · generation {} · {}",
                                escape(&generation.public_key_fingerprint),
                                generation.generation,
                                escape(&generation.state),
                            )
                        },
                    ),
                    actions,
                ]
            })
            .collect();
        body.push_str(&table(&["key", "latest generation", "lifecycle"], &rows));
    }

    let _ = write!(
        body,
        "<p><a href=\"/-/org/{}/signing-keys/new\">Enroll a signing key</a></p>",
        escape(org_slug)
    );

    org_settings_chrome(
        email,
        org_slug,
        "signing-keys",
        &body,
        navigation_permissions,
        started,
    )
}

/// The org webhooks inventory and sealed-workflow guidance.
///
/// A webhook `POST`s a signed JSON body to its URL for each subscribed event.
#[must_use]
pub fn org_webhooks_page(
    email: &str,
    org: &OrgRecord,
    _csrf: &str,
    webhooks: &[WebhookRecord],
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let org_slug = &org.slug;
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    body.push_str(
        "<p class=\"dim\">Each subscription receives an HMAC-SHA256-signed JSON \
         <code>POST</code> for the events you select (none selected means every event). \
         The delivery runtime resolves the configured immutable secret version only while \
         computing the <code>X-AOS-Signature</code> header.</p>\n",
    );
    let event_names = crate::webhook::SUPPORTED_EVENT_TYPES
        .iter()
        .map(|event| format!("<code>{}</code>", escape(event)))
        .collect::<Vec<_>>()
        .join(" ");
    let _ = write!(
        body,
        "<details><summary>Supported event filters</summary><p>{event_names}</p></details>\n"
    );

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
                vec![
                    format!("<code>{}</code>", escape(&w.url)),
                    events,
                    status,
                    format!("<code>{}</code>", escape(&w.secret_version_ref)),
                    ago(w.created_at),
                    w.resource_version.to_string(),
                ]
            })
            .collect();
        body.push_str(&table(
            &[
                "url",
                "events",
                "status",
                "secret version",
                "created",
                "version",
            ],
            &rows,
        ));
    }

    let _ = write!(
        body,
        "<p><a href=\"/-/org/{}/webhooks/new\">Add a webhook</a></p>",
        escape(org_slug)
    );

    org_settings_chrome(
        email,
        org_slug,
        "webhooks",
        &body,
        navigation_permissions,
        started,
    )
}

/// Renders the dedicated signing-key enrollment workflow.
#[must_use]
pub fn org_new_signing_key_page(
    email: &str,
    org: &OrgRecord,
    csrf: &str,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let body = format!(
        "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/signing-keys\">\n{csrf}\
         <input type=\"hidden\" name=\"operation\" value=\"enroll\">\
         <label>Name <input type=\"text\" name=\"key_id\" required placeholder=\"acme-release\"></label>\n\
         <label>Ed25519 public key <input type=\"text\" name=\"public_key\" required \
         autocomplete=\"off\" spellcheck=\"false\"></label>\n\
         <label>SHA-256 fingerprint <input type=\"text\" name=\"public_key_fingerprint\" \
         required autocomplete=\"off\" spellcheck=\"false\"></label>\n\
         <p class=\"dim\">Private key material remains in your external custody.</p>\n\
         <button>review enrollment</button>\n</form>\n",
        org = escape(&org.slug),
        csrf = csrf_field(csrf),
    );
    org_settings_chrome(
        email,
        &org.slug,
        "signing-keys",
        &body,
        navigation_permissions,
        started,
    )
}

/// Renders the dedicated webhook creation workflow.
#[must_use]
pub fn org_new_webhook_page(
    email: &str,
    org: &OrgRecord,
    _csrf: &str,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let body = format!(
        "<p>Webhook creation requires a sealed plan and explicit apply.</p>\n\
         <p class=\"dim\">Use <code>aos hub org webhook create {org} \
         --url https://ci.example.com/hooks/aos \
         --secret-version-ref vault://{org}/webhooks/ci/v1 \
         --credential-fingerprint &lt;sha256-hex&gt;</code>. The Hub persists only the \
         immutable provider reference; plaintext signing material is resolved inside the \
         delivery worker and never enters a plan or API response.</p>\n",
        org = escape(&org.slug),
    );
    org_settings_chrome(
        email,
        &org.slug,
        "webhooks",
        &body,
        navigation_permissions,
        started,
    )
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
    navigation_permissions: &NavigationPermissions,
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

    org_settings_chrome(
        email,
        org_slug,
        "sso",
        &body,
        navigation_permissions,
        started,
    )
}

/// The instance-scope settings sidebar.
fn instance_settings_navigation(active: &str) -> SettingsNavigation<'_> {
    SettingsNavigation::new(
        active,
        "Instance".to_string(),
        vec![
            SettingsNavGroup::new(
                "",
                vec![SettingsNavItem::new(
                    "overview",
                    "Overview",
                    "/-/instance".to_string(),
                )],
            ),
            SettingsNavGroup::new(
                "Infrastructure",
                vec![SettingsNavItem::new(
                    "storage",
                    "Storage bindings",
                    "/-/instance/storage-bindings".to_string(),
                )],
            ),
            SettingsNavGroup::new(
                "Access & trust",
                vec![SettingsNavItem::new(
                    "identity",
                    "Identity & signup",
                    "/-/instance/identity-and-signup".to_string(),
                )],
            ),
            SettingsNavGroup::new(
                "Policy",
                vec![SettingsNavItem::new(
                    "resource-defaults",
                    "Resource defaults",
                    "/-/instance/resource-defaults".to_string(),
                )],
            ),
            SettingsNavGroup::new(
                "Appearance",
                vec![SettingsNavItem::new(
                    "branding",
                    "Branding",
                    "/-/instance/branding".to_string(),
                )],
            ),
        ],
    )
}

/// Renders defaults applied only when new resources are created.
#[must_use]
pub fn instance_resource_defaults_page(
    email: &str,
    csrf: &str,
    settings: &crate::db::InstanceSettings,
    notice: Option<&str>,
    started: Instant,
) -> String {
    let mut body = String::new();
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    body.push_str("<p class=\"dim\">These values seed new surfaces. Existing placements and routes are never retargeted implicitly.</p>\n");
    let caches_public = if settings.caches_public {
        " checked"
    } else {
        ""
    };
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/instance/resource-defaults\">\n{csrf}\
         <label><span class=\"lbl\">show caches to logged-out visitors</span> \
         <input type=\"checkbox\" name=\"caches_public\" value=\"1\"{caches_public}> \
         <span class=\"dim\">off: cache inventories require login</span></label>\n\
         <button>save defaults</button>\n</form>\n",
        caches_public = caches_public,
        csrf = csrf_field(csrf),
    );
    instance_settings_chrome(email, "resource-defaults", &body, started)
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

/// Renders the instance operational overview.
#[must_use]
pub fn instance_overview_page(email: &str, notice: Option<&str>, started: Instant) -> String {
    let mut body = String::from(
        "<p class=\"dim\">Instance health, infrastructure defaults, and pending operations.</p>\n",
    );
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    instance_settings_chrome(email, "overview", &body, started)
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
    let lifetime = settings
        .session_lifetime_secs
        .map(|s| s.to_string())
        .unwrap_or_default();
    let _ = write!(
        body,
        "<h2>Signup &amp; identity</h2>\n\
         <form class=\"console\" method=\"post\" action=\"/-/instance/identity-and-signup\">{csrf}\
         <label><span class=\"lbl\">org signup{help}</span> <select name=\"signup_policy\">\
         <option value=\"invite_only\"{invite_sel}>invite only</option>\
         <option value=\"open\"{open_sel}>open</option></select></label>\n\
         <label><span class=\"lbl\">signup domain allowlist{domains_help}</span> \
         <input type=\"text\" name=\"signup_domains\" value=\"{domains}\" \
         placeholder=\"acme.com, example.org\"> \
         <span class=\"dim\">comma-separated; empty allows any domain</span></label>\n\
         <label><span class=\"lbl\">offer password login{pw_help}</span> \
         <input type=\"checkbox\" name=\"password_login\" value=\"1\"{pw}></label>\n\
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
    instance_settings_chrome(email, "identity", &body, started)
}

/// The instance-settings "Branding" page (instance admins only): the site
/// title, tagline, announcement banner, and footer legal/contact links.
///
/// All are database-backed and editable here; the deploy only seeds initial values.
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

/// Renders the deployment-provisioned default storage binding.
#[must_use]
pub fn instance_storage_page(
    email: &str,
    default_storage_location: Option<&str>,
    binding: Option<&StorageBindingRecord>,
    notice: Option<&str>,
    started: Instant,
) -> String {
    // The shared settings layout supplies the contextual page heading.
    let mut body = String::new();
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    let location = match default_storage_location {
        Some(loc) if !loc.trim().is_empty() => format!("<code>{}</code>", escape(loc)),
        _ => "<span class=\"dim\">configured at deploy time</span>".to_string(),
    };
    body.push_str(
        "<p class=\"dim\">The deployment provisions this singleton binding. Surfaces use it only through explicit placements. Delivery endpoints and storage gateways remain independent topology resources.</p>\n",
    );
    match binding {
        Some(binding) => {
            let _ = writeln!(
                body,
                "<p>binding <strong>{}</strong> · kind <span class=\"chip\">{}</span> · location {location}</p>",
                escape(&binding.name),
                escape(&binding.kind),
                location = location,
            );
        }
        None => body.push_str(
            "<p class=\"dim\">The instance default binding has not been seeded yet (run \
             <code>aos-hub init</code> to apply the latest migrations).</p>\n",
        ),
    }
    instance_settings_chrome(email, "storage", &body, started)
}

fn binding_settings_navigation<'a>(
    org_slug: &str,
    stable_id: &str,
    active: &'a str,
    permissions: &NavigationPermissions,
) -> SettingsNavigation<'a> {
    navigation_from_specs(
        &format!("/-/org/{org_slug}/storage-bindings/{stable_id}"),
        stable_id.to_string(),
        active,
        BINDING_PAGES,
        BindingPage::as_str,
        |spec| permissions.contains(&spec.permission),
    )
}

/// Renders one organization storage-binding section in its scoped settings shell.
pub fn org_binding_page(
    email: &str,
    org_slug: &str,
    csrf: &str,
    binding: &StorageBindingReadDetail,
    managed_binding: Option<&StorageBindingRecord>,
    credentials: &[StorageBindingCredentialRevisionRecord],
    write_revisions: &[(
        StorageBindingWriteRevisionRecord,
        Option<StorageBindingWriteObservationRecord>,
    )],
    grants: &[(ConsumerScopeGrantRecord, Vec<String>)],
    can_manage_binding: bool,
    notice: Option<&str>,
    active: &str,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let mut body = format!("<h1>Storage binding · {}</h1>\n", escape(&binding.name));
    if let Some(notice) = notice {
        let _ = writeln!(
            body,
            "<p class=\"notice\" role=\"status\">{}</p>",
            escape(notice)
        );
    }

    if active == "overview" {
        body.push_str("<h2>Provider identity</h2>\n");
        let _ = write!(
            body,
            "<dl><dt>stable id</dt><dd><code>{}</code></dd>\
             <dt>owner scope</dt><dd><code>{}</code></dd>\
             <dt>provider</dt><dd><span class=\"chip\">{}</span></dd>",
            escape(&binding.stable_id),
            escape(&binding.owner_scope_key),
            escape(&binding.kind),
        );
        if let Some(provider) = managed_binding {
            let location = provider
                .local_root_path
                .as_deref()
                .or(provider.object_bucket.as_deref())
                .unwrap_or("unconfigured");
            let _ = write!(
                body,
                "<dt>location</dt><dd><code>{}</code></dd>",
                escape(location),
            );
            if let Some(prefix) = provider.object_prefix.as_deref() {
                let _ = write!(
                    body,
                    "<dt>object prefix</dt><dd><code>{}</code></dd>",
                    escape(prefix)
                );
            }
            if let Some(region) = provider.signing_region.as_deref() {
                let _ = write!(
                    body,
                    "<dt>signing region</dt><dd><code>{}</code></dd>",
                    escape(region)
                );
            }
            if let Some(access) = provider.access_mode.as_deref() {
                let _ = write!(body, "<dt>access</dt><dd>{}</dd>", escape(access));
            }
        } else {
            body.push_str(
                "<dt>provider configuration</dt><dd><span class=\"dim\">hidden · storage management required</span></dd>",
            );
        }
        let _ = write!(
            body,
            "<dt>resource version</dt><dd>{}</dd></dl>",
            binding.resource_version,
        );
        if can_manage_binding {
            body.push_str("<p class=\"dim\">Provider identity is immutable. Replace the binding and migrate placements explicitly to change its provider configuration.</p>\n");
        } else {
            body.push_str("<p class=\"dim\">Provider identity is immutable. Storage management authority is required to inspect provider configuration.</p>\n");
        }
    }

    if active == "credentials" && can_manage_binding {
        body.push_str("<p class=\"dim\">Each purpose rotates independently and stores only an immutable secret-version reference. Delete authority is never implied by write authority.</p>\n");
        if credentials.is_empty() {
            body.push_str("<p class=\"dim\">No topology-managed credentials are configured.</p>\n");
        } else {
            let rows = credentials
                .iter()
                .map(|credential| {
                    vec![
                        escape(&credential.purpose),
                        credential.generation.to_string(),
                        format!("<code>{}</code>", escape(&credential.secret_version_ref)),
                        escape(&credential.validation_state),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &["purpose", "generation", "secret version ref", "validation"],
                &rows,
            ));
        }
        let supported = managed_binding.is_some_and(|provider| {
            matches!(provider.kind.as_str(), "s3" | "r2")
                && provider.access_mode.as_deref() == Some("private")
        });
        let missing = ["read", "write", "delete", "list", "presign"]
            .into_iter()
            .filter(|purpose| {
                !credentials
                    .iter()
                    .any(|credential| credential.purpose == *purpose)
            })
            .map(|purpose| format!("<option>{}</option>", escape(purpose)))
            .collect::<String>();
        if supported && !missing.is_empty() {
            let _ = write!(body,
                "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/storage-bindings/{binding}/credentials/plan-set\">{csrf}<fieldset><legend>Set a purpose credential</legend><input type=\"hidden\" name=\"expected_resource_version\" value=\"{version}\"><label>purpose <select name=\"purpose\">{missing}</select></label><label>secret version reference <input name=\"secret_version_ref\" required></label><label>SHA-256 fingerprint <input name=\"credential_fingerprint\" required></label><button>Review initial credential</button></fieldset></form>\n",
                org=escape(org_slug), binding=escape(&binding.stable_id), csrf=csrf_field(csrf), version=binding.resource_version);
        }
        for credential in credentials.iter().filter(|_| supported) {
            let _ = write!(body,
                "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/storage-bindings/{binding}/credentials/plan-rotate\">{csrf}<fieldset><legend>Rotate {purpose}</legend><input type=\"hidden\" name=\"purpose\" value=\"{purpose}\"><input type=\"hidden\" name=\"expected_resource_version\" value=\"{version}\"><input type=\"hidden\" name=\"expected_current_generation\" value=\"{generation}\"><label>new secret version reference <input name=\"secret_version_ref\" required></label><label>SHA-256 fingerprint <input name=\"credential_fingerprint\" required></label><button>Review rotation</button></fieldset></form>\n",
                org=escape(org_slug), binding=escape(&binding.stable_id), csrf=csrf_field(csrf), purpose=escape(&credential.purpose), version=binding.resource_version, generation=credential.generation);
        }
        if !supported {
            body.push_str("<p class=\"dim\">Topology-managed credentials apply only to private S3 and R2 bindings.</p>\n");
        }
    }
    if active == "credentials" && !can_manage_binding {
        body.push_str(
            "<p class=\"dim\">Credential metadata is hidden · storage management required.</p>\n",
        );
    }

    if active == "write-revisions" {
        body.push_str("<p class=\"dim\">Placements and write authority pin an exact validated revision; credential rotation never moves existing writers.</p>\n");
        if write_revisions.is_empty() {
            body.push_str("<p class=\"dim\">No write revision has been created.</p>\n");
        } else {
            let rows = write_revisions
                .iter()
                .map(|(revision, observation)| {
                    let validation = observation
                        .as_ref()
                        .map(|observation| observation.state.as_str())
                        .unwrap_or("unknown");
                    let contract = if revision.conditional_writes_supported {
                        "write + conditional"
                    } else if revision.writes_supported {
                        "write"
                    } else {
                        "read-only"
                    };
                    vec![
                        revision.revision.to_string(),
                        format!(
                            "<code>{}#{}</code>",
                            escape(&revision.write_credential_purpose),
                            revision.write_credential_generation
                        ),
                        contract.to_string(),
                        escape(validation),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &["revision", "credential", "write contract", "validation"],
                &rows,
            ));
        }
    }

    if active == "consumer-grants" {
        if grants.is_empty() {
            body.push_str("<p class=\"dim\">No consumer scopes have access to this binding.</p>\n");
        } else {
            let rows = grants
                .iter()
                .map(|(grant, pins)| {
                    vec![
                        format!("<code>{}</code>", escape(&grant.consumer_scope_key)),
                        escape(&grant.grant_kind),
                        grant.grant_generation.to_string(),
                        escape(&grant.state),
                        pins.len().to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            body.push_str(&table(
                &["consumer scope", "kind", "generation", "state", "live pins"],
                &rows,
            ));
        }
        let _ = write!(body,
            "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/storage-bindings/{binding}/consumer-grants/plan-grant\">{csrf}<fieldset><legend>Grant a consumer scope</legend><input type=\"hidden\" name=\"resource_generation\" value=\"{version}\"><label>consumer scope <input name=\"consumer_scope_key\" required placeholder=\"org:…\"></label><button>Review consumer grant</button></fieldset></form>\n",
            org=escape(org_slug), binding=escape(&binding.stable_id), csrf=csrf_field(csrf), version=binding.resource_version);
        for (grant, pins) in grants.iter().filter(|(grant, _)| grant.state == "active") {
            if !pins.is_empty() {
                let _ = write!(body, "<aside class=\"warn\"><strong>{scope} cannot be revoked.</strong><p>The typed impact plan reports these live pins:</p><ul>{pins}</ul></aside>\n", scope=escape(&grant.consumer_scope_key), pins=pins.iter().map(|pin| format!("<li><code>{}</code></li>", escape(pin))).collect::<String>());
                continue;
            }
            let _ = write!(body,
                "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/storage-bindings/{binding}/consumer-grants/plan-revoke\">{csrf}<fieldset><legend>Revoke {scope}</legend><input type=\"hidden\" name=\"resource_generation\" value=\"{binding_version}\"><input type=\"hidden\" name=\"consumer_scope_key\" value=\"{scope}\"><input type=\"hidden\" name=\"expected_resource_version\" value=\"{version}\"><button class=\"danger\">Review revocation</button></fieldset></form>\n",
                org=escape(org_slug), binding=escape(&binding.stable_id), csrf=csrf_field(csrf), binding_version=binding.resource_version, scope=escape(&grant.consumer_scope_key), version=grant.resource_version);
        }
    }

    if active == "placements" {
        body.push_str("<p>Placements that pin this binding and an exact write revision appear here.</p>\n<p class=\"dim\">No placement backlinks are currently visible.</p>\n");
    }
    if active == "storage-gateways" {
        let _ = write!(body, "<p>Direct HTTP publication is configured through <a href=\"/-/org/{}/storage-gateways\">storage gateways</a>. Hub-proxied routes remain owned by each registry or cache.</p>\n", escape(org_slug));
    }
    if active == "danger" {
        body.push_str("<p class=\"warn\">Deletion requires a sealed impact plan, an exact resource version, and zero unresolved placement or gateway pins.</p>\n");
    }

    let nav =
        binding_settings_navigation(org_slug, &binding.stable_id, active, navigation_permissions);
    let content = settings_layout(&nav, &body);
    page_with_session(
        &format!("storage binding {}", binding.name),
        &[
            (format!("/-/org/{org_slug}"), org_slug.to_string()),
            (
                format!("/-/org/{org_slug}/storage-bindings"),
                "storage bindings".to_string(),
            ),
            (String::new(), binding.name.clone()),
        ],
        &content,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// Renders the registry's delivery-route inventory independently of mirroring.
#[must_use]
pub fn registry_delivery_page(
    email: &str,
    registry: &RegistryRecord,
    routes: &[DeliveryRouteOverviewRow],
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let mut body = String::from(
        "<p class=\"dim\">Every enabled route remains independently usable. Canonical \
         Git, cache, and web audiences are selected explicitly.</p>\n",
    );
    let slug = &registry.slug;
    body.push_str(&delivery_local_navigation(
        &format!("/{slug}/-/settings/delivery-routes"),
        "routes",
    ));
    body.push_str(&delivery_route_inventory(routes));
    registry_settings_chrome(
        email,
        slug,
        "delivery-routes",
        &body,
        navigation_permissions,
        started,
    )
}

/// Renders exact canonical audience selections independently from route rows.
#[must_use]
pub fn registry_canonical_audiences_page(
    email: &str,
    registry: &RegistryRecord,
    routes: &[DeliveryRouteOverviewRow],
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let mut body = String::from(
        "<p class=\"dim\">Each audience selects one exact enabled route. Other routes remain simultaneously usable.</p>\n",
    );
    body.push_str(&delivery_local_navigation(
        &format!("/{slug}/-/settings/delivery-routes"),
        "audiences",
    ));
    body.push_str(&canonical_audience_inventory(routes));
    registry_settings_chrome(
        email,
        slug,
        "delivery-routes",
        &body,
        navigation_permissions,
        started,
    )
}

/// Renders upstream synchronization separately from client delivery.
#[must_use]
pub fn registry_upstream_mirror_page(
    email: &str,
    registry: &RegistryRecord,
    mirror: Option<&MirrorSource>,
    navigation_permissions: &NavigationPermissions,
    started: Instant,
) -> String {
    let mut body = String::from(
        "<p class=\"dim\">Upstream mirroring imports registry content. It does not \
         configure any client-facing delivery route.</p>\n",
    );
    if let Some(mirror) = mirror {
        let _ = write!(
            body,
            "<dl><dt>source</dt><dd><code>{}</code></dd><dt>mode</dt><dd>{}</dd>\
             <dt>schedule</dt><dd>every {} seconds</dd></dl>",
            escape(&mirror.upstream_url),
            escape(&mirror.mode),
            mirror.schedule_secs,
        );
    } else {
        body.push_str("<p class=\"dim\">No upstream mirror is configured.</p>\n");
    }
    registry_settings_chrome(
        email,
        &registry.slug,
        "upstream-mirror",
        &body,
        navigation_permissions,
        started,
    )
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
    navigation_permissions: &NavigationPermissions,
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
    let content = settings_layout(
        &registry_settings_navigation(slug, "publish-history", navigation_permissions),
        &body,
    );
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
pub fn grants_allow(
    grants: &[(Scope, Role)],
    perm: Permission,
    context: &iam::AuthorizationContext,
) -> bool {
    iam::allow(grants, perm, context)
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
    navigation_permissions: &NavigationPermissions,
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
             <p><a href=\"/{}/-/settings/change-requests\">view change requests</a></p>\n",
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
            "<form class=\"console\" method=\"post\" action=\"/{}/-/settings/configuration\">\n{}\
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

    registry_settings_chrome(
        email,
        slug,
        "configuration",
        &body,
        navigation_permissions,
        started,
    )
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

/// The auto-generated structured config-edit page (`/{slug}/-/settings/configuration`).
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
    result: Option<(&str, &str)>,
    navigation_permissions: &NavigationPermissions,
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
             <p><a href=\"/{}/-/settings/change-requests\">view change requests</a></p>\n",
            escape(change_id),
            escape(merge_command),
            escape(slug),
        );
    }

    if !can_edit {
        body.push_str(
            "<p class=\"dim\">You need <code>registry.configure</code> to propose a change.</p>\n",
        );
        return registry_settings_chrome(
            email,
            slug,
            "configuration",
            &body,
            navigation_permissions,
            started,
        );
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

    let _ = write!(
        body,
        "<form class=\"console\" data-config-form method=\"post\" \
         action=\"/{slug}/-/settings/configuration\">\n{csrf}\
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
        cache_stack_note = cache_stack_note,
    );

    registry_settings_chrome(
        email,
        slug,
        "configuration",
        &body,
        navigation_permissions,
        started,
    )
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
    navigation_permissions: &NavigationPermissions,
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
         <a class=\"button\" href=\"/{slug}/-/settings/configuration\">Propose a change</a></div>\n",
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
            "<a class=\"tab{active}\"{current} href=\"/{slug}/-/settings/change-requests?state={state}\">{label} \
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
        body.push_str(
            "<div class=\"table-scroll\" role=\"region\" aria-label=\"Scrollable change requests table\" tabindex=\"0\"><table class=\"change-table\">\n<caption class=\"visually-hidden\">Change requests</caption><thead class=\"visually-hidden\"><tr><th scope=\"col\">Status</th><th scope=\"col\">Change request</th></tr></thead><tbody>\n",
        );
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
                 <a href=\"/{slug}/-/settings/change-requests/{id}\">{title}</a>{comments}<br>\
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
        body.push_str("</tbody>\n</table></div>\n");
    }

    registry_settings_chrome(
        email,
        slug,
        "change-requests",
        &body,
        navigation_permissions,
        started,
    )
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
    navigation_permissions: &NavigationPermissions,
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
             href=\"/{slug}/-/settings/change-requests/{id}?view={view_slug}\">{label}{badge}</a>\n",
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

    registry_settings_chrome(
        email,
        slug,
        "change-requests",
        &body,
        navigation_permissions,
        started,
    )
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
             action=\"/{slug}/-/settings/change-requests/{id}/comment\">{csrf}\
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
             action=\"/{slug}/-/settings/change-requests/{id}/review\">{csrf}\
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
             action=\"/{slug}/-/settings/change-requests/{id}/{action}\">{csrf}\
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

    fn all_navigation_permissions() -> NavigationPermissions {
        ORG_PAGES
            .iter()
            .map(|page| page.permission)
            .chain(REGISTRY_PAGES.iter().map(|page| page.permission))
            .chain(CACHE_PAGES.iter().map(|page| page.permission))
            .chain(BINDING_PAGES.iter().map(|page| page.permission))
            .collect()
    }

    fn assert_one_current_per_navigation(html: &str) {
        for navigation in html.split("<nav ").skip(1) {
            let navigation = navigation.split("</nav>").next().unwrap_or(navigation);
            assert!(
                navigation.matches("aria-current=\"page\"").count() <= 1,
                "one navigation set contains multiple current destinations: {navigation}",
            );
        }
    }

    #[test]
    fn scoped_settings_navigation_is_grouped_overview_first_and_single_current() {
        let navigations = [
            settings_layout(
                &org_settings_navigation("acme", "overview", &all_navigation_permissions()),
                "",
            ),
            settings_layout(
                &registry_settings_navigation(
                    "acme/main",
                    "overview",
                    &all_navigation_permissions(),
                ),
                "",
            ),
            settings_layout(
                &cache_settings_navigation(
                    "acme",
                    "build",
                    "overview",
                    &all_navigation_permissions(),
                ),
                "",
            ),
            settings_layout(&instance_settings_navigation("overview"), ""),
        ];
        for html in navigations {
            assert_eq!(html.matches("aria-current=\"page\"").count(), 1);
            assert_one_current_per_navigation(&html);
            assert!(html.find(">Overview</a>").unwrap() < html.find("settings-nav-label").unwrap());
            assert!(html.contains("class=\"settings-nav-group\""));
        }
        assert!(navigations_reject_an_undeclared_active_key());
    }

    #[test]
    fn settings_navigation_follows_the_shared_topological_group_order() {
        let org = settings_layout(
            &org_settings_navigation("acme", "overview", &all_navigation_permissions()),
            "",
        );
        assert_ordered(
            &org,
            &[
                ">Overview</a>",
                ">Resources</span>",
                ">Infrastructure</span>",
                ">Access &amp; trust</span>",
                ">Automation</span>",
                ">Activity</span>",
                ">Danger zone</a>",
            ],
        );
        assert_ordered(&org, &[">SSO</a>", ">Signing keys</a>"]);

        let registry = settings_layout(
            &registry_settings_navigation("acme/main", "overview", &all_navigation_permissions()),
            "",
        );
        assert_ordered(
            &registry,
            &[
                ">Overview</a>",
                ">Topology</span>",
                ">Cache relationships</span>",
                ">Publishing</span>",
                ">Access &amp; trust</span>",
                ">Activity</span>",
                ">Danger zone</a>",
            ],
        );

        let cache = settings_layout(
            &cache_settings_navigation("acme", "build", "overview", &all_navigation_permissions()),
            "",
        );
        assert_ordered(
            &cache,
            &[
                ">Overview</a>",
                ">Topology</span>",
                ">Relationships</span>",
                ">Content</span>",
                ">Access &amp; trust</span>",
                ">Lifecycle</span>",
                ">Activity</span>",
                ">Danger zone</a>",
            ],
        );
        assert!(cache.contains(">Objects &amp; closures</a>"));
        assert!(cache.contains(">Operations &amp; health</a>"));

        let instance = settings_layout(&instance_settings_navigation("overview"), "");
        assert_ordered(
            &instance,
            &[
                ">Overview</a>",
                ">Infrastructure</span>",
                ">Access &amp; trust</span>",
                ">Policy</span>",
                ">Appearance</span>",
            ],
        );
    }

    #[test]
    fn organization_navigation_omits_unreadable_sections_and_empty_groups() {
        let viewer = settings_layout(
            &org_settings_navigation(
                "acme",
                "overview",
                &[Permission::Read].into_iter().collect(),
            ),
            "",
        );
        for unavailable in [
            "/storage-bindings",
            "/domains",
            "/network-boundaries",
            "/delivery-endpoints",
            "/storage-gateways",
            "/topology-defaults",
            "/sso",
            "/signing-keys",
            "/webhooks",
            "/audit-log",
            "/danger",
        ] {
            assert!(!viewer.contains(unavailable), "viewer sees {unavailable}");
        }
        assert!(!viewer.contains(">Automation</span>"));
        assert_eq!(viewer.matches("aria-current=\"page\"").count(), 1);
    }

    #[test]
    fn every_scope_filters_navigation_by_exact_permission_without_url_leaks() {
        let read_only = [Permission::Read].into_iter().collect();
        let registry = settings_layout(
            &registry_settings_navigation("acme/main", "overview", &read_only),
            "",
        );
        for hidden in [
            "/placement-policies",
            "/delivery-routes",
            "/configuration",
            "/signing-keys",
            "/tokens",
            "/danger",
        ] {
            assert!(!registry.contains(hidden), "registry leaked {hidden}");
        }

        let cache = settings_layout(
            &cache_settings_navigation("acme", "build", "overview", &read_only),
            "",
        );
        for hidden in [
            "/placements",
            "/delivery-routes",
            "/signing-key",
            "/garbage-collection",
            "/danger",
        ] {
            assert!(!cache.contains(hidden), "cache leaked {hidden}");
        }

        let binding_read = [Permission::StorageBindingRead].into_iter().collect();
        let binding = settings_layout(
            &binding_settings_navigation("acme", "binding-1", "overview", &binding_read),
            "",
        );
        for hidden in [
            "/credentials",
            "/write-revisions",
            "/consumer-grants",
            "/placements",
            "/storage-gateways",
            "/danger",
        ] {
            assert!(!binding.contains(hidden), "binding leaked {hidden}");
        }

        for html in [&registry, &cache, &binding] {
            assert_eq!(html.matches("aria-current=\"page\"").count(), 1);
            assert!(html.find(">Overview</a>").is_some());
        }

        let privileged = all_navigation_permissions();
        let binding = settings_layout(
            &binding_settings_navigation("acme", "binding-1", "overview", &privileged),
            "",
        );
        assert!(binding.contains("/credentials"));
        assert!(binding.contains("/consumer-grants"));
        assert!(binding.contains("/danger"));
        assert_eq!(binding.matches("aria-current=\"page\"").count(), 1);
    }

    fn assert_ordered(haystack: &str, needles: &[&str]) {
        let mut cursor = 0;
        for needle in needles {
            let offset = haystack[cursor..]
                .find(needle)
                .unwrap_or_else(|| panic!("missing navigation fragment: {needle}"));
            cursor += offset + needle.len();
        }
    }

    #[test]
    fn settings_navigation_supplies_one_contextual_h1_for_every_section() {
        let cases = [
            (
                settings_layout(
                    &org_settings_navigation(
                        "acme",
                        "storage-bindings",
                        &all_navigation_permissions(),
                    ),
                    "<p>body</p>",
                ),
                "<h1>Storage bindings · acme</h1>",
            ),
            (
                settings_layout(
                    &registry_settings_navigation(
                        "acme/main",
                        "delivery-routes",
                        &all_navigation_permissions(),
                    ),
                    "<p>body</p>",
                ),
                "<h1>Delivery routes · acme/main</h1>",
            ),
            (
                settings_layout(
                    &cache_settings_navigation(
                        "acme",
                        "build",
                        "retention-subscriptions",
                        &all_navigation_permissions(),
                    ),
                    "<p>body</p>",
                ),
                "<h1>Registry retention · build</h1>",
            ),
        ];
        for (html, heading) in cases {
            assert!(html.contains(heading), "missing {heading}");
            assert_eq!(html.matches("<h1").count(), 1);
        }

        let existing = settings_layout(
            &registry_settings_navigation("acme/main", "overview", &all_navigation_permissions()),
            "<h1>Registry · acme/main</h1>",
        );
        assert_eq!(existing.matches("<h1").count(), 1);
    }

    fn navigations_reject_an_undeclared_active_key() -> bool {
        let html = settings_layout(
            &cache_settings_navigation("acme", "build", "missing", &all_navigation_permissions()),
            "",
        );
        html.matches("aria-current=\"page\"").count() == 0
            && html.contains("Invalid settings destination")
    }

    fn cache() -> BinaryCache {
        BinaryCache {
            id: 1,
            stable_id: "cache:00000000000000000000000000000001".into(),
            scope_key: "cache:00000000000000000000000000000001".into(),
            owner_scope_key: "org:00000000000000000000000000000001".into(),
            org_id: Some(1),
            slug: "build".into(),
            name: "Build cache".into(),
            visibility: "public".into(),
            priority: 40,
            compression: "zstd".into(),
            want_mass_query: true,
            resource_version: 1,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
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
        let placements = [PlacementOverviewRow {
            name: "primary".into(),
            binding_name: "primary".into(),
            prefix: "caches/build".into(),
            role: "primary".into(),
            state: "ready".into(),
            desired_state: "active".into(),
            completeness: "complete".into(),
            read_enabled: true,
            desired_read_enabled: true,
            read_order: 0,
            write_enabled: true,
            desired_authority: true,
            observed_authority: true,
            desired_generation: Some(1),
            observed_generation: Some(1),
            authority_state: Some("ready".into()),
            resource_version: 1,
        }];
        let policies = [PlacementPolicyOverviewRow {
            id: "policy:primary".into(),
            name: "failover".into(),
            kind: "ordered_failover".into(),
            current_revision: Some(2),
            revision_count: 2,
            latest_state: Some("published".into()),
            current_digest: Some("sha256:policy".into()),
            resource_version: 3,
        }];
        let equivalences = [PlacementEquivalenceOverviewRow {
            id: "equivalence:primary-replica".into(),
            placement_a: "primary".into(),
            placement_b: "replica".into(),
            evidence_digest: "sha256:evidence".into(),
            state: "active".into(),
            resource_version: 1,
        }];
        let render = |active: &str| {
            cache_page(
                "a@b.com",
                "acme",
                "csrf-tok",
                &cache(),
                &placements,
                &policies,
                &equivalences,
                &[],
                &[],
                &[],
                &[],
                &usage(),
                true,
                None,
                &[],
                true,
                active,
                None,
                &all_navigation_permissions(),
                Instant::now(),
            )
        };

        // Every section renders inside the cache settings chrome. Overview is
        // the first destination and the only current item on the default page.
        let overview = render("overview");
        assert!(overview.contains("class=\"settings-nav\""));
        assert!(overview.contains("Registry retention"));
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
        assert!(
            overview.find(">Overview</a>").unwrap() < overview.find(">Placements</a>").unwrap()
        );

        // General owns mutable cache policy and no longer overloads Overview.
        let general = render("access");
        assert!(general.contains("<h1>Identity &amp; access · build</h1>"));
        assert!(general.contains("<h2>Cache policy</h2>"));
        assert!(general.contains("<button>Review policy update</button>"));
        assert!(general.contains("action=\"/-/org/acme/caches/build/access/plan-update\""));
        assert!(general.contains("name=\"expected_resource_version\""));
        assert!(general.contains("csrf-tok"));
        assert_eq!(general.matches("aria-current=\"page\"").count(), 1);
        assert!(general.contains("Placements"));
        assert!(general.contains("Delivery routes"));
        assert!(!general.contains("Change storage"));
        assert!(!general.contains("Bucket-direct serving"));

        // The base cache route is a read-only overview; its content never owns
        // a mutation form or points a form action back at the base route.
        assert!(!overview.contains("<form"));
        assert!(!overview.contains("action=\"/-/org/acme/caches/build\""));

        // Placement mutations and the immutable policy/equivalence inventories
        // share the topology section without collapsing their resource models.
        let storage = render("placements");
        assert!(storage.contains("placements/new"));
        assert!(!storage.contains("Selection policies"));
        assert!(render("placement-policies").contains("ordered_failover"));
        assert!(render("placement-equivalences").contains("sha256:evidence"));

        // Delivery is independent from storage and starts with an empty state.
        let serving = render("delivery-routes");
        assert!(serving.contains("No delivery routes"));
        assert!(!serving.contains("delivery/routes/new"));

        // Links tab: the link form (the `\"` guards against matching the
        // sidebar's `/links` tab href).
        let links = render("population-targets");
        assert!(!links.contains("<form"));

        // Retention is an independent typed resource inventory.
        let pins_tab = render("retention-subscriptions");
        assert!(pins_tab.contains("No retention subscriptions"));

        // Danger tab: the delete form, styled like the registry/org remove pages.
        let danger = render("danger");
        assert!(danger.contains("<h2 class=\"danger\">Delete cache</h2>"));
        assert!(danger.contains("/-/org/acme/caches/build/danger/plan-delete"));
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
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &usage(),
                false,
                None,
                &[],
                false,
                active,
                None,
                &all_navigation_permissions(),
                Instant::now(),
            )
        };
        // Overview remains useful to a plain member; General exposes no form.
        let overview = render("overview");
        assert!(overview.contains("Cache · build"));
        let general = render("access");
        assert!(!general.contains("<h2>Settings</h2>"));
        assert!(general.contains("requires cache administration"));
        // The privileged tabs show an admins-only notice, not the controls.
        let pins = render("retention-subscriptions");
        assert!(!pins.contains("<form"));
        assert!(pins.contains("No retention subscriptions"));
        assert!(!render("danger").contains("/caches/build/danger/plan-delete"));
        assert!(!render("population-targets").contains("<form"));
    }

    #[test]
    fn gc_notice_is_surfaced() {
        // A GC run returns to the Pins tab with its notice.
        let html = cache_page(
            "a@b.com",
            "acme",
            "csrf-tok",
            &cache(),
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            &usage(),
            true,
            None,
            &[],
            true,
            "retention-subscriptions",
            Some("Collected 5 objects, reclaimed 1.0 MiB (3 retained)."),
            &all_navigation_permissions(),
            Instant::now(),
        );
        assert!(html.contains("Collected 5 objects"));
        assert!(html.contains("No retention subscriptions"));
    }

    fn settings_registry() -> RegistryRecord {
        RegistryRecord {
            id: 1,
            stable_id: "registry:00000000000000000000000000000001".into(),
            scope_key: "registry:00000000000000000000000000000001".into(),
            owner_scope_key: "org:00000000000000000000000000000001".into(),
            slug: "demo".into(),
            trust_keys: vec![],
            require_signatures: true,
            org_id: Some(1),
            project_path: String::new(),
            visibility: "public".into(),
            crawl_policy: "allow_all".into(),
            llms_txt_body: None,
            resource_version: 1,
            updated_at: 0,
        }
    }

    #[test]
    fn registry_overview_and_access_keep_policy_mutation_in_reviewed_interfaces() {
        let render = |active: &str| {
            registry_settings_page(
                "a@b.com",
                &settings_registry(),
                "csrf-tok",
                &[],
                &[],
                &[],
                false,
                None,
                active,
                &all_navigation_permissions(),
                Instant::now(),
            )
        };
        let overview = render("overview");
        assert!(overview.contains("Registry · demo"));
        assert!(overview.contains("Physical placements"));
        assert!(!overview.contains("change visibility"));
        assert_eq!(overview.matches("aria-current=\"page\"").count(), 1);

        let general = render("access");
        assert!(general.contains("<h1>Identity &amp; access · demo</h1>"));
        assert!(general.contains("current <strong>public</strong>"));
        assert!(general.contains("current <strong>allow_all</strong>"));
        assert!(general.contains("Registry API or CLI"));
        assert!(general.contains("sealed plan and exact resource version"));
        assert!(!general.contains("<form"));
        assert!(!general.contains("Physical placements"));
        assert_eq!(general.matches("aria-current=\"page\"").count(), 1);

        let storage = render("placements");
        assert!(storage.contains("<h1>Placements · demo</h1>"));
    }

    #[test]
    fn registry_delivery_is_read_only_and_separate_from_mirroring() {
        let html = registry_delivery_page(
            "a@b.com",
            &settings_registry(),
            &[],
            &all_navigation_permissions(),
            Instant::now(),
        );
        assert!(html.contains("No delivery routes"));
        assert!(!html.contains("settings/delivery/routes/new"));
        assert!(html.contains("Upstream mirror"));
        assert!(!html.contains("No upstream mirror is configured"));
        assert!(!html.contains("<form"));
        assert_eq!(html.matches("aria-current=\"page\"").count(), 2);
        assert_one_current_per_navigation(&html);
    }

    fn org() -> OrgRecord {
        OrgRecord {
            id: 1,
            stable_id: "org:00000000000000000000000000000001".into(),
            slug: "acme".into(),
            name: "Acme Systems".into(),
            created_at: 1_700_000_000,
            resource_version: 1,
            updated_at: 1_700_000_000,
        }
    }

    fn storage_bindings() -> Vec<StorageBindingRecord> {
        vec![
            StorageBindingRecord {
                id: 10,
                stable_id: "binding-local-primary".into(),
                org_id: Some(1),
                name: "local-primary".into(),
                kind: "local_fs".into(),
                local_root_path: Some("/srv/private/acme".into()),
                is_instance_default: false,
                created_at: 1_700_000_000,
                ..StorageBindingRecord::default()
            },
            StorageBindingRecord {
                id: 11,
                stable_id: "binding-object-replica".into(),
                org_id: Some(1),
                name: "object-replica".into(),
                kind: "s3".into(),
                object_bucket: Some("private-bucket".into()),
                object_prefix: Some("tenant-prefix".into()),
                endpoint_scheme: Some("https".into()),
                endpoint_host_kind: Some("dns".into()),
                endpoint_host_bytes: Some(b"origin.internal.example".to_vec()),
                endpoint_port: Some(443),
                signing_region: Some("auto".into()),
                access_mode: Some("private".into()),
                ..StorageBindingRecord::default()
            },
        ]
    }

    fn render_org_storage(can_configure: bool, can_manage_storage: bool) -> String {
        let managed = storage_bindings();
        let summaries = managed
            .iter()
            .map(StorageBindingReadSummary::from)
            .collect::<Vec<_>>();
        org_dashboard(
            "viewer@acme.example",
            &org(),
            "csrf-tok",
            &[],
            &[],
            &[],
            &[],
            &summaries,
            can_manage_storage.then_some(managed.as_slice()),
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
            false,
            can_configure,
            can_manage_storage,
            false,
            1,
            1,
            1,
            "storage-bindings",
            &all_navigation_permissions(),
            Instant::now(),
        )
    }

    fn active_signing_key() -> aos_proto_types::SigningKey {
        aos_proto_types::SigningKey {
            stable_id: "signing-key:00000000000000000000000000000001".into(),
            scope_key: org().stable_id,
            name: "publication".into(),
            resource_version: "3".into(),
            latest_generation: Some(aos_proto_types::SigningKeyGeneration {
                generation: 2,
                algorithm: "ed25519".into(),
                public_key: "public".into(),
                public_key_fingerprint: "fingerprint".into(),
                custody: "external".into(),
                state: "active".into(),
                created_at: 1,
                retired_at: 0,
            }),
            created_at: 1,
            updated_at: 2,
        }
    }

    #[test]
    fn signing_settings_render_reviewed_generation_and_channel_controls() {
        let key = active_signing_key();
        let organization = org_signing_keys_page(
            "owner@example.com",
            &org(),
            "csrf-token",
            std::slice::from_ref(&key),
            None,
            &all_navigation_permissions(),
            Instant::now(),
        );
        assert!(organization.contains("name=\"operation\" value=\"rotate\""));
        assert!(organization.contains("name=\"operation\" value=\"retire\""));
        assert!(organization.contains("name=\"expected_resource_version\" value=\"3\""));

        let registry = keys_page(
            "owner@example.com",
            &settings_registry(),
            "csrf-token",
            &[],
            None,
            &[key],
            &[ChannelSigningUsageRow {
                name: "stable".into(),
                usage: None,
            }],
            true,
            1,
            &all_navigation_permissions(),
            Instant::now(),
        );
        assert!(registry.contains("name=\"purpose\" value=\"channel_frontier\""));
        assert!(registry.contains("name=\"channel_name\" value=\"stable\""));
        assert!(registry.contains("value=\"absent\""));
    }

    #[test]
    fn org_storage_redacts_locations_without_storage_manage() {
        // Deliberately grant registry configuration but not storage management:
        // the two permissions must not be conflated by the renderer.
        let redacted = render_org_storage(true, false);
        assert!(redacted.contains("<h1>Storage bindings · acme</h1>"));
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
        assert!(redacted.contains("/-/org/acme/storage-bindings/binding-local-primary"));
        assert!(!redacted.contains("/binding-local-primary/plan-delete"));

        let privileged = render_org_storage(false, true);
        assert!(privileged.contains("/srv/private/acme"));
        assert!(
            privileged.contains("https://origin.internal.example:443/private-bucket/tenant-prefix")
        );
        assert!(privileged.contains("/-/org/acme/storage-bindings/binding-local-primary"));
        assert!(privileged.contains("/binding-local-primary/plan-delete"));
        assert!(!privileged.contains("name=\"id\""));
        assert!(!privileged.contains("sealed:never-render"));
    }

    #[test]
    fn every_overflow_capable_table_is_named_and_keyboard_focusable() {
        let compact = table(&["name", "state"], &[vec!["cache".into(), "ready".into()]]);
        assert!(compact.contains("<caption class=\"visually-hidden\">name table</caption>"));
        assert!(compact.contains("aria-label=\"Scrollable name table\""));
        assert!(compact.contains("tabindex=\"0\""));
        assert!(compact.contains("role=\"region\""));

        let wide = table(
            &["cache", "visibility", "priority", "objects"],
            &[vec![
                "build".into(),
                "private".into(),
                "40".into(),
                "1".into(),
            ]],
        );
        assert!(wide.contains("aria-label=\"Scrollable cache table\""));
        assert!(wide.contains("tabindex=\"0\""));
        assert!(wide.contains("<th scope=\"col\">cache</th>"));

        let sortable = table_raw_headers(
            &["<a href=\"?sort=name\">name</a>".into(), "state".into()],
            &[vec!["build".into(), "ready".into()]],
        );
        assert!(sortable.contains("aria-label=\"Scrollable sortable data table\""));
        assert!(sortable.contains("tabindex=\"0\""));
        assert!(
            sortable.contains("<caption class=\"visually-hidden\">Sortable data table</caption>")
        );
        assert!(sortable.contains("<th scope=\"col\"><a href=\"?sort=name\">name</a></th>"));
    }

    #[test]
    fn change_request_table_has_a_keyboard_named_region_and_headers() {
        let html = changes_page(
            "maintainer@example.com",
            &settings_registry(),
            &[ChangeListRow {
                change_id: "0123456789abcdef".into(),
                title: "Update cache stack".into(),
                status: "draft".into(),
                closed: false,
                actor_label: "maintainer@example.com".into(),
                created_at: 0,
                comment_count: 0,
            }],
            ChangesFilter::Open,
            &all_navigation_permissions(),
            Instant::now(),
        );
        assert!(html.contains("aria-label=\"Scrollable change requests table\""));
        assert!(html.contains("tabindex=\"0\""));
        assert!(html.contains("<caption class=\"visually-hidden\">Change requests</caption>"));
        assert!(html.contains("<th scope=\"col\">Status</th>"));
        assert!(html.contains("<th scope=\"col\">Change request</th>"));
    }

    #[test]
    fn desktop_css_reopens_mobile_settings_navigation_without_javascript() {
        const STYLE: &str = include_str!("static_assets/style.css");
        assert!(STYLE.contains("@media (min-width: 48.0625rem)"));
        assert!(STYLE
            .contains(".settings-nav-disclosure:not([open]) > .settings-nav { display: flex; }"));
    }

    #[test]
    fn settings_route_matrix_uses_section_destinations() {
        let cache_nav = settings_layout(
            &cache_settings_navigation("acme", "build", "overview", &all_navigation_permissions()),
            "",
        );
        for route in [
            "/-/org/acme/caches/build",
            "/-/org/acme/caches/build/placements",
            "/-/org/acme/caches/build/delivery-routes",
            "/-/org/acme/caches/build/retention-subscriptions",
            "/-/org/acme/caches/build/population-targets",
            "/-/org/acme/caches/build/manual-roots",
            "/-/org/acme/caches/build/garbage-collection",
            "/-/org/acme/caches/build/access",
            "/-/org/acme/caches/build/danger",
        ] {
            assert!(cache_nav.contains(&format!("href=\"{route}\"")), "{route}");
        }

        let registry_nav = settings_layout(
            &registry_settings_navigation("acme/main", "overview", &all_navigation_permissions()),
            "",
        );
        for route in [
            "/acme/main/-/settings",
            "/acme/main/-/settings/access",
            "/acme/main/-/settings/placements",
            "/acme/main/-/settings/delivery-routes",
            "/acme/main/-/settings/upstream-mirror",
            "/acme/main/-/settings/cache-stack",
            "/acme/main/-/settings/danger",
        ] {
            assert!(
                registry_nav.contains(&format!("href=\"{route}\"")),
                "{route}"
            );
        }
    }

    #[test]
    fn passkey_continuation_cannot_terminate_its_script_element() {
        let html = login_page(
            None,
            Some("nonce"),
            Some("/</script><meta http-equiv=refresh content=0;url=//evil.test>"),
            Instant::now(),
        );
        assert!(!html.contains("</script><meta"));
        assert!(html.contains("\\u003c/script\\u003e\\u003cmeta"));
    }
}
