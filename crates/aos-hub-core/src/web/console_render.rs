//! Transport-neutral HTML rendering for the authenticated producer console.
//!
//! RFC-0004 Phase 5 (console-dedup) lifts the console's *foundation* — the
//! shared page chrome and every console page builder — out of the native
//! `aos-hub` crate so the Cloudflare Worker can eventually serve the
//! identical console from one code path. The builders are pure string-building
//! over the `aos.registry.v1` read shapes ([`crate::db`] record types) and the
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

use std::fmt::Write as _;
use std::sync::OnceLock;
use crate::binding::RuntimeKind;
use crate::clock::Instant;

use crate::db::{
    AuditRow, Cache, CacheUsage, ChangesetRow, ChannelSummary, FrontendRecord, HostedKeyRecord,
    IdpConfigRecord, IndexStatus, MirrorSource, OrgDomainRecord, OrgRecord, ProjectRecord,
    RegistryRecord, ReleaseRow, SignupPolicy, StorageBindingRecord, WebauthnCredentialRecord,
    WebhookRecord,
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

    /// Renders the indicator as the right-hand masthead HTML fragment.
    ///
    /// It always leads with a "registries" home link (so there is always a
    /// way back to the instance home). When signed in it continues as the
    /// primary navigation — the caller's organizations and account profile
    /// (the entry points to all management pages) plus the email and a
    /// log-out link; when anonymous it is the home link plus log-in.
    fn render(&self) -> String {
        match &self.email {
            Some(email) => format!(
                "<span class=\"session\">\
                 <a href=\"/\">registries</a> · \
                 <a href=\"/-/orgs\">organizations</a> · \
                 <a href=\"/account\">account</a> · \
                 <span class=\"who\">{}</span> · \
                 <a href=\"/logout\">log out</a></span>",
                escape(email),
            ),
            None => "<span class=\"session\">\
                     <a href=\"/\">registries</a> · \
                     <a href=\"/login\">log in</a></span>"
                .to_string(),
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

    // The brand is operator-configurable (default empty): when set it
    // leads the masthead and titles every page; when empty the crumbs lead.
    let brand_span = brand_span(brand());
    let page_title = page_title(brand(), title);

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>{page_title}</title>\n\
         <link rel=\"stylesheet\" href=\"/_assets/style.css?v={ver}\">\n\
         <script src=\"/_assets/app.js?v={ver}\" defer></script>\n</head>\n<body>\n\
         <header class=\"masthead\">{brand_span}\
         <span class=\"crumbs\">{crumb_html}</span>{session}</header>\n\
         <main>\n{body}\n</main>\n\
         <footer class=\"statline\">{statline}</footer>\n</body>\n</html>\n",
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
fn release_glyphs(channel: &ChannelSummary) -> (Vec<String>, std::collections::BTreeMap<String, usize>) {
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
/// `/account/passkeys/begin` for the options, runs the WebAuthn `create`
/// ceremony, base64url-encodes the response, and POSTs it to
/// `/account/passkeys/finish`; on success it reloads to show the new passkey.
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
    var opts=await (await fetch('/account/passkeys/begin',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf='+encodeURIComponent(csrf)})).json();
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
    var r=await fetch('/account/passkeys/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
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
                     action=\"/account/passkeys/remove\" style=\"display:inline\">{csrf}\
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
    let mut body = format!(
        "<h1>Account</h1>\n<p>signed in as <code>{}</code></p>\n",
        escape(email)
    );

    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }

    // Password: set one, or change an existing one. The CSRF-protected form
    // posts the new password to /account/password for the logged-in user.
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
    body.push_str("<form class=\"console\" method=\"post\" action=\"/account/password\">\n");
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
         <form class=\"console\" method=\"post\" action=\"/account/sessions/revoke-all\">\n",
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
         <a href=\"/account/passkeys\">Manage passkeys →</a></p>\n",
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
    let mut body = String::from("<h1>Organizations</h1>\n");
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
    /// This cache's URL is advertised in the registry's cache stack.
    pub advertised: bool,
    /// A non-blocking visibility warning for this link (e.g. a private
    /// registry's closures rooted into this more-visible cache), or `None`.
    pub warning: Option<String>,
}

/// A linked binary cache shown on a *registry's* settings page (the reverse of
/// [`CacheLinkRow`]).
pub struct RegistryCacheRow {
    /// The linked cache's slug.
    pub cache_slug: String,
    /// This cache is advertised in the registry's consumer cache stack.
    pub advertised: bool,
    /// The registry's live store paths pin GC roots in this cache.
    pub roots_packages: bool,
    /// Whether this cache *may* be advertised on the registry — false when the
    /// cache is less visible than the registry (its consumers couldn't read it),
    /// in which case the advertise toggle is greyed out.
    pub can_advertise: bool,
}

/// The org dashboard: projects, registries, members, bindings, audit link.
///
/// `can_manage_members` gates the member-management controls (invite/remove)
/// to admins; a viewer sees the lists without the forms. `can_configure` gates
/// the create affordances — the "create registry" link and the inline
/// create-project/create-binding forms — to a caller holding
/// `registry.configure`/`storage.manage` at the org scope. `can_delete` gates
/// the typed-confirmation org-delete form to an org owner. `owner_count` is the
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
    can_delete: bool,
    owner_count: usize,
    registries_page: usize,
    members_page: usize,
    // Which org section to render: `registries` (default), `caches`, or
    // `settings`. The overview was one dense page; it is now split across these
    // sidebar tabs so each view is focused.
    active: &str,
    started: Instant,
) -> String {
    // The registries and members lists each paginate independently; each
    // pager preserves the other list's page so navigating one keeps the other.
    let reg_pager = Pager::new(registries_page, LIST_PER_PAGE, registries.len());
    let mem_pager = Pager::new(members_page, LIST_PER_PAGE, members.len());
    let reg_keep = (mem_pager.page() > 1)
        .then(|| format!("members_page={}", mem_pager.page()))
        .unwrap_or_default();
    let mem_keep = (reg_pager.page() > 1)
        .then(|| format!("registries_page={}", reg_pager.page()))
        .unwrap_or_default();
    let slug = &org.slug;
    // The org's dense overview is now split across sidebar tabs: registries
    // (default), binary caches, and settings (projects/storage/members/danger).
    let section_label = match active {
        "caches" => "binary caches",
        "settings" => "settings",
        _ => "registries",
    };
    let mut body = format!(
        "<h1>{} · {}</h1>\n",
        escape(&org.name),
        escape(section_label)
    );
    let _ = writeln!(body, "<p class=\"dim\"><code>{}</code></p>", escape(slug));

    // -- Registries (the default tab) ----------------------------------------
    if active == "registries" {
        body.push_str("<h2>Registries</h2>\n");
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
                &format!("/-/org/{slug}"),
                &reg_keep,
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
        body.push_str("<h2>Binary caches</h2>\n");
        if caches.is_empty() {
            body.push_str("<p class=\"dim\">No binary caches.</p>\n");
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
            let mut binding_options =
                String::from("<option value=\"\">default storage</option>");
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

    // -- Settings: projects, storage, members, and the danger zone -----------
    if active != "settings" {
        return org_settings_chrome(email, slug, active, &body, started);
    }
    body.push_str("<h2>Projects</h2>\n");
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

    body.push_str("<h2>Storage</h2>\n");
    // The deployment's default storage is always present and is what new
    // registries use with no binding at all. Render it as the first row — a
    // `default` chip, no delete — so it is *apparent* that storage already works
    // and any custom binding is purely additive (no prose needed to say so). Its
    // concrete location is a deployment-global setting shown on instance
    // settings, so the location cell links there rather than repeating it.
    let mut rows: Vec<Vec<String>> = vec![vec![
        "<span class=\"chip\">default</span>".to_string(),
        escape(RuntimeKind::current().default_storage_kind()),
        "<a href=\"/-/instance#storage\">deployment default →</a>".to_string(),
        String::new(),
    ]];
    rows.extend(bindings.iter().map(|b| {
        let action = if can_configure {
            format!(
                "<form class=\"console\" method=\"post\" \
                 action=\"/-/org/{org}/bindings/delete\" style=\"display:inline\">{csrf}\
                 <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                 <button class=\"danger\">delete</button></form>",
                org = escape(slug),
                csrf = csrf_field(csrf),
                id = b.id,
            )
        } else {
            String::new()
        };
        let location = if b.kind == "local_fs" {
            format!("<code>{}</code>", escape(&b.root))
        } else {
            // Object store: show endpoint + bucket + access mode, never the
            // sealed credential.
            let endpoint = b.public_base_url.as_deref().unwrap_or("");
            format!(
                "<code>{endpoint}/{bucket}</code> · {access}",
                endpoint = escape(endpoint.trim_end_matches('/')),
                bucket = escape(&b.root),
                access = escape(&b.access),
            )
        };
        vec![escape(&b.name), escape(&b.kind), location, action]
    }));
    body.push_str(&table(&["name", "kind", "location", ""], &rows));
    if can_configure {
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
             <label>endpoint <input type=\"text\" name=\"endpoint\" \
             placeholder=\"https://&lt;account&gt;.r2.cloudflarestorage.com\"></label>\n\
             <label>region <input type=\"text\" name=\"region\" value=\"auto\"></label>\n\
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
        );
    }

    body.push_str("<h2>Members</h2>\n");
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
    body.push_str(&mem_pager.nav_with(&format!("/-/org/{slug}"), &mem_keep, "members_page"));

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
    }

    org_settings_chrome(email, slug, active, &body, started)
}

/// A managed binary cache's detail page: configuration, usage, linked
/// registries, and (for an admin) the update / link / GC / delete controls.
///
/// `can_admin` gates every mutating form; a plain member sees the read-only
/// configuration and usage. `linkable` is the org's registries available to link
/// (already-linked ones are omitted). `notice` renders the outcome of the last
/// action (e.g. a GC sweep summary).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn cache_page(
    email: &str,
    org_slug: &str,
    csrf: &str,
    cache: &Cache,
    binding_name: &str,
    bindings: &[String],
    usage: &CacheUsage,
    links: &[CacheLinkRow],
    linkable: &[(String, String)],
    can_admin: bool,
    notice: Option<&str>,
    started: Instant,
) -> String {
    let mut body = format!("<h1>Cache · {}</h1>\n", escape(&cache.slug));
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }

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

    // Surface location (admin-only detail — never the credential).
    if can_admin {
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

    if can_admin {
        // -- Settings --------------------------------------------------------
        body.push_str("<h2>Settings</h2>\n");
        let opt = |value: &str, current: &str, label: &str| {
            let sel = if value == current { " selected" } else { "" };
            format!("<option value=\"{value}\"{sel}>{label}</option>")
        };
        let mass = if cache.want_mass_query { " checked" } else { "" };
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}\">{csrf}\
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
    }

    // -- Linked registries ---------------------------------------------------
    body.push_str("<h2>Linked registries</h2>\n");
    if links.is_empty() {
        body.push_str("<p class=\"dim\">No linked registries.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = links
            .iter()
            .map(|l| {
                let mut flags: Vec<String> = Vec::new();
                if l.advertised {
                    flags.push("<span class=\"chip\">advertised</span>".to_string());
                }
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
        // Each registry option carries its visibility, and the form this cache's,
        // so the JS greys out advertise when the chosen registry is more visible
        // than the cache (its consumers couldn't read the cache) — the same rule
        // the server enforces.
        let mut reg_options = String::new();
        for (slug, vis) in linkable {
            let _ = write!(
                reg_options,
                "<option value=\"{s}\" data-visibility=\"{v}\">{s} · {v}</option>",
                s = escape(slug),
                v = escape(vis),
            );
        }
        let _ = write!(
            body,
            "<h3>Link a registry</h3>\n\
             <form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/link\" \
             data-cache-link data-cache-visibility=\"{cachevis}\">{csrf}\
             <label>registry <select name=\"registry\">{regs}</select></label>\n\
             <label><span class=\"lbl\">advertise to consumers{adv_help}</span> \
             <input type=\"checkbox\" name=\"advertised\" value=\"1\" checked></label>\n\
             <label><span class=\"lbl\">pin GC roots from its packages{roots_help}</span> \
             <input type=\"checkbox\" name=\"roots_packages\" value=\"1\" checked></label>\n\
             <button>link</button>\n</form>\n",
            org = escape(org_slug),
            slug = escape(&cache.slug),
            cachevis = escape(&cache.visibility),
            csrf = csrf_field(csrf),
            regs = reg_options,
            adv_help = help::marker("link.advertised"),
            roots_help = help::marker("link.roots_packages"),
        );
    }

    if can_admin {
        // -- Garbage collection ---------------------------------------------
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

        // -- Delete ----------------------------------------------------------
        body.push_str("<h2 class=\"danger\">Delete cache</h2>\n");
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/caches/{slug}/delete\">{csrf}\
             <label>type <code>{slug}</code> to confirm \
             <input type=\"text\" name=\"confirm\" autocomplete=\"off\"></label>\n\
             <button class=\"danger\">delete cache</button>\n</form>\n",
            org = escape(org_slug),
            slug = escape(&cache.slug),
            csrf = csrf_field(csrf),
        );
    }

    page_with_session(
        &format!("cache {}", cache.slug),
        &[
            ("/-/orgs".into(), "organizations".into()),
            (format!("/-/org/{org_slug}"), org_slug.to_string()),
            (String::new(), format!("cache {}", cache.slug)),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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
    let mut body = format!("<h1>Audit · {}</h1>\n", escape(&org.name));
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
         <label>prefix \
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

/// The per-registry settings / management landing page (`/{slug}/-/settings`).
///
/// The "manage this registry" hub: it shows the current visibility with a
/// change form (a confirmation-gated [`config::change_registry_visibility`]
/// change-set), the read-only storage binding/prefix and trust anchors, a link
/// hub to every per-registry management page (tokens, keys, channels, changes,
/// publishes, health, packages), and — for an org owner/admin — a
/// typed-confirmation delete form. `binding` is the resolved
/// `(name, root, prefix)` of the registry's storage binding, when bound.
/// `can_delete` gates the delete form. `result` echoes a just-applied
/// visibility change-set id.
///
/// [`config::change_registry_visibility`]: crate::config::change_registry_visibility
#[must_use]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
/// One entry in a settings left-sidebar nav.
///
/// The settings IA is uniform across the registry, org, and instance scopes
/// (RFC-0004 console): every management page in a scope renders the same
/// [`settings_layout`] with one of these marked active.
pub struct SettingsTab {
    /// The destination URL.
    pub href: String,
    /// The visible label.
    pub label: String,
    /// Whether this is the current page.
    pub active: bool,
}

impl SettingsTab {
    /// Builds a tab, marking it active when `key == active`.
    fn new(key: &str, label: &str, href: String, active: &str) -> SettingsTab {
        SettingsTab {
            href,
            label: label.to_string(),
            active: key == active,
        }
    }
}

/// Wraps settings `content` in the shared left-sidebar layout.
///
/// Renders a vertical nav of `tabs` (the active one highlighted) beside the
/// content, so the registry, org, and instance settings scopes share one
/// information architecture. The page heading lives at the top of `content`
/// (in the content column, beside the nav — the GitHub settings convention).
/// On a narrow viewport the sidebar stacks above the content (see the
/// `.settings` rules in `style.css`).
fn settings_layout(tabs: &[SettingsTab], content: &str) -> String {
    let mut nav = String::from("<nav class=\"settings-nav\" aria-label=\"Settings sections\">\n");
    for tab in tabs {
        let _ = write!(
            nav,
            "<a href=\"{href}\"{active}>{label}</a>\n",
            href = escape(&tab.href),
            active = if tab.active {
                " class=\"active\" aria-current=\"page\""
            } else {
                ""
            },
            label = escape(&tab.label),
        );
    }
    nav.push_str("</nav>\n");
    format!("<div class=\"settings\">\n{nav}<div class=\"settings-body\">\n{content}</div>\n</div>\n")
}

/// The registry-scope settings sidebar (one of the management pages active).
///
/// `active` is the key of the current page (`general`, `tokens`, `keys`,
/// `changes`, `config`, `serving`, `publishes`, `health`); an unknown key
/// leaves none highlighted.
fn registry_settings_tabs(slug: &str, active: &str) -> Vec<SettingsTab> {
    vec![
        SettingsTab::new("general", "General", format!("/{slug}/-/settings"), active),
        SettingsTab::new(
            "tokens",
            "Tokens",
            format!("/{slug}/-/settings/tokens"),
            active,
        ),
        SettingsTab::new("keys", "Keys", format!("/{slug}/-/keys"), active),
        SettingsTab::new(
            "changes",
            "Change requests",
            format!("/{slug}/-/changes"),
            active,
        ),
        SettingsTab::new(
            "config",
            "Config",
            format!("/{slug}/-/settings/config"),
            active,
        ),
        SettingsTab::new(
            "serving",
            "Serving & mirror",
            format!("/{slug}/-/settings/serving"),
            active,
        ),
        SettingsTab::new(
            "publishes",
            "Publishes",
            format!("/{slug}/-/publishes"),
            active,
        ),
    ]
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
    let body = settings_layout(&registry_settings_tabs(slug, active), content);
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
/// `active` is the key of the current page (`registries`, `caches`, `settings`,
/// `keys`, `webhooks`, `sso`, `audit`).
fn org_settings_tabs(org_slug: &str, active: &str) -> Vec<SettingsTab> {
    vec![
        SettingsTab::new(
            "registries",
            "Registries",
            format!("/-/org/{org_slug}"),
            active,
        ),
        SettingsTab::new(
            "caches",
            "Binary caches",
            format!("/-/org/{org_slug}/caches"),
            active,
        ),
        SettingsTab::new(
            "settings",
            "Settings",
            format!("/-/org/{org_slug}/settings"),
            active,
        ),
        SettingsTab::new(
            "keys",
            "Hosted keys",
            format!("/-/org/{org_slug}/keys"),
            active,
        ),
        SettingsTab::new(
            "webhooks",
            "Webhooks",
            format!("/-/org/{org_slug}/webhooks"),
            active,
        ),
        SettingsTab::new("sso", "SSO", format!("/-/org/{org_slug}/sso"), active),
        SettingsTab::new("audit", "Audit", format!("/-/org/{org_slug}/audit"), active),
    ]
}

/// Renders an org management page: the shared sidebar (with `active`
/// highlighted) beside `content` (which carries its own `<h1>`), in the
/// standard session chrome. Mirrors [`registry_settings_chrome`] so the org and
/// registry settings IAs are identical.
fn org_settings_chrome(
    email: &str,
    org_slug: &str,
    active: &str,
    content: &str,
    started: Instant,
) -> String {
    let body = settings_layout(&org_settings_tabs(org_slug, active), content);
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

pub fn registry_settings_page(
    email: &str,
    registry: &RegistryRecord,
    org_slug: &str,
    csrf: &str,
    binding: Option<(&str, &str, &str)>,
    bindings: &[String],
    caches: &[RegistryCacheRow],
    linkable_caches: &[(String, String)],
    can_delete: bool,
    result: Option<&str>,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let mut body = format!("<h1>Settings · {}</h1>\n", escape(slug));

    if let Some(change_id) = result {
        let _ = writeln!(
            body,
            "<p class=\"good\">Visibility updated · change <code>{}</code>.</p>",
            escape(change_id),
        );
    }

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
        let _ = write!(crawl_options, "<option value=\"{p}\"{selected}>{p}</option>");
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

    // Storage (read-only). Three cases: a custom binding, the deployment's
    // default storage (a managed registry with no binding), or a phase-1
    // source-URL mirror (read-only upstream, no writable surface here).
    body.push_str("<h2>Storage</h2>\n");
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
                 <a href=\"/-/instance#storage\">deployment default →</a></p>",
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

    // Binary caches serving this registry (the reverse of a cache's
    // linked-registries list) — managed here from the registry side, and
    // equivalently from each cache's own page. Both routes share the same
    // upsert, so editing a link's flags works from either.
    body.push_str("<h2>Binary caches</h2>\n");
    if caches.is_empty() {
        body.push_str("<p class=\"dim\">No binary caches serve this registry yet.</p>\n");
    } else {
        // An aligned table of linked caches. Each row is a single form (laid out
        // across the shared grid via `display:contents`): toggle the link's flags
        // and `save` (an upsert), or `unlink` (the same form re-submitted to the
        // unlink route via `formaction`). The `?` help sits once in the header.
        body.push_str("<div class=\"linktable\">\n");
        let _ = write!(
            body,
            "<span class=\"linktable-h\">cache</span>\
             <span class=\"linktable-h\">advertised{adv_help}</span>\
             <span class=\"linktable-h\">gc roots{roots_help}</span>\
             <span class=\"linktable-h\"></span>\n",
            adv_help = help::marker("link.advertised"),
            roots_help = help::marker("link.roots_packages"),
        );
        for c in caches {
            let label = if org_slug.is_empty() {
                escape(&c.cache_slug)
            } else {
                format!(
                    "<a href=\"/-/org/{org}/caches/{slug}\">{slug}</a>",
                    org = escape(org_slug),
                    slug = escape(&c.cache_slug),
                )
            };
            let adv = if c.advertised { " checked" } else { "" };
            let roots = if c.roots_packages { " checked" } else { "" };
            // A cache less visible than the registry can't be advertised — grey
            // out (disable) that toggle, with the reason on hover.
            let adv_disabled = if c.can_advertise {
                ""
            } else {
                " disabled title=\"a less-visible cache can't be advertised on this registry — its consumers couldn't read it\""
            };
            let _ = write!(
                body,
                "<form class=\"linkrow\" method=\"post\" action=\"/{slug}/-/settings/cache-link\">{csrf}\
                 <input type=\"hidden\" name=\"cache\" value=\"{cache}\">\
                 <span class=\"linkrow-name\">{label}</span>\
                 <input type=\"checkbox\" name=\"advertised\" value=\"1\"{adv}{adv_disabled}>\
                 <input type=\"checkbox\" name=\"roots_packages\" value=\"1\"{roots}>\
                 <span class=\"linkrow-actions\"><button>save</button>\
                 <button class=\"danger\" formaction=\"/{slug}/-/settings/cache-unlink\">unlink</button>\
                 </span></form>\n",
                slug = escape(slug),
                csrf = csrf_field(csrf),
                cache = escape(&c.cache_slug),
                label = label,
                adv = adv,
                adv_disabled = adv_disabled,
                roots = roots,
            );
        }
        body.push_str("</div>\n");
    }
    // Link another of the org's caches to this registry. Each option carries its
    // cache's visibility, and the form the registry's, so the JS greys out the
    // advertise toggle when the chosen cache is less visible than the registry
    // (it can't be advertised) — the same rule the rows and the server enforce.
    if !linkable_caches.is_empty() {
        let mut options = String::new();
        for (slug, vis) in linkable_caches {
            let _ = write!(
                options,
                "<option value=\"{s}\" data-visibility=\"{v}\">{s} · {v}</option>",
                s = escape(slug),
                v = escape(vis),
            );
        }
        let _ = write!(
            body,
            "<h3>Link a cache</h3>\n\
             <form class=\"console\" method=\"post\" action=\"/{slug}/-/settings/cache-link\" \
             data-cache-link data-registry-visibility=\"{regvis}\">{csrf}\
             <label>cache <select name=\"cache\">{options}</select></label>\n\
             <label><span class=\"lbl\">advertise to consumers{adv_help}</span> \
             <input type=\"checkbox\" name=\"advertised\" value=\"1\" checked></label>\n\
             <label><span class=\"lbl\">pin GC roots from its packages{roots_help}</span> \
             <input type=\"checkbox\" name=\"roots_packages\" value=\"1\" checked></label>\n\
             <button>link</button>\n</form>\n",
            slug = escape(slug),
            regvis = escape(&registry.visibility),
            csrf = csrf_field(csrf),
            options = options,
            adv_help = help::marker("link.advertised"),
            roots_help = help::marker("link.roots_packages"),
        );
    }

    // Trust anchors (read-only — editing is the signed keys.toml flow).
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
        "<p class=\"dim\">Editing the roster is the signed <code>keys.toml</code> flow: see \
         the <a href=\"/{slug}/-/keys\">key roster</a> and propose roster edits as a \
         <a href=\"/{slug}/-/settings/config\">config change request</a>.</p>",
        slug = escape(slug),
    );

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
    }

    registry_settings_chrome(email, slug, "general", &body, started)
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
    let mut body = format!("<h1>Tokens · {}</h1>\n", escape(slug));

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
    let mut body = format!("<h1>Keys · {}</h1>\n", escape(slug));
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
    let mut body = format!("<h1>Hosted signing keys · {}</h1>\n", escape(&org.name));
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
    let mut body = format!("<h1>Webhooks · {}</h1>\n", escape(&org.name));
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
    body.push_str(
        "<label>secret <input type=\"text\" name=\"secret\" \
         placeholder=\"leave blank to generate\"></label>\n\
         <button>add webhook</button>\n</form>\n",
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
    let mut body = format!("<h1>Single sign-on · {}</h1>\n", escape(&org.name));
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
         <label>issuer <input type=\"text\" name=\"issuer\" required value=\"{issuer}\" \
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
        "<label><span class=\"lbl\">just-in-time provision unknown users</span> \
         <input type=\"checkbox\" name=\"allow_jit\" value=\"1\"{jit}></label>\n\
         <label><span class=\"lbl\">force org members through SSO</span> \
         <input type=\"checkbox\" name=\"enforce_sso\" value=\"1\"{enforce}></label>\n\
         <button>save identity provider</button>\n</form>\n",
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

/// The instance-scope settings sidebar (`general` or `storage` active).
fn instance_settings_tabs(active: &str) -> Vec<SettingsTab> {
    vec![
        SettingsTab::new("general", "General", "/-/instance".to_string(), active),
        SettingsTab::new(
            "storage",
            "Storage",
            "/-/instance/storage".to_string(),
            active,
        ),
    ]
}

/// Renders an instance settings page: the shared sidebar beside `content`
/// (which carries its own `<h1>`), in the standard chrome.
fn instance_settings_chrome(email: &str, active: &str, content: &str, started: Instant) -> String {
    let body = settings_layout(&instance_settings_tabs(active), content);
    page_with_session(
        "instance settings",
        &[(String::new(), "instance settings".into())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The instance-settings "General" page (instance admins only): the signup
/// policy.
///
/// The masthead brand is intentionally not editable here — it is fixed at
/// server start (a process-wide value), so it stays a `--brand`/CLI setting.
#[must_use]
pub fn instance_settings_page(
    email: &str,
    csrf: &str,
    policy: SignupPolicy,
    notice: Option<&str>,
    started: Instant,
) -> String {
    let mut body = String::from("<h1>Instance · general</h1>\n");
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    let _ = write!(
        body,
        "<h2>Signup policy{help}</h2>\n",
        help = help::marker("instance.signup_policy"),
    );
    let open_sel = if matches!(policy, SignupPolicy::Open) {
        " checked"
    } else {
        ""
    };
    let invite_sel = if matches!(policy, SignupPolicy::InviteOnly) {
        " checked"
    } else {
        ""
    };
    let _ = write!(
        body,
        "<form class=\"console\" method=\"post\" action=\"/-/instance\">{csrf}\
         <label><input type=\"radio\" name=\"signup_policy\" value=\"invite_only\"{invite_sel}> \
         invite only</label>\n\
         <label><input type=\"radio\" name=\"signup_policy\" value=\"open\"{open_sel}> \
         open</label>\n\
         <button>save</button>\n</form>\n",
        csrf = csrf_field(csrf),
    );
    instance_settings_chrome(email, "general", &body, started)
}

/// The instance-settings "Storage" page (instance admins only): the
/// deployment's default storage backend.
///
/// Read-only: the default store is the Worker's R2 bucket binding (or the
/// native hub's storage root), fixed when the hub is deployed and not
/// runtime-editable from the web. The actionable lever — pushing a registry or
/// cache elsewhere — is an org-scoped storage binding, linked from here.
#[must_use]
pub fn instance_storage_page(
    email: &str,
    default_storage_location: Option<&str>,
    started: Instant,
) -> String {
    let mut body = String::from("<h1>Instance · storage</h1>\n");
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
        "<p class=\"dim\">The default store is fixed at deploy time — the Worker's R2 \
         bucket binding, or the native hub's storage root — so it is not editable here. \
         Changing it means redeploying the hub against a different bucket. To send a \
         specific registry or cache elsewhere instead, add an org-scoped storage binding \
         (under an org's <strong>Settings</strong>) and point the registry or cache at \
         it.</p>\n",
    );
    instance_settings_chrome(email, "storage", &body, started)
}

/// The registry "serving & mirror" page: the serving frontends (domains) and
/// the optional upstream mirror configuration.
///
/// Frontends and mirror config are registry metadata, not signed surface
/// content, so they are direct mutations. (Triggering a mirror *sync* is a
/// scheduled background job / a CLI action, not a web button.)
#[must_use]
pub fn serving_page(
    email: &str,
    registry: &RegistryRecord,
    csrf: &str,
    frontends: &[FrontendRecord],
    mirror: Option<&MirrorSource>,
    notice: Option<&str>,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let mut body = format!("<h1>Serving &amp; mirror · {}</h1>\n", escape(slug));
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
                let delete = format!(
                    "<form class=\"console\" method=\"post\" \
                     action=\"/{slug}/-/settings/serving\" style=\"display:inline\">{csrf}\
                     <input type=\"hidden\" name=\"op\" value=\"delete-frontend\">\
                     <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                     <button class=\"danger\">delete</button></form>",
                    slug = escape(slug),
                    csrf = csrf_field(csrf),
                    id = f.id,
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
                    delete,
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
         <input type=\"hidden\" name=\"op\" value=\"add-frontend\">\n\
         <label>domain <input type=\"text\" name=\"domain\" required placeholder=\"cdn.acme.com\"></label>\n\
         <label>base path <input type=\"text\" name=\"base_path\" placeholder=\"(domain root)\"></label>\n\
         <label>mode <select name=\"mode\"><option value=\"direct\">direct</option>\
         <option value=\"proxied\">proxied</option></select></label>\n\
         <label><span class=\"lbl\">serves git</span> <input type=\"checkbox\" name=\"serves_git\" value=\"1\" checked></label>\n\
         <label><span class=\"lbl\">serves cache</span> <input type=\"checkbox\" name=\"serves_cache\" value=\"1\" checked></label>\n\
         <label><span class=\"lbl\">serves web</span> <input type=\"checkbox\" name=\"serves_web\" value=\"1\" checked></label>\n\
         <label><span class=\"lbl\">advertise to consumers</span> <input type=\"checkbox\" name=\"advertised\" value=\"1\"></label>\n\
         <label>consumer priority <input type=\"text\" name=\"consumer_priority\" value=\"100\"></label>\n\
         <button>add frontend</button>\n</form>\n",
        slug = escape(slug),
        csrf = csrf_field(csrf),
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
    let mut body = format!("<h1>Publishes · {}</h1>\n", escape(slug));

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
    let content = settings_layout(&registry_settings_tabs(slug, "publishes"), &body);
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
    let mut body = format!("<h1>Edit config: {}</h1>\n", escape(slug));
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

/// Renders one editable `[[caches]]` row (URL + priority + remove button).
///
/// `app.js` clones the trailing row to add more and wires the remove button;
/// with no JS the server-rendered rows (existing entries plus one blank) are
/// still fully editable.
fn cache_row_html(url: &str, priority: u32) -> String {
    format!(
        "<div class=\"cache-row\">\
         <input type=\"text\" name=\"cache_url\" value=\"{url}\" \
         placeholder=\"https://cache.example.org\" aria-label=\"cache URL\">\
         <input type=\"number\" name=\"cache_priority\" value=\"{priority}\" min=\"0\" \
         class=\"cache-prio\" aria-label=\"priority\">\
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
/// repeatable `[[caches]]` list. On submit the handler rebuilds the committed
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
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let mut body = format!("<h1>Edit config: {}</h1>\n", escape(slug));
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
        cache_rows.push_str(&cache_row_html(&cache.url, cache.priority));
    }
    cache_rows.push_str(&cache_row_html("", 100));

    let cache_stack_note = if model.has_cache_stack {
        "<p class=\"dim\">This registry also defines an advanced \
         <code>[cache_stack]</code>; it is preserved unchanged here. Edit the \
         stack expression via raw TOML with <code>apr</code>.</p>\n"
    } else {
        ""
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
         {cache_stack_note}\
         <button>submit change request</button>\n</form>\n\
         <p class=\"dim\">Submitting rebuilds <code>registry.toml</code> from these \
         fields; comments in the committed file are not preserved.</p>\n",
        csrf = csrf_field(csrf),
        name = escape(&model.name),
        description = escape(&model.description),
        readme = escape(&model.readme),
        readme_help = help::marker("registry.readme"),
        ca_help = help::marker("registry.content_addressed"),
        ca = if model.content_addressed { " checked" } else { "" },
        caches_help = help::marker("registry.caches"),
        cache_rows = cache_rows,
        cache_stack_note = cache_stack_note,
    );

    registry_settings_chrome(email, slug, "config", &body, started)
}

/// The change-requests list page for a registry (RFC-0004 "Configuration
/// management" git-backed path).
///
/// Lists the registry's git-backed change requests (drafts with a `refs/hub`
/// commit, plus their applied/reverted history) with each edited file's
/// unified diff and the `apr change merge` command that promotes a draft.
#[must_use]
pub fn changes_page(
    email: &str,
    registry: &RegistryRecord,
    requests: &[ChangeRequestView],
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let mut body = format!("<h1>Change requests: {}</h1>\n", escape(slug));
    body.push_str(&format!(
        "<p><a href=\"/{}/-/settings/config\">propose a config change</a></p>\n",
        escape(slug),
    ));
    if requests.is_empty() {
        body.push_str("<p class=\"dim\">No change requests yet.</p>\n");
    }
    for req in requests {
        let _ = write!(
            body,
            "<section class=\"change\">\n<h2><code>{}</code> <span class=\"dim\">{}</span></h2>\n\
             <p>{}</p>\n<p class=\"dim\">by {} · commit <code>{}</code></p>\n",
            escape(&req.change_id),
            escape(&req.status),
            escape(&req.summary),
            escape(&req.actor_label),
            escape(&req.git_commit),
        );
        for (path, diff) in &req.file_diffs {
            let _ = write!(
                body,
                "<h3>{}</h3>\n<pre class=\"diff\">{}</pre>\n",
                escape(path),
                escape(diff),
            );
        }
        if req.status == "draft" {
            let _ = write!(
                body,
                "<p class=\"dim\">promote with:</p>\n<pre>{}</pre>\n",
                escape(&req.merge_command),
            );
        }
        body.push_str("</section>\n");
    }

    registry_settings_chrome(email, slug, "changes", &body, started)
}

/// A rendered change request for [`changes_page`].
pub struct ChangeRequestView {
    /// The change-set id.
    pub change_id: String,
    /// Lifecycle status: draft | applied | reverted.
    pub status: String,
    /// One-line summary.
    pub summary: String,
    /// Human label of the actor that opened it.
    pub actor_label: String,
    /// The signed draft-commit oid.
    pub git_commit: String,
    /// Per-edited-file `(path, unified diff)`.
    pub file_diffs: Vec<(String, String)>,
    /// The `apr change merge` command that promotes a draft.
    pub merge_command: String,
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
        let html = cache_page(
            "a@b.com",
            "acme",
            "csrf-tok",
            &cache(),
            "primary",
            &["cold".to_string()],
            &usage(),
            &[],
            &[("cdn".to_string(), "public".to_string())],
            true,
            None,
            Instant::now(),
        );
        // Identity + usage are shown.
        assert!(html.contains("Cache · build"));
        assert!(html.contains("2.0 MiB"));
        assert!(html.contains("<span class=\"chip\">signed</span>"));
        // Every admin control is present.
        assert!(html.contains("/-/org/acme/caches/build/link"));
        assert!(html.contains("/-/org/acme/caches/build/gc"));
        assert!(html.contains("/-/org/acme/caches/build/delete"));
        assert!(html.contains("save"));
        // The CSRF token is wired into the forms.
        assert!(html.contains("csrf-tok"));
    }

    #[test]
    fn member_sees_no_mutating_forms() {
        let html = cache_page(
            "a@b.com",
            "acme",
            "csrf-tok",
            &cache(),
            "primary",
            &["cold".to_string()],
            &usage(),
            &[],
            &[("cdn".to_string(), "public".to_string())],
            false,
            None,
            Instant::now(),
        );
        assert!(html.contains("Cache · build"));
        // No admin forms for a plain member.
        assert!(!html.contains("/caches/build/delete"));
        assert!(!html.contains("/caches/build/gc"));
        assert!(!html.contains("/caches/build/link"));
    }

    #[test]
    fn gc_notice_is_surfaced() {
        let html = cache_page(
            "a@b.com",
            "acme",
            "csrf-tok",
            &cache(),
            "primary",
            &["cold".to_string()],
            &usage(),
            &[],
            &[],
            true,
            Some("Collected 5 objects, reclaimed 1.0 MiB (3 retained)."),
            Instant::now(),
        );
        assert!(html.contains("Collected 5 objects"));
    }
}
