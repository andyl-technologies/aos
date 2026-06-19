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
    AuditRow, ChangesetRow, ChannelSummary, FrontendRecord, HostedKeyRecord, IdpConfigRecord,
    IndexStatus, MirrorSource, OrgDomainRecord, OrgRecord, ProjectRecord, RegistryRecord,
    ReleaseRow, SignupPolicy, StorageBindingRecord, WebauthnCredentialRecord, WebhookRecord,
};
use crate::domain::{iam, Permission, Role, Scope};
use crate::web::render::{escape, key_fingerprint, table};

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
         <link rel=\"stylesheet\" href=\"/_assets/style.css\">\n\
         <script src=\"/_assets/app.js\" defer></script>\n</head>\n<body>\n\
         <header class=\"masthead\">{brand_span}\
         <span class=\"crumbs\">{crumb_html}</span>{session}</header>\n\
         <main>\n{body}\n</main>\n\
         <footer class=\"statline\">{statline}</footer>\n</body>\n</html>\n",
        session = session.render(),
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
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
        let rows: Vec<Vec<String>> = creds
            .iter()
            .map(|c| {
                let label = c.label.as_deref().unwrap_or("passkey");
                let last = c.last_used_at.map_or_else(|| "never".to_string(), ago);
                vec![
                    escape(label),
                    ago(c.created_at),
                    escape(&last),
                    c.sign_count.to_string(),
                ]
            })
            .collect();
        body.push_str(&table(&["label", "added", "last used", "counter"], &rows));
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
    if is_instance_admin {
        body.push_str("<p><a href=\"/-/instance\">instance settings →</a></p>\n");
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
    body.push_str(
        "<p class=\"dim\">An organization is your tenant boundary: it owns projects, \
         storage bindings, and registries. You become its first owner.</p>\n",
    );
    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }
    body.push_str("<form class=\"console\" method=\"post\" action=\"/new\">\n");
    body.push_str(&csrf_field(csrf));
    body.push_str(
        "<label>slug <input type=\"text\" name=\"slug\" required \
         placeholder=\"acme\"></label>\n\
         <label>display name <input type=\"text\" name=\"name\" required \
         placeholder=\"Acme, Inc.\"></label>\n\
         <button>create organization</button>\n</form>\n",
    );
    body.push_str(
        "<p class=\"dim\">The slug is the URL-safe handle every registry under the org \
         is addressed by; it cannot be changed later.</p>\n",
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
    can_manage_members: bool,
    can_read_audit: bool,
    can_configure: bool,
    can_delete: bool,
    owner_count: usize,
    registries_page: usize,
    members_page: usize,
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
    let mut body = format!("<h1>{}</h1>\n", escape(&org.name));
    let _ = writeln!(
        body,
        "<p class=\"dim\"><code>{}</code> · <a href=\"/-/org/{}/audit\">{}</a> · \
         <a href=\"/-/org/{}/keys\">hosted keys →</a> · \
         <a href=\"/-/org/{}/webhooks\">webhooks →</a> · \
         <a href=\"/-/org/{}/sso\">SSO →</a></p>",
        escape(slug),
        escape(slug),
        if can_read_audit {
            "audit feed →"
        } else {
            "audit (admin only)"
        },
        escape(slug),
        escape(slug),
        escape(slug),
    );

    body.push_str("<h2>Registries</h2>\n");
    if registries.is_empty() {
        body.push_str("<p class=\"dim\">No registries.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = reg_pager
            .slice(registries)
            .iter()
            .map(|reg| {
                let manage = if can_configure {
                    format!("<a href=\"/{}/-/settings\">manage →</a>", escape(&reg.slug))
                } else {
                    String::new()
                };
                vec![
                    format!("<a href=\"/{0}/\">{0}</a>", escape(&reg.slug)),
                    escape(&reg.visibility),
                    manage,
                ]
            })
            .collect();
        body.push_str(&table(&["registry", "visibility", ""], &rows));
        body.push_str(&reg_pager.nav_with(&format!("/-/org/{slug}"), &reg_keep, "registries_page"));
    }
    if can_configure {
        let _ = writeln!(
            body,
            "<p><a href=\"/-/org/{}/registries/new\">+ create a registry</a></p>",
            escape(slug),
        );
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
        body.push_str("<h3>Create a project</h3>\n");
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/projects\">\n{csrf}\
             <label>path <input type=\"text\" name=\"path\" placeholder=\"infra/prod\"></label>\n\
             <label>name <input type=\"text\" name=\"name\" required placeholder=\"Production\"></label>\n\
             <button>create project</button>\n</form>\n",
            org = escape(slug),
            csrf = csrf_field(csrf),
        );
        body.push_str(
            "<p class=\"dim\">The path is the materialized prefix registries are nested under \
             (leave blank for an org-root project).</p>\n",
        );
    }

    body.push_str("<h2>Storage bindings</h2>\n");
    if bindings.is_empty() {
        body.push_str("<p class=\"dim\">No storage bindings.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = bindings
            .iter()
            .map(|b| {
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
                vec![
                    escape(&b.name),
                    escape(&b.kind),
                    format!("<code>{}</code>", escape(&b.root)),
                    action,
                ]
            })
            .collect();
        body.push_str(&table(&["name", "kind", "root", ""], &rows));
    }
    // New registries use the deployment's default storage automatically — no
    // binding required. A custom binding is only for pointing an org at an
    // *additional* backend.
    let _ = write!(
        body,
        "<p class=\"dim\">New registries use {default} automatically — no storage binding is \
         required. A custom binding below only adds an extra backend.</p>\n",
        default = escape(RuntimeKind::current().default_storage_label()),
    );
    if can_configure {
        // Offer only kinds that are both runtime-supported and actually
        // implemented as a custom binding. Today that is `local_fs` on the
        // native hub and nothing on the Worker (its R2 is the default storage,
        // not a custom binding), so the misleading "create an s3/r2 binding that
        // can't serve" form is never shown.
        let creatable = RuntimeKind::current().creatable_binding_kinds();
        if creatable.is_empty() {
            body.push_str(
                "<p class=\"dim\">Custom storage bindings (for example an external S3 bucket) are \
                 not available on this deployment yet — registries use the default storage \
                 above.</p>\n",
            );
        } else {
            body.push_str("<h3>Add a custom storage binding</h3>\n");
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
                "<form class=\"console\" method=\"post\" action=\"/-/org/{org}/bindings\">\n{csrf}\
                 <label>name <input type=\"text\" name=\"name\" required placeholder=\"primary\"></label>\n\
                 <label>kind <select name=\"kind\">{kinds}</select></label>\n\
                 <label>root <input type=\"text\" name=\"root\" required \
                 placeholder=\"/srv/registries/acme\"></label>\n\
                 <button>create binding</button>\n</form>\n",
                org = escape(slug),
                csrf = csrf_field(csrf),
                kinds = kind_options,
            );
            body.push_str(
                "<p class=\"dim\">For <code>local_fs</code> the root is an absolute host path with no \
                 <code>..</code> components. Managed registries place their surfaces under it.</p>\n",
            );
        }
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
        body.push_str("<h3>Invite a member</h3>\n");
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
        body.push_str(
            "<p class=\"dim\">Invitations create a pending membership the invitee accepts; \
             removing a member also deadens every token they minted.</p>\n",
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

    page_with_session(
        &org.name,
        &[
            ("/-/orgs".into(), "organizations".into()),
            (String::new(), org.slug.clone()),
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
    page_with_session(
        "audit",
        &[
            ("/-/orgs".into(), "organizations".into()),
            (format!("/-/org/{}", org.slug), org.slug.clone()),
            (String::new(), "audit".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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
         <label>visibility <select name=\"visibility\">\
         <option value=\"private\">private</option>\
         <option value=\"internal\">internal</option>\
         <option value=\"public\">public</option></select></label>\n\
         <label>prefix (optional — defaults to the registry slug) \
         <input type=\"text\" name=\"prefix\" placeholder=\"optional — defaults to the registry slug\"></label>\n\
         <label>trust anchors\n<textarea name=\"trust_keys\" rows=\"4\" cols=\"80\" \
         placeholder=\"release:Ed25519:base64...\"></textarea></label>\n\
         <label><input type=\"checkbox\" name=\"require_signatures\" value=\"1\" checked> \
         require signatures</label>\n\
         <button>create registry</button>\n</form>\n",
        org = escape(org_slug),
        csrf = csrf_field(csrf),
        projects = project_options,
        bindings = binding_options,
    );
    body.push_str(
        "<p class=\"dim\">The registry is created at <code>{org}/{project}/{name}</code> and \
         indexed lazily from its surface. Leaving the storage binding on \
         <em>Default storage</em> uses this deployment's own storage; the prefix \
         auto-derives from the registry name when left blank. One trust anchor per \
         line, in <code>name:Ed25519:&lt;base64&gt;</code> form.</p>\n",
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
pub fn registry_settings_page(
    email: &str,
    registry: &RegistryRecord,
    csrf: &str,
    binding: Option<(&str, &str, &str)>,
    can_delete: bool,
    result: Option<&str>,
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let mut body = format!("<h1>Manage · {}</h1>\n", escape(slug));

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
         <label>policy <select name=\"policy\">{crawl_options}</select></label>\n\
         <button>change crawl policy</button>\n</form>\n",
        slug = escape(slug),
        csrf = csrf_field(csrf),
        crawl_options = crawl_options,
    );
    body.push_str(
        "<p class=\"dim\">Controls the generated <code>robots.txt</code>. \
         <strong>allow_all</strong> lets every crawler index; \
         <strong>allow_no_ai</strong> blocks known AI crawlers (GPTBot, ClaudeBot, …); \
         <strong>deny_all</strong> blocks every crawler. \
         A confirmation-gated change-set, recorded in the audit feed.</p>\n",
    );

    // Storage (read-only).
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
        None => body
            .push_str("<p class=\"dim\">No storage binding (a phase-1 source-URL registry).</p>\n"),
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

    // The management link hub.
    body.push_str("<h2>Manage this registry</h2>\n");
    let _ = write!(
        body,
        "<ul class=\"manage-links\">\n\
         <li><a href=\"/{slug}/-/settings/tokens\">tokens</a></li>\n\
         <li><a href=\"/{slug}/-/keys\">keys</a></li>\n\
         <li><a href=\"/{slug}/-/changes\">change requests</a></li>\n\
         <li><a href=\"/{slug}/-/settings/config\">config</a></li>\n\
         <li><a href=\"/{slug}/-/settings/serving\">serving &amp; mirror</a></li>\n\
         <li><a href=\"/{slug}/-/publishes\">publishes</a></li>\n\
         <li><a href=\"/{slug}/-/health\">health</a></li>\n\
         <li><a href=\"/{slug}/-/packages\">packages</a></li>\n\
         <li><a href=\"/{slug}/\">registry home</a></li>\n\
         </ul>\n",
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

    let crumbs = registry_crumbs(slug);
    page_with_session(
        &format!("manage · {slug}"),
        &crumbs,
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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
             <label><input type=\"checkbox\" name=\"perm_read\" value=\"1\" checked> read</label>\n\
             <label><input type=\"checkbox\" name=\"perm_publish\" value=\"1\"> publish</label>\n\
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

    page_with_session(
        &format!("{slug} tokens"),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/"), slug.clone()),
            (String::new(), "tokens".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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

    page_with_session(
        &format!("{slug} keys"),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/"), slug.clone()),
            (String::new(), "keys".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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
    page_with_session(
        "key rotation",
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/"), slug.clone()),
            (format!("/{slug}/-/keys"), "keys".into()),
            (String::new(), "rotate".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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

    page_with_session(
        &format!("{org_slug} hosted keys"),
        &[
            ("/-/orgs".into(), "orgs".into()),
            (format!("/-/org/{org_slug}"), org_slug.clone()),
            (String::new(), "hosted keys".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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
            "<label><input type=\"checkbox\" name=\"events\" value=\"{event}\"> \
             <code>{event}</code> — {label}</label>\n",
        );
    }
    body.push_str("</fieldset>\n");
    body.push_str(
        "<label>secret <input type=\"text\" name=\"secret\" \
         placeholder=\"leave blank to generate\"></label>\n\
         <button>add webhook</button>\n</form>\n",
    );

    page_with_session(
        &format!("{org_slug} webhooks"),
        &[
            ("/-/orgs".into(), "orgs".into()),
            (format!("/-/org/{org_slug}"), org_slug.clone()),
            (String::new(), "webhooks".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
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
        "<label><input type=\"checkbox\" name=\"allow_jit\" value=\"1\"{jit}> \
         just-in-time provision unknown users</label>\n\
         <label><input type=\"checkbox\" name=\"enforce_sso\" value=\"1\"{enforce}> \
         force org members through SSO</label>\n\
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

    page_with_session(
        &format!("{org_slug} single sign-on"),
        &[
            ("/-/orgs".into(), "orgs".into()),
            (format!("/-/org/{org_slug}"), org_slug.clone()),
            (String::new(), "single sign-on".into()),
        ],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
}

/// The instance-settings page (instance admins only): the signup policy.
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
    let mut body = String::from("<h1>Instance settings</h1>\n");
    if let Some(notice) = notice {
        let _ = writeln!(body, "<p class=\"notice\">{}</p>", escape(notice));
    }
    body.push_str("<h2>Signup policy</h2>\n");
    body.push_str(
        "<p class=\"dim\">Who may create a new organization. <code>invite_only</code> requires \
         an existing membership, an invitation, or an instance admin; <code>open</code> lets any \
         signed-in user create one.</p>\n",
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

    page_with_session(
        "instance settings",
        &[(String::new(), "instance settings".into())],
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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
         <label><input type=\"checkbox\" name=\"serves_git\" value=\"1\" checked> serves git</label>\n\
         <label><input type=\"checkbox\" name=\"serves_cache\" value=\"1\" checked> serves cache</label>\n\
         <label><input type=\"checkbox\" name=\"serves_web\" value=\"1\" checked> serves web</label>\n\
         <label><input type=\"checkbox\" name=\"advertised\" value=\"1\"> advertise to consumers</label>\n\
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
         <label><input type=\"checkbox\" name=\"verify\" value=\"1\"{verify}> verify upstream signatures</label>\n\
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

    let mut crumbs = registry_crumbs(slug);
    crumbs.push((String::new(), "serving".into()));
    page_with_session(
        &format!("{slug} serving"),
        &crumbs,
        &body,
        &StateLine::timed(started),
        &indicator(email),
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

    let state_line = match status {
        Some(s) => StateLine {
            surface_commit: s.last_indexed_commit.clone(),
            indexed_at: s.indexed_at,
            state: Some(s.state.clone()),
            started: Some(started),
        },
        None => StateLine::timed(started),
    };
    page_with_session(
        &format!("{slug} publishes"),
        &[
            ("/".into(), "registries".into()),
            (format!("/{slug}/"), slug.clone()),
            (String::new(), "publishes".into()),
        ],
        &body,
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

    let crumbs = registry_crumbs(slug);
    page_with_session(
        &format!("edit config · {slug}"),
        &crumbs,
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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

    let crumbs = registry_crumbs(slug);
    page_with_session(
        &format!("change requests · {slug}"),
        &crumbs,
        &body,
        &StateLine::timed(started),
        &indicator(email),
    )
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
