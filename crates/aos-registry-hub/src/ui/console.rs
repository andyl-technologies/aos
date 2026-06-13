//! The authenticated producer console: human management pages.
//!
//! Phase-3b of RFC-0004 (the producer-facing surface) renders here. Every
//! page is the no-JS floor — plain `GET`/`POST` forms and redirects, no
//! client-side framework — in the same "release-engineering paper" language
//! as the consumer browse tier ([`super::pages`]). The pages are:
//!
//! - **Auth**: login (email-first magic link), the "check your email"
//!   confirmation, the account profile (sessions, tokens, passkey
//!   placeholder), and the RFC 8628 device-approval page at `/activate`.
//! - **Org/project**: the user's org list, a per-org dashboard (projects,
//!   registries, members, storage bindings, tokens), and the org audit feed.
//! - **Registry management**: per-registry token management, the channel
//!   rollout console (prepared `apr` operations for BYO-key orgs), the key
//!   roster with the rotation wizard, and the publish-pipeline status view.
//!
//! # CSRF
//!
//! Every `POST` form here is a cookie-authenticated mutation, so it carries a
//! hidden per-session synchronizer token minted by
//! [`crate::auth::extract::mint_csrf_token`] and verified on submit. The
//! [`csrf_field`] helper renders that hidden input.

use std::fmt::Write as _;
use std::time::Instant;

use crate::db::{
    AuditRow, ChangesetRow, ChannelSummary, IndexStatus, OrgRecord, ProjectRecord, RegistryRecord,
    ReleaseRow, StorageBindingRecord,
};
use crate::domain::{iam, Permission, Role, Scope};
use crate::ui::render::{
    ago, escape, key_fingerprint, page_with_session, table, SessionIndicator, StateLine,
};

/// The hidden CSRF synchronizer field every console `POST` form embeds.
///
/// `token` is the value from [`crate::auth::extract::mint_csrf_token`] for
/// the current session; the POST handler verifies it with
/// [`crate::auth::extract::connect_or_csrf_ok`] and rejects a mismatch 403.
fn csrf_field(token: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        escape(token)
    )
}

/// A session indicator for the signed-in `email`.
fn indicator(email: &str) -> SessionIndicator {
    SessionIndicator::signed_in(email)
}

/// The login page: a single email field that issues a magic link.
///
/// `error` renders an inline error (e.g. a malformed address). The form
/// `POST`s to `/login`; there is no CSRF token because the caller is
/// anonymous (no ambient cookie to forge against).
#[must_use]
pub fn login_page(error: Option<&str>, started: Instant) -> String {
    let mut body = String::from("<h1>Log in</h1>\n");
    body.push_str(
        "<p class=\"dim\">Enter your email; we send a one-time sign-in link. \
         There are no passwords.</p>\n",
    );
    if let Some(error) = error {
        let _ = writeln!(body, "<p class=\"bad\">{}</p>", escape(error));
    }
    body.push_str(
        "<form class=\"console\" method=\"post\" action=\"/login\">\n\
         <label>email <input type=\"email\" name=\"email\" required \
         placeholder=\"you@example.com\"></label>\n\
         <button>send sign-in link</button>\n</form>\n",
    );
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

/// The account profile page: email, active sessions, tokens, passkeys.
///
/// `tokens` are `(id, scope, permissions)` tuples across every scope the
/// user owns. The sessions section offers a "sign out everywhere" button;
/// passkeys are a documented placeholder (a later spike, RFC-0004).
#[must_use]
pub fn account_page(
    email: &str,
    csrf: &str,
    tokens: &[(String, String, Vec<Permission>)],
    started: Instant,
) -> String {
    let mut body = format!(
        "<h1>Account</h1>\n<p>signed in as <code>{}</code></p>\n",
        escape(email)
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
         <p class=\"dim\">Passkey (WebAuthn) sign-in is planned (RFC-0004); not yet available.</p>\n",
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
#[must_use]
pub fn orgs_page(email: &str, orgs: &[OrgRecord], started: Instant) -> String {
    let mut body = String::from("<h1>Organizations</h1>\n");
    if orgs.is_empty() {
        body.push_str("<p class=\"dim\">You are not a member of any organization.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = orgs
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
    }
    page_with_session(
        "organizations",
        &[(String::new(), "organizations".into())],
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
/// to admins; a viewer sees the lists without the forms. `owner_count` is the
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
    owner_count: usize,
    started: Instant,
) -> String {
    let mut body = format!("<h1>{}</h1>\n", escape(&org.name));
    let _ = writeln!(
        body,
        "<p class=\"dim\"><code>{}</code> · <a href=\"/-/org/{}/audit\">{}</a></p>",
        escape(&org.slug),
        escape(&org.slug),
        if can_read_audit {
            "audit feed →"
        } else {
            "audit (admin only)"
        },
    );

    body.push_str("<h2>Registries</h2>\n");
    if registries.is_empty() {
        body.push_str("<p class=\"dim\">No registries.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = registries
            .iter()
            .map(|reg| {
                vec![
                    format!("<a href=\"/{0}/\">{0}</a>", escape(&reg.slug)),
                    escape(&reg.visibility),
                ]
            })
            .collect();
        body.push_str(&table(&["registry", "visibility"], &rows));
    }

    body.push_str("<h2>Projects</h2>\n");
    if projects.is_empty() {
        body.push_str("<p class=\"dim\">No projects.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = projects
            .iter()
            .map(|p| {
                vec![
                    escape(if p.path.is_empty() { "(root)" } else { &p.path }),
                    escape(&p.name),
                ]
            })
            .collect();
        body.push_str(&table(&["path", "name"], &rows));
    }

    body.push_str("<h2>Storage bindings</h2>\n");
    if bindings.is_empty() {
        body.push_str("<p class=\"dim\">No storage bindings.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = bindings
            .iter()
            .map(|b| {
                vec![
                    escape(&b.name),
                    escape(&b.kind),
                    format!("<code>{}</code>", escape(&b.root)),
                ]
            })
            .collect();
        body.push_str(&table(&["name", "kind", "root"], &rows));
    }

    body.push_str("<h2>Members</h2>\n");
    let rows: Vec<Vec<String>> = members
        .iter()
        .map(|m| {
            let mut action = String::new();
            if can_manage_members {
                // Hard-block removing the final owner: render no remove form.
                let is_last_owner = m.role == "owner" && owner_count <= 1;
                if is_last_owner {
                    action = "<span class=\"dim\">last owner</span>".to_string();
                } else {
                    action = format!(
                        "<form class=\"console\" method=\"post\" \
                         action=\"/-/org/{}/members/remove\" style=\"display:inline\">{}\
                         <input type=\"hidden\" name=\"principal_kind\" value=\"{}\">\
                         <input type=\"hidden\" name=\"principal_id\" value=\"{}\">\
                         <button>remove</button></form>",
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
pub fn audit_page(email: &str, org: &OrgRecord, rows: &[AuditRow], started: Instant) -> String {
    let mut body = format!("<h1>Audit · {}</h1>\n", escape(&org.name));
    if rows.is_empty() {
        body.push_str("<p class=\"dim\">No audit entries.</p>\n");
    } else {
        let table_rows: Vec<Vec<String>> = rows
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

    if tokens.is_empty() {
        body.push_str("<p class=\"dim\">You hold no tokens at this registry.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = tokens
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
    prepared: Option<(&str, &str)>,
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
        body.push_str("<h2>Advance</h2>\n");
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/{slug}/-/channels/{name}/console\">\n{csrf}\
             <label>release <input type=\"text\" name=\"release\" required \
             placeholder=\"1.4.2\"></label>\n\
             <label>partitions (1–256) <input type=\"text\" name=\"partitions\" value=\"256\"></label>\n\
             <button>prepare advance</button>\n</form>\n",
            slug = escape(slug),
            name = escape(&channel.name),
            csrf = csrf_field(csrf),
        );
        body.push_str(
            "<p class=\"dim\">Web edits are change requests: this records a prepared operation and \
             renders the <code>apr channel advance --from-hub</code> command. The maintainer signs \
             the partition tags locally and pushes. A direct web-button advance needs a hosted \
             signing key (phase 4).</p>\n",
        );
    } else {
        body.push_str("<p class=\"dim\">Read-only: you need a maintainer role to advance.</p>\n");
    }

    // Reuse the consumer channel grid renderer for the partition view.
    let grid = super::pages::channel_grid_pre(channel);
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
    started: Instant,
) -> String {
    let slug = &registry.slug;
    let mut body = format!("<h1>Keys · {}</h1>\n", escape(slug));
    body.push_str(
        "<p class=\"dim\">The roster is signed tree content. Keys are added and retired by \
         client-side signing, never by a raw web mutation.</p>\n",
    );

    if roster.is_empty() {
        body.push_str("<p class=\"dim\">No roster keys indexed.</p>\n");
    } else {
        let rows: Vec<Vec<String>> = roster
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
