//! The authenticated producer console: human management pages.
//!
//! Phase-3b of RFC-0004 (the producer-facing surface) renders here. Every
//! page is the no-JS floor — plain `GET`/`POST` forms and redirects, no
//! client-side framework — in the same "release-engineering paper" language
//! as the consumer browse tier ([`super::pages`]). The pages are:
//!
//! - **Auth**: login (email-first magic link, plus a passkey sign-in button
//!   and its nonced inline script), the "check your email" confirmation, the
//!   account profile (sessions, tokens, passkeys), the passkey management page
//!   (`/account/passkeys`), and the RFC 8628 device-approval page at
//!   `/activate`.
//! - **Org/project**: the user's org list, a per-org dashboard (projects,
//!   registries, members, storage bindings, tokens), and the org audit feed.
//! - **Registry management**: per-registry token management, the channel
//!   rollout console (prepared `apr` operations for BYO-key orgs, or a direct
//!   hub-signed advance form when a hosted key is bound), the key roster with
//!   the rotation wizard, the org hosted-key enrollment page, and the
//!   publish-pipeline status view.
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
    AuditRow, ChangesetRow, ChannelSummary, HostedKeyRecord, IndexStatus, OrgRecord, ProjectRecord,
    RegistryRecord, ReleaseRow, StorageBindingRecord, WebauthnCredentialRecord,
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

/// The login page: a single email field that issues a magic link, plus an
/// optional "Sign in with a passkey" button.
///
/// `error` renders an inline error (e.g. a malformed address). The email form
/// `POST`s to `/login`; there is no CSRF token because the caller is anonymous
/// (no ambient cookie to forge against).
///
/// `passkey_nonce` is `Some(nonce)` on the canonical `GET /login` render, where
/// the handler also sets a `script-src 'nonce-…'` CSP: it adds a passkey button
/// and the first-party inline script that drives `navigator.credentials.get`.
/// It is `None` on no-JS error re-renders, which still show the email form (a
/// plain reload restores the passkey button).
#[must_use]
pub fn login_page(error: Option<&str>, passkey_nonce: Option<&str>, started: Instant) -> String {
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
    if(r.ok){window.location='/';}else{err.textContent='Passkey sign-in failed.';}
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

/// The account profile page: email, active sessions, tokens, passkeys.
///
/// `tokens` are `(id, scope, permissions)` tuples across every scope the
/// user owns. The sessions section offers a "sign out everywhere" button; the
/// passkeys section links to the dedicated management page
/// ([`passkeys_page`]).
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
        let _ = write!(
            body,
            "<form class=\"console\" method=\"post\" action=\"/{}/-/settings/config\">\n{}\
             <label>registry.toml\n<textarea name=\"contents\" rows=\"18\" cols=\"80\" required>{}</textarea></label>\n\
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
        (String::new(), "registries".to_string()),
        (format!("/{slug}/"), slug.to_string()),
    ]
}
