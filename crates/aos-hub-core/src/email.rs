//! Shared transactional-email rendering (RFC-0004).
//!
//! The hub sends two human-facing transactional emails — a magic-link sign-in
//! and an org-invite notice — and both must read identically whether they are
//! delivered by the native hub (SMTP/HTTP) or the Cloudflare Worker (the Email
//! Service binding). This module owns the *content*: it renders each message
//! into an [`EmailContent`] (`subject`/`html`/`text`) once, so the two
//! deployment shells share a single source of truth for wording and markup and
//! differ only in transport.
//!
//! The renderers are pure and wasm-clean — no I/O, no clock, no randomness — so
//! they compile unchanged into the Worker and are trivially unit-tested. The
//! `link_url` a caller passes is HTML-escaped wherever it lands in markup (the
//! `href` attribute and the visible link text) so a hostile or merely
//! awkward URL cannot break out of its context, reusing the crate's
//! [`crate::web::render::escape`] helper.
//!
//! A rendered magic-link email looks like:
//!
//! ```text
//! Subject: Sign in to Example Hub
//!
//! Click the link below to sign in to Example Hub:
//!
//!   https://hub.example.com/auth/magic?token=…
//!
//! This link expires in 15 minutes and can be used once. If you did not
//! request it, you can safely ignore this email.
//! ```

use crate::web::render::escape;

/// A rendered transactional email in its three wire forms.
///
/// Every transport the hub uses takes the same shape — a subject line plus an
/// HTML and a plaintext body — so a renderer produces one of these and each
/// [`Mailer`](crate::auth::magic::Mailer) maps it onto its provider's API
/// (`EMAIL.send({ subject, html, text })` on the Worker, an SMTP multipart
/// natively).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailContent {
    /// The subject line, already in its final human-readable form.
    pub subject: String,
    /// The `text/html` body, with all interpolated values HTML-escaped.
    pub html: String,
    /// The `text/plain` alternative body, carrying the link verbatim.
    pub text: String,
}

/// The fallback brand name used when the caller supplies an empty `brand`.
///
/// The console's brand is configured at startup ([`crate::web::console_render::brand`])
/// and may be unset (the empty string); this keeps the copy readable in that
/// case rather than emitting "Sign in to ".
const DEFAULT_BRAND: &str = "the registry hub";

/// Returns `brand` if non-empty, otherwise the [`DEFAULT_BRAND`] fallback.
fn brand_or_default(brand: &str) -> &str {
    if brand.is_empty() {
        DEFAULT_BRAND
    } else {
        brand
    }
}

/// Renders the magic-link sign-in email.
///
/// `brand` is the hub's display name (empty falls back to [`DEFAULT_BRAND`]);
/// `link_url` is the fully-formed single-use sign-in URL. The HTML body offers a
/// styled button to `link_url` and notes that the link expires in 15 minutes and
/// can be ignored if unexpected; the plaintext body carries the URL verbatim.
/// `link_url` is HTML-escaped in both the `href` and the visible link text.
///
/// # Examples
///
/// ```
/// use aos_hub_core::email::magic_link_email;
///
/// let email = magic_link_email("Example Hub", "https://h/auth/magic?token=abc");
/// assert_eq!(email.subject, "Sign in to Example Hub");
/// assert!(email.text.contains("https://h/auth/magic?token=abc"));
/// ```
#[must_use]
pub fn magic_link_email(brand: &str, link_url: &str) -> EmailContent {
    let brand = brand_or_default(brand);
    let href = escape(link_url);
    let subject = format!("Sign in to {brand}");
    let html = format!(
        "<!doctype html>\n\
         <html><body style=\"font-family:system-ui,sans-serif;line-height:1.5;color:#1a1a1a\">\n\
         <p>Click the button below to sign in to {brand_esc}.</p>\n\
         <p><a href=\"{href}\" \
         style=\"display:inline-block;padding:10px 18px;background:#1a1a1a;color:#fff;\
         text-decoration:none;border-radius:6px\">Sign in</a></p>\n\
         <p style=\"color:#555;font-size:13px\">Or paste this link into your browser:<br>\n\
         <a href=\"{href}\">{href}</a></p>\n\
         <p style=\"color:#555;font-size:13px\">This link expires in 15 minutes and can be used \
         once. If you did not request it, you can safely ignore this email.</p>\n\
         </body></html>\n",
        brand_esc = escape(brand),
        href = href,
    );
    let text = format!(
        "Click the link below to sign in to {brand}:\n\n  {link_url}\n\n\
         This link expires in 15 minutes and can be used once. If you did not \
         request it, you can safely ignore this email.\n",
    );
    EmailContent {
        subject,
        html,
        text,
    }
}

/// Renders the org-invite notification email.
///
/// `brand` is the hub's display name (empty falls back to [`DEFAULT_BRAND`]);
/// `org_slug` and `role` identify the org the recipient was added to and the
/// role they were granted; `link_url` is a fully-formed sign-in URL to the
/// console. The bodies explain the grant and offer the sign-in link;
/// `link_url`, `org_slug`, and `role` are HTML-escaped in the HTML body.
///
/// # Examples
///
/// ```
/// use aos_hub_core::email::invite_email;
///
/// let email = invite_email("Example Hub", "acme", "admin", "https://h/login");
/// assert!(email.subject.contains("acme"));
/// assert!(email.text.contains("admin"));
/// assert!(email.text.contains("https://h/login"));
/// ```
#[must_use]
pub fn invite_email(brand: &str, org_slug: &str, role: &str, link_url: &str) -> EmailContent {
    let brand = brand_or_default(brand);
    let href = escape(link_url);
    let subject = format!("You're invited to {org_slug} on {brand}");
    let html = format!(
        "<!doctype html>\n\
         <html><body style=\"font-family:system-ui,sans-serif;line-height:1.5;color:#1a1a1a\">\n\
         <p>You've been invited to the <strong>{org_esc}</strong> organization on {brand_esc}.</p>\n\
         <p>Accept to receive the <strong>{role_esc}</strong> role:</p>\n\
         <p><a href=\"{href}\" \
         style=\"display:inline-block;padding:10px 18px;background:#1a1a1a;color:#fff;\
         text-decoration:none;border-radius:6px\">Review invitation</a></p>\n\
         <p style=\"color:#555;font-size:13px\">Or paste this link into your browser:<br>\n\
         <a href=\"{href}\">{href}</a></p>\n\
         <p style=\"color:#555;font-size:13px\">This invitation link expires and can be used once. \
         If you did not expect this, you can safely ignore this email.</p>\n\
         </body></html>\n",
        org_esc = escape(org_slug),
        brand_esc = escape(brand),
        role_esc = escape(role),
        href = href,
    );
    let text = format!(
        "You've been invited to the {org_slug} organization on {brand}.\n\n\
         Accept to receive the {role} role:\n\n  {link_url}\n\n\
         This invitation link expires and can be used once. If you did not expect this, \
         you can safely ignore this email.\n",
    );
    EmailContent {
        subject,
        html,
        text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_link_subject_uses_brand() {
        let e = magic_link_email("Example Hub", "https://h/auth/magic?token=x");
        assert_eq!(e.subject, "Sign in to Example Hub");
    }

    #[test]
    fn magic_link_empty_brand_falls_back() {
        let e = magic_link_email("", "https://h/auth/magic?token=x");
        assert_eq!(e.subject, "Sign in to the registry hub");
        assert!(e.html.contains("the registry hub"));
    }

    #[test]
    fn magic_link_text_carries_url_and_expiry() {
        let url = "https://h/auth/magic?token=abc123";
        let e = magic_link_email("Hub", url);
        assert!(e.text.contains(url));
        assert!(e.text.contains("15 minutes"));
        assert!(e.text.contains("ignore"));
    }

    #[test]
    fn magic_link_html_escapes_quote_in_url() {
        // A `"` in the URL must not break out of the href attribute.
        let url = "https://h/auth/magic?token=a\"b";
        let e = magic_link_email("Hub", url);
        assert!(!e.html.contains("token=a\"b"));
        assert!(e.html.contains("token=a&quot;b"));
        // The plaintext body carries the URL verbatim (no escaping there).
        assert!(e.text.contains(url));
    }

    #[test]
    fn invite_subject_and_text_carry_org_role_and_link() {
        let link = "https://h/login";
        let e = invite_email("Example Hub", "acme", "admin", link);
        assert_eq!(e.subject, "You're invited to acme on Example Hub");
        assert!(e.text.contains("acme"));
        assert!(e.text.contains("admin"));
        assert!(e.text.contains(link));
    }

    #[test]
    fn invite_html_escapes_quote_in_url() {
        let link = "https://h/login?next=\"x\"";
        let e = invite_email("Hub", "acme", "admin", link);
        assert!(!e.html.contains("next=\"x\""));
        assert!(e.html.contains("&quot;"));
    }
}
