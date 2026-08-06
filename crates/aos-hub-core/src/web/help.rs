//! Attached, progressive help for cryptic configuration controls.
//!
//! Good design is apparent, not narrated — but a few controls have genuinely
//! non-obvious meaning (`WantMassQuery`, GC roots, signature enforcement). This
//! module gives those two tiers of help, *attached to the control* rather than
//! dumped as page prose:
//!
//! 1. **Glance** — [`hint`] renders a small dim one-liner under a field. Always
//!    visible, no JavaScript.
//! 2. **Detail** — [`marker`] renders a small `?` affordance that opens a
//!    *segmented card*: a titled popover with a summary plus labelled rows (a
//!    checkbox's on/off, a select's per-value meaning). The card is enhanced by
//!    `app.js` (hover/focus/click-to-pin, edge-flip positioning, Esc/click-away);
//!    its no-JS floor is the `title` tooltip carrying the summary.
//!
//! All help text lives here, keyed by a short id, so it is consistent across the
//! WebUI and maintained in one place. A render site calls
//! `help::marker("cache.mass_query")` next to the label and (optionally)
//! `help::hint("…")` after the control.
//!
//! ```text
//! label  [?]                       ← marker(): the affordance
//! control                          ← the input/select/checkbox
//! glance one-liner                 ← hint(): level-1
//!
//! on click/hover the [?] opens:
//!   ┌──────────────────────────────┐
//!   │ Mass-query            cache   │  term + context tag
//!   ├──────────────────────────────┤
//!   │ Batched availability queries. │  summary
//!   │ On   nix asks for many paths… │  segment rows
//!   │ Off  one path per request.    │
//!   └──────────────────────────────┘
//! ```

use crate::web::render::escape;
use std::fmt::Write as _;

/// A segmented help card: a titled, structured explanation of one control.
pub struct HelpCard {
    /// Human title (the control's real-world name).
    pub term: &'static str,
    /// Small context tag shown top-right (e.g. `cache`, `registry`); `""` for
    /// none.
    pub tag: &'static str,
    /// One-line summary — the glance value, also the no-JS `title` tooltip.
    pub summary: &'static str,
    /// Labelled detail rows: `(label, text)`. For a checkbox these are typically
    /// `("On", …)` / `("Off", …)`; for a select, one row per value.
    pub segments: &'static [(&'static str, &'static str)],
}

/// Look up the help card for a control `key`, or `None` if undefined.
///
/// Keys are dotted `area.control` strings (e.g. `cache.mass_query`). An unknown
/// key renders nothing, so a marker can be added before its content exists
/// without breaking the page.
#[must_use]
pub fn card(key: &str) -> Option<HelpCard> {
    let c = |term, tag, summary, segments| HelpCard {
        term,
        tag,
        summary,
        segments,
    };
    Some(match key {
        // -- caches ----------------------------------------------------------
        "cache.mass_query" => c(
            "Mass-query",
            "cache",
            "Lets clients ask about many store paths in one request.",
            &[
                ("On", "nix can batch \"do you have these paths?\" queries — fewer round-trips, faster resolution. The default for a serving cache."),
                ("Off", "clients probe one path at a time; set this for a cache that should not advertise bulk availability."),
            ],
        ),
        "cache.compression" => c(
            "Compression",
            "cache",
            "How NARs are compressed at rest and on the wire.",
            &[
                ("zstd", "fast to compress and decompress, good ratio — the recommended default."),
                ("xz", "smaller files, much slower to compress; for cold archives where size dominates."),
                ("none", "store NARs uncompressed; only for already-compressed payloads or local testing."),
            ],
        ),
        "cache.priority" => c(
            "Priority",
            "cache",
            "Substituter ordering — lower numbers are preferred.",
            &[
                ("Lower = preferred", "nix tries lower-priority substituters first. The official nixos cache is 40, so a faster local cache might be 30."),
                ("Default 40", "leave at 40 unless you are deliberately ordering this cache ahead of or behind another."),
            ],
        ),
        // -- storage bindings ------------------------------------------------
        "binding.kind" => c(
            "Backend kind",
            "storage",
            "Where this binding stores bytes.",
            &[
                ("local_fs", "a directory on the host filesystem (native hub only)."),
                ("s3", "any S3-compatible object store (AWS S3, MinIO, …) reached over its S3 API."),
                ("r2", "Cloudflare R2 via its S3-compatible API."),
            ],
        ),
        "binding.access" => c(
            "Access mode",
            "storage",
            "Whether the hub holds credentials for this store.",
            &[
                ("private", "the hub signs reads/writes with stored credentials (sealed at rest) — full read/write. The usual choice for your own bucket."),
                ("public", "no credentials; the store is world-readable and the hub only reads it. Read-only mirror use."),
            ],
        ),
        "storage.change" => c(
            "Change storage",
            "storage",
            "Move this surface's objects to a different backend, then re-point it.",
            &[
                ("Copies first", "every object is copied to the new store before the pointer flips, so the content is never stranded; an empty surface just re-points."),
                ("Old copy stays", "the source objects are left in place (not deleted), so a failed move is harmless and the surface keeps serving from its original store until the copy finishes."),
                ("Index reconciles", "the registry re-indexes (or a cache re-scans) from the new surface afterward, so search/browse stay correct."),
            ],
        ),
        // -- registries ------------------------------------------------------
        "registry.require_signatures" => c(
            "Require signatures",
            "registry",
            "Index only signed, verifiable surface content.",
            &[
                ("On", "the indexer fails closed: a release tag or channel that isn't signed by a pinned trust anchor is rejected, never served. The safe default."),
                ("Off", "unsigned content is indexed and served unverified — only for a fully-trusted internal source."),
            ],
        ),
        "registry.readme" => c(
            "Readme",
            "registry",
            "A longer preamble shown above the registry's home page.",
            &[
                ("Markdown-ish", "a paragraph or three of plain text; blank lines separate paragraphs."),
                ("Optional", "leave empty for just the one-line description."),
            ],
        ),
        "registry.content_addressed" => c(
            "Content-addressed",
            "registry",
            "Whether the registry records content addresses in its realisation graph.",
            &[
                ("On", "the producer records the store/ realisation graph (RFC-0005), so the registry serves both input-addressed and content-addressed consumers. The default."),
                ("Off", "a pure input-addressed registry; set this only when the producer never records content addresses."),
            ],
        ),
        "registry.caches" => c(
            "Binary caches",
            "registry",
            "Substituters every consumer of this registry should use, in preference order (first is highest).",
            &[
                ("URL", "the base URL of a binary cache the registry advertises to its consumers."),
                ("Order", "rows are tried top to bottom; the first listed cache is highest priority."),
                ("Advanced", "a registry may define a nestable [caches] stack (a mirror, or nesting); that is preserved here and edited via raw TOML."),
            ],
        ),
        "registry.trust_anchors" => c(
            "Trust anchors",
            "registry",
            "The public keys whose signatures this registry will trust.",
            &[
                ("Format", "one per line, name:Ed25519:<base64> — the line a signer publishes."),
                ("Why", "consumers verify the catalog against these; with \"require signatures\" on, content signed by anything else is rejected."),
                ("Optional", "may be left empty now and set later via the signed keys.toml roster flow."),
            ],
        ),
        "registry.visibility" | "cache.visibility" => c(
            "Visibility",
            "",
            "Who can read this without a token.",
            &[
                ("public", "anyone, anonymously — every package/channel is world-readable."),
                ("internal", "any authenticated member of the org."),
                ("private", "only principals explicitly granted read; anonymous reads fail."),
            ],
        ),
        // -- policies --------------------------------------------------------
        "registry.crawl_policy" => c(
            "Crawl policy",
            "registry",
            "What the generated robots.txt tells web crawlers.",
            &[
                ("allow_all", "every crawler may index the registry's web pages."),
                ("allow_no_ai", "blocks known AI crawlers (GPTBot, ClaudeBot, …); others allowed."),
                ("deny_all", "blocks every crawler."),
            ],
        ),
        "instance.signup_policy" => c(
            "Signup policy",
            "instance",
            "Who may create a new organization on this deployment.",
            &[
                ("invite_only", "an existing membership, an invitation, or an instance admin is required."),
                ("open", "any signed-in user can create an org."),
            ],
        ),
        "instance.signup_domains" => c(
            "Signup domain allowlist",
            "instance",
            "Restrict signups to specific email domains.",
            &[
                ("Set", "only users whose email domain is on the list may create their first org; existing members and admins are exempt."),
                ("Empty", "any email domain may sign up (subject to the signup policy)."),
            ],
        ),
        "instance.password_login" => c(
            "Password login",
            "instance",
            "Whether local email + password sign-in is offered.",
            &[
                ("On", "users can sign in with a password (and via SSO / magic link)."),
                ("Off", "password sign-in is refused; only SSO and magic-link remain."),
            ],
        ),
        "instance.session_lifetime" => c(
            "Session lifetime",
            "instance",
            "Absolute lifetime of a console session, in seconds.",
            &[
                ("Set", "sessions expire this many seconds after sign-in, forcing re-authentication."),
                ("Empty", "uses the built-in default lifetime."),
            ],
        ),
        "instance.max_upload" => c(
            "Max upload",
            "instance",
            "Largest single surface upload the hub accepts, in bytes.",
            &[
                ("Set", "an upload whose body exceeds this is rejected with 413."),
                ("Empty", "uses the built-in default cap."),
            ],
        ),
        "instance.announcement" => c(
            "Announcement banner",
            "instance",
            "A short notice shown on every console page.",
            &[
                ("Set", "the text renders in a banner above every page (HTML-escaped)."),
                ("Empty", "no banner is shown."),
            ],
        ),
        "binding.endpoint" => c(
            "Endpoint",
            "storage",
            "The S3/R2 API endpoint URL (with scheme).",
            &[
                ("S3/R2", "e.g. https://<account>.r2.cloudflarestorage.com — the API the hub writes objects through."),
            ],
        ),
        "binding.region" => c(
            "Region",
            "storage",
            "The S3 region for this binding.",
            &[
                ("auto", "use `auto` for Cloudflare R2."),
                ("region", "for S3, the bucket's region (e.g. us-east-1)."),
            ],
        ),
        "cache.prefix" => c(
            "Prefix",
            "cache",
            "Path prefix within the storage binding where this cache's objects live.",
            &[
                ("Set", "the cache's narinfo/.nar objects are stored under this sub-path."),
                ("Empty", "defaults to the cache slug on the deployment's default storage."),
            ],
        ),
        "registry.prefix" => c(
            "Prefix",
            "registry",
            "Path prefix within the storage binding for this registry's surface.",
            &[
                ("Set", "the registry's git/index surface lives under this sub-path of the binding."),
                ("Empty", "defaults to the registry slug."),
            ],
        ),
        // -- upstream mirror -------------------------------------------------
        "mirror.mode" => c(
            "Mirror mode",
            "registry",
            "How an upstream registry is mirrored.",
            &[
                ("full", "a scheduled full copy of the upstream surface."),
                ("pullthrough", "fetch objects from the upstream on demand (on cache miss)."),
            ],
        ),
        "mirror.verify" => c(
            "Verify upstream signatures",
            "registry",
            "Require valid upstream signatures before indexing mirrored content.",
            &[
                ("On", "content that fails signature verification against the upstream's trust anchors is rejected."),
                ("Off", "mirrored content is indexed without verifying upstream signatures."),
            ],
        ),
        // -- webhooks / SSO --------------------------------------------------
        "webhook.secret_version_ref" => c(
            "Signing secret version",
            "webhook",
            "Immutable provider reference resolved only while signing a delivery.",
            &[
                ("Reference", "identifies one exact operator-managed secret version; never put plaintext signing material in this field."),
                ("Fingerprint", "optionally pins the SHA-256 digest of the resolved value so provider drift fails closed."),
            ],
        ),
        "sso.endpoints" => c(
            "OIDC endpoints",
            "sso",
            "Discovery values from your identity provider (full https URLs).",
            &[
                ("issuer", "the IdP's issuer identifier."),
                ("authorization / token / JWKS", "the OAuth2/OIDC endpoints the hub redirects to and validates tokens against."),
            ],
        ),
        "sso.jit" => c(
            "Just-in-time provisioning",
            "sso",
            "Auto-create accounts for unknown SSO users on first login.",
            &[
                ("On", "a successful SSO login for an unknown email creates an account (with the default role)."),
                ("Off", "only pre-existing members may sign in via SSO."),
            ],
        ),
        "sso.enforce" => c(
            "Force SSO",
            "sso",
            "Require org members to authenticate through SSO.",
            &[
                ("On", "members must use the IdP; password/magic-link is refused for them."),
                ("Off", "SSO is offered but not required."),
            ],
        ),
        _ => return None,
    })
}

/// Render the `?` help affordance for `key` (with its hidden detail card), or an
/// empty string if `key` has no defined card.
///
/// Place it right after a control's label text. The card content is rendered
/// into the DOM (hidden); `app.js` turns it into a positioned popover, and the
/// `title` attribute is the no-JS floor.
#[must_use]
pub fn marker(key: &str) -> String {
    let Some(card) = card(key) else {
        return String::new();
    };
    let mut segs = String::new();
    for (label, text) in card.segments {
        let _ = write!(
            segs,
            "<span class=\"help-seg\"><b>{}</b> {}</span>",
            escape(label),
            escape(text),
        );
    }
    let tag = if card.tag.is_empty() {
        String::new()
    } else {
        format!("<span class=\"help-tag\">{}</span>", escape(card.tag))
    };
    format!(
        "<span class=\"help\"><button type=\"button\" class=\"help-mark\" \
         aria-label=\"About {term}\" title=\"{summary}\">?</button>\
         <span class=\"help-card\" role=\"tooltip\">\
         <span class=\"help-head\">{term}{tag}</span>\
         <span class=\"help-sum\">{summary}</span>{segs}</span></span>",
        term = escape(card.term),
        summary = escape(card.summary),
        tag = tag,
        segs = segs,
    )
}

/// Render a level-1 glance hint — a small dim one-liner placed after a control.
#[must_use]
pub fn hint(text: &str) -> String {
    format!("<span class=\"hint\">{}</span>", escape(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_renders_card_for_known_key() {
        let html = marker("cache.mass_query");
        assert!(html.contains("class=\"help\""));
        assert!(html.contains("class=\"help-card\""));
        assert!(html.contains("Mass-query"));
        // Both on and off states appear as segments.
        assert!(html.contains("<b>On</b>"));
        assert!(html.contains("<b>Off</b>"));
        // The summary doubles as the no-JS title tooltip.
        assert!(html.contains("title=\"Lets clients ask"));
    }

    #[test]
    fn unknown_key_renders_nothing() {
        assert_eq!(marker("nope.nope"), "");
        assert!(card("nope.nope").is_none());
    }

    #[test]
    fn shared_keys_resolve() {
        assert!(card("registry.visibility").is_some());
        assert!(card("cache.visibility").is_some());
    }

    #[test]
    fn hint_is_a_dim_one_liner() {
        assert_eq!(hint("optional"), "<span class=\"hint\">optional</span>");
    }
}
