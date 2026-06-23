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
        // -- cache <-> registry link ----------------------------------------
        "link.advertised" => c(
            "Advertise to consumers",
            "link",
            "Put this cache in the registry's published substituter list.",
            &[
                ("On", "consumers of the registry are told to pull binaries from this cache automatically."),
                ("Off", "the link exists (e.g. for GC roots) but the cache is not advertised; consumers won't use it unless they add it themselves."),
            ],
        ),
        "link.roots_packages" => c(
            "Pin GC roots from packages",
            "link",
            "Keep this cache from evicting paths the registry still ships.",
            &[
                ("On", "the registry's live package store-paths are treated as GC roots in this cache, so garbage collection never deletes a binary the catalog still references."),
                ("Off", "GC ignores the registry; only the cache's own roots/policy protect objects."),
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
