//! Machine-surface path classification and R2 key mapping (RFC-0004).
//!
//! Every registry URL is simultaneously a dumb-HTTP git origin and a Nix binary
//! cache (RFC-0004 "URL design"). This module is the **single, runtime-neutral**
//! source of truth for classifying a request path into the machine surface and
//! deriving its `Cache-Control`/`Content-Type` — the byte-faithful serving
//! contract (the immutable/60-second cache split `apr origin upload` writes)
//! must hold identically on the native hub and the Cloudflare Worker. Both
//! shells use these functions (the native hub's `compat` and the Worker's
//! facade re-export them), so the two facades cannot drift.
//!
//! It also maps a registry prefix + machine path to an R2 object key, since a
//! registry is a *prefix* within a shared hub-owned bucket (RFC-0004 "Storage").
//! These are pure functions free of any platform types, so they compile to
//! `wasm32` and are unit-tested once here.
//!
//! # R2 key layout
//!
//! ```text
//! request   GET /demo/channels/stable/00          (slug = "demo")
//! prefix    "demo/"                                (the registry's R2 prefix)
//! key       "demo/channels/stable/00"             (prefix + machine path)
//! ```

/// The machine-surface directory prefixes (also valid as bare paths).
const MACHINE_DIRS: [&str; 7] = [
    "info", "objects", "channels", "releases", "nar", "web", "browse",
];

/// Cache-control for content-addressed (immutable) payloads.
pub const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
/// Cache-control for mutable pointers.
pub const MUTABLE_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

/// Whether a relative path belongs to the machine surface.
///
/// The registry-root machine paths (`HEAD`, `nix-cache-info`, `index.html`,
/// `*.narinfo`) plus every file and directory under the machine prefixes.
/// Anything else under a registry URL is either the human `/-/` namespace or
/// not found.
#[must_use]
pub fn is_machine_path(path: &str) -> bool {
    path == "HEAD"
        || path == "nix-cache-info"
        || path == "index.html"
        || path.ends_with(".narinfo")
        || MACHINE_DIRS
            .iter()
            .any(|dir| path == *dir || path.starts_with(&format!("{dir}/")))
}

/// Classify a machine path into its `Cache-Control` header.
///
/// Follows `classify_git_path` in `apr`'s `static_upload.rs`: under `objects/`
/// only `objects/info/**` is mutable; `releases/**` and `nar/**` are
/// content-addressed; under `web/` only `config.json`, `index.json`, and
/// `packages/**` are mutable; everything else (refs, channel partitions,
/// narinfos, server-info) revalidates.
#[must_use]
pub fn cache_control(path: &str) -> &'static str {
    let immutable = if let Some(rest) = path.strip_prefix("objects/") {
        !rest.starts_with("info/")
    } else if let Some(rest) = path.strip_prefix("web/") {
        rest != "config.json" && rest != "index.json" && !rest.starts_with("packages/")
    } else {
        path.starts_with("releases/") || path.starts_with("nar/")
    };
    if immutable {
        IMMUTABLE_CACHE_CONTROL
    } else {
        MUTABLE_CACHE_CONTROL
    }
}

/// The `Content-Type` for a machine path.
#[must_use]
pub fn content_type(path: &str) -> &'static str {
    if path.ends_with(".narinfo") {
        "text/x-nix-narinfo"
    } else if path.ends_with(".nar.zst") || path.ends_with(".zst") {
        "application/zstd"
    } else if path.ends_with(".nar.xz") || path.ends_with(".xz") {
        "application/x-xz"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".js") {
        "text/javascript"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else if path == "HEAD" || path == "nix-cache-info" || path.starts_with("info/") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

/// Map a registry prefix and a machine path to its R2 object key.
///
/// The registry's surface lives under `{prefix}` in the hub-owned bucket
/// (RFC-0004 "Storage": registries as prefixes in a shared bucket). The key is
/// the prefix joined to the machine path with a single `/` separator; a leading
/// `/` on either side is normalized so an empty prefix (a dedicated
/// bucket-per-registry, or a test) maps the path through unchanged.
///
/// # Examples
///
/// ```
/// use aos_hub_core::keymap::r2_key;
/// assert_eq!(r2_key("demo/", "channels/stable/00"), "demo/channels/stable/00");
/// assert_eq!(r2_key("demo", "HEAD"), "demo/HEAD");
/// assert_eq!(r2_key("", "nix-cache-info"), "nix-cache-info");
/// ```
#[must_use]
pub fn r2_key(prefix: &str, path: &str) -> String {
    let prefix = prefix.trim_matches('/');
    let path = path.trim_start_matches('/');
    if prefix.is_empty() {
        path.to_string()
    } else {
        format!("{prefix}/{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_paths_match_native_classification() {
        for path in [
            "HEAD",
            "info/refs",
            "objects/ab/cd",
            "objects/info/packs",
            "channels/stable/00",
            "releases/1/2/3/pack/p.pack.zst",
            "nix-cache-info",
            "abcd.narinfo",
            "nar/x.nar.zst",
            "index.html",
            "web/index.json",
            "browse/curl.html",
        ] {
            assert!(is_machine_path(path), "{path}");
        }
        for dir in [
            "objects",
            "objects/",
            "channels",
            "channels/stable/",
            "releases/",
            "nar",
            "info",
            "web/",
            "browse",
        ] {
            assert!(is_machine_path(dir), "{dir}");
        }
        assert!(!is_machine_path("-/packages"));
        assert!(!is_machine_path("random"));
        assert!(!is_machine_path("objectstore"), "prefixes must not bleed");
    }

    #[test]
    fn cache_classes_follow_static_upload() {
        for immutable in [
            "objects/ab/cd",
            "releases/1/2/3/pack/p",
            "nar/x.nar.zst",
            "web/app-ab12cd_bg.wasm",
            "web/app-ab12cd.js",
            "web/style-ab12cd.css",
        ] {
            assert_eq!(
                cache_control(immutable),
                IMMUTABLE_CACHE_CONTROL,
                "{immutable}"
            );
        }
        for mutable in [
            "HEAD",
            "info/refs",
            "objects/info/packs",
            "channels/stable/00",
            "nix-cache-info",
            "abcd.narinfo",
            "index.html",
            "web/config.json",
            "web/index.json",
            "web/packages/curl.json",
            "browse/curl.html",
        ] {
            assert_eq!(cache_control(mutable), MUTABLE_CACHE_CONTROL, "{mutable}");
        }
    }

    #[test]
    fn content_types_cover_wire_formats() {
        assert_eq!(content_type("abcd.narinfo"), "text/x-nix-narinfo");
        assert_eq!(content_type("nar/x.nar.zst"), "application/zstd");
        assert_eq!(content_type("web/app.wasm"), "application/wasm");
        assert_eq!(content_type("HEAD"), "text/plain; charset=utf-8");
        assert_eq!(content_type("web/index.json"), "application/json");
    }

    #[test]
    fn r2_key_joins_prefix_and_path() {
        assert_eq!(
            r2_key("demo/", "channels/stable/00"),
            "demo/channels/stable/00"
        );
        assert_eq!(r2_key("demo", "HEAD"), "demo/HEAD");
        assert_eq!(r2_key("/demo/", "/HEAD"), "demo/HEAD");
        assert_eq!(r2_key("", "nix-cache-info"), "nix-cache-info");
        assert_eq!(
            r2_key("acme/infra/prod", "nar/x.nar"),
            "acme/infra/prod/nar/x.nar"
        );
    }
}
