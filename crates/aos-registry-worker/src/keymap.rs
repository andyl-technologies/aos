//! The R2 machine-path facade: key mapping and cache/content classification.
//!
//! Every registry URL the Worker serves is simultaneously a dumb-HTTP git
//! origin and a Nix binary cache (RFC-0004 "URL design"). On the Workers
//! target the bytes live in an R2 bucket bound at deploy time, and a registry
//! is a *prefix* within a shared hub bucket (RFC-0004 "Storage": "one (or a
//! few) hub-owned shared buckets bound at deploy time, with registries as
//! prefixes"). This module is the pure mapping between a request path and the
//! R2 object key, plus the per-object `Cache-Control`/`Content-Type`
//! classification.
//!
//! These are deliberately faithful copies of the native hub's
//! `compat::{is_machine_path, cache_control, content_type}` (the facade
//! classification is the same on every runtime) so the byte-faithful serving
//! contract — the immutable/60-second cache split from `apr origin upload`'s
//! `static_upload.rs` — holds identically on Workers. Keeping them here, pure
//! and free of any `worker` types, lets the native test suite assert the
//! Worker and native facades agree.
//!
//! # R2 key layout
//!
//! ```text
//! request   GET /demo/channels/stable/00          (slug = "demo")
//! prefix    "demo/"                                (the registry's R2 prefix)
//! key       "demo/channels/stable/00"             (prefix + machine path)
//! ```

/// The machine-surface directory prefixes (also valid as bare paths).
///
/// Mirrors the native `compat::MACHINE_DIRS`.
const MACHINE_DIRS: [&str; 7] = [
    "info", "objects", "channels", "releases", "nar", "web", "browse",
];

/// Cache-control for content-addressed (immutable) payloads.
pub const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
/// Cache-control for mutable pointers.
pub const MUTABLE_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

/// Whether a relative path belongs to the machine surface.
///
/// A faithful copy of the native `compat::is_machine_path`: the registry-root
/// machine paths (`HEAD`, `nix-cache-info`, `index.html`, `*.narinfo`) plus
/// every file and directory under the machine prefixes. Anything else under a
/// registry URL is either the human `/-/` namespace (not served by this
/// read-only Worker) or not found.
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
/// A faithful copy of the native `compat::cache_control`, which follows
/// `classify_git_path` in `apr`'s `static_upload.rs`: under `objects/` only
/// `objects/info/**` is mutable; `releases/**` and `nar/**` are
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
///
/// A faithful copy of the native `compat::content_type`.
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
/// use aos_registry_worker::keymap::r2_key;
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
