//! The machine-path facade: byte-faithful registry serving.
//!
//! Every registry URL the hub serves is simultaneously a dumb-HTTP git
//! origin and a Nix binary cache (RFC-0004 "URL design"). This module
//! serves those machine paths from the registry's storage source:
//! `file://` sources are read and served directly; `http(s)://` sources
//! are answered with a redirect to the upstream CDN, keeping the hub out
//! of the byte path.
//!
//! Cache headers mirror `apr origin upload`'s two-class model
//! (`crates/aos-package/src/registry/static_upload.rs`): immutable
//! content-addressed payloads get a one-year `immutable` lifetime, mutable
//! pointers (`HEAD`, refs, channel partitions, narinfos, server info) get
//! 60 seconds with revalidation.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::db::RegistryRecord;
use crate::fetch::{LocalFsFetch, SurfaceFetch};

/// Cache-control for content-addressed (immutable) payloads.
pub const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
/// Cache-control for mutable pointers.
pub const MUTABLE_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

/// Whether a relative path belongs to the machine surface.
///
/// Anything else under a registry URL is either the human `/-/` namespace
/// (routed before the facade) or not found.
pub fn is_machine_path(path: &str) -> bool {
    path == "HEAD"
        || path == "nix-cache-info"
        || path == "index.html"
        || path.starts_with("info/")
        || path.starts_with("objects/")
        || path.starts_with("channels/")
        || path.starts_with("releases/")
        || path.starts_with("nar/")
        || path.starts_with("web/")
        || path.starts_with("browse/")
        || path.ends_with(".narinfo")
}

/// Classify a machine path into its cache-control header.
///
/// Mirrors `classify_git_path` in `static_upload.rs`: under `objects/`
/// only `objects/info/**` is mutable; `releases/**` and `nar/**` are
/// content-addressed; refs, channel partitions, narinfos, and server-info
/// files are mutable pointers.
pub fn cache_control(path: &str) -> &'static str {
    let immutable = if let Some(rest) = path.strip_prefix("objects/") {
        !rest.starts_with("info/")
    } else {
        path.starts_with("releases/") || path.starts_with("nar/")
    };
    if immutable {
        IMMUTABLE_CACHE_CONTROL
    } else {
        MUTABLE_CACHE_CONTROL
    }
}

/// The Content-Type for a machine path.
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

/// Serve one machine path for a registry.
///
/// `file://` (or bare-path) sources are served from disk; `http(s)://`
/// sources answer with `302` to the upstream URL so bulk bytes never
/// transit the hub.
pub async fn serve_machine_path(registry: &RegistryRecord, path: &str) -> Response {
    if !is_machine_path(path) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let source = registry.source_url.as_str();
    if source.starts_with("http://") || source.starts_with("https://") {
        let location = format!("{}/{path}", source.trim_end_matches('/'));
        return (
            StatusCode::FOUND,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, MUTABLE_CACHE_CONTROL.to_string()),
            ],
        )
            .into_response();
    }

    let root = source.strip_prefix("file://").unwrap_or(source);
    let fetch = LocalFsFetch::new(root);
    match fetch.fetch(path).await {
        Ok(Some(bytes)) => {
            let mut response = bytes.into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type(path)),
            );
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static(cache_control(path)),
            );
            response
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::warn!(%path, error = %format!("{err:#}"), "facade read failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_paths_are_recognized() {
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
        assert!(!is_machine_path("-/packages"));
        assert!(!is_machine_path("random"));
    }

    #[test]
    fn cache_classes_mirror_static_upload() {
        assert_eq!(cache_control("objects/ab/cd"), IMMUTABLE_CACHE_CONTROL);
        assert_eq!(
            cache_control("releases/1/2/3/pack/p"),
            IMMUTABLE_CACHE_CONTROL
        );
        assert_eq!(cache_control("nar/x.nar.zst"), IMMUTABLE_CACHE_CONTROL);
        for mutable in [
            "HEAD",
            "info/refs",
            "objects/info/packs",
            "channels/stable/00",
            "nix-cache-info",
            "abcd.narinfo",
            "index.html",
            "web/index.json",
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
    }
}
