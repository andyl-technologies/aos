//! The machine-path facade: byte-faithful registry serving.
//!
//! Every registry URL the hub serves is simultaneously a dumb-HTTP git
//! origin and a Nix binary cache (RFC-0004 "URL design"). This module
//! serves those machine paths from the registry's storage source:
//! `file://` sources are read and served directly; `http(s)://` sources
//! are answered with a redirect to the upstream CDN, keeping the hub out
//! of the byte path.
//!
//! Cache headers follow `apr origin upload`'s two-class model
//! (`crates/aos-package/src/registry/static_upload.rs`): immutable
//! content-addressed payloads (loose objects, release packs, NARs,
//! hash-named `web/` assets) get a one-year `immutable` lifetime, mutable
//! pointers (`HEAD`, refs, channel partitions, narinfos, server info,
//! `index.html`, `browse/` pages, and the `web/` JSON snapshots) get
//! 60 seconds with revalidation.
//!
//! Directory paths on `file://` sources render a minimal Debian-style
//! HTML autoindex (the raw directory-listing fallback from RFC-0004's UI
//! surface map); `http(s)://` sources keep redirecting upstream.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::db::RegistryRecord;
use crate::fetch::{safe_join, LocalFsFetch, SurfaceFetch};
use crate::ui::render::escape;

/// Cache-control for content-addressed (immutable) payloads.
pub const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
/// Cache-control for mutable pointers.
pub const MUTABLE_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

/// The machine-surface directory prefixes (also valid as bare paths, for
/// the autoindex fallback).
const MACHINE_DIRS: [&str; 7] = [
    "info", "objects", "channels", "releases", "nar", "web", "browse",
];

/// Whether a relative path belongs to the machine surface.
///
/// Directory forms of the machine prefixes (`objects`, `channels/stable/`,
/// …) are machine paths too, so `file://` sources can answer them with an
/// autoindex. Anything else under a registry URL is either the human
/// `/-/` namespace (routed before the facade) or not found.
pub fn is_machine_path(path: &str) -> bool {
    path == "HEAD"
        || path == "nix-cache-info"
        || path == "index.html"
        || path.ends_with(".narinfo")
        || MACHINE_DIRS
            .iter()
            .any(|dir| path == *dir || path.starts_with(&format!("{dir}/")))
}

/// Classify a machine path into its cache-control header.
///
/// Follows `classify_git_path` in `static_upload.rs` for the git surface
/// — under `objects/` only `objects/info/**` is mutable; `releases/**`
/// and `nar/**` are content-addressed — and extends it to the web
/// surface: hash-named files under `web/` are immutable, while the
/// mutable pointers (`web/config.json`, `web/index.json`, the
/// `web/packages/` snapshots, `browse/` pages, `index.html`) plus refs,
/// channel partitions, narinfos, and server-info files revalidate.
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
/// `file://` (or bare-path) sources are served from disk, with directory
/// paths answered by a minimal HTML autoindex; `http(s)://` sources
/// answer with `302` to the upstream URL (carrying the path's cache
/// class) so bulk bytes never transit the hub.
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
                (header::LOCATION, location.as_str()),
                (header::CACHE_CONTROL, cache_control(path)),
            ],
        )
            .into_response();
    }

    let root = source.strip_prefix("file://").unwrap_or(source);

    // Directory paths get a Debian-style autoindex instead of a file read.
    // The same symlink containment that protects file reads applies here:
    // a symlinked directory escaping the surface root is never listed.
    if let Ok(full) = safe_join(std::path::Path::new(root), path.trim_end_matches('/')) {
        if full.is_dir() {
            if !dir_is_contained(std::path::Path::new(root), &full) {
                return StatusCode::NOT_FOUND.into_response();
            }
            if !path.ends_with('/') {
                // Redirect to the trailing-slash form so the autoindex's
                // relative links resolve under the directory.
                let location = format!("/{}/{path}/", registry.slug);
                return (
                    StatusCode::FOUND,
                    [
                        (header::LOCATION, location.as_str()),
                        (header::CACHE_CONTROL, MUTABLE_CACHE_CONTROL),
                    ],
                )
                    .into_response();
            }
            return autoindex(&registry.slug, path, &full).await;
        }
    }

    let fetch = LocalFsFetch::new(root);
    match fetch.fetch(path).await {
        // Symlink containment for file reads happens inside LocalFsFetch.
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

/// Whether a directory, after resolving symlinks, still lives under the
/// surface root — the directory analogue of `LocalFsFetch`'s file-read
/// containment, so a symlinked directory cannot leak outside entry names
/// through the autoindex.
fn dir_is_contained(root: &std::path::Path, dir: &std::path::Path) -> bool {
    match (std::fs::canonicalize(root), std::fs::canonicalize(dir)) {
        (Ok(root), Ok(dir)) => dir.starts_with(&root),
        _ => false,
    }
}

/// Render a minimal Debian-style autoindex for one surface directory.
///
/// Entries are plain relative links (directories with a trailing `/`),
/// preceded by a parent link — no stylesheet, no scripts, nothing beyond
/// what `lynx` needs. Directory listings are mutable pointers.
async fn autoindex(slug: &str, path: &str, dir: &std::path::Path) -> Response {
    let mut reader = match tokio::fs::read_dir(dir).await {
        Ok(reader) => reader,
        Err(err) => {
            tracing::warn!(%path, error = %err, "autoindex read failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let mut entries: Vec<String> = Vec::new();
    while let Ok(Some(entry)) = reader.next_entry().await {
        let mut name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
            name.push('/');
        }
        entries.push(name);
    }
    entries.sort();

    let title = escape(&format!("/{slug}/{path}"));
    let mut html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">\
         <title>Index of {title}</title></head>\n<body>\n<h1>Index of {title}</h1>\n\
         <pre><a href=\"../\">../</a>\n"
    );
    for name in &entries {
        let name = escape(name);
        html.push_str(&format!("<a href=\"{name}\">{name}</a>\n"));
    }
    html.push_str("</pre>\n</body>\n</html>\n");

    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, MUTABLE_CACHE_CONTROL),
        ],
        html,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal phase-1 `file://`-style registry record for facade tests.
    fn test_registry(source_url: String) -> RegistryRecord {
        RegistryRecord {
            id: 1,
            slug: "demo".into(),
            source_url,
            trust_keys: vec![],
            require_signatures: false,
            org_id: None,
            project_path: String::new(),
            visibility: "public".into(),
            storage_binding_id: None,
            prefix: String::new(),
        }
    }

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
        // Directory forms (bare and trailing-slash) are machine paths too,
        // so file:// sources can answer them with an autoindex.
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

    #[cfg(unix)]
    #[tokio::test]
    async fn autoindex_refuses_symlinked_directory_escape() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"top secret").unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("channels")).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("channels/stable")).unwrap();
        let registry = test_registry(dir.path().display().to_string());
        let response = serve_machine_path(&registry, "channels/stable/").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn autoindex_lists_directories_and_redirects_bare_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("channels/stable")).unwrap();
        std::fs::write(dir.path().join("channels/stable/00"), b"payload").unwrap();
        std::fs::write(dir.path().join("channels/stable/<evil>"), b"x").unwrap();
        let registry = test_registry(dir.path().display().to_string());

        // Trailing-slash directory: an HTML listing with relative links.
        let response = serve_machine_path(&registry, "channels/stable/").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            MUTABLE_CACHE_CONTROL
        );
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Index of /demo/channels/stable/"));
        assert!(html.contains("<a href=\"00\">00</a>"));
        assert!(html.contains("<a href=\"../\">../</a>"));
        assert!(html.contains("&lt;evil&gt;"), "names are escaped");
        assert!(!html.contains("<evil>"));

        // Bare directory paths redirect to the trailing-slash form.
        let response = serve_machine_path(&registry, "channels/stable").await;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers()[header::LOCATION],
            "/demo/channels/stable/"
        );

        // Files under the same prefix are unaffected.
        let response = serve_machine_path(&registry, "channels/stable/00").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn content_types_cover_wire_formats() {
        assert_eq!(content_type("abcd.narinfo"), "text/x-nix-narinfo");
        assert_eq!(content_type("nar/x.nar.zst"), "application/zstd");
        assert_eq!(content_type("web/app.wasm"), "application/wasm");
        assert_eq!(content_type("HEAD"), "text/plain; charset=utf-8");
    }
}
