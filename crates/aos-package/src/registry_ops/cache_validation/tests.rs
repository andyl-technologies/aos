//! Tests for hTTP cache reachability validation and removal of missing catalog entries.

use super::{
    CacheValidationEntry, collect_cache_validation_entries, remove_missing_cache_entries,
    validate_cache_entry,
};
use crate::types::CacheEntry;
use std::fs;
use tempfile::TempDir;

#[test]
fn cache_validation_entries_honor_package_and_platform_filters() {
    let tmp = TempDir::new().unwrap();
    let pkg_dir = tmp.path().join("packages").join("t");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("tool.toml"),
        r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.0.0"
nar_hash = "sha256:x86"
nar_size = 1
closure_size = 1
references = []

[versions.platforms.aarch64-linux]
store_path = "/nix/store/bbb222-tool-1.0.0"
nar_hash = "sha256:arm"
nar_size = 1
closure_size = 1
references = []

[[versions.platforms.aarch64-linux.images]]
format = "raw"
store_path = "/nix/store/ccc333-tool-image-1.0.0"
nar_hash = "sha256:image"
nar_size = 1
"#,
    )
    .unwrap();

    let entries =
        collect_cache_validation_entries(tmp.path(), Some("tool"), Some("aarch64-linux")).unwrap();
    assert_eq!(
        entries,
        vec![
            CacheValidationEntry {
                name: "tool".into(),
                platform: "aarch64-linux".into(),
                store_path: "/nix/store/bbb222-tool-1.0.0".into(),
                store_hash: "bbb222".into(),
                nar_hashes: vec!["sha256:arm".into()],
            },
            CacheValidationEntry {
                name: "tool".into(),
                platform: "aarch64-linux".into(),
                store_path: "/nix/store/ccc333-tool-image-1.0.0".into(),
                store_hash: "ccc333".into(),
                nar_hashes: vec!["sha256:image".into()],
            },
        ]
    );
    assert!(
        collect_cache_validation_entries(tmp.path(), Some("missing"), None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn remove_missing_cache_entries_prunes_platforms_and_images() {
    let tmp = TempDir::new().unwrap();
    let pkg_dir = tmp.path().join("packages/t");
    fs::create_dir_all(&pkg_dir).unwrap();
    let toml_path = pkg_dir.join("tool.toml");
    fs::write(
        &toml_path,
        r#"[package]
name = "tool"
description = "test"
license = "MIT"
maintainer = "test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaa111-tool-1.0.0"
nar_hash = "sha256:x86"
nar_size = 1
closure_size = 1
references = []

[versions.platforms.aarch64-linux]
store_path = "/nix/store/bbb222-tool-1.0.0"
nar_hash = "sha256:arm"
nar_size = 1
closure_size = 1
references = []

[[versions.platforms.aarch64-linux.images]]
format = "raw"
store_path = "/nix/store/ccc333-tool-image-1.0.0"
nar_hash = "sha256:image"
nar_size = 1
"#,
    )
    .unwrap();

    let mut missing = std::collections::HashSet::new();
    missing.insert("/nix/store/ccc333-tool-image-1.0.0".to_string());
    assert_eq!(
        remove_missing_cache_entries(tmp.path(), &missing).unwrap(),
        1
    );
    let toml_val: toml::Value = toml::from_str(&fs::read_to_string(&toml_path).unwrap()).unwrap();
    let aarch64 = toml_val
        .get("versions")
        .and_then(|versions| versions.as_array())
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("platforms"))
        .and_then(|platforms| platforms.get("aarch64-linux"))
        .unwrap();
    assert!(aarch64.get("images").is_none());

    missing.clear();
    missing.insert("/nix/store/bbb222-tool-1.0.0".to_string());
    assert_eq!(
        remove_missing_cache_entries(tmp.path(), &missing).unwrap(),
        1
    );
    let toml_val: toml::Value = toml::from_str(&fs::read_to_string(&toml_path).unwrap()).unwrap();
    let platforms = toml_val
        .get("versions")
        .and_then(|versions| versions.as_array())
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("platforms"))
        .and_then(|platforms| platforms.as_table())
        .unwrap();
    assert!(platforms.contains_key("x86_64-linux"));
    assert!(!platforms.contains_key("aarch64-linux"));

    missing.clear();
    missing.insert("/nix/store/aaa111-tool-1.0.0".to_string());
    assert_eq!(
        remove_missing_cache_entries(tmp.path(), &missing).unwrap(),
        1
    );
    assert!(!toml_path.exists());
}

#[tokio::test]
async fn cache_validation_entry_follows_narinfo_url() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            let narinfo = concat!(
                "StorePath: /nix/store/abc123-tool-1.0.0\n",
                "URL: nar/abc123-sha256-test.nar.zst\n",
                "Compression: zstd\n",
                "NarHash: sha256:test\n",
                "NarSize: 1\n",
            );
            let response = if req.starts_with("GET /abc123.narinfo ") {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    narinfo.len(),
                    narinfo,
                )
            } else if req.starts_with("HEAD /nar/abc123-sha256-test.nar.zst ") {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });

    let result = validate_cache_entry(
        &reqwest::Client::new(),
        &[CacheEntry {
            url: format!("http://{addr}"),
            priority: 100,
        }],
        CacheValidationEntry {
            name: "tool".into(),
            platform: "x86_64-linux".into(),
            store_path: "/nix/store/abc123-tool-1.0.0".into(),
            store_hash: "abc123".into(),
            nar_hashes: vec!["sha256:test".into()],
        },
    )
    .await;

    assert!(result.found, "{result:?}");
    server.await.unwrap();
}
