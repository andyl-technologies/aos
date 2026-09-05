//! Tests for registry selection, committed configuration, upload defaults, and display formatting.

use super::{
    format_size, registry_upload_auth_config, resolve_effective_release_cache_url,
    resolve_upload_urls,
};
use crate::config::ApmConfig;
use crate::registry_ops::test_support::test_registry_config;
use crate::types::{ApmSettings, ProfileScope, RegistryUploadAuthConfig};

#[test]
fn resolve_upload_urls_prefers_flags_over_persisted_defaults() {
    let upload_auth = RegistryUploadAuthConfig {
        upload_urls: vec!["s3://persisted/".to_string()],
        ..RegistryUploadAuthConfig::default()
    };
    let config = ApmConfig {
        settings: ApmSettings::default(),
        registries: vec![(test_registry_config("aos-core", Some(upload_auth)), None)],
        scope: ProfileScope::User,
    };

    let flags = vec!["s3://flag/".to_string()];
    assert_eq!(resolve_upload_urls(&config, "aos-core", &flags), flags);
    assert_eq!(
        resolve_upload_urls(&config, "aos-core", &[]),
        vec!["s3://persisted/".to_string()],
    );
    // A registry with no persisted defaults resolves to no destinations.
    assert!(resolve_upload_urls(&config, "other", &[]).is_empty());
}

#[test]
fn release_cache_url_derives_from_single_http_upload_only() {
    assert_eq!(
        resolve_effective_release_cache_url(
            None,
            &["https://cache.example/root".to_string()],
            true,
        )
        .unwrap()
        .as_deref(),
        Some("https://cache.example/root"),
    );
    // Write-only single destinations cannot be advertised as a read URL.
    for write_only in [
        "file:///tmp/origin",
        "s3://bucket/prefix",
        "sftp://host/srv/cache",
    ] {
        assert!(
            resolve_effective_release_cache_url(None, &[write_only.to_string()], true).is_err(),
            "{write_only} should require an explicit --cache-url",
        );
    }
    assert!(
        resolve_effective_release_cache_url(
            None,
            &[
                "https://cache.example/a".to_string(),
                "https://cache.example/b".to_string(),
            ],
            true,
        )
        .is_err()
    );
    // An explicit --cache-url is always honored, even for write-only uploads.
    assert_eq!(
        resolve_effective_release_cache_url(
            Some("https://cdn.example/cache"),
            &["s3://bucket/prefix".to_string()],
            true,
        )
        .unwrap()
        .as_deref(),
        Some("https://cdn.example/cache"),
    );
}

#[test]
fn registry_upload_auth_config_selects_requested_registry() {
    let config_auth = RegistryUploadAuthConfig {
        token: Some("core-token".into()),
        view: Some("prod".into()),
        ..RegistryUploadAuthConfig::default()
    };
    let config = ApmConfig {
        settings: ApmSettings::default(),
        registries: vec![
            (test_registry_config("other", None), None),
            (
                test_registry_config("core", Some(config_auth.clone())),
                None,
            ),
        ],
        scope: ProfileScope::User,
    };

    let selected = registry_upload_auth_config(&config, "core").expect("core auth config");
    assert_eq!(selected, &config_auth);
    assert!(registry_upload_auth_config(&config, "missing").is_none());
}

#[test]
fn format_size_values() {
    assert_eq!(format_size(500), "500 B");
    assert_eq!(format_size(2048), "2.0 KiB");
    assert_eq!(format_size(3_300_000), "3.1 MiB");
    assert_eq!(format_size(2_147_483_648), "2.0 GiB");
}
