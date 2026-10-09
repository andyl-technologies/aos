//! Recorded response checks for shared upstream normalization and boundaries.

use std::collections::BTreeSet;

use anyhow::Result;
use aos_assessment_providers::upstream;

#[test]
fn release_prefixes_publication_times_and_flags_are_preserved() -> Result<()> {
    let bytes = br#"[
        {"tag_name":"v1.2.0","published_at":"2026-08-29T12:34:56Z","prerelease":false},
        {"tag_name":"v1.3.0-rc1","prerelease":true,"draft":true},
        {"tag_name":"other-9.0.0"}
    ]"#;

    let candidates = upstream::github_releases(bytes, "v", 1_788_006_900)?;

    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].raw_version, "1.2.0");
    assert_eq!(candidates[0].published_at_unix, Some(1_788_006_896));
    assert_eq!(candidates[0].first_observed_at_unix, 1_788_006_900);
    assert!(candidates[1].prerelease);
    assert!(candidates[1].yanked);
    Ok(())
}

#[test]
fn ambiguous_and_oversized_provider_documents_are_rejected() {
    assert!(upstream::github_releases(br#"[{"tag_name":"v1","tag_name":"v2"}]"#, "v", 1).is_err());
    assert!(upstream::github_releases(br#"[{"published_at":"invalid"}]"#, "v", 1).is_err());
    assert!(upstream::go_releases(&vec![b' '; 8 * 1024 * 1024 + 1], 1).is_err());
}

#[test]
fn go_feed_requires_a_stable_version_with_matching_source() -> Result<()> {
    let bytes = br#"[
        {"version":"go1.24.1","stable":true,"files":[{"kind":"source","filename":"go1.24.1.src.tar.gz"}]},
        {"version":"go1.25rc1","stable":false,"files":[{"kind":"source","filename":"go1.25rc1.src.tar.gz"}]},
        {"version":"go1.24.2","stable":true,"files":[{"kind":"source","filename":"different.tar.gz"}]}
    ]"#;

    let candidates = upstream::go_releases(bytes, 100)?;

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].raw_id, "go1.24.1");
    assert_eq!(candidates[0].raw_version, "1.24.1");
    Ok(())
}

#[test]
fn repology_history_survives_response_reordering_and_preserves_signals() -> Result<()> {
    let bytes = br#"[
        {"repo":"a","version":"1.0","origversion":"1.0-r1","status":"outdated","vulnerable":true,"licenses":["MIT","MIT"]},
        {"repo":"b","version":"2.0","status":"newest"},
        {"repo":"c","version":"0.9","status":"legacy"}
    ]"#;
    let reordered = br#"[
        {"repo":"b","version":"2.0","status":"newest"},
        {"repo":"a","version":"1.0","origversion":"1.0-r1","status":"outdated","vulnerable":true,"licenses":["MIT"]}
    ]"#;
    let versions = BTreeSet::from(["1.0".to_string()]);

    let candidates = upstream::repology(bytes, "example", &versions)?;
    let later = upstream::repology(reordered, "example", &versions)?;

    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].first_key, later[1].first_key);
    assert_ne!(candidates[0].raw_id, later[1].raw_id);
    assert_eq!(candidates[0].vulnerable, Some(true));
    assert_eq!(candidates[0].licenses, vec!["MIT"]);
    Ok(())
}

#[test]
fn git_tags_use_exact_prefix_and_encode_release_path_segments() -> Result<()> {
    let bytes = br#"[{"name":"release/1.0"},{"name":"unrelated-2.0"}]"#;

    let candidates = upstream::github_tags(bytes, "owner/project", "release/", 1)?;

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].raw_version, "1.0");
    assert_eq!(
        candidates[0].release_url.as_deref(),
        Some("https://github.com/owner/project/releases/tag/release%2F1.0")
    );
    Ok(())
}
