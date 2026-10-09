//! Tests for signed rollout channel partitions and fix-forward channel advancement.

use super::{
    ensure_channel_advance_fix_forward, parse_partition_list, select_partitions_for_advance,
};
use aos_registry_client::registry::channel::PartitionMap;
use crate::registry_ops::git::git;
use crate::registry_ops::tags::sign_tag;
use crate::registry_ops::test_support::write_seeded_signing_key;
use std::fs;
use tempfile::TempDir;

#[test]
fn partition_list_accepts_decimal_and_hex() {
    assert_eq!(
        parse_partition_list("0,1,0a,0xff,1").unwrap(),
        vec![0, 1, 10, 255],
    );
    assert!(parse_partition_list("").is_err());
    assert!(parse_partition_list("256").is_err());
}

#[test]
fn channel_advance_selector_requires_one_mode() {
    let map = PartitionMap::all(semver::Version::parse("1.0.0").unwrap());
    let target = semver::Version::parse("1.1.0").unwrap();

    assert!(select_partitions_for_advance(None, None, &map, &target).is_err());
    assert!(select_partitions_for_advance(Some(1), Some("0"), &map, &target).is_err());
    assert_eq!(
        select_partitions_for_advance(Some(3), None, &map, &target).unwrap(),
        vec![0, 1, 2],
    );
}

#[test]
fn channel_advance_rejects_selected_partition_decrement() {
    let mut map = PartitionMap::all(semver::Version::parse("1.1.0").unwrap());
    map.set(2, semver::Version::parse("1.0.0").unwrap())
        .unwrap();
    let older = semver::Version::parse("1.0.0").unwrap();
    let same = semver::Version::parse("1.1.0").unwrap();
    let newer = semver::Version::parse("1.2.0").unwrap();

    let err = ensure_channel_advance_fix_forward(&map, &[0], &older).unwrap_err();
    assert!(format!("{err:#}").contains("decrement partition 00 from 1.1.0 to 1.0.0"));
    ensure_channel_advance_fix_forward(&map, &[0], &same).unwrap();
    ensure_channel_advance_fix_forward(&map, &[0, 2], &newer).unwrap();
}

#[test]
fn partition_signing_preserves_existing_tag_named_after_channel() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    git(
        tmp.path(),
        &[
            "init",
            "--object-format=sha256",
            "--initial-branch=main",
            repo.to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
    git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
    git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
    fs::write(
        repo.join("registry.toml"),
        "[registry]\nname = \"aos-core\"\n",
    )
    .unwrap();
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();
    let key = write_seeded_signing_key(tmp.path(), "aos-core", [18u8; 32], "maintainer");
    let key_path = key.private_key.to_str().unwrap();
    sign_tag(&repo, "1.0.0", "HEAD", None, key_path, false).unwrap();
    sign_tag(
        &repo,
        "stable",
        "HEAD",
        Some("maintenance tag"),
        key_path,
        false,
    )
    .unwrap();
    let maintenance_before = git(&repo, &["rev-parse", "refs/tags/stable"]).unwrap();
    let release_before = git(&repo, &["rev-parse", "refs/tags/1.0.0"]).unwrap();

    super::write_channel_partition_tag(
        &repo,
        "stable",
        10,
        &semver::Version::new(1, 0, 0),
        key_path,
    )
    .unwrap();

    assert_eq!(
        git(&repo, &["rev-parse", "refs/tags/stable"]).unwrap(),
        maintenance_before
    );
    let payload = fs::read(repo.join(".git/channels/stable/0a")).unwrap();
    let verified =
        aos_registry_format::tag::verify_signed_tag(&payload, "stable", &[key.trusted_key])
            .unwrap();
    assert_eq!(verified.tag.object, release_before);
    assert_eq!(
        super::read_channel_partition_map(&repo, "stable")
            .unwrap()
            .get(10),
        Some(&semver::Version::new(1, 0, 0))
    );
}
