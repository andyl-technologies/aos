//! OCI layout, archive, Docker compatibility, and corruption fixtures.

#![allow(clippy::expect_used)]

mod support;

use std::fs;

use aos_oci::{
    PlatformSelector, prepare_layout, read_verified_index, verify_layout, write_docker_archive,
    write_oci_archive, write_oci_layout,
};

#[test]
fn verifies_layout_and_round_trips_deterministic_archives() {
    let fixture = support::fixture();
    let platform = PlatformSelector::parse("linux/amd64").expect("platform");
    let verified = verify_layout(fixture.root(), Some(&platform)).expect("verified layout");
    assert_eq!(verified.layers.len(), 1);

    let outputs = tempfile::tempdir().expect("outputs");
    let first = outputs.path().join("first.oci.tar");
    let second = outputs.path().join("second.oci.tar");
    write_oci_archive(fixture.root(), &first).expect("first OCI archive");
    write_oci_archive(fixture.root(), &second).expect("second OCI archive");
    assert_eq!(
        fs::read(&first).expect("first bytes"),
        fs::read(&second).expect("second bytes")
    );

    let extracted = prepare_layout(&first).expect("safe archive extraction");
    verify_layout(extracted.root(), Some(&platform)).expect("round-trip layout");

    let docker = outputs.path().join("image.docker.tar");
    write_docker_archive(
        fixture.root(),
        &docker,
        Some(&platform),
        &["example/aos:latest".to_string()],
    )
    .expect("Docker archive");
    assert!(
        write_docker_archive(
            fixture.root(),
            &outputs.path().join("invalid-tag.docker.tar"),
            Some(&platform),
            &["registry.example/aos@sha256:deadbeef".to_string()],
        )
        .is_err()
    );
    let file = fs::File::open(&docker).expect("Docker archive file");
    let paths = tar::Archive::new(file)
        .entries()
        .expect("Docker entries")
        .map(|entry| {
            entry
                .expect("Docker entry")
                .path()
                .expect("Docker path")
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert!(
        paths
            .iter()
            .any(|path| path == std::path::Path::new("manifest.json"))
    );
    assert!(
        paths
            .iter()
            .any(|path| path.to_string_lossy().ends_with("/layer.tar"))
    );
}

#[cfg(unix)]
#[test]
fn accepts_a_nix_style_top_level_result_symlink() {
    let fixture = support::fixture();
    let parent = tempfile::tempdir().expect("result-link parent");
    let result = parent.path().join("result");
    std::os::unix::fs::symlink(fixture.root(), &result).expect("result symlink");

    let prepared = prepare_layout(&result).expect("symlinked layout");
    verify_layout(
        prepared.root(),
        Some(&PlatformSelector::parse("linux/amd64").expect("platform")),
    )
    .expect("verified symlinked layout");
}

#[test]
fn corruption_fails_before_an_image_is_reported() {
    let fixture = support::fixture();
    let layer = fixture
        .root()
        .join("blobs/sha256")
        .join(fixture.layer_descriptor.digest.encoded());
    let mut bytes = fs::read(&layer).expect("layer bytes");
    bytes[0] ^= 0xff;
    fs::write(&layer, bytes).expect("corrupt layer");

    let error = verify_layout(
        fixture.root(),
        Some(&PlatformSelector::parse("linux/amd64").expect("platform")),
    )
    .expect_err("corruption must fail");
    assert!(format!("{error:#}").contains("descriptor digest mismatch"));
}

#[test]
fn exact_index_reads_remain_bound_to_the_verified_bytes() {
    let fixture = support::fixture();
    let verified = verify_layout(fixture.root(), None).expect("verified fixture");
    let bytes =
        read_verified_index(fixture.root(), &verified.index_digest).expect("verified exact index");
    assert_eq!(bytes, fixture.index);

    fs::write(fixture.root().join("index.json"), b"{}").expect("replace index");
    assert!(read_verified_index(fixture.root(), &verified.index_digest).is_err());
}

#[test]
fn archive_ingestion_rejects_links_and_duplicate_members() {
    let outputs = tempfile::tempdir().expect("malicious archive outputs");

    let link_archive = outputs.path().join("link.tar");
    {
        let file = fs::File::create(&link_archive).expect("link archive");
        let mut builder = tar::Builder::new(file);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_size(0);
        header.set_mtime(1);
        header.set_link_name("../../outside").expect("link target");
        header.set_cksum();
        builder
            .append_data(&mut header, "link", std::io::empty())
            .expect("link member");
        builder.finish().expect("finish link archive");
    }
    assert!(prepare_layout(&link_archive).is_err());

    let duplicate_archive = outputs.path().join("duplicate.tar");
    {
        let file = fs::File::create(&duplicate_archive).expect("duplicate archive");
        let mut builder = tar::Builder::new(file);
        for contents in [b"one".as_slice(), b"two".as_slice()] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(contents.len() as u64);
            header.set_mtime(1);
            header.set_cksum();
            builder
                .append_data(&mut header, "same", contents)
                .expect("duplicate member");
        }
        builder.finish().expect("finish duplicate archive");
    }
    assert!(prepare_layout(&duplicate_archive).is_err());
}

#[cfg(unix)]
#[test]
fn verification_rejects_descendant_symlinks_and_hardlinked_blobs() {
    let symlink_fixture = support::fixture();
    let blobs = symlink_fixture.root().join("blobs");
    let moved = symlink_fixture.root().join("real-blobs");
    fs::rename(&blobs, &moved).expect("move blob directory");
    std::os::unix::fs::symlink(&moved, &blobs).expect("descendant symlink");
    assert!(verify_layout(symlink_fixture.root(), None).is_err());

    let hardlink_fixture = support::fixture();
    let layer = hardlink_fixture
        .root()
        .join("blobs/sha256")
        .join(hardlink_fixture.layer_descriptor.digest.encoded());
    fs::hard_link(&layer, hardlink_fixture.root().join("external-layer"))
        .expect("hardlink fixture");
    assert!(verify_layout(hardlink_fixture.root(), None).is_err());
}

#[test]
fn exports_include_only_the_verified_reachable_graph() {
    let fixture = support::fixture();
    let stale_digest = aos_oci_types::Sha256Digest::digest(b"private stale blob");
    let stale_name = stale_digest.encoded();
    fs::write(
        fixture.root().join("blobs/sha256").join(&stale_name),
        b"private stale blob",
    )
    .expect("stale blob");

    let outputs = tempfile::tempdir().expect("outputs");
    let archive = outputs.path().join("image.oci.tar");
    write_oci_archive(fixture.root(), &archive).expect("clean archive");
    let archive_paths = tar::Archive::new(fs::File::open(&archive).expect("archive"))
        .entries()
        .expect("archive entries")
        .map(|entry| {
            entry
                .expect("archive entry")
                .path()
                .expect("archive path")
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert!(!archive_paths.iter().any(|path| path.ends_with(&stale_name)));

    let clean = outputs.path().join("clean");
    fs::create_dir(&clean).expect("clean destination");
    write_oci_layout(fixture.root(), &clean).expect("clean layout");
    assert!(!clean.join("blobs/sha256").join(stale_name).exists());
}
