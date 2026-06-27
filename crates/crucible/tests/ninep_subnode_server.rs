//! Checks T-IO-6 deterministic read-only 9P2000.L served-tree behavior.

#![forbid(unsafe_code)]

use crucible::{
    NINEP_BLOCK_COUNT_UNIT, NINEP_DEFAULT_MAXIMUM_MSIZE, NINEP_FIXED_BLOCK_SIZE,
    NINEP_FIXED_EPOCH_SECONDS, NINEP_FIXED_GID, NINEP_FIXED_QID_VERSION, NINEP_FIXED_UID,
    NINEP_HEADER_SIZE, NINEP_PROTOCOL_VERSION, NinePServedEntry, NinePServedTree, NinePServerError,
};

#[test]
fn qids_are_path_hashed_with_fixed_version_and_kind_not_host_inode_inputs() {
    let tree = sample_tree();
    let file_qid = tree.qid("/zeta.txt").expect("file qid should exist");
    let same_path_different_content = NinePServedTree::new(vec![NinePServedEntry::file(
        "/zeta.txt",
        b"different bytes",
    )])
    .expect("tree should build")
    .qid("/zeta.txt")
    .expect("file qid should exist");
    let other_path = tree.qid("/alpha.txt").expect("other qid should exist");
    let directory = tree.qid("/dir").expect("directory qid should exist");

    assert_eq!(file_qid.version, NINEP_FIXED_QID_VERSION);
    assert_eq!(same_path_different_content.version, NINEP_FIXED_QID_VERSION);
    assert_eq!(file_qid.path, same_path_different_content.path);
    assert_ne!(file_qid.path, other_path.path);
    assert_eq!(file_qid.qtype, 0x00);
    assert_eq!(directory.qtype, 0x80);
}

#[test]
fn readdir_is_lexicographic_and_offsets_are_assigned_after_sort() {
    let tree = sample_tree();

    let root_entries = tree.readdir("/").expect("root should enumerate");

    assert_eq!(
        root_entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry.offset))
            .collect::<Vec<_>>(),
        vec![("alpha.txt", 1), ("dir", 2), ("link", 3), ("zeta.txt", 4)]
    );
    assert_eq!(
        tree.readdir("/dir")
            .expect("directory should enumerate")
            .iter()
            .map(|entry| (entry.name.as_str(), entry.offset))
            .collect::<Vec<_>>(),
        vec![("a.txt", 1), ("b.txt", 2)]
    );
    assert_eq!(root_entries, tree.readdir("/").expect("repeat readdir"));
}

#[test]
fn getattr_and_statfs_are_fixed_or_content_derived() {
    let tree = sample_tree();

    let file = tree.getattr("/zeta.txt").expect("file attrs should exist");
    assert_eq!(file.uid, NINEP_FIXED_UID);
    assert_eq!(file.gid, NINEP_FIXED_GID);
    assert_eq!(file.atime_sec, NINEP_FIXED_EPOCH_SECONDS);
    assert_eq!(file.mtime_sec, NINEP_FIXED_EPOCH_SECONDS);
    assert_eq!(file.ctime_sec, NINEP_FIXED_EPOCH_SECONDS);
    assert_eq!(file.size, 4);
    assert_eq!(file.block_size, NINEP_FIXED_BLOCK_SIZE);
    assert_eq!(file.blocks, 1);
    assert_eq!(file.mode, 0o100444);

    let dir = tree.getattr("/dir").expect("dir attrs should exist");
    assert_eq!(dir.size, 0);
    assert_eq!(dir.blocks, 0);
    assert_eq!(dir.mode, 0o040555);

    let link = tree.getattr("/link").expect("link attrs should exist");
    assert_eq!(link.size, "/alpha.txt".len() as u64);
    assert_eq!(link.mode, 0o120555);

    let statfs = tree.statfs().expect("statfs should compute");
    assert_eq!(statfs.block_size, NINEP_FIXED_BLOCK_SIZE);
    assert_eq!(statfs.blocks, 1);
    assert_eq!(statfs.files, 7);
    assert_eq!(statfs.name_max, 255);
    assert_eq!(statfs, tree.statfs().expect("repeat statfs"));
}

#[test]
fn custom_permissions_never_advertise_write_bits() {
    let tree = NinePServedTree::new(vec![
        NinePServedEntry::file("/file", b"x").with_permissions(0o666),
        NinePServedEntry::directory("/dir").with_permissions(0o777),
    ])
    .expect("tree should build");

    assert_eq!(
        tree.getattr("/file").expect("file attrs should exist").mode,
        0o100444
    );
    assert_eq!(
        tree.getattr("/dir").expect("dir attrs should exist").mode,
        0o040555
    );
}

#[test]
fn getattr_blocks_use_fixed_512_byte_units_not_preferred_block_size() {
    let tree = NinePServedTree::new(vec![NinePServedEntry::file(
        "/large",
        vec![0u8; (NINEP_FIXED_BLOCK_SIZE + 1) as usize],
    )])
    .expect("tree should build");
    let attrs = tree.getattr("/large").expect("large attrs should exist");

    assert_eq!(NINEP_BLOCK_COUNT_UNIT, 512);
    assert_eq!(attrs.block_size, NINEP_FIXED_BLOCK_SIZE);
    assert_eq!(attrs.blocks, 9);
}

#[test]
fn version_negotiation_uses_fixed_protocol_and_deterministic_msize() {
    let tree = sample_tree();

    assert_eq!(
        tree.negotiate_version(NINEP_PROTOCOL_VERSION, NINEP_DEFAULT_MAXIMUM_MSIZE + 1)
            .expect("large client msize should clamp")
            .msize,
        NINEP_DEFAULT_MAXIMUM_MSIZE
    );
    assert_eq!(
        tree.negotiate_version(NINEP_PROTOCOL_VERSION, 8192)
            .expect("small client msize should win"),
        crucible::NinePVersionNegotiation {
            version: NINEP_PROTOCOL_VERSION.to_owned(),
            msize: 8192,
        }
    );
    assert!(matches!(
        tree.negotiate_version("9P2000.u", 8192),
        Err(NinePServerError::UnsupportedVersion { requested }) if requested == "9P2000.u"
    ));
    assert!(matches!(
        tree.negotiate_version(NINEP_PROTOCOL_VERSION, 0),
        Err(NinePServerError::InvalidMsize { requested: 0 })
    ));
    assert!(matches!(
        tree.negotiate_version(NINEP_PROTOCOL_VERSION, NINEP_HEADER_SIZE - 1),
        Err(NinePServerError::InvalidMsize { requested }) if requested == NINEP_HEADER_SIZE - 1
    ));
}

#[test]
fn served_tree_hash_and_readdir_are_independent_of_authoring_order() {
    let first = NinePServedTree::new(vec![
        NinePServedEntry::file("/b", b"b"),
        NinePServedEntry::directory("/d"),
        NinePServedEntry::file("/d/c", b"c"),
        NinePServedEntry::file("/a", b"a"),
    ])
    .expect("first tree should build");
    let second = NinePServedTree::new(vec![
        NinePServedEntry::file("/a", b"a"),
        NinePServedEntry::file("/d/c", b"c"),
        NinePServedEntry::directory("/d"),
        NinePServedEntry::file("/b", b"b"),
    ])
    .expect("second tree should build");

    assert_eq!(first.content_hash(), second.content_hash());
    assert_eq!(
        first.readdir("/").expect("first root readdir"),
        second.readdir("/").expect("second root readdir")
    );
    assert_eq!(first.qid("/d/c"), second.qid("/d/c"));
}

#[test]
fn statfs_fsid_and_tree_content_hash_ignore_negotiation_msize() {
    let entries = vec![NinePServedEntry::file("/file", b"content")];
    let small_msize = NinePServedTree::with_maximum_msize(entries.clone(), 8192)
        .expect("small msize tree should build");
    let large_msize = NinePServedTree::with_maximum_msize(entries, 65_536)
        .expect("large msize tree should build");

    assert_ne!(small_msize.maximum_msize(), large_msize.maximum_msize());
    assert_eq!(small_msize.content_hash(), large_msize.content_hash());
    assert_eq!(
        small_msize.statfs().expect("small statfs").fsid,
        large_msize.statfs().expect("large statfs").fsid
    );
    assert_eq!(
        small_msize
            .negotiate_version(NINEP_PROTOCOL_VERSION, 65_536)
            .expect("small negotiation")
            .msize,
        8192
    );
}

#[test]
fn validation_rejects_nondeterministic_or_non_tree_paths() {
    assert!(matches!(
        NinePServedTree::new(vec![NinePServedEntry::file("relative", b"x")]),
        Err(NinePServerError::InvalidPath { .. })
    ));
    assert!(matches!(
        NinePServedTree::new(vec![NinePServedEntry::file("/../escape", b"x")]),
        Err(NinePServerError::InvalidPath { .. })
    ));
    assert!(matches!(
        NinePServedTree::new(vec![NinePServedEntry::file("/missing/child", b"x")]),
        Err(NinePServerError::MissingParent { .. })
    ));
    assert!(matches!(
        NinePServedTree::new(vec![
            NinePServedEntry::file("/parent", b"x"),
            NinePServedEntry::file("/parent/child", b"x"),
        ]),
        Err(NinePServerError::ParentNotDirectory { .. })
    ));
    assert!(matches!(
        NinePServedTree::new(vec![
            NinePServedEntry::file("/dup", b"a"),
            NinePServedEntry::file("/dup", b"b"),
        ]),
        Err(NinePServerError::DuplicatePath { path }) if path == "/dup"
    ));
    assert!(matches!(
        NinePServedTree::new(vec![NinePServedEntry::file("/", b"not-root")]),
        Err(NinePServerError::RootMustBeDirectory)
    ));
}

#[test]
fn lookup_and_readdir_errors_are_typed() {
    let tree = sample_tree();

    assert!(matches!(
        tree.qid("/missing"),
        Err(NinePServerError::NotFound { path }) if path == "/missing"
    ));
    assert!(matches!(
        tree.readdir("/zeta.txt"),
        Err(NinePServerError::NotDirectory { path }) if path == "/zeta.txt"
    ));
    assert!(matches!(
        tree.readdir("/bad//path"),
        Err(NinePServerError::InvalidPath { .. })
    ));
}

fn sample_tree() -> NinePServedTree {
    NinePServedTree::new(vec![
        NinePServedEntry::file("/zeta.txt", b"zeta"),
        NinePServedEntry::symlink("/link", "/alpha.txt"),
        NinePServedEntry::directory("/dir"),
        NinePServedEntry::file("/dir/b.txt", b"b"),
        NinePServedEntry::file("/alpha.txt", b"alpha"),
        NinePServedEntry::file("/dir/a.txt", b"a"),
    ])
    .expect("sample tree should build")
}
