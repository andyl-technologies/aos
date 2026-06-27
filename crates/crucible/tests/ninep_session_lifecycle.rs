//! Checks T-IO-7 deterministic 9p session request handling and fid restore.

#![forbid(unsafe_code)]

use crucible::{
    NINEP_EINVAL, NINEP_EIO, NINEP_ENOSYS, NINEP_EROFS, NINEP_HEADER_SIZE, NINEP_PROTOCOL_VERSION,
    NinePFidSnapshot, NinePMutatingMessage, NinePRequest, NinePRequestKind, NinePResponseKind,
    NinePServedEntry, NinePServedTree, NinePServerError, NinePSession, NinePSessionSnapshot,
};

#[test]
fn session_handles_read_traverse_metadata_and_clunk_requests() {
    let mut session = NinePSession::new(sample_tree());

    assert!(matches!(
        session.handle_request(NinePRequest::new(
            1,
            NinePRequestKind::Version {
                msize: 8192,
                version: NINEP_PROTOCOL_VERSION.to_owned(),
            },
        )),
        crucible::NinePResponse {
            tag: 1,
            kind: NinePResponseKind::Version(version),
        } if version.msize == 8192
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(2, NinePRequestKind::Attach { fid: 1 })),
        crucible::NinePResponse {
            tag: 2,
            kind: NinePResponseKind::Attach { .. },
        }
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(
            3,
            NinePRequestKind::Walk {
                fid: 1,
                newfid: 2,
                names: vec![String::from("alpha.txt")],
            },
        )),
        crucible::NinePResponse {
            tag: 3,
            kind: NinePResponseKind::Walk { qids },
        } if qids.len() == 1
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(4, NinePRequestKind::Lopen { fid: 2 })),
        crucible::NinePResponse {
            tag: 4,
            kind: NinePResponseKind::Lopen { .. },
        }
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(
            5,
            NinePRequestKind::Read {
                fid: 2,
                offset: 1,
                count: 3,
            },
        )),
        crucible::NinePResponse {
            tag: 5,
            kind: NinePResponseKind::Read { data },
        } if data == b"lph".to_vec()
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(6, NinePRequestKind::GetAttr { fid: 2 })),
        crucible::NinePResponse {
            tag: 6,
            kind: NinePResponseKind::GetAttr(attrs),
        } if attrs.size == 5
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(7, NinePRequestKind::StatFs { fid: 2 })),
        crucible::NinePResponse {
            tag: 7,
            kind: NinePResponseKind::StatFs(statfs),
        } if statfs.files == 6
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(
            8,
            NinePRequestKind::Walk {
                fid: 1,
                newfid: 3,
                names: vec![String::from("link")],
            },
        )),
        crucible::NinePResponse {
            tag: 8,
            kind: NinePResponseKind::Walk { qids },
        } if qids.len() == 1
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(9, NinePRequestKind::ReadLink { fid: 3 })),
        crucible::NinePResponse {
            tag: 9,
            kind: NinePResponseKind::ReadLink { target },
        } if target == "/alpha.txt"
    ));
    assert_eq!(
        session.handle_request(NinePRequest::new(10, NinePRequestKind::Flush)),
        crucible::NinePResponse {
            tag: 10,
            kind: NinePResponseKind::Flush,
        }
    );
    assert_eq!(
        session.handle_request(NinePRequest::new(11, NinePRequestKind::Clunk { fid: 2 })),
        crucible::NinePResponse {
            tag: 11,
            kind: NinePResponseKind::Clunk,
        }
    );
}

#[test]
fn readdir_uses_cached_sorted_directory_and_snapshot_restore_rebuilds_it() {
    let mut session = NinePSession::new(sample_tree());
    attach_root(&mut session, 1);
    walk(&mut session, 1, 2, &["dir"]);
    open(&mut session, 2);

    let first_page = session.handle_request(NinePRequest::new(
        4,
        NinePRequestKind::Readdir {
            fid: 2,
            offset: 0,
            count: 29,
        },
    ));
    assert!(matches!(
        first_page,
        crucible::NinePResponse {
            tag: 4,
            kind: NinePResponseKind::Readdir { entries },
        } if entries.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>() == vec!["a.txt"]
    ));

    let snapshot = session.snapshot();
    let mut restored = NinePSession::new(sample_tree());
    restored
        .restore_snapshot(snapshot)
        .expect("snapshot should restore");

    assert_eq!(restored.negotiated_msize(), session.negotiated_msize());
    let restored_page = restored.handle_request(NinePRequest::new(
        5,
        NinePRequestKind::Readdir {
            fid: 2,
            offset: 1,
            count: 1024,
        },
    ));
    assert!(matches!(
        restored_page,
        crucible::NinePResponse {
            tag: 5,
            kind: NinePResponseKind::Readdir { entries },
        } if entries.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>() == vec!["b.txt"]
    ));
}

#[test]
fn readdir_count_is_an_encoded_payload_byte_budget() {
    let mut session = NinePSession::new(sample_tree());
    attach_root(&mut session, 1);
    walk(&mut session, 1, 2, &["dir"]);
    open(&mut session, 2);

    assert!(matches!(
        session.handle_request(NinePRequest::new(
            4,
            NinePRequestKind::Readdir {
                fid: 2,
                offset: 0,
                count: 1,
            },
        )),
        crucible::NinePResponse {
            tag: 4,
            kind: NinePResponseKind::Readdir { entries },
        } if entries.is_empty()
    ));
}

#[test]
fn mutating_unknown_and_malformed_requests_fail_with_typed_errno() {
    let mut session = NinePSession::new(sample_tree());

    assert_errno(
        session.handle_request(NinePRequest::new(
            1,
            NinePRequestKind::Mutating(NinePMutatingMessage::Write),
        )),
        1,
        NINEP_EROFS,
    );
    assert_errno(
        session.handle_request(NinePRequest::new(
            2,
            NinePRequestKind::Unknown { message_type: 255 },
        )),
        2,
        NINEP_ENOSYS,
    );
    assert_errno(
        session.handle_request(NinePRequest::new(
            3,
            NinePRequestKind::Malformed { io_error: false },
        )),
        3,
        NINEP_EINVAL,
    );
    assert_errno(
        session.handle_request(NinePRequest::new(
            4,
            NinePRequestKind::Malformed { io_error: true },
        )),
        4,
        NINEP_EIO,
    );
}

#[test]
fn msize_enforcement_happens_before_request_state_mutation() {
    let mut session = NinePSession::new(sample_tree());
    assert!(matches!(
        session.handle_request(NinePRequest::new(
            1,
            NinePRequestKind::Version {
                msize: 23,
                version: NINEP_PROTOCOL_VERSION.to_owned(),
            },
        )),
        crucible::NinePResponse {
            tag: 1,
            kind: NinePResponseKind::Version(version),
        } if version.msize == 23
    ));

    assert_errno(
        session.handle_request(
            NinePRequest::new(2, NinePRequestKind::Attach { fid: 1 }).with_encoded_size(24),
        ),
        2,
        NINEP_EINVAL,
    );
    assert_errno(
        session.handle_request(NinePRequest::new(3, NinePRequestKind::GetAttr { fid: 1 })),
        3,
        NINEP_EINVAL,
    );
    assert!(matches!(
        session.handle_request(
            NinePRequest::new(4, NinePRequestKind::Attach { fid: 1 }).with_encoded_size(23)
        ),
        crucible::NinePResponse {
            tag: 4,
            kind: NinePResponseKind::Attach { .. },
        }
    ));
    assert_errno(
        session.handle_request(NinePRequest::new(
            5,
            NinePRequestKind::Walk {
                fid: 1,
                newfid: 2,
                names: vec![String::from("alpha.txt")],
            },
        )),
        5,
        NINEP_EINVAL,
    );
    assert_errno(
        session.handle_request(NinePRequest::new(6, NinePRequestKind::GetAttr { fid: 2 })),
        6,
        NINEP_EINVAL,
    );
}

#[test]
fn read_payload_is_limited_by_negotiated_msize() {
    let mut session = NinePSession::new(long_file_tree());
    assert!(matches!(
        session.handle_request(NinePRequest::new(
            1,
            NinePRequestKind::Version {
                msize: 23,
                version: NINEP_PROTOCOL_VERSION.to_owned(),
            },
        )),
        crucible::NinePResponse {
            tag: 1,
            kind: NinePResponseKind::Version(version),
        } if version.msize == 23
    ));
    attach_root(&mut session, 1);
    walk(&mut session, 1, 2, &["a"]);
    open(&mut session, 2);

    assert!(matches!(
        session.handle_request(NinePRequest::new(
            2,
            NinePRequestKind::Read {
                fid: 2,
                offset: 0,
                count: 26,
            },
        )),
        crucible::NinePResponse {
            tag: 2,
            kind: NinePResponseKind::Read { data },
        } if data == b"abcdefghijkl".to_vec()
    ));
}

#[test]
fn walk_supports_same_fid_and_rejects_opened_source_fids() {
    let mut session = NinePSession::new(sample_tree());
    attach_root(&mut session, 1);

    assert!(matches!(
        session.handle_request(NinePRequest::new(
            2,
            NinePRequestKind::Walk {
                fid: 1,
                newfid: 1,
                names: vec![String::from("dir")],
            },
        )),
        crucible::NinePResponse {
            tag: 2,
            kind: NinePResponseKind::Walk { qids },
        } if qids.len() == 1
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(3, NinePRequestKind::GetAttr { fid: 1 })),
        crucible::NinePResponse {
            tag: 3,
            kind: NinePResponseKind::GetAttr(attrs),
        } if attrs.mode == 0o040555
    ));
    assert!(matches!(
        session.handle_request(NinePRequest::new(
            4,
            NinePRequestKind::Walk {
                fid: 1,
                newfid: 2,
                names: Vec::new(),
            },
        )),
        crucible::NinePResponse {
            tag: 4,
            kind: NinePResponseKind::Walk { qids },
        } if qids.is_empty()
    ));
    open(&mut session, 2);
    assert_errno(
        session.handle_request(NinePRequest::new(
            5,
            NinePRequestKind::Walk {
                fid: 2,
                newfid: 3,
                names: Vec::new(),
            },
        )),
        5,
        NINEP_EINVAL,
    );
    assert_errno(
        session.handle_request(NinePRequest::new(6, NinePRequestKind::GetAttr { fid: 3 })),
        6,
        NINEP_EINVAL,
    );
}

#[test]
fn version_negotiation_resets_fid_state() {
    let mut session = NinePSession::new(sample_tree());
    attach_root(&mut session, 1);

    assert!(matches!(
        session.handle_request(NinePRequest::new(
            2,
            NinePRequestKind::Version {
                msize: 512,
                version: NINEP_PROTOCOL_VERSION.to_owned(),
            },
        )),
        crucible::NinePResponse {
            tag: 2,
            kind: NinePResponseKind::Version(version),
        } if version.msize == 512
    ));
    assert_errno(
        session.handle_request(NinePRequest::new(3, NinePRequestKind::GetAttr { fid: 1 })),
        3,
        NINEP_EINVAL,
    );
    assert!(session.snapshot().fids.is_empty());
}

#[test]
fn xattrwalk_creates_deterministic_empty_xattr_fid() {
    let mut session = NinePSession::new(sample_tree());
    attach_root(&mut session, 1);

    assert_eq!(
        session.handle_request(NinePRequest::new(
            2,
            NinePRequestKind::XattrWalk {
                fid: 1,
                newfid: 7,
                name: String::from("user.none"),
            },
        )),
        crucible::NinePResponse {
            tag: 2,
            kind: NinePResponseKind::XattrWalk { size: 0 },
        }
    );
    assert!(matches!(
        session.handle_request(NinePRequest::new(3, NinePRequestKind::GetAttr { fid: 7 })),
        crucible::NinePResponse {
            tag: 3,
            kind: NinePResponseKind::GetAttr(attrs),
        } if attrs.mode == 0o100444 && attrs.size == 0
    ));
    open(&mut session, 7);
    assert!(matches!(
        session.handle_request(NinePRequest::new(
            4,
            NinePRequestKind::Read {
                fid: 7,
                offset: 0,
                count: 64,
            },
        )),
        crucible::NinePResponse {
            tag: 4,
            kind: NinePResponseKind::Read { data },
        } if data.is_empty()
    ));

    let snapshot = session.snapshot();
    assert!(
        snapshot
            .fids
            .iter()
            .any(|fid| fid.fid == 7 && fid.xattr_name.as_deref() == Some("user.none"))
    );
    let mut restored = NinePSession::new(sample_tree());
    restored
        .restore_snapshot(snapshot)
        .expect("xattr snapshot should restore");
    assert!(matches!(
        restored.handle_request(NinePRequest::new(5, NinePRequestKind::GetAttr { fid: 7 })),
        crucible::NinePResponse {
            tag: 5,
            kind: NinePResponseKind::GetAttr(attrs),
        } if attrs.mode == 0o100444 && attrs.size == 0
    ));
}

#[test]
fn snapshot_restore_rejects_forged_fids_msize_and_open_kinds() {
    let mut session = NinePSession::new(sample_tree());
    attach_root(&mut session, 1);
    walk(&mut session, 1, 2, &["alpha.txt"]);
    let snapshot = session.snapshot();

    let mut duplicate = snapshot.clone();
    duplicate.fids.push(duplicate.fids[0].clone());
    assert!(matches!(
        NinePSession::new(sample_tree()).restore_snapshot(duplicate),
        Err(NinePServerError::DuplicateFid { .. })
    ));

    let mut invalid_msize = snapshot.clone();
    invalid_msize.negotiated_msize = 0;
    assert!(matches!(
        NinePSession::new(sample_tree()).restore_snapshot(invalid_msize),
        Err(NinePServerError::InvalidMsize { requested: 0 })
    ));

    let mut header_too_small = snapshot.clone();
    header_too_small.negotiated_msize = NINEP_HEADER_SIZE - 1;
    assert!(matches!(
        NinePSession::new(sample_tree()).restore_snapshot(header_too_small),
        Err(NinePServerError::InvalidMsize { requested }) if requested == NINEP_HEADER_SIZE - 1
    ));

    let forged_open = NinePSessionSnapshot {
        negotiated_msize: snapshot.negotiated_msize,
        fids: vec![NinePFidSnapshot {
            fid: 9,
            path: String::from("/alpha.txt"),
            xattr_name: None,
            open_kind: Some(crucible::NinePEntryKind::Directory),
        }],
    };
    assert!(matches!(
        NinePSession::new(sample_tree()).restore_snapshot(forged_open),
        Err(NinePServerError::InvalidFidSnapshot { fid: 9 })
    ));
}

fn attach_root(session: &mut NinePSession, fid: u32) {
    assert!(matches!(
        session.handle_request(NinePRequest::new(10, NinePRequestKind::Attach { fid })),
        crucible::NinePResponse {
            kind: NinePResponseKind::Attach { .. },
            ..
        }
    ));
}

fn walk(session: &mut NinePSession, fid: u32, newfid: u32, names: &[&str]) {
    assert!(matches!(
        session.handle_request(NinePRequest::new(
            11,
            NinePRequestKind::Walk {
                fid,
                newfid,
                names: names.iter().map(|name| (*name).to_owned()).collect(),
            },
        )),
        crucible::NinePResponse {
            kind: NinePResponseKind::Walk { .. },
            ..
        }
    ));
}

fn open(session: &mut NinePSession, fid: u32) {
    assert!(matches!(
        session.handle_request(NinePRequest::new(12, NinePRequestKind::Lopen { fid })),
        crucible::NinePResponse {
            kind: NinePResponseKind::Lopen { .. },
            ..
        }
    ));
}

fn assert_errno(response: crucible::NinePResponse, tag: u16, errno: u32) {
    assert_eq!(
        response,
        crucible::NinePResponse {
            tag,
            kind: NinePResponseKind::Error { errno },
        }
    );
}

fn sample_tree() -> NinePServedTree {
    NinePServedTree::new(vec![
        NinePServedEntry::file("/alpha.txt", b"alpha"),
        NinePServedEntry::directory("/dir"),
        NinePServedEntry::file("/dir/b.txt", b"b"),
        NinePServedEntry::file("/dir/a.txt", b"a"),
        NinePServedEntry::symlink("/link", "/alpha.txt"),
    ])
    .expect("sample tree should build")
}

fn long_file_tree() -> NinePServedTree {
    NinePServedTree::new(vec![NinePServedEntry::file(
        "/a",
        b"abcdefghijklmnopqrstuvwxyz",
    )])
    .expect("long file tree should build")
}
