//! Checks T-IO-8 9P2000.L wire golden vectors and arbitrary-byte handling.

#![forbid(unsafe_code)]

use crucible::{
    NINEP_EINVAL, NINEP_EIO, NINEP_ENOSYS, NINEP_EROFS, NINEP_FIXED_BLOCK_SIZE,
    NINEP_FIXED_EPOCH_SECONDS, NINEP_FIXED_GID, NINEP_FIXED_UID, NINEP_PROTOCOL_VERSION,
    NinePServedEntry, NinePServedTree, NinePSession,
};

const RLERROR: u8 = 7;
const TSTATFS: u8 = 8;
const RSTATFS: u8 = 9;
const TLOPEN: u8 = 12;
const RLOPEN: u8 = 13;
const TREADLINK: u8 = 22;
const RREADLINK: u8 = 23;
const TGETATTR: u8 = 24;
const RGETATTR: u8 = 25;
const TREADDIR: u8 = 40;
const RREADDIR: u8 = 41;
const TVERSION: u8 = 100;
const RVERSION: u8 = 101;
const TATTACH: u8 = 104;
const RATTACH: u8 = 105;
const TFLUSH: u8 = 108;
const RFLUSH: u8 = 109;
const TWALK: u8 = 110;
const RWALK: u8 = 111;
const TREAD: u8 = 116;
const RREAD: u8 = 117;
const TWRITE: u8 = 118;
const TCLUNK: u8 = 120;
const RCLUNK: u8 = 121;
const UNKNOWN: u8 = 255;
const NOTAG: u16 = u16::MAX;
const NOFID: u32 = u32::MAX;
const O_WRONLY: u32 = 1;
const DT_REG: u8 = 8;

#[test]
fn wire_golden_vectors_cover_read_traverse_and_error_responses() {
    let tree = sample_tree();
    let mut session = NinePSession::new(tree.clone());

    let mut version_body = Vec::new();
    append_u32(&mut version_body, 8192);
    append_string(&mut version_body, NINEP_PROTOCOL_VERSION);
    assert_eq!(
        session.handle_wire_request(&message(TVERSION, NOTAG, version_body.clone())),
        message(RVERSION, NOTAG, version_body)
    );
    assert_eq!(
        session.handle_wire_request(&message(TVERSION, 1, version_request_body(8192))),
        wire_error(1, NINEP_EINVAL)
    );

    assert_eq!(
        session.handle_wire_request(&message(UNKNOWN, 9, Vec::new())),
        wire_error(9, NINEP_ENOSYS)
    );
    assert_eq!(
        session.handle_wire_request(&message(TWRITE, 10, Vec::new())),
        wire_error(10, NINEP_EROFS)
    );
    assert_eq!(
        session.handle_wire_request(&message(TREAD, 11, vec![0])),
        wire_error(11, NINEP_EINVAL)
    );

    assert_eq!(
        session.handle_wire_request(&message(TATTACH, 2, attach_body(1))),
        message(RATTACH, 2, qid_body(tree.qid("/").expect("root qid")))
    );

    assert_eq!(
        session.handle_wire_request(&message(TWALK, 3, walk_body(1, 2, &["a"]))),
        message(
            RWALK,
            3,
            qid_list_body(&[tree.qid("/a").expect("file qid")])
        )
    );
    assert_eq!(
        session.handle_wire_request(&message(TLOPEN, 4, lopen_body(2, 0))),
        message(
            RLOPEN,
            4,
            lopen_response_body(tree.qid("/a").expect("file qid"))
        )
    );
    assert_eq!(
        session.handle_wire_request(&message(TLOPEN, 40, lopen_body(2, O_WRONLY))),
        wire_error(40, NINEP_EROFS)
    );

    let mut expected_read_body = Vec::new();
    append_u32(&mut expected_read_body, 3);
    expected_read_body.extend_from_slice(b"bcd");
    assert_eq!(
        session.handle_wire_request(&message(TREAD, 5, read_body(2, 1, 3))),
        message(RREAD, 5, expected_read_body)
    );

    assert_eq!(
        session.handle_wire_request(&message(TGETATTR, 6, getattr_body(2))),
        message(
            RGETATTR,
            6,
            getattr_response_body(tree.qid("/a").expect("file qid"), 0o100444, 5, 1),
        )
    );

    assert_eq!(
        session.handle_wire_request(&message(TSTATFS, 7, fid_body(1))),
        message(RSTATFS, 7, statfs_response_body(&tree))
    );

    assert_eq!(
        session.handle_wire_request(&message(TWALK, 8, walk_body(1, 3, &["l"]))),
        message(
            RWALK,
            8,
            qid_list_body(&[tree.qid("/l").expect("link qid")])
        )
    );
    let mut readlink_body = Vec::new();
    append_string(&mut readlink_body, "/a");
    assert_eq!(
        session.handle_wire_request(&message(TREADLINK, 12, fid_body(3))),
        message(RREADLINK, 12, readlink_body)
    );

    assert_eq!(
        session.handle_wire_request(&message(TWALK, 13, walk_body(1, 4, &["d"]))),
        message(
            RWALK,
            13,
            qid_list_body(&[tree.qid("/d").expect("dir qid")])
        )
    );
    assert_eq!(
        session.handle_wire_request(&message(TLOPEN, 14, lopen_body(4, 0))),
        message(
            RLOPEN,
            14,
            lopen_response_body(tree.qid("/d").expect("dir qid"))
        )
    );
    assert_eq!(
        session.handle_wire_request(&message(TREADDIR, 15, read_body(4, 0, 1024))),
        message(
            RREADDIR,
            15,
            readdir_response_body(tree.qid("/d/b").expect("dir child qid"), "b"),
        )
    );

    assert_eq!(
        session.handle_wire_request(&message(TFLUSH, 16, flush_body(99))),
        message(RFLUSH, 16, Vec::new())
    );
    assert_eq!(
        session.handle_wire_request(&message(TCLUNK, 17, fid_body(2))),
        message(RCLUNK, 17, Vec::new())
    );
}

#[test]
fn wire_response_msize_and_string_failures_return_well_formed_errors() {
    let mut session = NinePSession::new(sample_tree());
    assert_eq!(
        session.handle_wire_request(&message(TVERSION, NOTAG, version_request_body(23))),
        message(RVERSION, NOTAG, version_request_body(23))
    );
    assert_eq!(
        session.handle_wire_request(&message(TATTACH, 1, attach_body(1))),
        message(
            RATTACH,
            1,
            qid_body(sample_tree().qid("/").expect("root qid"))
        )
    );
    assert_eq!(
        session.handle_wire_request(&message(TGETATTR, 2, getattr_body(1))),
        wire_error(2, NINEP_EINVAL)
    );
    assert_eq!(
        session.handle_wire_request(&message(TWALK, 6, walk_body(1, 2, &["d", "b"]))),
        wire_error(6, NINEP_EINVAL)
    );
    assert!(
        !session
            .snapshot()
            .fids
            .iter()
            .any(|snapshot| snapshot.fid == 2)
    );
    assert_eq!(
        session.handle_wire_request(&message(TLOPEN, 7, lopen_body(1, 0))),
        wire_error(7, NINEP_EINVAL)
    );
    let snapshot = session.snapshot();
    let attached_fid = snapshot
        .fids
        .iter()
        .find(|snapshot| snapshot.fid == 1)
        .expect("fid 1 should remain attached");
    assert_eq!(attached_fid.open_kind, None);

    let mut long_target = String::new();
    for _ in 0..70_000 {
        long_target.push('x');
    }
    let mut long_session = NinePSession::new(
        NinePServedTree::new(vec![NinePServedEntry::symlink("/long", long_target)])
            .expect("long symlink tree should build"),
    );
    assert_eq!(
        long_session.handle_wire_request(&message(TVERSION, NOTAG, version_request_body(8192))),
        message(RVERSION, NOTAG, version_request_body(8192))
    );
    assert_eq!(
        long_session.handle_wire_request(&message(TATTACH, 3, attach_body(1))),
        message(
            RATTACH,
            3,
            qid_body(long_session_tree().qid("/").expect("root qid")),
        )
    );
    assert_well_formed_response(&long_session.handle_wire_request(&message(
        TWALK,
        4,
        walk_body(1, 2, &["long"]),
    )));
    assert_eq!(
        long_session.handle_wire_request(&message(TREADLINK, 5, fid_body(2))),
        wire_error(5, NINEP_EIO)
    );
}

#[test]
fn wire_fuzzer_never_panics_and_returns_structurally_valid_response() {
    let mut seed = 0x0123_4567_89ab_cdefu64;

    for length in 0..128usize {
        for _ in 0..4 {
            let input = random_bytes(&mut seed, length);
            assert_fuzz_response(&input);
        }

        let random_body = random_bytes(&mut seed, length);
        assert_fuzz_response(&message(UNKNOWN, length as u16, random_body.clone()));
        assert_fuzz_response(&message(TWRITE, length as u16, random_body));
        assert_fuzz_response(&message(TFLUSH, length as u16, flush_body(length as u16)));
        assert_fuzz_response(&message(TVERSION, NOTAG, version_request_body(64)));
    }
}

fn assert_fuzz_response(input: &[u8]) {
    let result = std::panic::catch_unwind(|| {
        let mut session = NinePSession::new(sample_tree());
        session.handle_wire_request(input)
    });
    let response = match result {
        Ok(response) => response,
        Err(_) => panic!("wire request panicked for input length {}", input.len()),
    };
    assert_well_formed_response(&response);
}

fn random_bytes(seed: &mut u64, length: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(length);
    for _ in 0..length {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        input.push((*seed >> 32) as u8);
    }
    input
}

fn message(message_type: u8, tag: u16, body: Vec<u8>) -> Vec<u8> {
    let size = u32::try_from(7 + body.len()).expect("test vector should fit in u32");
    let mut message = Vec::new();
    append_u32(&mut message, size);
    message.push(message_type);
    append_u16(&mut message, tag);
    message.extend_from_slice(&body);
    message
}

fn version_request_body(msize: u32) -> Vec<u8> {
    let mut body = Vec::new();
    append_u32(&mut body, msize);
    append_string(&mut body, NINEP_PROTOCOL_VERSION);
    body
}

fn attach_body(fid: u32) -> Vec<u8> {
    let mut body = Vec::new();
    append_u32(&mut body, fid);
    append_u32(&mut body, NOFID);
    append_string(&mut body, "");
    append_string(&mut body, "");
    append_u32(&mut body, 0);
    body
}

fn walk_body(fid: u32, newfid: u32, names: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    append_u32(&mut body, fid);
    append_u32(&mut body, newfid);
    append_u16(
        &mut body,
        u16::try_from(names.len()).expect("test walk should fit in u16"),
    );
    for name in names {
        append_string(&mut body, name);
    }
    body
}

fn lopen_body(fid: u32, flags: u32) -> Vec<u8> {
    let mut body = Vec::new();
    append_u32(&mut body, fid);
    append_u32(&mut body, flags);
    body
}

fn fid_body(fid: u32) -> Vec<u8> {
    let mut body = Vec::new();
    append_u32(&mut body, fid);
    body
}

fn flush_body(oldtag: u16) -> Vec<u8> {
    let mut body = Vec::new();
    append_u16(&mut body, oldtag);
    body
}

fn read_body(fid: u32, offset: u64, count: u32) -> Vec<u8> {
    let mut body = Vec::new();
    append_u32(&mut body, fid);
    append_u64(&mut body, offset);
    append_u32(&mut body, count);
    body
}

fn getattr_body(fid: u32) -> Vec<u8> {
    let mut body = Vec::new();
    append_u32(&mut body, fid);
    append_u64(&mut body, 0xffff);
    body
}

fn wire_error(tag: u16, errno: u32) -> Vec<u8> {
    let mut response = Vec::new();
    append_u32(&mut response, 11);
    response.push(RLERROR);
    append_u16(&mut response, tag);
    append_u32(&mut response, errno);
    response
}

fn qid_body(qid: crucible::NinePQid) -> Vec<u8> {
    let mut body = Vec::new();
    append_qid(&mut body, qid);
    body
}

fn qid_list_body(qids: &[crucible::NinePQid]) -> Vec<u8> {
    let mut body = Vec::new();
    append_u16(
        &mut body,
        u16::try_from(qids.len()).expect("test qid list should fit in u16"),
    );
    for qid in qids {
        append_qid(&mut body, *qid);
    }
    body
}

fn lopen_response_body(qid: crucible::NinePQid) -> Vec<u8> {
    let mut body = qid_body(qid);
    append_u32(&mut body, 0);
    body
}

fn getattr_response_body(qid: crucible::NinePQid, mode: u32, size: u64, blocks: u64) -> Vec<u8> {
    let mut body = Vec::new();
    append_u64(&mut body, 0x3fff);
    append_qid(&mut body, qid);
    append_u32(&mut body, mode);
    append_u32(&mut body, NINEP_FIXED_UID);
    append_u32(&mut body, NINEP_FIXED_GID);
    append_u64(&mut body, 1);
    append_u64(&mut body, 0);
    append_u64(&mut body, size);
    append_u64(&mut body, NINEP_FIXED_BLOCK_SIZE);
    append_u64(&mut body, blocks);
    append_u64(&mut body, NINEP_FIXED_EPOCH_SECONDS);
    append_u64(&mut body, 0);
    append_u64(&mut body, NINEP_FIXED_EPOCH_SECONDS);
    append_u64(&mut body, 0);
    append_u64(&mut body, NINEP_FIXED_EPOCH_SECONDS);
    append_u64(&mut body, 0);
    append_u64(&mut body, 0);
    append_u64(&mut body, 0);
    append_u64(&mut body, 0);
    append_u64(&mut body, 0);
    body
}

fn statfs_response_body(tree: &NinePServedTree) -> Vec<u8> {
    let statfs = tree.statfs().expect("statfs should compute");
    let mut body = Vec::new();
    append_u32(&mut body, 0x0102_1997);
    append_u32(
        &mut body,
        u32::try_from(statfs.block_size).expect("block size should fit"),
    );
    append_u64(&mut body, statfs.blocks);
    append_u64(&mut body, 0);
    append_u64(&mut body, 0);
    append_u64(&mut body, statfs.files);
    append_u64(&mut body, 0);
    append_u64(&mut body, statfs.fsid);
    append_u32(&mut body, statfs.name_max);
    body
}

fn readdir_response_body(qid: crucible::NinePQid, name: &str) -> Vec<u8> {
    let mut entries = Vec::new();
    append_qid(&mut entries, qid);
    append_u64(&mut entries, 1);
    entries.push(DT_REG);
    append_string(&mut entries, name);

    let mut body = Vec::new();
    append_u32(
        &mut body,
        u32::try_from(entries.len()).expect("entry bytes should fit"),
    );
    body.extend_from_slice(&entries);
    body
}

fn append_qid(bytes: &mut Vec<u8>, qid: crucible::NinePQid) {
    bytes.push(qid.qtype);
    append_u32(bytes, qid.version);
    append_u64(bytes, qid.path);
}

fn assert_well_formed_response(response: &[u8]) {
    assert!(response.len() >= 7, "response shorter than 9p header");
    let declared = u32::from_le_bytes([response[0], response[1], response[2], response[3]]);
    assert_eq!(
        usize::try_from(declared).expect("declared response size should fit usize"),
        response.len()
    );

    let message_type = response[4];
    let body = &response[7..];
    match message_type {
        RLERROR => assert_eq!(body.len(), 4),
        RVERSION => {
            assert!(body.len() >= 6);
            let string_len = usize::from(u16::from_le_bytes([body[4], body[5]]));
            assert_eq!(body.len(), 6 + string_len);
        }
        RATTACH => assert_eq!(body.len(), 13),
        RWALK => {
            assert!(body.len() >= 2);
            let qid_count = usize::from(u16::from_le_bytes([body[0], body[1]]));
            assert_eq!(body.len(), 2 + (qid_count * 13));
        }
        RLOPEN => assert_eq!(body.len(), 17),
        RREAD | RREADDIR => {
            assert!(body.len() >= 4);
            let payload_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            assert_eq!(
                usize::try_from(payload_len).expect("payload length should fit"),
                body.len() - 4
            );
        }
        RGETATTR => assert_eq!(body.len(), 153),
        RREADLINK => {
            assert!(body.len() >= 2);
            let string_len = usize::from(u16::from_le_bytes([body[0], body[1]]));
            assert_eq!(body.len(), 2 + string_len);
        }
        RCLUNK | RFLUSH => assert!(body.is_empty()),
        RSTATFS => assert_eq!(body.len(), 60),
        other => panic!("unexpected response type {other}"),
    }
}

fn append_string(bytes: &mut Vec<u8>, value: &str) {
    append_u16(
        bytes,
        u16::try_from(value.len()).expect("test string should fit in u16"),
    );
    bytes.extend_from_slice(value.as_bytes());
}

fn append_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn sample_tree() -> NinePServedTree {
    NinePServedTree::new(vec![
        NinePServedEntry::file("/a", b"abcde"),
        NinePServedEntry::directory("/d"),
        NinePServedEntry::file("/d/b", b"b"),
        NinePServedEntry::symlink("/l", "/a"),
    ])
    .expect("sample tree should build")
}

fn long_session_tree() -> NinePServedTree {
    NinePServedTree::new(Vec::new()).expect("root-only tree should build")
}
