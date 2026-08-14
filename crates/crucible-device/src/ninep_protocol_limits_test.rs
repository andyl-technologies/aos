//! 9p protocol rejection, msize, and adversarial regression tests.

use std::collections::BTreeMap;

use super::test_support::*;
use super::*;
use crate::subnode::IoCore;

#[test]
fn every_mutating_message_returns_erofs() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    // A representative body for each mutating type; the dispatcher rejects on
    // type alone, so the body content is irrelevant (must still size-match).
    let mutating = [
        codec::TWRITE,
        codec::TLCREATE,
        codec::TMKDIR,
        codec::TSYMLINK,
        codec::TLINK,
        codec::TRENAME,
        codec::TRENAMEAT,
        codec::TUNLINKAT,
        codec::TSETATTR,
        codec::TREMOVE,
        codec::TMKNOD,
        codec::TXATTRCREATE,
        codec::TLOCK,
        codec::TGETLOCK,
    ];
    for (t, (i, &mt)) in (2..).zip(mutating.iter().enumerate()) {
        let req = frame(mt, 100 + i as u16, &[0u8; 8]);
        let (_, reply) = round_trip(&mut dev, t, &req);
        assert_eq!(
            reply_type(&reply),
            codec::RLERROR,
            "mutating type {mt} must error"
        );
        assert_eq!(
            rlerror_code(&reply),
            errno::EROFS,
            "mutating type {mt} must be EROFS"
        );
    }
}

#[test]
fn unknown_message_type_returns_enosys() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    // Type 200 is undefined in 9P2000.L.
    let (_, reply) = round_trip(&mut dev, 1, &frame(200, 5, &[0u8; 4]));
    assert_eq!(reply_type(&reply), codec::RLERROR);
    assert_eq!(rlerror_code(&reply), errno::ENOSYS);
}

#[test]
fn malformed_body_returns_einval() {
    let mut dev = device();
    // A Twalk whose body is too short to hold fid+newfid+nwname.
    let (_, reply) = round_trip(&mut dev, 0, &frame(codec::TWALK, 9, &[0u8; 3]));
    assert_eq!(reply_type(&reply), codec::RLERROR);
    assert_eq!(rlerror_code(&reply), errno::EINVAL);
}

// ---- msize enforcement (IO-18) ---------------------------------------

#[test]
fn over_msize_request_is_rejected() {
    let mut dev = device();
    // A tiny proposed msize clamps UP to the MIN_MSIZE floor (which provably
    // fits every fixed-shape reply, [IO-18]).
    round_trip(&mut dev, 0, &tversion(1, 64, codec::PROTOCOL_VERSION));
    let msize = dev.server().msize();
    assert_eq!(msize, server::MIN_MSIZE);
    // A frame one byte larger than the negotiated msize is rejected before
    // any parsing.
    let pad = msize as usize + 1 - codec::HEADER_LEN;
    let big = frame(codec::TREAD, 7, &vec![0u8; pad]);
    assert!(big.len() > msize as usize);
    let (_, reply) = round_trip(&mut dev, 1, &big);
    assert_eq!(reply_type(&reply), codec::RLERROR);
    assert_eq!(rlerror_code(&reply), errno::EMSGSIZE);
}

#[test]
fn readdir_respects_msize_budget_across_chunks() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    // A small client `count` (not msize, which is floored at MIN_MSIZE) forces
    // the directory to span multiple readdir calls. Each sample entry encodes
    // to ~36-40 bytes, so a 40-byte count yields one whole entry per chunk.
    let chunk = 40u32;
    // First chunk: bounded by count, returns a prefix of the sorted entries.
    let (_, first) = round_trip(&mut dev, 2, &treaddir(3, 1, 0, chunk));
    let first_names = readdir_names(&first);
    assert!(!first_names.is_empty(), "first chunk must make progress");
    assert!(first.len() <= dev.server().msize() as usize);
    // Resume from the last cookie; collect until exhausted.
    let mut all = first_names.clone();
    let mut cookie = (all.len()) as u64; // offsets are 1-based and contiguous
    let mut t = 3u64;
    loop {
        let (lim, reply) = round_trip(&mut dev, t, &treaddir(20, 1, cookie, chunk));
        let names = readdir_names(&reply);
        if names.is_empty() {
            break;
        }
        all.extend(names.iter().cloned());
        cookie += names.len() as u64;
        t = lim;
        assert!(reply.len() <= dev.server().msize() as usize);
    }
    assert_eq!(
        all,
        vec![".", "..", "alpha", "bin", "link", "zeta"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );
}

// ---- regression: MAJOR #1 — every reply is bounded by msize ----------

#[test]
fn regression_no_reply_exceeds_negotiated_msize() {
    // Before the fix, MIN_MSIZE (71) was below the 152-byte Rgetattr frame:
    // negotiating the floor and issuing a getattr emitted a 152-byte reply >
    // msize, violating [IO-18]. Now MIN_MSIZE is derived to fit every
    // fixed-shape reply, and a universal outbound cap backstops the rest.
    // Property: across a representative request mix, NO reply exceeds msize.
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, server::MIN_MSIZE, codec::PROTOCOL_VERSION),
    );
    let msize = dev.server().msize() as usize;
    // The floor must fit the largest fixed reply (Rgetattr = 152 bytes).
    assert!(msize >= 152, "MIN_MSIZE must fit Rgetattr");
    round_trip(&mut dev, 1, &tattach(2, 1));
    // A getattr on the root: its 152-byte Rgetattr must fit the floor.
    let (_, ga) = round_trip(&mut dev, 2, &tgetattr(3, 1, 0x7ff));
    assert_eq!(reply_type(&ga), codec::RGETATTR);
    assert!(ga.len() <= msize, "Rgetattr must fit msize");

    // Exhaustive property check: drive a varied request sequence at the floor
    // and assert every emitted reply frame is <= the negotiated msize.
    let reqs = vec![
        twalk(10, 1, 2, &["bin", "tool"]),
        tlopen(11, 2, 0),
        tread(12, 2, 0, 4096),
        tgetattr(13, 2, 0x7ff),
        tstatfs(14, 1),
        twalk(15, 1, 3, &["link"]),
        treadlink(16, 3),
        treaddir(17, 1, 0, MAX_MSIZE),
        tclunk(18, 2),
    ];
    let mut t = 3u64;
    for req in &reqs {
        let (lim, reply) = round_trip(&mut dev, t, req);
        assert!(
            reply.len() <= msize,
            "reply type {} exceeded msize {} ({} bytes)",
            reply_type(&reply),
            msize,
            reply.len()
        );
        t = lim;
    }
}

// ---- regression: structured QID paths have no delimiter ambiguity ----

#[test]
fn regression_qid_path_distinguishes_adversarial_structured_samples() {
    // Before the fix, qid_path joined components with '/', so distinct
    // component vectors collided: ["a","b"] == ["a/b"] and [] == [""].
    // The length-prefixed encoding makes these distinct ([IO-13]).
    assert_ne!(
        qid_path(&["a".to_string(), "b".to_string()]),
        qid_path(&["a/b".to_string()]),
        "nested vs joined must not collide"
    );
    assert_ne!(
        qid_path(&[]),
        qid_path(&[String::new()]),
        "root vs empty-named child must not collide"
    );
    // A broader fixed regression sample also remains pairwise distinct. This
    // is not a claim that a 64-bit truncated hash is mathematically injective.
    let vectors: Vec<Vec<String>> = vec![
        vec![],
        vec!["a".to_string()],
        vec!["ab".to_string()],
        vec!["a".to_string(), "b".to_string()],
        vec!["a".to_string(), "bc".to_string()],
        vec!["ab".to_string(), "c".to_string()],
        vec!["a".to_string(), "b".to_string(), "c".to_string()],
        vec!["abc".to_string()],
    ];
    let mut seen = std::collections::BTreeSet::new();
    for v in &vectors {
        assert!(
            seen.insert(qid_path(v)),
            "fixed qid_path regression sample collided on {v:?}"
        );
    }
    // Illegal components are rejected at tree construction.
    let mut bad_children = BTreeMap::new();
    bad_children.insert(
        "a/b".to_string(),
        Node::File {
            content: Vec::new(),
        },
    );
    let bad_root = Node::Directory {
        children: bad_children,
    };
    assert!(
        FsTree::try_new(bad_root).is_err(),
        "slash name must be rejected"
    );
}

#[test]
fn regression_walk_rejects_illegal_component_from_wire() {
    // A walk name carrying a NUL byte (illegal, would alias a QID) is rejected
    // with EINVAL rather than silently aliasing ([IO-13]).
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    // Build a Twalk whose single wname is "a\0b" (contains NUL).
    let mut body = 1u32.to_le_bytes().to_vec(); // fid
    body.extend_from_slice(&2u32.to_le_bytes()); // newfid
    body.extend_from_slice(&1u16.to_le_bytes()); // nwname
    body.extend_from_slice(&string_bytes("a\0b"));
    let req = frame(codec::TWALK, 9, &body);
    let (_, reply) = round_trip(&mut dev, 2, &req);
    assert_eq!(reply_type(&reply), codec::RLERROR);
    assert_eq!(rlerror_code(&reply), errno::EINVAL);
}

// ---- regression: MAJOR #3 — readdir never silently truncates ---------

#[test]
fn regression_oversized_single_dirent_returns_emsgsize_not_empty() {
    // Before the fix, a dirent larger than the client `count` budget yielded
    // an empty Rreaddir (count=0) — read as end-of-directory by the client,
    // i.e. silent truncation that [IO-18] forbids. Now the server returns
    // Rlerror(EMSGSIZE) when not even the first resumable entry fits.
    //
    // Build a tree with one long-named child so a single dirent is large.
    let long_name = "x".repeat(200);
    let mut children = BTreeMap::new();
    children.insert(
        long_name.clone(),
        Node::File {
            content: b"data".to_vec(),
        },
    );
    let tree =
        FsTree::try_new(Node::Directory { children }).expect("test 9p tree components are valid");
    let src = crucible_shmem::SLOT_9P_IO as u32;
    let core = ok(IoCore::new(8, src, 16, 16));
    let mut dev = NinepDevice::new(core, tree, NinepLatency::default());

    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    // Resume at offset 2 (past "." and "..") so the long-named entry is the
    // first resumable one, with a client `count` too small to hold it.
    let (_, reply) = round_trip(&mut dev, 2, &treaddir(3, 1, 2, 32));
    assert_eq!(
        reply_type(&reply),
        codec::RLERROR,
        "an unfit first entry must error, not return count=0"
    );
    assert_eq!(rlerror_code(&reply), errno::EMSGSIZE);

    // With an adequate count the same entry is delivered whole.
    let (_, ok_reply) = round_trip(&mut dev, 3, &treaddir(4, 1, 2, MAX_MSIZE));
    assert_eq!(reply_type(&ok_reply), codec::RREADDIR);
    let names = readdir_names(&ok_reply);
    assert_eq!(names, vec![long_name]);
}

// ---- fid table snapshot/restore round-trip (IO-19) -------------------
