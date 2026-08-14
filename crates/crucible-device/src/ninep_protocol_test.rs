//! Core 9p protocol traversal, metadata, and read tests.

use std::collections::BTreeMap;

use super::test_support::*;
use super::*;
use crate::subnode::IoCore;

#[test]
fn version_pins_protocol_and_clamps_msize_down() {
    let mut dev = device();
    // Client proposes a huge msize; server clamps to its fixed maximum.
    let (_, reply) = round_trip(&mut dev, 0, &tversion(1, 1 << 30, codec::PROTOCOL_VERSION));
    assert_eq!(reply_type(&reply), codec::RVERSION);
    let msize = u32::from_le_bytes([reply[7], reply[8], reply[9], reply[10]]);
    assert_eq!(msize, MAX_MSIZE);
    // The version string echoes the fixed protocol.
    let vlen = u16::from_le_bytes([reply[11], reply[12]]) as usize;
    let v = std::str::from_utf8(&reply[13..13 + vlen]).unwrap_or("");
    assert_eq!(v, codec::PROTOCOL_VERSION);
    assert!(dev.server().negotiated());
    assert_eq!(dev.server().msize(), MAX_MSIZE);
}

#[test]
fn version_clamps_msize_to_client_when_smaller() {
    let mut dev = device();
    let (_, reply) = round_trip(&mut dev, 0, &tversion(1, 2048, codec::PROTOCOL_VERSION));
    let msize = u32::from_le_bytes([reply[7], reply[8], reply[9], reply[10]]);
    assert_eq!(msize, 2048);
    assert_eq!(dev.server().msize(), 2048);
}

#[test]
fn version_rejects_unknown_protocol_string() {
    let mut dev = device();
    let (_, reply) = round_trip(&mut dev, 0, &tversion(1, 4096, "9P2000"));
    let vlen = u16::from_le_bytes([reply[11], reply[12]]) as usize;
    let v = std::str::from_utf8(&reply[13..13 + vlen]).unwrap_or("");
    assert_eq!(v, "unknown");
    assert!(!dev.server().negotiated());
}

// ---- attach + walk + QID path-hashing (IO-13) ------------------------

#[test]
fn attach_returns_root_qid_path_hashed() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    let (_, reply) = round_trip(&mut dev, 1, &tattach(2, 1));
    assert_eq!(reply_type(&reply), codec::RATTACH);
    let qid = ok(Qid::decode(&reply[7..]));
    assert_eq!(qid.kind, QidType::Dir);
    assert_eq!(qid.version, Qid::FIXED_VERSION);
    // The root QID path is the stable hash of "/", not a host inode.
    assert_eq!(qid.path, qid_path(&[]));
}

#[test]
fn qid_is_path_hashed_and_stable_across_trees() {
    // Two independently constructed trees yield identical QIDs for the same
    // path — proving QIDs depend on path text, not host inode allocation.
    let a = sample_tree();
    let b = sample_tree();
    let path = vec!["bin".to_string(), "tool".to_string()];
    assert_eq!(a.qid(&path), b.qid(&path));
    // Distinct paths get distinct QID paths.
    assert_ne!(a.qid(&path).map(|q| q.path), a.qid(&[]).map(|q| q.path));
}

#[test]
fn walk_resolves_into_subdirectory() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    let (_, reply) = round_trip(&mut dev, 2, &twalk(3, 1, 2, &["bin", "tool"]));
    assert_eq!(reply_type(&reply), codec::RWALK);
    let nwqid = u16::from_le_bytes([reply[7], reply[8]]);
    assert_eq!(nwqid, 2);
    // The final QID is the file's path-hash.
    let last = ok(Qid::decode(&reply[7 + 2 + codec::QID_LEN..]));
    assert_eq!(last.kind, QidType::File);
    assert_eq!(
        last.path,
        qid_path(&["bin".to_string(), "tool".to_string()])
    );
}

#[test]
fn walk_missing_component_returns_enoent() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    let (_, reply) = round_trip(&mut dev, 2, &twalk(3, 1, 2, &["nope"]));
    assert_eq!(reply_type(&reply), codec::RLERROR);
    assert_eq!(rlerror_code(&reply), errno::ENOENT);
}

// ---- sorted readdir (IO-14) ------------------------------------------

/// Decodes the names from a packed Rreaddir payload in wire order.
fn readdir_names(reply: &[u8]) -> Vec<String> {
    let count = u32::from_le_bytes([reply[7], reply[8], reply[9], reply[10]]) as usize;
    let data = &reply[11..11 + count];
    let mut names = Vec::new();
    let mut pos = 0;
    while pos + codec::QID_LEN + 8 + 1 + 2 <= data.len() {
        // qid[13] offset[8] type[1] name[s]
        let name_off = pos + codec::QID_LEN + 8 + 1;
        let nlen = u16::from_le_bytes([data[name_off], data[name_off + 1]]) as usize;
        let nstart = name_off + 2;
        let name = String::from_utf8_lossy(&data[nstart..nstart + nlen]).to_string();
        names.push(name);
        pos = nstart + nlen;
    }
    names
}

#[test]
fn readdir_returns_sorted_entries_with_dot_first() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    round_trip(&mut dev, 2, &tlopen(3, 1, 0));
    let (_, reply) = round_trip(&mut dev, 3, &treaddir(4, 1, 0, MAX_MSIZE));
    assert_eq!(reply_type(&reply), codec::RREADDIR);
    let names = readdir_names(&reply);
    // "." and ".." first, then children lexicographically — NOT insert order.
    assert_eq!(
        names,
        vec![".", "..", "alpha", "bin", "link", "zeta"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );
}

#[test]
fn readdir_is_byte_identical_on_repeat() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    // Identical tag on both reads: the reply must be byte-identical, proving
    // enumeration order (not just content) is deterministic ([IO-14]).
    let (_, a) = round_trip(&mut dev, 2, &treaddir(3, 1, 0, MAX_MSIZE));
    let (_, b) = round_trip(&mut dev, 3, &treaddir(3, 1, 0, MAX_MSIZE));
    assert_eq!(a, b, "repeated readdir of the same snapshot must match");
}

// ---- getattr / statfs host-independence (IO-15) ----------------------

#[test]
fn getattr_returns_fixed_and_content_derived_attrs() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    round_trip(&mut dev, 2, &twalk(3, 1, 2, &["alpha"]));
    let (_, reply) = round_trip(&mut dev, 3, &tgetattr(4, 2, 0x7ff));
    assert_eq!(reply_type(&reply), codec::RGETATTR);
    // Body: valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8] rdev[8]
    //       size[8] blksize[8] blocks[8] then 9*u64 timestamps (all zero).
    let mut p = 7;
    let _valid = u64::from_le_bytes(reply[p..p + 8].try_into().unwrap_or([0; 8]));
    p += 8 + codec::QID_LEN;
    let uid_off = p + 4;
    let uid = u32::from_le_bytes(reply[uid_off..uid_off + 4].try_into().unwrap_or([0; 4]));
    let gid = u32::from_le_bytes(reply[uid_off + 4..uid_off + 8].try_into().unwrap_or([0; 4]));
    assert_eq!(uid, 0, "uid must be fixed root");
    assert_eq!(gid, 0, "gid must be fixed root");
    // size = len("alpha-content") = 13; blocks = ceil(13/512) = 1.
    let size_off = uid_off + 8 + 8 + 8; // skip uid,gid,nlink,rdev
    let size = u64::from_le_bytes(reply[size_off..size_off + 8].try_into().unwrap_or([0; 8]));
    assert_eq!(size, 13);
    let blksize = u64::from_le_bytes(
        reply[size_off + 8..size_off + 16]
            .try_into()
            .unwrap_or([0; 8]),
    );
    let blocks = u64::from_le_bytes(
        reply[size_off + 16..size_off + 24]
            .try_into()
            .unwrap_or([0; 8]),
    );
    assert_eq!(blksize, 4096);
    assert_eq!(blocks, 1);
    // All timestamp words after blocks are the fixed epoch zero.
    let ts_off = size_off + 24;
    for chunk in reply[ts_off..].chunks(8) {
        if chunk.len() == 8 {
            assert_eq!(
                u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])),
                0,
                "timestamps must be a fixed epoch"
            );
        }
    }
}

#[test]
fn statfs_is_synthetic_and_host_independent() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    let (_, reply) = round_trip(&mut dev, 2, &tstatfs(3, 1));
    assert_eq!(reply_type(&reply), codec::RSTATFS);
    let fs_type = u32::from_le_bytes([reply[7], reply[8], reply[9], reply[10]]);
    assert_eq!(fs_type, tree::STATFS_MAGIC);
    let bsize = u32::from_le_bytes([reply[11], reply[12], reply[13], reply[14]]);
    assert_eq!(bsize, 4096);
}

// ---- read file content (IO-17) ---------------------------------------

#[test]
fn read_returns_content_derived_bytes() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    round_trip(&mut dev, 2, &twalk(3, 1, 2, &["alpha"]));
    round_trip(&mut dev, 3, &tlopen(4, 2, 0));
    let (_, reply) = round_trip(&mut dev, 4, &tread(5, 2, 0, 64));
    assert_eq!(reply_type(&reply), codec::RREAD);
    let count = u32::from_le_bytes([reply[7], reply[8], reply[9], reply[10]]) as usize;
    assert_eq!(&reply[11..11 + count], b"alpha-content");
}

#[test]
fn read_of_directory_is_eisdir() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    let (_, reply) = round_trip(&mut dev, 2, &tread(3, 1, 0, 16));
    assert_eq!(reply_type(&reply), codec::RLERROR);
    assert_eq!(rlerror_code(&reply), errno::EISDIR);
}

#[test]
fn readlink_returns_symlink_target() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    round_trip(&mut dev, 2, &twalk(3, 1, 2, &["link"]));
    let (_, reply) = round_trip(&mut dev, 3, &treadlink(4, 2));
    assert_eq!(reply_type(&reply), codec::RREADLINK);
    let tlen = u16::from_le_bytes([reply[7], reply[8]]) as usize;
    assert_eq!(&reply[9..9 + tlen], b"alpha");
}

// ---- clunk + fid table (IO-19) ---------------------------------------

#[test]
fn clunk_releases_fid() {
    let mut dev = device();
    round_trip(
        &mut dev,
        0,
        &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
    );
    round_trip(&mut dev, 1, &tattach(2, 1));
    assert!(dev.server().fids().contains_key(&1));
    let (_, reply) = round_trip(&mut dev, 2, &tclunk(3, 1));
    assert_eq!(reply_type(&reply), codec::RCLUNK);
    assert!(!dev.server().fids().contains_key(&1));
    // A second clunk of the now-unknown fid is EBADF.
    let (_, reply2) = round_trip(&mut dev, 3, &tclunk(4, 1));
    assert_eq!(reply_type(&reply2), codec::RLERROR);
    assert_eq!(rlerror_code(&reply2), errno::EBADF);
}

// ---- the read-only EROFS boundary (IO-17) ----------------------------
