//! Shared 9p device test fixtures and snapshot-codec coverage.

use super::*;
use crate::subnode::IoCore;
use std::collections::BTreeMap;

/// Unwraps a result in tests, panicking with the error on failure.
pub(super) fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
}

/// Builds a small deterministic tree: a root with sorted children including
/// a subdirectory, a regular file, and a symlink.
///
/// ```text
///   /
///   |- alpha            (file, "alpha-content")
///   |- bin/
///   |   |- tool         (file, "TOOL")
///   |- link             (symlink -> alpha)
///   |- zeta             (file, "z")
/// ```
pub(super) fn sample_tree() -> FsTree {
    let mut bin = BTreeMap::new();
    bin.insert(
        "tool".to_string(),
        Node::File {
            content: b"TOOL".to_vec(),
        },
    );
    let mut root = BTreeMap::new();
    // Insert in NON-sorted order to prove enumeration sorts regardless.
    root.insert(
        "zeta".to_string(),
        Node::File {
            content: b"z".to_vec(),
        },
    );
    root.insert(
        "alpha".to_string(),
        Node::File {
            content: b"alpha-content".to_vec(),
        },
    );
    root.insert("bin".to_string(), Node::Directory { children: bin });
    root.insert(
        "link".to_string(),
        Node::Symlink {
            target: "alpha".to_string(),
        },
    );
    FsTree::try_new(Node::Directory { children: root }).expect("test 9p tree components are valid")
}

/// Builds a 9p device over the sample tree with a default latency model.
pub(super) fn device() -> NinepDevice {
    let src = crucible_shmem::SLOT_9P_IO as u32;
    let core = ok(IoCore::new(8, src, 16, 16));
    NinepDevice::new(core, sample_tree(), NinepLatency::default())
}

#[test]
pub(super) fn ninep_snapshot_codec_round_trips_complete_device_state() {
    let device = device();
    let snapshot = device.snapshot();
    let bytes = ok(snapshot.to_canonical_bytes());
    assert_eq!(ok(NinepSnapshot::from_canonical_bytes(&bytes)), snapshot);

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        NinepSnapshot::from_canonical_bytes(&trailing),
        Err(NinepSnapshotCodecError::Noncanonical)
    );
}

// ---- frame builders for the request side -----------------------------

pub(super) fn frame(msg_type: u8, tag: u16, body: &[u8]) -> Vec<u8> {
    let size = (codec::HEADER_LEN + body.len()) as u32;
    let mut f = Vec::new();
    f.extend_from_slice(&size.to_le_bytes());
    f.push(msg_type);
    f.extend_from_slice(&tag.to_le_bytes());
    f.extend_from_slice(body);
    f
}

pub(super) fn string_bytes(s: &str) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(s.len() as u16).to_le_bytes());
    b.extend_from_slice(s.as_bytes());
    b
}

pub(super) fn tversion(tag: u16, msize: u32, version: &str) -> Vec<u8> {
    let mut body = msize.to_le_bytes().to_vec();
    body.extend_from_slice(&string_bytes(version));
    frame(codec::TVERSION, tag, &body)
}

pub(super) fn tattach(tag: u16, fid: u32) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&u32::MAX.to_le_bytes()); // afid = NOFID
    body.extend_from_slice(&string_bytes("user"));
    body.extend_from_slice(&string_bytes(""));
    body.extend_from_slice(&0u32.to_le_bytes()); // n_uname
    frame(codec::TATTACH, tag, &body)
}

pub(super) fn twalk(tag: u16, fid: u32, newfid: u32, names: &[&str]) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&newfid.to_le_bytes());
    body.extend_from_slice(&(names.len() as u16).to_le_bytes());
    for n in names {
        body.extend_from_slice(&string_bytes(n));
    }
    frame(codec::TWALK, tag, &body)
}

pub(super) fn tlopen(tag: u16, fid: u32, flags: u32) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&flags.to_le_bytes());
    frame(codec::TLOPEN, tag, &body)
}

pub(super) fn tread(tag: u16, fid: u32, offset: u64, count: u32) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&offset.to_le_bytes());
    body.extend_from_slice(&count.to_le_bytes());
    frame(codec::TREAD, tag, &body)
}

pub(super) fn treaddir(tag: u16, fid: u32, offset: u64, count: u32) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&offset.to_le_bytes());
    body.extend_from_slice(&count.to_le_bytes());
    frame(codec::TREADDIR, tag, &body)
}

pub(super) fn tgetattr(tag: u16, fid: u32, mask: u64) -> Vec<u8> {
    let mut body = fid.to_le_bytes().to_vec();
    body.extend_from_slice(&mask.to_le_bytes());
    frame(codec::TGETATTR, tag, &body)
}

pub(super) fn tstatfs(tag: u16, fid: u32) -> Vec<u8> {
    frame(codec::TSTATFS, tag, &fid.to_le_bytes())
}

pub(super) fn tclunk(tag: u16, fid: u32) -> Vec<u8> {
    frame(codec::TCLUNK, tag, &fid.to_le_bytes())
}

pub(super) fn treadlink(tag: u16, fid: u32) -> Vec<u8> {
    frame(codec::TREADLINK, tag, &fid.to_le_bytes())
}

/// Submits a single request frame and returns the reply frame.
pub(super) fn round_trip(dev: &mut NinepDevice, t: u64, req: &[u8]) -> (u64, Vec<u8>) {
    ok(dev.submit(t, req));
    let lim = dev.core().next_exact_local_event().unwrap_or(t);
    ok(dev.advance_to(lim));
    let reply = dev
        .next_response()
        .unwrap_or_else(|| panic!("expected a reply"));
    (lim, reply)
}

/// Reads the 9p reply type byte (offset 4).
pub(super) fn reply_type(frame: &[u8]) -> u8 {
    frame[4]
}

/// Reads the Rlerror ecode (offset 7..11) from an Rlerror frame.
pub(super) fn rlerror_code(frame: &[u8]) -> u32 {
    u32::from_le_bytes([frame[7], frame[8], frame[9], frame[10]])
}

/// Decodes directory-entry names from a packed `Rreaddir` reply.
pub(super) fn readdir_names(reply: &[u8]) -> Vec<String> {
    let count = u32::from_le_bytes([reply[7], reply[8], reply[9], reply[10]]) as usize;
    let data = &reply[11..11 + count];
    let mut names = Vec::new();
    let mut pos = 0;
    while pos + codec::QID_LEN + 8 + 1 + 2 <= data.len() {
        let name_off = pos + codec::QID_LEN + 8 + 1;
        let name_len = u16::from_le_bytes([data[name_off], data[name_off + 1]]) as usize;
        let name_start = name_off + 2;
        names.push(String::from_utf8_lossy(&data[name_start..name_start + name_len]).to_string());
        pos = name_start + name_len;
    }
    names
}

// ---- version negotiation (IO-16) -------------------------------------
