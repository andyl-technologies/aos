//! The 9p filesystem sub-node: a read-only 9P2000.L server over a content tree.
//!
//! This module assembles the 9p I/O sub-node of RFC-0010 §15.3 from four focused
//! submodules and re-exports their public surface:
//!
//! - [`codec`]: the versioned, little-endian, bounds-checked 9p wire ABI
//!   (message framing, [`Qid`], request decode, reply encode, [IO-16], [IO-18]).
//! - [`tree`]: the deterministic in-memory [`FsTree`] — path-hashed QIDs, sorted
//!   enumeration, and fixed/content-derived attributes ([IO-13], [IO-14],
//!   [IO-15]).
//! - [`server`]: the [`NinepServer`] dispatcher — fid state, the `EROFS`
//!   read-only boundary, `msize` enforcement, and snapshot/restore of the fid
//!   table ([IO-17], [IO-19]).
//! - [`device`]: the [`NinepDevice`] [`IoSubNode`](crate::subnode::IoSubNode)
//!   implementation, its [`NinepLatency`] completion model, and its
//!   [`NinepSnapshot`] device-half `MaterializedState` ([IO-22], [IO-23]).
//! - [`errno`]: the fixed Linux errno codes returned in `Rlerror` replies.
//!
//! The 9p device composes the uniform [`IoCore`](crate::subnode::IoCore) of the
//! CS-IO-1 foundation for the clock, rings, in-flight queue, and
//! COMPUTE-then-DELIVER lifecycle; this module supplies only the 9p-specific
//! COMPUTE (dispatch a request frame against the read-only tree) and state (the
//! served tree, the fid table, the RNG placeholder).
//!
//! # Determinism by construction
//!
//! Every value the server returns is a pure function of the served tree's content
//! and the request ([IO-13]): QIDs are path-hashed not inode-derived, directory
//! enumeration is lexicographically sorted, attributes are a fixed epoch / root
//! ownership / content-derived sizes, and the fid table is a
//! [`BTreeMap`](std::collections::BTreeMap) so its iteration never depends on
//! host hashing ([IO-24]). No host clock, host filesystem ordering, or host inode
//! ever participates.
//!
//! ```text
//! 9p message frame (little-endian) — size[4] type[1] tag[2] body...
//! served (read/traverse):
//!   Tversion Tattach Twalk Tlopen Tread Treaddir Tgetattr
//!   Treadlink Tclunk Tstatfs Tflush Txattrwalk Tfsync
//! rejected with EROFS (write/mutate):
//!   Tlcreate Twrite Tmkdir Tunlinkat Trenameat Tsetattr Tsymlink Tlink ...
//! unknown type -> ENOSYS ; malformed body -> EINVAL ; over-msize -> EMSGSIZE
//! ```

pub mod codec;
pub mod device;
pub mod errno;
pub mod fault;
pub mod server;
pub mod tree;

pub use codec::{
    GetattrReply, HEADER_LEN, Message, NinepCodecError, PROTOCOL_VERSION, QID_LEN, Qid, QidType,
    StatfsReply, TMessage,
};
pub use device::{
    NinepDevice, NinepLatency, NinepSnapshot, NinepSnapshotCodecError, NinepVirtualFid,
};
pub use fault::*;
pub use server::{FidEntry, FidState, MAX_MSIZE, MIN_MSIZE, NinepServer, NinepServerSnapshot};
pub use tree::{
    BadComponent, DirEntry, FsTree, FsTreeDecodeError, Node, qid_path, validate_component,
};

#[cfg(test)]
mod golden;

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- unit-test fixtures and assertions fail loudly.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::subnode::IoCore;
    use std::collections::BTreeMap;

    /// Unwraps a result in tests, panicking with the error on failure.
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
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
    fn sample_tree() -> FsTree {
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
        FsTree::try_new(Node::Directory { children: root })
            .expect("test 9p tree components are valid")
    }

    /// Builds a 9p device over the sample tree with a default latency model.
    fn device() -> NinepDevice {
        let src = crucible_shmem::SLOT_9P_IO as u32;
        let core = ok(IoCore::new(8, src, 16, 16));
        NinepDevice::new(core, sample_tree(), NinepLatency::default())
    }

    #[test]
    fn ninep_snapshot_codec_round_trips_complete_device_state() {
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

    fn frame(msg_type: u8, tag: u16, body: &[u8]) -> Vec<u8> {
        let size = (codec::HEADER_LEN + body.len()) as u32;
        let mut f = Vec::new();
        f.extend_from_slice(&size.to_le_bytes());
        f.push(msg_type);
        f.extend_from_slice(&tag.to_le_bytes());
        f.extend_from_slice(body);
        f
    }

    fn string_bytes(s: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(s.len() as u16).to_le_bytes());
        b.extend_from_slice(s.as_bytes());
        b
    }

    fn tversion(tag: u16, msize: u32, version: &str) -> Vec<u8> {
        let mut body = msize.to_le_bytes().to_vec();
        body.extend_from_slice(&string_bytes(version));
        frame(codec::TVERSION, tag, &body)
    }

    fn tattach(tag: u16, fid: u32) -> Vec<u8> {
        let mut body = fid.to_le_bytes().to_vec();
        body.extend_from_slice(&u32::MAX.to_le_bytes()); // afid = NOFID
        body.extend_from_slice(&string_bytes("user"));
        body.extend_from_slice(&string_bytes(""));
        body.extend_from_slice(&0u32.to_le_bytes()); // n_uname
        frame(codec::TATTACH, tag, &body)
    }

    fn twalk(tag: u16, fid: u32, newfid: u32, names: &[&str]) -> Vec<u8> {
        let mut body = fid.to_le_bytes().to_vec();
        body.extend_from_slice(&newfid.to_le_bytes());
        body.extend_from_slice(&(names.len() as u16).to_le_bytes());
        for n in names {
            body.extend_from_slice(&string_bytes(n));
        }
        frame(codec::TWALK, tag, &body)
    }

    fn tlopen(tag: u16, fid: u32, flags: u32) -> Vec<u8> {
        let mut body = fid.to_le_bytes().to_vec();
        body.extend_from_slice(&flags.to_le_bytes());
        frame(codec::TLOPEN, tag, &body)
    }

    fn tread(tag: u16, fid: u32, offset: u64, count: u32) -> Vec<u8> {
        let mut body = fid.to_le_bytes().to_vec();
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        frame(codec::TREAD, tag, &body)
    }

    fn treaddir(tag: u16, fid: u32, offset: u64, count: u32) -> Vec<u8> {
        let mut body = fid.to_le_bytes().to_vec();
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        frame(codec::TREADDIR, tag, &body)
    }

    fn tgetattr(tag: u16, fid: u32, mask: u64) -> Vec<u8> {
        let mut body = fid.to_le_bytes().to_vec();
        body.extend_from_slice(&mask.to_le_bytes());
        frame(codec::TGETATTR, tag, &body)
    }

    fn tstatfs(tag: u16, fid: u32) -> Vec<u8> {
        frame(codec::TSTATFS, tag, &fid.to_le_bytes())
    }

    fn tclunk(tag: u16, fid: u32) -> Vec<u8> {
        frame(codec::TCLUNK, tag, &fid.to_le_bytes())
    }

    fn treadlink(tag: u16, fid: u32) -> Vec<u8> {
        frame(codec::TREADLINK, tag, &fid.to_le_bytes())
    }

    /// Submits a single request frame and returns the reply frame.
    fn round_trip(dev: &mut NinepDevice, t: u64, req: &[u8]) -> (u64, Vec<u8>) {
        ok(dev.submit(t, req));
        let lim = dev.core().next_exact_local_event().unwrap_or(t);
        ok(dev.advance_to(lim));
        let reply = dev
            .next_response()
            .unwrap_or_else(|| panic!("expected a reply"));
        (lim, reply)
    }

    /// Reads the 9p reply type byte (offset 4).
    fn reply_type(frame: &[u8]) -> u8 {
        frame[4]
    }

    /// Reads the Rlerror ecode (offset 7..11) from an Rlerror frame.
    fn rlerror_code(frame: &[u8]) -> u32 {
        u32::from_le_bytes([frame[7], frame[8], frame[9], frame[10]])
    }

    // ---- version negotiation (IO-16) -------------------------------------

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
        let tree = FsTree::try_new(Node::Directory { children })
            .expect("test 9p tree components are valid");
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

    #[test]
    fn snapshot_restore_round_trips_fid_table_and_msize() {
        let mut dev = device();
        round_trip(&mut dev, 0, &tversion(1, 4096, codec::PROTOCOL_VERSION));
        round_trip(&mut dev, 1, &tattach(2, 1));
        round_trip(&mut dev, 2, &twalk(3, 1, 2, &["bin"]));
        let snap = dev.snapshot();
        assert_eq!(snap.server.msize, 4096);
        // The fid table holds both fid 1 (root) and fid 2 (bin).
        let fids: Vec<u32> = snap.fids().iter().map(|(f, _)| *f).collect();
        assert_eq!(fids, vec![1, 2]);

        // Restore over a freshly built (content-identical) tree.
        let restored = ok(NinepDevice::restore(&snap, sample_tree()));
        assert_eq!(restored.server().msize(), 4096);
        assert_eq!(restored.server().fids(), dev.server().fids());

        // The restored device answers a getattr on the restored fid identically.
        let mut a = dev;
        let mut b = restored;
        let (_, ra) = round_trip(&mut a, 10, &tgetattr(50, 2, 0x7ff));
        let (_, rb) = round_trip(&mut b, 10, &tgetattr(50, 2, 0x7ff));
        assert_eq!(ra, rb, "restored fid table must answer identically");
    }

    #[test]
    fn snapshot_preserves_inflight_responses() {
        let mut dev = device();
        // Submit without advancing: the reply stays in flight.
        ok(dev.submit(0, &tversion(1, 4096, codec::PROTOCOL_VERSION)));
        assert_eq!(dev.core().inflight_len(), 1);
        let snap = dev.snapshot();
        assert_eq!(snap.inflight().len(), 1);
        let restored = ok(NinepDevice::restore(&snap, sample_tree()));
        assert_eq!(restored.core().inflight_len(), 1);
        assert_eq!(
            restored.core().next_exact_local_event(),
            dev.core().next_exact_local_event()
        );
    }

    // ---- completion model + determinism (IO-22, IO-28) -------------------

    /// Drives a fixed request sequence and returns (delivery_icount, reply) of
    /// every response. `skew` is artificial host work that must NOT affect output.
    fn run_sequence(skew: usize) -> Vec<(u64, Vec<u8>)> {
        let mut dev = device();
        let reqs = vec![
            tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
            tattach(2, 1),
            twalk(3, 1, 2, &["bin", "tool"]),
            tlopen(4, 2, 0),
            tread(5, 2, 0, 64),
            tgetattr(6, 2, 0x7ff),
            tclunk(7, 2),
        ];
        let mut out = Vec::new();
        let mut t = 0u64;
        for req in &reqs {
            let mut sink = 0u64;
            for i in 0..skew {
                sink = sink.wrapping_add(i as u64);
            }
            std::hint::black_box(sink);

            ok(dev.submit(t, req));
            let lim = dev.core().next_exact_local_event().unwrap_or(t);
            ok(dev.advance_to(lim));
            while let Some(pending) = dev.core_mut().pop_response() {
                out.push((pending.delivery_icount(), pending.response.payload));
            }
            t = lim;
        }
        out
    }

    #[test]
    fn completion_is_host_timing_independent() {
        let a = run_sequence(0);
        let b = run_sequence(500_000);
        assert_eq!(a, b, "host COMPUTE skew leaked into delivery/payload");
    }

    #[test]
    fn run_twice_is_byte_identical() {
        let first = run_sequence(0);
        let second = run_sequence(0);
        assert_eq!(first, second);
    }

    #[test]
    fn latency_depends_only_on_message_kind_and_size() {
        let lat = NinepLatency::new(800, 1200, 2);
        let read = tread(1, 1, 0, 64);
        let clunk = tclunk(1, 1);
        // A read uses the data floor; a clunk uses the control floor.
        assert_eq!(lat.latency_for(&read), 1200 + 2 * read.len() as u64);
        assert_eq!(lat.latency_for(&clunk), 800 + 2 * clunk.len() as u64);
        // A garbage frame falls back to the control floor.
        assert_eq!(lat.latency_for(&[0xFF]), 800 + 2);
    }

    // ---- arbitrary-bytes decoder never panics (IO-18) --------------------

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        // A deterministic LCG fuzz over Message::decode and the server handler:
        // arbitrary bytes in, never a panic / OOB read, always Ok or a codec
        // error, and the SERVER always produces a well-formed reply frame.
        let mut state: u64 = 0x0bad_f00d_dead_beef;
        let mut dev = device();
        round_trip(
            &mut dev,
            0,
            &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
        );
        let mut t = 1u64;
        for _ in 0..50_000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let len = (state >> 56) as usize % 48;
            let mut bytes = Vec::with_capacity(len);
            let mut s = state;
            for _ in 0..len {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                bytes.push((s >> 33) as u8);
            }
            // The decoder never panics.
            let _ = Message::decode(&bytes);
            // The server never panics and always yields a valid 9p reply frame
            // (size prefix matches length) — even for hostile bytes.
            if let Ok(reply) = dev.server().clone().handle(&bytes) {
                assert!(reply.len() >= codec::HEADER_LEN);
                let size = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]) as usize;
                assert_eq!(size, reply.len(), "reply size prefix must match length");
            }
            // Also exercise the real submit path occasionally (bounded frames).
            if len >= codec::HEADER_LEN && bytes.len() <= dev.server().msize() as usize {
                // Fix the size prefix so the frame is structurally plausible.
                let size = bytes.len() as u32;
                bytes[0..4].copy_from_slice(&size.to_le_bytes());
                if dev.submit(t, &bytes).is_ok() {
                    let lim = dev.core().next_exact_local_event().unwrap_or(t);
                    let _ = dev.advance_to(lim);
                    while dev.core_mut().pop_response().is_some() {}
                    t = lim;
                }
            }
        }
    }

    #[test]
    fn structured_fuzz_reaches_deep_decode_paths_without_panic() {
        // The shallow random-bytes fuzz above almost always bails at the
        // size-prefix check, so the doc-advertised adversarial shapes (huge
        // string/name lengths, nwname=0xFFFF, count=u32::MAX, valid bodies of
        // every type) are never reached. This fuzzer emits WELL-FRAMED messages
        // (correct size prefix) with a chosen type byte and adversarial field
        // values, so the body decoders and the server handlers are exercised on
        // hostile-but-plausible input. The invariant is the same: never panic,
        // and the server always yields a well-formed reply whose size prefix
        // matches its length and whose length is within msize.
        let mut state: u64 = 0xfeed_face_c0ff_ee00;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        // The full set of 9p type bytes the dispatcher recognizes, plus a couple
        // of unknowns, so every match arm is reachable.
        let types: [u8; 18] = [
            codec::TVERSION,
            codec::TATTACH,
            codec::TWALK,
            codec::TLOPEN,
            codec::TREAD,
            codec::TREADDIR,
            codec::TGETATTR,
            codec::TREADLINK,
            codec::TSTATFS,
            codec::TCLUNK,
            codec::TFLUSH,
            codec::TXATTRWALK,
            codec::TFSYNC,
            codec::TWRITE, // mutating
            codec::TMKDIR, // mutating
            200,           // unknown
            7,             // Rlerror-as-request (unknown direction)
            0,             // type 0
        ];

        let mut dev = device();
        round_trip(
            &mut dev,
            0,
            &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
        );
        round_trip(&mut dev, 1, &tattach(2, 1));
        let msize = dev.server().msize() as usize;
        let mut t = 2u64;

        for _ in 0..40_000 {
            let r = next();
            let msg_type = types[(r >> 3) as usize % types.len()];
            let tag = (r >> 11) as u16;

            // Build an adversarial body: a mix of valid-shaped fields with
            // extreme values (max counts, oversized declared string lengths).
            let mut body: Vec<u8> = Vec::new();
            // fid / newfid words drawn from a tiny set incl. the live fids 1/2.
            let fid = [0u32, 1, 2, u32::MAX][(r >> 17) as usize % 4];
            body.extend_from_slice(&fid.to_le_bytes());

            match (r >> 19) % 6 {
                0 => {
                    // A second fid + an oversized declared string length.
                    body.extend_from_slice(&2u32.to_le_bytes());
                    body.extend_from_slice(&u16::MAX.to_le_bytes()); // declared len
                    body.extend_from_slice(b"short"); // far fewer bytes than declared
                }
                1 => {
                    // offset + count=u32::MAX (Tread/Treaddir shape).
                    body.extend_from_slice(&(r).to_le_bytes()); // offset (8)
                    body.extend_from_slice(&u32::MAX.to_le_bytes()); // count
                }
                2 => {
                    // Twalk with nwname=0xFFFF but only a couple of names present.
                    body.extend_from_slice(&3u32.to_le_bytes()); // newfid
                    body.extend_from_slice(&u16::MAX.to_le_bytes()); // nwname
                    body.extend_from_slice(&string_bytes("a"));
                    body.extend_from_slice(&string_bytes("b"));
                }
                3 => {
                    // request_mask / flags (8 bytes of entropy).
                    body.extend_from_slice(&r.to_le_bytes());
                }
                4 => {
                    // A long, valid-length name (exercises near-namelen entries).
                    let name = "z".repeat((r as usize) % 300);
                    body.extend_from_slice(&3u32.to_le_bytes());
                    body.extend_from_slice(&1u16.to_le_bytes()); // nwname = 1
                    body.extend_from_slice(&string_bytes(&name));
                }
                _ => {
                    // A grab-bag of random trailing bytes.
                    let n = (r as usize) % 64;
                    let mut s = r;
                    for _ in 0..n {
                        s = s.wrapping_mul(2862933555777941757).wrapping_add(1);
                        body.push((s >> 40) as u8);
                    }
                }
            }

            let f = frame(msg_type, tag, &body);
            // The decoder never panics on this well-framed-but-hostile input.
            let _ = Message::decode(&f);
            // The server never panics and always yields a valid, within-msize
            // reply frame whose size prefix matches its length.
            let reply = dev
                .server()
                .clone()
                .handle(&f)
                .unwrap_or_else(|e| panic!("handle returned Err on structured input: {e}"));
            assert!(reply.len() >= codec::HEADER_LEN);
            let size = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]) as usize;
            assert_eq!(size, reply.len(), "reply size prefix must match length");
            assert!(
                reply.len() <= msize,
                "reply exceeded msize: type {msg_type} -> {} bytes",
                reply.len()
            );

            // Drive the real lifecycle for in-msize frames.
            if f.len() <= msize && dev.submit(t, &f).is_ok() {
                let lim = dev.core().next_exact_local_event().unwrap_or(t);
                let _ = dev.advance_to(lim);
                while dev.core_mut().pop_response().is_some() {}
                t = lim;
            }
        }
    }

    // ---- signal-driven exact request directives -------------------------

    fn file_object(path: &str, version: u32, data: &[u8]) -> NinepObjectVersion {
        NinepObjectVersion {
            path: path.to_owned(),
            version,
            mode: 0o100_644,
            data: data.to_vec(),
            deleted: false,
        }
    }

    fn install_result(dev: &mut NinepDevice, t: u64, request: &[u8], result: NinepResultDirective) {
        let sequence = u32::from(u16::from_le_bytes([request[5], request[6]]));
        let mut directive = ResolvedNinepRequestDirective::fault_free(t, sequence, request)
            .unwrap_or_else(|error| panic!("valid directive: {error}"));
        directive.result = result;
        ok(dev.install_fault_directive(t, sequence, request, directive));
    }

    #[test]
    fn required_directive_is_fail_closed_and_preserves_server_state() {
        let mut dev = device();
        dev.require_fault_directives();
        let request = tattach(2, 1);
        let error = dev
            .submit(0, &request)
            .expect_err("missing exact directive must fail");
        assert!(matches!(
            error,
            crate::DeviceError::MissingNinepFaultDirective { tag: 2 }
        ));
        assert!(dev.server().fids().is_empty());
    }

    #[test]
    fn errno_directive_returns_rlerror_without_attach_side_effects() {
        let mut dev = device();
        dev.require_fault_directives();
        let request = tattach(2, 1);
        install_result(
            &mut dev,
            0,
            &request,
            NinepResultDirective::Errno(errno::EIO),
        );
        let (_, reply) = round_trip(&mut dev, 0, &request);
        assert_eq!(reply_type(&reply), codec::RLERROR);
        assert_eq!(rlerror_code(&reply), errno::EIO);
        assert!(dev.server().fids().is_empty());
        assert!(dev.snapshot().directives.is_empty());
    }

    #[test]
    fn stale_read_uses_exact_object_bytes_and_survives_restore_before_consumption() {
        let mut dev = device();
        dev.require_fault_directives();
        let request = tread(9, 55, 1, 3);
        install_result(
            &mut dev,
            7,
            &request,
            NinepResultDirective::Stale(file_object("/captured", 4, b"ABCDE")),
        );
        let snapshot = dev.snapshot();
        let mut restored = ok(NinepDevice::restore(&snapshot, sample_tree()));
        let (_, reply) = round_trip(&mut restored, 7, &request);
        assert_eq!(reply_type(&reply), codec::RREAD);
        assert_eq!(&reply[11..], b"BCD");
        assert!(restored.snapshot().directives.is_empty());
    }

    fn atomic_visibility(retain_deleted_objects: bool) -> NinepVisibilityPolicy {
        NinepVisibilityPolicy {
            scope: NinepVisibilityScope::Global,
            atomic_metadata_and_data: true,
            retain_deleted_objects,
        }
    }

    #[test]
    fn visible_deletion_hides_base_tree_and_already_walked_fids() {
        let mut dev = device();
        round_trip(
            &mut dev,
            0,
            &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
        );
        round_trip(&mut dev, 1, &tattach(2, 1));
        round_trip(&mut dev, 2, &twalk(3, 1, 2, &["alpha"]));
        let deletion = NinepObjectVersion {
            path: String::from("/alpha"),
            version: 2,
            mode: 0,
            data: Vec::new(),
            deleted: true,
        };
        ok(dev.commit_visibility_update(
            [7; 32],
            deletion,
            atomic_visibility(true),
            NinepVisibilityRelease::AtNanos(0),
            0,
        ));
        ok(dev.advance_visibility(0, &BTreeMap::new()));

        let (_, existing) = round_trip(&mut dev, 3, &tread(4, 2, 0, 8));
        assert_eq!(reply_type(&existing), codec::RLERROR);
        assert_eq!(rlerror_code(&existing), errno::ENOENT);
        let (_, new_walk) = round_trip(&mut dev, 4, &twalk(5, 1, 3, &["alpha"]));
        assert_eq!(reply_type(&new_walk), codec::RLERROR);
        assert_eq!(rlerror_code(&new_walk), errno::ENOENT);
    }

    #[test]
    fn visible_creation_is_discoverable_by_normal_walk_and_tracks_updates() {
        let mut dev = device();
        round_trip(
            &mut dev,
            0,
            &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
        );
        round_trip(&mut dev, 1, &tattach(2, 1));
        ok(dev.commit_visibility_update(
            [1; 32],
            file_object("/new", 1, b"first"),
            atomic_visibility(false),
            NinepVisibilityRelease::AtNanos(0),
            0,
        ));
        ok(dev.advance_visibility(0, &BTreeMap::new()));
        let (_, walked) = round_trip(&mut dev, 2, &twalk(3, 1, 2, &["new"]));
        assert_eq!(reply_type(&walked), codec::RWALK);
        let (_, first) = round_trip(&mut dev, 3, &tread(4, 2, 0, 16));
        assert_eq!(&first[11..], b"first");

        ok(dev.commit_visibility_update(
            [2; 32],
            file_object("/new", 2, b"second"),
            atomic_visibility(false),
            NinepVisibilityRelease::AtNanos(0),
            0,
        ));
        ok(dev.advance_visibility(0, &BTreeMap::new()));
        let (_, second) = round_trip(&mut dev, 4, &tread(5, 2, 0, 16));
        assert_eq!(&second[11..], b"second");
    }

    #[test]
    fn visible_walk_never_traverses_through_a_regular_object() {
        let mut dev = device();
        round_trip(
            &mut dev,
            0,
            &tversion(1, MAX_MSIZE, codec::PROTOCOL_VERSION),
        );
        round_trip(&mut dev, 1, &tattach(2, 1));
        for (identity, object) in [
            ([3; 32], file_object("/a", 1, b"regular")),
            ([4; 32], file_object("/a/b", 1, b"unreachable")),
        ] {
            ok(dev.commit_visibility_update(
                identity,
                object,
                atomic_visibility(false),
                NinepVisibilityRelease::AtNanos(0),
                0,
            ));
        }
        ok(dev.advance_visibility(0, &BTreeMap::new()));
        let (_, walked) = round_trip(&mut dev, 2, &twalk(3, 1, 2, &["a", "b"]));
        assert_eq!(reply_type(&walked), codec::RWALK);
        assert_eq!(u16::from_le_bytes([walked[7], walked[8]]), 1);
    }

    #[test]
    fn unsupported_object_result_shapes_are_rejected_before_installation() {
        let mut dev = device();
        for request in [tstatfs(8, 1), twalk(9, 1, 2, &["bin", "tool"])] {
            let sequence = u32::from(u16::from_le_bytes([request[5], request[6]]));
            let mut directive = ResolvedNinepRequestDirective::fault_free(4, sequence, &request)
                .unwrap_or_else(|error| panic!("valid request identity: {error}"));
            directive.result = NinepResultDirective::Stale(file_object("/x", 1, b"x"));
            assert!(
                dev.install_fault_directive(4, sequence, &request, directive)
                    .is_err()
            );
        }
    }
}
