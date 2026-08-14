//! 9p server limits, fid state, snapshots, and server storage.

use super::*;

/// The server's fixed maximum message size in bytes ([IO-16]).
///
/// Negotiation pins the effective `msize` to `min(client_msize, MAX_MSIZE)`. The
/// value matches the shmem frame data budget so a reply always fits one frame.
pub const MAX_MSIZE: u32 = crucible_shmem::MAX_FRAME_DATA as u32;

/// The encoded size in bytes of the largest single `Rreaddir` directory entry.
///
/// A `readdir` entry is `qid[13] offset[8] type[1] name[s]`, and a name is at
/// most [`STATFS_NAMELEN`] bytes (the advertised `namelen`). A `readdir` chunk
/// MUST be able to carry at least one whole entry of any legal name, so the
/// negotiated `msize` floor is derived from this ([IO-18]).
pub const MAX_DIRENT_LEN: usize = QID_LEN + 8 + 1 + 2 + STATFS_NAMELEN as usize;

/// The encoded size in bytes of an `Rwalk` carrying the maximum 16 QIDs.
///
/// `Rwalk` is `header[7] nwqid[2] nwqid*qid[13]`; with the 9p `MAX_WALK_NAMES`
/// cap of 16 this is the largest fixed-shape traverse reply.
pub(super) const MAX_RWALK_LEN: usize = HEADER_LEN + 2 + codec::MAX_WALK_NAMES * QID_LEN;

/// The encoded size in bytes of an `Rgetattr` reply (a fixed-shape body).
///
/// `header[7] valid[8] qid[13]` + 7 fixed `u64`/`u32` attribute words + 9 fixed
/// timestamp `u64`s. Computed here so the `msize` floor provably accommodates it.
const RGETATTR_LEN: usize = HEADER_LEN + 8 + QID_LEN + (4 * 3 + 8 * 4) + 9 * 8;

/// The minimum `msize` the server will negotiate ([IO-16], [IO-18]).
///
/// Derived as the largest single reply the server can emit — the maximum
/// `Rreaddir` entry, the 16-QID `Rwalk`, and the fixed `Rgetattr` — plus the
/// `Rreaddir` `header[7] count[4]` prefix. Pinning the floor here guarantees
/// every fixed-shape reply and at least one whole directory entry of any legal
/// name fit the negotiated `msize`, so a reply is never silently truncated and
/// `readdir` always makes progress ([IO-18]). A working 9p client proposes far
/// more; this only guards a degenerate request.
pub const MIN_MSIZE: u32 = {
    let readdir_floor = HEADER_LEN + 4 + MAX_DIRENT_LEN;
    let a = if readdir_floor > MAX_RWALK_LEN {
        readdir_floor
    } else {
        MAX_RWALK_LEN
    };
    let floor = if a > RGETATTR_LEN { a } else { RGETATTR_LEN };
    floor as u32
};

/// Compile-time proof that the floor accommodates every fixed-shape reply.
const _: () = {
    assert!(MIN_MSIZE as usize >= RGETATTR_LEN);
    assert!(MIN_MSIZE as usize >= MAX_RWALK_LEN);
    assert!(MIN_MSIZE as usize >= HEADER_LEN + 4 + MAX_DIRENT_LEN);
    assert!(MIN_MSIZE <= MAX_MSIZE);
};

/// The iounit reported in `Rlopen`: zero means "no fixed I/O unit" ([IO-16]).
const IOUNIT_ANY: u32 = 0;

/// The open state of a fid: closed (walk target) or opened for reading.
///
/// A read-only export only ever opens for reading; the cached, sorted directory
/// enumeration of an opened directory is *not* stored here — it is recomputed
/// deterministically from the tree on each `readdir`, so it survives
/// snapshot/restore for free ([IO-19]).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum FidState {
    /// The fid is bound to a path but not yet opened.
    Clunked,
    /// The fid has been opened for reading.
    Open,
}

/// A live fid binding: the canonical path it names and its open state.
///
/// The `path` is the component vector within the served tree (empty = root). The
/// binding is the unit captured and restored by the snapshot ([IO-19]).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FidEntry {
    /// The canonical path within the served tree this fid names.
    pub path: Vec<String>,
    /// Whether the fid has been opened for reading.
    pub state: FidState,
}

/// A captured, restorable snapshot of a [`NinepServer`]'s deterministic state.
///
/// Holds the negotiated `msize`, whether version negotiation has completed, and
/// the **fid table** as a sorted `(fid, FidEntry)` vector ([IO-19]). The served
/// tree and any open directory caches are *not* carried: the tree is the shared,
/// content-addressed `World` and the caches are pure functions of it, so restore
/// reconstructs them exactly from the supplied tree.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NinepServerSnapshot {
    /// The negotiated maximum message size.
    pub msize: u32,
    /// Whether a `Tversion` has pinned the protocol version and `msize`.
    pub negotiated: bool,
    /// The fid table, as `(fid, entry)` pairs in ascending fid order.
    pub fids: Vec<(u32, FidEntry)>,
}

/// The deterministic 9P2000.L protocol engine over a read-only tree.
///
/// Composes the served [`FsTree`] with the negotiated `msize` and the fid table.
/// Drive it with [`NinepServer::handle`], which decodes a request frame and
/// returns the encoded reply frame; the engine never panics on hostile input and
/// never reads host state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NinepServer {
    pub(super) tree: FsTree,
    pub(super) msize: u32,
    pub(super) negotiated: bool,
    /// The fid table: a [`BTreeMap`] so iteration is fixed and host-independent.
    pub(super) fids: BTreeMap<u32, FidEntry>,
}
