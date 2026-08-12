//! The 9P2000.L request dispatcher: fid state, the read-only boundary, errnos.
//!
//! This module owns [`NinepServer`], the deterministic protocol engine that maps
//! a decoded [`Message`] to a reply frame. It holds the negotiated `msize`, the
//! [`FsTree`] being served, and the **fid table** — a [`BTreeMap`] from fid to
//! the canonical path (and open state) it names ([IO-19]). The dispatcher:
//!
//! - negotiates a **fixed protocol version** and a **deterministic `msize`** (the
//!   minimum of the client's request and the server's fixed maximum, [IO-16]);
//! - serves the read/traverse subset (attach, walk, lopen, read, readdir,
//!   getattr, readlink, statfs, clunk, flush, xattrwalk, fsync) ([IO-17]);
//! - answers **every mutating message** with `EROFS`, unknown types with
//!   `ENOSYS`, and malformed input with `EINVAL`/`EIO` ([IO-17]);
//! - **enforces `msize`**: a request frame larger than the negotiated `msize` is
//!   rejected, and a reply that would exceed `msize` is turned into an error
//!   rather than emitted ([IO-18]);
//! - is **snapshot/restore-able**: [`NinepServer::snapshot`] captures the fid
//!   table and `msize`; open directory caches are reconstructed from the tree on
//!   restore because their content is a pure function of the tree ([IO-19]).
//!
//! The fid table iteration order is fixed (a [`BTreeMap`]), so no host hashing
//! ever influences a reply ([IO-24]).

use std::collections::BTreeMap;

use super::codec::{self, HEADER_LEN, Message, NinepCodecError, QID_LEN, Qid, TMessage};
use super::errno;
use super::tree::{FsTree, STATFS_NAMELEN};

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
const MAX_RWALK_LEN: usize = HEADER_LEN + 2 + codec::MAX_WALK_NAMES * QID_LEN;

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
    tree: FsTree,
    msize: u32,
    negotiated: bool,
    /// The fid table: a [`BTreeMap`] so iteration is fixed and host-independent.
    fids: BTreeMap<u32, FidEntry>,
}

impl NinepServer {
    /// Builds a server over `tree` with `msize` un-negotiated (the fixed max).
    ///
    /// The effective `msize` is pinned by the first `Tversion` ([IO-16]); before
    /// that the server reports [`MAX_MSIZE`].
    #[must_use]
    pub fn new(tree: FsTree) -> Self {
        Self {
            tree,
            msize: MAX_MSIZE,
            negotiated: false,
            fids: BTreeMap::new(),
        }
    }

    /// Returns the currently negotiated maximum message size.
    #[must_use]
    pub fn msize(&self) -> u32 {
        self.msize
    }

    /// Returns whether version negotiation has completed.
    #[must_use]
    pub fn negotiated(&self) -> bool {
        self.negotiated
    }

    /// Returns a read-only view of the fid table in ascending fid order.
    #[must_use]
    pub fn fids(&self) -> &BTreeMap<u32, FidEntry> {
        &self.fids
    }

    /// Returns a shared reference to the served tree.
    #[must_use]
    pub fn tree(&self) -> &FsTree {
        &self.tree
    }

    /// Handles one request frame, returning the encoded reply frame.
    ///
    /// Decodes `request_bytes`, enforces the negotiated `msize`, dispatches the
    /// typed message, and encodes the reply. A malformed frame, a mutating
    /// message, an unknown type, an over-`msize` frame, or a fid error all yield
    /// a well-formed `Rlerror` reply rather than a panic ([IO-17], [IO-18]).
    ///
    /// The returned bytes are always a valid 9p frame; the only `Err` path is a
    /// pathological *reply* that cannot be encoded (frame-size overflow), which
    /// indicates an internal bug, not external input.
    ///
    /// # Errors
    ///
    /// Returns [`NinepCodecError`] only when encoding the reply frame itself
    /// fails (frame-size overflow). All request-side malformations are answered
    /// in band with an `Rlerror`, never returned as an `Err`.
    pub fn handle(&mut self, request_bytes: &[u8]) -> Result<Vec<u8>, NinepCodecError> {
        // Enforce msize on the inbound frame ([IO-18]): a frame larger than the
        // negotiated maximum is rejected before any parsing. The tag is unknown
        // for an over-large frame, so the error carries the NOTAG sentinel.
        if request_bytes.len() > self.msize as usize {
            return codec::encode_rlerror(NOTAG, errno::EMSGSIZE);
        }

        let message = match Message::decode(request_bytes) {
            Ok(message) => message,
            Err(_) => {
                // Malformed body -> EINVAL ([IO-17]). The tag may be unparsable,
                // so recover it from the header if present, else use NOTAG.
                let tag = request_bytes
                    .get(5..7)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .unwrap_or(NOTAG);
                return codec::encode_rlerror(tag, errno::EINVAL);
            }
        };

        let tag = message.tag;
        let reply = match message.body {
            TMessage::Version { msize, version } => self.handle_version(tag, msize, &version),
            TMessage::Attach { fid } => self.handle_attach(tag, fid),
            TMessage::Walk {
                fid,
                newfid,
                wnames,
            } => self.handle_walk(tag, fid, newfid, &wnames),
            TMessage::Lopen { fid, flags } => self.handle_lopen(tag, fid, flags),
            TMessage::Read { fid, offset, count } => self.handle_read(tag, fid, offset, count),
            TMessage::Readdir { fid, offset, count } => {
                self.handle_readdir(tag, fid, offset, count)
            }
            TMessage::Getattr { fid, request_mask } => self.handle_getattr(tag, fid, request_mask),
            TMessage::Readlink { fid } => self.handle_readlink(tag, fid),
            TMessage::Statfs { fid } => self.handle_statfs(tag, fid),
            TMessage::Clunk { fid } => self.handle_clunk(tag, fid),
            TMessage::Flush { .. } => codec::encode_rflush(tag),
            TMessage::Xattrwalk { fid, newfid } => self.handle_xattrwalk(tag, fid, newfid),
            TMessage::Fsync { fid } => self.handle_fsync(tag, fid),
            // The read-only boundary: every mutating message is EROFS ([IO-17]).
            TMessage::Mutating { .. } => codec::encode_rlerror(tag, errno::EROFS),
            // An unimplemented message type is ENOSYS ([IO-17]).
            TMessage::Unknown { .. } => codec::encode_rlerror(tag, errno::ENOSYS),
        }?;

        // Universal outbound msize cap ([IO-18]): no reply may exceed the
        // negotiated msize. The per-handler budgets (read/readdir) keep their
        // replies within it, and MIN_MSIZE is the floor that fits every
        // fixed-shape reply; this is the backstop that turns any reply that
        // would still overflow into an Rlerror(EMSGSIZE) rather than emitting an
        // un-representable frame. An Rlerror is HEADER+4 bytes, always <= msize.
        if reply.len() > self.msize as usize {
            return codec::encode_rlerror(tag, errno::EMSGSIZE);
        }
        Ok(reply)
    }

    /// Negotiates the protocol version and `msize` ([IO-16]).
    ///
    /// On **accept** (the client proposed [`codec::PROTOCOL_VERSION`]) this pins
    /// the `msize` to `client.clamp(MIN_MSIZE, MAX_MSIZE)`, marks the session
    /// negotiated, and resets the fid table — a `Tversion` re-initializes the
    /// session per the 9p convention. On **reject** (any other version string)
    /// the server leaves its `msize` and fid table untouched, marks the session
    /// not-negotiated, and replies with the conventional `"unknown"` version and
    /// an advisory negotiated `msize`, so a rejected negotiation does not perturb
    /// an already-established session.
    fn handle_version(
        &mut self,
        tag: u16,
        client_msize: u32,
        client_version: &str,
    ) -> Result<Vec<u8>, NinepCodecError> {
        // The advisory msize is the deterministic minimum, clamped to the floor.
        // MIN_MSIZE < MAX_MSIZE always holds, so clamp cannot panic.
        let negotiated = client_msize.clamp(MIN_MSIZE, MAX_MSIZE);

        // Pin the version. A client requesting the exact 9P2000.L version is
        // accepted; anything else is answered with the fixed "unknown" per the 9p
        // convention WITHOUT mutating the live session state.
        if client_version == codec::PROTOCOL_VERSION {
            self.msize = negotiated;
            self.fids.clear();
            self.negotiated = true;
            codec::encode_rversion(tag, negotiated, codec::PROTOCOL_VERSION)
        } else {
            self.negotiated = false;
            codec::encode_rversion(tag, negotiated, "unknown")
        }
    }

    /// Attaches `fid` to the served tree root ([IO-17]).
    fn handle_attach(&mut self, tag: u16, fid: u32) -> Result<Vec<u8>, NinepCodecError> {
        let qid = Qid::new(self.tree.root().qid_type(), super::tree::qid_path(&[]));
        self.fids.insert(
            fid,
            FidEntry {
                path: Vec::new(),
                state: FidState::Clunked,
            },
        );
        codec::encode_rattach(tag, &qid)
    }

    /// Walks `wnames` from `fid`, binding the result to `newfid` ([IO-17]).
    ///
    /// A zero-length walk clones the fid (the 9p `Twalk` convention). A walk that
    /// cannot resolve a component returns `ENOENT`; a partial walk is reported as
    /// the standard 9p short-`Rwalk` only when at least one component resolved,
    /// otherwise `ENOENT`.
    fn handle_walk(
        &mut self,
        tag: u16,
        fid: u32,
        newfid: u32,
        wnames: &[String],
    ) -> Result<Vec<u8>, NinepCodecError> {
        let base = match self.fids.get(&fid) {
            Some(entry) => entry.path.clone(),
            None => return codec::encode_rlerror(tag, errno::EBADF),
        };

        let mut path = base;
        let mut qids = Vec::with_capacity(wnames.len());
        for name in wnames {
            // ".." climbs toward the root; "." stays put. Neither escapes the
            // served tree (a ".." at the root is a no-op), so the export boundary
            // holds.
            if name == ".." {
                path.pop();
            } else if name != "." {
                // Reject an illegal walk component from the wire ([IO-13]): an
                // empty, '/'-bearing, or NUL-bearing name would alias another
                // node's QID. EINVAL is the 9p errno for a malformed name.
                if super::tree::validate_component(name).is_err() {
                    return codec::encode_rlerror(tag, errno::EINVAL);
                }
                path.push(name.clone());
            }
            match self.tree.qid(&path) {
                Some(qid) => qids.push(qid),
                None => {
                    if qids.is_empty() {
                        // Nothing resolved: the first component is absent.
                        return codec::encode_rlerror(tag, errno::ENOENT);
                    }
                    // A short walk: bind nothing, report the prefix that resolved.
                    return codec::encode_rwalk(tag, &qids);
                }
            }
        }

        // Full walk succeeded: bind newfid to the resolved path.
        self.fids.insert(
            newfid,
            FidEntry {
                path,
                state: FidState::Clunked,
            },
        );
        codec::encode_rwalk(tag, &qids)
    }

    /// Opens `fid` for reading ([IO-17]).
    ///
    /// The flags are accepted but a read-only server never honors write intent;
    /// the open simply marks the fid [`FidState::Open`] so subsequent reads and
    /// readdirs are permitted.
    fn handle_lopen(
        &mut self,
        tag: u16,
        fid: u32,
        _flags: u32,
    ) -> Result<Vec<u8>, NinepCodecError> {
        let entry = match self.fids.get_mut(&fid) {
            Some(entry) => entry,
            None => return codec::encode_rlerror(tag, errno::EBADF),
        };
        let qid = match self.tree.qid(&entry.path) {
            Some(qid) => qid,
            None => return codec::encode_rlerror(tag, errno::ENOENT),
        };
        entry.state = FidState::Open;
        codec::encode_rlopen(tag, &qid, IOUNIT_ANY)
    }

    /// Reads `count` bytes at `offset` from the file behind `fid` ([IO-17]).
    ///
    /// A read of a directory fid is rejected with `EISDIR` (clients must use
    /// `readdir`); a read past end returns an empty `Rread`. The returned slice
    /// is content-derived, so two runs read byte-identical data.
    fn handle_read(
        &mut self,
        tag: u16,
        fid: u32,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, NinepCodecError> {
        let path = match self.fids.get(&fid) {
            Some(entry) => entry.path.clone(),
            None => return codec::encode_rlerror(tag, errno::EBADF),
        };
        let node = match self.tree.resolve(&path) {
            Some(node) => node,
            None => return codec::encode_rlerror(tag, errno::ENOENT),
        };
        let content: &[u8] = match node {
            super::tree::Node::File { content } => content,
            super::tree::Node::Directory { .. } => {
                return codec::encode_rlerror(tag, errno::EISDIR);
            }
            super::tree::Node::Symlink { .. } => {
                return codec::encode_rlerror(tag, errno::EINVAL);
            }
        };
        let data = slice_at(content, offset, count, self.max_payload());
        codec::encode_rread(tag, data)
    }

    /// Reads packed directory entries at `offset` from `fid` ([IO-14], [IO-17]).
    ///
    /// Entries are the [`FsTree`] children in lexicographic order with offsets
    /// assigned *after* the sort, plus the synthetic `.` and `..` entries first.
    /// The reply packs as many whole entries as fit `min(count, msize-budget)`,
    /// resuming from the cookie `offset`; enumeration is byte-identical across
    /// runs ([IO-14]).
    fn handle_readdir(
        &mut self,
        tag: u16,
        fid: u32,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, NinepCodecError> {
        let path = match self.fids.get(&fid) {
            Some(entry) => entry.path.clone(),
            None => return codec::encode_rlerror(tag, errno::EBADF),
        };
        let children = match self.tree.children(&path) {
            Some(children) => children,
            None => return codec::encode_rlerror(tag, errno::ENOTDIR),
        };

        // Build the full, deterministically ordered entry list once: "." and ".."
        // (offsets 1 and 2), then the sorted children (offsets 3..). Offsets are
        // 1-based cookies assigned strictly after the sort ([IO-14]).
        let self_qid = self.tree.qid(&path).unwrap_or(Qid::new(
            super::codec::QidType::Dir,
            super::tree::qid_path(&path),
        ));
        let mut parent_path = path.clone();
        parent_path.pop();
        let parent_qid = self.tree.qid(&parent_path).unwrap_or(self_qid);

        let mut entries: Vec<(u64, Qid, u8, String)> = Vec::with_capacity(children.len() + 2);
        entries.push((1, self_qid, 4, ".".to_string()));
        entries.push((2, parent_qid, 4, "..".to_string()));
        for (i, child) in children.into_iter().enumerate() {
            // Offset i+3: strictly after "." (1) and ".." (2), in sorted order.
            entries.push((i as u64 + 3, child.qid, child.dtype, child.name));
        }

        // Pack entries whose cookie is strictly greater than the resume offset,
        // up to the smaller of the client count and the msize payload budget.
        let budget = (count as usize).min(self.max_payload());
        let mut data = Vec::new();
        for (cookie, qid, dtype, name) in &entries {
            if *cookie <= offset {
                continue;
            }
            // Measure the entry against the remaining budget without partially
            // emitting it: a directory entry is emitted whole or not at all.
            let mut probe = Vec::new();
            codec::push_dirent(&mut probe, qid, *cookie, *dtype, name)?;
            if data.len() + probe.len() > budget {
                // If not even the FIRST resumable entry fits, the client's count
                // (or msize) is too small to carry this entry: fail loudly with
                // EMSGSIZE rather than returning an empty Rreaddir, which the
                // client would read as end-of-directory — silent truncation that
                // [IO-18] forbids. The MIN_MSIZE floor guarantees any entry of a
                // legal (<= namelen) name fits the negotiated msize, so this can
                // only fire on a too-small client `count`.
                if data.is_empty() {
                    return codec::encode_rlerror(tag, errno::EMSGSIZE);
                }
                break;
            }
            data.extend_from_slice(&probe);
        }
        codec::encode_rreaddir(tag, &data)
    }

    /// Returns the fixed/content-derived attributes for `fid` ([IO-15], [IO-17]).
    fn handle_getattr(
        &mut self,
        tag: u16,
        fid: u32,
        request_mask: u64,
    ) -> Result<Vec<u8>, NinepCodecError> {
        let path = match self.fids.get(&fid) {
            Some(entry) => entry.path.clone(),
            None => return codec::encode_rlerror(tag, errno::EBADF),
        };
        match self.tree.getattr(&path, request_mask) {
            Some(reply) => reply.encode(tag),
            None => codec::encode_rlerror(tag, errno::ENOENT),
        }
    }

    /// Returns the symlink target behind `fid` ([IO-17]).
    fn handle_readlink(&mut self, tag: u16, fid: u32) -> Result<Vec<u8>, NinepCodecError> {
        let path = match self.fids.get(&fid) {
            Some(entry) => entry.path.clone(),
            None => return codec::encode_rlerror(tag, errno::EBADF),
        };
        match self.tree.resolve(&path) {
            Some(super::tree::Node::Symlink { target }) => codec::encode_rreadlink(tag, target),
            Some(_) => codec::encode_rlerror(tag, errno::EINVAL),
            None => codec::encode_rlerror(tag, errno::ENOENT),
        }
    }

    /// Returns the synthetic filesystem statistics for `fid` ([IO-15], [IO-17]).
    fn handle_statfs(&mut self, tag: u16, fid: u32) -> Result<Vec<u8>, NinepCodecError> {
        if !self.fids.contains_key(&fid) {
            return codec::encode_rlerror(tag, errno::EBADF);
        }
        self.tree.statfs().encode(tag)
    }

    /// Releases `fid`, removing its binding ([IO-17], [IO-19]).
    fn handle_clunk(&mut self, tag: u16, fid: u32) -> Result<Vec<u8>, NinepCodecError> {
        if self.fids.remove(&fid).is_none() {
            return codec::encode_rlerror(tag, errno::EBADF);
        }
        codec::encode_rclunk(tag)
    }

    /// Prepares an xattr walk; a read-only export advertises no xattrs ([IO-17]).
    ///
    /// The new fid is bound to the same path and the reported attribute size is
    /// zero, so a client's subsequent xattr read yields nothing — deterministic
    /// and host-independent.
    fn handle_xattrwalk(
        &mut self,
        tag: u16,
        fid: u32,
        newfid: u32,
    ) -> Result<Vec<u8>, NinepCodecError> {
        let base = match self.fids.get(&fid) {
            Some(entry) => entry.path.clone(),
            None => return codec::encode_rlerror(tag, errno::EBADF),
        };
        self.fids.insert(
            newfid,
            FidEntry {
                path: base,
                state: FidState::Open,
            },
        );
        codec::encode_rxattrwalk(tag, 0)
    }

    /// Acknowledges an `fsync` as a no-op success on a read-only export.
    fn handle_fsync(&mut self, tag: u16, fid: u32) -> Result<Vec<u8>, NinepCodecError> {
        if !self.fids.contains_key(&fid) {
            return codec::encode_rlerror(tag, errno::EBADF);
        }
        codec::encode_rfsync(tag)
    }

    /// Returns the maximum reply *payload* bytes that fit the negotiated `msize`.
    ///
    /// A reply frame is the fixed [`HEADER_LEN`] header plus a small per-message
    /// fixed prefix plus the payload; budgeting the payload at `msize - HEADER -
    /// COUNT_PREFIX` keeps every reply within `msize` ([IO-18]).
    fn max_payload(&self) -> usize {
        // Reserve the header and the 4-byte count prefix carried by Rread/Rreaddir.
        (self.msize as usize).saturating_sub(HEADER_LEN + 4)
    }

    /// Captures the fid table and `msize` for snapshot/restore ([IO-19]).
    ///
    /// The fid table is serialized in ascending fid order so the snapshot is
    /// byte-stable; the tree and open caches are omitted (reconstructed from the
    /// tree on restore).
    #[must_use]
    pub fn snapshot(&self) -> NinepServerSnapshot {
        NinepServerSnapshot {
            msize: self.msize,
            negotiated: self.negotiated,
            fids: self
                .fids
                .iter()
                .map(|(&fid, entry)| (fid, entry.clone()))
                .collect(),
        }
    }

    /// Reconstructs a server from a snapshot stacked over the served tree.
    ///
    /// The tree is re-supplied (it is the shared, content-addressed `World`,
    /// never carried in the snapshot, [IO-19]); the fid table and `msize` are
    /// restored verbatim. Open directory caches are *not* restored because they
    /// are pure functions of the tree and are recomputed on each `readdir`, so
    /// the restored server answers byte-identically to an uninterrupted run.
    #[must_use]
    pub fn restore(snapshot: &NinepServerSnapshot, tree: FsTree) -> Self {
        let fids = snapshot
            .fids
            .iter()
            .map(|(fid, entry)| (*fid, entry.clone()))
            .collect();
        Self {
            tree,
            msize: snapshot.msize,
            negotiated: snapshot.negotiated,
            fids,
        }
    }
}

/// The 9p `NOTAG` sentinel used when a request's tag cannot be recovered.
const NOTAG: u16 = u16::MAX;

/// Returns the `count`-byte slice at `offset`, clamped to the content and budget.
///
/// A read past the end yields an empty slice (the 9p end-of-file convention); a
/// `count` larger than the payload budget is clamped, so the reply always fits
/// the negotiated `msize` ([IO-18]). Pure slicing — never reads host state.
fn slice_at(content: &[u8], offset: u64, count: u32, budget: usize) -> &[u8] {
    let start = match usize::try_from(offset) {
        Ok(start) if start <= content.len() => start,
        // An offset past the end (or past `usize`) is end-of-file: empty read.
        _ => return &[],
    };
    let want = (count as usize).min(budget);
    let end = start.saturating_add(want).min(content.len());
    &content[start..end]
}
