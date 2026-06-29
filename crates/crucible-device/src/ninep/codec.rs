//! The 9P2000.L wire codec: message framing, QIDs, and bounds-checked decode.
//!
//! This module owns the on-wire format the 9p sub-node speaks across the
//! `SLOT_9P_IO` shmem rings ([IO-16], [IO-18]). The framing is the Plan 9
//! convention: a fixed `size[4] type[1] tag[2]` header followed by a
//! type-specific body, with **all multi-byte integers little-endian**. Strings
//! are `len[2] data[len]`; a QID is the fixed 13-byte `type[1] version[4]
//! path[8]`. Decoding is fully bounds-checked: an arbitrary byte sequence never
//! panics, never reads out of bounds, and yields a [`NinepCodecError`] when
//! malformed — the fuzz-safe boundary `gate:abi-conformance` consumes.
//!
//! ```text
//! 9p message frame (little-endian)
//!   off 0   u32  size   -- total byte length of the frame, INCLUDING this field
//!   off 4   u8   type   -- message type code (T-message request / R-message reply)
//!   off 5   u16  tag    -- request/response correlation tag
//!   off 7   ...         -- type-specific body
//!
//! string  = len[2] data[len]           -- u16 length, then raw bytes (UTF-8)
//! qid     = type[1] version[4] path[8] -- 13 bytes; path is a stable path-hash
//!
//! Tversion size[4] Tversion tag[2] msize[4] version[s]
//! Rversion size[4] Rversion tag[2] msize[4] version[s]
//! Tattach  size[4] Tattach  tag[2] fid[4] afid[4] uname[s] aname[s] n_uname[4]
//! Rattach  size[4] Rattach  tag[2] qid[13]
//! Twalk    size[4] Twalk    tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
//! Rwalk    size[4] Rwalk    tag[2] nwqid[2] nwqid*(qid[13])
//! Tlopen   size[4] Tlopen   tag[2] fid[4] flags[4]
//! Rlopen   size[4] Rlopen   tag[2] qid[13] iounit[4]
//! Treaddir size[4] Treaddir tag[2] fid[4] offset[8] count[4]
//! Rreaddir size[4] Rreaddir tag[2] count[4] data[count]
//! Tread    size[4] Tread    tag[2] fid[4] offset[8] count[4]
//! Rread    size[4] Rread    tag[2] count[4] data[count]
//! Tgetattr size[4] Tgetattr tag[2] fid[4] request_mask[8]
//! Rgetattr size[4] Rgetattr tag[2] (fixed Linux getattr body; see RGETATTR_BODY)
//! Treadlink size[4] Treadlink tag[2] fid[4]
//! Rreadlink size[4] Rreadlink tag[2] target[s]
//! Tstatfs  size[4] Tstatfs  tag[2] fid[4]
//! Rstatfs  size[4] Rstatfs  tag[2] (fixed statfs body; see RSTATFS_BODY)
//! Tclunk   size[4] Tclunk   tag[2] fid[4]
//! Rclunk   size[4] Rclunk   tag[2]
//! Tflush   size[4] Tflush   tag[2] oldtag[2]
//! Rflush   size[4] Rflush   tag[2]
//! Txattrwalk size[4] Txattrwalk tag[2] fid[4] newfid[4] name[s]
//! Rlerror  size[4] Rlerror  tag[2] ecode[4]   -- Linux errno, the only error reply
//! ```
//!
//! The encoded bytes are carried as the opaque
//! [`crate::request::Request::payload`] / [`crate::request::Response::payload`]
//! and ride the `FrameEntry.data` field of a [`crucible_shmem::SLOT_9P_IO`] ring
//! frame ([`crucible_shmem::MAX_FRAME_DATA`] = 4608 bytes).
//! [`crate::subnode::IoCore`] supplies the shmem lifecycle bridge that drains
//! VM-to-9p frames, computes replies, publishes 9p-to-VM frames, and issues the
//! corresponding wake.

/// The fixed 9p frame header length: `size[4] type[1] tag[2]`.
pub const HEADER_LEN: usize = 7;

/// The encoded length of a 9p QID: `type[1] version[4] path[8]`.
pub const QID_LEN: usize = 13;

/// The fixed protocol version string the server pins ([IO-16]).
pub const PROTOCOL_VERSION: &str = "9P2000.L";

// ---- 9p message type codes (9P2000.L) ----------------------------------------

/// `Tlerror` is unused in 9P2000.L; type 6 is reserved. Kept for completeness.
pub const TLERROR: u8 = 6;
/// `Rlerror`: the Linux error reply carrying a 32-bit errno ([IO-17]).
pub const RLERROR: u8 = 7;
/// `Tstatfs`: query filesystem statistics for a fid.
pub const TSTATFS: u8 = 8;
/// `Rstatfs`: filesystem statistics reply.
pub const RSTATFS: u8 = 9;
/// `Tlopen`: open an existing fid (Linux open).
pub const TLOPEN: u8 = 12;
/// `Rlopen`: open reply carrying the opened QID.
pub const RLOPEN: u8 = 13;
/// `Tlcreate`: create a file (mutating, answered `EROFS`).
pub const TLCREATE: u8 = 14;
/// `Rlcreate`: create reply (never emitted by this read-only server).
pub const RLCREATE: u8 = 15;
/// `Tsymlink`: create a symlink (mutating, answered `EROFS`).
pub const TSYMLINK: u8 = 16;
/// `Rsymlink`: symlink reply (never emitted).
pub const RSYMLINK: u8 = 17;
/// `Tmknod`: create a device node (mutating, answered `EROFS`).
pub const TMKNOD: u8 = 18;
/// `Rmknod`: mknod reply (never emitted).
pub const RMKNOD: u8 = 19;
/// `Trename`: rename (mutating, answered `EROFS`).
pub const TRENAME: u8 = 20;
/// `Rrename`: rename reply (never emitted).
pub const RRENAME: u8 = 21;
/// `Treadlink`: read a symlink target.
pub const TREADLINK: u8 = 22;
/// `Rreadlink`: symlink-target reply.
pub const RREADLINK: u8 = 23;
/// `Tgetattr`: query file attributes.
pub const TGETATTR: u8 = 24;
/// `Rgetattr`: file-attributes reply.
pub const RGETATTR: u8 = 25;
/// `Tsetattr`: change file attributes (mutating, answered `EROFS`).
pub const TSETATTR: u8 = 26;
/// `Rsetattr`: setattr reply (never emitted).
pub const RSETATTR: u8 = 27;
/// `Txattrwalk`: prepare to read an extended attribute.
pub const TXATTRWALK: u8 = 30;
/// `Rxattrwalk`: xattrwalk reply.
pub const RXATTRWALK: u8 = 31;
/// `Txattrcreate`: create an extended attribute (mutating, answered `EROFS`).
pub const TXATTRCREATE: u8 = 32;
/// `Rxattrcreate`: xattrcreate reply (never emitted).
pub const RXATTRCREATE: u8 = 33;
/// `Treaddir`: read directory entries.
pub const TREADDIR: u8 = 40;
/// `Rreaddir`: directory-entries reply.
pub const RREADDIR: u8 = 41;
/// `Tfsync`: flush file buffers (no-op success on a read-only export).
pub const TFSYNC: u8 = 50;
/// `Rfsync`: fsync reply.
pub const RFSYNC: u8 = 51;
/// `Tlock`: POSIX advisory lock (mutating, answered `EROFS`).
pub const TLOCK: u8 = 52;
/// `Rlock`: lock reply (never emitted).
pub const RLOCK: u8 = 53;
/// `Tgetlock`: query a POSIX advisory lock (mutating-class, answered `EROFS`).
pub const TGETLOCK: u8 = 54;
/// `Rgetlock`: getlock reply (never emitted).
pub const RGETLOCK: u8 = 55;
/// `Tlink`: create a hard link (mutating, answered `EROFS`).
pub const TLINK: u8 = 70;
/// `Rlink`: link reply (never emitted).
pub const RLINK: u8 = 71;
/// `Tmkdir`: create a directory (mutating, answered `EROFS`).
pub const TMKDIR: u8 = 72;
/// `Rmkdir`: mkdir reply (never emitted).
pub const RMKDIR: u8 = 73;
/// `Trenameat`: rename within directories (mutating, answered `EROFS`).
pub const TRENAMEAT: u8 = 74;
/// `Rrenameat`: renameat reply (never emitted).
pub const RRENAMEAT: u8 = 75;
/// `Tunlinkat`: unlink within a directory (mutating, answered `EROFS`).
pub const TUNLINKAT: u8 = 76;
/// `Runlinkat`: unlinkat reply (never emitted).
pub const RUNLINKAT: u8 = 77;
/// `Tversion`: protocol/msize negotiation.
pub const TVERSION: u8 = 100;
/// `Rversion`: version-negotiation reply.
pub const RVERSION: u8 = 101;
/// `Tauth`: begin authentication (answered `EROFS`-free `ENOSYS`-class).
pub const TAUTH: u8 = 102;
/// `Rauth`: auth reply (never emitted).
pub const RAUTH: u8 = 103;
/// `Tattach`: attach to the file tree root.
pub const TATTACH: u8 = 104;
/// `Rattach`: attach reply carrying the root QID.
pub const RATTACH: u8 = 105;
/// `Twalk`: walk a path from one fid to another.
pub const TWALK: u8 = 110;
/// `Rwalk`: walk reply carrying the walked QIDs.
pub const RWALK: u8 = 111;
/// `Tflush`: abort an in-flight request (a no-op success on this server).
pub const TFLUSH: u8 = 108;
/// `Rflush`: flush reply.
pub const RFLUSH: u8 = 109;
/// `Tread`: read file bytes.
pub const TREAD: u8 = 116;
/// `Rread`: file-bytes reply.
pub const RREAD: u8 = 117;
/// `Twrite`: write file bytes (mutating, answered `EROFS`).
pub const TWRITE: u8 = 118;
/// `Rwrite`: write reply (never emitted).
pub const RWRITE: u8 = 119;
/// `Tclunk`: release a fid.
pub const TCLUNK: u8 = 120;
/// `Rclunk`: clunk reply.
pub const RCLUNK: u8 = 121;
/// `Tremove`: remove a file (mutating, answered `EROFS`).
pub const TREMOVE: u8 = 122;
/// `Rremove`: remove reply (never emitted).
pub const RREMOVE: u8 = 123;

// ---- QID ---------------------------------------------------------------------

/// The QID type byte: the high-level kind of the file the QID names.
///
/// The numeric values are part of the 9p wire ABI ([IO-13], [IO-18]) and follow
/// the Plan 9 `QTDIR`/`QTSYMLINK`/`QTFILE` convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QidType {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink,
}

impl QidType {
    /// The Plan 9 `QTDIR` bit.
    const QTDIR: u8 = 0x80;
    /// The Plan 9 `QTSYMLINK` bit.
    const QTSYMLINK: u8 = 0x02;
    /// The Plan 9 `QTFILE` value (a plain file has no type bits set).
    const QTFILE: u8 = 0x00;

    /// Returns the wire type byte for this QID kind.
    #[must_use]
    pub fn to_wire(self) -> u8 {
        match self {
            QidType::File => Self::QTFILE,
            QidType::Dir => Self::QTDIR,
            QidType::Symlink => Self::QTSYMLINK,
        }
    }

    /// Decodes a QID kind from its wire byte.
    ///
    /// The directory bit takes precedence over the symlink bit, mirroring how a
    /// Plan 9 client interprets a QID type. Any byte with neither bit set decodes
    /// as [`QidType::File`], so this never fails (it is total over `u8`).
    #[must_use]
    pub fn from_wire(byte: u8) -> Self {
        if byte & Self::QTDIR != 0 {
            QidType::Dir
        } else if byte & Self::QTSYMLINK != 0 {
            QidType::Symlink
        } else {
            QidType::File
        }
    }
}

/// A 9p QID: the server's unique, cacheable identifier for a file.
///
/// The `path` is a **stable hash of the file's path within the served tree**,
/// never a host inode number ([IO-13]); `version` is the fixed
/// [`Qid::FIXED_VERSION`]; `kind` is derived from the file's content. Two runs on
/// two hosts produce byte-identical QIDs for the same served tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Qid {
    /// The high-level file kind.
    pub kind: QidType,
    /// The fixed QID version ([IO-13]); always [`Qid::FIXED_VERSION`] on emit.
    pub version: u32,
    /// The stable path-hash identifying the file ([IO-13]).
    pub path: u64,
}

impl Qid {
    /// The fixed QID version every emitted QID carries ([IO-13]).
    pub const FIXED_VERSION: u32 = 1;

    /// Builds a QID with the fixed version from a kind and a path-hash.
    #[must_use]
    pub fn new(kind: QidType, path: u64) -> Self {
        Self {
            kind,
            version: Self::FIXED_VERSION,
            path,
        }
    }

    /// Appends this QID's 13 wire bytes to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.kind.to_wire());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.path.to_le_bytes());
    }

    /// Decodes a QID from a 13-byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`NinepCodecError::Truncated`] when `bytes` is shorter than
    /// [`QID_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NinepCodecError> {
        let raw = bytes.get(..QID_LEN).ok_or(NinepCodecError::Truncated {
            needed: QID_LEN,
            got: bytes.len(),
        })?;
        // `raw` is exactly QID_LEN bytes, so every fixed offset below is in range.
        let kind = QidType::from_wire(raw[0]);
        let version = u32_le(raw, 1);
        let path = u64_le(raw, 5);
        Ok(Self {
            kind,
            version,
            path,
        })
    }
}

// ---- decoded request bodies --------------------------------------------------

/// A decoded, validated 9p T-message (a request from the client).
///
/// Each variant carries exactly the fields the server reads; the read/traverse
/// subset is modeled explicitly, every *mutating* operation collapses to
/// [`TMessage::Mutating`] (answered `EROFS`, [IO-17]), and any byte that names a
/// type this server does not implement decodes to [`TMessage::Unknown`]
/// (answered `ENOSYS`, [IO-17]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TMessage {
    /// `Tversion`: negotiate the protocol version and `msize`.
    Version {
        /// The client's proposed maximum message size.
        msize: u32,
        /// The client's proposed protocol version string.
        version: String,
    },
    /// `Tattach`: attach `fid` to the served tree root.
    Attach {
        /// The fid to bind to the root.
        fid: u32,
    },
    /// `Twalk`: walk `wnames` from `fid`, binding the result to `newfid`.
    Walk {
        /// The starting fid.
        fid: u32,
        /// The fid to bind the walked location to.
        newfid: u32,
        /// The path components to walk (already length-checked).
        wnames: Vec<String>,
    },
    /// `Tlopen`: open `fid` for reading (`flags` is accepted but not honored).
    Lopen {
        /// The fid to open.
        fid: u32,
        /// The open flags (recorded; a read-only server ignores write intent).
        flags: u32,
    },
    /// `Tread`: read `count` bytes at `offset` from `fid`.
    Read {
        /// The fid to read.
        fid: u32,
        /// The byte offset.
        offset: u64,
        /// The byte count.
        count: u32,
    },
    /// `Treaddir`: read directory entries at `offset` from `fid`.
    Readdir {
        /// The directory fid.
        fid: u32,
        /// The entry offset (a previously returned cookie, or zero).
        offset: u64,
        /// The maximum byte count to return.
        count: u32,
    },
    /// `Tgetattr`: query attributes of `fid`.
    Getattr {
        /// The fid to query.
        fid: u32,
        /// The requested attribute mask (echoed as the valid mask).
        request_mask: u64,
    },
    /// `Treadlink`: read the symlink target of `fid`.
    Readlink {
        /// The symlink fid.
        fid: u32,
    },
    /// `Tstatfs`: query filesystem statistics for `fid`.
    Statfs {
        /// The fid whose filesystem is queried.
        fid: u32,
    },
    /// `Tclunk`: release `fid`.
    Clunk {
        /// The fid to release.
        fid: u32,
    },
    /// `Tflush`: abort the in-flight request tagged `oldtag` (a no-op here).
    Flush {
        /// The tag of the request to abort.
        oldtag: u16,
    },
    /// `Txattrwalk`: prepare to read an extended attribute (always size zero).
    Xattrwalk {
        /// The starting fid.
        fid: u32,
        /// The fid to bind the xattr handle to.
        newfid: u32,
    },
    /// `Tfsync`: flush buffers for `fid` (a no-op success on a read-only export).
    Fsync {
        /// The fid to fsync.
        fid: u32,
    },
    /// A mutating message the read-only server answers with `EROFS` ([IO-17]).
    Mutating {
        /// The mutating message's type byte, for diagnostics.
        msg_type: u8,
    },
    /// A message type this server does not implement, answered `ENOSYS`.
    Unknown {
        /// The unimplemented message's type byte.
        msg_type: u8,
    },
}

/// A decoded 9p message: its tag and its typed body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The request/response correlation tag.
    pub tag: u16,
    /// The typed message body.
    pub body: TMessage,
}

impl Message {
    /// Decodes a complete 9p frame from arbitrary bytes, fully bounds-checked.
    ///
    /// Never panics and never reads out of bounds on hostile input: a truncated
    /// frame, an inconsistent `size` field, a string length that runs past the
    /// buffer, or an `nwname` count that overruns all return a
    /// [`NinepCodecError`] rather than parsing past the buffer ([IO-18]). A
    /// mutating message type decodes to [`TMessage::Mutating`] and an
    /// unimplemented type to [`TMessage::Unknown`] (both are well-formed bodies
    /// the server answers in band), so only structural corruption errors here.
    ///
    /// # Errors
    ///
    /// - [`NinepCodecError::Truncated`] when the buffer is shorter than the
    ///   header, or a body field runs past the available bytes.
    /// - [`NinepCodecError::SizeMismatch`] when the `size[4]` prefix does not
    ///   equal the buffer length.
    /// - [`NinepCodecError::BadString`] when a string's declared length runs past
    ///   the frame.
    /// - [`NinepCodecError::TooManyNames`] when a `Twalk` `nwname` exceeds the 9p
    ///   limit of 16.
    pub fn decode(bytes: &[u8]) -> Result<Self, NinepCodecError> {
        let header = bytes.get(..HEADER_LEN).ok_or(NinepCodecError::Truncated {
            needed: HEADER_LEN,
            got: bytes.len(),
        })?;
        let size = u32_le(header, 0);
        let msg_type = header[4];
        let tag = u16_le(header, 5);

        // The size prefix MUST equal the actual frame length: a frame whose
        // declared size disagrees with its byte count is malformed ([IO-18]).
        if size as usize != bytes.len() {
            return Err(NinepCodecError::SizeMismatch {
                declared: size,
                actual: bytes.len(),
            });
        }

        let mut cursor = Cursor::new(bytes, HEADER_LEN);
        let body = match msg_type {
            TVERSION => {
                let msize = cursor.u32()?;
                let version = cursor.string()?;
                TMessage::Version { msize, version }
            }
            TATTACH => {
                let fid = cursor.u32()?;
                let _afid = cursor.u32()?;
                let _uname = cursor.string()?;
                let _aname = cursor.string()?;
                // n_uname is present in 9P2000.L Tattach; tolerate its absence.
                let _ = cursor.try_u32();
                TMessage::Attach { fid }
            }
            TWALK => {
                let fid = cursor.u32()?;
                let newfid = cursor.u32()?;
                let nwname = cursor.u16()?;
                if nwname as usize > MAX_WALK_NAMES {
                    return Err(NinepCodecError::TooManyNames { nwname });
                }
                let mut wnames = Vec::with_capacity(nwname as usize);
                for _ in 0..nwname {
                    wnames.push(cursor.string()?);
                }
                TMessage::Walk {
                    fid,
                    newfid,
                    wnames,
                }
            }
            TLOPEN => {
                let fid = cursor.u32()?;
                let flags = cursor.u32()?;
                TMessage::Lopen { fid, flags }
            }
            TREAD => {
                let fid = cursor.u32()?;
                let offset = cursor.u64()?;
                let count = cursor.u32()?;
                TMessage::Read { fid, offset, count }
            }
            TREADDIR => {
                let fid = cursor.u32()?;
                let offset = cursor.u64()?;
                let count = cursor.u32()?;
                TMessage::Readdir { fid, offset, count }
            }
            TGETATTR => {
                let fid = cursor.u32()?;
                let request_mask = cursor.u64()?;
                TMessage::Getattr { fid, request_mask }
            }
            TREADLINK => {
                let fid = cursor.u32()?;
                TMessage::Readlink { fid }
            }
            TSTATFS => {
                let fid = cursor.u32()?;
                TMessage::Statfs { fid }
            }
            TCLUNK => {
                let fid = cursor.u32()?;
                TMessage::Clunk { fid }
            }
            TFLUSH => {
                let oldtag = cursor.u16()?;
                TMessage::Flush { oldtag }
            }
            TXATTRWALK => {
                let fid = cursor.u32()?;
                let newfid = cursor.u32()?;
                let _name = cursor.string()?;
                TMessage::Xattrwalk { fid, newfid }
            }
            TFSYNC => {
                let fid = cursor.u32()?;
                TMessage::Fsync { fid }
            }
            // Every mutating operation collapses here; the server answers EROFS.
            TLCREATE | TWRITE | TMKDIR | TUNLINKAT | TRENAMEAT | TRENAME | TSETATTR | TSYMLINK
            | TLINK | TMKNOD | TREMOVE | TXATTRCREATE | TLOCK | TGETLOCK => {
                TMessage::Mutating { msg_type }
            }
            other => TMessage::Unknown { msg_type: other },
        };

        Ok(Self { tag, body })
    }
}

/// The maximum number of path components a single `Twalk` may carry (9p limit).
pub const MAX_WALK_NAMES: usize = 16;

// ---- response encoding -------------------------------------------------------

/// Begins a reply frame: reserves the `size[4] type[1] tag[2]` header.
///
/// The caller appends the body, then [`finish_frame`] back-patches the `size`
/// field with the total length. Returns the buffer with the header in place.
fn begin_frame(msg_type: u8, tag: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
    out.push(msg_type);
    out.extend_from_slice(&tag.to_le_bytes());
    out
}

/// Back-patches a reply frame's `size[4]` prefix with its total length.
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] when the frame length exceeds
/// `u32::MAX` and cannot be represented in the wire `size` field.
fn finish_frame(mut frame: Vec<u8>) -> Result<Vec<u8>, NinepCodecError> {
    let size = u32::try_from(frame.len())
        .map_err(|_| NinepCodecError::FrameTooLarge { len: frame.len() })?;
    frame[0..4].copy_from_slice(&size.to_le_bytes());
    Ok(frame)
}

/// Appends a 9p string (`len[2] data[len]`) to `out`.
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] when the string exceeds `u16::MAX`
/// bytes and cannot be length-prefixed.
fn push_string(out: &mut Vec<u8>, s: &str) -> Result<(), NinepCodecError> {
    let len =
        u16::try_from(s.len()).map_err(|_| NinepCodecError::FrameTooLarge { len: s.len() })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Encodes an `Rversion` reply pinning the negotiated `msize` and version.
///
/// # Errors
///
/// Returns [`NinepCodecError`] when the frame or version string cannot be sized.
pub fn encode_rversion(tag: u16, msize: u32, version: &str) -> Result<Vec<u8>, NinepCodecError> {
    let mut frame = begin_frame(RVERSION, tag);
    frame.extend_from_slice(&msize.to_le_bytes());
    push_string(&mut frame, version)?;
    finish_frame(frame)
}

/// Encodes an `Rattach` reply carrying the root QID.
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] only on a pathological frame size.
pub fn encode_rattach(tag: u16, qid: &Qid) -> Result<Vec<u8>, NinepCodecError> {
    let mut frame = begin_frame(RATTACH, tag);
    qid.encode_into(&mut frame);
    finish_frame(frame)
}

/// Encodes an `Rwalk` reply carrying the walked QIDs.
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] when more than `u16::MAX` QIDs are
/// supplied (unreachable in practice; `nwname` is capped at [`MAX_WALK_NAMES`]).
pub fn encode_rwalk(tag: u16, qids: &[Qid]) -> Result<Vec<u8>, NinepCodecError> {
    let nwqid = u16::try_from(qids.len())
        .map_err(|_| NinepCodecError::FrameTooLarge { len: qids.len() })?;
    let mut frame = begin_frame(RWALK, tag);
    frame.extend_from_slice(&nwqid.to_le_bytes());
    for qid in qids {
        qid.encode_into(&mut frame);
    }
    finish_frame(frame)
}

/// Encodes an `Rlopen` reply carrying the opened QID and an iounit.
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] only on a pathological frame size.
pub fn encode_rlopen(tag: u16, qid: &Qid, iounit: u32) -> Result<Vec<u8>, NinepCodecError> {
    let mut frame = begin_frame(RLOPEN, tag);
    qid.encode_into(&mut frame);
    frame.extend_from_slice(&iounit.to_le_bytes());
    finish_frame(frame)
}

/// Encodes an `Rread` reply carrying `data`.
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] when `data` exceeds the `u32`
/// `count` field or the frame exceeds `u32::MAX`.
pub fn encode_rread(tag: u16, data: &[u8]) -> Result<Vec<u8>, NinepCodecError> {
    encode_count_data(RREAD, tag, data)
}

/// Encodes an `Rreaddir` reply carrying packed directory-entry `data`.
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] when `data` exceeds the `u32`
/// `count` field or the frame exceeds `u32::MAX`.
pub fn encode_rreaddir(tag: u16, data: &[u8]) -> Result<Vec<u8>, NinepCodecError> {
    encode_count_data(RREADDIR, tag, data)
}

/// Shared `count[4] data[count]` body encoder for `Rread`/`Rreaddir`.
fn encode_count_data(msg_type: u8, tag: u16, data: &[u8]) -> Result<Vec<u8>, NinepCodecError> {
    let count = u32::try_from(data.len())
        .map_err(|_| NinepCodecError::FrameTooLarge { len: data.len() })?;
    let mut frame = begin_frame(msg_type, tag);
    frame.extend_from_slice(&count.to_le_bytes());
    frame.extend_from_slice(data);
    finish_frame(frame)
}

/// Encodes an `Rreadlink` reply carrying the symlink target.
///
/// # Errors
///
/// Returns [`NinepCodecError`] when the target string or frame cannot be sized.
pub fn encode_rreadlink(tag: u16, target: &str) -> Result<Vec<u8>, NinepCodecError> {
    let mut frame = begin_frame(RREADLINK, tag);
    push_string(&mut frame, target)?;
    finish_frame(frame)
}

/// Encodes an `Rclunk` reply (header only).
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] only on a pathological frame size.
pub fn encode_rclunk(tag: u16) -> Result<Vec<u8>, NinepCodecError> {
    finish_frame(begin_frame(RCLUNK, tag))
}

/// Encodes an `Rflush` reply (header only).
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] only on a pathological frame size.
pub fn encode_rflush(tag: u16) -> Result<Vec<u8>, NinepCodecError> {
    finish_frame(begin_frame(RFLUSH, tag))
}

/// Encodes an `Rfsync` reply (header only).
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] only on a pathological frame size.
pub fn encode_rfsync(tag: u16) -> Result<Vec<u8>, NinepCodecError> {
    finish_frame(begin_frame(RFSYNC, tag))
}

/// Encodes an `Rxattrwalk` reply with a fixed zero attribute size.
///
/// A read-only export advertises no extended attributes, so the reported size is
/// always zero — deterministic and host-independent ([IO-15]).
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] only on a pathological frame size.
pub fn encode_rxattrwalk(tag: u16, size: u64) -> Result<Vec<u8>, NinepCodecError> {
    let mut frame = begin_frame(RXATTRWALK, tag);
    frame.extend_from_slice(&size.to_le_bytes());
    finish_frame(frame)
}

/// Encodes an `Rlerror` reply carrying a Linux errno ([IO-17]).
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] only on a pathological frame size.
pub fn encode_rlerror(tag: u16, ecode: u32) -> Result<Vec<u8>, NinepCodecError> {
    let mut frame = begin_frame(RLERROR, tag);
    frame.extend_from_slice(&ecode.to_le_bytes());
    finish_frame(frame)
}

/// The fixed attributes carried in an `Rgetattr` reply ([IO-15]).
///
/// Every field is fixed or content-derived: timestamps are a fixed epoch,
/// ownership is root, the block size is fixed, and the block count is derived
/// from the file size — never the host's observed metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetattrReply {
    /// The valid-attribute mask echoed to the client.
    pub valid: u64,
    /// The file's QID.
    pub qid: Qid,
    /// The POSIX mode bits (kind + permissions), content-derived.
    pub mode: u32,
    /// The owning uid (fixed to root, `0`).
    pub uid: u32,
    /// The owning gid (fixed to root, `0`).
    pub gid: u32,
    /// The hard-link count (fixed to `1`).
    pub nlink: u64,
    /// The device id (fixed to `0`).
    pub rdev: u64,
    /// The file size in bytes (content-derived).
    pub size: u64,
    /// The preferred block size (fixed to `4096`).
    pub blksize: u64,
    /// The allocated 512-byte block count, `ceil(size / 512)` (content-derived).
    pub blocks: u64,
}

impl GetattrReply {
    /// Encodes this attribute set as an `Rgetattr` reply.
    ///
    /// The timestamp fields (atime/mtime/ctime, both seconds and nanoseconds, and
    /// the legacy btime/gen/data_version words) are all emitted as the fixed
    /// epoch zero, so no host clock can leak into the reply ([IO-15]).
    ///
    /// # Errors
    ///
    /// Returns [`NinepCodecError::FrameTooLarge`] only on a pathological frame
    /// size.
    pub fn encode(&self, tag: u16) -> Result<Vec<u8>, NinepCodecError> {
        let mut frame = begin_frame(RGETATTR, tag);
        frame.extend_from_slice(&self.valid.to_le_bytes());
        self.qid.encode_into(&mut frame);
        frame.extend_from_slice(&self.mode.to_le_bytes());
        frame.extend_from_slice(&self.uid.to_le_bytes());
        frame.extend_from_slice(&self.gid.to_le_bytes());
        frame.extend_from_slice(&self.nlink.to_le_bytes());
        frame.extend_from_slice(&self.rdev.to_le_bytes());
        frame.extend_from_slice(&self.size.to_le_bytes());
        frame.extend_from_slice(&self.blksize.to_le_bytes());
        frame.extend_from_slice(&self.blocks.to_le_bytes());
        // atime, mtime, ctime (sec+nsec) and btime/gen/data_version: fixed epoch.
        for _ in 0..9 {
            frame.extend_from_slice(&0u64.to_le_bytes());
        }
        finish_frame(frame)
    }
}

/// The fixed statistics carried in an `Rstatfs` reply ([IO-15]).
///
/// Synthetic and host-independent: a fixed filesystem type, block size, and
/// (zero) usage counters, so `statfs` never leaks host device accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatfsReply {
    /// The filesystem type magic (a fixed synthetic value).
    pub fs_type: u32,
    /// The block size (fixed to `4096`).
    pub bsize: u32,
    /// The total block count (fixed synthetic value).
    pub blocks: u64,
    /// The free block count (fixed to `0` — read-only).
    pub bfree: u64,
    /// The available block count (fixed to `0`).
    pub bavail: u64,
    /// The total inode count (fixed synthetic value).
    pub files: u64,
    /// The free inode count (fixed to `0`).
    pub ffree: u64,
    /// The filesystem id (fixed to `0`).
    pub fsid: u64,
    /// The maximum filename length (fixed to `255`).
    pub namelen: u32,
}

impl StatfsReply {
    /// Encodes these statistics as an `Rstatfs` reply.
    ///
    /// # Errors
    ///
    /// Returns [`NinepCodecError::FrameTooLarge`] only on a pathological frame
    /// size.
    pub fn encode(&self, tag: u16) -> Result<Vec<u8>, NinepCodecError> {
        let mut frame = begin_frame(RSTATFS, tag);
        frame.extend_from_slice(&self.fs_type.to_le_bytes());
        frame.extend_from_slice(&self.bsize.to_le_bytes());
        frame.extend_from_slice(&self.blocks.to_le_bytes());
        frame.extend_from_slice(&self.bfree.to_le_bytes());
        frame.extend_from_slice(&self.bavail.to_le_bytes());
        frame.extend_from_slice(&self.files.to_le_bytes());
        frame.extend_from_slice(&self.ffree.to_le_bytes());
        frame.extend_from_slice(&self.fsid.to_le_bytes());
        frame.extend_from_slice(&self.namelen.to_le_bytes());
        finish_frame(frame)
    }
}

/// Packs one `Rreaddir` entry (`qid[13] offset[8] type[1] name[s]`) onto `out`.
///
/// The `offset` is the cookie a client passes to resume enumeration; it is
/// assigned after the deterministic sort so it never depends on host readdir
/// order ([IO-14]). Returns the number of bytes appended.
///
/// # Errors
///
/// Returns [`NinepCodecError::FrameTooLarge`] when `name` exceeds `u16::MAX`.
pub fn push_dirent(
    out: &mut Vec<u8>,
    qid: &Qid,
    offset: u64,
    dtype: u8,
    name: &str,
) -> Result<usize, NinepCodecError> {
    let before = out.len();
    qid.encode_into(out);
    out.extend_from_slice(&offset.to_le_bytes());
    out.push(dtype);
    push_string(out, name)?;
    Ok(out.len() - before)
}

// ---- cursor + little-endian helpers ------------------------------------------

/// A forward-only, bounds-checked reader over a 9p frame body.
///
/// Every accessor advances the cursor only on success and returns
/// [`NinepCodecError::Truncated`] when the requested field runs past the buffer,
/// so decoding hostile input never panics or reads out of bounds ([IO-18]).
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a cursor starting at `pos` over `bytes`.
    fn new(bytes: &'a [u8], pos: usize) -> Self {
        Self { bytes, pos }
    }

    /// Reads the next `n` bytes, advancing the cursor, or fails if too short.
    fn take(&mut self, n: usize) -> Result<&'a [u8], NinepCodecError> {
        let end = self.pos.checked_add(n).ok_or(NinepCodecError::Truncated {
            needed: n,
            got: self.bytes.len().saturating_sub(self.pos),
        })?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(NinepCodecError::Truncated {
                needed: n,
                got: self.bytes.len().saturating_sub(self.pos),
            })?;
        self.pos = end;
        Ok(slice)
    }

    /// Reads a little-endian `u16`.
    fn u16(&mut self) -> Result<u16, NinepCodecError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Reads a little-endian `u32`.
    fn u32(&mut self) -> Result<u32, NinepCodecError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a little-endian `u32` if four bytes remain, else returns `None`.
    ///
    /// Used for optional trailing fields (the 9P2000.L `Tattach.n_uname`) that
    /// some clients omit; absence is not an error.
    fn try_u32(&mut self) -> Option<u32> {
        self.u32().ok()
    }

    /// Reads a little-endian `u64`.
    fn u64(&mut self) -> Result<u64, NinepCodecError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a 9p string (`len[2] data[len]`), validating bounds and UTF-8.
    fn string(&mut self) -> Result<String, NinepCodecError> {
        let len = self.u16()? as usize;
        let raw = self.take(len).map_err(|_| NinepCodecError::BadString {
            declared: len,
            available: self.bytes.len().saturating_sub(self.pos),
        })?;
        // A 9p path component is UTF-8 by the Linux convention; reject invalid
        // sequences rather than lossily transcoding (keeps QID hashing exact).
        String::from_utf8(raw.to_vec()).map_err(|_| NinepCodecError::BadString {
            declared: len,
            available: raw.len(),
        })
    }
}

/// Reads a little-endian `u16` at `offset` from a header slice long enough.
fn u16_le(buf: &[u8], offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&buf[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

/// Reads a little-endian `u32` at `offset` from a header slice long enough.
fn u32_le(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

/// Reads a little-endian `u64` at `offset` from a header slice long enough.
fn u64_le(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// A malformed-message failure of the 9p wire codec.
///
/// Every variant is a pure function of the input bytes; decoding hostile input
/// always lands here rather than panicking ([IO-18], `gate:abi-conformance`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NinepCodecError {
    /// The buffer (or a body field) is shorter than the bytes it must contain.
    #[error("9p message truncated: needed {needed} more bytes, {got} available")]
    Truncated {
        /// The number of bytes the field required.
        needed: usize,
        /// The number of bytes actually available.
        got: usize,
    },

    /// The `size[4]` prefix disagrees with the actual frame length.
    #[error("9p frame size mismatch: declared {declared}, actual {actual}")]
    SizeMismatch {
        /// The size declared in the frame's `size[4]` prefix.
        declared: u32,
        /// The actual byte length of the frame.
        actual: usize,
    },

    /// A 9p string's declared length runs past the frame, or is not UTF-8.
    #[error("9p string malformed: declared {declared} bytes, {available} available")]
    BadString {
        /// The declared string length.
        declared: usize,
        /// The bytes actually available for the string.
        available: usize,
    },

    /// A `Twalk` carried more path components than the 9p limit allows.
    #[error("9p Twalk nwname {nwname} exceeds the maximum of 16")]
    TooManyNames {
        /// The oversized `nwname` count.
        nwname: u16,
    },

    /// An encoded reply frame exceeds a wire size field (`u16`/`u32`).
    #[error("9p frame field overflow: length {len} does not fit its wire size field")]
    FrameTooLarge {
        /// The length that overflowed its wire size field.
        len: usize,
    },
}
