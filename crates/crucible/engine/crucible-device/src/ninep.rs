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
    MAX_NINEP_SNAPSHOT_BYTES, NinepDevice, NinepFaultResourceUsage, NinepLatency, NinepSnapshot,
    NinepSnapshotCodecError, NinepVirtualFid,
};
pub use fault::*;
pub use server::{FidEntry, FidState, MAX_MSIZE, MIN_MSIZE, NinepServer, NinepServerSnapshot};
pub use tree::{
    BadComponent, DirEntry, FsTree, FsTreeDecodeError, Node, qid_path, validate_component,
};

#[cfg(test)]
mod golden;

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "ninep_fault_policy_test.rs"]
mod fault_policy_tests;
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "ninep_lifecycle_test.rs"]
mod lifecycle_tests;
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "ninep_protocol_limits_test.rs"]
mod protocol_limits_tests;
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "ninep_protocol_test.rs"]
mod protocol_tests;
#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
#[path = "ninep_test_support.rs"]
mod test_support;
