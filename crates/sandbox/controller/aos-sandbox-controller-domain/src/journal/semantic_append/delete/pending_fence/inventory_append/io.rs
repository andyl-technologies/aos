//! Keeps the original D API on the sole shared native IO and disposal engine.

pub(super) use crate::journal::inventory_native::io::{IoOriginals, Turn, require_before};
pub use crate::journal::inventory_native::io::DeleteInventoryIoDisposalV1;
