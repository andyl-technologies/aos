//! Owns pure collector records and reachability policy from specification 17.
//!
//! The lease module preserves the registered singleton collector record and
//! pure proposal/ownership checks. Native conditional writes, authoritative
//! time, and physical collection qualification remain backend obligations.
//!
//! ```text
//! GcLease = {1: holder, 2: epoch, 3: expiry}
//! ```
//!
//! Publication codecs carry untrusted record data; native current-root and
//! destructive-effect authorization remain independent backend obligations.

mod lease;

pub mod publication;

pub use lease::{GcError, GcLease};
