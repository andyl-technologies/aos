//! Owns pure collector records and reachability policy from specification 17.
//!
//! The lease module preserves the registered singleton collector record and
//! pure proposal/ownership checks. Native conditional writes, authoritative
//! time, and physical collection qualification remain backend obligations.
//!
//! ```text
//! GcLease = {1: holder, 2: epoch, 3: expiry}
//! ```

mod lease;

pub use lease::{GcError, GcLease};
