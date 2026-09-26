//! Dormant Mount-manager startup inventory and custody authority.
//!
//! Its fixed-root owner consumes the Linux one-shot complete descriptor-table
//! claim, derives roles only from protected journal state, atomically appends
//! the immutable startup capture, and then releases move-only typed
//! capabilities. Raw journal selection and namespace-45 claims stay private.

mod absence;
mod authority;
mod custody;
mod owner;
mod recovery;

pub use absence::*;
pub use authority::*;
pub use custody::*;
pub use owner::*;
pub use recovery::*;
