//! Live-store verification and temporary garbage-collection protection.
//!
//! [`verification`] authenticates NAR identities and direct references through
//! a selected Nix executable. [`temp_roots`] keeps a live store connection while
//! immutable objects are prepared for durable deployment roots.

pub mod temp_roots;
pub mod verification;
