//! Transaction-scoped boot preparation ability provider.
//!
//! The provider executes one authenticated package artifact, records exact
//! completion beneath the stage runtime root, and reports only evidence bound
//! to the selected resource and semantic revision.

#![forbid(unsafe_code)]

pub mod handler;

mod process;
