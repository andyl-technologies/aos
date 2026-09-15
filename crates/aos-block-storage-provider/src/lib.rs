//! Checked block-storage resource providers.
//!
//! The shared engine validates the command-handler protocol and delegates only
//! exact device inspection and mutation to the cryptsetup and util-linux
//! backends. Each backend is exposed as a separate package-owned executable.

#![forbid(unsafe_code)]

pub mod cryptsetup;
pub mod engine;
pub mod process;
pub mod storage_format;
