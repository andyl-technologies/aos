//! Nix store database ability provider.
//!
//! The provider admits one exact local database request, validates the selected
//! `nix-store` executable, and compares the requested registration stream with
//! the live database. Effects initialize the database and load that same stream
//! through the selected executable.

#![forbid(unsafe_code)]

pub mod handler;

mod process;
