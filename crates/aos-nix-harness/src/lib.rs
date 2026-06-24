//! Differential harnesses for the RFC-0007 Nix evaluator.
//!
//! This crate owns reusable comparison logic that validates an evaluator against
//! C++ Nix without depending on the `aos` command-line porcelain.

#![forbid(unsafe_code)]

pub mod diff;
