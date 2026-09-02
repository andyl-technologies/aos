//! Shared implementation for the AOS command-line programs.
//!
//! This package builds three independent public programs: `aos` for repository
//! and system-development workflows, `apm` for package consumption, and `apr`
//! for registry authoring. The binaries share implementation modules through
//! this library; none selects a command personality from `argv[0]`.

mod cli;
mod commands;
pub mod entry;
mod logging;
