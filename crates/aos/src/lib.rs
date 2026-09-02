//! Shared implementation for the AOS command-line programs.
//!
//! This package builds three independent public programs: `aos` for repository
//! and system-development workflows, `apm` for package consumption, and `apr`
//! for registry authoring. A private `aos-package-runtime` program owns the
//! on-host service and activation subcommands. The binaries share implementation
//! modules through this library; none selects authority from `argv[0]`.

mod cli;
mod commands;
pub mod entry;
mod logging;
