//! Shared implementation for the AOS command-line programs.
//!
//! This package builds three public programs: `aos` for repository and system
//! development workflows, `apm` for package consumption, and `apr` for registry
//! authoring. Two private programs provide bounded on-host command surfaces:
//! `aos-package-runtime` owns service and activation commands, while
//! `aos-metadata-runtime` owns provisioning metadata commands. The installed
//! `apm` and package runtime entry points share one executable to keep the
//! immutable system closure bounded. Its entry-point name selects only the
//! parser; signed artifacts and current operator authority still select native
//! effects.

mod cli;
mod commands;
pub mod entry;
mod logging;
