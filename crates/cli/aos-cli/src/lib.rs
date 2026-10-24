//! Shared implementation for the AOS command-line programs.
//!
//! This package builds three public programs: `aos` for repository and system
//! development workflows, `apm` for package consumption, and `apr` for registry
//! authoring. The private `aos-package-runtime` owns bounded on-host service
//! and activation commands; `aos-boot-configuration` adopts authenticated
//! platform metadata and transfers initrd receipts. These installed entry
//! points share one executable with `apm` to keep the immutable system closure
//! bounded. Its entry-point name selects only the parser; signed artifacts and
//! current operator authority still select native effects.

mod cli;
mod commands;
pub mod entry;
mod error;
mod logging;
