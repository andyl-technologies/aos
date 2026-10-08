//! Nonauthorizing physical Guest template and complete-root measurement.
//!
//! [`guest_root_tree`] owns the canonical comparison and offline digest,
//! complete descriptor-relative capture, bounded resident accounting, and
//! retained native failure custody. Callers independently retain protected
//! roots and writer exclusion; measurement grants no publication, mount,
//! execution, resource, deadline, or readiness authority.

#![cfg(target_os = "linux")]
#![deny(missing_docs)]

pub mod guest_root_tree;
