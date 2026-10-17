//! Runtime-independent provider parsing for package assessments.
//!
//! [`upstream`] projects GitHub releases/tags, Go releases, and Repology into
//! the shared observation contracts. Transport, credentials, response storage,
//! and history are supplied by local, Native, or Worker adapters. No parser
//! reads a clock or performs network, filesystem, database, or process I/O.

#![forbid(unsafe_code)]

mod json;
pub mod kev;
pub mod nvd;
pub mod osv;
pub mod upstream;

fn sanitized_summary(value: &str) -> String {
    let mut summary = String::new();
    for character in value.chars().filter(|character| !character.is_control()) {
        if summary.len() + character.len_utf8() > 4096 {
            break;
        }
        summary.push(character);
    }
    if summary.is_empty() {
        "Advisory details unavailable".into()
    } else {
        summary
    }
}

/// Identifies the behavior-preserving legacy upstream normalization profile.
pub const UPSTREAM_ADAPTER_VERSION: &str = "aos-maintain-providers/v1";
