//! Effectful release coordination over verified AOS release formats.
//!
//! [`capture`] bounds and snapshots untrusted filesystem inputs; [`projection`]
//! prepares consumer-facing publication layouts, and [`readback`] verifies
//! published objects anonymously. [`journal`] owns durable transition output.
//! [`registry_entries`] converts frozen outputs and retained source evidence
//! into registry publication entries.
//! [`config`] and [`credentials`] resolve operator configuration, while
//! [`tooling`] locates installed qualification tools and [`signer`] implements
//! the bounded external-signing process protocol.
//!
//! The crate contains no command parser or terminal presentation. Release
//! schemas and semantic verification remain in `aos-release-format`; private
//! signing keys remain behind the external `aos-release-signer` executable.

#![forbid(unsafe_code)]

pub mod capture;
pub mod config;
pub mod credentials;
pub mod journal;
pub mod projection;
pub mod readback;
pub mod registry_entries;
pub mod signer;
pub mod tooling;
