//! Offline database capture without serving or provider initialization.
//!
//! This module exposes the audited Native SQLite capture seam. It owns no CLI,
//! files, keys, import, storage binding, jobs or activation policy.

pub mod capture;

pub mod scratch;
