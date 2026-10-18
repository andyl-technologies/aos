//! Portable domain values and policies for the AOS Hub.
//!
//! Identity and IAM rules, credential primitives, delivery contracts, cache
//! metadata, and webhook events have no database or application dependencies.
//! Native and Worker deployments consume the same validated representations.

pub mod auth;
pub mod binding;
pub mod cache;
pub mod clock;
pub mod crawl;
pub mod delivery;
pub mod delivery_http;
pub mod domain;
pub mod endpoint;
pub mod identity;
pub mod keymap;
pub mod retention;
pub mod runtime;
pub mod secret_version;
pub mod url_guard;
pub mod webhook;
