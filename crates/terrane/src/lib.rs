//! Provides the portable storage and role configuration layer of Terrane.
//!
//! [`config`] loads the vocabulary in specifications 11 and 26; [`role`]
//! selects the process roles in specifications 03 and 37. [`codec`] owns
//! native compression and [`store`] defines the I/O boundaries. These T1
//! modules are completed by their named tasks; unavailable services and
//! surfaces continue to fail explicitly.

#![forbid(unsafe_code)]

#[cfg(feature = "std")]
pub mod bucket;
pub mod codec;
pub mod config;
pub mod derived;
pub mod domain;
pub mod gc;
pub mod guard;
#[cfg(feature = "std")]
pub mod indexing;
pub mod model;
pub mod pack;
#[cfg(feature = "std")]
pub mod ref_advance;
#[cfg(feature = "std")]
pub mod repository;
pub mod role;
#[cfg(feature = "std")]
pub(crate) mod selected_bridge;
pub mod store;
pub mod surface;
