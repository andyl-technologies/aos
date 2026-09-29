//! Provides the portable storage and role configuration layer of Terrane.
//!
//! [`config`] loads the vocabulary in specifications 11 and 26; [`role`]
//! selects the process roles in specifications 03 and 37. [`codec`] owns
//! native compression and [`store`] defines the I/O boundaries. These T1
//! modules are completed by their named tasks; unavailable services and
//! surfaces continue to fail explicitly.

#![forbid(unsafe_code)]

pub mod codec;
pub mod config;
pub mod role;
pub mod store;
