//! Qualifies the supported local registered SDK checkout through public APIs.
#![cfg(all(feature = "tokio", feature = "surface-sdk", unix))]

#[path = "local_sdk/fixture.rs"]
mod fixture;
#[path = "local_sdk/lifecycle.rs"]
mod lifecycle;
#[path = "local_sdk/pinned.rs"]
mod pinned;
#[path = "local_sdk/refusals.rs"]
mod refusals;
