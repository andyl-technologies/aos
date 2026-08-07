//! Browser management application for the AOS Hub control plane.
//!
//! This crate is the single client-side settings application specified by
//! RFC-0012. [`route`] owns the closed canonical deep-link registry and is
//! compiled on every target for contract tests. On `wasm32`, [`transport`]
//! exchanges the ambient browser session for an in-memory bearer and invokes
//! generated Connect paths with the ProtoJSON types from
//! [`aos_proto_types`]. [`app`] renders the shared settings shell.
//!
//! The native and Cloudflare Worker deployments consume one content-addressed
//! build of this crate. Both serve the same closed deep links and all resource
//! management leaves the browser through the canonical API; there is no
//! server-rendered management fallback.

pub mod route;

#[cfg(target_arch = "wasm32")]
pub mod app;
#[cfg(target_arch = "wasm32")]
pub mod components;
#[cfg(target_arch = "wasm32")]
mod mutation;
#[cfg(target_arch = "wasm32")]
pub mod transport;
#[cfg(target_arch = "wasm32")]
mod workflows;

/// Mounts the management application into the document body.
#[cfg(target_arch = "wasm32")]
pub fn mount() {
    use leptos::prelude::*;

    std::panic::set_hook(Box::new(|information| {
        leptos::web_sys::console::error_1(&format!("{information}").into());
    }));
    mount_to_body(app::App);
}
