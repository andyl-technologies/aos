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
//! build of this crate. Until every management workflow is implemented and the
//! one-shot route cutover is ready, the bundle is deliberately not mounted by
//! either runtime.

pub mod route;

#[cfg(target_arch = "wasm32")]
pub mod app;
#[cfg(target_arch = "wasm32")]
pub mod components;
#[cfg(target_arch = "wasm32")]
pub mod transport;

/// Mounts the management application into the document body.
#[cfg(target_arch = "wasm32")]
pub fn mount() {
    use leptos::prelude::*;

    std::panic::set_hook(Box::new(|information| {
        leptos::web_sys::console::error_1(&format!("{information}").into());
    }));
    mount_to_body(app::App);
}
