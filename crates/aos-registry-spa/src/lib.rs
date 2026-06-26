//! The registry web-surface SPA (RFC-0004): a Leptos CSR WASM app.
//!
//! Every AOS registry gets a static **`web` surface** — a polished UI
//! uploaded to the registry's own bucket and served by plain S3/HTTP file
//! serving, with **zero hub in the serving path**. This crate is that UI:
//! a Leptos client-side-rendered app compiled to `wasm32-unknown-unknown`
//! that *progressively enhances* the content-bearing, no-JS static pages
//! `apr web generate` emits (see `aos_package::registry::webgen`). The same
//! URL serves real content to curl and lynx; when WASM runs, the SPA takes
//! over in place.
//!
//! # What it does
//!
//! - Fetches `web/config.json` (branding + optional `hub_url`) and
//!   `web/index.json` (registry meta + package list) **same-origin** — zero
//!   CORS — and renders the registry home and per-package views, reading the
//!   exact field shapes the generator wrote ([`model`]).
//! - Runs the **honest verification badge** entirely in the browser
//!   ([`verify`]): it lazily fetches the channel partition and the committed
//!   roster same-origin and runs *real* Ed25519 verification client-side,
//!   reusing [`aos_registry_surface`] — the very reader the hub indexer and
//!   `apm` run. One parser across server, Worker, and browser.
//! - When `config.json` carries a `hub_url`, lights up hub search over
//!   Connect-JSON ([`net`]); absent it, degrades to a client-side substring
//!   filter over `index.json`.
//!
//! # Module map
//!
//! - [`model`] — serde models for the same-origin JSON snapshots.
//! - [`closure`] — the cache closure-graph view model (pure ordering logic;
//!   the Leptos `ClosureGraph` component that paints it lives in `app`).
//! - [`verify`] — the in-browser verification badge: pure outcome logic
//!   plus the async surface walk, both reusing [`aos_registry_surface`].
//! - `net` — browser `fetch()` glue and the hub Connect POST (wasm only).
//! - `app` — the Leptos components and the home/package routing (wasm only).
//!
//! # Build
//!
//! The native workspace build only compiles the pure modules ([`model`],
//! [`verify`]); the Leptos UI is wasm-only. Produce the deployable dist
//! with `trunk`:
//!
//! ```text
//! cd crates/aos-registry-spa && trunk build --release
//! # -> dist/index.html + dist/app-<hash>.js + dist/app-<hash>_bg.wasm
//! #    + dist/style-<hash>.css  (the artifact apr web generate ships)
//! ```
//!
//! A plain compile check (no wasm-bindgen, no bundler) is
//! `cargo build -p aos-registry-spa --target wasm32-unknown-unknown`.

pub mod closure;
pub mod model;
pub mod verify;

#[cfg(target_arch = "wasm32")]
pub mod app;
#[cfg(target_arch = "wasm32")]
pub mod net;

/// Mount the SPA onto the document body, replacing the static no-JS floor.
///
/// Called from the WASM entry point ([`main`](../aos_registry_spa/index.html));
/// only present on the `wasm32` target.
#[cfg(target_arch = "wasm32")]
pub fn mount() {
    use leptos::prelude::*;
    console_error_panic_hook_set();
    mount_to_body(app::App);
}

/// Install a panic hook that logs Rust panics to the browser console.
///
/// A no-op stand-in is intentionally avoided: surfacing a panic message in
/// the console is the only debug signal a CSR app gets. Kept tiny and
/// dependency-free by writing through `web_sys::console`.
#[cfg(target_arch = "wasm32")]
fn console_error_panic_hook_set() {
    use std::panic;
    panic::set_hook(Box::new(|info| {
        leptos::web_sys::console::error_1(&format!("{info}").into());
    }));
}
