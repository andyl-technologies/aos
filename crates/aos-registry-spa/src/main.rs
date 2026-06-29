//! WASM entry point for the registry web-surface SPA.
//!
//! `trunk` compiles this binary to `wasm32-unknown-unknown` and wires its
//! `main` as the module's start function; on any other target it is an inert
//! stub so the native workspace build still type-checks the bin target.

fn main() {
    #[cfg(target_arch = "wasm32")]
    aos_registry_spa::mount();
}
