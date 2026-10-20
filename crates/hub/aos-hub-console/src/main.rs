//! WASM entry point for the AOS Hub management application.
//!
//! Native workspace builds retain an inert executable so the route registry
//! remains testable without a browser runtime.

fn main() {
    #[cfg(target_arch = "wasm32")]
    aos_hub_console::mount();
}
