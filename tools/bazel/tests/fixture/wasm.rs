//! Requires a WASM target while using native generators and procedural macros.

#[cfg(not(target_arch = "wasm32"))]
compile_error!("the fixture application must compile for WebAssembly");

fn main() {
    assert_eq!(fixture_macro::identity!(fixture_library::answer()), 42);
}
