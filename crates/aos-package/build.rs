//! Generates closed native-adapter source consumed by `aos-package`.

use std::error::Error;

#[path = "build/native_adapter_surface.rs"]
mod native_adapter_surface;

fn main() -> Result<(), Box<dyn Error>> {
    native_adapter_surface::compile()
}
