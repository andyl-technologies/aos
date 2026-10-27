//! Exposes the consuming crate's build-script profile to compiler actions.

use std::env;

fn main() -> Result<(), env::VarError> {
    for key in ["OPT_LEVEL", "DEBUG", "PROFILE", "HOST", "TARGET"] {
        println!("cargo:rustc-env=AOS_PROFILE_{key}={}", env::var(key)?);
    }

    Ok(())
}
