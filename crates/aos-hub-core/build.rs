//! Prepares optional browser-console artifacts for embedding in both runtimes.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-env-changed=AOS_HUB_CONSOLE_JS");
    println!("cargo:rerun-if-env-changed=AOS_HUB_CONSOLE_WASM");
    println!("cargo:rerun-if-env-changed=AOS_HUB_CONSOLE_CSS");

    let output =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Cargo did not provide OUT_DIR")
        })?);
    stage(
        "AOS_HUB_CONSOLE_JS",
        &output.join("hub-console.js"),
        b"document.body.textContent = 'The AOS Hub console asset is unavailable in this development build.';\n",
    )?;
    stage(
        "AOS_HUB_CONSOLE_WASM",
        &output.join("hub-console_bg.wasm"),
        &[],
    )?;
    stage(
        "AOS_HUB_CONSOLE_CSS",
        &output.join("hub-console.css"),
        b"/* Console CSS is supplied by the production package. */\n",
    )?;
    Ok(())
}

fn stage(variable: &str, destination: &Path, fallback: &[u8]) -> io::Result<()> {
    let contents = match env::var_os(variable) {
        Some(source) => {
            println!(
                "cargo:rerun-if-changed={}",
                PathBuf::from(&source).display()
            );
            fs::read(source)?
        }
        None => fallback.to_vec(),
    };
    // Store artifacts are read-only. Copying their permissions into OUT_DIR
    // makes the next incremental build unable to replace the staged assets.
    // Replace any older copied output and create a normal writable build file.
    match fs::remove_file(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::write(destination, contents)
}
