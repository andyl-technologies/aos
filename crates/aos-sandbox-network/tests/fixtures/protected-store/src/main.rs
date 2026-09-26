//! Runs the real-ext4 namespace-inspector protected-store qualification.

use std::error::Error;
use std::ffi::OsStr;
use std::io::{self, Write as _};
use std::path::Path;

use aos_sandbox_network::{
    PROTECTED_STORE_EXT4_CASES, run_namespace_inspector_protected_store_ext4_fixture,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("namespace-inspector protected-store fixture failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == [OsStr::new("--list")] {
        serde_json::to_writer(io::stdout().lock(), PROTECTED_STORE_EXT4_CASES)?;
        io::stdout().lock().write_all(b"\n")?;
        return Ok(());
    }
    let [root, ambiguous_spent_final] = arguments.as_slice() else {
        return Err(io::Error::other(
            "usage: aos-sandbox-network-protected-store-fixture ROOT AMBIGUOUS_SPENT_FINAL",
        )
        .into());
    };

    let proof = run_namespace_inspector_protected_store_ext4_fixture(
        Path::new(root),
        Path::new(ambiguous_spent_final),
    )?;
    serde_json::to_writer(io::stdout().lock(), &proof)?;
    io::stdout().lock().write_all(b"\n")?;
    Ok(())
}
