//! Separately selected CNP endpoint for the native positive-work fault fixture.

use std::path::PathBuf;

use crucible_node_contract::canonical;
use crucible_node_provider::reference_service::{ReferenceProgressLaunchBootstrap, serve_progress};
use crucible_node_provider::transport::FrameReader;

fn main() {
    if run().is_err() {
        // Private launch authority is never included in diagnostics.
        eprintln!("reference progress provider failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = PathBuf::from(arguments.next().ok_or("expected provider socket")?);
    let child = PathBuf::from(
        arguments
            .next()
            .ok_or("expected measured progress device")?,
    );
    if arguments.next().is_some() {
        return Err("unexpected progress provider argument".into());
    }
    let value = FrameReader::with_limits(std::io::stdin().lock(), 16 * 1024 * 1024, 64)?
        .read()?
        .ok_or("private progress bootstrap missing")?;
    let launch: ReferenceProgressLaunchBootstrap =
        canonical::decode(&canonical::canonical_json(&value)?, 16 * 1024 * 1024)?;
    serve_progress(&socket, &child, launch)?;
    Ok(())
}
