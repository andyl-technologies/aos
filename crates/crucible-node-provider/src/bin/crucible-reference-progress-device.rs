//! Separate qualification-only device with an actual positive-work response latch.

use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("reference progress device failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let control = PathBuf::from(arguments.next().ok_or("expected native control socket")?);
    let progress = PathBuf::from(
        arguments
            .next()
            .ok_or("expected separate private progress socket")?,
    );
    if arguments.next().is_some() {
        return Err("unexpected progress device argument".into());
    }
    crucible_node_provider::reference_device::serve_with_progress(&control, &progress)?;
    Ok(())
}
