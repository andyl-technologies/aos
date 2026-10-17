//! Source-built controlled checksum device for provider conformance exercises.

use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("reference device failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = arguments.next().ok_or("expected one private socket path")?;
    if arguments.next().is_some() {
        return Err("unexpected reference device argument".into());
    }
    crucible_node_provider::reference_device::serve(&PathBuf::from(socket))?;
    Ok(())
}
