//! Distinct source-built ordered-lineage checksum child for qualification exercises.

use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("reference lineage device failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = arguments
        .next()
        .ok_or("expected one private lineage socket path")?;
    if arguments.next().is_some() {
        return Err("unexpected reference lineage device argument".into());
    }
    crucible_node_provider::reference_lineage::serve(&PathBuf::from(socket))?;
    Ok(())
}
