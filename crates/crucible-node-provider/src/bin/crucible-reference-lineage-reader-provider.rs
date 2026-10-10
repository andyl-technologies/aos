//! Separately selected public endpoint for launch6 original-input reader under distinct measured source policy.

use std::path::PathBuf;

use crucible_node_contract::canonical;
use crucible_node_provider::{
    reference_service::ReferenceLineageReaderLaunchBootstrap, transport::FrameReader,
};

fn main() {
    if run().is_err() {
        eprintln!("lineage reference provider failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = PathBuf::from(arguments.next().ok_or("expected private socket")?);
    let child = PathBuf::from(arguments.next().ok_or("expected lineage companion")?);
    if arguments.next().is_some() {
        return Err("unexpected lineage provider argument".into());
    }
    let value = FrameReader::with_limits(std::io::stdin().lock(), 16 * 1024 * 1024, 64)?
        .read()?
        .ok_or("lineage bootstrap unavailable")?;
    let bytes = canonical::canonical_json(&value)?;
    let launch: ReferenceLineageReaderLaunchBootstrap =
        canonical::decode(&bytes, 16 * 1024 * 1024)?;
    crucible_node_provider::reference_service::serve_lineage_reader(&socket, &child, launch)?;
    Ok(())
}
