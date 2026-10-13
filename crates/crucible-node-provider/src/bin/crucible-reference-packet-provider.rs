//! Runs the separately measured finite packet source on its private CNP socket.
//!
//! The inherited launch selects the exact source program, original controller,
//! finite limits and coordinator edition. It issues no ordinary class acceptance.
//! Host-owned slots retain this actual process and journals until independent
//! kernel reclamation. An uncertain established service stays in this process;
//! it never accepts a replacement source, bootstrap or connection.

use std::path::PathBuf;

use crucible_node_contract::canonical;
use crucible_node_provider::{
    ProviderError,
    reference_packet::service::{
        PacketConnectedSourceLaunch, PacketNative5SourceLaunch, PacketSourceLaunch,
        PacketSourceService,
    },
    transport::FrameReader,
};

fn main() {
    if let Err(error) = run() {
        // The private launch body and its credentials are never logged.
        eprintln!("packet private bootstrap refused: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = PathBuf::from(arguments.next().ok_or("expected private packet socket")?);
    if arguments.next().is_some() {
        return Err("unexpected private packet argument".into());
    }
    let value = FrameReader::with_limits(std::io::stdin().lock(), 1024 * 1024, 64)?
        .read()?
        .ok_or("private packet bootstrap unavailable")?;
    let bytes = canonical::canonical_json(&value)?;
    let mut service = match value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
    {
        Some(5) => {
            let launch = PacketNative5SourceLaunch::decode(&bytes, 1024 * 1024)?;
            PacketSourceService::accept_complete(&socket, launch)?
        }
        Some(4) => {
            let launch = PacketConnectedSourceLaunch::decode(&bytes, 1024 * 1024)?;
            PacketSourceService::accept_connected(&socket, launch)?
        }
        _ => {
            let launch = PacketSourceLaunch::decode(&bytes, 1024 * 1024)?;
            PacketSourceService::accept(&socket, launch)?
        }
    };

    loop {
        if let Err(error) = service.step() {
            report_endpoint_failure(&error);
            // Keep the same established endpoint and every uncertain original
            // until its independently owned host slot performs kernel cleanup.
            // Parking has no semantic time or native publication meaning.
            loop {
                std::thread::park();
            }
        }
    }
}

/// Reports only fixed error categories from the first private endpoint failure.
fn report_endpoint_failure(error: &ProviderError) {
    match error {
        ProviderError::Io(error) => {
            eprintln!("packet private endpoint held: I/O {:?}", error.kind());
        }
        ProviderError::Contract(_) => {
            eprintln!("packet private endpoint held: contract validation");
        }
        ProviderError::Frame(reason)
        | ProviderError::Correlation(reason)
        | ProviderError::ResourceExhausted(reason)
        | ProviderError::Conflict(reason) => {
            eprintln!("packet private endpoint held: {reason}");
        }
    }
}
