//! Runs the separately measured finite packet source on its private CNP socket.
//!
//! The inherited launch selects the exact source program, original controller,
//! finite limits and coordinator edition. It issues no ordinary class acceptance.
//! Host-owned slots retain this actual process and journals until independent
//! kernel reclamation. An uncertain established service stays in this process;
//! it never accepts a replacement source, bootstrap or connection.

use std::path::PathBuf;

use crucible_node_format::canonical;
use crucible_node_transport::{
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

// This private argument selects only a strict inherited-channel decoder. Every
// route still obtains authority from actual peer/MAC/row checks, never the flag.
#[derive(Clone, Copy)]
enum PrivateBootstrap {
    Canonical,
    Startup14,
    Invocation15,
    RestoredSuffix16,
    RestoredSettled17,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = PathBuf::from(arguments.next().ok_or("expected private packet socket")?);
    let original_boot = match arguments.next() {
        None => None,
        Some(flag) if flag == "--original-canonical-ack-boot" => Some(PrivateBootstrap::Canonical),
        Some(flag) if flag == "--original-native-startup14" => Some(PrivateBootstrap::Startup14),
        Some(flag) if flag == "--original-native-startup15" => Some(PrivateBootstrap::Invocation15),
        Some(flag) if flag == "--original-native-startup16" => {
            Some(PrivateBootstrap::RestoredSuffix16)
        }
        Some(flag) if flag == "--original-native-startup17" => {
            Some(PrivateBootstrap::RestoredSettled17)
        }
        Some(_) => return Err("unexpected private packet argument".into()),
    };
    if arguments.next().is_some() {
        return Err("unexpected private packet argument".into());
    }
    if let Some(edition) = original_boot {
        if !matches!(edition, PrivateBootstrap::Canonical) && socket.as_os_str().len() > 4096 {
            return Err("native startup socket path exceeds fixed original bound".into());
        }
        let mut service = match edition {
            PrivateBootstrap::Canonical => {
                PacketSourceService::accept_original_private_bootstrap(&socket, std::io::stdin())?
            }
            PrivateBootstrap::Startup14 => {
                PacketSourceService::accept_original_native_startup_bootstrap(&socket)?
            }
            PrivateBootstrap::Invocation15 => {
                PacketSourceService::accept_original_native_invocation_bootstrap(&socket)?
            }
            PrivateBootstrap::RestoredSuffix16 => {
                PacketSourceService::accept_original_restored_suffix_bootstrap(&socket)?
            }
            PrivateBootstrap::RestoredSettled17 => {
                PacketSourceService::accept_original_restored_settled_bootstrap(&socket)?
            }
        };
        return drive(&mut service);
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

    drive(&mut service)
}

fn drive(service: &mut PacketSourceService) -> Result<(), Box<dyn std::error::Error>> {
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
