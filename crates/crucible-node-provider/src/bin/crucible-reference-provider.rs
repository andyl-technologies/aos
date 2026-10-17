//! Private-bootstrap public CNP endpoint for the controlled checksum provider.

use std::path::PathBuf;

use crucible_node_contract::{Validate, canonical};
use crucible_node_provider::{
    reference_service::{
        ReferenceServiceBootstrap, ReferenceServiceInstalledLaunchBootstrap,
        ReferenceServiceLaunchBootstrap,
    },
    transport::FrameReader,
};

fn main() {
    if run().is_err() {
        // Private bootstrap and native paths can carry credentials; expose only
        // a fixed operational failure diagnostic.
        eprintln!("reference provider failed");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let socket = PathBuf::from(arguments.next().ok_or("expected socket path")?);
    let child = PathBuf::from(
        arguments
            .next()
            .ok_or("expected source-built child executable")?,
    );
    if arguments.next().is_some() {
        return Err("unexpected provider argument".into());
    }
    let value = FrameReader::with_limits(std::io::stdin().lock(), 16 * 1024 * 1024, 64)?
        .read()?
        .ok_or("private bootstrap missing")?;
    let bytes = canonical::canonical_json(&value)?;
    if value.get("schema_version") == Some(&serde_json::json!(3)) {
        let launch: ReferenceServiceInstalledLaunchBootstrap =
            canonical::decode(&bytes, 16 * 1024 * 1024)?;
        crucible_node_provider::reference_service::serve_installed(&socket, &child, launch)?;
    } else if value.get("schema_version").is_some() {
        let launch: ReferenceServiceLaunchBootstrap = canonical::decode(&bytes, 16 * 1024 * 1024)?;
        launch.validate()?;
        crucible_node_provider::reference_service::serve_selected(
            &socket,
            &child,
            launch.bootstrap,
            launch.profile,
        )?;
    } else {
        let bootstrap: ReferenceServiceBootstrap = canonical::decode(&bytes, 16 * 1024 * 1024)?;
        bootstrap.validate()?;
        crucible_node_provider::reference_service::serve(&socket, &child, bootstrap)?;
    }
    Ok(())
}
