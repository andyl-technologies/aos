//! Assembles bounded certificate-source JSON into validated PEM on stdout.
//!
//! Accepts `[ { "kind": "store-file", "path": "/nix/store/.../ca.pem" } ]`
//! on stdin. Diagnostics go to stderr; stdout contains only bundle bytes.

use std::io::{self, Read as _, Write as _};

use anyhow::{Result, ensure};
use aos_configuration_lower::{certificate_bundle, model::CertificatePart};

fn main() {
    if let Err(error) = run() {
        eprintln!("aos-certificate-bundle: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    ensure!(
        std::env::args_os().len() == 1,
        "expected certificate-source JSON on stdin"
    );
    let mut input = Vec::new();
    io::stdin().take(1024 * 1024 + 1).read_to_end(&mut input)?;
    ensure!(
        input.len() <= 1024 * 1024,
        "certificate input exceeds its JSON bound"
    );
    let parts: Vec<CertificatePart> = serde_json::from_slice(&input)?;
    io::stdout().write_all(&certificate_bundle(&parts)?)?;
    Ok(())
}
