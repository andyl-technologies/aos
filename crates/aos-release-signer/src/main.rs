//! File-backed signing adapter for canonical AOS releases.
//!
//! `aos release` commands never touch private keys; they invoke a
//! deployment-configured executable with the `sign-exchange-v1` operation and
//! verify whatever comes back against independently pinned public material.
//! This binary is such an executable for deployments whose keys live in
//! operator-owned files rather than an HSM or remote signing service, such as
//! the `andyl/testing` registry.
//!
//! Modules:
//!
//! - [`config`] describes the JSON configuration that maps key ids to files.
//! - [`keys`] loads private keys and derives their public identities.
//! - [`exchange`] frames requests and responses on standard input and output.
//! - [`sign`] authorizes a request and selects the signature mechanism.
//! - [`image`] performs Authenticode, kernel-module, and PCR-policy transforms.
//! - [`envelope`] signs operator approvals as release-evidence envelopes.
//!
//! The configuration path comes from `--config` or the
//! `AOS_RELEASE_SIGNER_CONFIG` environment variable. A successful
//! `sign-exchange-v1` writes nothing to standard error, because the
//! coordinator treats any diagnostic as a failed operation.

mod config;
mod envelope;
mod exchange;
mod image;
mod keys;
mod sign;

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use aos_release::canonical;
use clap::{Parser, Subcommand};

use crate::config::SignerConfigV1;
use crate::keys::LoadedKey;

#[derive(Parser)]
#[command(name = "aos-release-signer", version, about = None, long_about = None)]
struct Cli {
    /// Configuration file; defaults to $AOS_RELEASE_SIGNER_CONFIG
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve one framed signing request from standard input (coordinator protocol)
    #[command(name = "sign-exchange-v1")]
    SignExchangeV1,
    /// Sign a canonical approval payload into a release-evidence envelope
    SignEvidence {
        /// Configured Ed25519 key id that approves the payload
        #[arg(long)]
        key_id: String,
        /// Canonical JSON payload to sign
        #[arg(long)]
        payload: PathBuf,
        /// New envelope path; existing files are never replaced
        #[arg(long)]
        output: PathBuf,
    },
    /// Load the configuration and print each key's public identity
    Show,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-release-signer: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let config = SignerConfigV1::load(cli.config.as_deref())?;
    match cli.command {
        Command::SignExchangeV1 => sign_exchange(&config),
        Command::SignEvidence {
            key_id,
            payload,
            output,
        } => sign_evidence(&config, &key_id, &payload, &output),
        Command::Show => show(&config),
    }
}

/// Reads one request, signs it, and writes the framed response.
///
/// The response is fully computed before the first byte reaches standard
/// output, so a refused request leaves the stream empty.
fn sign_exchange(config: &SignerConfigV1) -> Result<()> {
    let mut stdin = io::stdin().lock();
    let request = exchange::read_request(&mut stdin)?;
    let signed = sign::sign_exchange(config, &request)?;
    let response = canonical::to_vec(&signed.response)?;

    let mut stdout = io::stdout().lock();
    exchange::write_response(&mut stdout, &response, &signed.output)
}

fn sign_evidence(
    config: &SignerConfigV1,
    key_id: &str,
    payload: &Path,
    output: &Path,
) -> Result<()> {
    let mut bytes = Vec::new();
    File::open(payload)
        .with_context(|| format!("opening payload {}", payload.display()))?
        .read_to_end(&mut bytes)?;
    let envelope = envelope::sign_evidence(config, key_id, &bytes)?;

    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(output)
        .with_context(|| format!("creating envelope {}", output.display()))?;
    file.write_all(&envelope)?;
    file.sync_all()?;
    println!("Wrote signed evidence envelope {}", output.display());
    Ok(())
}

fn show(config: &SignerConfigV1) -> Result<()> {
    println!("provider_revision: {}", config.provider_revision);
    println!("registries: {}", config.registries.join(", "));
    for entry in &config.keys {
        let key = LoadedKey::load(&entry.material)
            .with_context(|| format!("loading key {}", entry.key_id))?;
        let roles: Vec<String> = entry.roles.iter().map(|role| format!("{role:?}")).collect();
        println!(
            "{}: roles=[{}] identity={} material-digest={} public={}",
            entry.key_id,
            roles.join(", "),
            entry.verification_identity,
            key.verification_material_digest()?,
            key.public_summary()
        );
    }
    Ok(())
}
