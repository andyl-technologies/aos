//! Explicit independent measured-acceptance preparation and signing CLI.
//!
//! This offline operator tool consumes exact reviewed files and protected key
//! custody. It writes public candidates or signed artifacts without deploying or
//! activating a Worker. The selection formats live in `direct_upload_review`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aos-hub-direct-review")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Derive the public lookup key for an exact unchanged script")]
    RegistryKey {
        /// Select the observed deployment audience.
        #[arg(long)]
        deployment_id: String,
        /// Select the observed compiled source digest.
        #[arg(long)]
        source_digest: String,
        /// Select the exact observed script identity.
        #[arg(long)]
        script_version: String,
    },
    #[command(about = "Encode a fixed clock policy before measurement")]
    ClockPolicy {
        /// Select conservative uncertainty before deployment and measurement.
        #[arg(long)]
        uncertainty_seconds: u64,
    },
    #[command(about = "Prepare an unsigned candidate from selected raw observations")]
    Prepare {
        /// Select exact installed facts, observations and file hashes.
        #[arg(long)]
        selection_file: PathBuf,
        /// Create a new unsigned candidate file.
        #[arg(long)]
        output: PathBuf,
    },
    #[command(about = "Sign an explicitly reviewed candidate under the installed verifier")]
    Sign {
        /// Recheck the exact selection used during preparation.
        #[arg(long)]
        selection_file: PathBuf,
        /// Read the independently reviewed unsigned candidate.
        #[arg(long)]
        candidate_file: PathBuf,
        /// Require its explicitly reviewed lowercase SHA-256.
        #[arg(long)]
        candidate_sha256: String,
        /// Read the protected file containing exactly 32 raw Ed25519 seed bytes.
        #[arg(long)]
        reviewer_key_file: PathBuf,
        /// Match the independently installed lowercase hex public verifier.
        #[arg(long)]
        reviewer_public_key_file: PathBuf,
        /// Create a new independently signed artifact file.
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> std::process::ExitCode {
    let result = match Cli::parse().command {
        Command::RegistryKey {
            deployment_id,
            source_digest,
            script_version,
        } => aos_hub_core::direct_upload::direct_worker_acceptance_key(
            &deployment_id,
            &source_digest,
            &script_version,
        ),
        Command::ClockPolicy {
            uncertainty_seconds,
        } => aos_hub::direct_upload_review::direct_upload_review_clock_policy(uncertainty_seconds),
        Command::Prepare {
            selection_file,
            output,
        } => aos_hub::direct_upload_review::prepare_direct_upload_review(&selection_file, &output),
        Command::Sign {
            selection_file,
            candidate_file,
            candidate_sha256,
            reviewer_key_file,
            reviewer_public_key_file,
            output,
        } => aos_hub::direct_upload_review::sign_direct_upload_review(
            &selection_file,
            &candidate_file,
            &candidate_sha256,
            &reviewer_key_file,
            &reviewer_public_key_file,
            &output,
        ),
    };
    match result {
        Ok(hash) => {
            println!("{hash}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
