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
    #[command(about = "Create new owner-private External Mirror functional reviewer keys")]
    MirrorFunctionalFixtureKey {
        /// Create a new raw ephemeral seed file.
        #[arg(long)]
        private_output: PathBuf,
        /// Create its separate public verifier file.
        #[arg(long)]
        public_output: PathBuf,
    },
    #[command(about = "Prepare a finite External Mirror functional candidate from actual inputs")]
    MirrorFunctionalPrepare {
        /// Select closed actual retained inputs and installed files.
        #[arg(long)]
        selection_file: PathBuf,
        /// Create a new unsigned candidate for independent review.
        #[arg(long)]
        output: PathBuf,
    },
    #[command(about = "Sign only an explicitly reviewed External Mirror functional candidate")]
    MirrorFunctionalSign {
        /// Recheck exact actual selected inputs.
        #[arg(long)]
        selection_file: PathBuf,
        /// Read the independently reviewed candidate.
        #[arg(long)]
        candidate_file: PathBuf,
        /// Require its explicit reviewed lowercase SHA-256.
        #[arg(long)]
        candidate_sha256: String,
        /// Select only the private ephemeral functional reviewer seed.
        #[arg(long)]
        reviewer_key_file: PathBuf,
        /// Match the separately installed functional verifier.
        #[arg(long)]
        reviewer_public_key_file: PathBuf,
        /// Create a new signed functional-only artifact.
        #[arg(long)]
        output: PathBuf,
    },
    #[command(about = "Verify functional artifact bytes against current actual selected inputs")]
    MirrorFunctionalVerify {
        /// Reopen exact current actual inputs.
        #[arg(long)]
        selection_file: PathBuf,
        /// Read the signed bounded functional artifact.
        #[arg(long)]
        artifact_file: PathBuf,
    },
    #[command(about = "Derive only the shared Rust External Mirror functional KV address")]
    MirrorFunctionalRegistryKey {
        /// Reopen exact current actual inputs.
        #[arg(long)]
        selection_file: PathBuf,
        /// Verify the actual signed functional artifact before deriving its slot.
        #[arg(long)]
        artifact_file: PathBuf,
    },
    #[command(about = "Create new owner-private ephemeral OCI fixture reviewer keys")]
    OciSdkFixtureKey {
        /// Create a new raw 32-byte seed; never select an existing signing key.
        #[arg(long)]
        private_output: PathBuf,
        /// Create its separate public verifier file.
        #[arg(long)]
        public_output: PathBuf,
    },
    #[command(about = "Observe an actual owned Native process and exact executable")]
    OciSdkObserveNative {
        /// Select the actual running Native PID.
        #[arg(long)]
        pid: u32,
        /// Select its current source-built ELF.
        #[arg(long)]
        executable: PathBuf,
        /// Create new private argv/environment capture.
        #[arg(long)]
        configuration_output: PathBuf,
        /// Create new process/executable observation.
        #[arg(long)]
        observation_output: PathBuf,
    },
    #[command(about = "Prepare an OCI-only SDK candidate from selected actual captures")]
    OciSdkPrepare {
        /// Select closed independently retained inputs.
        #[arg(long)]
        selection_file: PathBuf,
        /// Create a new unsigned candidate.
        #[arg(long)]
        output: PathBuf,
    },
    #[command(about = "Sign an exact reviewed OCI-only fixture candidate")]
    OciSdkSign {
        /// Recheck exact selected actual inputs.
        #[arg(long)]
        selection_file: PathBuf,
        /// Select the independently reviewed candidate.
        #[arg(long)]
        candidate_file: PathBuf,
        /// Require its explicit reviewed SHA-256.
        #[arg(long)]
        candidate_sha256: String,
        /// Select only the ephemeral owner-private fixture seed.
        #[arg(long)]
        reviewer_key_file: PathBuf,
        /// Match the separately installed public verifier.
        #[arg(long)]
        reviewer_public_key_file: PathBuf,
        /// Create a new signed OCI-only artifact.
        #[arg(long)]
        output: PathBuf,
    },
    #[command(about = "Verify an OCI-only artifact without installing or dispatching work")]
    OciSdkVerify {
        /// Read the exact owner-private artifact.
        #[arg(long)]
        artifact_file: PathBuf,
        /// Select the separately installed public verifier.
        #[arg(long)]
        reviewer_public_key_file: PathBuf,
        /// Require the separately installed reviewer identity.
        #[arg(long)]
        reviewer_key_id: String,
        /// Require the expected deployment.
        #[arg(long)]
        deployment_id: String,
        /// Require the expected local Worker HTTPS origin.
        #[arg(long)]
        public_origin: String,
        /// Require the actual current compiled source digest.
        #[arg(long)]
        source_digest: String,
        /// Require its exact current script identity.
        #[arg(long)]
        script_version: String,
    },
    #[command(about = "Derive only the separate OCI emulator acceptance slot")]
    OciSdkRegistryKey {
        /// Select the actual deployment.
        #[arg(long)]
        deployment_id: String,
        /// Select actual current compiled source.
        #[arg(long)]
        source_digest: String,
        /// Select its exact current script.
        #[arg(long)]
        script_version: String,
    },

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
        Command::MirrorFunctionalFixtureKey {
            private_output,
            public_output,
        } => aos_hub::external_mirror_review::create_external_mirror_fixture_key(
            &private_output,
            &public_output,
        ),
        Command::MirrorFunctionalPrepare {
            selection_file,
            output,
        } => aos_hub::external_mirror_review::prepare_external_mirror_review(
            &selection_file,
            &output,
        ),
        Command::MirrorFunctionalSign {
            selection_file,
            candidate_file,
            candidate_sha256,
            reviewer_key_file,
            reviewer_public_key_file,
            output,
        } => aos_hub::external_mirror_review::sign_external_mirror_review(
            &selection_file,
            &candidate_file,
            &candidate_sha256,
            &reviewer_key_file,
            &reviewer_public_key_file,
            &output,
        ),
        Command::MirrorFunctionalVerify {
            selection_file,
            artifact_file,
        } => aos_hub::external_mirror_review::verify_external_mirror_review(
            &selection_file,
            &artifact_file,
        ),
        Command::MirrorFunctionalRegistryKey {
            selection_file,
            artifact_file,
        } => aos_hub::external_mirror_review::external_mirror_registry_key(
            &selection_file,
            &artifact_file,
        ),
        Command::OciSdkFixtureKey {
            private_output,
            public_output,
        } => aos_hub::oci_sdk_review::create_oci_sdk_fixture_key(&private_output, &public_output),
        Command::OciSdkObserveNative {
            pid,
            executable,
            configuration_output,
            observation_output,
        } => aos_hub::oci_sdk_review::observe_oci_sdk_native(
            pid,
            &executable,
            &configuration_output,
            &observation_output,
        ),
        Command::OciSdkPrepare {
            selection_file,
            output,
        } => aos_hub::oci_sdk_review::prepare_oci_sdk_review(&selection_file, &output),
        Command::OciSdkSign {
            selection_file,
            candidate_file,
            candidate_sha256,
            reviewer_key_file,
            reviewer_public_key_file,
            output,
        } => aos_hub::oci_sdk_review::sign_oci_sdk_review(
            &selection_file,
            &candidate_file,
            &candidate_sha256,
            &reviewer_key_file,
            &reviewer_public_key_file,
            &output,
        ),
        Command::OciSdkVerify {
            artifact_file,
            reviewer_public_key_file,
            reviewer_key_id,
            deployment_id,
            public_origin,
            source_digest,
            script_version,
        } => aos_hub::oci_sdk_review::verify_oci_sdk_review(
            &artifact_file,
            &reviewer_public_key_file,
            &reviewer_key_id,
            &deployment_id,
            &public_origin,
            &source_digest,
            &script_version,
        ),
        Command::OciSdkRegistryKey {
            deployment_id,
            source_digest,
            script_version,
        } => aos_hub_core::oci_sdk_emulation::oci_sdk_emulation_acceptance_key(
            &deployment_id,
            &source_digest,
            &script_version,
        ),
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
