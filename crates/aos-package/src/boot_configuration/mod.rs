//! Adopts image-authorized platform metadata before the first host deployment.
//!
//! Initial activation inspects the exact committed initrd decision and derives
//! immutable host and facts modules from its authenticated receipt. Recovery and
//! subsequent boots use the normal profile coordinator and retain accepted
//! operator sources instead of reading new platform metadata.

mod capture;
mod proof;
mod reader;
mod retained;

#[cfg(test)]
mod integration;

use anyhow::{Result, ensure};
use aos_ability_runtime::adapter::CancellationToken;
use clap::Parser as _;

#[derive(clap::Parser)]
struct Arguments {
    #[command(flatten)]
    deployment: crate::native_deployment::NativeDeploymentArgs,
}

/// Runs the OS bootstrap bridge with explicit verified image deployment inputs.
///
/// Local source authority comes from the checked committed initrd decision and
/// the verified image admission. The receipt's signer label is not a signature.
/// An independent attestation verifier must pin the original proof digest and
/// exact source NAR map independently; quoted receipt fields cannot supply
/// their own expectations.
///
/// # Errors
/// Returns an error for invalid invocation, missing or uncommitted metadata
/// authority, changed source identities, admission or evaluation failure, or a
/// failed native activation or recovery.
pub fn run_from_process() -> Result<()> {
    let arguments = Arguments::parse();
    let command = arguments.deployment.command()?;
    ensure!(
        command.input == std::path::Path::new("/usr/lib/aos/host/deployment")
            && command.profile.as_deref() == Some(std::path::Path::new("/var/lib/profiles/system"))
            && command.state_directory
                == std::path::Path::new("/var/lib/profiles/system/deployment"),
        "host metadata adoption requires the fixed verified image and system profile"
    );
    ensure!(
        command.admission == command.input.join("admission.json"),
        "host bootstrap admission must come from its verified image bundle"
    );
    let digest_path = std::fs::canonicalize(command.input.join("admission-sha256"))?;
    crate::deployment::nix::store_root_and_suffix(&digest_path)?;
    let digest_bytes = reader::read_bounded(&digest_path, 128)?;
    let digest = std::str::from_utf8(&digest_bytes)?.trim_end_matches('\n');
    ensure!(
        aos_contract::Sha256Digest::parse(digest)? == command.admission_sha256,
        "host admission digest differs from its verified image bundle"
    );
    ensure!(
        std::env::var_os("AOS_NIX_STORE").as_deref() == Some(command.nix_store.as_os_str()),
        "host bootstrap store differs from its retained launcher"
    );
    let cancellation = CancellationToken::default();
    if let Some(number) = crate::native_deployment::resume_profile(&command, &cancellation)? {
        retained::verify(&command, number)?;
        return crate::native_deployment::apply(&command, &cancellation);
    }
    if !reader::metadata_required()? {
        return crate::native_deployment::apply(&command, &cancellation);
    }
    let authorized = reader::read_initial(&command)?;
    capture::apply(&command, authorized, &cancellation)
}
