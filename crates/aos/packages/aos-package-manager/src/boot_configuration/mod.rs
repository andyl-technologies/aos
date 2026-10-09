//! Adopts image-authorized platform metadata before the first host deployment.
//!
//! Initial activation inspects the exact committed initrd decision and derives
//! immutable host and facts modules from its authenticated receipt. Recovery and
//! subsequent boots use the normal profile coordinator and retain accepted
//! operator sources instead of reading new platform metadata.

mod capture;
mod handoff;
mod image;
mod proof;
mod reader;
mod retained;

#[cfg(test)]
mod integration;

use anyhow::{Result, ensure};
use aos_activation::adapter::CancellationToken;
use clap::Parser as _;

#[derive(clap::Parser)]
struct Arguments {
    #[command(flatten)]
    deployment: crate::native_deployment::NativeDeploymentArgs,
    /// Verify completion without recovering or applying the deployment.
    #[arg(long)]
    verify: bool,
}

/// Runs host adoption, read-only completion verification, or initrd receipt handoff.
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
/// failed native activation, recovery, completion verification, or receipt
/// transfer to the host store.
pub fn run_from_process() -> Result<()> {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "handoff-initrd-store")
    {
        return handoff::run_from_process();
    }
    let arguments = Arguments::parse();
    let mut command = arguments.deployment.command()?;
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
    aos_deployment::nix::store_root_and_suffix(&digest_path)?;
    let digest_bytes = reader::read_bounded(&digest_path, 128)?;
    let digest = std::str::from_utf8(&digest_bytes)?.trim_end_matches('\n');
    ensure!(
        aos_core::Sha256Digest::parse(digest)? == command.admission_sha256,
        "host admission digest differs from its verified image bundle"
    );
    ensure!(
        std::env::var_os("AOS_NIX_STORE").as_deref() == Some(command.nix_store.as_os_str()),
        "host bootstrap store differs from its retained launcher"
    );
    // The verified image copy preserves member aliases; evaluation requires
    // the original registered bundle identity retained by its toplevel.
    command.input = image::retained_bundle(
        &command.input,
        std::path::Path::new("/usr/lib/aos/toplevel"),
    )?;
    command.admission = command.input.join("admission.json");
    run_host_command(&command, arguments.verify)
}

fn run_host_command(
    command: &crate::native_deployment::NativeDeploymentCommand,
    verify_only: bool,
) -> Result<()> {
    if verify_only {
        return crate::native_deployment::verify(command);
    }

    let cancellation = CancellationToken::default();
    if let Some(recovered) =
        crate::native_deployment::recover_profile_publication(command, &cancellation)?
    {
        retained::verify(command, recovered.generation)?;
        return crate::native_deployment::apply_after_recovery(command, &cancellation, &recovered);
    }
    if !reader::metadata_required()? {
        return crate::native_deployment::apply(command, &cancellation);
    }
    let authorized = reader::read_initial(command)?;
    capture::apply(command, authorized, &cancellation)
}
