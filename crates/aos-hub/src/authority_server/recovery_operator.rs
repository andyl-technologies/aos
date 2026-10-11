//! Bounded private inspect, independent sign and explicit resolve file operations.
//!
//! Each command accepts explicit operator coordinates. No command provisions a
//! credential, reads issuance keys, performs provider work or infers readiness.
//! Output is a create-new owner-private canonical document, never stdout secrets.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use anyhow::{ensure, Context as _, Result};

use super::AuthorityConfiguration;
use crate::authority_journal::recovery::{
    self, ClockRecoveryPlan, ClockRecoveryPolicy, ClockRecoveryReceipt, ClockRecoveryReview,
    MAX_CLOCK_RECOVERY_BYTES,
};

/// Exports a bounded unchanged head and one nominated successor for review.
///
/// # Errors
/// Returns an error for active owners, invalid state/configuration or output custody.
pub fn inspect(configuration: &AuthorityConfiguration, output: &Path) -> Result<()> {
    let journal = configuration.open_recovery_journal()?;
    let policy = configuration
        .clock_recovery
        .as_ref()
        .context("recovery policy missing")?;
    let plan = journal.inspect_clock_session(policy)?;
    write_new(output, &recovery::encode(&plan)?)
}

/// Signs a complete plan with the independently held pinned reviewer seed.
///
/// The caller selects its already qualified public policy, independent from the
/// issuer's command configuration. Seed custody is checked and never provisioned.
///
/// # Errors
/// Returns an error for invalid/private inputs, changed reviewer or output custody.
pub fn sign(policy: &Path, plan: &Path, reviewer_seed: &Path, output: &Path) -> Result<()> {
    let policy: ClockRecoveryPolicy = read_document(policy)?;
    let plan: ClockRecoveryPlan = read_document(plan)?;
    let bytes = crate::auth::seal::read_secret_file_zeroizing_capped(reviewer_seed, 128)?;
    let material = zeroize::Zeroizing::new(crate::auth::seal::parse_key(&bytes)?);
    let seed: [u8; 32] = material
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("independent reviewer seed must contain exactly 32 bytes"))?;
    let seed = zeroize::Zeroizing::new(seed);
    let review = ClockRecoveryReview::sign(plan, &policy, &seed)?;
    write_new(output, &recovery::encode(&review)?)
}

/// Resolves one inactive exact original and exports its acknowledged positive.
///
/// Exact retry after lost output reads the retained positive under a fresh
/// qualified clock; it does not undo or invent an uncertain resolution.
///
/// # Errors
/// Returns an error for changed/stale reviews, active owners, time failures,
/// indeterminate commit or output custody. Failed output does not undo the receipt.
pub fn resolve(configuration: &AuthorityConfiguration, review: &Path, output: &Path) -> Result<()> {
    let review: ClockRecoveryReview = read_document(review)?;
    let journal = configuration.open_recovery_journal()?;
    let policy = configuration
        .clock_recovery
        .as_ref()
        .context("recovery policy missing")?;
    let receipt = journal.resolve_clock_session(policy, &review)?;
    write_new(output, &recovery::encode(&receipt)?)
}

/// Reads the exact bounded canonical positive for an explicit successor start.
///
/// # Errors
/// Returns an error for insecure, oversized, malformed or noncanonical input.
pub fn read_receipt(path: &Path) -> Result<ClockRecoveryReceipt> {
    read_document(path)
}

fn read_document<T: serde::de::DeserializeOwned + serde::Serialize>(path: &Path) -> Result<T> {
    let bytes = crate::auth::seal::read_secret_file_zeroizing_capped(
        path,
        MAX_CLOCK_RECOVERY_BYTES as u64,
    )?;
    recovery::decode(&bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_CLOCK_RECOVERY_BYTES,
        "recovery output exceeds bound"
    );
    let parent = path
        .parent()
        .context("recovery output requires private parent")?;
    ensure!(
        path.is_absolute() && std::fs::canonicalize(parent)? == parent,
        "recovery output must have exact absolute parent"
    );
    let original = std::fs::symlink_metadata(parent)?;
    ensure!(
        original.is_dir()
            && original.uid() == rustix::process::geteuid().as_raw()
            && original.mode() & 0o7777 == 0o700,
        "recovery output parent must be owner-private"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32)
        .open(parent)?;
    let current = directory.metadata()?;
    ensure!(
        current.dev() == original.dev() && current.ino() == original.ino(),
        "recovery output parent changed"
    );
    directory.sync_all()?;
    let retained = std::fs::symlink_metadata(path)?;
    let written = file.metadata()?;
    ensure!(
        retained.dev() == written.dev()
            && retained.ino() == written.ino()
            && retained.nlink() == 1
            && retained.mode() & 0o7777 == 0o600,
        "recovery output was replaced"
    );
    Ok(())
}
