//! Offline release verification and the verified-bundle context shared by
//! every effectful step.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, anyhow, bail};
use aos_cli_ui::output::Printer;
use aos_release_format::canonical;
use aos_release_format::digest::Sha256Digest;
use aos_release_format::manifest::ManifestEnvelopeV1;
use aos_release_format::plan::ReleasePlan;
use aos_release_format::signing::TrustedEd25519Key;
use aos_release_format::state::parse_journal;
use aos_release_format::verify::VerificationSummary;

use crate::cli::ReleaseVerifyArgs;

use super::capture;

/// A captured bundle whose signatures, closure, and plan were verified.
pub(super) struct VerifiedBundle {
    /// Captured control bytes and file identities.
    pub(super) captured: capture::CapturedBundle,
    /// Parsed frozen plan.
    pub(super) plan: ReleasePlan,
    /// Parsed signed manifest envelope.
    pub(super) manifest: ManifestEnvelopeV1,
    /// Verification summary, including plan and manifest digests.
    pub(super) summary: VerificationSummary,
    /// Closed bundle identity bound by receipts.
    pub(super) bundle_digest: Sha256Digest,
    /// Release-evidence keys that verified the manifest.
    pub(super) manifest_keys: Vec<TrustedEd25519Key>,
}

/// Captures and verifies a bundle that may cross a publication boundary.
///
/// # Errors
/// Returns an error for an unreadable bundle, invalid trust input, failed
/// verification, or a plan that is invalid or a qualification snapshot.
pub(super) fn verified_bundle(path: &Path, key_specs: &[String]) -> Result<VerifiedBundle> {
    let captured = capture::bundle(path)?;
    let manifest_keys = load_trusted_keys(key_specs)?;
    let summary = aos_release_format::verify::verify_release(
        &captured.plan_bytes,
        &captured.manifest_bytes,
        &captured.files,
        &manifest_keys,
    )?;
    let plan: ReleasePlan = canonical::from_slice(&captured.plan_bytes, "release plan")?;
    plan.require_publishable_qualification()?;
    let manifest: ManifestEnvelopeV1 =
        canonical::from_slice(&captured.manifest_bytes, "release manifest")?;
    let bundle_digest =
        aos_release_format::verify::bundle_digest(&captured.manifest_bytes, &captured.files)?;
    Ok(VerifiedBundle {
        captured,
        plan,
        manifest,
        summary,
        bundle_digest,
        manifest_keys,
    })
}

/// Verifies one release bundle and optional restricted journal offline.
pub(super) fn run(args: &ReleaseVerifyArgs, printer: &Printer) -> Result<()> {
    let captured = capture::bundle(&args.bundle)?;
    let trusted_keys = load_trusted_keys(&args.trusted_keys)?;
    let summary = aos_release_format::verify::verify_release(
        &captured.plan_bytes,
        &captured.manifest_bytes,
        &captured.files,
        &trusted_keys,
    )?;

    let journal_state = args
        .journal
        .as_ref()
        .map(|path| {
            let bytes = capture::control_file(path, "release journal")?;
            let entries = parse_journal(&bytes)?;
            aos_release_format::verify::verify_journal(&entries)
        })
        .transpose()?;
    if printer.json_if_active(&serde_json::json!({
        "verification": summary,
        "journal_state": journal_state,
    })) {
        return Ok(());
    }
    printer.success(&format!(
        "Verified release {} ({}) with {} artifacts and {} manifest signature(s)",
        summary.release_id, summary.version, summary.artifact_count, summary.signatures_verified
    ));
    if let Some(summary) = journal_state {
        printer.info(&format!("Journal state: {}", summary.global));
        for (destination, state) in &summary.destinations {
            printer.kv(destination, &state.to_string());
        }
    }
    Ok(())
}

pub(super) fn load_trusted_keys(specifications: &[String]) -> Result<Vec<TrustedEd25519Key>> {
    let mut ids = BTreeSet::new();
    specifications
        .iter()
        .map(|specification| {
            let (key_id, path) = specification
                .split_once('=')
                .ok_or_else(|| anyhow!("trusted key must use KEY_ID=PATH"))?;
            if !ids.insert(key_id) {
                bail!("duplicate trusted key id: {key_id}");
            }
            let bytes = capture::control_file(path.as_ref(), "trusted public key")?;
            TrustedEd25519Key::from_encoded(key_id, &bytes)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use aos_release_format::state::parse_journal;

    #[test]
    fn journal_requires_canonical_nonempty_jsonl() {
        assert!(parse_journal(b"\n").is_err());
        assert!(parse_journal(b"{} ").is_err());
        assert!(parse_journal(b"{}\n").is_err());
    }
}
