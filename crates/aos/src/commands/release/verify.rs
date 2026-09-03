//! Offline release verification command.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use aos_core::output::Printer;
use aos_release::signing::TrustedEd25519Key;
use aos_release::state::parse_journal;

use crate::cli::ReleaseVerifyArgs;

use super::capture;

/// Verifies one release bundle and optional restricted journal offline.
pub(super) fn run(args: &ReleaseVerifyArgs, printer: &Printer) -> Result<()> {
    let captured = capture::bundle(&args.bundle)?;
    let trusted_keys = load_trusted_keys(&args.trusted_keys)?;
    let summary = aos_release::verify::verify_release(
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
            aos_release::verify::verify_journal(&entries)
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
    if let Some(state) = journal_state {
        printer.info(&format!("Journal state: {state:?}"));
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
    use aos_release::state::parse_journal;

    #[test]
    fn journal_requires_canonical_nonempty_jsonl() {
        assert!(parse_journal(b"\n").is_err());
        assert!(parse_journal(b"{} ").is_err());
        assert!(parse_journal(b"{}\n").is_err());
    }
}
