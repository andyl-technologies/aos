//! Native explicit swap formatting with crash recovery receipts.
//!
//! Removal releases the receipt without erasing the durable device format.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{native_state as state, process::run_native};

const ROOT: &str = "/run/aos/native-storage-formats";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    name: String,
    source: String,
    format: Format,
    policy: Policy,
    mkswap: PathBuf,
    blkid: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Format {
    Swap,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Policy {
    Always,
    IfAbsent,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    id: String,
    revision: String,
    source: String,
    pending: bool,
}

/// Executes an explicit native formatting invocation.
///
/// # Errors
/// Returns an error for malformed inputs, incompatible existing formats,
/// inaccessible devices, corrupt receipts, or failed util-linux commands.
pub fn handle(action: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let invocation: Invocation = serde_json::from_slice(bytes)?;
    ensure!(
        matches!(action, "apply" | "remove" | "observe"),
        "unsupported format action"
    );
    ensure!(
        action == "observe"
            || matches!(
                (action, invocation.action),
                ("apply", Action::Apply) | ("remove", Action::Remove)
            ),
        "action differs from invocation"
    );
    let input: Input = serde_json::from_value(invocation.input.clone())?;
    validate(&input)?;
    let root = Path::new(ROOT);
    let _lock = state::Lock::acquire(root)?;
    let receipt: Option<Receipt> = state::read(root, &invocation.id)?;
    if let Some(receipt) = &receipt {
        ensure!(
            receipt.id == invocation.id,
            "format receipt belongs to another effect"
        );
    }

    if action == "remove" {
        state::remove(root, &invocation.id)?;
        return Ok(serde_json::to_vec(&json!({}))?);
    }
    if action == "observe" && invocation.action == Action::Remove {
        return Ok(serde_json::to_vec(
            &json!({"status": if receipt.is_none() {"absent"} else {"retry-safe"}}),
        )?);
    }

    let source = fs::canonicalize(&input.source)
        .with_context(|| format!("resolving format source {}", input.source))?
        .to_str()
        .context("format source is not UTF-8")?
        .to_owned();
    let observed = inspect(&input.blkid, &source)?;
    let current = exact(
        &invocation.revision,
        receipt.as_ref(),
        &source,
        observed.as_deref(),
    );
    let outputs = json!({"path": input.source, "resource": invocation.id});
    if action == "observe" {
        return Ok(serde_json::to_vec(&if current {
            json!({"status":"current", "outputs": outputs})
        } else {
            json!({"status":"retry-safe"})
        })?);
    }
    if current {
        return Ok(serde_json::to_vec(&outputs)?);
    }

    // A completed pending receipt plus an exact swap signature proves the
    // preceding mutation succeeded, even if its final receipt write did not.
    if matches!(input.policy, Policy::IfAbsent)
        && let Some(format) = &observed
    {
        ensure!(
            format == "swap",
            "refusing to replace existing storage format {format:?}"
        );
    } else {
        let receipt = Receipt {
            id: invocation.id.clone(),
            revision: invocation.revision.clone(),
            source: source.clone(),
            pending: true,
        };
        state::write(root, &invocation.id, &receipt)?;
        let result = run_native(
            &input.mkswap,
            &["--", &source],
            invocation.effect.timeout_ms,
        )?;
        ensure!(
            result.status.success(),
            "mkswap failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        ensure!(
            inspect(&input.blkid, &source)?.as_deref() == Some("swap"),
            "format mutation did not produce swap"
        );
    }
    state::write(
        root,
        &invocation.id,
        &Receipt {
            id: invocation.id.clone(),
            revision: invocation.revision.clone(),
            source,
            pending: false,
        },
    )?;
    Ok(serde_json::to_vec(&outputs)?)
}

fn exact(revision: &str, receipt: Option<&Receipt>, source: &str, observed: Option<&str>) -> bool {
    observed == Some("swap")
        && receipt.is_some_and(|receipt| receipt.revision == revision && receipt.source == source)
}

fn inspect(executable: &Path, source: &str) -> Result<Option<String>> {
    let output = run_native(
        executable,
        &["-p", "-o", "value", "-s", "TYPE", "--", source],
        5_000,
    )?;
    if !output.status.success() {
        ensure!(
            output.status.code() == Some(2),
            "blkid inspection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)?.trim().to_owned();
    Ok((!value.is_empty()).then_some(value))
}

fn validate(input: &Input) -> Result<()> {
    ensure!(
        !input.name.is_empty()
            && input.name.len() <= 128
            && input
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')),
        "invalid format name"
    );
    let path = Path::new(&input.source);
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "format source is not a normalized absolute path"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambient_matching_format_is_unmanaged() {
        assert!(!exact("desired", None, "/dev/dm-0", Some("swap")));
    }

    #[test]
    fn old_receipt_cannot_satisfy_new_revision() {
        let receipt = Receipt {
            id: "swap".into(),
            revision: "old".into(),
            source: "/dev/dm-0".into(),
            pending: false,
        };
        assert!(!exact("desired", Some(&receipt), "/dev/dm-0", Some("swap")));
    }

    #[test]
    fn pending_receipt_and_exact_format_prove_recovery() {
        let receipt = Receipt {
            id: "swap".into(),
            revision: "desired".into(),
            source: "/dev/dm-0".into(),
            pending: true,
        };
        assert!(exact("desired", Some(&receipt), "/dev/dm-0", Some("swap")));
        assert!(!exact("desired", Some(&receipt), "/dev/dm-1", Some("swap")));
    }

    #[test]
    fn validation_rejects_relative_and_traversing_sources() {
        let mut input = Input {
            name: "swap".into(),
            source: "/dev/mapper/swap".into(),
            format: Format::Swap,
            policy: Policy::Always,
            mkswap: PathBuf::new(),
            blkid: PathBuf::new(),
        };
        validate(&input).unwrap();

        input.source = "dev/swap".into();
        assert!(validate(&input).is_err());
        input.source = "/dev/../swap".into();
        assert!(validate(&input).is_err());
    }
}
