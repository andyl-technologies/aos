//! Restores receipt-owned account rows from authenticated retained invocations.
//!
//! The package runtime supplies the checked authority across the process
//! boundary. Durable backend receipts alone never authorize restoring a row.
//! Every receipt and projected database is checked before any live write.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_ability_runtime::activation::{Action, Invocation};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    Account, Membership, Receipt, check_rows, database, desired, install_rows, membership_snapshot,
    name, principal_row, read_regular, reconcile_members, replacement_target, write_database,
    write_membership_snapshot,
};

const BATCH_LIMIT: usize = 67_108_864;
const EFFECT_LIMIT: usize = 16_384;
const JOURNAL_WRAPPER_DEPTH: usize = 4;
const JOURNAL_WRAPPER_ITEMS: usize = 16;
const EXPORT_WRAPPER_DEPTH: usize = 2;
const EXPORT_WRAPPER_ITEMS: usize = 5 + 3 * EFFECT_LIMIT;
const DATABASES: [&str; 4] = ["group", "gshadow", "passwd", "shadow"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    schema: String,
    scope: Vec<String>,
    effects: Vec<RetainedEffect>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedEffect {
    invocation: Invocation,
    outputs: Value,
}

/// Restores backend-owned identities from the checked system profile export.
///
/// # Errors
/// Returns an error for invalid authority, incomplete or conflicting receipts,
/// database conflicts, unavailable pinned shells, or failed durable writes.
pub(crate) fn restore(bytes: &[u8], shells: Option<(&str, &str)>) -> Result<()> {
    super::super::private_directory(Path::new(super::super::STATE_ROOT))?;
    let lock = lock(Path::new(super::super::STATE_ROOT), ".lock")?;
    let result = restore_at(
        Path::new("/etc"),
        Path::new(super::super::STATE_ROOT),
        bytes,
        shells,
    );
    drop(lock);
    result
}

fn lock(root: &Path, filename: &str) -> Result<fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(root.join(filename))?;
    if filename == ".pwd.lock" {
        rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::LockExclusive)?;
    } else {
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)?;
    }
    Ok(file)
}

fn batch_limits() -> aos_contract::limits::JsonLimits {
    // Match the package journal's graph envelope bounds, with bounded room for
    // the export's outer object, effects array, and invocation/result pairs.
    aos_contract::limits::JsonLimits {
        max_bytes: BATCH_LIMIT,
        max_depth: GRAPH_LIMITS.max_depth + JOURNAL_WRAPPER_DEPTH + EXPORT_WRAPPER_DEPTH,
        max_items: 2 * GRAPH_LIMITS.max_items + JOURNAL_WRAPPER_ITEMS + EXPORT_WRAPPER_ITEMS,
        max_string_bytes: GRAPH_LIMITS.max_string_bytes,
    }
}

fn restore_at(root: &Path, state: &Path, bytes: &[u8], shells: Option<(&str, &str)>) -> Result<()> {
    let batch: Batch = batch_limits().decode(bytes, "retained identity authority")?;
    ensure!(
        batch.schema == "aos.package.retained-effects",
        "unsupported retained effects schema"
    );
    ensure!(
        batch.effects.len() <= EFFECT_LIMIT,
        "retained effects exceed identity restoration bound"
    );
    if batch.scope.is_empty() && batch.effects.is_empty() {
        return Ok(());
    }
    ensure!(
        batch.scope == ["profile", "system"],
        "identity restoration requires the system profile"
    );

    let _lock = lock(root, ".pwd.lock")?;
    let mut receipts = Vec::new();
    let mut identities = BTreeSet::new();
    for retained in batch.effects {
        let invocation = retained.invocation;
        let identity = &invocation.effect.identity;
        ensure!(
            identity.starts_with(&batch.scope),
            "retained effect differs from profile scope"
        );
        if identity.len() < 3 || identity[identity.len() - 3] != "identity" {
            continue;
        }
        let handler = serde_json::to_value(&invocation.effect.handler)?;
        let artifact = handler.get("artifact").and_then(Value::as_str);
        if handler.get("kind").and_then(Value::as_str) != Some("process")
            || !artifact.is_some_and(|artifact| {
                handler.get("executable").and_then(Value::as_str)
                    == Some(format!("{artifact}/bin/aos-systemd-native-resources").as_str())
            })
        {
            continue;
        }
        let operation = identity[identity.len() - 2].as_str();
        ensure!(
            matches!(operation, "group" | "principal" | "membership"),
            "unsupported retained identity operation"
        );
        ensure!(
            invocation.action == Action::Apply && identities.insert(invocation.id.clone()),
            "duplicate or removed retained identity"
        );
        let path = state.join(format!(
            "{}-identity.json",
            super::super::key(&invocation.id)
        ));
        let bytes =
            read_regular(&path, 1_048_576)?.context("retained identity has no durable receipt")?;
        let receipt: Receipt = serde_json::from_slice(&bytes)?;
        ensure!(
            receipt.complete
                && receipt.previous_rows.is_empty()
                && !receipt
                    .replacement
                    .as_ref()
                    .is_some_and(|replacement| replacement.restoring
                        || !replacement.previous_members.is_empty()),
            "retained identity receipt is incomplete"
        );
        ensure!(
            receipt.owner == invocation.id
                && receipt.revision == invocation.revision
                && receipt.operation == operation
                && receipt.input == invocation.input,
            "identity receipt lacks exact retained authority"
        );
        validate_outputs(&receipt, &retained.outputs)?;
        receipts.push(receipt);
    }

    // A private projection preserves foreign rows while checking the complete
    // batch, including cross-effect numeric collisions and missing parents.
    let projected = tempfile::tempdir_in(state)?;
    for file in DATABASES {
        write_database(projected.path(), file, &database(root, file)?)?;
    }
    project(projected.path(), &receipts, shells)?;

    // Repeating after an interrupted database publication produces the same
    // projection. Receipts remain unchanged and keep their original authority.
    publish(root, projected.path())?;
    Ok(())
}

fn publish(root: &Path, projected: &Path) -> Result<()> {
    // Publish parent groups without new membership references first. Existing
    // membership columns stay intact until every principal row is available.
    for file in ["group", "gshadow"] {
        let current = database(root, file)?;
        let mut planned = database(projected, file)?;
        for row in &mut planned {
            row[3] = current
                .iter()
                .find(|existing| existing[0] == row[0])
                .map(|existing| existing[3].clone())
                .unwrap_or_default();
        }
        if planned != current {
            write_database(root, file, &planned)?;
        }
    }
    for file in ["passwd", "shadow", "group", "gshadow"] {
        let planned = database(projected, file)?;
        if planned != database(root, file)? {
            write_database(root, file, &planned)?;
        }
    }
    Ok(())
}

fn validate_outputs(receipt: &Receipt, outputs: &Value) -> Result<()> {
    let expected = if receipt.operation == "membership" {
        json!({"resource":format!("identity:membership:{}",super::super::key(&receipt.owner))})
    } else {
        let account: Account = serde_json::from_value(receipt.input.clone())?;
        json!({"name":account.name,"resource":format!("identity:{}:{}",receipt.operation,account.name)})
    };
    ensure!(
        *outputs == expected,
        "retained identity result differs from receipt"
    );
    Ok(())
}

fn project(root: &Path, receipts: &[Receipt], shells: Option<(&str, &str)>) -> Result<()> {
    let mut owners = BTreeSet::new();
    for operation in ["group", "principal"] {
        for receipt in receipts
            .iter()
            .filter(|receipt| receipt.operation == operation)
        {
            validate_rows(root, receipt, &mut owners)?;
            check_rows(root, receipt)?;
            install_rows(root, receipt)?;
            let retained_shells = receipt_shells(receipt, shells)?;
            let expected = desired(
                root,
                &receipt.input,
                operation,
                Some(receipt),
                retained_shells,
            )?;
            ensure!(
                expected.rows == receipt.rows,
                "owned identity rows differ from retained input"
            );
            if let Some(row) = receipt.rows.get("passwd") {
                let account: Account = serde_json::from_value(receipt.input.clone())?;
                let id = row
                    .split(':')
                    .nth(2)
                    .context("owned principal lacks ID")?
                    .parse()?;
                ensure!(
                    *row == principal_row(root, &account, id, retained_shells)?,
                    "owned principal differs from retained policy"
                );
            }
        }
    }
    for receipt in receipts {
        if receipt.operation == "membership" {
            ensure!(
                receipt.rows.is_empty(),
                "membership receipt claims account rows"
            );
        }
        let expected = desired(
            root,
            &receipt.input,
            &receipt.operation,
            Some(receipt),
            receipt_shells(receipt, shells)?,
        )?;
        ensure!(
            receipt.additions.is_subset(&expected.additions),
            "receipt claims unauthored memberships"
        );
        if let Some(replacement) = &receipt.replacement {
            let input: Membership = serde_json::from_value(receipt.input.clone())?;
            ensure!(
                replacement.group == input.group
                    && replacement
                        .original_members
                        .keys()
                        .all(|file| matches!(file.as_str(), "group" | "gshadow")),
                "replacement receipt differs from its retained group"
            );
            let owned_group = receipts.iter().any(|group| {
                group.operation == "group"
                    && group.rows.get("group").is_some_and(|row| {
                        row.split(':').next() == Some(replacement.group.as_str())
                    })
            });
            ensure!(
                owned_group,
                "replacement membership lacks retained group ownership"
            );
            let target = replacement_target(receipt)?;
            let current = membership_snapshot(root, &replacement.group)?;
            for (file, members) in &current {
                ensure!(
                    members.is_subset(&target)
                        || replacement.original_members.get(file) == Some(members),
                    "replacement membership has foreign changes"
                );
            }
            let wanted = current
                .keys()
                .map(|file| (file.clone(), target.clone()))
                .collect();
            write_membership_snapshot(root, &replacement.group, &wanted)?;
        } else {
            reconcile_members(root, &receipt.additions, &BTreeSet::new())?;
        }
    }
    Ok(())
}

// An older retained backend can have different packaged shell defaults. Its
// complete receipt retains that original path; explicit authored overrides are
// still checked by principal_shell instead of being inferred from this row.
fn receipt_shells<'a>(
    receipt: &'a Receipt,
    current: Option<(&'a str, &'a str)>,
) -> Result<Option<(&'a str, &'a str)>> {
    let Some(row) = receipt.rows.get("passwd") else {
        return Ok(current);
    };
    let shell = row
        .split(':')
        .nth(6)
        .context("owned principal lacks shell")?;
    let path = super::normalized_path(shell)?;
    ensure!(
        path.starts_with("/nix/store"),
        "retained principal shell is not immutable"
    );
    Ok(Some((shell, shell)))
}

fn validate_rows(
    root: &Path,
    receipt: &Receipt,
    owners: &mut BTreeSet<(String, String)>,
) -> Result<()> {
    let allowed = if receipt.operation == "group" {
        ["group", "gshadow"]
    } else {
        ["passwd", "shadow"]
    };
    ensure!(
        receipt.rows.is_empty()
            || receipt
                .rows
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == allowed.into_iter().collect(),
        "identity receipt has incomplete or foreign database rows"
    );
    for (file, line) in &receipt.rows {
        let input: Account = serde_json::from_value(receipt.input.clone())?;
        let fields: Vec<_> = line.split(':').collect();
        let count = match file.as_str() {
            "passwd" => 7,
            "shadow" => 9,
            _ => 3,
        };
        ensure!(
            fields.len() == count && !line.contains(['\n', '\r', '\0']),
            "malformed owned identity row"
        );
        name(fields[0])?;
        ensure!(
            fields[0] == input.name && input.allocation == "managed",
            "owned row differs from retained account"
        );
        ensure!(
            owners.insert((file.clone(), fields[0].to_owned())),
            "multiple retained effects own one account row"
        );
        if matches!(file.as_str(), "group" | "passwd") {
            let id: u32 = fields[2].parse()?;
            for row in database(root, file)? {
                ensure!(
                    row[0] == fields[0] || row[2].parse::<u32>()? != id,
                    "owned numeric identity conflicts with a foreign account"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
