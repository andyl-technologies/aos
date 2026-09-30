//! Establishes local accounts and explicitly owned membership additions.
//!
//! Receipts retain exact created database rows and membership deltas. Existing
//! accounts are never adopted for deletion. The standard password-database lock
//! serializes edits with system account tools; pending receipts precede writes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{atomic_write, normalized_path, read_regular, state_path};

const LIMIT: u64 = 16_777_216;

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Account {
    name: String,
    #[serde(default = "managed")]
    allocation: String,
    #[serde(default)]
    requested_id: Option<u32>,
    #[serde(default)]
    primary_group: Option<String>,
    #[serde(default)]
    supplementary_groups: Vec<String>,
    #[serde(default = "disabled")]
    login_access: String,
    #[serde(default = "home")]
    home_directory: String,
    #[serde(default)]
    description: String,
}
fn managed() -> String {
    "managed".into()
}
fn disabled() -> String {
    "disabled".into()
}
fn home() -> String {
    "/var/empty".into()
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Membership {
    group: String,
    members: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    owner: String,
    revision: String,
    operation: String,
    input: Value,
    /// Exact database rows created by this effect, excluding mutable membership columns.
    rows: BTreeMap<String, String>,
    previous_rows: BTreeMap<String, String>,
    /// Membership pairs added by this effect, excluding preexisting memberships.
    additions: BTreeSet<(String, String)>,
    complete: bool,
}

fn name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 31
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
        "invalid local account name"
    );
    Ok(())
}

fn database(root: &Path, file: &str) -> Result<Vec<Vec<String>>> {
    let bytes = read_regular(&root.join(file), LIMIT)?.unwrap_or_default();
    let text = std::str::from_utf8(&bytes)?;
    ensure!(
        text.is_empty() || text.ends_with('\n'),
        "account database has a truncated row"
    );
    let count = match file {
        "passwd" => 7,
        "shadow" => 9,
        _ => 4,
    };
    let mut seen = BTreeSet::new();
    text.lines()
        .map(|line| {
            let row: Vec<String> = line.split(':').map(str::to_owned).collect();
            ensure!(
                row.len() == count && seen.insert(row[0].clone()),
                "account database has malformed or duplicate rows"
            );
            Ok(row)
        })
        .collect()
}

fn write_database(root: &Path, file: &str, rows: &[Vec<String>]) -> Result<()> {
    let text: String = rows
        .iter()
        .map(|row| format!("{}\n", row.join(":")))
        .collect();
    atomic_write(
        &root.join(file),
        text.as_bytes(),
        if matches!(file, "shadow" | "gshadow") {
            0o600
        } else {
            0o644
        },
    )
}

fn lookup<'a>(rows: &'a [Vec<String>], account: &str) -> Result<&'a Vec<String>> {
    rows.iter()
        .find(|row| row[0] == account)
        .context("required local account does not exist")
}

fn members(row: &[String]) -> BTreeSet<String> {
    row[3]
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn owned_row(file: &str, row: &[String]) -> String {
    if matches!(file, "group" | "gshadow") {
        row[..3].join(":")
    } else {
        row.join(":")
    }
}

fn check_rows(root: &Path, receipt: &Receipt) -> Result<bool> {
    let mut present = true;
    for (file, expected) in &receipt.rows {
        let rows = database(root, file)?;
        let account = expected.split(':').next().context("owned row lacks name")?;
        if let Some(row) = rows.iter().find(|row| row[0] == account) {
            ensure!(
                owned_row(file, row) == *expected
                    || (!receipt.complete
                        && receipt.previous_rows.get(file) == Some(&owned_row(file, row))),
                "owned account database row has changed"
            );
        } else {
            present = false;
        }
    }
    Ok(present)
}

fn reconcile_members(
    root: &Path,
    desired: &BTreeSet<(String, String)>,
    previous: &BTreeSet<(String, String)>,
) -> Result<()> {
    for file in ["group", "gshadow"] {
        let mut rows = database(root, file)?;
        if file == "gshadow" && rows.is_empty() {
            continue;
        }
        for group in desired
            .iter()
            .chain(previous)
            .map(|pair| &pair.0)
            .collect::<BTreeSet<_>>()
        {
            let row = rows
                .iter_mut()
                .find(|row| &row[0] == group)
                .context("membership group is missing")?;
            let mut names = members(row);
            for (_, principal) in previous.iter().filter(|pair| &pair.0 == group) {
                names.remove(principal);
            }
            for (_, principal) in desired.iter().filter(|pair| &pair.0 == group) {
                names.insert(principal.clone());
            }
            row[3] = names.into_iter().collect::<Vec<_>>().join(",");
        }
        write_database(root, file, &rows)?;
    }
    Ok(())
}

fn memberships_current(root: &Path, additions: &BTreeSet<(String, String)>) -> Result<bool> {
    for file in ["group", "gshadow"] {
        let rows = database(root, file)?;
        if file == "gshadow" && rows.is_empty() {
            continue;
        }
        for (group, principal) in additions {
            if !lookup(&rows, group).is_ok_and(|row| members(row).contains(principal)) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn numeric_id(rows: &[Vec<String>], requested: Option<u32>) -> Result<u32> {
    let used: BTreeSet<u32> = rows
        .iter()
        .map(|row| row[2].parse())
        .collect::<std::result::Result<_, _>>()?;
    if let Some(id) = requested {
        ensure!(
            id != 0 && !used.contains(&id),
            "requested numeric identity is already allocated or reserved"
        );
        return Ok(id);
    }
    (61184..65519)
        .find(|id| !used.contains(id))
        .context("managed account identity range is exhausted")
}

fn desired(
    root: &Path,
    input: &Value,
    operation: &str,
    prior: Option<&Receipt>,
    shells: Option<(&str, &str)>,
) -> Result<Receipt> {
    let mut receipt = Receipt {
        owner: String::new(),
        revision: String::new(),
        operation: operation.into(),
        input: input.clone(),
        rows: BTreeMap::new(),
        previous_rows: BTreeMap::new(),
        additions: BTreeSet::new(),
        complete: false,
    };
    if operation != "membership" {
        if let Some(old) = prior.filter(|old| old.input == *input) {
            receipt.rows = old.rows.clone();
        }
    }
    let mut wanted = BTreeSet::new();
    if operation == "membership" {
        let value: Membership = serde_json::from_value(input.clone())?;
        name(&value.group)?;
        lookup(&database(root, "group")?, &value.group)?;
        for principal in value.members {
            name(&principal)?;
            lookup(&database(root, "passwd")?, &principal)?;
            wanted.insert((value.group.clone(), principal));
        }
    } else {
        let value: Account = serde_json::from_value(input.clone())?;
        name(&value.name)?;
        ensure!(
            matches!(value.allocation.as_str(), "managed" | "existing"),
            "unsupported account allocation"
        );
        if operation == "principal" && value.allocation == "managed" {
            name(
                value
                    .primary_group
                    .as_deref()
                    .context("managed principal requires a primary group")?,
            )?;
            ensure!(
                matches!(value.login_access.as_str(), "enabled" | "disabled"),
                "invalid login policy"
            );
        }
        let file = if operation == "group" {
            "group"
        } else {
            "passwd"
        };
        let rows = database(root, file)?;
        let existing = rows.iter().find(|row| row[0] == value.name);
        let owns = prior.is_some_and(|old| {
            old.rows
                .get(file)
                .is_some_and(|line| line.split(':').next() == Some(value.name.as_str()))
        });
        if let Some(old) = prior.filter(|old| !old.rows.is_empty()) {
            let old_value: Account = serde_json::from_value(old.input.clone())?;
            ensure!(
                old_value.name == value.name && old_value.allocation == value.allocation,
                "owned identity name and allocation cannot change without teardown"
            );
            ensure!(
                old.complete || old.input == *input,
                "pending identity update must complete before another update"
            );
        }
        if let Some(row) = existing {
            if let Some(id) = value.requested_id {
                ensure!(
                    row[2].parse::<u32>()? == id,
                    "existing account numeric identity conflicts"
                );
            }
            if operation == "principal" && value.allocation == "managed" && !owns {
                let (login, nologin) =
                    shells.context("managed principal requires pinned shell executables")?;
                let shell = if value.login_access == "enabled" {
                    login
                } else {
                    nologin
                };
                ensure!(
                    row[6] == shell
                        && row[5] == value.home_directory
                        && row[4] == value.description,
                    "existing principal login, home, or description differs from managed policy"
                );
            }
            if let Some(prior) = prior {
                if prior
                    .rows
                    .get(file)
                    .is_some_and(|line| line.split(':').next() == Some(value.name.as_str()))
                {
                    receipt.rows = prior.rows.clone();
                }
            }
        } else {
            ensure!(
                value.allocation == "managed",
                "existing-only account does not exist"
            );
            let id = if receipt.rows.is_empty() {
                numeric_id(&rows, value.requested_id)?
            } else {
                receipt
                    .rows
                    .get(file)
                    .context("pending account receipt lacks identity row")?
                    .split(':')
                    .nth(2)
                    .context("pending account has no numeric ID")?
                    .parse()?
            };
            if operation == "group" {
                receipt
                    .rows
                    .insert("group".into(), format!("{}:x:{id}", value.name));
                receipt
                    .rows
                    .insert("gshadow".into(), format!("{}:!:", value.name));
            } else {
                let group = value
                    .primary_group
                    .as_deref()
                    .context("managed principal requires a primary group")?;
                name(group)?;
                let groups = database(root, "group")?;
                let gid: u32 = lookup(&groups, group)?[2].parse()?;
                let (login, nologin) =
                    shells.context("managed principal requires pinned shell executables")?;
                for shell in [login, nologin] {
                    ensure!(
                        normalized_path(shell)?.starts_with("/nix/store"),
                        "shell is not an immutable store executable"
                    );
                }
                ensure!(
                    matches!(value.login_access.as_str(), "enabled" | "disabled"),
                    "invalid login policy"
                );
                normalized_path(&value.home_directory)?;
                ensure!(
                    !value.description.contains([':', '\n', '\r', '\0'])
                        && !value.home_directory.contains(':'),
                    "invalid account database field"
                );
                let shell = if value.login_access == "enabled" {
                    login
                } else {
                    nologin
                };
                receipt.rows.insert(
                    "passwd".into(),
                    format!(
                        "{}:x:{id}:{gid}:{}:{}:{shell}",
                        value.name, value.description, value.home_directory
                    ),
                );
                receipt
                    .rows
                    .insert("shadow".into(), format!("{}:!:0:0:99999:7:::", value.name));
            }
        }
        if owns && operation == "principal" && existing.is_some() {
            let row = existing.context("owned principal is missing during update")?;
            let id: u32 = row[2].parse()?;
            receipt
                .rows
                .insert("passwd".into(), principal_row(root, &value, id, shells)?);
        }
        if operation == "principal" && value.allocation == "managed" {
            if let Some(group) = &value.primary_group {
                let groups = database(root, "group")?;
                if let Some(row) = existing.filter(|_| !owns) {
                    ensure!(
                        row[3] == lookup(&groups, group)?[2],
                        "existing principal primary group conflicts"
                    );
                }
            }
            for group in value.supplementary_groups {
                name(&group)?;
                wanted.insert((group, value.name.clone()));
            }
        }
    }
    let groups = database(root, "group")?;
    for pair in wanted {
        let row = lookup(&groups, &pair.0)?;
        if !members(row).contains(&pair.1) || prior.is_some_and(|old| old.additions.contains(&pair))
        {
            receipt.additions.insert(pair);
        }
    }
    Ok(receipt)
}

fn principal_row(
    root: &Path,
    value: &Account,
    id: u32,
    shells: Option<(&str, &str)>,
) -> Result<String> {
    let group = value
        .primary_group
        .as_deref()
        .context("managed principal requires primary group")?;
    let groups = database(root, "group")?;
    let gid: u32 = lookup(&groups, group)?[2].parse()?;
    let (login, nologin) = shells.context("managed principal requires pinned shells")?;
    for shell in [login, nologin] {
        ensure!(
            normalized_path(shell)?.starts_with("/nix/store"),
            "shell is not immutable"
        );
    }
    normalized_path(&value.home_directory)?;
    ensure!(
        !value.description.contains([':', '\n', '\r', '\0']) && !value.home_directory.contains(':'),
        "invalid account database field"
    );
    let shell = if value.login_access == "enabled" {
        login
    } else {
        nologin
    };
    Ok(format!(
        "{}:x:{id}:{gid}:{}:{}:{shell}",
        value.name, value.description, value.home_directory
    ))
}

fn install_rows(root: &Path, receipt: &Receipt) -> Result<()> {
    for (file, line) in &receipt.rows {
        let mut rows = database(root, file)?;
        let account = line.split(':').next().context("owned row lacks name")?;
        if let Some(row) = rows.iter_mut().find(|row| row[0] == account) {
            let actual = owned_row(file, row);
            ensure!(
                actual == *line || receipt.previous_rows.get(file) == Some(&actual),
                "created account row has drifted"
            );
            if actual != *line {
                let suffix = if matches!(file.as_str(), "group" | "gshadow") {
                    format!(":{}", row[3])
                } else {
                    String::new()
                };
                *row = format!("{line}{suffix}")
                    .split(':')
                    .map(str::to_owned)
                    .collect();
                write_database(root, file, &rows)?;
            }
            continue;
        }
        let complete = if matches!(file.as_str(), "group" | "gshadow") {
            format!("{line}:")
        } else {
            line.clone()
        };
        rows.push(complete.split(':').map(str::to_owned).collect());
        write_database(root, file, &rows)?;
    }
    Ok(())
}

fn remove_rows(root: &Path, receipt: &Receipt) -> Result<()> {
    check_rows(root, receipt)?;
    // Validate every row before deleting any account. Foreign memberships and
    // primary users keep a group alive, even if its original creator leaves.
    if let Some(principal) = receipt.rows.get("passwd") {
        let account = principal
            .split(':')
            .next()
            .context("principal lacks name")?;
        ensure!(
            !database(root, "group")?
                .iter()
                .any(|row| members(row).contains(account))
                && !database(root, "gshadow")?
                    .iter()
                    .any(|row| members(row).contains(account)),
            "owned principal still has external group membership"
        );
    }
    if let Some(group) = receipt.rows.get("group") {
        let account = group.split(':').next().context("group lacks name")?;
        let groups = database(root, "group")?;
        let shadow_groups = database(root, "gshadow")?;
        if let Ok(row) = lookup(&shadow_groups, account) {
            ensure!(
                members(row).is_empty(),
                "owned group still has external shadow members"
            );
        }
        if let Ok(row) = lookup(&groups, account) {
            ensure!(
                members(row).is_empty(),
                "owned group still has external members"
            );
            ensure!(
                !database(root, "passwd")?
                    .iter()
                    .any(|user| user[3] == row[2]),
                "owned group is still a primary group"
            );
        }
    }
    for (file, line) in &receipt.rows {
        let account = line.split(':').next().context("owned row lacks name")?;
        let mut rows = database(root, file)?;
        rows.retain(|row| row[0] != account);
        write_database(root, file, &rows)?;
    }
    Ok(())
}

/// Converges or observes a checked native local identity operation.
///
/// # Errors
/// Returns an error for missing existing accounts, identity conflicts, database drift, or failed receipt and account writes.
pub(super) fn execute(
    invocation: &Invocation,
    action: &str,
    operation: &str,
    shells: Option<(&str, &str)>,
) -> Result<Value> {
    execute_at(Path::new("/etc"), invocation, action, operation, shells)
}

fn execute_at(
    root: &Path,
    invocation: &Invocation,
    action: &str,
    operation: &str,
    shells: Option<(&str, &str)>,
) -> Result<Value> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(root.join(".pwd.lock"))?;
    rustix::fs::fcntl_lock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
    let path = state_path(invocation, "identity");
    let prior: Option<Receipt> = read_regular(&path, 1_048_576)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?;
    if let Some(old) = &prior {
        ensure!(
            old.owner == invocation.id && old.operation == operation,
            "identity receipt differs"
        );
        check_rows(root, old)?;
        if old.revision != invocation.revision {
            ensure!(
                action != "remove"
                    && invocation
                        .previous
                        .as_ref()
                        .is_some_and(|previous| previous.revision == old.revision
                            && previous.input == old.input),
                "identity update lacks its exact retained previous authority"
            );
        }
    }
    if action == "remove" {
        if let Some(old) = prior {
            reconcile_members(root, &BTreeSet::new(), &old.additions)?;
            remove_rows(root, &old)?;
            fs::remove_file(path)?;
        }
        return Ok(json!({}));
    }
    if action == "observe" && prior.is_none() && invocation.action == Action::Remove {
        return Ok(json!({"status":"absent"}));
    }
    let mut next = desired(root, &invocation.input, operation, prior.as_ref(), shells)?;
    next.owner = invocation.id.clone();
    next.revision = invocation.revision.clone();
    let outputs = if operation == "membership" {
        json!({"resource":format!("identity:membership:{}",super::key(&invocation.id))})
    } else {
        let value: Account = serde_json::from_value(invocation.input.clone())?;
        json!({"name":value.name,"resource":format!("identity:{operation}:{}",value.name)})
    };
    if action == "observe" {
        let current = prior.as_ref().is_some_and(|old| {
            old.complete && old.revision == invocation.revision && old.input == invocation.input
        }) && check_rows(root, &next)?
            && memberships_current(root, &next.additions)?;
        return Ok(if current {
            json!({"status":"current","outputs":outputs})
        } else {
            json!({"status":"retry-safe"})
        });
    }
    // Preserve all prior additions until both database writes have completed;
    // an interrupted replacement can therefore remove the old owned delta.
    let previous = prior
        .as_ref()
        .map(|old| old.additions.clone())
        .unwrap_or_default();
    let desired_additions = next.additions.clone();
    if let Some(old) = &prior {
        next.previous_rows = if old.complete {
            old.rows.clone()
        } else {
            old.previous_rows.clone()
        };
    }
    next.additions.extend(previous.iter().cloned());
    atomic_write(&path, &serde_json::to_vec(&next)?, 0o600)?;
    install_rows(root, &next)?;
    reconcile_members(root, &desired_additions, &previous)?;
    next.additions = desired_additions;
    next.complete = true;
    next.previous_rows.clear();
    atomic_write(&path, &serde_json::to_vec(&next)?, 0o600)?;
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("group"), "staff:x:50:external\n").unwrap();
        fs::write(root.path().join("gshadow"), "staff:!::external\n").unwrap();
        fs::write(
            root.path().join("passwd"),
            "external:x:1000:50::/home/external:/shell\n",
        )
        .unwrap();
        fs::write(root.path().join("shadow"), "external:!:0:0:99999:7:::\n").unwrap();
        root
    }
    #[test]
    fn existing_only_requires_account_and_exact_numeric_id() {
        let root = fixture();
        assert!(
            desired(
                root.path(),
                &json!({"name":"staff","allocation":"existing","requested_id":51}),
                "group",
                None,
                None
            )
            .is_err()
        );
        assert!(
            desired(
                root.path(),
                &json!({"name":"missing","allocation":"existing"}),
                "group",
                None,
                None
            )
            .is_err()
        );
        assert!(
            desired(
                root.path(),
                &json!({"name":"staff","allocation":"existing","requested_id":50}),
                "group",
                None,
                None
            )
            .unwrap()
            .rows
            .is_empty()
        );
    }
    #[test]
    fn membership_delta_preserves_existing_members() {
        let root = fixture();
        let additions = BTreeSet::from([("staff".into(), "owned".into())]);
        reconcile_members(root.path(), &additions, &BTreeSet::new()).unwrap();
        assert_eq!(
            members(&database(root.path(), "group").unwrap()[0]),
            BTreeSet::from(["external".into(), "owned".into()])
        );
        reconcile_members(root.path(), &BTreeSet::new(), &additions).unwrap();
        assert_eq!(
            members(&database(root.path(), "group").unwrap()[0]),
            BTreeSet::from(["external".into()])
        );
    }
    #[test]
    fn principal_has_disabled_login_and_locked_password() {
        let root = fixture();
        let input = json!({"name":"owned","primary_group":"staff","requested_id":27});
        let receipt = desired(
            root.path(),
            &input,
            "principal",
            None,
            Some((
                "/nix/store/hash-bash/bin/bash",
                "/nix/store/hash-util/sbin/nologin",
            )),
        )
        .unwrap();
        install_rows(root.path(), &receipt).unwrap();
        assert_eq!(
            lookup(&database(root.path(), "passwd").unwrap(), "owned").unwrap()[6],
            "/nix/store/hash-util/sbin/nologin"
        );
        assert_eq!(
            lookup(&database(root.path(), "shadow").unwrap(), "owned").unwrap()[1],
            "!"
        );
        remove_rows(root.path(), &receipt).unwrap();
        assert_eq!(database(root.path(), "passwd").unwrap().len(), 1);
    }
    #[test]
    fn owned_principal_updates_retain_id_and_accept_interrupted_rows() {
        let root = fixture();
        let shells = Some((
            "/nix/store/hash-bash/bin/bash",
            "/nix/store/hash-util/sbin/nologin",
        ));
        let input = json!({"name":"owned","primary_group":"staff","requested_id":27});
        let mut old = desired(root.path(), &input, "principal", None, shells).unwrap();
        install_rows(root.path(), &old).unwrap();
        old.complete = true;
        let new_input = json!({"name":"owned","primary_group":"staff","requested_id":27,"description":"Updated purpose","home_directory":"/var/lib/owned"});
        let mut next = desired(root.path(), &new_input, "principal", Some(&old), shells).unwrap();
        next.previous_rows = old.rows.clone();
        assert!(check_rows(root.path(), &next).unwrap());
        install_rows(root.path(), &next).unwrap();
        assert!(check_rows(root.path(), &next).unwrap());
        let rows = database(root.path(), "passwd").unwrap();
        let row = lookup(&rows, "owned").unwrap();
        assert_eq!(row[2], "27");
        assert_eq!(row[4], "Updated purpose");
        assert_eq!(row[5], "/var/lib/owned");
    }

    #[test]
    fn pending_account_replay_retains_reserved_id() {
        let root = fixture();
        let input = json!({"name":"owned"});
        let old = desired(root.path(), &input, "group", None, None).unwrap();
        let replay = desired(root.path(), &input, "group", Some(&old), None).unwrap();
        assert_eq!(old.rows, replay.rows);
        install_rows(root.path(), &replay).unwrap();
        assert!(check_rows(root.path(), &old).unwrap());
    }

    #[test]
    fn external_membership_keeps_owned_principal_alive() {
        let root = fixture();
        let input = json!({"name":"owned","primary_group":"staff","requested_id":27});
        let receipt = desired(
            root.path(),
            &input,
            "principal",
            None,
            Some((
                "/nix/store/hash-bash/bin/bash",
                "/nix/store/hash-util/sbin/nologin",
            )),
        )
        .unwrap();
        install_rows(root.path(), &receipt).unwrap();
        reconcile_members(
            root.path(),
            &BTreeSet::from([("staff".into(), "owned".into())]),
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(remove_rows(root.path(), &receipt).is_err());
        assert!(lookup(&database(root.path(), "passwd").unwrap(), "owned").is_ok());
    }

    #[test]
    fn foreign_account_row_blocks_removal() {
        let root = fixture();
        let mut receipt = desired(
            root.path(),
            &json!({"name":"owned","requested_id":27}),
            "group",
            None,
            None,
        )
        .unwrap();
        install_rows(root.path(), &receipt).unwrap();
        receipt.rows.insert("group".into(), "owned:x:28".into());
        assert!(remove_rows(root.path(), &receipt).is_err());
        assert_eq!(database(root.path(), "group").unwrap().len(), 2);
    }
}
