//! Reconciles portable configuration files through durable ownership receipts.
//!
//! The provider shares service ownership claims and locking while retaining
//! pending destination evidence until path retirement has been synchronized.
//! `format` owns resolved encoding and `io` owns durable filesystem operations.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result, ensure};
use rustix::fs::fchown;
use rustix::process::{Gid, Uid};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod format;
mod io;

#[derive(Deserialize)]
struct Invocation {
    id: String,
    revision: String,
    input: Input,
    effect: Effect,
    #[serde(default = "apply_action")]
    action: String,
}

fn apply_action() -> String {
    "apply".into()
}

#[derive(Deserialize)]
struct Effect {
    identity: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    path: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    fragments: Vec<Fragment>,
    #[serde(default = "text_format")]
    format: String,
    #[serde(default)]
    value: Value,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    group: Option<String>,
    mode: String,
}

fn text_format() -> String {
    "text".into()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Fragment {
    Text(String),
    Credential {
        #[serde(rename = "credentialPath")]
        credential_path: String,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: u64,
    },
}

/// Retains interoperable file ownership evidence in the shared service namespace.
///
/// ```json
/// {"kind":"configuration","id":"effect","revision":"revision",
///  "path":"/etc/example","digest":"sha256","pending":false,
///  "owned_paths":["/etc/example"]}
/// ```
#[derive(Clone, Deserialize, Serialize)]
struct Receipt {
    kind: String,
    id: String,
    revision: String,
    path: String,
    digest: String,
    pending: bool,
    owned_paths: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_path_digest: Option<String>,
}

/// Executes one bounded native configuration invocation.
///
/// # Errors
/// Returns an error for invalid invocation data, ownership conflicts, unsafe
/// paths, unresolved accounts, modified files, or failed durable filesystem IO.
pub fn handle(action: &str, document: &[u8], state_directory: &Path) -> Result<Value> {
    ensure!(
        document.len() <= 256 * 1024,
        "native invocation exceeds limit"
    );
    ensure!(
        matches!(action, "apply" | "remove" | "observe"),
        "unsupported native configuration action"
    );
    let mut invocation: Invocation = serde_json::from_slice(document)?;
    // Equivalent lexical paths must claim the same shared resource namespace.
    invocation.input.path = io::normalize(&invocation.input.path)?;
    let identity = &invocation.effect.identity;
    ensure!(
        identity.len() >= 3
            && identity[identity.len() - 3..identity.len() - 1] == ["configuration", "file"],
        "unsupported native configuration operation"
    );
    ensure!(
        matches!(invocation.action.as_str(), "apply" | "remove")
            && (action == "observe" || action == invocation.action),
        "process action differs from invocation"
    );
    let _lock = io::lock(state_directory)?;
    let receipt_path =
        state_directory.join(format!("{}.json", io::digest(invocation.id.as_bytes())));
    let mut receipt = match io::regular(&receipt_path)? {
        Some(file) => Some(serde_json::from_reader::<_, Receipt>(file)?),
        None => None,
    };
    if let Some(receipt) = &mut receipt {
        ensure!(
            receipt.id == invocation.id && receipt.kind == "configuration",
            "native ownership receipt identity differs"
        );
        for path in &receipt.owned_paths {
            io::owned_path(path)?;
        }
        io::owned_path(&receipt.path)?;
        if let Some(path) = &receipt.previous_path {
            io::owned_path(path)?;
        }
        let mut expected_paths = BTreeSet::from([receipt.path.clone()]);
        if let Some(path) = &receipt.previous_path {
            expected_paths.insert(path.clone());
        }
        ensure!(
            receipt.owned_paths == expected_paths,
            "configuration receipt claims differ from retained destinations"
        );
        receipt.path = io::normalize(&receipt.path)?;
        receipt.previous_path = receipt
            .previous_path
            .as_deref()
            .map(io::normalize)
            .transpose()?;
        receipt.owned_paths = receipt
            .owned_paths
            .iter()
            .map(|path| io::normalize(path))
            .collect::<Result<_>>()?;
    }
    let path = io::owned_path(&invocation.input.path)?;
    let contents = format::contents(&invocation.input)?;
    let expected = io::digest(&contents);
    let current = io::read_digest(path)?;
    match action {
        "observe" if invocation.action == "remove" => {
            observe_removal(receipt.as_ref(), current, &receipt_path)
        }
        "observe" => {
            let (uid, gid) = ownership(&invocation.input)?;
            if current.as_deref() == Some(&expected)
                && receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.digest == expected && !receipt.pending)
            {
                let metadata = fs::symlink_metadata(path)?;
                if uid.is_none_or(|uid| metadata.uid() == uid)
                    && gid.is_none_or(|gid| metadata.gid() == gid)
                    && metadata.mode() & 0o7777 == io::mode(&invocation.input.mode)?
                {
                    return Ok(json!({"status": "current", "outputs": results(path, &contents)}));
                }
            }
            let status = if current.is_none() && receipt.is_none() {
                "absent"
            } else if safe(current.as_deref(), &expected, receipt.as_ref()) {
                "retry-safe"
            } else {
                "indeterminate"
            };
            Ok(json!({"status": status}))
        }
        "remove" => {
            let Some(receipt) = &receipt else {
                ensure!(
                    current.is_none(),
                    "configuration removal has no ownership receipt"
                );
                return Ok(json!({}));
            };
            ensure!(
                removal_safe(receipt)?,
                "configuration was modified outside its owning effect"
            );
            for path in &receipt.owned_paths {
                io::unlink(io::owned_path(path)?)?;
            }
            io::unlink(&receipt_path)?;
            Ok(json!({}))
        }
        _ => apply(
            &invocation,
            state_directory,
            &receipt_path,
            receipt.as_ref(),
            &contents,
            expected,
            current,
        ),
    }
}

fn safe(current: Option<&str>, expected: &str, receipt: Option<&Receipt>) -> bool {
    current.is_none()
        || current == Some(expected)
        || receipt.is_some_and(|receipt| {
            current == Some(receipt.digest.as_str())
                || current == receipt.previous_digest.as_deref()
        })
}

fn removal_safe(receipt: &Receipt) -> Result<bool> {
    let current = io::read_digest(io::owned_path(&receipt.path)?)?;
    let same_previous_path = receipt.previous_path.as_deref() == Some(&receipt.path);
    if current.is_some()
        && current.as_deref() != Some(&receipt.digest)
        && current != receipt.previous_digest
        && !(same_previous_path && current == receipt.previous_path_digest)
    {
        return Ok(false);
    }
    if let Some(path) = &receipt.previous_path {
        if path == &receipt.path {
            return Ok(true);
        }
        let current = io::read_digest(io::owned_path(path)?)?;
        if current.is_some() && current != receipt.previous_path_digest {
            return Ok(false);
        }
    }
    Ok(true)
}

fn observe_removal(
    receipt: Option<&Receipt>,
    current: Option<String>,
    receipt_path: &Path,
) -> Result<Value> {
    let Some(receipt) = receipt else {
        return Ok(json!({"status": if current.is_none() { "absent" } else { "indeterminate" }}));
    };
    if !removal_safe(receipt)? {
        return Ok(json!({"status": "indeterminate"}));
    }
    for path in &receipt.owned_paths {
        if io::read_digest(io::owned_path(path)?)?.is_some() {
            return Ok(json!({"status": "retry-safe"}));
        }
    }
    io::unlink(receipt_path)?;
    Ok(json!({"status": "absent"}))
}

fn save(path: &Path, receipt: &Receipt) -> Result<()> {
    io::write(path, &serde_json::to_vec(receipt)?, 0o600)
}

fn apply(
    invocation: &Invocation,
    state_directory: &Path,
    receipt_path: &Path,
    receipt: Option<&Receipt>,
    contents: &[u8],
    expected: String,
    current: Option<String>,
) -> Result<Value> {
    ensure!(
        safe(current.as_deref(), &expected, receipt),
        "configuration destination conflicts with externally modified data"
    );
    let path = io::owned_path(&invocation.input.path)?;
    let permissions = io::mode(&invocation.input.mode)?;
    let (uid, gid) = ownership(&invocation.input)?;
    for entry in fs::read_dir(state_directory)? {
        let entry = entry?;
        if entry.path() == receipt_path
            || entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
        {
            continue;
        }
        let other: Value = serde_json::from_reader(
            io::regular(&entry.path())?.context("ownership receipt is absent")?,
        )?;
        let claims = other["owned_paths"]
            .as_array()
            .context("native receipt has no owned paths")?;
        for claim in claims {
            let claim = io::normalize(
                claim
                    .as_str()
                    .context("native claim path is not a string")?,
            )?;
            ensure!(
                claim != invocation.input.path,
                "native resource is owned by another installation effect"
            );
        }
    }
    // Recovery carries the original destination through every interrupted replay.
    let (previous_path, previous_path_digest) = match receipt {
        Some(receipt) if receipt.pending => (
            receipt.previous_path.clone(),
            receipt.previous_path_digest.clone(),
        ),
        Some(receipt) => (Some(receipt.path.clone()), Some(receipt.digest.clone())),
        None => (None, None),
    };
    let mut owned_paths = BTreeSet::from([invocation.input.path.clone()]);
    if let Some(path) = &previous_path {
        owned_paths.insert(path.clone());
    }
    let mut pending = Receipt {
        kind: "configuration".into(),
        id: invocation.id.clone(),
        revision: invocation.revision.clone(),
        path: invocation.input.path.clone(),
        digest: expected,
        pending: true,
        owned_paths,
        previous_digest: current,
        previous_path,
        previous_path_digest,
    };
    save(receipt_path, &pending)?;
    io::write(path, contents, permissions)?;
    if uid.is_some() || gid.is_some() {
        let file =
            io::regular(path)?.context("configuration disappeared before ownership update")?;
        fchown(&file, uid.map(Uid::from_raw), gid.map(Gid::from_raw))?;
        file.sync_all()?;
    }
    if let Some(old_path) = &pending.previous_path {
        if old_path != &invocation.input.path {
            let old_path = io::owned_path(old_path)?;
            let observed = io::read_digest(old_path)?;
            ensure!(
                observed.is_none() || observed == pending.previous_path_digest,
                "previous configuration path changed outside its effect"
            );
            io::unlink(old_path)?;
        }
    }
    pending.pending = false;
    pending.owned_paths = BTreeSet::from([pending.path.clone()]);
    pending.previous_digest = None;
    pending.previous_path = None;
    pending.previous_path_digest = None;
    save(receipt_path, &pending)?;
    Ok(results(path, contents))
}

fn results(path: &Path, contents: &[u8]) -> Value {
    json!({"path": path, "resource": format!("configuration:{}:{}", io::digest(path.as_os_str().as_encoded_bytes()), io::digest(contents))})
}

fn ownership(input: &Input) -> Result<(Option<u32>, Option<u32>)> {
    Ok((
        input
            .owner
            .as_deref()
            .map(|name| account("passwd", name))
            .transpose()?,
        input
            .group
            .as_deref()
            .map(|name| account("group", name))
            .transpose()?,
    ))
}

fn account(database: &str, name: &str) -> Result<u32> {
    ensure!(
        !name.is_empty() && !name.contains(['\0', '\n', ':']) && !name.starts_with('-'),
        "invalid account name"
    );
    // The source-built helper calls name-based NSS APIs even for numeric names.
    let executable = option_env!("AOS_ACCOUNT_LOOKUP")
        .context("NSS account lookup executable was not pinned at build time")?;
    let mut child = Command::new(executable)
        .args([database, name])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("resolving configuration account through NSS")?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .context("account lookup output is absent")?
        .take(128)
        .read_to_end(&mut output)?;
    if output.len() >= 128 {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("NSS account lookup response exceeds bound");
    }
    let status = child.wait()?;
    ensure!(
        status.code() != Some(2),
        "unknown {database} account {name}"
    );
    ensure!(status.success(), "NSS {database} account lookup failed");
    let record = std::str::from_utf8(&output)?.trim_end();
    ensure!(
        !record.is_empty() && record.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid NSS identity response"
    );
    Ok(record.parse()?)
}

#[cfg(test)]
mod tests;
