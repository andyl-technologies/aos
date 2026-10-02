//! Delivers bounded credentials into private views without exposing plaintext in receipts.
//!
//! Private JSON receipts retain hashes rather than credential bytes:
//!
//! ```json
//! {"owner":"effect-id","revision":"...","source":"/run/credentials/@system/name",
//! "encrypted":false,"source_digest":"...","view":"/run/aos/credential-views/key/credential",
//! "view_digest":"...","previous_view_digest":null,"complete":true}
//! ```

use std::fs;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    atomic_write, digest, key, normalized_path, private_directory, read_regular, state_path,
};

const ENCRYPTED_ROOTS: [&str; 3] = [
    "/run/credstore.encrypted",
    "/etc/credstore.encrypted",
    "/usr/lib/credstore.encrypted",
];
const CLEAR_ROOT: &str = "/run/credentials/@system";
const VIEW_ROOT: &str = "/run/aos/credential-views";
const LIMIT: u64 = 1_048_576;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default = "system")]
    scope: String,
    #[serde(default)]
    encrypted: bool,
}

fn system() -> String {
    "system".into()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    owner: String,
    revision: String,
    source: PathBuf,
    encrypted: bool,
    source_digest: String,
    view: PathBuf,
    view_digest: String,
    previous_view_digest: Option<String>,
    complete: bool,
}

fn source(input: &Input) -> Result<PathBuf> {
    ensure!(
        input.scope == "system",
        "user credential scope is unavailable"
    );
    ensure!(
        input.name.is_some() != input.resource.is_some(),
        "exactly one credential name or resource is required"
    );
    if let Some(name) = &input.name {
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                && name != "."
                && name != "..",
            "invalid credential name"
        );
        if !input.encrypted {
            return Ok(Path::new(CLEAR_ROOT).join(name));
        }
        let mut candidates = Vec::new();
        for root in ENCRYPTED_ROOTS {
            let candidate = Path::new(root).join(name);
            if read_regular(&candidate, LIMIT)?.is_some() {
                candidates.push(candidate);
            }
        }
        ensure!(
            candidates.len() == 1,
            "encrypted credential source is unavailable or ambiguous"
        );
        return candidates
            .pop()
            .context("encrypted credential source missing");
    }
    let path = normalized_path(
        input
            .resource
            .as_deref()
            .context("credential resource missing")?,
    )?;
    let roots: Vec<&str> = if input.encrypted {
        ENCRYPTED_ROOTS.to_vec()
    } else {
        vec![CLEAR_ROOT, VIEW_ROOT]
    };
    ensure!(
        roots
            .iter()
            .any(|root| path.starts_with(root) && path != Path::new(root)),
        "credential source is outside authorized roots"
    );
    Ok(path.into())
}

fn view(invocation: &Invocation) -> PathBuf {
    Path::new(VIEW_ROOT)
        .join(key(&invocation.id))
        .join("credential")
}

fn owned_digest(receipt: &Receipt, bytes: &[u8]) -> bool {
    let actual = digest(bytes);
    actual == receipt.view_digest
        || (!receipt.complete && receipt.previous_view_digest.as_ref() == Some(&actual))
}

fn validate_receipt(invocation: &Invocation, receipt: &Receipt) -> Result<()> {
    ensure!(
        receipt.owner == invocation.id && receipt.view == view(invocation),
        "credential receipt ownership differs"
    );
    if let Some(bytes) = read_regular(&receipt.view, LIMIT)? {
        let metadata = fs::symlink_metadata(&receipt.view)?;
        ensure!(
            metadata.uid() == 0
                && metadata.permissions().mode() & 0o777 == 0o600
                && owned_digest(receipt, &bytes),
            "credential view differs from receipt"
        );
    }
    Ok(())
}

fn decrypt(program: Option<&str>, source_bytes: &[u8], input: &Input) -> Result<Vec<u8>> {
    let program = program.context("encrypted delivery requires pinned systemd-creds")?;
    let path = normalized_path(program)?;
    ensure!(
        path.starts_with("/nix/store") && path.components().count() >= 5,
        "systemd-creds is not an immutable store executable"
    );
    let mut command = Command::new(path);
    command.arg("decrypt");
    if let Some(name) = &input.name {
        command.arg(format!("--name={name}"));
    }
    let mut snapshot = tempfile::tempfile()?;
    snapshot.write_all(source_bytes)?;
    snapshot.rewind()?;
    command
        .arg("-")
        .arg("-")
        .stdin(Stdio::from(snapshot))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .context("cannot launch pinned credential decryptor")?;
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .context("decryptor has no output channel")?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        let _ = child.kill();
        let _ = child.wait();
        bail!("decrypted credential exceeds byte limit");
    }
    ensure!(
        child.wait()?.success(),
        "encrypted credential could not be decrypted"
    );
    Ok(bytes)
}

/// Delivers, revokes, or observes a private credential view.
///
/// # Errors
/// Returns an error for unavailable or ambiguous sources, unauthorized paths,
/// changed owned bytes, or unsuccessful encrypted delivery.
pub(super) fn execute(invocation: &Invocation, action: &str, creds: Option<&str>) -> Result<Value> {
    let input: Input = serde_json::from_value(invocation.input.clone())?;
    let path = state_path(invocation, "credential");
    let previous: Option<Receipt> = read_regular(&path, LIMIT)?
        .map(|bytes| serde_json::from_slice(&bytes))
        .transpose()?;
    if let Some(receipt) = &previous {
        validate_receipt(invocation, receipt)?;
    }
    let destination = view(invocation);
    let outputs = json!({"path":destination,"resource":destination});

    if action == "remove" {
        if let Some(receipt) = previous {
            if read_regular(&receipt.view, LIMIT)?.is_some() {
                fs::remove_file(&receipt.view)?;
            }
            fs::remove_file(path)?;
        } else {
            ensure!(
                read_regular(&destination, LIMIT)?.is_none(),
                "credential view exists without ownership receipt"
            );
        }
        return Ok(json!({}));
    }
    if action == "observe" {
        return Ok(
            match observe(invocation, &input, previous.as_ref(), &destination, outputs) {
                Ok(value) => value,
                Err(_) => json!({"status":"indeterminate"}),
            },
        );
    }

    let source = source(&input)?;
    let source_bytes = read_regular(&source, LIMIT)?.context("credential source is unavailable")?;
    let bytes = if input.encrypted {
        decrypt(creds, &source_bytes, &input)?
    } else {
        source_bytes.clone()
    };
    let mut receipt = Receipt {
        owner: invocation.id.clone(),
        revision: invocation.revision.clone(),
        source,
        encrypted: input.encrypted,
        source_digest: digest(&source_bytes),
        view: destination.clone(),
        view_digest: digest(&bytes),
        // A retry can find the old generation still live; preserve its actual hash.
        previous_view_digest: read_regular(&destination, LIMIT)?.map(|bytes| digest(&bytes)),
        complete: false,
    };
    private_directory(path.parent().context("receipt parent missing")?)?;
    private_directory(
        destination
            .parent()
            .context("credential view parent missing")?,
    )?;
    if previous.is_none() {
        ensure!(
            read_regular(&destination, LIMIT)?.is_none(),
            "credential view already exists without ownership receipt"
        );
    }

    // An interrupted replacement recognizes either exact owned byte generation.
    atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
    atomic_write(&destination, &bytes, 0o600)?;
    receipt.view_digest = digest(&bytes);
    receipt.previous_view_digest = None;
    receipt.complete = true;
    atomic_write(&path, &serde_json::to_vec(&receipt)?, 0o600)?;
    Ok(outputs)
}

fn observe(
    invocation: &Invocation,
    input: &Input,
    receipt: Option<&Receipt>,
    destination: &Path,
    outputs: Value,
) -> Result<Value> {
    let Some(receipt) = receipt else {
        ensure!(
            read_regular(destination, LIMIT)?.is_none(),
            "unowned credential view exists"
        );
        return Ok(
            json!({"status": if invocation.action == Action::Remove { "absent" } else { "retry-safe" }}),
        );
    };
    if invocation.action == Action::Remove
        || !receipt.complete
        || receipt.revision != invocation.revision
        || read_regular(destination, LIMIT)?.is_none()
    {
        return Ok(json!({"status":"retry-safe"}));
    }
    let source = source(input)?;
    let bytes = read_regular(&source, LIMIT)?.context("credential source disappeared")?;
    if source != receipt.source
        || input.encrypted != receipt.encrypted
        || digest(&bytes) != receipt.source_digest
    {
        return Ok(json!({"status":"retry-safe"}));
    }
    Ok(json!({"status":"current","outputs":outputs}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_credential_rotation_recognizes_only_retained_generations() {
        let mut receipt = Receipt {
            owner: "effect".into(),
            revision: "a".repeat(64),
            source: "/run/credentials/@system/source".into(),
            encrypted: false,
            source_digest: digest(b"new"),
            view: "/run/aos/credential-views/key/credential".into(),
            view_digest: digest(b"new"),
            previous_view_digest: Some(digest(b"old")),
            complete: false,
        };
        assert!(owned_digest(&receipt, b"old"));
        assert!(owned_digest(&receipt, b"new"));
        assert!(!owned_digest(&receipt, b"foreign"));
        receipt.complete = true;
        assert!(!owned_digest(&receipt, b"old"));
        assert!(owned_digest(&receipt, b"new"));
        let serialized = serde_json::to_string(&receipt).unwrap();
        assert!(!serialized.contains("\"new\""));
        assert!(!serialized.contains("\"old\""));
    }

    #[test]
    fn delivery_requires_one_source_and_known_scope() {
        for value in [
            json!({}),
            json!({"name":"one","resource":"/run/credentials/@system/two"}),
            json!({"name":"../foreign"}),
            json!({"name":"valid","scope":"user"}),
            json!({"resource":"/etc/shadow"}),
            json!({"resource":"/run/credentials/@system/name","encrypted":true}),
        ] {
            let input: Input = serde_json::from_value(value).unwrap();
            assert!(source(&input).is_err());
        }
        let input: Input = serde_json::from_value(json!({"name":"service-secret"})).unwrap();
        assert_eq!(
            source(&input).unwrap(),
            Path::new(CLEAR_ROOT).join("service-secret")
        );
    }

    #[test]
    fn encrypted_delivery_cannot_fall_back_to_plaintext() {
        let input: Input =
            serde_json::from_value(json!({"name":"secret","encrypted":true})).unwrap();
        assert!(decrypt(None, b"ciphertext", &input).is_err());
        assert!(decrypt(Some("/usr/bin/systemd-creds"), b"ciphertext", &input).is_err());
    }
}
