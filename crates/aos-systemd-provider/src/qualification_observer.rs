//! Independent read-only qualification observations for systemd service effects.
//!
//! The observer discovers the exact units owned by a checked resource from the
//! provider's durable receipts, then reads their live state from the pinned
//! systemd manager. It never invokes an effect handler or execution journal.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write as _};
use std::path::{Component, Path};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{ABILITY_LIMITS_V1, LocalKey, Operation, ResourceId};
use aos_contract::Sha256Digest;
use aos_systemd::PinnedSystemdManager;
use serde::{Deserialize, Serialize};

const RECEIPT_ROOT: &str = "/etc/aos/ability-revisions";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverArguments {
    request_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverRequest {
    adapter: LocalKey,
    scope: LocalKey,
    operation: Operation,
}

#[derive(Debug, Serialize)]
struct ObserverResult {
    provider: LocalKey,
    kind: LocalKey,
    scope: LocalKey,
    observation: String,
}

#[derive(Debug, Serialize)]
struct SystemdObservation<'a> {
    kind: &'static str,
    resource: &'a ResourceId,
    manager: ManagerObservation,
    receipts: Vec<ReceiptObservation>,
    units: Vec<UnitObservation>,
}

#[derive(Debug, Serialize)]
struct ManagerObservation {
    bus_id: String,
    owner: String,
}

#[derive(Debug, Serialize)]
struct ReceiptObservation {
    path: String,
    digest: Sha256Digest,
}

#[derive(Debug, Serialize)]
struct UnitObservation {
    unit: String,
    identity: Option<String>,
    active_state: Option<String>,
}

/// Runs the package-owned service-effects qualification observer.
///
/// # Errors
///
/// Returns an error when the request is malformed, the receipt inventory
/// exceeds canonical bounds, or live manager state cannot be read.
pub(crate) async fn run() -> Result<()> {
    let arguments: ObserverArguments = read_json(io::stdin())?;
    let request_path = Path::new(&arguments.request_path);
    ensure!(
        request_path.is_absolute()
            && !request_path
                .components()
                .any(|component| matches!(component, Component::ParentDir)),
        "qualification observer request path is not absolute and normalized",
    );

    let request: ObserverRequest = serde_json::from_slice(&read_bounded(request_path)?)
        .context("decoding observer request")?;
    ensure!(
        request.operation.target.interface == request.operation.interface,
        "qualification operation target selects another interface",
    );

    let manager = PinnedSystemdManager::connect().await?;
    let (receipts, unit_names) =
        receipts_for(Path::new(RECEIPT_ROOT), &request.operation.target.resource)?;
    let mut units = Vec::new();
    for unit in unit_names {
        let identity = match manager.unit_identity(&unit).await {
            Ok(identity) => Some(identity),
            Err(error) if error.is_no_such_unit() => None,
            Err(error) => return Err(error.into()),
        };
        let active_state = match &identity {
            Some(identity) => Some(
                manager
                    .active_state_exact(&unit, identity)
                    .await?
                    .label()
                    .to_string(),
            ),
            None => None,
        };
        units.push(UnitObservation {
            unit,
            identity,
            active_state,
        });
    }

    let observation = SystemdObservation {
        kind: "systemd",
        resource: &request.operation.target.resource,
        manager: ManagerObservation {
            bus_id: manager.incarnation().bus_id().to_string(),
            owner: manager.incarnation().owner().to_string(),
        },
        receipts,
        units,
    };
    let observation = String::from_utf8(aos_contract::canonical::to_vec(&observation)?)
        .context("encoding systemd observation as UTF-8")?;
    let result = ObserverResult {
        provider: request.adapter,
        kind: LocalKey::new("systemd")?,
        scope: request.scope,
        observation,
    };
    io::stdout().write_all(&aos_contract::canonical::to_vec(&result)?)?;
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(input: impl Read) -> Result<T> {
    let mut bytes = Vec::new();
    input
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "qualification observer input exceeds the canonical document bound",
    );
    serde_json::from_slice(&bytes).context("decoding qualification observer input")
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "observer request is not a regular file"
    );
    ensure!(
        metadata.len() <= ABILITY_LIMITS_V1.max_document_bytes,
        "observer request exceeds the canonical document bound",
    );
    fs::read(path).context("reading qualification observer request")
}

fn receipts_for(
    root: &Path,
    resource: &ResourceId,
) -> Result<(Vec<ReceiptObservation>, Vec<String>)> {
    let mut pending = vec![root.to_path_buf()];
    let mut inspected = 0_u64;
    let mut receipts = Vec::new();
    let mut units = BTreeSet::new();
    let resource = serde_json::to_value(resource)?;

    while let Some(path) = pending.pop() {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                let mut entries = fs::read_dir(&path)?.collect::<Result<Vec<_>, _>>()?;
                entries.sort_by_key(fs::DirEntry::file_name);
                for entry in entries.into_iter().rev() {
                    inspected += 1;
                    ensure!(
                        inspected <= ABILITY_LIMITS_V1.max_collection_items,
                        "systemd receipt inventory exceeds its canonical bound",
                    );
                    pending.push(entry.path());
                }
            }
            Ok(metadata) if metadata.file_type().is_file() => {
                ensure!(
                    metadata.len() <= ABILITY_LIMITS_V1.max_document_bytes,
                    "systemd receipt exceeds the canonical document bound",
                );
                let bytes = fs::read(&path)?;
                let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                    continue;
                };
                if document.get("resource") != Some(&resource) {
                    continue;
                }
                collect_units(&document, &mut units)?;
                receipts.push(ReceiptObservation {
                    path: path.to_string_lossy().into_owned(),
                    digest: Sha256Digest::of_bytes(&bytes),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    receipts.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((receipts, units.into_iter().collect()))
}

fn collect_units(document: &serde_json::Value, units: &mut BTreeSet<String>) -> Result<()> {
    for field in ["unit_name", "units"] {
        let Some(value) = document.get(field) else {
            continue;
        };
        let candidates = match value {
            serde_json::Value::String(unit) => vec![unit.as_str()],
            serde_json::Value::Array(units) => units
                .iter()
                .map(|unit| unit.as_str().context("receipt unit is not a string"))
                .collect::<Result<Vec<_>>>()?,
            _ => bail!("receipt unit inventory has an unsupported shape"),
        };
        for unit in candidates {
            ensure!(
                !unit.is_empty()
                    && unit.len() <= 255
                    && unit
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric()
                            || "_.@:-".contains(character)),
                "receipt carries an invalid systemd unit name",
            );
            units.insert(unit.to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aos_ability_model::ResourceId;
    use tempfile::tempdir;

    use super::receipts_for;

    #[test]
    fn receipts_select_only_the_exact_checked_resource() {
        let directory = tempdir().expect("temporary receipt root");
        let resource: ResourceId = serde_json::from_value(serde_json::json!({
            "provider": {
                "environment": {"authority": "test", "key": "host", "stage": "host"},
                "key": "systemd",
            },
            "key": "example",
        }))
        .expect("resource fixture parses");
        fs::write(
            directory.path().join("receipt"),
            aos_contract::canonical::to_vec(&serde_json::json!({
                "schema": "aos.systemd.service-revision/v1",
                "resource": resource,
                "units": ["example.service"],
                "links": [],
                "revision": format!("sha256:{}", "1".repeat(64)),
            }))
            .expect("receipt encodes"),
        )
        .expect("receipt writes");

        let (receipts, units) = receipts_for(directory.path(), &resource).expect("scan succeeds");

        assert_eq!(receipts.len(), 1);
        assert_eq!(units, ["example.service"]);
    }
}
