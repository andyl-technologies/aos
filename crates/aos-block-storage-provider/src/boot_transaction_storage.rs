//! Native checked views of pre-mounted boot transaction storage.
//!
//! Mounting the ESP is a bootstrap prerequisite. This handler verifies its
//! journal directory and exports the locator; removal retires only the view,
//! preserving journals and their recovery receipts.

use std::fs;
use std::path::{Component, Path};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_contract::limits::JsonLimits;
use serde::Deserialize;
use serde_json::json;

const LIMITS: JsonLimits = JsonLimits {
    max_bytes: 256 * 1024,
    max_depth: 64,
    max_items: 65_536,
    max_string_bytes: 128 * 1024,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    path: String,
}

/// Verifies and exports a mounted journal directory for the boot runtime.
///
/// # Errors
/// Returns an error for invalid invocation data, an unnormalized locator,
/// missing storage, or a symbolic link substituted for the journal directory.
pub fn handle(operation: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let invocation: Invocation = LIMITS.decode(bytes, "boot storage invocation")?;
    let desired: Desired =
        serde_json::from_value(invocation.input).context("decoding boot storage input")?;
    validate_path(&desired.path)?;

    let output = match operation {
        "remove" => {
            ensure!(
                invocation.action == Action::Remove,
                "remove action differs from invocation"
            );
            json!({})
        }
        "apply" | "observe" => {
            let metadata = fs::symlink_metadata(&desired.path);
            let ready = match metadata {
                Ok(metadata) => metadata.is_dir() && !metadata.file_type().is_symlink(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error).context("inspecting boot storage directory"),
            };
            if operation == "observe" {
                if invocation.action == Action::Remove {
                    json!({"status": "absent"})
                } else if ready {
                    json!({"status": "current", "outputs": {"path": desired.path}})
                } else {
                    json!({"status": "indeterminate"})
                }
            } else {
                ensure!(
                    invocation.action == Action::Apply,
                    "apply action differs from invocation"
                );
                ensure!(
                    ready,
                    "boot transaction storage has not been mounted by the bootstrap sequence"
                );
                json!({"path": desired.path})
            }
        }
        _ => bail!("unsupported boot storage operation {operation:?}"),
    };
    serde_json::to_vec(&output).context("encoding boot storage response")
}

fn validate_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "transaction storage path is not absolute and normalized"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation(path: &Path, action: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": "stage-storage", "revision": "first", "action": action, "previous": null,
            "input": {"path": path},
            "effect": {
                "owner": "boot", "identity": ["initrd", "storage"], "input": {}, "inputs": {},
                "input_type": {"kind": "submodule", "open": false, "fields": {}}, "after": [],
                "results": {"path": {"kind": "string"}}, "dependencies": [], "revision": "first",
                "lifetime": "instance", "timeout_ms": 1000,
                "handler": {"kind": "process", "artifact": "/nix/store/00000000000000000000000000000000-handler", "executable": "/nix/store/00000000000000000000000000000000-handler/bin/handler"}
            }
        })).expect("native invocation")
    }

    #[test]
    fn view_teardown_preserves_recovery_journals() {
        let directory = tempfile::tempdir().expect("journal directory");
        let journal = directory.path().join("generations.journal");
        fs::write(&journal, b"retained generation").expect("journal receipt");
        let apply = invocation(directory.path(), "apply");

        let output: serde_json::Value =
            serde_json::from_slice(&handle("apply", &apply).expect("verify storage"))
                .expect("response");
        assert_eq!(output["path"], directory.path().to_str().expect("path"));

        handle("remove", &invocation(directory.path(), "remove")).expect("retire view");
        assert_eq!(
            fs::read(journal).expect("retained journal"),
            b"retained generation"
        );
    }

    #[test]
    fn missing_or_substituted_storage_fails_before_execution() {
        let directory = tempfile::tempdir().expect("journal directory");
        let missing = directory.path().join("missing");
        assert!(handle("apply", &invocation(&missing, "apply")).is_err());
        let substituted = directory.path().join("substituted");
        std::os::unix::fs::symlink(directory.path(), &substituted).expect("substituted directory");
        assert!(handle("apply", &invocation(&substituted, "apply")).is_err());
    }

    #[test]
    fn rejects_noncanonical_view_paths() {
        assert!(validate_path("/run/aos-boot-transaction-storage/journal").is_ok());
        assert!(validate_path("/run/../boot").is_err());
        assert!(validate_path("boot").is_err());
    }
}
