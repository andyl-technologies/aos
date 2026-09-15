//! OpenZFS-backed storage-pool import resources.

use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{AbilityValue, ResourceReference, RevisionId};
use aos_provider_protocol::ResourceContext;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::engine::{Backend, BackendObservation, ability_value};
use crate::process::{Executable, ExecutableReference};
use crate::state;

const INTERFACE: &str = "aos.zfs.storage-pool-effects";
const REALIZATION_SCHEMA: &str = "aos.storage.pool-realization/v1";
const OBSERVATION_SCHEMA: &str = "aos.ability.storage-pool-observation/v1";
const CONTEXT_SCHEMA: &str = "aos.zfs.storage-pool-context/v1";
const MARKER_SCHEMA: &str = "aos.zfs.storage-pool-state/v1";
const STATE_ROOT: &str = "/run/aos/storage-pools";
const MARKER_DOMAIN: &str = "aos.storage.pool-resource/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    name: String,
    enabled: bool,
    pool: String,
    import_policy: ImportPolicy,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ImportPolicy {
    Force,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Realization {
    schema: String,
    zpool: ExecutableReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    zpool: Executable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    revision: RevisionId,
    pool: String,
    pending: bool,
}

/// Implements pool import effects through one exact zpool executable.
pub struct ZfsPoolBackend;

impl Backend for ZfsPoolBackend {
    fn interface_name(&self) -> &'static str {
        INTERFACE
    }

    fn action_method(&self) -> &'static str {
        "import"
    }

    fn path_output(&self) -> &'static str {
        "pool-name"
    }

    fn admit_context(
        &self,
        desired: &AbilityValue,
        realization: &AbilityValue,
        _target: &ResourceReference,
        _revision: RevisionId,
        _resources: &[ResourceContext],
    ) -> Result<AbilityValue> {
        validate_desired(&decode(desired)?)?;
        let realization: Realization = decode(realization)?;
        ensure!(
            realization.schema == REALIZATION_SCHEMA,
            "unsupported storage-pool realization"
        );
        ability_value(serde_json::to_value(Context {
            schema: CONTEXT_SCHEMA.into(),
            zpool: realization.zpool.resolve()?,
        })?)
    }

    fn observe(
        &self,
        desired: &AbilityValue,
        _realization: &AbilityValue,
        target: &ResourceReference,
        revision: RevisionId,
        context: &AbilityValue,
    ) -> Result<BackendObservation> {
        let desired_value: Desired = decode(desired)?;
        let context: Context = decode(context)?;
        validate_context(&context)?;
        let marker = read_marker(target)?;
        let imported = is_imported(&context.zpool, &desired_value.pool)?;
        let (state_name, ready, released) =
            classify(&desired_value, revision, marker.as_ref(), imported);
        let evidence = ability_value(json!({
            "schema": OBSERVATION_SCHEMA,
            "expected": desired.as_json(),
            "realized": ready.then(|| desired_value.pool.clone()),
            "state": state_name,
        }))?;
        Ok(BackendObservation {
            evidence,
            ready,
            released,
            path: ready.then_some(desired_value.pool),
            unknown: false,
        })
    }

    fn apply(
        &self,
        desired: &AbilityValue,
        _realization: &AbilityValue,
        target: &ResourceReference,
        revision: RevisionId,
        context: &AbilityValue,
        remaining_millis: u64,
    ) -> Result<()> {
        let desired: Desired = decode(desired)?;
        let context: Context = decode(context)?;
        validate_context(&context)?;
        let old_marker = read_marker(target)?;
        if let Some(marker) = old_marker
            .as_ref()
            .filter(|marker| marker.pool != desired.pool)
            && is_imported(&context.zpool, &marker.pool)?
        {
            run_success(
                &context.zpool,
                &["export", "--", &marker.pool],
                remaining_millis,
            )?;
        }

        let pending = Marker {
            schema: MARKER_SCHEMA.into(),
            revision,
            pool: desired.pool.clone(),
            pending: true,
        };
        write_marker(target, &pending)?;
        if !is_imported(&context.zpool, &desired.pool)? {
            run_success(
                &context.zpool,
                &["import", "-N", "-f", "--", &desired.pool],
                remaining_millis,
            )?;
        }
        write_marker(
            target,
            &Marker {
                pending: false,
                ..pending
            },
        )
    }

    fn release(
        &self,
        _desired: &AbilityValue,
        _realization: &AbilityValue,
        target: &ResourceReference,
        context: &AbilityValue,
        remaining_millis: u64,
    ) -> Result<()> {
        let context: Context = decode(context)?;
        validate_context(&context)?;
        if let Some(marker) = read_marker(target)?
            && is_imported(&context.zpool, &marker.pool)?
        {
            run_success(
                &context.zpool,
                &["export", "--", &marker.pool],
                remaining_millis,
            )?;
        }
        remove_marker(target)
    }
}

fn classify(
    desired: &Desired,
    revision: RevisionId,
    marker: Option<&Marker>,
    imported: bool,
) -> (&'static str, bool, bool) {
    let exact_marker =
        marker.is_some_and(|marker| marker.revision == revision && marker.pool == desired.pool);
    let ready = desired.enabled && imported && exact_marker;
    let released = marker.is_none();
    let state = if ready {
        "ready"
    } else if marker.is_none() && !imported {
        "absent"
    } else if marker.is_none() {
        "unmanaged"
    } else {
        "drifted"
    };
    (state, ready, released)
}

fn is_imported(zpool: &Executable, pool: &str) -> Result<bool> {
    let output = zpool.run(&["list", "-H", "-o", "name", "--", pool], 5_000)?;
    if !output.status.success() {
        ensure!(
            output.status.code() == Some(1),
            "zpool inspection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(false);
    }
    let observed = String::from_utf8(output.stdout).context("decoding zpool output")?;
    Ok(observed.trim() == pool)
}

fn validate_desired(desired: &Desired) -> Result<()> {
    validate_pool_name(&desired.pool)?;
    ensure!(
        !desired.name.is_empty() && desired.name.len() <= 128,
        "storage-pool request name is invalid"
    );
    Ok(())
}

fn validate_pool_name(pool: &str) -> Result<()> {
    ensure!(
        !pool.is_empty() && pool.len() <= 255,
        "storage-pool name is invalid"
    );
    ensure!(
        pool.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_alphabetic()
            } else {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            }
        }),
        "storage-pool name is invalid"
    );
    Ok(())
}

fn validate_context(context: &Context) -> Result<()> {
    ensure!(
        context.schema == CONTEXT_SCHEMA,
        "unsupported storage-pool context"
    );
    Ok(())
}

fn read_marker(target: &ResourceReference) -> Result<Option<Marker>> {
    let marker: Marker = match state::read(Path::new(STATE_ROOT), MARKER_DOMAIN, target)? {
        Some(marker) => marker,
        None => return Ok(None),
    };
    ensure!(
        marker.schema == MARKER_SCHEMA,
        "unsupported storage-pool marker"
    );
    validate_pool_name(&marker.pool)?;
    Ok(Some(marker))
}

fn write_marker(target: &ResourceReference, marker: &Marker) -> Result<()> {
    state::write(Path::new(STATE_ROOT), MARKER_DOMAIN, target, marker)
}

fn remove_marker(target: &ResourceReference) -> Result<()> {
    state::remove(Path::new(STATE_ROOT), MARKER_DOMAIN, target)
}

fn run_success(executable: &Executable, arguments: &[&str], remaining_millis: u64) -> Result<()> {
    let output = executable.run(arguments, remaining_millis)?;
    ensure!(
        output.status.success(),
        "zpool command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn decode<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding storage-pool value")
}

#[cfg(test)]
mod tests {
    use aos_contract::Sha256Digest;

    use super::*;

    fn revision(label: &[u8]) -> RevisionId {
        RevisionId(Sha256Digest::of_bytes(label))
    }

    fn desired() -> Desired {
        Desired {
            name: "pool".into(),
            enabled: true,
            pool: "aos-pool".into(),
            import_policy: ImportPolicy::Force,
            prerequisites: vec![],
        }
    }

    #[test]
    fn ambient_import_is_unmanaged() {
        assert_eq!(
            classify(&desired(), revision(b"desired"), None, true),
            ("unmanaged", false, true)
        );
    }

    #[test]
    fn pending_exact_import_is_recoverably_ready() {
        let marker = Marker {
            schema: MARKER_SCHEMA.into(),
            revision: revision(b"desired"),
            pool: "aos-pool".into(),
            pending: true,
        };
        assert_eq!(
            classify(&desired(), revision(b"desired"), Some(&marker), true),
            ("ready", true, false)
        );
    }
}
