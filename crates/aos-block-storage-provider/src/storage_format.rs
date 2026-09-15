//! Util-linux-backed storage-format convergence.

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{AbilityValue, ResourceReference, RevisionId};
use aos_contract::Sha256Digest;
use aos_provider_protocol::ResourceContext;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::engine::{Backend, BackendObservation, ability_value};
use crate::process::{Executable, ExecutableReference};

const INTERFACE: &str = "aos.util-linux.storage-format-effects";
const REALIZATION_SCHEMA: &str = "aos.storage.format-realization/v1";
const OBSERVATION_SCHEMA: &str = "aos.ability.storage-format-observation/v1";
const CONTEXT_SCHEMA: &str = "aos.util-linux.storage-format-context/v1";
const MARKER_SCHEMA: &str = "aos.util-linux.storage-format-state/v1";
const STATE_ROOT: &str = "/run/aos/storage-formats";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    name: String,
    enabled: bool,
    source: String,
    format: StorageFormat,
    policy: FormatPolicy,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum StorageFormat {
    Swap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum FormatPolicy {
    Always,
    IfAbsent,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Realization {
    schema: String,
    mkswap: ExecutableReference,
    blkid: ExecutableReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    mkswap: Executable,
    blkid: Executable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    revision: RevisionId,
    source: String,
    format: StorageFormat,
    pending: bool,
}

/// Implements explicit storage formatting through exact util-linux tools.
pub struct StorageFormatBackend;

impl Backend for StorageFormatBackend {
    fn interface_name(&self) -> &'static str {
        INTERFACE
    }

    fn action_method(&self) -> &'static str {
        "format"
    }

    fn path_output(&self) -> &'static str {
        "formatted-path"
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
            "unsupported storage-format realization"
        );
        let context = Context {
            schema: CONTEXT_SCHEMA.into(),
            mkswap: realization.mkswap.resolve()?,
            blkid: realization.blkid.resolve()?,
        };
        ability_value(serde_json::to_value(context)?)
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
        ensure!(
            context.schema == CONTEXT_SCHEMA,
            "unsupported storage-format context"
        );
        let marker = read_marker(target)?;
        let source = canonical_source(&desired_value.source).ok();
        let observed_format = source
            .as_deref()
            .map(|source| inspect_format(&context.blkid, source))
            .transpose()?;
        let (state, ready, released) = classify(
            &desired_value,
            revision,
            marker.as_ref(),
            source.as_deref(),
            observed_format.as_ref().and_then(|value| value.as_deref()),
        );
        let evidence = ability_value(json!({
            "schema": OBSERVATION_SCHEMA,
            "expected": desired.as_json(),
            "realized": ready.then(|| source.clone()).flatten(),
            "state": state,
        }))?;
        Ok(BackendObservation {
            evidence,
            ready,
            released,
            path: ready.then(|| source).flatten(),
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
        let source = canonical_source(&desired.source)?;
        let observed = inspect_format(&context.blkid, &source)?;
        if desired.policy == FormatPolicy::IfAbsent {
            if let Some(format) = observed {
                ensure!(
                    format == "swap",
                    "refusing to replace existing storage format {format:?}"
                );
                return write_marker(
                    target,
                    &Marker {
                        schema: MARKER_SCHEMA.into(),
                        revision,
                        source,
                        format: desired.format,
                        pending: false,
                    },
                );
            }
        }

        let pending = Marker {
            schema: MARKER_SCHEMA.into(),
            revision,
            source: source.clone(),
            format: desired.format,
            pending: true,
        };
        write_marker(target, &pending)?;
        match desired.format {
            StorageFormat::Swap => {
                run_success(&context.mkswap, &["--", &source], remaining_millis)?
            }
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
        _context: &AbilityValue,
        _remaining_millis: u64,
    ) -> Result<()> {
        remove_marker(target)
    }
}

fn classify(
    desired: &Desired,
    revision: RevisionId,
    marker: Option<&Marker>,
    source: Option<&str>,
    observed_format: Option<&str>,
) -> (&'static str, bool, bool) {
    let exact_marker = marker.is_some_and(|marker| {
        marker.revision == revision
            && marker.source == source.unwrap_or("")
            && marker.format == desired.format
    });
    let ready = desired.enabled && observed_format == Some("swap") && exact_marker;
    let released = marker.is_none();
    let state = if ready {
        "ready"
    } else if marker.is_none() && observed_format.is_none() {
        "absent"
    } else if marker.is_none() {
        "unmanaged"
    } else {
        "drifted"
    };
    (state, ready, released)
}

fn inspect_format(executable: &Executable, source: &str) -> Result<Option<String>> {
    let output = executable.run(&["-p", "-o", "value", "-s", "TYPE", "--", source], 5_000)?;
    if !output.status.success() {
        ensure!(
            output.status.code() == Some(2),
            "blkid inspection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)
        .context("decoding blkid output")?
        .trim()
        .to_string();
    Ok((!value.is_empty()).then_some(value))
}

fn validate_desired(desired: &Desired) -> Result<()> {
    ensure!(
        !desired.name.is_empty() && desired.name.len() <= 128,
        "format name is invalid"
    );
    ensure!(
        desired
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')),
        "format name is invalid"
    );
    validate_path(&desired.source)
}

fn canonical_source(path: &str) -> Result<String> {
    validate_path(path)?;
    Ok(fs::canonicalize(path)
        .with_context(|| format!("resolving storage-format source {path}"))?
        .to_string_lossy()
        .into_owned())
}

fn validate_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(path.is_absolute(), "storage-format source is not absolute");
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "storage-format source is not normalized"
    );
    Ok(())
}

fn marker_path(target: &ResourceReference) -> Result<PathBuf> {
    let digest = Sha256Digest::of_canonical("aos.storage.format-resource/v1", &target.resource)?;
    Ok(Path::new(STATE_ROOT).join(digest.hex()))
}

fn read_marker(target: &ResourceReference) -> Result<Option<Marker>> {
    let path = marker_path(target)?;
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("opening storage-format marker"),
    };
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 64 * 1024, "storage-format marker is oversized");
    let marker: Marker = aos_contract::canonical::from_slice(&bytes, "storage-format marker")?;
    ensure!(
        marker.schema == MARKER_SCHEMA,
        "unsupported storage-format marker"
    );
    validate_path(&marker.source)?;
    Ok(Some(marker))
}

fn write_marker(target: &ResourceReference, marker: &Marker) -> Result<()> {
    fs::create_dir_all(STATE_ROOT)?;
    fs::set_permissions(STATE_ROOT, fs::Permissions::from_mode(0o700))?;
    let path = marker_path(target)?;
    let temporary = path.with_extension("tmp");
    let bytes = aos_contract::canonical::canonical_json(&serde_json::to_value(marker)?)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn remove_marker(target: &ResourceReference) -> Result<()> {
    match fs::remove_file(marker_path(target)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("removing storage-format marker"),
    }
}

fn run_success(executable: &Executable, arguments: &[&str], remaining_millis: u64) -> Result<()> {
    let output = executable.run(arguments, remaining_millis)?;
    ensure!(
        output.status.success(),
        "storage-format command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn decode<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding storage-format value")
}

#[cfg(test)]
mod tests {
    use aos_contract::Sha256Digest;

    use super::*;

    fn revision(label: &[u8]) -> RevisionId {
        RevisionId(Sha256Digest::of_bytes(label))
    }

    fn desired(policy: FormatPolicy) -> Desired {
        Desired {
            name: "encrypted-swap".into(),
            enabled: true,
            source: "/dev/mapper/cryptswap".into(),
            format: StorageFormat::Swap,
            policy,
            prerequisites: Vec::new(),
        }
    }

    fn marker(revision: RevisionId) -> Marker {
        Marker {
            schema: MARKER_SCHEMA.into(),
            revision,
            source: "/dev/dm-0".into(),
            format: StorageFormat::Swap,
            pending: false,
        }
    }

    #[test]
    fn ambient_matching_format_is_unmanaged() {
        let (state, ready, released) = classify(
            &desired(FormatPolicy::IfAbsent),
            revision(b"desired"),
            None,
            Some("/dev/dm-0"),
            Some("swap"),
        );

        assert_eq!(state, "unmanaged");
        assert!(!ready);
        assert!(released);
    }

    #[test]
    fn old_marker_cannot_satisfy_a_new_format_revision() {
        let marker = marker(revision(b"old"));
        let (state, ready, _) = classify(
            &desired(FormatPolicy::Always),
            revision(b"desired"),
            Some(&marker),
            Some("/dev/dm-0"),
            Some("swap"),
        );

        assert_eq!(state, "drifted");
        assert!(!ready);
    }

    #[test]
    fn pending_marker_and_exact_format_prove_completion() {
        let desired_revision = revision(b"desired");
        let mut marker = marker(desired_revision);
        marker.pending = true;
        let (state, ready, _) = classify(
            &desired(FormatPolicy::Always),
            desired_revision,
            Some(&marker),
            Some("/dev/dm-0"),
            Some("swap"),
        );

        assert_eq!(state, "ready");
        assert!(ready);
    }
}
