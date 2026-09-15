//! Cryptsetup-backed ephemeral encrypted block mappings.

use std::fs;
use std::path::{Component, Path};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{AbilityValue, ResourceReference, RevisionId};
use aos_provider_protocol::ResourceContext;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::engine::{Backend, BackendObservation, ability_value};
use crate::process::{Executable, ExecutableReference};
use crate::state;

const INTERFACE: &str = "aos.cryptsetup.encrypted-block-mapping-effects";
const REALIZATION_SCHEMA: &str = "aos.storage.encrypted-block-mapping-realization/v1";
const OBSERVATION_SCHEMA: &str = "aos.ability.encrypted-block-mapping-observation/v1";
const CONTEXT_SCHEMA: &str = "aos.cryptsetup.encrypted-block-mapping-context/v1";
const MARKER_SCHEMA: &str = "aos.cryptsetup.encrypted-block-mapping-state/v1";
const STATE_ROOT: &str = "/run/aos/encrypted-block-mappings";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Desired {
    name: String,
    enabled: bool,
    source: String,
    cipher: String,
    key_size_bits: u16,
    key: KeySource,
    prerequisites: Vec<ResourceReference>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum KeySource {
    EphemeralRandom,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Realization {
    schema: String,
    cryptsetup: ExecutableReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    cryptsetup: Executable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema: String,
    revision: RevisionId,
    name: String,
    source: String,
    cipher: String,
    key_size_bits: u16,
    pending: bool,
}

#[derive(Default)]
struct NativeState {
    active: bool,
    source: Option<String>,
    cipher: Option<String>,
    key_size_bits: Option<u16>,
}

/// Implements encrypted mapping effects through one exact cryptsetup executable.
pub struct CryptsetupBackend;

impl Backend for CryptsetupBackend {
    fn interface_name(&self) -> &'static str {
        INTERFACE
    }

    fn action_method(&self) -> &'static str {
        "open"
    }

    fn path_output(&self) -> &'static str {
        "mapped-device"
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
            "unsupported encrypted mapping realization"
        );
        let context = Context {
            schema: CONTEXT_SCHEMA.into(),
            cryptsetup: realization.cryptsetup.resolve()?,
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
            "unsupported encrypted mapping context"
        );
        let marker = read_marker(target)?;
        let native = inspect(&context.cryptsetup, &desired_value.name)?;
        let mapped = format!("/dev/mapper/{}", desired_value.name);
        let source = canonical_source(&desired_value.source).ok();
        let exact_native = native.active
            && native.source == source
            && native.cipher.as_deref() == Some(desired_value.cipher.as_str())
            && native.key_size_bits == Some(desired_value.key_size_bits);
        let (state, ready, released) = classify(
            &desired_value,
            revision,
            marker.as_ref(),
            native.active,
            exact_native,
            source.as_deref(),
        );
        let evidence = ability_value(json!({
            "schema": OBSERVATION_SCHEMA,
            "expected": desired.as_json(),
            "realized": ready.then_some(mapped.clone()),
            "state": state,
        }))?;
        Ok(BackendObservation {
            evidence,
            ready,
            released,
            path: ready.then_some(mapped),
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
        let marker = read_marker(target)?;
        if marker
            .as_ref()
            .is_some_and(|marker| marker.name != desired.name)
            && inspect(&context.cryptsetup, &desired.name)?.active
        {
            bail!("refusing to replace an unmanaged encrypted mapping");
        }
        if let Some(marker) = &marker {
            let owned = inspect(&context.cryptsetup, &marker.name)?;
            if owned.active {
                run_success(
                    &context.cryptsetup,
                    &["close", &marker.name],
                    remaining_millis,
                )?;
            }
        }
        if inspect(&context.cryptsetup, &desired.name)?.active {
            bail!("refusing to replace an unmanaged encrypted mapping");
        }
        let pending = Marker {
            schema: MARKER_SCHEMA.into(),
            revision,
            name: desired.name.clone(),
            source: source.clone(),
            cipher: desired.cipher.clone(),
            key_size_bits: desired.key_size_bits,
            pending: true,
        };
        write_marker(target, &pending)?;
        run_success(
            &context.cryptsetup,
            &[
                "open",
                "--type=plain",
                &format!("--cipher={}", desired.cipher),
                &format!("--key-size={}", desired.key_size_bits),
                "--key-file=/dev/urandom",
                &source,
                &desired.name,
            ],
            remaining_millis,
        )?;
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
        let marker = read_marker(target)?;
        if let Some(marker) = marker {
            let native = inspect(&context.cryptsetup, &marker.name)?;
            if native.active {
                run_success(
                    &context.cryptsetup,
                    &["close", &marker.name],
                    remaining_millis,
                )?;
            }
        }
        remove_marker(target)
    }
}

fn classify(
    desired: &Desired,
    revision: RevisionId,
    marker: Option<&Marker>,
    native_active: bool,
    exact_native: bool,
    source: Option<&str>,
) -> (&'static str, bool, bool) {
    let exact_marker = marker.is_some_and(|marker| {
        marker.revision == revision
            && marker.name == desired.name
            && marker.source == source.unwrap_or("")
            && marker.cipher == desired.cipher
            && marker.key_size_bits == desired.key_size_bits
    });
    let ready = desired.enabled && exact_native && exact_marker;
    let released = marker.is_none();
    let state = if ready {
        "ready"
    } else if native_active && marker.is_none() {
        "unmanaged"
    } else if released {
        "absent"
    } else {
        "drifted"
    };
    (state, ready, released)
}

fn inspect(executable: &Executable, name: &str) -> Result<NativeState> {
    let output = executable.run(&["status", name], 5_000)?;
    if !output.status.success() {
        ensure!(
            output.status.code() == Some(4),
            "cryptsetup status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(NativeState::default());
    }
    ensure!(
        output.stdout.len() <= 64 * 1024,
        "cryptsetup status output is unbounded"
    );
    let text = String::from_utf8(output.stdout).context("decoding cryptsetup status")?;
    let mut state = NativeState {
        active: true,
        ..NativeState::default()
    };
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key {
            "device" => state.source = Some(canonical_source(value)?),
            "cipher" => state.cipher = Some(value.to_string()),
            "keysize" => {
                state.key_size_bits = value
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse().ok());
            }
            _ => {}
        }
    }
    Ok(state)
}

fn validate_desired(desired: &Desired) -> Result<()> {
    ensure!(
        !desired.name.is_empty() && desired.name.len() <= 128,
        "mapping name is invalid"
    );
    ensure!(
        desired
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')),
        "mapping name is invalid"
    );
    ensure!(
        (128..=512).contains(&desired.key_size_bits),
        "mapping key size is invalid"
    );
    ensure!(
        !desired.cipher.is_empty() && desired.cipher.len() <= 128,
        "mapping cipher is invalid"
    );
    validate_path(&desired.source)
}

fn canonical_source(path: &str) -> Result<String> {
    validate_path(path)?;
    Ok(fs::canonicalize(path)
        .with_context(|| format!("resolving encrypted mapping source {path}"))?
        .to_string_lossy()
        .into_owned())
}

fn validate_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(path.is_absolute(), "mapping source is not absolute");
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "mapping source is not normalized"
    );
    Ok(())
}

fn read_marker(target: &ResourceReference) -> Result<Option<Marker>> {
    let marker: Marker = match state::read(
        Path::new(STATE_ROOT),
        "aos.storage.encrypted-block-mapping-resource/v1",
        target,
    )? {
        Some(marker) => marker,
        None => return Ok(None),
    };
    ensure!(
        marker.schema == MARKER_SCHEMA,
        "unsupported encrypted mapping marker"
    );
    validate_path(&marker.source)?;
    ensure!(
        !marker.name.is_empty()
            && marker.name.len() <= 128
            && marker
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')),
        "encrypted mapping marker name is invalid"
    );
    ensure!(
        !marker.cipher.is_empty() && marker.cipher.len() <= 128,
        "encrypted mapping marker cipher is invalid"
    );
    ensure!(
        marker
            .cipher
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')),
        "encrypted mapping marker cipher is invalid"
    );
    ensure!(
        (128..=512).contains(&marker.key_size_bits),
        "encrypted mapping marker key size is invalid"
    );
    Ok(Some(marker))
}

fn write_marker(target: &ResourceReference, marker: &Marker) -> Result<()> {
    state::write(
        Path::new(STATE_ROOT),
        "aos.storage.encrypted-block-mapping-resource/v1",
        target,
        marker,
    )
}

fn remove_marker(target: &ResourceReference) -> Result<()> {
    state::remove(
        Path::new(STATE_ROOT),
        "aos.storage.encrypted-block-mapping-resource/v1",
        target,
    )
}

fn run_success(executable: &Executable, arguments: &[&str], remaining_millis: u64) -> Result<()> {
    let output = executable.run(arguments, remaining_millis)?;
    ensure!(
        output.status.success(),
        "cryptsetup command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn decode<T: for<'de> Deserialize<'de>>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding encrypted mapping value")
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
            name: "cryptswap".into(),
            enabled: true,
            source: "/dev/disk/by-partlabel/swap".into(),
            cipher: "aes-xts-plain64".into(),
            key_size_bits: 256,
            key: KeySource::EphemeralRandom,
            prerequisites: Vec::new(),
        }
    }

    fn marker(revision: RevisionId) -> Marker {
        Marker {
            schema: MARKER_SCHEMA.into(),
            revision,
            name: "cryptswap".into(),
            source: "/dev/sda3".into(),
            cipher: "aes-xts-plain64".into(),
            key_size_bits: 256,
            pending: false,
        }
    }

    #[test]
    fn ambient_matching_mapping_is_unmanaged() {
        let (state, ready, released) = classify(
            &desired(),
            revision(b"desired"),
            None,
            true,
            true,
            Some("/dev/sda3"),
        );

        assert_eq!(state, "unmanaged");
        assert!(!ready);
        assert!(released);
    }

    #[test]
    fn marker_must_bind_exact_revision() {
        let marker = marker(revision(b"old"));
        let (state, ready, _) = classify(
            &desired(),
            revision(b"desired"),
            Some(&marker),
            true,
            true,
            Some("/dev/sda3"),
        );

        assert_eq!(state, "drifted");
        assert!(!ready);
    }

    #[test]
    fn pending_marker_and_exact_native_state_prove_completion() {
        let desired_revision = revision(b"desired");
        let mut marker = marker(desired_revision);
        marker.pending = true;
        let (state, ready, _) = classify(
            &desired(),
            desired_revision,
            Some(&marker),
            true,
            true,
            Some("/dev/sda3"),
        );

        assert_eq!(state, "ready");
        assert!(ready);
    }
}
