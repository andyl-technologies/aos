//! Compares immutable admitted bindings with every current Prepare field.
//!
//! Fresh executable measurements and the actual current authority are borrowed.
//! No expected JSON tree, path, hash, serializer or generic callback is created.
//! These data comparisons neither verify a MAC nor grant Prepare allocation.

use super::*;
use crate::handshake::Limits;
use crucible_node_format::{ExtensionSelection, HashRef, Id, SemanticVersion};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub(super) fn authenticate_kernel_data(
    value: &Value,
    controller_pid: U64,
    controller_uid: U64,
    controller_executable: &ContentRef,
    native_executable: &ContentRef,
) -> Result<(), ProviderError> {
    let root = object(value, &["schema", "controller", "native"])?;
    text(
        &root["schema"],
        "source-owned.packet-canonical-ack-kernel-binding/5",
    )?;
    executable(
        &root["controller"],
        controller_pid,
        controller_uid,
        controller_executable,
    )?;
    executable(
        &root["native"],
        U64::new(u64::from(std::process::id())),
        U64::new(u64::from(rustix::process::geteuid().as_raw())),
        native_executable,
    )
}

pub(super) fn authenticate_policy_data(
    value: &Value,
    source_birth: &Value,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    authority.ensure_live()?;
    authenticate_policy_parts_data(
        value,
        source_birth,
        authority.limits(),
        authority.selected_features(),
        authority.selected_extensions().ok_or_else(refused)?,
        authority.envelope_extensions(),
    )?;
    authority.ensure_live()
}

fn authenticate_policy_parts_data(
    value: &Value,
    source_birth: &Value,
    limits: Limits,
    features: &[Id],
    selections: &[ExtensionSelection],
    envelope_keys: &BTreeSet<String>,
) -> Result<(), ProviderError> {
    let root = object(value, &["schema", "source_binding", "negotiated"])?;
    text(
        &root["schema"],
        "source-owned.packet-canonical-ack-policy-binding/5",
    )?;
    if &root["source_binding"] != source_birth {
        return Err(refused());
    }
    let negotiated = object(
        &root["negotiated"],
        &["limits", "features", "extensions", "envelope_extensions"],
    )?;
    let actual_limits = object(
        &negotiated["limits"],
        &[
            "frame_bytes",
            "nesting",
            "requests",
            "journal_entries",
            "blob_chunk_bytes",
        ],
    )?;
    for (name, expected) in [
        ("frame_bytes", limits.frame_bytes),
        ("nesting", limits.nesting),
        ("requests", limits.requests),
        ("journal_entries", limits.journal_entries),
        ("blob_chunk_bytes", limits.blob_chunk_bytes),
    ] {
        unsigned(&actual_limits[name], expected)?;
    }
    let actual_features = array(&negotiated["features"], features.len())?;
    for (actual, expected) in actual_features.iter().zip(features) {
        text(actual, expected.as_str())?;
    }
    let actual_selections = array(&negotiated["extensions"], selections.len())?;
    for (actual, expected) in actual_selections.iter().zip(selections) {
        selection(actual, expected)?;
    }
    let actual_keys = array(&negotiated["envelope_extensions"], envelope_keys.len())?;
    for (actual, expected) in actual_keys.iter().zip(envelope_keys) {
        text(actual, expected)?;
    }
    Ok(())
}

fn executable(
    value: &Value,
    pid: U64,
    uid: U64,
    reference: &ContentRef,
) -> Result<(), ProviderError> {
    let fields = object(value, &["pid", "uid", "executable"])?;
    unsigned(&fields["pid"], pid)?;
    unsigned(&fields["uid"], uid)?;
    content(&fields["executable"], reference)
}

fn selection(value: &Value, expected: &ExtensionSelection) -> Result<(), ProviderError> {
    let fields = object(
        value,
        &[
            "declaration",
            "identifier",
            "semantic_version",
            "schema_digest",
        ],
    )?;
    content(&fields["declaration"], &expected.declaration)?;
    text(&fields["identifier"], expected.identifier.as_str())?;
    version(&fields["semantic_version"], &expected.semantic_version)?;
    hash(&fields["schema_digest"], &expected.schema_digest)
}

fn version(value: &Value, expected: &SemanticVersion) -> Result<(), ProviderError> {
    let fields = object(value, &["major", "minor", "patch", "prerelease", "build"])?;
    unsigned(&fields["major"], expected.major)?;
    unsigned(&fields["minor"], expected.minor)?;
    unsigned(&fields["patch"], expected.patch)?;
    nullable_text(&fields["prerelease"], expected.prerelease.as_deref())?;
    nullable_text(&fields["build"], expected.build.as_deref())
}

fn content(value: &Value, expected: &ContentRef) -> Result<(), ProviderError> {
    let fields = object(value, &["hash", "length", "media_type"])?;
    hash(&fields["hash"], &expected.hash)?;
    unsigned(&fields["length"], expected.length)?;
    text(&fields["media_type"], &expected.media_type)
}

fn hash(value: &Value, expected: &HashRef) -> Result<(), ProviderError> {
    let fields = object(value, &["algorithm", "domain", "digest"])?;
    text(&fields["algorithm"], &expected.algorithm)?;
    text(&fields["domain"], &expected.domain)?;
    text(&fields["digest"], &expected.digest)
}

fn object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, ProviderError> {
    let fields = value.as_object().ok_or_else(refused)?;
    if fields.len() != keys.len() || keys.iter().any(|key| !fields.contains_key(*key)) {
        return Err(refused());
    }
    Ok(fields)
}

fn array(value: &Value, length: usize) -> Result<&[Value], ProviderError> {
    let array = value.as_array().ok_or_else(refused)?;
    if array.len() != length {
        return Err(refused());
    }
    Ok(array)
}

fn text(value: &Value, expected: &str) -> Result<(), ProviderError> {
    if value.as_str() != Some(expected) {
        return Err(refused());
    }
    Ok(())
}

fn nullable_text(value: &Value, expected: Option<&str>) -> Result<(), ProviderError> {
    match expected {
        Some(expected) => text(value, expected),
        None if value.is_null() => Ok(()),
        None => Err(refused()),
    }
}

fn unsigned(value: &Value, expected: U64) -> Result<(), ProviderError> {
    let mut digits = [0u8; 20];
    let mut cursor = digits.len();
    let mut remaining = expected.get();
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    if value.as_str().map(str::as_bytes) != Some(&digits[cursor..]) {
        return Err(refused());
    }
    Ok(())
}

/// Names fixed borrowed views/counters, not recursive or compiler stack frames.
pub(super) const fn declared_counter_scratch_data() -> usize {
    std::mem::size_of::<[u8; 20]>()
        + std::mem::size_of::<[(&str, U64); 5]>()
        + std::mem::size_of::<[&str; 5]>()
        + 8 * std::mem::size_of::<&Map<String, Value>>()
        + 8 * std::mem::size_of::<&Value>()
        + 8 * std::mem::size_of::<usize>()
        + std::mem::size_of::<std::slice::Iter<'static, Value>>()
        + std::mem::size_of::<std::collections::btree_set::Iter<'static, String>>()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("Prepare current kernel or policy binding changed")
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Closed comparison controls panic on failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;
    use serde_json::json;

    fn reference() -> ContentRef {
        canonical::content_ref(b"actual", "application/json").unwrap()
    }

    #[test]
    fn actual_kernel_measurement_and_every_independent_identity_group_are_checked() {
        let executable = reference();
        let actual = json!({
            "schema":"source-owned.packet-canonical-ack-kernel-binding/5",
            "controller":{"pid":U64::new(42),"uid":U64::new(43),"executable":executable},
            "native":{"pid":U64::new(u64::from(std::process::id())),
                "uid":U64::new(u64::from(rustix::process::geteuid().as_raw())),"executable":executable}
        });
        authenticate_kernel_data(&actual, 42.into(), 43.into(), &executable, &executable).unwrap();
        for path in [
            ["controller", "pid"],
            ["controller", "uid"],
            ["native", "pid"],
            ["native", "uid"],
        ] {
            let mut changed = actual.clone();
            changed[path[0]][path[1]] = json!(U64::new(u64::MAX));
            assert!(
                authenticate_kernel_data(&changed, 42.into(), 43.into(), &executable, &executable)
                    .is_err()
            );
        }
        for role in ["controller", "native"] {
            for field in ["algorithm", "domain", "digest"] {
                let mut changed = actual.clone();
                changed[role]["executable"]["hash"][field] = json!("changed");
                assert!(
                    authenticate_kernel_data(
                        &changed,
                        42.into(),
                        43.into(),
                        &executable,
                        &executable
                    )
                    .is_err()
                );
            }
            for field in ["length", "media_type"] {
                let mut changed = actual.clone();
                changed[role]["executable"][field] = json!("changed");
                assert!(
                    authenticate_kernel_data(
                        &changed,
                        42.into(),
                        43.into(),
                        &executable,
                        &executable
                    )
                    .is_err()
                );
            }
        }
        let mut changed = actual.clone();
        changed["extra"] = json!(true);
        assert!(
            authenticate_kernel_data(&changed, 42.into(), 43.into(), &executable, &executable)
                .is_err()
        );
    }

    #[test]
    fn complete_source_limits_features_exact_versions_and_envelope_keys_are_checked() {
        let source = json!({"schema":"binding14", "nested":{"extensions":{"opaque":[0,"value"]}}});
        let limits = Limits {
            frame_bytes: 65536.into(),
            nesting: 64.into(),
            requests: 8.into(),
            journal_entries: 64.into(),
            blob_chunk_bytes: 4096.into(),
        };
        let features = vec![Id::new("vendor.example/feature").unwrap()];
        let selections = vec![ExtensionSelection {
            declaration: reference(),
            identifier: Id::new("vendor.example/feature").unwrap(),
            semantic_version: SemanticVersion {
                major: 1.into(),
                minor: 2.into(),
                patch: 3.into(),
                prerelease: Some("rc.1".into()),
                build: Some("build.1".into()),
            },
            schema_digest: reference().hash,
        }];
        let keys = BTreeSet::from(["vendor.example/key".into()]);
        let actual = json!({"schema":"source-owned.packet-canonical-ack-policy-binding/5",
            "source_binding":source,"negotiated":{"limits":limits,"features":features,"extensions":selections,"envelope_extensions":keys}});
        authenticate_policy_parts_data(&actual, &source, limits, &features, &selections, &keys)
            .unwrap();
        let mut changed = actual.clone();
        changed["source_binding"]["nested"]["extensions"]["opaque"][1] = json!("changed");
        assert!(
            authenticate_policy_parts_data(
                &changed,
                &source,
                limits,
                &features,
                &selections,
                &keys
            )
            .is_err()
        );
        for name in [
            "frame_bytes",
            "nesting",
            "requests",
            "journal_entries",
            "blob_chunk_bytes",
        ] {
            let mut changed = actual.clone();
            changed["negotiated"]["limits"][name] = json!("0");
            assert!(
                authenticate_policy_parts_data(
                    &changed,
                    &source,
                    limits,
                    &features,
                    &selections,
                    &keys
                )
                .is_err()
            );
        }
        for name in ["features", "extensions", "envelope_extensions"] {
            let mut changed = actual.clone();
            changed["negotiated"][name] = json!([]);
            assert!(
                authenticate_policy_parts_data(
                    &changed,
                    &source,
                    limits,
                    &features,
                    &selections,
                    &keys
                )
                .is_err()
            );
        }
        for name in [
            "declaration",
            "identifier",
            "semantic_version",
            "schema_digest",
        ] {
            let mut changed = actual.clone();
            changed["negotiated"]["extensions"][0][name] = Value::Null;
            assert!(
                authenticate_policy_parts_data(
                    &changed,
                    &source,
                    limits,
                    &features,
                    &selections,
                    &keys
                )
                .is_err()
            );
        }
        for name in ["major", "minor", "patch", "prerelease", "build"] {
            let mut changed = actual.clone();
            changed["negotiated"]["extensions"][0]["semantic_version"][name] = json!("changed");
            assert!(
                authenticate_policy_parts_data(
                    &changed,
                    &source,
                    limits,
                    &features,
                    &selections,
                    &keys
                )
                .is_err()
            );
        }
    }
}
