//! Checks build-only qualification sources without treating them as native state.
//!
//! Profile v1 remains an explicit legacy format. Profile v2 binds a closed pair
//! of qualification files separately from its unchanged runtime artifact roster.
//! Neither source receipt nor a passing build test supplies execution authority.
//!
//! The separate receipt uses this closed JSON shape:
//!
//! ```json
//! {"schema":"crucible.gem5.root-qualification-sources.v1",
//!  "controller_sha256":"<64 lowercase hexadecimal digits>",
//!  "checks":{"native-controller-temporary-root-check.py":"<64 lowercase hexadecimal digits>"}}
//! ```

use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

use serde_json::Value;

use crate::ProviderError;

/// Names the fixed build-only input roster, separate from runtime artifacts.
pub(super) const ROLES: [&str; 2] = ["source_manifest", "temporary_root_check"];
const CHECK: &str = "native-controller-temporary-root-check.py";

/// Checks explicit legacy/current versions and the closed current input records.
///
/// # Errors
/// Refuses unknown versions, cross-version namespaces, and malformed records.
pub(super) fn validate_profile_version(
    document: &Value,
    legacy: &str,
    current: &str,
) -> Result<(), ProviderError> {
    if document["schema"] == legacy {
        if document.get("qualification_inputs").is_some() {
            return Err(invalid());
        }
        return Ok(());
    }
    if document["schema"] != current {
        return Err(invalid());
    }
    let inputs = document["qualification_inputs"]
        .as_object()
        .ok_or_else(invalid)?;
    if inputs.len() != ROLES.len() || ROLES.iter().any(|role| !inputs.contains_key(*role)) {
        return Err(invalid());
    }
    for value in inputs.values() {
        let record = value.as_object().ok_or_else(invalid)?;
        let length = value["length"].as_str().ok_or_else(invalid)?;
        let numeric = length.parse::<u64>().map_err(|_| invalid())?;
        if record.len() != 3
            || !["path", "length", "sha256"]
                .iter()
                .all(|key| record.contains_key(*key))
            || !value["path"]
                .as_str()
                .is_some_and(|path| path.starts_with("/nix/store/"))
            || numeric == 0
            || numeric > 2 * 1024 * 1024 * 1024
            || length.starts_with('0')
            || !length.bytes().all(|byte| byte.is_ascii_digit())
            || !value["sha256"].as_str().is_some_and(valid_sha256)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Binds the qualification receipt to both independently measured source files.
///
/// # Errors
/// Refuses missing/unknown fields, unsupported schemas, and substituted digests.
pub(super) fn validate_source_document(
    source: &Value,
    controller_sha256: &str,
    check_sha256: &str,
) -> Result<(), ProviderError> {
    let object = source.as_object().ok_or_else(invalid)?;
    let checks = source["checks"].as_object().ok_or_else(invalid)?;
    if !valid_sha256(controller_sha256)
        || !valid_sha256(check_sha256)
        || object.len() != 3
        || !["schema", "controller_sha256", "checks"]
            .iter()
            .all(|key| object.contains_key(*key))
        || source["schema"] != "crucible.gem5.root-qualification-sources.v1"
        || source["controller_sha256"].as_str() != Some(controller_sha256)
        || checks.len() != 1
        || checks.get(CHECK).and_then(Value::as_str) != Some(check_sha256)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Reads only the separately remeasured immutable qualification receipt.
///
/// # Errors
/// Refuses invalid extents, changed files, malformed strict JSON, and read errors.
pub(super) fn read_source_document(mut file: File, maximum: usize) -> Result<Value, ProviderError> {
    let before = file.metadata()?;
    let fingerprint = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.nlink(),
            metadata.mode(),
        )
    };
    let limit = u64::try_from(maximum)
        .ok()
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(invalid)?;
    if before.len() == 0 || before.len() >= limit {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.by_ref().take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > maximum
        || bytes.len() as u64 != before.len()
        || fingerprint(&before) != fingerprint(&file.metadata()?)
    {
        return Err(invalid());
    }
    Ok(crucible_node_format::canonical::parse_json(
        &bytes, maximum,
    )?)
}

fn invalid() -> ProviderError {
    ProviderError::Frame("installed Root qualification sources differ")
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Inert format fixtures issue no
    // installed profile, native preparation, or live execution authority.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use serde_json::json;

    #[test]
    fn source_receipt_binds_both_controller_and_executed_check() {
        let controller = "a".repeat(64);
        let check = "b".repeat(64);
        let source = json!({"schema":"crucible.gem5.root-qualification-sources.v1",
            "controller_sha256":controller,"checks":{CHECK:check}});
        assert!(validate_source_document(&source, &controller, &check).is_ok());

        for field in ["schema", "controller_sha256", "checks"] {
            let mut changed = source.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(validate_source_document(&changed, &controller, &check).is_err());
        }
        for changed in [
            Value::Null,
            json!([]),
            json!({CHECK:"c".repeat(64)}),
            json!({CHECK:check,"unknown.py":check}),
        ] {
            let mut substituted = source.clone();
            substituted["checks"] = changed;
            assert!(validate_source_document(&substituted, &controller, &check).is_err());
        }
        assert!(validate_source_document(&source, &"c".repeat(64), &check).is_err());
        assert!(validate_source_document(&source, &controller, &"c".repeat(64)).is_err());
        let mut changed = source;
        changed["extra"] = true.into();
        assert!(validate_source_document(&changed, &controller, &check).is_err());
    }

    #[test]
    fn legacy_and_current_profile_namespaces_cannot_be_crossed() {
        let old = json!({"schema":"legacy"});
        assert!(validate_profile_version(&old, "legacy", "current").is_ok());
        let mut new = json!({"schema":"current","qualification_inputs":{
            "source_manifest":{"path":"/nix/store/source-only-fixture","length":"1","sha256":"a".repeat(64)},
            "temporary_root_check":{"path":"/nix/store/check-only-fixture","length":"1","sha256":"b".repeat(64)}}});
        assert!(validate_profile_version(&new, "legacy", "current").is_ok());
        for field in ["path", "length", "sha256"] {
            let mut malformed = new.clone();
            malformed["qualification_inputs"]["source_manifest"][field] = Value::Null;
            assert!(validate_profile_version(&malformed, "legacy", "current").is_err());
        }
        new["schema"] = "legacy".into();
        assert!(validate_profile_version(&new, "legacy", "current").is_err());
        new["schema"] = "current".into();
        for field in ROLES {
            let mut missing = new.clone();
            missing["qualification_inputs"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(validate_profile_version(&missing, "legacy", "current").is_err());
        }
        let mut unsupported = new.clone();
        unsupported["schema"] = "future".into();
        assert!(validate_profile_version(&unsupported, "legacy", "current").is_err());
        new["qualification_inputs"]["unknown"] = json!({});
        assert!(validate_profile_version(&new, "legacy", "current").is_err());
    }
}
