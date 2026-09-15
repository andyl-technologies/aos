//! Typed QMP contract for the realized fingerprint projection manifest.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::{QmpCommandKind, QmpError};

pub(crate) const QMP_FINGERPRINT_PROJECTION_MANIFEST_SCHEMA_VERSION: u32 = 4;
pub(crate) const QMP_QUERY_FINGERPRINT_PROJECTION_MANIFEST_COMMAND: &str =
    "query-crucible-fingerprint-projection-manifest";
const FINGERPRINT_PROJECTION_SCHEMA_DOMAIN: &str = "crucible.qemu.device-projection-schema.v3";
const FINGERPRINT_PROJECTION_SECTION_DOMAIN: &str = "read-only-section";
const FINGERPRINT_PROJECTION_END_DOMAIN: &str = "read-only-sections-end";
const MAX_FINGERPRINT_PROJECTION_ROWS: usize = 64;
const MAX_FINGERPRINT_PROJECTION_TEXT_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct QmpFingerprintProjectionManifestRow {
    pub(crate) id: String,
    pub(crate) instance: u32,
    pub(crate) vmsd_name: String,
    pub(crate) vmsd_version: u32,
    pub(crate) domain: u32,
    pub(crate) projection_schema: String,
    pub(crate) projection_version: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct QmpFingerprintProjectionManifest {
    pub(crate) schema_version: u32,
    pub(crate) sections: u64,
    pub(crate) digest: String,
    pub(crate) rows: Vec<QmpFingerprintProjectionManifestRow>,
}

impl QmpFingerprintProjectionManifest {
    pub(crate) fn from_rows(rows: Vec<QmpFingerprintProjectionManifestRow>) -> Self {
        let digest = fingerprint_projection_manifest_digest(&rows);
        Self {
            schema_version: QMP_FINGERPRINT_PROJECTION_MANIFEST_SCHEMA_VERSION,
            sections: rows.len() as u64,
            digest,
            rows,
        }
    }
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn fingerprint_projection_manifest_digest(rows: &[QmpFingerprintProjectionManifestRow]) -> String {
    let mut hasher = Sha256::new();
    hash_string(&mut hasher, FINGERPRINT_PROJECTION_SCHEMA_DOMAIN);
    for row in rows {
        hash_string(&mut hasher, FINGERPRINT_PROJECTION_SECTION_DOMAIN);
        hash_string(&mut hasher, &row.id);
        hasher.update(u64::from(row.instance).to_be_bytes());
        hash_string(&mut hasher, &row.vmsd_name);
        hasher.update(u64::from(row.vmsd_version).to_be_bytes());
        hasher.update(u64::from(row.domain).to_be_bytes());
        hash_string(&mut hasher, &row.projection_schema);
        hasher.update(u64::from(row.projection_version).to_be_bytes());
    }
    hash_string(&mut hasher, FINGERPRINT_PROJECTION_END_DOMAIN);
    format!("{:x}", hasher.finalize())
}

fn manifest_text_is_bounded(row: &QmpFingerprintProjectionManifestRow) -> bool {
    [&row.id, &row.vmsd_name, &row.projection_schema]
        .into_iter()
        .all(|value| !value.is_empty() && value.len() <= MAX_FINGERPRINT_PROJECTION_TEXT_BYTES)
}

pub(crate) fn parse_fingerprint_projection_manifest(
    value: &Value,
) -> Result<QmpFingerprintProjectionManifest, QmpError> {
    let manifest: QmpFingerprintProjectionManifest = serde_json::from_value(value.clone())
        .map_err(|_| QmpError::UnexpectedResponse {
            command: QmpCommandKind::QueryFingerprintProjectionManifest,
            response: value.to_string(),
        })?;
    let valid_digest = manifest.digest.len() == 64
        && manifest
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if manifest.schema_version != QMP_FINGERPRINT_PROJECTION_MANIFEST_SCHEMA_VERSION
        || manifest.rows.len() > MAX_FINGERPRINT_PROJECTION_ROWS
        || manifest.sections != u64::try_from(manifest.rows.len()).unwrap_or(u64::MAX)
        || !valid_digest
        || !manifest.rows.iter().all(manifest_text_is_bounded)
        || manifest.digest != fingerprint_projection_manifest_digest(&manifest.rows)
    {
        return Err(QmpError::UnexpectedResponse {
            command: QmpCommandKind::QueryFingerprintProjectionManifest,
            response: value.to_string(),
        });
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn one_row() -> QmpFingerprintProjectionManifestRow {
        QmpFingerprintProjectionManifestRow {
            id: "cpu".to_owned(),
            instance: 0,
            vmsd_name: "cpu".to_owned(),
            vmsd_version: 12,
            domain: 1,
            projection_schema: "crucible.qemu.x86-cpu.v1".to_owned(),
            projection_version: 1,
        }
    }

    #[test]
    fn parser_recomputes_the_ordered_manifest_digest() -> Result<(), QmpError> {
        let expected = QmpFingerprintProjectionManifest::from_rows(vec![one_row()]);
        let value = json!({
            "schema-version": expected.schema_version,
            "sections": expected.sections,
            "digest": expected.digest,
            "rows": expected.rows,
        });

        assert_eq!(parse_fingerprint_projection_manifest(&value)?, expected);
        Ok(())
    }

    #[test]
    fn parser_rejects_digest_and_row_drift() {
        let expected = QmpFingerprintProjectionManifest::from_rows(vec![one_row()]);
        let wrong_digest = json!({
            "schema-version": expected.schema_version,
            "sections": expected.sections,
            "digest": "00".repeat(32),
            "rows": expected.rows,
        });
        assert!(parse_fingerprint_projection_manifest(&wrong_digest).is_err());

        let too_many_rows = vec![one_row(); MAX_FINGERPRINT_PROJECTION_ROWS + 1];
        let oversized = QmpFingerprintProjectionManifest::from_rows(too_many_rows);
        let oversized_value = json!({
            "schema-version": oversized.schema_version,
            "sections": oversized.sections,
            "digest": oversized.digest,
            "rows": oversized.rows,
        });
        assert!(parse_fingerprint_projection_manifest(&oversized_value).is_err());
    }
}
