//! Exact, versioned OCI inventory ranges under the existing read guard.
//!
//! The signed storage-work plan supplies the portable continuation. A fresh
//! HEAD must match its frozen identity before a conditional range is consumed;
//! neither HEAD nor a later version can replace that identity.

use anyhow::{Result, ensure};
use aos_hub_core::{
    db::OciSha256State,
    storage_authority::{external_object::copy::CopySourceObject, lease::LeaseInteger},
    storage_work::{MAX_OCI_HASH_RANGE_BYTES, StorageObjectIdentity, StorageWorkOperation},
};

/// Selects a bounded range from an already authenticated inventory plan.
pub(super) struct Selection<'a> {
    pub(super) path: &'a str,
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) bytes: u64,
    pub(super) source: CopySourceObject,
    pub(super) continuation: OciSha256State,
}

impl<'a> Selection<'a> {
    /// Validates the closed range and its exact portable continuation.
    ///
    /// # Errors
    /// Refuses non-OCI keys, unsupported versions, invalid tags, corrupt hash
    /// state, an offset mismatch, or an out-of-bounds range.
    pub(super) fn from_operation(operation: &'a StorageWorkOperation) -> Result<Self> {
        let StorageWorkOperation::HashOciRange {
            path,
            start,
            end,
            total,
            strong_etag,
            expected_provider_version,
            sha256_state,
        } = operation
        else {
            anyhow::bail!("external inventory hash operation differs");
        };
        let bytes = end
            .checked_sub(*start)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| anyhow::anyhow!("external inventory range overflow"))?;
        ensure!(
            aos_hub_core::storage_work::admitted_oci_blob_path(path)
                && *end < *total
                && bytes <= MAX_OCI_HASH_RANGE_BYTES as u64,
            "external inventory range or path differs"
        );
        sha256_state.validate()?;
        ensure!(
            sha256_state.total_bytes == *start,
            "external inventory offset differs"
        );
        let source = CopySourceObject {
            provider_version: Some(
                expected_provider_version
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("external inventory version absent"))?,
            ),
            etag: strong_etag.clone(),
            bytes: LeaseInteger::new(i64::try_from(*total)?)?,
            guard_stamp: None,
        };
        source.validate()?;

        Ok(Self {
            path,
            start: *start,
            end: *end,
            bytes,
            source,
            continuation: sha256_state.clone(),
        })
    }

    /// Checks the observed HEAD without retagging the signed source.
    ///
    /// # Errors
    /// Refuses a changed key, length, tag or immutable provider version.
    pub(super) fn validate_identity(
        &self,
        key: &str,
        identity: &StorageObjectIdentity,
    ) -> Result<()> {
        ensure!(
            identity.key == key
                && identity.size == self.source.bytes.get() as u64
                && identity.etag == self.source.etag
                && identity.provider_version.as_deref() == self.source.provider_version.as_deref(),
            "external inventory source identity differs"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation() -> StorageWorkOperation {
        StorageWorkOperation::HashOciRange {
            path: format!("oci/blobs/sha256/{}", "a".repeat(64)),
            start: 0,
            end: 2,
            total: 6,
            strong_etag: "\"actual-tag\"".into(),
            expected_provider_version: Some("actual-version".into()),
            sha256_state: OciSha256State::initial(),
        }
    }

    #[test]
    fn signed_continuation_advances_across_exact_bounded_ranges() {
        let first = operation();
        let selection = Selection::from_operation(&first).unwrap();
        let mut digest = super::super::bytes::RangeDigest::new(
            selection.start,
            selection.bytes,
            selection.continuation,
        )
        .unwrap();
        digest.update(b"abc").unwrap();
        let state = digest.finish().unwrap().source_state;
        let mut second = operation();
        if let StorageWorkOperation::HashOciRange {
            start,
            end,
            sha256_state,
            ..
        } = &mut second
        {
            *start = 3;
            *end = 5;
            *sha256_state = state;
        }
        let selection = Selection::from_operation(&second).unwrap();
        let mut digest = super::super::bytes::RangeDigest::new(
            selection.start,
            selection.bytes,
            selection.continuation,
        )
        .unwrap();
        digest.update(b"def").unwrap();
        let mut expected = OciSha256State::initial();
        expected.update(b"abcdef").unwrap();
        assert_eq!(digest.finish().unwrap().source_state, expected);
    }

    #[test]
    fn unsupported_identity_and_invalid_geometry_refuse() {
        for case in 0..7 {
            let mut operation = operation();
            if let StorageWorkOperation::HashOciRange {
                path,
                start,
                end,
                total,
                strong_etag,
                expected_provider_version,
                ..
            } = &mut operation
            {
                match case {
                    0 => *expected_provider_version = None,
                    1 => *expected_provider_version = Some("null".into()),
                    2 => *strong_etag = "W/\"weak\"".into(),
                    3 => *start = 1,
                    4 => *end = *total,
                    5 => {
                        *total = MAX_OCI_HASH_RANGE_BYTES as u64 + 1;
                        *end = *total - 1;
                    }
                    _ => *path = "oci/blobs/sha256/not-a-digest".into(),
                }
            }
            assert!(
                Selection::from_operation(&operation).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn fresh_head_cannot_replace_the_selected_incarnation() {
        let operation = operation();
        let selection = Selection::from_operation(&operation).unwrap();
        let identity = StorageObjectIdentity {
            key: "binding/placement/blob".into(),
            size: 6,
            etag: selection.source.etag.clone(),
            provider_version: selection.source.provider_version.clone(),
        };
        selection
            .validate_identity(&identity.key, &identity)
            .unwrap();
        for case in 0..4 {
            let mut changed = identity.clone();
            match case {
                0 => changed.key.push_str("-other"),
                1 => changed.size += 1,
                2 => changed.etag = "\"replacement\"".into(),
                _ => changed.provider_version = Some("replacement-version".into()),
            }
            assert!(
                selection
                    .validate_identity(&identity.key, &changed)
                    .is_err()
            );
        }
    }
}
