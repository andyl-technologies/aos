//! Exact distribution metadata bindings for unpublished release stages.
//!
//! These checks decode canonical envelopes and bind the prepared timestamp to
//! its immutable inventory. They establish byte identity, not root authority.
//! Consumers separately verify signatures against independently pinned roots
//! with the ordinary distribution TUF verifier.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, ensure};

use super::{
    DelegatedTargetsMetadataV1, ImmutableTufSetV1, RootMetadataV1, SnapshotMetadataV1,
    TUF_DELEGATED_TARGETS_V1, TUF_ROOT_V1, TUF_SNAPSHOT_V1, TUF_TARGETS_V1, TUF_TIMESTAMP_V1,
    TargetsMetadataV1, TimestampMetadataV1, TufEnvelopeV1, TufMetadataDescriptionV1, TufRole,
    validate_common, validate_snapshot,
};
use crate::canonical;
use crate::digest::Sha256Digest;

/// Exact timestamp and snapshot identities admitted by a publication service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedTimestampBinding {
    /// Version of the mutable prepared timestamp.
    pub timestamp_version: u64,
    /// SHA-256 of the exact prepared timestamp envelope.
    pub timestamp_digest: Sha256Digest,
    /// Origin-relative immutable snapshot path.
    pub snapshot_path: String,
    /// Version of the snapshot described by the timestamp.
    pub snapshot_version: u64,
    /// SHA-256 of the exact immutable snapshot envelope.
    pub snapshot_digest: Sha256Digest,
}

/// Binds a canonical prepared timestamp to its exact immutable metadata set.
///
/// `immutable` contains captured origin-relative `tuf/<version>.<role>.json`
/// bytes from the admitted inventory. Signature trust and timestamp continuity
/// remain the consumer's and publication service's separate responsibilities.
/// No keys found inside these envelopes become bootstrap trust through this
/// function.
///
/// # Errors
///
/// Returns an error for noncanonical envelopes, malformed schema headers,
/// registry mismatch, unsafe or noncanonical metadata paths, missing inventory
/// bytes, or any version, digest, or byte-length mismatch in the chain.
pub fn bind_staged_timestamp(
    registry: &str,
    timestamp_bytes: &[u8],
    immutable: &BTreeMap<String, Vec<u8>>,
) -> Result<StagedTimestampBinding> {
    let timestamp: TufEnvelopeV1<TimestampMetadataV1> =
        decode(timestamp_bytes, "staged distribution timestamp")?;
    validate_common(&timestamp.signed, TUF_TIMESTAMP_V1)?;
    ensure!(
        timestamp.signed.registry == registry,
        "staged distribution timestamp crosses registry identities"
    );

    let snapshot_path = metadata_path(&timestamp.signed.snapshot, "snapshot")?;
    let snapshot_bytes = described_bytes(immutable, &timestamp.signed.snapshot, "snapshot")?;
    let snapshot: TufEnvelopeV1<SnapshotMetadataV1> =
        decode(snapshot_bytes, "staged distribution snapshot")?;
    validate_common(&snapshot.signed, TUF_SNAPSHOT_V1)?;
    ensure!(
        snapshot.signed.version == timestamp.signed.snapshot.version,
        "staged distribution snapshot version differs from its timestamp"
    );
    ensure!(
        snapshot.signed.registry == registry,
        "staged distribution snapshot crosses registry identities"
    );
    ensure!(
        snapshot.signed.metadata.len() == 3,
        "staged distribution snapshot must describe root, targets, and one delegated role"
    );

    let root_description = &snapshot.signed.metadata[0];
    let targets_description = &snapshot.signed.metadata[1];
    let delegated_description = &snapshot.signed.metadata[2];
    let root: TufEnvelopeV1<RootMetadataV1> = decode(
        described_bytes(immutable, root_description, "root")?,
        "staged distribution root",
    )?;
    let targets: TufEnvelopeV1<TargetsMetadataV1> = decode(
        described_bytes(immutable, targets_description, "targets")?,
        "staged distribution targets",
    )?;

    let delegated_role = [TufRole::Stable, TufRole::Candidate, TufRole::Edge]
        .into_iter()
        .find(|role| {
            delegated_description.path
                == format!("{}.{}.json", delegated_description.version, role.as_str())
        })
        .context("staged distribution snapshot has no canonical delegated role path")?;
    let delegated: TufEnvelopeV1<DelegatedTargetsMetadataV1> = decode(
        described_bytes(immutable, delegated_description, delegated_role.as_str())?,
        "staged distribution delegated targets",
    )?;

    validate_common(&root.signed, TUF_ROOT_V1)?;
    validate_common(&targets.signed, TUF_TARGETS_V1)?;
    validate_common(&delegated.signed, TUF_DELEGATED_TARGETS_V1)?;
    ensure!(
        root.signed.registry == registry
            && targets.signed.registry == registry
            && delegated.signed.registry == registry,
        "staged distribution metadata crosses registry identities"
    );
    ensure!(
        delegated.signed.role == delegated_role,
        "staged distribution delegated role differs from its snapshot path"
    );
    validate_snapshot(&ImmutableTufSetV1 {
        root,
        targets,
        delegated,
        snapshot,
    })?;

    Ok(StagedTimestampBinding {
        timestamp_version: timestamp.signed.version,
        timestamp_digest: Sha256Digest::of_bytes(timestamp_bytes),
        snapshot_path,
        snapshot_version: timestamp.signed.snapshot.version,
        snapshot_digest: timestamp.signed.snapshot.sha256,
    })
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    canonical::require_canonical(bytes, label)?;
    canonical::from_slice(bytes, label)
}

fn metadata_path(description: &TufMetadataDescriptionV1, role: &str) -> Result<String> {
    ensure!(
        description.version != 0
            && description.path == format!("{}.{role}.json", description.version),
        "staged distribution metadata has a noncanonical {role} path"
    );
    Ok(format!("tuf/{}", description.path))
}

fn described_bytes<'a>(
    immutable: &'a BTreeMap<String, Vec<u8>>,
    description: &TufMetadataDescriptionV1,
    role: &str,
) -> Result<&'a [u8]> {
    let path = metadata_path(description, role)?;
    let bytes = immutable
        .get(&path)
        .with_context(|| format!("staged distribution inventory lacks {path}"))?;
    ensure!(
        u64::try_from(bytes.len())? == description.length
            && Sha256Digest::of_bytes(bytes) == description.sha256,
        "staged distribution metadata differs from its described bytes: {path}"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::ReleaseClass;
    use crate::tuf::{
        TUF_SPEC_VERSION, TufReleaseTargetV1, canonical_targets_metadata,
        delegated_release_metadata, immutable_snapshot_metadata, timestamp_metadata,
    };

    fn candidate() -> Result<(Vec<u8>, BTreeMap<String, Vec<u8>>)> {
        // Empty signature sets deliberately demonstrate the admission helper's
        // byte-binding boundary; consumer trust still needs the normal verifier.
        let root = TufEnvelopeV1 {
            signed: RootMetadataV1 {
                schema_version: TUF_ROOT_V1.to_owned(),
                spec_version: TUF_SPEC_VERSION.to_owned(),
                registry: "andyl/testing".to_owned(),
                version: 1,
                expires: "2030-01-01T00:00:00Z".to_owned(),
                consistent_snapshot: true,
                keys: vec![],
                roles: vec![],
            },
            signatures: vec![],
        };
        let targets = TufEnvelopeV1 {
            signed: canonical_targets_metadata(
                "andyl/testing",
                2,
                "2030-01-01T00:00:00Z".to_owned(),
            )?,
            signatures: vec![],
        };
        let delegated = TufEnvelopeV1 {
            signed: delegated_release_metadata(
                "andyl/testing",
                3,
                "2030-01-01T00:00:00Z".to_owned(),
                TufReleaseTargetV1 {
                    path: "releases/stable/release-2029.12.0/release-manifest.json".to_owned(),
                    release_id: "release-2029.12.0".to_owned(),
                    release_class: ReleaseClass::Stable,
                    manifest_digest: Sha256Digest::of_bytes("manifest"),
                    length: 123,
                    record: None,
                },
            )?,
            signatures: vec![],
        };
        let snapshot = TufEnvelopeV1 {
            signed: immutable_snapshot_metadata(
                "andyl/testing",
                4,
                "2030-01-01T00:00:00Z".to_owned(),
                &root,
                &targets,
                &delegated,
            )?,
            signatures: vec![],
        };
        let timestamp = TufEnvelopeV1 {
            signed: timestamp_metadata(
                "andyl/testing",
                5,
                "2029-12-01T00:00:00Z".to_owned(),
                "2029-12-02T00:00:00Z".to_owned(),
                &snapshot,
            )?,
            signatures: vec![],
        };
        Ok((
            canonical::to_vec(&timestamp)?,
            BTreeMap::from([
                ("tuf/1.root.json".to_owned(), canonical::to_vec(&root)?),
                (
                    "tuf/2.targets.json".to_owned(),
                    canonical::to_vec(&targets)?,
                ),
                (
                    "tuf/3.stable.json".to_owned(),
                    canonical::to_vec(&delegated)?,
                ),
                (
                    "tuf/4.snapshot.json".to_owned(),
                    canonical::to_vec(&snapshot)?,
                ),
            ]),
        ))
    }

    #[test]
    fn captures_exact_identity_without_claiming_root_trust() -> Result<()> {
        let (timestamp, immutable) = candidate()?;
        let binding = bind_staged_timestamp("andyl/testing", &timestamp, &immutable)?;

        assert_eq!(binding.timestamp_version, 5);
        assert_eq!(binding.snapshot_version, 4);
        assert_eq!(binding.snapshot_path, "tuf/4.snapshot.json");
        assert_eq!(
            binding.snapshot_digest,
            Sha256Digest::of_bytes(&immutable["tuf/4.snapshot.json"])
        );
        assert!(bind_staged_timestamp("andyl/main", &timestamp, &immutable).is_err());
        Ok(())
    }

    #[test]
    fn rejects_changed_inventory_missing_role_and_unsafe_pointer() -> Result<()> {
        let (timestamp, immutable) = candidate()?;
        let mut changed = immutable.clone();
        changed.get_mut("tuf/1.root.json").unwrap().push(b' ');
        assert!(bind_staged_timestamp("andyl/testing", &timestamp, &changed).is_err());

        let mut missing = immutable.clone();
        missing.remove("tuf/3.stable.json");
        assert!(bind_staged_timestamp("andyl/testing", &timestamp, &missing).is_err());

        let mut unsafe_pointer: TufEnvelopeV1<TimestampMetadataV1> =
            canonical::from_slice(&timestamp, "timestamp")?;
        unsafe_pointer.signed.snapshot.path = "../4.snapshot.json".to_owned();
        assert!(
            bind_staged_timestamp(
                "andyl/testing",
                &canonical::to_vec(&unsafe_pointer)?,
                &immutable
            )
            .is_err()
        );
        Ok(())
    }
}
