//! Independently checks the sole publication change permitted by local reopening.
//!
//! A writable T1 reopen refreshes its capability probe timestamp. Saved fixture
//! bytes and the exact immutable predecessor distinguish that operation from
//! reference, catalog or authority changes; decoded snapshots grant no authority.

use super::{FixtureResult, check_owner, fs, write_private};
use std::path::Path;
use terrane_format::{
    bucket::BucketCapabilities,
    gc::publication::{PortableCurrent, PortableSnapshot},
};

/// Saves the exact original publication and capabilities after fixture setup.
///
/// # Errors
/// Rejects unavailable original records or failed exclusive fixture writes.
pub(super) fn save(root: &Path) -> FixtureResult<()> {
    for (source, destination) in [
        ("publication/PORTABLE", "expected.portable"),
        ("CAPABILITIES", "expected.capabilities"),
    ] {
        write_private(
            &root.join(destination),
            &fs::read(root.join("bucket").join(source))?,
        )?;
    }
    Ok(())
}

/// Refuses any publication change beyond the existing startup probe refresh.
///
/// # Errors
/// Rejects wrong ownership, missing records, invalid digests or ancestry, and
/// changes to any selected projection or capability field except the timestamp.
pub(super) fn verify(root: &Path, owner: u32) -> FixtureResult<()> {
    check_owner(root, owner)?;
    let bucket = root.join("bucket");
    let original_bytes = fs::read(root.join("expected.portable"))?;
    let original = PortableCurrent::decode(&original_bytes)?;
    let previous_bytes = fs::read(bucket.join(&original.key))?;
    original.check_snapshot(&previous_bytes)?;

    let current_bytes = fs::read(bucket.join("publication/PORTABLE"))?;
    let current = PortableCurrent::decode(&current_bytes)?;
    let current_snapshot_bytes = fs::read(bucket.join(&current.key))?;
    current.check_snapshot(&current_snapshot_bytes)?;
    let original_capabilities = fs::read(root.join("expected.capabilities"))?;
    let current_capabilities = fs::read(bucket.join("CAPABILITIES"))?;
    if current_bytes == original_bytes {
        if current_capabilities != original_capabilities {
            return Err("unchanged original pointer has different capabilities".into());
        }
        return Ok(());
    }

    let snapshot = PortableSnapshot::decode(&current_snapshot_bytes)?;
    check_refresh(
        &snapshot,
        &original,
        &previous_bytes,
        &original_capabilities,
        &current_capabilities,
    )
}

/// Checks the exact metadata-only delta without interpreting it as authority.
fn check_refresh(
    snapshot: &PortableSnapshot,
    original: &PortableCurrent,
    previous_bytes: &[u8],
    original_capabilities: &[u8],
    current_capabilities: &[u8],
) -> FixtureResult<()> {
    snapshot.check_predecessor(original, previous_bytes)?;
    let [change] = snapshot.projection.as_slice() else {
        return Err("reopen changed more than its exact capability projection".into());
    };
    if change.key != "CAPABILITIES" || change.value.as_deref() != Some(current_capabilities) {
        return Err("reopen changed original reference or catalog projections".into());
    }

    let original = BucketCapabilities::decode(original_capabilities)?;
    let mut current = BucketCapabilities::decode(current_capabilities)?;
    if current.probed_at < original.probed_at {
        return Err("reopen probe timestamp regressed".into());
    }
    current.probed_at = original.probed_at;
    if current != original {
        return Err("reopen changed original capability fields beyond its timestamp".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use terrane_format::{
        bucket::StoreProfile,
        gc::publication::{BackendBinding, ProjectionEntry, SelectedHistory},
    };

    struct Records {
        original: PortableCurrent,
        previous: Vec<u8>,
        capabilities: BucketCapabilities,
        successor: PortableSnapshot,
    }

    impl Records {
        fn new() -> FixtureResult<Self> {
            let capabilities = BucketCapabilities {
                layout_version: 2,
                create_if_absent: true,
                compare_and_swap: true,
                ranges: true,
                presign: false,
                multi_writer: true,
                probed_at: 7,
                profile: StoreProfile {
                    identity: "terrane-v1".into(),
                    algorithm: "blake3".into(),
                    chunk: "cdc-1m".into(),
                    seed: [3; 32],
                },
                generation: Some(8),
                ref_names: Some(vec!["refs/heads/_/main".into()]),
                publication_protocol: Some(1),
            };
            let origin = BackendBinding::Local {
                root: b"/fixture".to_vec(),
                root_device: 1,
                root_inode: 2,
                coordination_device: 3,
                coordination_inode: 4,
            };
            let history = SelectedHistory {
                branches: Vec::new(),
                origin: origin.clone(),
            };
            let checkpoint = PortableSnapshot {
                revision: 0,
                origin,
                projection: vec![
                    ProjectionEntry {
                        key: "CAPABILITIES".into(),
                        value: Some(capabilities.encode()?),
                    },
                    ProjectionEntry {
                        key: "gc/lease".into(),
                        value: None,
                    },
                    ProjectionEntry {
                        key: "publication/SELECTED-HISTORY".into(),
                        value: Some(history.encode()?),
                    },
                ],
                predecessor: None,
            };
            let previous = checkpoint.encode()?;
            let original = PortableCurrent {
                key: format!("publication/snapshots/0:{}", "00".repeat(32)),
                digest: *blake3::hash(&previous).as_bytes(),
            };
            let successor = PortableSnapshot {
                revision: 1,
                origin: checkpoint.origin,
                projection: Vec::new(),
                predecessor: Some(original.clone()),
            };
            Ok(Self {
                original,
                previous,
                capabilities,
                successor,
            })
        }

        fn check(&mut self, current: &BucketCapabilities) -> FixtureResult<()> {
            let bytes = current.encode()?;
            self.successor.projection = vec![ProjectionEntry {
                key: "CAPABILITIES".into(),
                value: Some(bytes.clone()),
            }];
            check_refresh(
                &self.successor,
                &self.original,
                &self.previous,
                &self.capabilities.encode()?,
                &bytes,
            )
        }
    }

    #[test]
    fn publication_verifier_accepts_only_the_probe_timestamp_change() -> FixtureResult<()> {
        let mut records = Records::new()?;
        let mut current = records.capabilities.clone();
        current.probed_at += 1;
        records.check(&current)?;

        current.presign = true;
        assert!(records.check(&current).is_err());
        current.presign = false;
        current.probed_at = records.capabilities.probed_at - 1;
        assert!(records.check(&current).is_err());
        Ok(())
    }

    #[test]
    fn publication_verifier_rejects_an_added_reference_projection() -> FixtureResult<()> {
        let mut records = Records::new()?;
        let mut current = records.capabilities.clone();
        current.probed_at += 1;
        records.check(&current)?;

        records.successor.projection.push(ProjectionEntry {
            key: "refs/heads/_/main:record".into(),
            value: Some(vec![1]),
        });
        assert!(
            check_refresh(
                &records.successor,
                &records.original,
                &records.previous,
                &records.capabilities.encode()?,
                &current.encode()?
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn publication_verifier_rejects_rebound_predecessor_bytes() -> FixtureResult<()> {
        let mut records = Records::new()?;
        let mut current = records.capabilities.clone();
        current.probed_at += 1;
        records.check(&current)?;

        records.previous.push(0);
        assert!(records.check(&current).is_err());
        Ok(())
    }
}
