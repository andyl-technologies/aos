//! Channel and rollout selection helpers.
//!
//! A registry channel (e.g. `stable`) is published as a set of
//! [`PARTITION_COUNT`] static partition objects under
//! `channels/<channel>/<bucket-hex>`, each pointing at a signed release tag.
//! Every host deterministically hashes itself into one bucket (from a
//! registry-local salt generated on first sync), so producers can advance a
//! release across partitions gradually and hosts follow the rollout without
//! any server-side coordination.
//!
//! Two safety properties are enforced here:
//!
//! - **Monotonic floor**: [`check_floor`] refuses releases older than the
//!   highest release a host has already verified and installed, blocking
//!   rollback attacks against the mutable channel pointer.
//! - **Complete partition sets**: [`assert_full_partition_set`] refuses to
//!   publish a channel with unassigned buckets, so every consumer always
//!   resolves to some release.

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

/// The number of rollout partitions in every channel.
pub const PARTITION_COUNT: usize = 256;

/// In-memory view of the 256 partition targets for one channel.
///
/// Each bucket optionally targets one release version; `None` means the
/// bucket has not been assigned yet (only valid before first publication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionMap {
    targets: Vec<Option<semver::Version>>,
}

impl Default for PartitionMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PartitionMap {
    /// Creates an empty partition map with every bucket unassigned.
    pub fn new() -> Self {
        Self {
            targets: vec![None; PARTITION_COUNT],
        }
    }

    /// Creates a partition map with every bucket pointing at `version`.
    pub fn all(version: semver::Version) -> Self {
        Self {
            targets: vec![Some(version); PARTITION_COUNT],
        }
    }

    /// Sets a partition target.
    ///
    /// # Errors
    ///
    /// Returns an error if `bucket` is outside the fixed partition range.
    pub fn set(&mut self, bucket: usize, version: semver::Version) -> Result<()> {
        let slot = self
            .targets
            .get_mut(bucket)
            .ok_or_else(|| anyhow::anyhow!("partition bucket {bucket} is outside 0..255"))?;
        *slot = Some(version);
        Ok(())
    }

    /// Returns the target release for a bucket, or `None` if unassigned.
    pub fn get(&self, bucket: u8) -> Option<&semver::Version> {
        self.targets[bucket as usize].as_ref()
    }

    /// Iterates over all partition targets in bucket order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, Option<&semver::Version>)> {
        self.targets
            .iter()
            .enumerate()
            .map(|(i, v)| (i as u8, v.as_ref()))
    }

    /// Counts partitions that target `version`.
    pub fn count_targeting(&self, version: &semver::Version) -> usize {
        self.targets
            .iter()
            .filter(|target| target.as_ref() == Some(version))
            .count()
    }
}

/// Compute the stable rollout bucket for a seed string.
///
/// The bucket is the low byte of `sha256(seed)`, yielding `0..=255`.
pub fn select_bucket(seed: &str) -> u8 {
    let digest = Sha256::digest(seed.as_bytes());
    digest[31]
}

/// Compute a bucket from a registry-local salt.
///
/// The salt is generated on first channel sync and the resulting bucket index is
/// persisted, so cloned images do not inherit an image-baked machine id and the
/// host keeps the same rollout assignment after the first successful sync.
pub fn select_registry_bucket(registry: &str, salt: &str) -> u8 {
    select_bucket(&format!("{registry}\0{salt}"))
}

/// Generate a fresh random hex salt for first-time bucket assignment.
pub fn generate_bucket_salt() -> String {
    let random_bytes: [u8; 32] = rand::random();
    hex::encode(random_bytes)
}

/// Render a bucket as a two-digit lowercase hex partition name.
pub fn bucket_hex(bucket: u8) -> String {
    format!("{bucket:02x}")
}

/// Return the static partition object path for a channel and bucket.
///
/// Bucket `10` of channel `stable` maps to `channels/stable/0a`.
pub fn partition_path(channel: &str, bucket: u8) -> String {
    format!("channels/{channel}/{}", bucket_hex(bucket))
}

/// Return the deterministic probe-forward order for a bucket.
///
/// Starts at the host's own bucket and wraps around all 256 buckets, so a
/// consumer whose partition object is missing falls forward to the next
/// available one instead of failing.
pub fn probe_order(bucket: u8) -> Vec<u8> {
    (0..=255).map(|i| bucket.wrapping_add(i)).collect()
}

/// Use a persisted bucket when present, otherwise compute one from registry salt.
pub fn resolve_bucket(persisted: Option<u8>, registry: &str, salt: &str) -> u8 {
    persisted.unwrap_or_else(|| select_registry_bucket(registry, salt))
}

/// Refuse candidates older than the persisted semver floor.
///
/// Equal versions are accepted as a no-op; newer versions raise the floor after
/// the caller has verified and installed the target.
///
/// # Errors
///
/// Returns an error when `candidate` is strictly older than `floor`,
/// indicating an attempted channel rollback.
pub fn check_floor(floor: Option<&semver::Version>, candidate: &semver::Version) -> Result<()> {
    if let Some(floor) = floor {
        if candidate < floor {
            bail!(
                "registry rollback refused: target release {candidate} is older than floor {floor}",
            );
        }
    }
    Ok(())
}

/// Compute the frontier release for a partition map.
///
/// The frontier is the maximum semver targeted by any partition.
pub fn compute_frontier(map: &PartitionMap) -> Option<semver::Version> {
    map.targets.iter().filter_map(Clone::clone).max()
}

/// Refuse to publish a channel with missing partition targets.
///
/// # Errors
///
/// Returns an error listing the hex names of every unassigned partition.
pub fn assert_full_partition_set(map: &PartitionMap) -> Result<()> {
    let missing: Vec<String> = map
        .iter()
        .filter_map(|(bucket, target)| {
            if target.is_none() {
                Some(bucket_hex(bucket))
            } else {
                None
            }
        })
        .collect();

    if !missing.is_empty() {
        bail!(
            "channel partition set is incomplete; missing {} partition(s): {}",
            missing.len(),
            missing.join(", "),
        );
    }
    Ok(())
}

/// Select the next `count` partitions to advance to `target` in ascending order.
///
/// Partitions that already target `target` are skipped, so calling this
/// repeatedly walks the whole channel toward the new release.
pub fn ascending_fill(count: usize, current: &PartitionMap, target: &semver::Version) -> Vec<u8> {
    current
        .iter()
        .filter_map(|(bucket, version)| {
            if version == Some(target) {
                None
            } else {
                Some(bucket)
            }
        })
        .take(count)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    #[test]
    fn bucket_is_deterministic() {
        assert_eq!(select_bucket("seed-a"), select_bucket("seed-a"));
        assert_ne!(select_bucket("seed-a"), select_bucket("seed-b"));
    }

    #[test]
    fn registry_bucket_uses_registry_local_salt() {
        assert_eq!(
            select_registry_bucket("core", "salt-a"),
            select_registry_bucket("core", "salt-a"),
        );
        assert_ne!(
            select_registry_bucket("core", "salt-a"),
            select_registry_bucket("core", "salt-b"),
        );
        assert_ne!(
            select_registry_bucket("core", "salt-a"),
            select_registry_bucket("extras", "salt-a"),
        );
    }

    #[test]
    fn generated_bucket_salt_is_hex_encoded_random_material() {
        let salt = generate_bucket_salt();
        assert_eq!(salt.len(), 64);
        assert!(salt.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn bucket_hex_two_digits() {
        assert_eq!(bucket_hex(0), "00");
        assert_eq!(bucket_hex(5), "05");
        assert_eq!(bucket_hex(255), "ff");
    }

    #[test]
    fn partition_path_uses_two_digit_bucket() {
        assert_eq!(partition_path("stable", 10), "channels/stable/0a");
    }

    #[test]
    fn probe_order_wraps_and_covers_all_buckets() {
        let order = probe_order(254);
        assert_eq!(order[0], 254);
        assert_eq!(order[1], 255);
        assert_eq!(order[2], 0);
        assert_eq!(order.len(), 256);
        let unique: HashSet<u8> = order.into_iter().collect();
        assert_eq!(unique.len(), 256);
    }

    #[test]
    fn persisted_bucket_wins() {
        assert_eq!(resolve_bucket(Some(42), "core", "new-salt"), 42);
    }

    #[test]
    fn persisted_bucket_survives_bucket_source_migration() {
        let migrated = resolve_bucket(Some(183), "core", "registry-local-salt");
        assert_eq!(migrated, 183);
    }

    #[test]
    fn floor_allows_equal_or_newer() {
        assert!(check_floor(Some(&v("1.4.2")), &v("1.4.2")).is_ok());
        assert!(check_floor(Some(&v("1.4.2")), &v("1.4.3")).is_ok());
    }

    #[test]
    fn floor_rejects_older() {
        assert!(check_floor(Some(&v("1.4.2")), &v("1.4.1")).is_err());
    }

    #[test]
    fn floor_allows_missing_floor() {
        assert!(check_floor(None, &v("0.1.0")).is_ok());
    }

    #[test]
    fn frontier_is_max_semver_over_partitions() {
        let mut map = PartitionMap::all(v("1.1.3"));
        map.set(0, v("1.2.0")).unwrap();
        map.set(255, v("1.0.0")).unwrap();

        assert_eq!(compute_frontier(&map), Some(v("1.2.0")));
    }

    #[test]
    fn full_partition_set_rejects_missing_targets() {
        let mut map = PartitionMap::all(v("1.0.0"));
        map.targets[7] = None;

        let err = assert_full_partition_set(&map).unwrap_err().to_string();
        assert!(err.contains("07"), "got: {err}");
    }

    #[test]
    fn full_partition_set_accepts_complete_map() {
        let map = PartitionMap::all(v("1.0.0"));
        assert_full_partition_set(&map).unwrap();
    }

    #[test]
    fn ascending_fill_skips_already_advanced_partitions() {
        let mut map = PartitionMap::all(v("1.0.0"));
        map.set(0, v("1.1.0")).unwrap();
        map.set(2, v("1.1.0")).unwrap();

        assert_eq!(ascending_fill(4, &map, &v("1.1.0")), vec![1, 3, 4, 5]);
    }
}
