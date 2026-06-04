//! Channel and rollout selection helpers.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

/// Compute the stable rollout bucket for a machine id.
///
/// The bucket is the low byte of `sha256(machine_id)`, yielding `0..=255`.
pub fn select_bucket(machine_id: &str) -> u8 {
    let digest = Sha256::digest(machine_id.as_bytes());
    digest[31]
}

/// Render a bucket as a two-digit lowercase hex partition name.
pub fn bucket_hex(bucket: u8) -> String {
    format!("{bucket:02x}")
}

/// Return the deterministic probe-forward order for a bucket.
pub fn probe_order(bucket: u8) -> Vec<u8> {
    (0..=255).map(|i| bucket.wrapping_add(i)).collect()
}

/// Use a persisted bucket when present, otherwise compute one from `machine_id`.
pub fn resolve_bucket(persisted: Option<u8>, machine_id: &str) -> u8 {
    persisted.unwrap_or_else(|| select_bucket(machine_id))
}

/// Refuse candidates older than the persisted semver floor.
///
/// Equal versions are accepted as a no-op; newer versions raise the floor after
/// the caller has verified and installed the target.
pub fn check_floor(
    floor: Option<&semver::Version>,
    candidate: &semver::Version,
) -> Result<()> {
    if let Some(floor) = floor {
        if candidate < floor {
            bail!(
                "registry rollback refused: target release {candidate} is older than floor {floor}",
            );
        }
    }
    Ok(())
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
        assert_eq!(select_bucket("machine-a"), select_bucket("machine-a"));
        assert_ne!(select_bucket("machine-a"), select_bucket("machine-b"));
    }

    #[test]
    fn bucket_hex_two_digits() {
        assert_eq!(bucket_hex(0), "00");
        assert_eq!(bucket_hex(5), "05");
        assert_eq!(bucket_hex(255), "ff");
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
        assert_eq!(resolve_bucket(Some(42), "new-machine-id"), 42);
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
}
