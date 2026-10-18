//! Consumer rollout buckets and shared pure channel operations.
//!
//! The wire paths, partition maps, SemVer floors, and frontier rules are owned
//! by [`aos_registry_format::channel`] so native, server, and browser callers
//! use the same policy. This module adds native random salt generation for a
//! host's persistent registry bucket assignment.

pub use aos_registry_format::channel::{
    PARTITION_COUNT, PartitionMap, ascending_fill, assert_full_partition_set, bucket_hex,
    check_floor, compute_frontier, partition_path, probe_order, resolve_bucket, select_bucket,
    select_registry_bucket,
};

/// Generate a fresh random hex salt for first-time bucket assignment.
pub fn generate_bucket_salt() -> String {
    let random_bytes: [u8; 32] = rand::random();
    hex::encode(random_bytes)
}

#[cfg(test)]
mod tests {
    use super::generate_bucket_salt;

    #[test]
    fn generated_bucket_salt_is_hex_encoded_random_material() {
        let salt = generate_bucket_salt();
        assert_eq!(salt.len(), 64);
        assert!(salt.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
