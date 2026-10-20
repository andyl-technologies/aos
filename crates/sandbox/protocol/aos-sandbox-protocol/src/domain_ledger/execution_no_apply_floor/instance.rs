//! Encodes the one independently initialized protected Root NoApply instance.
//!
//! ```text
//! namespace78 key = 16 zero bytes (reserved, never an operation head)
//! AOSRNI02 | native-entropy-instance:16 | checksum:32
//! ```
//!
//! This type validates DATA only. Only the actual paid Root writer may generate
//! entropy and atomically append the first instance/floor/head transaction.

use super::{RootExecutionNoApplyFloorDataErrorV2 as Error, field, hash};

const MAGIC: &[u8; 8] = b"AOSRNI02";
const DOMAIN: &[u8] = b"aos.sandbox.root.execution-no-apply-instance.v2\0";

/// Reserves a key disjoint from every validated operation head and revision key.
pub const ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2: [u8; 16] = [0; 16];
/// Names the exact canonical persistent instance record width.
pub const ROOT_EXECUTION_NO_APPLY_INSTANCE_BYTES_V2: usize = 56;

/// Carries a decoded persistent instance without creating or opening Root custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootExecutionNoApplyInstanceDataV2 {
    instance: [u8; 16],
}

impl RootExecutionNoApplyInstanceDataV2 {
    /// Validates a nonzero historical instance identifier as DATA.
    ///
    /// # Errors
    /// Rejects the reserved zero identity; no entropy or authority is created.
    pub fn new(instance: [u8; 16]) -> Result<Self, Error> {
        if instance == [0; 16] {
            return Err(Error);
        }
        Ok(Self { instance })
    }

    /// Returns the independently persisted identifier as comparison DATA.
    #[must_use]
    pub const fn instance(self) -> [u8; 16] {
        self.instance
    }

    /// Encodes the exact persistent-instance comparison record.
    #[must_use]
    pub fn encode_canonical(self) -> [u8; ROOT_EXECUTION_NO_APPLY_INSTANCE_BYTES_V2] {
        let mut bytes = [0; ROOT_EXECUTION_NO_APPLY_INSTANCE_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.instance);
        let checksum = hash(DOMAIN, &bytes[..24]);
        bytes[24..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes only this reserved key and exact checked persistent instance.
    ///
    /// # Errors
    /// Rejects operation/revision keys, wrong width/magic/checksum or zero identity.
    pub fn decode_canonical(key: &[u8], bytes: &[u8]) -> Result<Self, Error> {
        if key != ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2
            || bytes.len() != ROOT_EXECUTION_NO_APPLY_INSTANCE_BYTES_V2
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || hash(DOMAIN, &bytes[..24]) != field::<32>(bytes, 24)?
        {
            return Err(Error);
        }
        Self::new(field(bytes, 8)?)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        RootExecutionNoApplyFloorHeadDataV2, RootExecutionNoApplyFloorKeyDataV2,
        RootExecutionNoApplyFloorRecordDataV2,
    };
    use super::*;

    #[test]
    fn reserved_instance_key_is_disjoint_from_all_floor_and_derived_head_keys() {
        assert!(RootExecutionNoApplyFloorKeyDataV2::new([0; 16], 1).is_err());
        assert!(RootExecutionNoApplyFloorKeyDataV2::decode_canonical(&[0; 24]).is_err());
        let floor = RootExecutionNoApplyFloorRecordDataV2::new(super::super::tests::floor_fields())
            .unwrap();
        let head = RootExecutionNoApplyFloorHeadDataV2::from_floor_data_v2(floor);
        assert_ne!(
            floor.key().head_key_data_v2(),
            ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2
        );
        assert_ne!(head.key_data_v2(), ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2);
        assert_ne!(
            floor.key().encode_canonical().as_slice(),
            ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2
        );
        assert!(
            RootExecutionNoApplyFloorHeadDataV2::decode_canonical(
                &ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2,
                &head.encode_canonical()
            )
            .is_err()
        );
    }

    #[test]
    fn instance_requires_its_exact_key_bytes_and_checksum() {
        let instance = RootExecutionNoApplyInstanceDataV2::new([1; 16]).unwrap();
        let bytes = instance.encode_canonical();
        assert_eq!(
            RootExecutionNoApplyInstanceDataV2::decode_canonical(
                &ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2,
                &bytes
            )
            .unwrap(),
            instance
        );
        assert!(RootExecutionNoApplyInstanceDataV2::decode_canonical(&[1; 16], &bytes).is_err());
        for index in 0..bytes.len() {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(
                RootExecutionNoApplyInstanceDataV2::decode_canonical(
                    &ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2,
                    &changed
                )
                .is_err()
            );
        }
    }
}
