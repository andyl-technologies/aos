//! Frames post26 currentness comparison on the same retained Delete socket.
//!
//! ```text
//! AOSDPV03 | version3/reserved6 | challenge16 | opening32 | draft32 |
//! accepted-C64 | committed-Source64 | completed-Session64 |
//! signed-request-artifact-digest32 | actual-outcome-commitment32
//! ```
//!
//! The frame carries comparison DATA only. Root must independently read and
//! validate all actual native/model histories under the original D horizon.

/// Gives the exact finite post26 comparison extent.
pub const DELETE_ROOT_PREPARATION_CURRENT_BYTES_V3: usize = 352;
/// Selects only the new post26 comparison frame, never preparatory acceptance.
pub const DELETE_ROOT_PREPARATION_CURRENT_MAGIC_V3: &[u8; 8] = b"AOSDPV03";

/// Reports malformed post26 comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Delete post26 currentness comparison frame differs")]
pub struct DeleteRootPreparationCurrentErrorV3;

/// Carries exact comparison coordinates; no field is native authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPreparationCurrentDataV3 {
    /// Same original Root challenge, never a new nonce or horizon.
    pub challenge: [u8; 16],
    /// Exact retained opening commitment.
    pub opening: [u8; 32],
    /// Exact previously accepted signed26 draft commitment.
    pub draft: [u8; 32],
    /// Actual completed Controller desired-state acceptance native COMMIT.
    pub controller: [u8; 64],
    /// Actual Source ControllerCommitted native COMMIT.
    pub source: [u8; 64],
    /// Actual same Storage Session terminal native COMMIT after full posts.
    pub session: [u8; 64],
    /// Canonical signed26 request-artifact digest from the completed protected receipt.
    pub request: [u8; 32],
    /// BLAKE3 commitment to its complete authenticated outcome packet.
    pub outcome: [u8; 32],
}

impl DeleteRootPreparationCurrentDataV3 {
    /// Encodes one exact finite purpose without granting an effect or completion.
    ///
    /// # Errors
    /// Rejects sentinel coordinates or malformed native COMMIT DATA.
    pub fn encode_v3(
        self,
    ) -> Result<[u8; DELETE_ROOT_PREPARATION_CURRENT_BYTES_V3], DeleteRootPreparationCurrentErrorV3>
    {
        self.require_shape_v3()?;
        let mut bytes = [0; DELETE_ROOT_PREPARATION_CURRENT_BYTES_V3];
        bytes[..8].copy_from_slice(DELETE_ROOT_PREPARATION_CURRENT_MAGIC_V3);
        bytes[8..10].copy_from_slice(&3_u16.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.challenge);
        bytes[32..64].copy_from_slice(&self.opening);
        bytes[64..96].copy_from_slice(&self.draft);
        bytes[96..160].copy_from_slice(&self.controller);
        bytes[160..224].copy_from_slice(&self.source);
        bytes[224..288].copy_from_slice(&self.session);
        bytes[288..320].copy_from_slice(&self.request);
        bytes[320..352].copy_from_slice(&self.outcome);
        Ok(bytes)
    }

    /// Decodes only the exact new finite purpose and complete fixed extent.
    ///
    /// # Errors
    /// Rejects old/other purposes, versions, reserved bytes or malformed coordinates.
    pub fn decode_v3(bytes: &[u8]) -> Result<Self, DeleteRootPreparationCurrentErrorV3> {
        if bytes.len() != DELETE_ROOT_PREPARATION_CURRENT_BYTES_V3
            || &bytes[..8] != DELETE_ROOT_PREPARATION_CURRENT_MAGIC_V3
            || bytes[8..10] != 3_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(DeleteRootPreparationCurrentErrorV3);
        }
        let result = Self {
            challenge: read(bytes, 16)?,
            opening: read(bytes, 32)?,
            draft: read(bytes, 64)?,
            controller: read(bytes, 96)?,
            source: read(bytes, 160)?,
            session: read(bytes, 224)?,
            request: read(bytes, 288)?,
            outcome: read(bytes, 320)?,
        };
        result.require_shape_v3()?;
        Ok(result)
    }

    /// Commits the exact canonical completed post26 frame for later Apply signing.
    ///
    /// # Errors
    /// Rejects the same malformed native DATA as the strict frame encoder.
    pub fn commitment_v3(self) -> Result<[u8;32], DeleteRootPreparationCurrentErrorV3> {
        use sha2::{Digest as _, Sha256};
        Ok(Sha256::new().chain_update(b"aos.sandbox.delete.completed-preparation.v3\0")
            .chain_update(self.encode_v3()?).finalize().into())
    }

    fn require_shape_v3(&self) -> Result<(), DeleteRootPreparationCurrentErrorV3> {
        if self.challenge == [0; 16]
            || self.opening == [0; 32]
            || self.draft == [0; 32]
            || self.request == [0; 32]
            || self.outcome == [0; 32]
        {
            return Err(DeleteRootPreparationCurrentErrorV3);
        }
        for native in [&self.controller, &self.source, &self.session] {
            let sequence = u64::from_be_bytes(read(native, 48)?);
            let end = u64::from_be_bytes(read(native, 56)?);
            if native[..16] == [0; 16]
                || native[16..48] == [0; 32]
                || matches!(sequence, 0 | u64::MAX)
                || end == 0
            {
                return Err(DeleteRootPreparationCurrentErrorV3);
            }
        }
        Ok(())
    }
}

fn read<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], DeleteRootPreparationCurrentErrorV3> {
    bytes
        .get(offset..offset + N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(DeleteRootPreparationCurrentErrorV3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> DeleteRootPreparationCurrentDataV3 {
        let native = crate::domain_ledger::delete_batch::encode_native_commit_data_v1(
            [4; 16], 7, 512, &[5; 32],
        )
        .unwrap();
        DeleteRootPreparationCurrentDataV3 {
            challenge: [1; 16],
            opening: [2; 32],
            draft: [3; 32],
            controller: native,
            source: native,
            session: native,
            request: [6; 32],
            outcome: [7; 32],
        }
    }

    #[test]
    fn apply_predecessor_commitment_includes_each_complete_native_and_receipt_coordinate() {
        let original = frame();
        let commitment = original.commitment_v3().unwrap();
        for coordinate in 0..3 {
            for offset in [0, 15, 16, 47, 48, 55, 56, 63] {
                let mut changed = original;
                let native = match coordinate {
                    0 => &mut changed.controller,
                    1 => &mut changed.source,
                    _ => &mut changed.session,
                };
                native[offset] ^= 1;
                if let Ok(changed) = changed.commitment_v3() {
                    assert_ne!(changed, commitment);
                }
            }
        }
        let mut changed = original;
        changed.request[0] ^= 1;
        assert_ne!(changed.commitment_v3().unwrap(), commitment);
        let mut changed = original;
        changed.outcome[31] ^= 1;
        assert_ne!(changed.commitment_v3().unwrap(), commitment);
    }

    #[test]
    fn fixed_post26_purpose_is_strict_and_preserves_all_coordinates() {
        let frame = frame();
        let bytes = frame.encode_v3().unwrap();
        assert_eq!(
            DeleteRootPreparationCurrentDataV3::decode_v3(&bytes).unwrap(),
            frame
        );
        for index in [0, 7, 8, 9, 10, 15] {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(DeleteRootPreparationCurrentDataV3::decode_v3(&changed).is_err());
        }
        for length in 0..bytes.len() {
            assert!(DeleteRootPreparationCurrentDataV3::decode_v3(&bytes[..length]).is_err());
        }
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(DeleteRootPreparationCurrentDataV3::decode_v3(&extended).is_err());
        let mut changed = frame;
        changed.source[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(changed.encode_v3().is_err());
        let mut old = bytes;
        old[..8].copy_from_slice(b"AOSDPA03");
        assert!(DeleteRootPreparationCurrentDataV3::decode_v3(&old).is_err());
    }
}
