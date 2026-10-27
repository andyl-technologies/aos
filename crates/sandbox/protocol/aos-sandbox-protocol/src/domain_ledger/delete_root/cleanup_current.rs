//! Frames actual completed Network9 and fresh Host3 receipt comparison DATA.
//!
//! ```text
//! AOSDCC04/version4/reserved6 | challenge16 | opening32 | strict9-approval32 |
//! network(native64,signed-request32,outcome32) | host(native64,signed-request32,outcome32)
//! ```
//!
//! Native64 uses the existing names48/next8/held-length8 Session position.
//! Receivers separately select actual receipt COMMITs, complete histories,
//! same-D/Source/C currentness and every native post. These bytes create no
//! Session, Host disposal original, signature or Mount permission.

use sha2::{Digest as _, Sha256};

/// Gives the exact finite postNetwork/preReap comparison frame width.
pub const DELETE_ROOT_CLEANUP_CURRENT_BYTES_V4: usize = 352;
const MAGIC: &[u8; 8] = b"AOSDCC04";

/// Carries one historical receipt's native and authenticated packet coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootCleanupTerminalDataV4 {
    /// Carries the actual names48/next8/held-length8 Session completion position.
    pub native: [u8; 64],
    /// Names the exact authenticated signed request artifact.
    pub request: [u8; 32],
    /// Commits the whole authenticated outcome packet.
    pub outcome: [u8; 32],
}

impl DeleteRootCleanupTerminalDataV4 {
    pub(super) fn require_shape_v4(self) -> Result<(), DeleteRootCleanupCurrentErrorV4> {
        super::super::protected_names::SessionCompletionPositionDataV4::decode_v4(&self.native)
            .map_err(|_| DeleteRootCleanupCurrentErrorV4)?;
        if self.request == [0; 32] || self.outcome == [0; 32] {
            return Err(DeleteRootCleanupCurrentErrorV4);
        }
        Ok(())
    }

    pub(super) fn write_v4(self, bytes: &mut [u8]) {
        bytes[..64].copy_from_slice(&self.native);
        bytes[64..96].copy_from_slice(&self.request);
        bytes[96..128].copy_from_slice(&self.outcome);
    }

    pub(super) fn read_v4(bytes: &[u8]) -> Result<Self, DeleteRootCleanupCurrentErrorV4> {
        let value = Self {
            native: array(bytes, 0)?,
            request: array(bytes, 64)?,
            outcome: array(bytes, 96)?,
        };
        value.require_shape_v4()?;
        Ok(value)
    }
}

/// Carries full receipt associations for the genuine same-D Root comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootCleanupCurrentDataV4 {
    /// Preserves the actual original Root challenge.
    pub challenge: [u8; 16],
    /// Commits the unchanged pending D opening.
    pub opening: [u8; 32],
    /// Commits the exact completed strict Network9 approval.
    pub approved9: [u8; 32],
    /// Identifies the actual completed Destroy9 receipt.
    pub network: DeleteRootCleanupTerminalDataV4,
    /// Identifies the actual fresh Host3 receipt under its paid kernel nonce.
    pub host: DeleteRootCleanupTerminalDataV4,
}

impl DeleteRootCleanupCurrentDataV4 {
    /// Encodes exactly this new finite comparison purpose.
    ///
    /// # Errors
    /// Rejects zero identities or malformed native receipt coordinates.
    pub fn encode_v4(
        self,
    ) -> Result<[u8; DELETE_ROOT_CLEANUP_CURRENT_BYTES_V4], DeleteRootCleanupCurrentErrorV4> {
        if self.challenge == [0; 16] || self.opening == [0; 32] || self.approved9 == [0; 32] {
            return Err(DeleteRootCleanupCurrentErrorV4);
        }
        self.network.require_shape_v4()?;
        self.host.require_shape_v4()?;
        let mut bytes = [0; DELETE_ROOT_CLEANUP_CURRENT_BYTES_V4];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&4_u16.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.challenge);
        bytes[32..64].copy_from_slice(&self.opening);
        bytes[64..96].copy_from_slice(&self.approved9);
        self.network.write_v4(&mut bytes[96..224]);
        self.host.write_v4(&mut bytes[224..]);
        Ok(bytes)
    }

    /// Decodes only the complete exact comparison frame.
    ///
    /// # Errors
    /// Rejects another purpose/version, reserved bytes, width or malformed proof DATA.
    pub fn decode_v4(bytes: &[u8]) -> Result<Self, DeleteRootCleanupCurrentErrorV4> {
        if bytes.len() != DELETE_ROOT_CLEANUP_CURRENT_BYTES_V4
            || &bytes[..8] != MAGIC
            || bytes[8..10] != 4_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(DeleteRootCleanupCurrentErrorV4);
        }
        let value = Self {
            challenge: array(bytes, 16)?,
            opening: array(bytes, 32)?,
            approved9: array(bytes, 64)?,
            network: DeleteRootCleanupTerminalDataV4::read_v4(&bytes[96..224])?,
            host: DeleteRootCleanupTerminalDataV4::read_v4(&bytes[224..])?,
        };
        value.encode_v4()?;
        Ok(value)
    }

    /// Commits every receipt coordinate under its distinct cleanup purpose.
    ///
    /// # Errors
    /// Rejects the same malformed fields as the canonical encoder.
    pub fn commitment_v4(self) -> Result<[u8; 32], DeleteRootCleanupCurrentErrorV4> {
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.delete.cleanup-current.v4\0")
            .chain_update(self.encode_v4()?)
            .finalize()
            .into())
    }
}

/// Commits the complete strict Network9 approval under the cleanup domain.
///
/// # Errors
/// Rejects a malformed strict Network9 approval encoding.
pub fn cleanup_approval_commitment_data_v4(
    approval: super::final_inventory::DeleteRootPreparatoryApprovalDataV3,
) -> Result<[u8; 32], super::resource_exchange::DeleteRootResourceWireErrorV2> {
    let bytes = approval.encode_for_purpose_v3(
        super::resource_exchange::DeleteRootResourcePurposeDataV3::Network9,
    )?;
    Ok(Sha256::new()
        .chain_update(b"aos.sandbox.delete.cleanup-approved-network.v4\0")
        .chain_update(bytes)
        .finalize()
        .into())
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], DeleteRootCleanupCurrentErrorV4> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(N)
                    .ok_or(DeleteRootCleanupCurrentErrorV4)?,
        )
        .ok_or(DeleteRootCleanupCurrentErrorV4)?
        .try_into()
        .map_err(|_| DeleteRootCleanupCurrentErrorV4)
}

/// Reports malformed cleanup receipt association DATA.
#[derive(Debug, thiserror::Error)]
#[error("Delete cleanup receipt association is malformed")]
pub struct DeleteRootCleanupCurrentErrorV4;

#[cfg(test)]
mod tests {
    use super::super::super::protected_names::{
        ProtectedJournalNamesV1, SessionCompletionPositionDataV4,
    };
    use super::*;

    #[test]
    fn cleanup_frame_preserves_both_positions_and_rejects_old_or_partial_purposes() {
        let position = SessionCompletionPositionDataV4::from_native_data_v4(
            ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            12,
            400,
        )
        .unwrap()
        .encode_v4();
        let frame = DeleteRootCleanupCurrentDataV4 {
            challenge: [1; 16],
            opening: [2; 32],
            approved9: [3; 32],
            network: DeleteRootCleanupTerminalDataV4 {
                native: position,
                request: [4; 32],
                outcome: [5; 32],
            },
            host: DeleteRootCleanupTerminalDataV4 {
                native: position,
                request: [6; 32],
                outcome: [7; 32],
            },
        };
        let bytes = frame.encode_v4().unwrap();
        assert_eq!(
            DeleteRootCleanupCurrentDataV4::decode_v4(&bytes).unwrap(),
            frame
        );
        let original = frame.commitment_v4().unwrap();
        for offset in [16, 32, 64, 96, 160, 192, 224, 288, 320] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert_ne!(
                DeleteRootCleanupCurrentDataV4::decode_v4(&changed)
                    .unwrap()
                    .commitment_v4()
                    .unwrap(),
                original
            );
        }
        for offset in [0, 8, 10] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(DeleteRootCleanupCurrentDataV4::decode_v4(&changed).is_err());
        }
        assert!(DeleteRootCleanupCurrentDataV4::decode_v4(&bytes[..351]).is_err());
        assert!(
            DeleteRootCleanupCurrentDataV4::decode_v4(&[bytes.as_slice(), &[0]].concat()).is_err()
        );
        let mut old_purpose = bytes;
        old_purpose[..8].copy_from_slice(b"AOSDPC03");
        assert!(DeleteRootCleanupCurrentDataV4::decode_v4(&old_purpose).is_err());
    }
}
