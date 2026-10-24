//! Frames final Delete physical receipts and Source COMMIT comparison DATA.
//!
//! ```text
//! AOSDFP04/version4/reserved6 | challenge16 | opening32 | cleanup352-hash32 |
//! strict62-hash32 | strict7-hash32 | mount-Session128 | storage-Session128
//! final-source-frame = physical416 | accepted-Controller-COMMIT64 | final-Source-COMMIT64
//! ```
//!
//! Session positions retain their names48/NEXT8/end8 ABI. Controller and Source
//! COMMIT positions retain tx16/digest32/sequence8/end8. Equal array widths do
//! not identify these contracts. Actual owners independently authenticate the
//! full histories, EOF, currentness, same D, and every owed post.

use super::cleanup_current::DeleteRootCleanupTerminalDataV4;
use super::final_inventory::DeleteRootPreparatoryApprovalDataV3;
use super::resource_exchange::DeleteRootResourcePurposeDataV3;
use sha2::{Digest as _, Sha256};

/// Gives the exact finite physical comparison extent.
pub const DELETE_ROOT_PHYSICAL_COMPLETION_BYTES_V4: usize = 416;
/// Gives the physical comparison plus the two distinct COMMIT positions.
pub const DELETE_ROOT_SOURCE_COMPLETION_BYTES_V4: usize = 544;

/// Carries exact physical receipts retained by the genuine completion borrower.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootPhysicalCompletionDataV4 {
    /// Preserves the original kernel nonce.
    pub challenge: [u8; 16],
    /// Commits the unchanged original D opening.
    pub opening: [u8; 32],
    /// Commits the actual post9/freshHost3 cleanup352 frame.
    pub cleanup: [u8; 32],
    /// Commits the exact strict Mount62 approval under its own domain.
    pub approved_mount: [u8; 32],
    /// Commits the exact strict Storage7 approval under its own domain.
    pub approved_storage: [u8; 32],
    /// Carries actual Mount Released request/outcome/Session coordinates.
    pub mount: DeleteRootCleanupTerminalDataV4,
    /// Carries actual destructive Storage completion coordinates.
    pub storage: DeleteRootCleanupTerminalDataV4,
}

impl DeleteRootPhysicalCompletionDataV4 {
    /// Encodes the exact complete finite physical comparison.
    ///
    /// # Errors
    /// Refuses sentinel identities or malformed canonical Session positions.
    pub fn encode_v4(
        self,
    ) -> Result<[u8; DELETE_ROOT_PHYSICAL_COMPLETION_BYTES_V4], DeleteCompletionDataErrorV4> {
        if self.challenge == [0; 16]
            || [
                self.opening,
                self.cleanup,
                self.approved_mount,
                self.approved_storage,
            ]
            .contains(&[0; 32])
        {
            return Err(DeleteCompletionDataErrorV4);
        }
        self.mount
            .require_shape_v4()
            .map_err(|_| DeleteCompletionDataErrorV4)?;
        self.storage
            .require_shape_v4()
            .map_err(|_| DeleteCompletionDataErrorV4)?;
        let mut bytes = [0; DELETE_ROOT_PHYSICAL_COMPLETION_BYTES_V4];
        bytes[..8].copy_from_slice(b"AOSDFP04");
        bytes[8..10].copy_from_slice(&4_u16.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.challenge);
        for (index, field) in [
            self.opening,
            self.cleanup,
            self.approved_mount,
            self.approved_storage,
        ]
        .iter()
        .enumerate()
        {
            bytes[32 + index * 32..64 + index * 32].copy_from_slice(field);
        }
        self.mount.write_v4(&mut bytes[160..288]);
        self.storage.write_v4(&mut bytes[288..416]);
        Ok(bytes)
    }

    /// Decodes only this exact physical comparison purpose.
    ///
    /// # Errors
    /// Refuses another width, magic/version, reserved field or proof shape.
    pub fn decode_v4(bytes: &[u8]) -> Result<Self, DeleteCompletionDataErrorV4> {
        if bytes.len() != DELETE_ROOT_PHYSICAL_COMPLETION_BYTES_V4
            || &bytes[..8] != b"AOSDFP04"
            || bytes[8..10] != 4_u16.to_be_bytes()
            || bytes[10..16] != [0; 6]
        {
            return Err(DeleteCompletionDataErrorV4);
        }
        let value = Self {
            challenge: array(bytes, 16)?,
            opening: array(bytes, 32)?,
            cleanup: array(bytes, 64)?,
            approved_mount: array(bytes, 96)?,
            approved_storage: array(bytes, 128)?,
            mount: DeleteRootCleanupTerminalDataV4::read_v4(&bytes[160..288])
                .map_err(|_| DeleteCompletionDataErrorV4)?,
            storage: DeleteRootCleanupTerminalDataV4::read_v4(&bytes[288..416])
                .map_err(|_| DeleteCompletionDataErrorV4)?,
        };
        value.encode_v4()?;
        Ok(value)
    }

    /// Commits every byte of the physical completion comparison.
    ///
    /// # Errors
    /// Refuses the same malformed fields as the canonical encoder.
    pub fn commitment_v4(self) -> Result<[u8; 32], DeleteCompletionDataErrorV4> {
        Ok(Sha256::new()
            .chain_update(b"aos.sandbox.delete.physical-completion.v4\0")
            .chain_update(self.encode_v4()?)
            .finalize()
            .into())
    }
}

/// Carries final Source and accepted Controller COMMIT comparisons without grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteRootSourceCompletionDataV4 {
    /// Identifies the actual completed physical conjunction.
    pub physical: DeleteRootPhysicalCompletionDataV4,
    /// Preserves the actual accepted Controller COMMIT, not a Session position.
    pub controller: [u8; 64],
    /// Identifies the actual terminal Source COMMIT at the held final EOF.
    pub source: [u8; 64],
}

impl DeleteRootSourceCompletionDataV4 {
    /// Commits the exact final comparison frame for passive socket acknowledgement.
    ///
    /// This digest is not a grant or proof of D disposition. The client also
    /// requires the permanent listener's explicit post-D confirmation, actual
    /// EOF, the same live authenticated Root and all own independent posts.
    ///
    /// # Errors
    /// Refuses the same malformed fields as the canonical full encoder.
    pub fn acknowledgement_digest_v4(self) -> Result<[u8; 32], DeleteCompletionDataErrorV4> {
        Ok(Sha256::new().chain_update(b"aos.sandbox.delete.source-completion-ack.v4\0")
            .chain_update(self.encode_v4()?).finalize().into())
    }

    /// Encodes the exact physical and distinct COMMIT comparisons.
    ///
    /// # Errors
    /// Refuses malformed physical fields or sentinel COMMIT coordinates.
    pub fn encode_v4(
        self,
    ) -> Result<[u8; DELETE_ROOT_SOURCE_COMPLETION_BYTES_V4], DeleteCompletionDataErrorV4> {
        require_commit_v4(&self.controller)?;
        require_commit_v4(&self.source)?;
        let mut bytes = [0; DELETE_ROOT_SOURCE_COMPLETION_BYTES_V4];
        bytes[..416].copy_from_slice(&self.physical.encode_v4()?);
        bytes[416..480].copy_from_slice(&self.controller);
        bytes[480..544].copy_from_slice(&self.source);
        Ok(bytes)
    }

    /// Decodes only the exact final physical/Source comparison extent.
    ///
    /// # Errors
    /// Refuses malformed fields, another purpose or incomplete input.
    pub fn decode_v4(bytes: &[u8]) -> Result<Self, DeleteCompletionDataErrorV4> {
        if bytes.len() != DELETE_ROOT_SOURCE_COMPLETION_BYTES_V4 {
            return Err(DeleteCompletionDataErrorV4);
        }
        let value = Self {
            physical: DeleteRootPhysicalCompletionDataV4::decode_v4(&bytes[..416])?,
            controller: array(bytes, 416)?,
            source: array(bytes, 480)?,
        };
        value.encode_v4()?;
        Ok(value)
    }
}

/// Commits a strict62 or strict7 approval under its separate finality domain.
///
/// # Errors
/// Refuses another purpose or noncanonical approval encoding.
pub fn completion_approval_commitment_data_v4(
    approval: DeleteRootPreparatoryApprovalDataV3,
    purpose: DeleteRootResourcePurposeDataV3,
) -> Result<[u8; 32], DeleteCompletionDataErrorV4> {
    let domain = match purpose {
        DeleteRootResourcePurposeDataV3::MountReap62 => {
            b"aos.sandbox.delete.completed-mount.v4\0".as_slice()
        }
        DeleteRootResourcePurposeDataV3::Apply7 => {
            b"aos.sandbox.delete.completed-storage.v4\0".as_slice()
        }
        _ => return Err(DeleteCompletionDataErrorV4),
    };
    let bytes = approval
        .encode_for_purpose_v3(purpose)
        .map_err(|_| DeleteCompletionDataErrorV4)?;
    Ok(Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into())
}

fn require_commit_v4(native: &[u8; 64]) -> Result<(), DeleteCompletionDataErrorV4> {
    let sequence = u64::from_be_bytes(array(native, 48)?);
    let end = u64::from_be_bytes(array(native, 56)?);
    if native[..16] == [0; 16]
        || native[16..48] == [0; 32]
        || sequence == 0
        || sequence == u64::MAX
        || end == 0
    {
        return Err(DeleteCompletionDataErrorV4);
    }
    Ok(())
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], DeleteCompletionDataErrorV4> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(DeleteCompletionDataErrorV4)?)
        .ok_or(DeleteCompletionDataErrorV4)?
        .try_into()
        .map_err(|_| DeleteCompletionDataErrorV4)
}

/// Reports malformed passive final-completion comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Delete final completion comparison data is malformed")]
pub struct DeleteCompletionDataErrorV4;
