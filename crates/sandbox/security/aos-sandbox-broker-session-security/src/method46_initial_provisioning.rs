//! Canonical independent approval DATA for initial METHOD46 provisioning.
//!
//! These bounded records describe the first Controller or Storage floor. They
//! neither fund a caller nor authenticate a journal, TPM observation, key pin,
//! durable write, or stopped owner. The eventual manual producer must retain
//! those originals independently. Normal runtime startup does not consume this
//! format and cannot adopt an initial intent as a successor preparation.
//!
//! Approval covers the complete canonical request, including both fixed TPM
//! handles, the salt Name, deployment profile, and generation-one checkpoint.
//! The signed intent is a separate durable format, never an existing runtime
//! checkpoint or successor intent:
//!
//! ```text
//! request: AOSBIP01 | version:1u16be | reserved:0u16be |
//!          profile:AOSBTP01:112 | salt-Name:34 |
//!          NV-index:u32be | salt-handle:u32be | checkpoint:AOSBTF01:156 (322)
//! intent:  AOSBII01 | version:1u16be | reserved:0u16be |
//!          request:322 | independent-Ed25519-signature:64               (398)
//! ```
//!
//! The credential decode owner consumes the genuine startup's separately paid
//! public readback loan. It retains the normal-owner canonical decoder result
//! and compares its role/node with that same Source. This supplies no stopped
//! owner, independent key, journal writer, physical TPM or publication authority.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::tpm_nv_custody::{FloorCheckpointV1, FloorCutV1, FloorEndpointV1, FloorProfileV1};

mod credential_decode;
pub use credential_decode::Method46InitialProvisionDecodeOriginalV1;
mod main_cut;
pub use main_cut::Method46InitialMainCutOriginalV1;

/// Fixes the complete initial provisioning request width.
pub const METHOD46_INITIAL_REQUEST_BYTES_V1: usize = 322;

/// Fixes the complete independently signed initial intent width.
pub const METHOD46_INITIAL_INTENT_BYTES_V1: usize = 398;

/// Selects one local METHOD46 provisioning purpose without granting access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method46InitialPurposeV1 {
    /// Names the Controller's Storage-client journal and NV index 0x0180a046.
    ControllerStorageClient,
    /// Names the Storage broker's journal and NV index 0x0180a047.
    StorageBroker,
}

impl Method46InitialPurposeV1 {
    fn endpoint(self) -> FloorEndpointV1 {
        match self {
            Self::ControllerStorageClient => FloorEndpointV1::ControllerStorageClient,
            Self::StorageBroker => FloorEndpointV1::StorageBroker,
        }
    }

    /// Returns the purpose's fixed local NV index as comparison DATA.
    pub const fn nv_index(self) -> u32 {
        match self {
            Self::ControllerStorageClient => 0x0180_a046,
            Self::StorageBroker => 0x0180_a047,
        }
    }

    /// Returns the purpose's independent persistent salt-key handle.
    pub const fn salt_handle(self) -> u32 {
        match self {
            Self::ControllerStorageClient => 0x8100_a046,
            Self::StorageBroker => 0x8100_a047,
        }
    }
}

/// Reports a noncanonical, unapproved, or conflicting initial provisioning claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Method46InitialDataErrorV1 {
    /// The fixed encoding, purpose, scope, or initial checkpoint is invalid.
    #[error("initial METHOD46 provisioning data is noncanonical")]
    Encoding,
    /// The signature does not verify under the independently supplied key pin.
    #[error("initial METHOD46 approval does not verify")]
    Approval,
    /// The compared retained request, main cut, or observed Written value differs.
    #[error("initial METHOD46 provisioning claims conflict")]
    Conflict,
}

/// Describes one initial floor without admitting physical or financial authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Method46InitialRequestDataV1 {
    profile: FloorProfileV1,
    salt_name: [u8; 34],
    checkpoint: FloorCheckpointV1,
}

impl Method46InitialRequestDataV1 {
    /// Constructs a canonical request from independently established cut DATA.
    ///
    /// The complete main-map head and next native sequence must come from the
    /// same held, nonempty protected journal. This function does not establish
    /// that provenance and performs no allocation or I/O.
    ///
    /// # Errors
    /// Rejects empty identity fields, a malformed SHA-256 salt Name, an empty
    /// or exhausted journal cut, or an invalid generation-one checkpoint.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aos_sandbox_broker_session_security::method46_initial_provisioning::{
    ///     Method46InitialPurposeV1, Method46InitialRequestDataV1,
    /// };
    ///
    /// // These stand-in claims must come from the actual held originals.
    /// let mut salt_name = [4; 34];
    /// salt_name[..2].copy_from_slice(&[0, 0x0b]);
    /// let request = Method46InitialRequestDataV1::new(
    ///     Method46InitialPurposeV1::StorageBroker,
    ///     [1; 16], [2; 16], [3; 32], salt_name, 4, [5; 32],
    /// )?;
    /// let bytes_for_independent_approval = request.encode();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(
        purpose: Method46InitialPurposeV1,
        node: [u8; 16],
        deployment_epoch: [u8; 16],
        stable_endpoint: [u8; 32],
        salt_name: [u8; 34],
        next_sequence: u64,
        complete_main_head: [u8; 32],
    ) -> Result<Self, Method46InitialDataErrorV1> {
        if salt_name[..2] != [0, 0x0b] || salt_name[2..] == [0; 32] || next_sequence <= 1 {
            return Err(Method46InitialDataErrorV1::Encoding);
        }

        let profile = FloorProfileV1::new(
            purpose.endpoint(),
            node,
            deployment_epoch,
            stable_endpoint,
            Sha256::digest(salt_name).into(),
        )
        .map_err(|_| Method46InitialDataErrorV1::Encoding)?;
        let cut = FloorCutV1::new(next_sequence, complete_main_head)
            .map_err(|_| Method46InitialDataErrorV1::Encoding)?;
        let checkpoint = FloorCheckpointV1::new(1, profile.scope(), cut, [0; 32], [0; 32])
            .map_err(|_| Method46InitialDataErrorV1::Encoding)?;
        Ok(Self {
            profile,
            salt_name,
            checkpoint,
        })
    }

    /// Returns the request's fixed provisioning purpose.
    pub fn purpose(self) -> Method46InitialPurposeV1 {
        match self.profile.endpoint() {
            FloorEndpointV1::ControllerStorageClient => {
                Method46InitialPurposeV1::ControllerStorageClient
            }
            FloorEndpointV1::StorageBroker => Method46InitialPurposeV1::StorageBroker,
        }
    }

    /// Encodes the exact bytes covered by independent approval.
    pub fn encode(self) -> [u8; METHOD46_INITIAL_REQUEST_BYTES_V1] {
        let mut bytes = [0; METHOD46_INITIAL_REQUEST_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSBIP01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[12..124].copy_from_slice(&self.profile.encode());
        bytes[124..158].copy_from_slice(&self.salt_name);
        bytes[158..162].copy_from_slice(&self.purpose().nv_index().to_be_bytes());
        bytes[162..166].copy_from_slice(&self.purpose().salt_handle().to_be_bytes());
        bytes[166..].copy_from_slice(&self.checkpoint.encode());
        bytes
    }

    /// Decodes only a canonical generation-one METHOD46 request.
    ///
    /// # Errors
    /// Rejects wrong framing or width, reserved bytes, another purpose's
    /// handles, a salt/profile disagreement, or any noninitial checkpoint.
    pub fn decode(bytes: &[u8]) -> Result<Self, Method46InitialDataErrorV1> {
        require_header(bytes, b"AOSBIP01", METHOD46_INITIAL_REQUEST_BYTES_V1)?;
        let profile = FloorProfileV1::decode(&bytes[12..124])
            .map_err(|_| Method46InitialDataErrorV1::Encoding)?;
        let salt_name = bytes[124..158]
            .try_into()
            .map_err(|_| Method46InitialDataErrorV1::Encoding)?;
        let checkpoint = FloorCheckpointV1::decode(&bytes[166..])
            .map_err(|_| Method46InitialDataErrorV1::Encoding)?;
        let purpose = match profile.endpoint() {
            FloorEndpointV1::ControllerStorageClient => {
                Method46InitialPurposeV1::ControllerStorageClient
            }
            FloorEndpointV1::StorageBroker => Method46InitialPurposeV1::StorageBroker,
        };
        let profile_bytes = profile.encode();
        let request = Self::new(
            purpose,
            profile.node(),
            profile_bytes[32..48]
                .try_into()
                .map_err(|_| Method46InitialDataErrorV1::Encoding)?,
            profile.stable_endpoint(),
            salt_name,
            checkpoint.cut().sequence(),
            checkpoint.cut().head(),
        )?;
        // Re-encoding checks all derived fields together, including the scope,
        // generation-one zero sentinels, salt commitment and both fixed handles.
        if request.encode() != bytes {
            return Err(Method46InitialDataErrorV1::Encoding);
        }
        Ok(request)
    }

    /// Returns the canonical generation-one checkpoint DATA.
    pub fn checkpoint(self) -> [u8; 156] {
        self.checkpoint.encode()
    }

    /// Returns the exact first encrypted Extend preimage DATA.
    pub fn extend_input(self) -> [u8; 32] {
        self.checkpoint.extend_input()
    }

    /// Returns the expected first NV value without observing hardware.
    pub fn expected_nv(self) -> [u8; 32] {
        self.checkpoint.nv_value()
    }
}

/// Retains independently verified initial approval as DATA, never a live permit.
///
/// A producer must fsync this separate intent before its first Extend, retain
/// the actual writer and financial originals, and obtain fresh authenticated
/// TPM observations before acting. Decoding this record cannot establish any
/// of those facts or authorize normal startup to initialize a floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Method46InitialIntentDataV1 {
    request: Method46InitialRequestDataV1,
    signature: [u8; 64],
}

impl Method46InitialIntentDataV1 {
    /// Verifies approval of the exact request under an independently pinned key.
    ///
    /// The caller must establish the pin's provenance and its separation from
    /// runtime endpoint, Nix and Root approval keys. No key is read or installed.
    ///
    /// # Errors
    /// Rejects a malformed or weak public key and an invalid strict signature.
    pub fn from_approval(
        request: Method46InitialRequestDataV1,
        signature: [u8; 64],
        independent_public_key: [u8; 32],
    ) -> Result<Self, Method46InitialDataErrorV1> {
        let key = VerifyingKey::from_bytes(&independent_public_key)
            .map_err(|_| Method46InitialDataErrorV1::Approval)?;
        if key.is_weak() {
            return Err(Method46InitialDataErrorV1::Approval);
        }
        key.verify_strict(&request.encode(), &Signature::from_bytes(&signature))
            .map_err(|_| Method46InitialDataErrorV1::Approval)?;
        Ok(Self { request, signature })
    }

    /// Encodes the distinct initial intent without serializing private auth.
    pub fn encode(self) -> [u8; METHOD46_INITIAL_INTENT_BYTES_V1] {
        let mut bytes = [0; METHOD46_INITIAL_INTENT_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSBII01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[12..334].copy_from_slice(&self.request.encode());
        bytes[334..].copy_from_slice(&self.signature);
        bytes
    }

    /// Decodes the fixed initial intent and reverifies independent approval.
    ///
    /// # Errors
    /// Rejects noncanonical framing or request data, an invalid key, or a
    /// signature that does not cover the entire enclosed canonical request.
    pub fn decode(
        bytes: &[u8],
        independent_public_key: [u8; 32],
    ) -> Result<Self, Method46InitialDataErrorV1> {
        require_header(bytes, b"AOSBII01", METHOD46_INITIAL_INTENT_BYTES_V1)?;
        let request = Method46InitialRequestDataV1::decode(&bytes[12..334])?;
        let signature = bytes[334..]
            .try_into()
            .map_err(|_| Method46InitialDataErrorV1::Encoding)?;
        Self::from_approval(request, signature, independent_public_key)
    }

    /// Returns the exact approved request for comparison with the held main cut.
    pub const fn request(self) -> Method46InitialRequestDataV1 {
        self.request
    }

    /// Classifies matching initial claims without granting recovery authority.
    ///
    /// The supplied request must have been freshly derived from the same held
    /// canonical writer. The observed state must come from authenticated fixed
    /// public-area/Name/value observations, under the original pinned salt key.
    /// An Unwritten result permits no inference about an ordinary runtime floor.
    /// This comparison cannot establish whether checkpoint publication already
    /// consumed the intent; the protected producer must reject that state.
    ///
    /// # Errors
    /// Rejects a different current request or a conflicting Written NV value.
    pub fn compare_recovery(
        self,
        current_request: Method46InitialRequestDataV1,
        observed: Method46InitialNvDataV1,
    ) -> Result<Method46InitialRecoveryDataV1, Method46InitialDataErrorV1> {
        if current_request != self.request {
            return Err(Method46InitialDataErrorV1::Conflict);
        }
        match observed {
            Method46InitialNvDataV1::Unwritten => Ok(Method46InitialRecoveryDataV1::ExtendInitial),
            Method46InitialNvDataV1::Written(value) if value == self.request.expected_nv() => {
                Ok(Method46InitialRecoveryDataV1::CheckpointInitial)
            }
            Method46InitialNvDataV1::Written(_) => Err(Method46InitialDataErrorV1::Conflict),
        }
    }
}

/// Describes a separately authenticated fixed-index observation as DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method46InitialNvDataV1 {
    /// Describes an exact defined SHA-256 Extend index without TPMA_NV_WRITTEN.
    Unwritten,
    /// Describes the exact authenticated value of the matching Written index.
    Written([u8; 32]),
}

/// Classifies the initial ordering without minting a physical operation permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method46InitialRecoveryDataV1 {
    /// The compared initial intent precedes the first physical Extend.
    ExtendInitial,
    /// The compared value already equals the first target; no Extend is owed.
    CheckpointInitial,
}

fn require_header(
    bytes: &[u8],
    magic: &[u8; 8],
    width: usize,
) -> Result<(), Method46InitialDataErrorV1> {
    if bytes.len() != width || &bytes[..8] != magic || bytes[8..12] != [0, 1, 0, 0] {
        return Err(Method46InitialDataErrorV1::Encoding);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
