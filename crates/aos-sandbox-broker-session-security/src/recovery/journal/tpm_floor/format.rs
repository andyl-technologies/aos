//! Fixed provisioning, checkpoint, and prepared-transition claims.
//!
//! Decoding authenticates no administrator, protected journal, or TPM. Runtime
//! callers must obtain the profile from immutable deployment provisioning and
//! match it against independently authenticated TPM public/name observations.

use super::{FloorErrorV1, hash_parts};
use aos_sandbox::JournalTransaction;

pub(super) const PROFILE_BYTES: usize = 112;
pub(super) const CHECKPOINT_BYTES: usize = 156;
pub(super) const INTENT_BYTES: usize = 12 + 2 * CHECKPOINT_BYTES;
pub(super) const NV_ATTRIBUTES_DEFINED: u32 = 0x0004_0044;
pub(super) const NV_ATTRIBUTES_WRITTEN: u32 = NV_ATTRIBUTES_DEFINED | 0x2000_0000;
const SCOPE_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.scope.v1\0";
const EXTEND_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.extend.v1\0";

/// Selects a fixed endpoint and a collision-checked local owner NV handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FloorEndpointV1 {
    ControllerStorageClient = 1,
    StorageBroker = 2,
}

impl FloorEndpointV1 {
    /// These are local owner assignments, not globally registered TCG handles.
    pub(super) const fn nv_index(self) -> u32 {
        match self {
            Self::ControllerStorageClient => 0x0180_a046,
            Self::StorageBroker => 0x0180_a047,
        }
    }
}

/// Pins one already provisioned deployment, endpoint, and TPM salt key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FloorProfileV1 {
    endpoint: FloorEndpointV1,
    node: [u8; 16],
    deployment_epoch: [u8; 16],
    stable_endpoint: [u8; 32],
    salt_key_name_digest: [u8; 32],
}

impl FloorProfileV1 {
    /// Constructs shape-only provisioning claims; it installs no NV index.
    pub(super) fn new(
        endpoint: FloorEndpointV1,
        node: [u8; 16],
        deployment_epoch: [u8; 16],
        stable_endpoint: [u8; 32],
        salt_key_name_digest: [u8; 32],
    ) -> Result<Self, FloorErrorV1> {
        if node == [0; 16]
            || deployment_epoch == [0; 16]
            || stable_endpoint == [0; 32]
            || salt_key_name_digest == [0; 32]
        {
            return Err(FloorErrorV1::Encoding);
        }
        Ok(Self {
            endpoint,
            node,
            deployment_epoch,
            stable_endpoint,
            salt_key_name_digest,
        })
    }

    pub(super) const fn endpoint(self) -> FloorEndpointV1 {
        self.endpoint
    }

    pub(super) const fn stable_endpoint(self) -> [u8; 32] {
        self.stable_endpoint
    }

    pub(super) const fn salt_key_name_digest(self) -> [u8; 32] {
        self.salt_key_name_digest
    }

    pub(super) fn encode(self) -> [u8; PROFILE_BYTES] {
        let mut bytes = [0; PROFILE_BYTES];
        header(&mut bytes, b"AOSBTP01");
        bytes[12] = self.endpoint as u8;
        bytes[16..32].copy_from_slice(&self.node);
        bytes[32..48].copy_from_slice(&self.deployment_epoch);
        bytes[48..80].copy_from_slice(&self.stable_endpoint);
        bytes[80..112].copy_from_slice(&self.salt_key_name_digest);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        require_header(bytes, b"AOSBTP01", PROFILE_BYTES)?;
        if bytes[13..16] != [0; 3] {
            return Err(FloorErrorV1::Encoding);
        }
        let endpoint = match bytes[12] {
            1 => FloorEndpointV1::ControllerStorageClient,
            2 => FloorEndpointV1::StorageBroker,
            _ => return Err(FloorErrorV1::Encoding),
        };
        Self::new(
            endpoint,
            array(bytes, 16)?,
            array(bytes, 32)?,
            array(bytes, 48)?,
            array(bytes, 80)?,
        )
    }

    pub(super) fn scope(self) -> [u8; 32] {
        hash_parts(SCOPE_DOMAIN, &[&self.encode()])
    }

    /// Computes the Name of the exact written TPMS_NV_PUBLIC, without a TPM2B prefix.
    pub(super) fn nv_name(self) -> [u8; 34] {
        let mut public = [0; 14];
        public[0..4].copy_from_slice(&self.endpoint.nv_index().to_be_bytes());
        public[4..6].copy_from_slice(&0x000b_u16.to_be_bytes());
        public[6..10].copy_from_slice(&NV_ATTRIBUTES_WRITTEN.to_be_bytes());
        // Empty authPolicy occupies two zero bytes at 10..12.
        public[12..14].copy_from_slice(&32_u16.to_be_bytes());
        let mut name = [0; 34];
        name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
        name[2..].copy_from_slice(&hash_parts(b"", &[&public]));
        name
    }
}

/// Represents a complete protected namespace-47 materialized HEAD and frame boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FloorCutV1 {
    sequence: u64,
    head: [u8; 32],
}

impl FloorCutV1 {
    pub(super) fn new(sequence: u64, head: [u8; 32]) -> Result<Self, FloorErrorV1> {
        if sequence == 0 || sequence == u64::MAX || head == [0; 32] {
            return Err(FloorErrorV1::Encoding);
        }
        Ok(Self { sequence, head })
    }

    pub(super) const fn sequence(self) -> u64 {
        self.sequence
    }

    pub(super) const fn head(self) -> [u8; 32] {
        self.head
    }
}

/// Retains the last extend preimage; a disk-stored NV digest alone is insufficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FloorCheckpointV1 {
    ordinal: u64,
    scope: [u8; 32],
    cut: FloorCutV1,
    predecessor_nv: [u8; 32],
    transaction_digest: [u8; 32],
}

impl FloorCheckpointV1 {
    /// Constructs a claim, including provisioning-only ordinal one with zero predecessor.
    pub(super) fn new(
        ordinal: u64,
        scope: [u8; 32],
        cut: FloorCutV1,
        predecessor_nv: [u8; 32],
        transaction_digest: [u8; 32],
    ) -> Result<Self, FloorErrorV1> {
        if ordinal == 0
            || ordinal == u64::MAX
            || scope == [0; 32]
            || (predecessor_nv == [0; 32]) != (ordinal == 1)
            || (transaction_digest == [0; 32]) != (ordinal == 1)
        {
            return Err(FloorErrorV1::Encoding);
        }
        Ok(Self {
            ordinal,
            scope,
            cut,
            predecessor_nv,
            transaction_digest,
        })
    }

    pub(super) const fn cut(self) -> FloorCutV1 {
        self.cut
    }

    pub(super) const fn ordinal(self) -> u64 {
        self.ordinal
    }

    pub(super) fn require_profile(self, profile: FloorProfileV1) -> Result<(), FloorErrorV1> {
        if self.scope == profile.scope() {
            Ok(())
        } else {
            Err(FloorErrorV1::Provisioning)
        }
    }

    pub(super) fn encode(self) -> [u8; CHECKPOINT_BYTES] {
        let mut bytes = [0; CHECKPOINT_BYTES];
        header(&mut bytes, b"AOSBTF01");
        bytes[12..20].copy_from_slice(&self.ordinal.to_be_bytes());
        bytes[20..52].copy_from_slice(&self.scope);
        bytes[52..60].copy_from_slice(&self.cut.sequence.to_be_bytes());
        bytes[60..92].copy_from_slice(&self.cut.head);
        bytes[92..124].copy_from_slice(&self.predecessor_nv);
        bytes[124..156].copy_from_slice(&self.transaction_digest);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        require_header(bytes, b"AOSBTF01", CHECKPOINT_BYTES)?;
        Self::new(
            u64::from_be_bytes(array(bytes, 12)?),
            array(bytes, 20)?,
            FloorCutV1::new(u64::from_be_bytes(array(bytes, 52)?), array(bytes, 60)?)?,
            array(bytes, 92)?,
            array(bytes, 124)?,
        )
    }

    /// The TPM receives this fixed-size domain-separated digest as `data.buffer`.
    pub(super) fn extend_input(self) -> [u8; 32] {
        hash_parts(EXTEND_DOMAIN, &[&self.encode()])
    }

    /// Matches TPM_NT_EXTEND: SHA256(previous NV || supplied extension bytes).
    pub(super) fn nv_value(self) -> [u8; 32] {
        hash_parts(b"", &[&self.predecessor_nv, &self.extend_input()])
    }
}

/// Claims one exact prepared successor without proving durable preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FloorIntentV1 {
    predecessor: FloorCheckpointV1,
    target: FloorCheckpointV1,
}

impl FloorIntentV1 {
    pub(super) fn new(
        profile: FloorProfileV1,
        predecessor: FloorCheckpointV1,
        target_cut: FloorCutV1,
        transaction: &JournalTransaction,
    ) -> Result<Self, FloorErrorV1> {
        if successor_sequence(predecessor.cut.sequence, transaction)? != target_cut.sequence {
            return Err(FloorErrorV1::Successor);
        }
        Self::from_digest(
            profile,
            predecessor,
            target_cut,
            super::head::transaction_digest_v1(transaction)?,
        )
    }

    fn from_digest(
        profile: FloorProfileV1,
        predecessor: FloorCheckpointV1,
        target_cut: FloorCutV1,
        transaction_digest: [u8; 32],
    ) -> Result<Self, FloorErrorV1> {
        predecessor.require_profile(profile)?;
        if target_cut.sequence <= predecessor.cut.sequence || transaction_digest == [0; 32] {
            return Err(FloorErrorV1::Successor);
        }
        let ordinal = predecessor
            .ordinal
            .checked_add(1)
            .ok_or(FloorErrorV1::Successor)?;
        let target = FloorCheckpointV1::new(
            ordinal,
            profile.scope(),
            target_cut,
            predecessor.nv_value(),
            transaction_digest,
        )?;
        Ok(Self {
            predecessor,
            target,
        })
    }

    pub(super) const fn target(self) -> FloorCheckpointV1 {
        self.target
    }

    pub(super) const fn predecessor(self) -> FloorCheckpointV1 {
        self.predecessor
    }

    pub(super) const fn transaction_digest(self) -> [u8; 32] {
        self.target.transaction_digest
    }

    pub(super) fn require_transaction(
        self,
        transaction: &JournalTransaction,
    ) -> Result<(), FloorErrorV1> {
        if successor_sequence(self.predecessor.cut.sequence, transaction)?
            != self.target.cut.sequence
            || super::head::transaction_digest_v1(transaction)? != self.target.transaction_digest
        {
            return Err(FloorErrorV1::Successor);
        }
        Ok(())
    }

    pub(super) fn require_predecessor(
        self,
        profile: FloorProfileV1,
        predecessor: FloorCheckpointV1,
    ) -> Result<(), FloorErrorV1> {
        let expected = Self::from_digest(
            profile,
            predecessor,
            self.target.cut,
            self.target.transaction_digest,
        )?;
        if expected == self {
            Ok(())
        } else {
            Err(FloorErrorV1::Successor)
        }
    }

    pub(super) fn encode(self) -> [u8; INTENT_BYTES] {
        let mut bytes = [0; INTENT_BYTES];
        header(&mut bytes, b"AOSBTI01");
        bytes[12..168].copy_from_slice(&self.predecessor.encode());
        bytes[168..324].copy_from_slice(&self.target.encode());
        bytes
    }

    pub(super) fn decode(profile: FloorProfileV1, bytes: &[u8]) -> Result<Self, FloorErrorV1> {
        require_header(bytes, b"AOSBTI01", INTENT_BYTES)?;
        let intent = Self {
            predecessor: FloorCheckpointV1::decode(&bytes[12..168])?,
            target: FloorCheckpointV1::decode(&bytes[168..324])?,
        };
        intent.require_predecessor(profile, intent.predecessor)?;
        Ok(intent)
    }
}

fn header(bytes: &mut [u8], magic: &[u8; 8]) {
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
}

fn require_header(bytes: &[u8], magic: &[u8; 8], length: usize) -> Result<(), FloorErrorV1> {
    if bytes.len() != length
        || &bytes[..8] != magic
        || bytes[8..10] != [0, 1]
        || bytes[10..12] != [0; 2]
    {
        return Err(FloorErrorV1::Encoding);
    }
    Ok(())
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], FloorErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(FloorErrorV1::Encoding)
}

pub(super) fn successor_sequence(
    sequence: u64,
    transaction: &JournalTransaction,
) -> Result<u64, FloorErrorV1> {
    let frames = u64::try_from(transaction.records().len())
        .ok()
        .and_then(|records| records.checked_add(2))
        .ok_or(FloorErrorV1::Successor)?;
    sequence
        .checked_add(frames)
        .filter(|next| *next != u64::MAX)
        .ok_or(FloorErrorV1::Successor)
}
