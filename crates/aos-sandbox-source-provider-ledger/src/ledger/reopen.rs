//! Pure canonical stable backend reopen identity.
//!
//! ```text
//! AOSSPR01 | version:u16be | class:u8 | flags:u8=0 | reserved:u32be=0 |
//! backend_id[32] | backend_generation:u64be | backend_digest[32] |
//! resource_id[32] | resource_generation:u64be | resource_digest[32] |
//! authority_object_id[32] | authority_generation:u64be |
//! authority_digest[32] | reserved[24]=0
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::SourceProviderProofV1;

use super::evidence::BackendEvidenceClassV1;

const MAGIC: &[u8; 8] = b"AOSSPR01";
const VERSION: u16 = 1;
const BYTES: usize = 256;
const PAYLOAD_BYTES: usize = 240;

const _: () = assert!(8 + 2 + 1 + 1 + 4 + PAYLOAD_BYTES == BYTES);
const _: () = assert!(32 + 8 + 32 + 32 + 8 + 32 + 32 + 8 + 32 + 24 == PAYLOAD_BYTES);

/// Retains only stable, class-specific facts needed to reopen a source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReopenIdentityV1 {
    class: BackendEvidenceClassV1,
    backend_id: [u8; 32],
    backend_generation: u64,
    backend_digest: ObjectDigest,
    resource_id: [u8; 32],
    resource_generation: u64,
    resource_digest: ObjectDigest,
    authority_object_id: [u8; 32],
    authority_generation: u64,
    authority_digest: ObjectDigest,
}

impl ReopenIdentityV1 {
    /// Constructs a stable, nonauthorizing backend reopen identity.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for any sentinel identity,
    /// generation, or digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class: BackendEvidenceClassV1,
        backend_id: [u8; 32],
        backend_generation: u64,
        backend_digest: ObjectDigest,
        resource_id: [u8; 32],
        resource_generation: u64,
        resource_digest: ObjectDigest,
        authority_object_id: [u8; 32],
        authority_generation: u64,
        authority_digest: ObjectDigest,
    ) -> Result<Self, super::LedgerFormatErrorV1> {
        if backend_id == [0; 32]
            || backend_generation == 0
            || backend_digest.as_bytes() == &[0; 32]
            || resource_id == [0; 32]
            || resource_generation == 0
            || resource_digest.as_bytes() == &[0; 32]
            || authority_object_id == [0; 32]
            || authority_generation == 0
            || authority_digest.as_bytes() == &[0; 32]
        {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "invalid reopen identity fields",
            ));
        }
        Ok(Self {
            class,
            backend_id,
            backend_generation,
            backend_digest,
            resource_id,
            resource_generation,
            resource_digest,
            authority_object_id,
            authority_generation,
            authority_digest,
        })
    }

    /// Returns the closed backend class.
    #[must_use]
    pub const fn class(&self) -> BackendEvidenceClassV1 {
        self.class
    }

    /// Returns the stable backend identity.
    #[must_use]
    pub const fn backend_id(&self) -> [u8; 32] {
        self.backend_id
    }

    /// Returns the retained backend generation.
    #[must_use]
    pub const fn backend_generation(&self) -> u64 {
        self.backend_generation
    }

    /// Returns the retained backend authority-state digest.
    #[must_use]
    pub const fn backend_digest(&self) -> ObjectDigest {
        self.backend_digest
    }

    /// Returns the stable selected resource identity.
    #[must_use]
    pub const fn resource_id(&self) -> [u8; 32] {
        self.resource_id
    }

    /// Returns the retained resource generation.
    #[must_use]
    pub const fn resource_generation(&self) -> u64 {
        self.resource_generation
    }

    /// Returns the retained resource digest.
    #[must_use]
    pub const fn resource_digest(&self) -> ObjectDigest {
        self.resource_digest
    }

    /// Returns the class-specific authority-object identity.
    #[must_use]
    pub const fn authority_object_id(&self) -> [u8; 32] {
        self.authority_object_id
    }

    /// Returns the class-specific authority-object generation.
    #[must_use]
    pub const fn authority_generation(&self) -> u64 {
        self.authority_generation
    }

    /// Returns the class-specific authority-object digest.
    #[must_use]
    pub const fn authority_digest(&self) -> ObjectDigest {
        self.authority_digest
    }

    /// Reports whether every retained authority-object fact matches a proof.
    #[must_use]
    pub fn matches_proof(&self, proof: &SourceProviderProofV1) -> bool {
        match proof {
            SourceProviderProofV1::ZfsHeldSnapshot { proof, .. } => {
                self.class == BackendEvidenceClassV1::ZfsHeldSnapshot
                    && self.authority_object_id == proof.storage_handle()
                    && self.authority_generation == proof.storage_version()
                    && self.authority_digest == proof.active_hold_digest()
            }
            SourceProviderProofV1::LocalLiveExport { proof, .. } => {
                self.class == BackendEvidenceClassV1::LocalLiveExport
                    && self.authority_object_id == proof.workspace_id()
                    && self.authority_generation == proof.export_generation()
                    && self.authority_digest == proof.workspace_digest()
            }
            SourceProviderProofV1::ImmutablePublisherTree { proof, .. } => {
                self.class == BackendEvidenceClassV1::ImmutablePublisherTree
                    && self.authority_object_id == proof.cache_id()
                    && self.authority_generation == proof.cache_generation()
                    && self.authority_digest == proof.cache_digest()
            }
            SourceProviderProofV1::BestEffortReplica { proof, .. } => {
                self.class == BackendEvidenceClassV1::BestEffortReplica
                    && self.authority_object_id == proof.replica_id()
                    && self.authority_generation == proof.replica_generation()
                    && self.authority_digest == proof.replica_digest()
            }
        }
    }

    /// Encodes this identity in its fixed canonical AOSSPR01 representation.
    #[must_use]
    pub fn encode(&self) -> [u8; BYTES] {
        let mut bytes = [0_u8; BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10] = self.class as u8;
        bytes[16..48].copy_from_slice(&self.backend_id);
        bytes[48..56].copy_from_slice(&self.backend_generation.to_be_bytes());
        bytes[56..88].copy_from_slice(self.backend_digest.as_bytes());
        bytes[88..120].copy_from_slice(&self.resource_id);
        bytes[120..128].copy_from_slice(&self.resource_generation.to_be_bytes());
        bytes[128..160].copy_from_slice(self.resource_digest.as_bytes());
        bytes[160..192].copy_from_slice(&self.authority_object_id);
        bytes[192..200].copy_from_slice(&self.authority_generation.to_be_bytes());
        bytes[200..232].copy_from_slice(self.authority_digest.as_bytes());
        bytes
    }

    /// Decodes and re-encodes one hostile AOSSPR01 representation.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for malformed, sentinel-bearing,
    /// or noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, super::LedgerFormatErrorV1> {
        if bytes.len() != BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || bytes.get(11..16) != Some([0_u8; 5].as_slice())
            || bytes.get(232..256) != Some([0_u8; 24].as_slice())
        {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "reopen identity header or padding",
            ));
        }
        let class = match bytes[10] {
            1 => BackendEvidenceClassV1::ZfsHeldSnapshot,
            2 => BackendEvidenceClassV1::LocalLiveExport,
            3 => BackendEvidenceClassV1::ImmutablePublisherTree,
            4 => BackendEvidenceClassV1::BestEffortReplica,
            _ => {
                return Err(super::LedgerFormatErrorV1::Corrupt("reopen identity class"));
            }
        };
        let value = Self::new(
            class,
            read_array(bytes, 16)?,
            read_u64(bytes, 48)?,
            ObjectDigest::from_bytes(read_array(bytes, 56)?),
            read_array(bytes, 88)?,
            read_u64(bytes, 120)?,
            ObjectDigest::from_bytes(read_array(bytes, 128)?),
            read_array(bytes, 160)?,
            read_u64(bytes, 192)?,
            ObjectDigest::from_bytes(read_array(bytes, 200)?),
        )?;
        if value.encode().as_slice() != bytes {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "noncanonical reopen identity",
            ));
        }
        Ok(value)
    }
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], super::LedgerFormatErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(super::LedgerFormatErrorV1::Corrupt(
            "truncated reopen identity",
        ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, super::LedgerFormatErrorV1> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}
