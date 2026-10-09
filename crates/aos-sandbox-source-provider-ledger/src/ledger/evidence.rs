//! Pure canonical persistent backend observation evidence.
//!
//! ```text
//! AOSSPE01 | version:u16be | class:u8 | state:u8 | reserved:u32be |
//! payload_len:u32be | backend_authority_id[16] |
//! backend_generation:u64be | backend_digest[32] |
//! observation_generation:u64be | observation_digest[32] | reserved[4] | payload
//!
//! Every class payload begins with its eight-byte class magic, class version,
//! two reserved zero bytes, predecessor observation generation, and
//! predecessor observation digest. This makes the opaque suffix a closed,
//! independently versioned canonical union rather than substitutable bytes.
//! LocalLive v2 (`AOSPLOC2`, version `2`) adds proof-digest[32],
//! export-lease-digest[32], kernel-grant-digest[32], and
//! descriptor-commitment[32]. The former empty-suffix LocalLive v1 is rejected
//! rather than interpreted as evidence for a physical export.
//! ```

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{SourceProviderProofV1, digest_provider_proof};

use crate::limits::MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES;

const MAGIC: &[u8; 8] = b"AOSSPE01";
const VERSION: u16 = 1;
const FIXED_BYTES: usize = 120;

const CLASS_PAYLOAD_PREFIX_BYTES: usize = 52;
const LOCAL_LIVE_BINDING_BYTES: usize = 128;

const _: () = assert!(8 + 2 + 1 + 1 + 4 + 4 + 16 + 8 + 32 + 8 + 32 + 4 == FIXED_BYTES);
const _: () = assert!(8 + 2 + 2 + 8 + 32 == CLASS_PAYLOAD_PREFIX_BYTES);

/// Identifies the closed root authority class of persistent backend evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BackendEvidenceClassV1 {
    /// A held ZFS snapshot supplies the source.
    ZfsHeldSnapshot = 1,
    /// A kernel-coupled live export supplies the source.
    LocalLiveExport = 2,
    /// An immutable publisher tree with fs-verity supplies the source.
    ImmutablePublisherTree = 3,
    /// A reconstructible best-effort replica supplies the source.
    BestEffortReplica = 4,
}

impl BackendEvidenceClassV1 {
    fn decode(value: u8) -> Result<Self, super::LedgerFormatErrorV1> {
        match value {
            1 => Ok(Self::ZfsHeldSnapshot),
            2 => Ok(Self::LocalLiveExport),
            3 => Ok(Self::ImmutablePublisherTree),
            4 => Ok(Self::BestEffortReplica),
            _ => Err(super::LedgerFormatErrorV1::Corrupt(
                "unknown backend evidence class",
            )),
        }
    }
}

/// Distinguishes persistent acquisition and release observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BackendEvidenceStateV1 {
    /// The exact backend acquisition is durably present.
    Acquired = 1,
    /// The exact backend acquisition is durably absent after release.
    Released = 2,
}

/// Retains the exact LocalLive proof and physical-root commitments.
///
/// The Storage export lease and independent kernel grant are separate fields
/// so a later readback cannot substitute one for the other. These bytes are
/// nonauthorizing; the fixed owner still requires both protected signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalLiveEvidenceBindingV1 {
    proof_digest: ObjectDigest,
    export_lease_digest: ObjectDigest,
    kernel_grant_digest: ObjectDigest,
    descriptor_commitment: ObjectDigest,
}

impl LocalLiveEvidenceBindingV1 {
    /// Binds one validated LocalLive proof to a kernel-observed source root.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for a different proof class or
    /// a sentinel descriptor commitment.
    pub fn from_proof(
        proof: &SourceProviderProofV1,
        descriptor_commitment: ObjectDigest,
    ) -> Result<Self, super::LedgerFormatErrorV1> {
        let SourceProviderProofV1::LocalLiveExport { proof: export, .. } = proof else {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "LocalLive evidence proof class",
            ));
        };
        let binding = Self {
            proof_digest: digest_provider_proof(proof),
            export_lease_digest: export.export_lease_digest(),
            kernel_grant_digest: export.kernel_grant_digest(),
            descriptor_commitment,
        };
        if binding.fields_are_valid() {
            Ok(binding)
        } else {
            Err(super::LedgerFormatErrorV1::Corrupt(
                "LocalLive evidence binding",
            ))
        }
    }

    /// Returns the canonical class-specific payload suffix.
    #[must_use]
    pub fn encode(self) -> [u8; LOCAL_LIVE_BINDING_BYTES] {
        let mut bytes = [0; LOCAL_LIVE_BINDING_BYTES];
        bytes[..32].copy_from_slice(self.proof_digest.as_bytes());
        bytes[32..64].copy_from_slice(self.export_lease_digest.as_bytes());
        bytes[64..96].copy_from_slice(self.kernel_grant_digest.as_bytes());
        bytes[96..128].copy_from_slice(self.descriptor_commitment.as_bytes());
        bytes
    }

    /// Decodes an exact, non-sentinel LocalLive binding.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for an incorrect length or a
    /// sentinel commitment.
    pub fn decode(bytes: &[u8]) -> Result<Self, super::LedgerFormatErrorV1> {
        if bytes.len() != LOCAL_LIVE_BINDING_BYTES {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "LocalLive evidence binding length",
            ));
        }
        let binding = Self {
            proof_digest: ObjectDigest::from_bytes(read_array(bytes, 0)?),
            export_lease_digest: ObjectDigest::from_bytes(read_array(bytes, 32)?),
            kernel_grant_digest: ObjectDigest::from_bytes(read_array(bytes, 64)?),
            descriptor_commitment: ObjectDigest::from_bytes(read_array(bytes, 96)?),
        };
        if binding.fields_are_valid() {
            Ok(binding)
        } else {
            Err(super::LedgerFormatErrorV1::Corrupt(
                "LocalLive evidence binding",
            ))
        }
    }

    /// Checks the retained proof and current kernel-observed descriptor.
    #[must_use]
    pub fn matches(self, proof: &SourceProviderProofV1, descriptor: ObjectDigest) -> bool {
        Self::from_proof(proof, descriptor).is_ok_and(|current| current == self)
    }

    /// Checks the current descriptor against the retained physical identity.
    #[must_use]
    pub fn matches_descriptor(self, descriptor: ObjectDigest) -> bool {
        self.descriptor_commitment == descriptor
    }

    fn fields_are_valid(self) -> bool {
        self.proof_digest.as_bytes() != &[0; 32]
            && self.export_lease_digest.as_bytes() != &[0; 32]
            && self.kernel_grant_digest.as_bytes() != &[0; 32]
            && self.descriptor_commitment.as_bytes() != &[0; 32]
    }
}

impl BackendEvidenceStateV1 {
    fn decode(value: u8) -> Result<Self, super::LedgerFormatErrorV1> {
        match value {
            1 => Ok(Self::Acquired),
            2 => Ok(Self::Released),
            _ => Err(super::LedgerFormatErrorV1::Corrupt(
                "unknown backend evidence state",
            )),
        }
    }
}

/// Retains bounded durable backend evidence without a live handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendEvidenceV1 {
    class: BackendEvidenceClassV1,
    state: BackendEvidenceStateV1,
    backend_authority_id: [u8; 16],
    backend_generation: u64,
    backend_digest: ObjectDigest,
    observation_generation: u64,
    observation_digest: ObjectDigest,
    payload: Vec<u8>,
}

impl BackendEvidenceV1 {
    /// Constructs one acquired observation from class-specific canonical bytes.
    ///
    /// LocalLive v2 requires an exact [`LocalLiveEvidenceBindingV1`] suffix.
    /// Other classes remain dormant with a closed empty v1 suffix. The helper
    /// supplies the class tag and zero predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for sentinel identities, an
    /// oversized suffix, or a noncanonical resulting observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new_acquired(
        class: BackendEvidenceClassV1,
        backend_authority_id: [u8; 16],
        backend_generation: u64,
        backend_digest: ObjectDigest,
        observation_generation: u64,
        observation_digest: ObjectDigest,
        class_payload_suffix: Vec<u8>,
    ) -> Result<Self, super::LedgerFormatErrorV1> {
        let payload = class_payload(
            class,
            0,
            ObjectDigest::from_bytes([0; 32]),
            class_payload_suffix,
        )?;
        Self::new(
            class,
            BackendEvidenceStateV1::Acquired,
            backend_authority_id,
            backend_generation,
            backend_digest,
            observation_generation,
            observation_digest,
            payload,
        )
    }

    /// Constructs one released observation linked to its acquired predecessor.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for sentinel identities, an
    /// invalid predecessor, an oversized suffix, or a noncanonical result.
    #[allow(clippy::too_many_arguments)]
    pub fn new_released(
        class: BackendEvidenceClassV1,
        backend_authority_id: [u8; 16],
        backend_generation: u64,
        backend_digest: ObjectDigest,
        observation_generation: u64,
        observation_digest: ObjectDigest,
        predecessor_observation_generation: u64,
        predecessor_observation_digest: ObjectDigest,
        class_payload_suffix: Vec<u8>,
    ) -> Result<Self, super::LedgerFormatErrorV1> {
        let payload = class_payload(
            class,
            predecessor_observation_generation,
            predecessor_observation_digest,
            class_payload_suffix,
        )?;
        Self::new(
            class,
            BackendEvidenceStateV1::Released,
            backend_authority_id,
            backend_generation,
            backend_digest,
            observation_generation,
            observation_digest,
            payload,
        )
    }

    /// Constructs bounded canonical persistent backend evidence.
    ///
    /// This value is nonauthorizing data. Runtime completion still requires a
    /// move-only durable effect permit and exact current-journal validation.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for sentinel identities,
    /// malformed class payloads, invalid predecessor shape, or size overflow.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class: BackendEvidenceClassV1,
        state: BackendEvidenceStateV1,
        backend_authority_id: [u8; 16],
        backend_generation: u64,
        backend_digest: ObjectDigest,
        observation_generation: u64,
        observation_digest: ObjectDigest,
        payload: Vec<u8>,
    ) -> Result<Self, super::LedgerFormatErrorV1> {
        let evidence = Self {
            class,
            state,
            backend_authority_id,
            backend_generation,
            backend_digest,
            observation_generation,
            observation_digest,
            payload,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Returns the closed backend authority class.
    #[must_use]
    pub const fn class(&self) -> BackendEvidenceClassV1 {
        self.class
    }

    /// Returns the persistent observation state.
    #[must_use]
    pub const fn state(&self) -> BackendEvidenceStateV1 {
        self.state
    }

    /// Returns the stable backend authority ID.
    #[must_use]
    pub const fn backend_authority_id(&self) -> [u8; 16] {
        self.backend_authority_id
    }

    /// Returns the backend authority generation.
    #[must_use]
    pub const fn backend_generation(&self) -> u64 {
        self.backend_generation
    }

    /// Returns the backend authority-state digest.
    #[must_use]
    pub const fn backend_digest(&self) -> ObjectDigest {
        self.backend_digest
    }

    /// Returns the monotonic observation generation.
    #[must_use]
    pub const fn observation_generation(&self) -> u64 {
        self.observation_generation
    }

    /// Returns the exact observation commitment.
    #[must_use]
    pub const fn observation_digest(&self) -> ObjectDigest {
        self.observation_digest
    }

    /// Borrows the class-specific persistent payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Decodes the retained LocalLive proof and descriptor binding.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for a different class or a
    /// malformed class-specific payload.
    pub fn local_live_binding(
        &self,
    ) -> Result<LocalLiveEvidenceBindingV1, super::LedgerFormatErrorV1> {
        if self.class != BackendEvidenceClassV1::LocalLiveExport {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "LocalLive evidence class",
            ));
        }
        let suffix = self.payload.get(CLASS_PAYLOAD_PREFIX_BYTES..).ok_or(
            super::LedgerFormatErrorV1::Corrupt("LocalLive evidence payload"),
        )?;
        LocalLiveEvidenceBindingV1::decode(suffix)
    }

    /// Returns the predecessor observation generation committed by the payload.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] if invariant-protected canonical
    /// payload bytes are unexpectedly truncated.
    pub fn predecessor_observation_generation(&self) -> Result<u64, super::LedgerFormatErrorV1> {
        read_u64(&self.payload, 12)
    }

    /// Returns the predecessor observation digest committed by the payload.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] if invariant-protected canonical
    /// payload bytes are unexpectedly truncated.
    pub fn predecessor_observation_digest(
        &self,
    ) -> Result<ObjectDigest, super::LedgerFormatErrorV1> {
        Ok(ObjectDigest::from_bytes(read_array(&self.payload, 20)?))
    }

    /// Encodes this evidence in the canonical AOSSPE01 representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FIXED_BYTES + self.payload.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(self.class as u8);
        bytes.push(self.state as u8);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.backend_authority_id);
        bytes.extend_from_slice(&self.backend_generation.to_be_bytes());
        bytes.extend_from_slice(self.backend_digest.as_bytes());
        bytes.extend_from_slice(&self.observation_generation.to_be_bytes());
        bytes.extend_from_slice(self.observation_digest.as_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Decodes and re-encodes one hostile AOSSPE01 representation.
    ///
    /// # Errors
    ///
    /// Returns [`super::LedgerFormatErrorV1`] for any malformed, oversized,
    /// sentinel-bearing, or noncanonical representation.
    pub fn decode(bytes: &[u8]) -> Result<Self, super::LedgerFormatErrorV1> {
        if bytes.len() < FIXED_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || bytes.get(12..16) != Some([0_u8; 4].as_slice())
            || bytes.get(116..120) != Some([0_u8; 4].as_slice())
        {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "backend evidence header",
            ));
        }
        let payload_len = read_u32(bytes, 16)? as usize;
        if payload_len > MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES
            || FIXED_BYTES.checked_add(payload_len) != Some(bytes.len())
        {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "backend evidence length",
            ));
        }
        let value = Self::new(
            BackendEvidenceClassV1::decode(bytes[10])?,
            BackendEvidenceStateV1::decode(bytes[11])?,
            read_array(bytes, 20)?,
            read_u64(bytes, 36)?,
            ObjectDigest::from_bytes(read_array(bytes, 44)?),
            read_u64(bytes, 76)?,
            ObjectDigest::from_bytes(read_array(bytes, 84)?),
            bytes[FIXED_BYTES..].to_vec(),
        )?;
        if value.encode() != bytes {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "noncanonical backend evidence",
            ));
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), super::LedgerFormatErrorV1> {
        if self.backend_authority_id == [0; 16]
            || self.backend_generation == 0
            || self.backend_digest.as_bytes() == &[0; 32]
            || self.observation_generation == 0
            || self.observation_digest.as_bytes() == &[0; 32]
            || self.payload.len() > MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES
            || !self.payload_is_canonical()
        {
            return Err(super::LedgerFormatErrorV1::Corrupt(
                "invalid backend evidence",
            ));
        }
        Ok(())
    }

    fn payload_is_canonical(&self) -> bool {
        let expected_suffix_len = match self.class {
            BackendEvidenceClassV1::LocalLiveExport => LOCAL_LIVE_BINDING_BYTES,
            _ => 0,
        };
        if self.payload.len() != CLASS_PAYLOAD_PREFIX_BYTES + expected_suffix_len
            || self.payload.get(..8) != Some(self.class.payload_magic().as_slice())
            || self.payload.get(8..10)
                != Some(self.class.payload_version().to_be_bytes().as_slice())
            || self.payload.get(10..12) != Some([0_u8; 2].as_slice())
            || (self.class == BackendEvidenceClassV1::LocalLiveExport
                && LocalLiveEvidenceBindingV1::decode(&self.payload[CLASS_PAYLOAD_PREFIX_BYTES..])
                    .is_err())
        {
            return false;
        }
        let predecessor_generation = read_u64(&self.payload, 12).ok();
        let predecessor_digest = read_array::<32>(&self.payload, 20).ok();
        match (self.state, predecessor_generation, predecessor_digest) {
            (BackendEvidenceStateV1::Acquired, Some(0), Some(digest)) => digest == [0; 32],
            (BackendEvidenceStateV1::Released, Some(generation), Some(digest)) => {
                generation > 0 && generation < self.observation_generation && digest != [0; 32]
            }
            _ => false,
        }
    }
}

impl BackendEvidenceClassV1 {
    const fn payload_magic(self) -> [u8; 8] {
        match self {
            Self::ZfsHeldSnapshot => *b"AOSPZFS1",
            Self::LocalLiveExport => *b"AOSPLOC2",
            Self::ImmutablePublisherTree => *b"AOSPIMM1",
            Self::BestEffortReplica => *b"AOSPREP1",
        }
    }

    const fn payload_version(self) -> u16 {
        match self {
            Self::LocalLiveExport => 2,
            _ => 1,
        }
    }
}

fn class_payload(
    class: BackendEvidenceClassV1,
    predecessor_generation: u64,
    predecessor_digest: ObjectDigest,
    suffix: Vec<u8>,
) -> Result<Vec<u8>, super::LedgerFormatErrorV1> {
    let suffix_is_valid = match class {
        BackendEvidenceClassV1::LocalLiveExport => {
            LocalLiveEvidenceBindingV1::decode(&suffix).is_ok()
        }
        _ => suffix.is_empty(),
    };
    if !suffix_is_valid {
        return Err(super::LedgerFormatErrorV1::Corrupt(
            "backend class payload suffix",
        ));
    }
    let capacity = CLASS_PAYLOAD_PREFIX_BYTES.checked_add(suffix.len()).ok_or(
        super::LedgerFormatErrorV1::LimitExceeded("backend evidence payload"),
    )?;
    if capacity > MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES {
        return Err(super::LedgerFormatErrorV1::LimitExceeded(
            "backend evidence payload",
        ));
    }
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(&class.payload_magic());
    payload.extend_from_slice(&class.payload_version().to_be_bytes());
    payload.extend_from_slice(&[0; 2]);
    payload.extend_from_slice(&predecessor_generation.to_be_bytes());
    payload.extend_from_slice(predecessor_digest.as_bytes());
    payload.extend_from_slice(&suffix);
    Ok(payload)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], super::LedgerFormatErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(super::LedgerFormatErrorV1::Corrupt(
            "truncated backend evidence",
        ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, super::LedgerFormatErrorV1> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, super::LedgerFormatErrorV1> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use aos_sandbox_source_provider_protocol::{
        LocalLiveExportProofV1, RecursiveTopologyProofV1, SourceProviderProofV1,
    };

    use super::{
        BackendEvidenceClassV1, BackendEvidenceV1, LocalLiveEvidenceBindingV1, ObjectDigest,
    };

    fn digest(value: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([value; 32])
    }

    fn local_live_proof(grant: u8) -> SourceProviderProofV1 {
        SourceProviderProofV1::LocalLiveExport {
            proof: LocalLiveExportProofV1::new(
                digest(1),
                [2; 16],
                [3; 16],
                [4; 16],
                5,
                digest(6),
                digest(7),
                [8; 16],
                9,
                digest(grant),
                [10; 32],
                digest(11),
            )
            .unwrap(),
            topology: RecursiveTopologyProofV1::new([12; 16], 13, digest(14), 1, 0, 1, 0).unwrap(),
        }
    }

    #[test]
    fn local_live_evidence_requires_exact_proof_and_descriptor() {
        let proof = local_live_proof(15);
        let binding = LocalLiveEvidenceBindingV1::from_proof(&proof, digest(16)).unwrap();
        assert_eq!(
            LocalLiveEvidenceBindingV1::decode(&binding.encode()),
            Ok(binding)
        );
        assert!(binding.matches(&proof, digest(16)));
        assert!(!binding.matches(&local_live_proof(17), digest(16)));
        assert!(!binding.matches_descriptor(digest(18)));

        let acquired = BackendEvidenceV1::new_acquired(
            BackendEvidenceClassV1::LocalLiveExport,
            [19; 16],
            20,
            digest(21),
            22,
            digest(23),
            binding.encode().to_vec(),
        )
        .unwrap();
        assert_eq!(acquired.local_live_binding(), Ok(binding));
        let acquired_bytes = acquired.encode();
        assert_eq!(&acquired_bytes[120..128], b"AOSPLOC2");
        assert_eq!(&acquired_bytes[128..130], &2_u16.to_be_bytes());
        assert_eq!(
            BackendEvidenceV1::decode(&acquired_bytes),
            Ok(acquired.clone())
        );

        let released = BackendEvidenceV1::new_released(
            BackendEvidenceClassV1::LocalLiveExport,
            [19; 16],
            20,
            digest(21),
            24,
            digest(25),
            acquired.observation_generation(),
            acquired.observation_digest(),
            binding.encode().to_vec(),
        )
        .unwrap();
        assert_eq!(released.local_live_binding(), Ok(binding));
        assert_eq!(BackendEvidenceV1::decode(&released.encode()), Ok(released));
    }

    #[test]
    fn local_live_evidence_rejects_missing_or_corrupt_binding() {
        let proof = local_live_proof(15);
        let binding = LocalLiveEvidenceBindingV1::from_proof(&proof, digest(16)).unwrap();
        assert!(
            BackendEvidenceV1::new_acquired(
                BackendEvidenceClassV1::LocalLiveExport,
                [19; 16],
                20,
                digest(21),
                22,
                digest(23),
                Vec::new(),
            )
            .is_err()
        );

        for offset in [0, 32, 64, 96] {
            let mut suffix = binding.encode();
            suffix[offset..offset + 32].fill(0);
            assert!(
                BackendEvidenceV1::new_acquired(
                    BackendEvidenceClassV1::LocalLiveExport,
                    [19; 16],
                    20,
                    digest(21),
                    22,
                    digest(23),
                    suffix.to_vec(),
                )
                .is_err()
            );
        }

        let mut evidence = BackendEvidenceV1::new_acquired(
            BackendEvidenceClassV1::LocalLiveExport,
            [19; 16],
            20,
            digest(21),
            22,
            digest(23),
            binding.encode().to_vec(),
        )
        .unwrap()
        .encode();
        evidence[120 + 52 + 96..120 + 52 + 128].fill(0);
        assert!(BackendEvidenceV1::decode(&evidence).is_err());
    }

    #[test]
    fn historical_empty_local_live_v1_is_rejected() {
        let proof = local_live_proof(15);
        let binding = LocalLiveEvidenceBindingV1::from_proof(&proof, digest(16)).unwrap();
        let mut historical = BackendEvidenceV1::new_acquired(
            BackendEvidenceClassV1::LocalLiveExport,
            [19; 16],
            20,
            digest(21),
            22,
            digest(23),
            binding.encode().to_vec(),
        )
        .unwrap()
        .encode();

        historical[120..128].copy_from_slice(b"AOSPLOC1");
        historical[128..130].copy_from_slice(&1_u16.to_be_bytes());
        assert!(BackendEvidenceV1::decode(&historical).is_err());

        historical[16..20].copy_from_slice(&52_u32.to_be_bytes());
        historical.truncate(120 + 52);
        assert!(BackendEvidenceV1::decode(&historical).is_err());
    }

    #[test]
    fn other_class_v1_payload_remains_canonical() {
        let evidence = BackendEvidenceV1::new_acquired(
            BackendEvidenceClassV1::ZfsHeldSnapshot,
            [19; 16],
            20,
            digest(21),
            22,
            digest(23),
            Vec::new(),
        )
        .unwrap();
        let bytes = evidence.encode();
        assert_eq!(&bytes[120..128], b"AOSPZFS1");
        assert_eq!(&bytes[128..130], &1_u16.to_be_bytes());
        assert_eq!(BackendEvidenceV1::decode(&bytes), Ok(evidence));
    }
}
