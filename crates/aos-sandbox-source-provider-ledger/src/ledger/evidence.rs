//! Pure canonical persistent backend observation evidence.
//!
//! ```text
//! AOSSPE01 | version:u16be | class:u8 | state:u8 | reserved:u32be |
//! payload_len:u32be | backend_authority_id[16] |
//! backend_generation:u64be | backend_digest[32] |
//! observation_generation:u64be | observation_digest[32] | reserved[4] | payload
//!
//! Every class payload begins with its eight-byte class magic, version `1`,
//! two reserved zero bytes, predecessor observation generation, and
//! predecessor observation digest. This makes the opaque suffix a closed,
//! independently versioned canonical union rather than substitutable bytes.
//! ```

use aos_sandbox_core::ObjectDigest;

use crate::limits::MAXIMUM_BACKEND_EVIDENCE_PAYLOAD_BYTES;

const MAGIC: &[u8; 8] = b"AOSSPE01";
const VERSION: u16 = 1;
const FIXED_BYTES: usize = 120;

const CLASS_PAYLOAD_PREFIX_BYTES: usize = 52;

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
    /// This dormant tranche accepts only the closed empty class suffix. A real
    /// adapter must add a versioned class-specific validator before its payload
    /// can be admitted. The helper supplies the class tag and zero predecessor.
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
        if self.payload.len() != CLASS_PAYLOAD_PREFIX_BYTES
            || self.payload.get(..8) != Some(self.class.payload_magic().as_slice())
            || self.payload.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || self.payload.get(10..12) != Some([0_u8; 2].as_slice())
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
            Self::LocalLiveExport => *b"AOSPLOC1",
            Self::ImmutablePublisherTree => *b"AOSPIMM1",
            Self::BestEffortReplica => *b"AOSPREP1",
        }
    }
}

fn class_payload(
    class: BackendEvidenceClassV1,
    predecessor_generation: u64,
    predecessor_digest: ObjectDigest,
    suffix: Vec<u8>,
) -> Result<Vec<u8>, super::LedgerFormatErrorV1> {
    if !suffix.is_empty() {
        return Err(super::LedgerFormatErrorV1::Corrupt(
            "backend class payload validator is dormant",
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
    payload.extend_from_slice(&VERSION.to_be_bytes());
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
