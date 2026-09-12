//! Supplemental finding-oracle sources, evaluations, and errors.

use super::*;

/// Immutable identity of one supplemental finding accepted by the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignSupplementalFinding {
    pub(super) source: CampaignHash,
    pub(super) fingerprint: CampaignHash,
    pub(super) property: String,
}

const SUPPLEMENTAL_FINDING_SOURCE_MAGIC: &[u8; 8] = b"GCSO\0\0\0\x01";
pub(super) const SUPPLEMENTAL_FINDING_SOURCE_SCHEMA: u32 = 1;
const MAX_SUPPLEMENTAL_FINDING_SOURCE_MEDIA_TYPE_BYTES: usize = 1_024;
const MAX_SUPPLEMENTAL_FINDING_SOURCE_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// Versioned immutable input used to reconstruct a supplemental finding oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingOracleSource {
    scenario: ScenarioDefId,
    media_type: String,
    payload: Vec<u8>,
}

impl GuardedCampaignFindingOracleSource {
    /// Builds one bounded oracle source bound to an exact scenario definition.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignFindingOracleError`] when the media type is
    /// empty, non-ASCII, or too long, or when the payload exceeds 32 MiB.
    pub fn new(
        scenario: ScenarioDefId,
        media_type: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<Self, GuardedCampaignFindingOracleError> {
        let media_type = media_type.into();
        if media_type.is_empty()
            || media_type.len() > MAX_SUPPLEMENTAL_FINDING_SOURCE_MEDIA_TYPE_BYTES
            || !media_type
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
        {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source media type is invalid",
            ));
        }
        if payload.len() > MAX_SUPPLEMENTAL_FINDING_SOURCE_PAYLOAD_BYTES {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source payload exceeds 32 MiB",
            ));
        }
        Ok(Self {
            scenario,
            media_type,
            payload,
        })
    }

    /// Returns the scenario whose configurations the source can evaluate.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the registered payload media type.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Returns the exact source payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Encodes the portable source record.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            SUPPLEMENTAL_FINDING_SOURCE_MAGIC.len()
                + 32
                + std::mem::size_of::<u32>()
                + std::mem::size_of::<u64>()
                + self.media_type.len()
                + self.payload.len(),
        );
        bytes.extend_from_slice(SUPPLEMENTAL_FINDING_SOURCE_MAGIC);
        bytes.extend_from_slice(&self.scenario.as_hash().as_bytes());
        bytes.extend_from_slice(&(self.media_type.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(self.media_type.as_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Decodes and validates a portable source record.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignFindingOracleError`] for malformed,
    /// noncanonical, oversized, or unsupported bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, GuardedCampaignFindingOracleError> {
        const HEADER_BYTES: usize = 8 + 32 + 4 + 8;
        if bytes.len() < HEADER_BYTES
            || bytes.get(..8) != Some(SUPPLEMENTAL_FINDING_SOURCE_MAGIC.as_slice())
        {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source header is invalid",
            ));
        }
        let scenario_bytes: [u8; 32] = bytes[8..40].try_into().map_err(|_| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source scenario is truncated",
            )
        })?;
        let media_length = u32::from_le_bytes(bytes[40..44].try_into().map_err(|_| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source media length is truncated",
            )
        })?) as usize;
        let payload_length = u64::from_le_bytes(bytes[44..52].try_into().map_err(|_| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source payload length is truncated",
            )
        })?);
        let payload_length = usize::try_from(payload_length).map_err(|_| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source payload length is not representable",
            )
        })?;
        let media_end = HEADER_BYTES.checked_add(media_length).ok_or_else(|| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source media length overflows",
            )
        })?;
        let payload_end = media_end.checked_add(payload_length).ok_or_else(|| {
            GuardedCampaignFindingOracleError::new(
                "supplemental finding source payload length overflows",
            )
        })?;
        if payload_end != bytes.len() {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source lengths disagree with its bytes",
            ));
        }
        let media_type = std::str::from_utf8(&bytes[HEADER_BYTES..media_end])
            .map_err(|_| {
                GuardedCampaignFindingOracleError::new(
                    "supplemental finding source media type is not UTF-8",
                )
            })?
            .to_owned();
        let source = Self::new(
            ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario_bytes)),
            media_type,
            bytes[media_end..].to_vec(),
        )?;
        if source.canonical_bytes() != bytes {
            return Err(GuardedCampaignFindingOracleError::new(
                "supplemental finding source is not canonically encoded",
            ));
        }
        Ok(source)
    }

    /// Returns the exact retained trace-leaf identity.
    #[must_use]
    pub fn content_id(&self) -> ContentId {
        ContentId::for_bytes(
            ObjectKind::Trace,
            SUPPLEMENTAL_FINDING_SOURCE_SCHEMA,
            &self.canonical_bytes(),
        )
    }

    /// Returns the source identity bound into campaign policy and findings.
    #[must_use]
    pub fn identity(&self) -> CampaignHash {
        CampaignHash::from_bytes(self.content_id().digest())
    }

    /// Reopens and decodes one exact retained source leaf.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignFindingOracleSourceLoadError`] when the leaf
    /// is absent or corrupt, uses another schema, or does not decode exactly.
    pub fn load(
        store: &CampaignExecutorStore,
        content: ContentId,
    ) -> Result<Self, GuardedCampaignFindingOracleSourceLoadError> {
        if content.kind() != ObjectKind::Trace
            || content.schema_version() != SUPPLEMENTAL_FINDING_SOURCE_SCHEMA
        {
            return Err(GuardedCampaignFindingOracleSourceLoadError::WrongSchema);
        }
        let bytes = store
            .load_executor_trace_leaf(
                content,
                (MAX_SUPPLEMENTAL_FINDING_SOURCE_PAYLOAD_BYTES
                    + MAX_SUPPLEMENTAL_FINDING_SOURCE_MEDIA_TYPE_BYTES
                    + 64) as u64,
            )
            .map_err(GuardedCampaignFindingOracleSourceLoadError::Repository)?;
        let source = Self::from_canonical_bytes(&bytes)
            .map_err(GuardedCampaignFindingOracleSourceLoadError::Decode)?;
        if source.content_id() != content {
            return Err(GuardedCampaignFindingOracleSourceLoadError::Identity);
        }
        Ok(source)
    }
}

/// Failure while reopening a retained supplemental-oracle source.
#[derive(Debug, Error)]
pub enum GuardedCampaignFindingOracleSourceLoadError {
    /// The requested leaf does not use the registered trace schema.
    #[error("supplemental finding source has the wrong object kind or schema")]
    WrongSchema,
    /// The immutable repository leaf could not be read and authenticated.
    #[error("load supplemental finding source: {0}")]
    Repository(#[source] CampaignRepositoryError),
    /// The retained bytes do not decode as the registered source format.
    #[error("decode supplemental finding source: {0}")]
    Decode(#[source] GuardedCampaignFindingOracleError),
    /// The decoded source derives another content identity.
    #[error("supplemental finding source identity mismatch")]
    Identity,
}

impl GuardedCampaignSupplementalFinding {
    /// Returns the authenticated supplemental-oracle source identity.
    #[must_use]
    pub const fn source(&self) -> CampaignHash {
        self.source
    }

    /// Returns the exact failure fingerprint reported for the configuration.
    #[must_use]
    pub const fn fingerprint(&self) -> CampaignHash {
        self.fingerprint
    }

    /// Returns the scenario-declared property selected by the oracle.
    #[must_use]
    pub fn property(&self) -> &str {
        &self.property
    }
}

/// One deterministic property failure returned by a supplemental oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedCampaignFindingOracleEvaluation {
    finding: crucible::SearchAssertionFinding,
}

impl GuardedCampaignFindingOracleEvaluation {
    /// Retains one typed assertion finding returned by the immutable oracle.
    #[must_use]
    pub fn new(finding: crucible::SearchAssertionFinding) -> Self {
        Self { finding }
    }

    /// Returns the scenario-declared property selected by the oracle.
    #[must_use]
    pub fn property(&self) -> &str {
        &self.finding.violation().assertion.name
    }

    /// Returns the stable failure fingerprint for the evaluated configuration.
    #[must_use]
    pub fn fingerprint(&self) -> CampaignHash {
        CampaignHash::from_bytes(self.finding.fingerprint().bytes)
    }

    /// Returns the actual typed assertion violation produced by the oracle.
    #[must_use]
    pub const fn violation(&self) -> &crucible::HostAssertionViolation {
        self.finding.violation()
    }
}

/// Deterministic configuration oracle evaluated by the campaign owner.
pub trait GuardedCampaignFindingOracle: Send + Sync {
    /// Returns the versioned source bound into policy and retained as evidence.
    fn source(&self) -> &GuardedCampaignFindingOracleSource;

    /// Evaluates one repository-authenticated child configuration.
    ///
    /// # Errors
    ///
    /// Returns [`GuardedCampaignFindingOracleError`] when the immutable source
    /// cannot evaluate the accepted configuration exactly.
    fn evaluate(
        &self,
        configuration: &Configuration,
    ) -> Result<Option<GuardedCampaignFindingOracleEvaluation>, GuardedCampaignFindingOracleError>;
}

/// Failure returned by an owner-attached supplemental finding oracle.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{message}")]
pub struct GuardedCampaignFindingOracleError {
    message: String,
}

impl GuardedCampaignFindingOracleError {
    /// Builds an oracle error from stable diagnostic text.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
