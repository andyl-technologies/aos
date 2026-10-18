//! Scenario root entropy and its deterministic decision-stream derivations.

use super::*;

/// The 256-bit root entropy component of a scenario definition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seed {
    pub(super) bytes: [u8; 32],
}

impl Seed {
    /// Builds a seed from canonical root-entropy bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Builds a seed from a small deterministic integer.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Self { bytes }
    }

    /// Returns this seed's canonical 256-bit byte representation.
    #[must_use]
    pub fn bytes(self) -> [u8; 32] {
        self.bytes
    }

    /// Renders this seed as 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_hex(&self.bytes)
    }

    /// Builds the deterministic decision RNG rooted at this seed.
    #[must_use]
    pub fn decision_rng(self) -> DecisionRng {
        DecisionRng::new(self.decision_rng_root_seed())
    }

    /// Returns the deterministic fork seed for `stream`.
    #[must_use]
    pub fn stream_seed(self, stream: &RngStreamId) -> u64 {
        self.decision_rng()
            .stream_seed_in_domain(&stream.domain, &stream.name)
    }

    /// Forks a deterministic decision stream for `stream`.
    #[must_use]
    pub fn fork_stream(self, stream: &RngStreamId) -> DecisionStream {
        self.decision_rng()
            .fork_in_domain(&stream.domain, &stream.name)
    }

    /// Serializes this seed component as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if serialization fails.
    pub fn to_canonical_toml(self) -> Result<String, EngineError> {
        toml::to_string(&seed_to_toml(self)).map_err(|source| {
            scenario_serialization_error(format!("serialize seed TOML: {source}"))
        })
    }

    /// Parses a deterministic TOML seed component.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed input.
    pub fn from_canonical_toml(input: &str) -> Result<Self, EngineError> {
        let toml = toml::from_str::<SeedToml>(input)
            .map_err(|source| scenario_serialization_error(format!("parse seed TOML: {source}")))?;
        seed_from_toml(&toml)
    }

    /// Serializes this seed component as compact binary.
    #[must_use]
    pub fn to_compact_binary(self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(SEED_BINARY_MAGIC);
        writer.write_seed(self);
        writer.finish()
    }

    /// Parses a compact binary seed component.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for invalid binary input.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, SEED_BINARY_MAGIC)?;
        let seed = reader.read_seed()?;
        reader.finish()?;
        Ok(seed)
    }

    /// Returns the canonical bytes used when this seed participates in identities.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        seed_material(self).into_bytes()
    }

    /// Returns the frozen `u64` root consumed by the L0 decision RNG.
    #[must_use]
    pub fn decision_rng_root_seed(self) -> u64 {
        let hash = ContentHash::from_canonical_material(
            "crucible.model.seed-decision-rng-root.v1",
            &seed_material(self),
        );
        let mut root = [0; 8];
        root.copy_from_slice(&hash.bytes[..8]);
        u64::from_le_bytes(root)
    }
}

/// One world-declared decision-RNG stream after forking from a scenario seed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeededRngStream {
    /// The declared per-entity stream id.
    pub stream: RngStreamId,
    /// The deterministic stream seed derived from [`Seed`] and stream name-hash.
    pub seed: u64,
}
