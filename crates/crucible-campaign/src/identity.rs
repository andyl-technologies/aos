//! Domain-separated campaign hashes and strongly typed identifiers.
//!
//! Stored-record wrappers validate the broad storage kind and supported schema
//! version present in a [`ContentId`]. Records sharing a broad kind (for
//! example policy and planner artifacts) are distinguished by the authenticated
//! envelope schema when dereferenced; repositories never trust the wrapper
//! alone as proof of the record body type.

use std::fmt;

use crucible_cas::content_store::{ContentId, ObjectKind};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::CampaignCodecError;
use super::codec::{Canonical, Decoder, Encoder};

const CAMPAIGN_HASH_DOMAIN: &[u8] = b"crucible.campaign.identity.v1";

/// Raw 256-bit campaign identity shared by strongly typed IDs.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CampaignHash([u8; 32]);

impl CampaignHash {
    /// Builds an identity from exactly 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact identity bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Derives a domain-separated identity from canonical object bytes.
    #[must_use]
    pub fn derive(domain: &str, canonical_bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(CAMPAIGN_HASH_DOMAIN.len() as u64).to_be_bytes());
        hasher.update(CAMPAIGN_HASH_DOMAIN);
        hasher.update(&(domain.len() as u64).to_be_bytes());
        hasher.update(domain.as_bytes());
        hasher.update(&(canonical_bytes.len() as u64).to_be_bytes());
        hasher.update(canonical_bytes);
        Self(*hasher.finalize().as_bytes())
    }

    /// Renders 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    /// Parses exactly 64 lowercase hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidHex`] for malformed or noncanonical
    /// text.
    pub fn parse(value: &str) -> Result<Self, CampaignCodecError> {
        if value.len() != 64 {
            return Err(CampaignCodecError::InvalidHex);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0]).ok_or(CampaignCodecError::InvalidHex)?;
            let low = hex_nibble(pair[1]).ok_or(CampaignCodecError::InvalidHex)?;
            bytes[index] = (high << 4) | low;
        }
        let hash = Self(bytes);
        if hash.to_hex() != value {
            return Err(CampaignCodecError::InvalidHex);
        }
        Ok(hash)
    }
}

impl fmt::Debug for CampaignHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CampaignHash")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for CampaignHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for CampaignHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for CampaignHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CampaignHashVisitor)
    }
}

struct CampaignHashVisitor;

impl Visitor<'_> for CampaignHashVisitor {
    type Value = CampaignHash;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a canonical lowercase 64-character campaign identity")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        CampaignHash::parse(value).map_err(E::custom)
    }
}

impl Canonical for CampaignHash {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.fixed(&self.0);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self(decoder.fixed()?))
    }
}

macro_rules! semantic_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(CampaignHash);

        impl $name {
            /// Builds the typed identity from a raw campaign hash.
            #[must_use]
            pub const fn from_hash(hash: CampaignHash) -> Self {
                Self(hash)
            }

            /// Returns the raw campaign hash.
            #[must_use]
            pub const fn as_hash(self) -> CampaignHash {
                self.0
            }

            /// Parses the canonical lowercase hexadecimal identity.
            ///
            /// # Errors
            ///
            /// Returns [`CampaignCodecError::InvalidHex`] for malformed or
            /// noncanonical text.
            pub fn parse(value: &str) -> Result<Self, CampaignCodecError> {
                CampaignHash::parse(value).map(Self)
            }

            /// Renders the canonical lowercase hexadecimal identity.
            #[must_use]
            pub fn to_hex(self) -> String {
                self.0.to_hex()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Canonical for $name {
            fn encode(&self, encoder: &mut Encoder) {
                self.0.encode(encoder);
            }

            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
                CampaignHash::decode(decoder).map(Self)
            }
        }
    };
}

macro_rules! content_object_id {
    ($name:ident, $kind:expr, $type_tag:literal, $doc:literal) => {
        content_object_id!(@impl $name, $kind, [1], $type_tag, $doc);
    };
    ($name:ident, $kind:expr, $schema_version:literal, $type_tag:literal, $doc:literal) => {
        content_object_id!(@impl $name, $kind, [$schema_version], $type_tag, $doc);
    };
    ($name:ident, $kind:expr, [$($schema_version:literal),+ $(,)?], $type_tag:literal, $doc:literal) => {
        content_object_id!(@impl $name, $kind, [$($schema_version),+], $type_tag, $doc);
    };
    (@impl $name:ident, $kind:expr, [$($schema_version:literal),+], $type_tag:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(ContentId);

        impl $name {
            /// Claims a record-specific identity for an unresolved content ID.
            ///
            /// This constructor is crate-private because a generic content ID
            /// does not expose the record schema committed inside its digest.
            /// Public text and binary forms carry an exact type tag; repository
            /// reads additionally authenticate the named envelope before use.
            ///
            /// # Errors
            ///
            /// Returns [`CampaignCodecError::InvalidValue`] for the wrong kind.
            // Schema compatibility is an explicit set even when its current
            // members happen to form a contiguous numeric range.
            #[allow(clippy::manual_range_patterns)]
            pub(crate) fn from_content_id(value: ContentId) -> Result<Self, CampaignCodecError> {
                if value.kind() != $kind
                    || !matches!(value.schema_version(), $($schema_version)|+)
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "content identity has the wrong object kind or schema version",
                    });
                }
                Ok(Self(value))
            }

            /// Returns the underlying backend-independent content identity.
            #[must_use]
            pub const fn content_id(self) -> ContentId {
                self.0
            }

            /// Parses a canonical record-typed content identity.
            ///
            /// # Errors
            ///
            /// Returns [`CampaignCodecError`] for malformed text or wrong kind.
            pub fn parse(value: &str) -> Result<Self, CampaignCodecError> {
                let (tag, encoded_content) =
                    value
                        .split_once('@')
                        .ok_or(CampaignCodecError::InvalidValue {
                            reason: "typed content identity is malformed",
                        })?;
                if tag != $type_tag {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "typed content identity has the wrong record type",
                    });
                }
                let content = ContentId::parse(encoded_content).map_err(|_| {
                    CampaignCodecError::InvalidValue {
                        reason: "typed content identity is malformed",
                    }
                })?;
                Self::from_content_id(content)
            }

            /// Renders the canonical content identity.
            #[must_use]
            pub fn to_text(self) -> String {
                format!("{}@{}", $type_tag, self.0.encode())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.to_text())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_text())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct TypedContentVisitor;

                impl Visitor<'_> for TypedContentVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a canonical record-typed content identity")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::parse(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(TypedContentVisitor)
            }
        }

        impl Canonical for $name {
            fn encode(&self, encoder: &mut Encoder) {
                encoder.string($type_tag);
                Canonical::encode(&self.0, encoder);
            }

            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
                if decoder.string_bounded($type_tag.len(), "typed-content-id-tag-bytes")?
                    != $type_tag
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "typed content identity has the wrong record type",
                    });
                }
                Self::from_content_id(ContentId::decode(decoder)?)
            }
        }
    };
}

semantic_id!(
    ScenarioDefId,
    "Identifies one immutable scenario definition."
);
semantic_id!(
    ConfigurationId,
    "Identifies one scenario definition and schedule."
);
content_object_id!(
    ScenarioArtifactId,
    ObjectKind::Scenario,
    "crucible.campaign.scenario-artifact",
    "Identifies exact canonical scenario-definition bytes."
);
content_object_id!(
    ConfigurationArtifactId,
    ObjectKind::Configuration,
    "crucible.campaign.configuration-artifact",
    "Identifies exact canonical configuration bytes."
);
content_object_id!(
    ExactCheckpointId,
    ObjectKind::ExactManifest,
    [2, 3],
    "crucible.executor.exact-checkpoint-root",
    "Identifies one durable exact-checkpoint closure; current roots carry complete campaign continuation state."
);

impl TryFrom<ContentId> for ExactCheckpointId {
    type Error = CampaignCodecError;

    fn try_from(value: ContentId) -> Result<Self, Self::Error> {
        Self::from_content_id(value)
    }
}
content_object_id!(
    CampaignLineageId,
    ObjectKind::CampaignFact,
    "crucible.campaign.lineage",
    "Identifies one campaign compatibility lineage."
);
content_object_id!(
    CampaignPolicyId,
    ObjectKind::Policy,
    "crucible.campaign.policy",
    "Identifies one immutable campaign policy revision."
);
content_object_id!(
    CampaignSnapshotId,
    ObjectKind::CampaignSnapshot,
    2,
    "crucible.campaign.snapshot",
    "Identifies one immutable campaign snapshot."
);
content_object_id!(
    CampaignViewId,
    ObjectKind::CampaignFact,
    "crucible.campaign.planning-view",
    "Identifies one bounded campaign planning view."
);
content_object_id!(
    PlannerEngineId,
    ObjectKind::Policy,
    "crucible.campaign.planner-engine",
    "Identifies one planner implementation and protocol."
);
content_object_id!(
    PolicyArtifactId,
    ObjectKind::Policy,
    "crucible.campaign.policy-artifact",
    "Identifies one reproducible planner policy artifact."
);
content_object_id!(
    PlannerStateId,
    ObjectKind::Policy,
    "crucible.campaign.planner-state",
    "Identifies one bounded portable planner state object."
);
content_object_id!(
    PlannerInvocationId,
    ObjectKind::Policy,
    2,
    "crucible.campaign.planner-invocation",
    "Identifies one pure planner invocation basis."
);
content_object_id!(
    RetainedPlannerRequestId,
    ObjectKind::Policy,
    "crucible.campaign.retained-planner-request",
    "Identifies one retained canonical pure-planner request."
);
content_object_id!(
    PlannerStepId,
    ObjectKind::CampaignFact,
    [3, 4],
    "crucible.campaign.planner-step",
    "Identifies one coordinator-accepted planner step; version 3 IDs remain decodable for fact compatibility."
);
content_object_id!(
    CampaignFactId,
    ObjectKind::CampaignFact,
    [2, 3, 4, 5],
    "crucible.campaign.fact",
    "Identifies one immutable campaign fact; versions 2 through 4 remain decodable for history compatibility."
);
semantic_id!(
    CampaignCommandId,
    "Identifies one idempotent campaign command."
);
content_object_id!(
    SelectableId,
    ObjectKind::CampaignFact,
    "crucible.campaign.selectable-declaration",
    "Identifies one reusable selectable declaration."
);
semantic_id!(AlternativeId, "Identifies one stable discrete alternative.");
semantic_id!(
    SelectableSemanticId,
    "Identifies presentation-independent selectable declaration semantics."
);
content_object_id!(
    ChoiceDomainId,
    ObjectKind::CampaignFact,
    "crucible.campaign.choice-domain",
    "Identifies one versioned typed choice domain."
);
semantic_id!(
    ChoiceDomainSemanticId,
    "Identifies the presentation-independent semantics of a choice domain."
);
semantic_id!(
    ChoiceClassId,
    "Identifies one class of semantically equivalent opportunities."
);
semantic_id!(
    ChoiceOpportunitySemanticId,
    "Identifies presentation-independent semantics of one runtime choice occurrence."
);
content_object_id!(
    ChoiceGroupId,
    ObjectKind::CampaignFact,
    "crucible.campaign.choice-group",
    "Identifies one atomically applied choice group."
);
content_object_id!(
    ChoiceOpportunityId,
    ObjectKind::CampaignFact,
    "crucible.campaign.choice-opportunity",
    "Identifies one stable runtime choice occurrence."
);
content_object_id!(
    SelectionId,
    ObjectKind::CampaignFact,
    "crucible.campaign.selection",
    "Identifies one canonical recorded selection."
);
semantic_id!(
    ProbabilityModelId,
    "Identifies one exact modeled probability distribution."
);
semantic_id!(
    ChoiceRngStreamId,
    "Identifies one stable modeled choice RNG stream."
);
semantic_id!(
    BranchPointId,
    "Identifies one parent configuration and choice opportunity."
);
content_object_id!(
    BranchRequestId,
    ObjectKind::CampaignFact,
    "crucible.campaign.branch-request",
    "Identifies one bounded request for branch candidates."
);
content_object_id!(
    CandidateGeneratorSpecId,
    ObjectKind::Policy,
    "crucible.campaign.candidate-generator-spec",
    "Identifies one versioned candidate generator specification."
);
content_object_id!(
    ProposalId,
    ObjectKind::CampaignFact,
    "crucible.campaign.proposal",
    "Identifies one proposed value and its campaign provenance."
);
semantic_id!(
    BranchEdgeId,
    "Identifies one semantic selected edge at a branch point."
);
content_object_id!(
    BranchPathId,
    ObjectKind::CampaignFact,
    [1, 2],
    "crucible.campaign.branch-path",
    "Identifies one ordered authenticated branch path; version 1 edge-only IDs remain decodable for history compatibility."
);
content_object_id!(
    AttemptId,
    ObjectKind::CampaignFact,
    "crucible.campaign.attempt",
    "Identifies one immutable semantic execution attempt."
);
content_object_id!(
    AttemptAdmissionId,
    ObjectKind::CampaignFact,
    "crucible.campaign.attempt-admission",
    "Identifies one immutable attempt admission or additional cause."
);
content_object_id!(
    ObservationId,
    ObjectKind::Observation,
    "crucible.campaign.observation",
    "Identifies one canonical attempt observation."
);
content_object_id!(
    FindingId,
    ObjectKind::Finding,
    "crucible.campaign.finding",
    "Identifies one canonical campaign finding."
);
content_object_id!(
    ReproductionArtifactId,
    ObjectKind::Finding,
    "crucible.campaign.reproduction-artifact",
    "Identifies one verifier-backed self-contained finding reproduction."
);
content_object_id!(
    MeasurementSetId,
    ObjectKind::Observation,
    "crucible.campaign.measurement-set",
    "Identifies one canonical measurement set."
);
content_object_id!(
    PropertyVerdictSetId,
    ObjectKind::Observation,
    "crucible.campaign.property-verdict-set",
    "Identifies one canonical property-verdict set."
);
content_object_id!(
    CoverageProjectionId,
    ObjectKind::Projection,
    "crucible.campaign.coverage-projection",
    "Identifies one canonical coverage projection."
);
content_object_id!(
    ExpansionStateId,
    ObjectKind::Projection,
    2,
    "crucible.campaign.expansion-state",
    "Identifies one derived branch expansion-state snapshot."
);
content_object_id!(
    ContinuationProjectionId,
    ObjectKind::Projection,
    "crucible.campaign.continuation-projection",
    "Identifies one authenticated per-request continuation projection."
);
semantic_id!(
    CreditId,
    "Identifies one idempotent observation-to-branch credit."
);
semantic_id!(
    DebugSessionId,
    "Identifies one non-canonical debugger session."
);

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
