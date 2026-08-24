//! Selectable declarations, stable runtime opportunities, and selections.

use std::collections::BTreeSet;

use crate::choice::domain::{ChoiceDomain, ChoiceValue};
use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    BranchEdgeId, BranchPointId, CampaignCodecError, CampaignHash, ChoiceClassId, ChoiceDomainId,
    ChoiceDomainSemanticId, ChoiceOpportunityId, ChoiceOpportunitySemanticId, ChoiceRngStreamId,
    ConfigurationId, ProbabilityModelId, ScenarioDefId, SelectableId, SelectableSemanticId,
    SelectionId,
};

const SELECTABLE_SCHEMA_VERSION: u32 = 1;
const OPPORTUNITY_SCHEMA_VERSION: u32 = 1;
const SELECTION_SCHEMA_VERSION: u32 = 1;
const MAX_TAGS: usize = 256;

/// Typed producer and consumer class for a choice opportunity.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChoiceSource {
    /// RFC-0014 environment adapter opportunity.
    Environment {
        /// Stable adapter implementation identity.
        adapter: String,
        /// Stable typed effect target identity.
        target: CampaignHash,
    },
    /// Reply-bearing guest application opportunity.
    Guest {
        /// Stable scenario node identifier.
        node: String,
        /// Guest choice protocol version.
        protocol_version: u32,
    },
    /// Explicitly explorable deterministic scheduler decision.
    Scheduler {
        /// Stable scheduler producer class.
        producer: String,
    },
    /// Scenario-declared workload input.
    Workload {
        /// Stable workload producer class.
        producer: String,
    },
}

impl ChoiceSource {
    fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::Environment { adapter, .. } => {
                validate_identifier(adapter, "environment choice adapter is invalid")
            }
            Self::Guest {
                node,
                protocol_version,
            } => {
                validate_identifier(node, "guest choice node is invalid")?;
                if *protocol_version == 0 {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "guest choice protocol version is zero",
                    });
                }
                Ok(())
            }
            Self::Scheduler { producer } => {
                validate_identifier(producer, "scheduler choice producer is invalid")
            }
            Self::Workload { producer } => {
                validate_identifier(producer, "workload choice producer is invalid")
            }
        }
    }
}

impl Canonical for ChoiceSource {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Environment { adapter, target } => {
                encoder.u8(0);
                adapter.encode(encoder);
                target.encode(encoder);
            }
            Self::Guest {
                node,
                protocol_version,
            } => {
                encoder.u8(1);
                node.encode(encoder);
                protocol_version.encode(encoder);
            }
            Self::Scheduler { producer } => {
                encoder.u8(2);
                producer.encode(encoder);
            }
            Self::Workload { producer } => {
                encoder.u8(3);
                producer.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let source = match decoder.u8()? {
            0 => Self::Environment {
                adapter: decoder
                    .string_bounded(MAX_IDENTIFIER_BYTES, "environment-adapter-name-bytes")?,
                target: CampaignHash::decode(decoder)?,
            },
            1 => Self::Guest {
                node: decoder.string_bounded(MAX_IDENTIFIER_BYTES, "guest-node-name-bytes")?,
                protocol_version: u32::decode(decoder)?,
            },
            2 => Self::Scheduler {
                producer: decoder
                    .string_bounded(MAX_IDENTIFIER_BYTES, "scheduler-producer-name-bytes")?,
            },
            3 => Self::Workload {
                producer: decoder
                    .string_bounded(MAX_IDENTIFIER_BYTES, "workload-producer-name-bytes")?,
            },
            tag => {
                return Err(CampaignCodecError::UnknownTag {
                    kind: "choice-source",
                    tag,
                });
            }
        };
        source.validate()?;
        Ok(source)
    }
}

/// Stable semantic context shared by equivalent repeated opportunities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceClassContext {
    tags: BTreeSet<String>,
}

impl ChoiceClassContext {
    /// Builds a bounded canonical context-tag set.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for too many or invalid tags.
    pub fn new(tags: BTreeSet<String>) -> Result<Self, CampaignCodecError> {
        if tags.len() > MAX_TAGS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "choice-class-tag-count",
            });
        }
        for tag in &tags {
            validate_identifier(tag, "choice class tag is invalid")?;
        }
        Ok(Self { tags })
    }

    /// Derives a class identity from a declaration and stable context tags.
    #[must_use]
    pub fn id(&self, declaration_semantics: SelectableSemanticId) -> ChoiceClassId {
        let mut encoder = Encoder::new();
        declaration_semantics.encode(&mut encoder);
        self.encode(&mut encoder);
        ChoiceClassId::from_hash(CampaignHash::derive(
            "crucible.choice-class.v1",
            &encoder.finish(),
        ))
    }

    /// Returns semantic context tags in canonical order.
    #[must_use]
    pub const fn tags(&self) -> &BTreeSet<String> {
        &self.tags
    }
}

impl Canonical for ChoiceClassContext {
    fn encode(&self, encoder: &mut Encoder) {
        self.tags.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            decoder.set_bounded_by(MAX_TAGS, "choice-class-tag-count", |decoder| {
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "choice-class-tag-bytes")
            })?,
        )
    }
}

/// Reusable typed selectable declared by a scenario producer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectableDeclaration {
    schema_version: u32,
    name: String,
    source: ChoiceSource,
    domain: ChoiceDomain,
    default: ChoiceValue,
    class_context: ChoiceClassContext,
    semantic_tags: BTreeSet<String>,
    required: bool,
}

impl SelectableDeclaration {
    /// Builds and validates a reusable selectable declaration.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for invalid names, tags, source, or
    /// default value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        source: ChoiceSource,
        domain: ChoiceDomain,
        default: ChoiceValue,
        class_context: ChoiceClassContext,
        semantic_tags: BTreeSet<String>,
        required: bool,
    ) -> Result<Self, CampaignCodecError> {
        let name = name.into();
        validate_identifier(&name, "selectable declaration name is invalid")?;
        source.validate()?;
        if semantic_tags.len() > MAX_TAGS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "selectable-tag-count",
            });
        }
        for tag in &semantic_tags {
            validate_identifier(tag, "selectable semantic tag is invalid")?;
        }
        if !domain.contains(&default) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "selectable default is outside its domain",
            });
        }
        Ok(Self {
            schema_version: SELECTABLE_SCHEMA_VERSION,
            name,
            source,
            domain,
            default,
            class_context,
            semantic_tags,
            required,
        })
    }

    /// Returns the stable declaration name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the environment or guest producer contract.
    #[must_use]
    pub const fn source(&self) -> &ChoiceSource {
        &self.source
    }

    /// Returns the declared complete legal domain.
    #[must_use]
    pub fn domain(&self) -> &ChoiceDomain {
        &self.domain
    }

    /// Returns the legal default value.
    #[must_use]
    pub fn default(&self) -> &ChoiceValue {
        &self.default
    }

    /// Returns semantic policy-selection tags in canonical order.
    #[must_use]
    pub const fn semantic_tags(&self) -> &BTreeSet<String> {
        &self.semantic_tags
    }

    /// Returns the semantic context used to derive the choice class.
    #[must_use]
    pub const fn class_context(&self) -> &ChoiceClassContext {
        &self.class_context
    }

    /// Returns whether absence of this selectable fails scenario admission.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    /// Returns the domain-separated declaration identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<SelectableId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::SelectableDeclaration,
            BTreeSet::new(),
            codec::encode(self),
        )?;
        SelectableId::from_content_id(envelope.content_id())
    }

    /// Returns the choice class shared by equivalent occurrences.
    #[must_use]
    pub fn class_id(&self) -> ChoiceClassId {
        self.class_context.id(self.semantic_id())
    }

    /// Returns the presentation-independent declaration identity.
    #[must_use]
    pub fn semantic_id(&self) -> SelectableSemanticId {
        let mut encoder = Encoder::new();
        self.schema_version.encode(&mut encoder);
        self.name.encode(&mut encoder);
        self.source.encode(&mut encoder);
        self.domain.semantic_id().encode(&mut encoder);
        self.default.encode(&mut encoder);
        self.class_context.encode(&mut encoder);
        self.semantic_tags.encode(&mut encoder);
        self.required.encode(&mut encoder);
        SelectableSemanticId::from_hash(CampaignHash::derive(
            "crucible.selectable-declaration-semantics.v1",
            &encoder.finish(),
        ))
    }

    /// Returns strict canonical declaration bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical declaration bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, oversized,
    /// or invalid input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }
}

impl Canonical for SelectableDeclaration {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.name.encode(encoder);
        self.source.encode(encoder);
        self.domain.encode(encoder);
        self.default.encode(encoder);
        self.class_context.encode(encoder);
        self.semantic_tags.encode(encoder);
        self.required.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != SELECTABLE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported selectable-declaration schema version",
            });
        }
        Self::new(
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "selectable-name-bytes")?,
            ChoiceSource::decode(decoder)?,
            ChoiceDomain::decode(decoder)?,
            ChoiceValue::decode(decoder)?,
            ChoiceClassContext::decode(decoder)?,
            decoder.set_bounded_by(MAX_TAGS, "selectable-tag-count", |decoder| {
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "selectable-tag-bytes")
            })?,
            bool::decode(decoder)?,
        )
    }
}

/// Stable modeled coordinate of one dynamic choice occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChoiceCoordinate {
    /// Scenario scheduler or RFC-0014 fault coordinate identity.
    pub scheduler: CampaignHash,
    /// Producer-specific semantic operation or phase identity.
    pub producer: CampaignHash,
}

impl Canonical for ChoiceCoordinate {
    fn encode(&self, encoder: &mut Encoder) {
        self.scheduler.encode(encoder);
        self.producer.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            scheduler: CampaignHash::decode(decoder)?,
            producer: CampaignHash::decode(decoder)?,
        })
    }
}

/// Stable runtime occurrence of one selectable declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChoiceOpportunity {
    schema_version: u32,
    scenario: ScenarioDefId,
    class: ChoiceClassId,
    source: ChoiceSource,
    declaration: SelectableId,
    declaration_semantics: SelectableSemanticId,
    domain: ChoiceDomainId,
    domain_semantics: ChoiceDomainSemanticId,
    coordinate: ChoiceCoordinate,
    instance: String,
    default: ChoiceValue,
    model_prior: Option<ProbabilityModelId>,
}

impl ChoiceOpportunity {
    /// Returns strict canonical runtime-opportunity bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one canonical runtime opportunity body.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the bytes are noncanonical, exceed
    /// a field bound, or carry an unsupported schema version.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    /// Builds a validated stable runtime opportunity and optional narrowed offer.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when declaration identity/source/default
    /// mismatches, the offer widens the declaration, or the instance key is
    /// invalid.
    pub fn new(
        scenario: ScenarioDefId,
        declaration: &SelectableDeclaration,
        offered_domain: &ChoiceDomain,
        coordinate: ChoiceCoordinate,
        instance: impl Into<String>,
        model_prior: Option<ProbabilityModelId>,
    ) -> Result<Self, CampaignCodecError> {
        let instance = instance.into();
        validate_identifier(&instance, "choice instance key is invalid")?;
        if !offered_domain.is_subset_of(declaration.domain()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "runtime choice offer widens or changes its declaration domain",
            });
        }
        if !offered_domain.contains(declaration.default()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "runtime choice offer excludes its declared default",
            });
        }
        Ok(Self {
            schema_version: OPPORTUNITY_SCHEMA_VERSION,
            scenario,
            class: declaration.class_id(),
            source: declaration.source.clone(),
            declaration: declaration.id()?,
            declaration_semantics: declaration.semantic_id(),
            domain: offered_domain.id()?,
            domain_semantics: offered_domain.semantic_id(),
            coordinate,
            instance,
            default: declaration.default.clone(),
            model_prior,
        })
    }

    /// Returns the scenario in which this occurrence exists.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the equivalence class used for policy matching and statistics.
    #[must_use]
    pub const fn class(&self) -> ChoiceClassId {
        self.class
    }

    /// Returns the producer contract copied from the declaration.
    #[must_use]
    pub const fn source(&self) -> &ChoiceSource {
        &self.source
    }

    /// Returns the immutable selectable declaration identity.
    #[must_use]
    pub const fn declaration(&self) -> SelectableId {
        self.declaration
    }

    /// Returns the presentation-independent declaration identity.
    #[must_use]
    pub const fn declaration_semantics(&self) -> SelectableSemanticId {
        self.declaration_semantics
    }

    /// Returns the effective narrowed domain identity.
    #[must_use]
    pub const fn domain(&self) -> ChoiceDomainId {
        self.domain
    }

    /// Returns the presentation-independent effective-domain identity.
    #[must_use]
    pub const fn domain_semantics(&self) -> ChoiceDomainSemanticId {
        self.domain_semantics
    }

    /// Returns the stable scheduler and producer coordinate.
    #[must_use]
    pub const fn coordinate(&self) -> ChoiceCoordinate {
        self.coordinate
    }

    /// Returns the producer-defined stable instance key.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Returns the presentation-independent runtime-opportunity identity.
    #[must_use]
    pub fn semantic_id(&self) -> ChoiceOpportunitySemanticId {
        let mut encoder = Encoder::new();
        self.schema_version.encode(&mut encoder);
        self.scenario.encode(&mut encoder);
        self.class.encode(&mut encoder);
        self.source.encode(&mut encoder);
        self.declaration_semantics.encode(&mut encoder);
        self.domain_semantics.encode(&mut encoder);
        self.coordinate.encode(&mut encoder);
        self.instance.encode(&mut encoder);
        self.default.encode(&mut encoder);
        self.model_prior.encode(&mut encoder);
        ChoiceOpportunitySemanticId::from_hash(CampaignHash::derive(
            "crucible.choice-opportunity-semantics.v1",
            &encoder.finish(),
        ))
    }

    /// Derives the semantic branch point beneath `parent`.
    #[must_use]
    pub fn branch_point_id(&self, parent: ConfigurationId) -> BranchPointId {
        let mut encoder = Encoder::new();
        parent.encode(&mut encoder);
        self.semantic_id().encode(&mut encoder);
        BranchPointId::from_hash(CampaignHash::derive(
            "crucible.branch-point.v1",
            &encoder.finish(),
        ))
    }

    /// Revalidates the exact and semantic declaration/domain references.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when either referenced object or any
    /// copied semantic field disagrees with this opportunity.
    pub fn validate_references(
        &self,
        declaration: &SelectableDeclaration,
        domain: &ChoiceDomain,
    ) -> Result<(), CampaignCodecError> {
        if self.declaration != declaration.id()?
            || self.declaration_semantics != declaration.semantic_id()
            || self.class != declaration.class_id()
            || &self.source != declaration.source()
            || &self.default != declaration.default()
            || self.domain != domain.id()?
            || self.domain_semantics != domain.semantic_id()
            || !domain.is_subset_of(declaration.domain())
            || !domain.contains(declaration.default())
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "choice opportunity disagrees with its referenced declaration or domain",
            });
        }
        Ok(())
    }

    /// Derives a compact digest of fields copied from referenced choice records.
    pub(crate) fn reference_contract_hash(&self) -> CampaignHash {
        let mut encoder = Encoder::new();
        self.declaration_semantics.encode(&mut encoder);
        self.class.encode(&mut encoder);
        self.source.encode(&mut encoder);
        self.default.encode(&mut encoder);
        self.domain_semantics.encode(&mut encoder);
        CampaignHash::derive(
            "crucible.choice-opportunity-reference-contract.v1",
            &encoder.finish(),
        )
    }

    /// Returns the stable opportunity identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<ChoiceOpportunityId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceOpportunity,
            crate::object::content_children(self.content_children())?,
            codec::encode(self),
        )?;
        ChoiceOpportunityId::from_content_id(envelope.content_id())
    }

    pub(crate) fn content_children(
        &self,
    ) -> Vec<(&'static str, crucible_cas::content_store::ContentId)> {
        vec![
            ("declaration", self.declaration.content_id()),
            ("domain", self.domain.content_id()),
        ]
    }

    /// Returns the declared default value.
    #[must_use]
    pub fn default(&self) -> &ChoiceValue {
        &self.default
    }

    /// Returns the optional modeled distribution identity.
    #[must_use]
    pub const fn model_prior(&self) -> Option<ProbabilityModelId> {
        self.model_prior
    }
}

impl Canonical for ChoiceOpportunity {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.scenario.encode(encoder);
        self.class.encode(encoder);
        self.source.encode(encoder);
        self.declaration.encode(encoder);
        self.declaration_semantics.encode(encoder);
        self.domain.encode(encoder);
        self.domain_semantics.encode(encoder);
        self.coordinate.encode(encoder);
        self.instance.encode(encoder);
        self.default.encode(encoder);
        self.model_prior.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != OPPORTUNITY_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported choice-opportunity schema version",
            });
        }
        let opportunity = Self {
            schema_version: OPPORTUNITY_SCHEMA_VERSION,
            scenario: ScenarioDefId::decode(decoder)?,
            class: ChoiceClassId::decode(decoder)?,
            source: ChoiceSource::decode(decoder)?,
            declaration: SelectableId::decode(decoder)?,
            declaration_semantics: SelectableSemanticId::decode(decoder)?,
            domain: ChoiceDomainId::decode(decoder)?,
            domain_semantics: ChoiceDomainSemanticId::decode(decoder)?,
            coordinate: ChoiceCoordinate::decode(decoder)?,
            instance: decoder.string_bounded(MAX_IDENTIFIER_BYTES, "choice-instance-key-bytes")?,
            default: ChoiceValue::decode(decoder)?,
            model_prior: Option::decode(decoder)?,
        };
        validate_identifier(&opportunity.instance, "choice instance key is invalid")?;
        Ok(opportunity)
    }
}

/// Exact model-sampling evidence stored in a selection origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ModelSampleEvidence {
    /// Modeled distribution identity.
    model: ProbabilityModelId,
    /// Stable keyed RNG stream.
    stream: ChoiceRngStreamId,
    /// Recorded exact draw.
    draw: u64,
}

impl ModelSampleEvidence {
    /// Builds exact evidence that must subsequently be checked by a model.
    #[must_use]
    pub const fn new(model: ProbabilityModelId, stream: ChoiceRngStreamId, draw: u64) -> Self {
        Self {
            model,
            stream,
            draw,
        }
    }

    /// Returns the modeled distribution identity.
    #[must_use]
    pub const fn model(self) -> ProbabilityModelId {
        self.model
    }

    /// Returns the stable modeled RNG stream.
    #[must_use]
    pub const fn stream(self) -> ChoiceRngStreamId {
        self.stream
    }

    /// Returns the exact recorded draw.
    #[must_use]
    pub const fn draw(self) -> u64 {
        self.draw
    }
}

/// Pure verifier for a probability model's exact draw-to-value mapping.
pub trait ModelSampleVerifier {
    /// Returns whether `evidence` deterministically produces `value`.
    fn verifies(&self, evidence: ModelSampleEvidence, value: &ChoiceValue) -> bool;
}

impl Canonical for ModelSampleEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.model.encode(encoder);
        self.stream.encode(encoder);
        self.draw.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            model: ProbabilityModelId::decode(decoder)?,
            stream: ChoiceRngStreamId::decode(decoder)?,
            draw: u64::decode(decoder)?,
        })
    }
}

/// Modeled delivery mechanism for one recorded choice value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SelectionOrigin {
    /// Scenario default without a sampled alternative.
    Default,
    /// Exact draw from a declared modeled distribution.
    ModelSample(ModelSampleEvidence),
    /// Campaign branch applying one semantic edge at its authenticated point.
    CampaignBranch {
        /// Parent-configuration/opportunity branch point.
        branch_point: BranchPointId,
        /// Semantic domain/value edge.
        edge: BranchEdgeId,
    },
    /// Selection accepted only after exact replay identity checks.
    LockedReplay,
}

impl Canonical for SelectionOrigin {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Default => encoder.u8(0),
            Self::ModelSample(evidence) => {
                encoder.u8(1);
                evidence.encode(encoder);
            }
            Self::CampaignBranch { branch_point, edge } => {
                encoder.u8(2);
                branch_point.encode(encoder);
                edge.encode(encoder);
            }
            Self::LockedReplay => encoder.u8(3),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Default),
            1 => ModelSampleEvidence::decode(decoder).map(Self::ModelSample),
            2 => Ok(Self::CampaignBranch {
                branch_point: BranchPointId::decode(decoder)?,
                edge: BranchEdgeId::decode(decoder)?,
            }),
            3 => Ok(Self::LockedReplay),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "selection-origin",
                tag,
            }),
        }
    }
}

/// Canonical modeled selection recorded in a scenario schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    schema_version: u32,
    opportunity: ChoiceOpportunityId,
    domain: ChoiceDomainId,
    value: ChoiceValue,
    origin: SelectionOrigin,
}

impl Selection {
    /// Derives the semantic edge for an exact branch point, domain semantics,
    /// and legal value.
    ///
    /// The derivation is pure and does not establish that the semantic domain
    /// belongs to a particular exact domain record. Owners must authenticate
    /// that exact-to-semantic binding before using the result.
    #[must_use]
    pub fn campaign_edge_id(
        branch_point: BranchPointId,
        domain: ChoiceDomainSemanticId,
        value: &ChoiceValue,
    ) -> BranchEdgeId {
        derive_branch_edge(branch_point, domain, value)
    }

    /// Builds a selection after validating its value against the supplied domain.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the supplied domain identity or value
    /// disagrees with the opportunity.
    pub fn new(
        opportunity: &ChoiceOpportunity,
        domain: &ChoiceDomain,
        value: ChoiceValue,
        origin: SelectionOrigin,
    ) -> Result<Self, CampaignCodecError> {
        if domain.id()? != opportunity.domain() || !domain.contains(&value) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "selection value or domain disagrees with its opportunity",
            });
        }
        match origin {
            SelectionOrigin::Default if value != *opportunity.default() => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "default selection does not equal the opportunity default",
                });
            }
            SelectionOrigin::ModelSample(_) | SelectionOrigin::CampaignBranch { .. } => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "selection origin requires its evidence-validating constructor",
                });
            }
            _ => {}
        }
        Ok(Self {
            schema_version: SELECTION_SCHEMA_VERSION,
            opportunity: opportunity.id()?,
            domain: domain.id()?,
            value,
            origin,
        })
    }

    /// Builds a model-sampled selection after checking exact draw provenance.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the model identity, value/domain, or
    /// deterministic draw mapping is invalid.
    pub fn new_model_sample(
        opportunity: &ChoiceOpportunity,
        domain: &ChoiceDomain,
        value: ChoiceValue,
        evidence: ModelSampleEvidence,
        verifier: &dyn ModelSampleVerifier,
    ) -> Result<Self, CampaignCodecError> {
        if opportunity.model_prior() != Some(evidence.model())
            || !verifier.verifies(evidence, &value)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "model-sample evidence does not reproduce the selected value",
            });
        }
        Self::new_with_validated_origin(
            opportunity,
            domain,
            value,
            SelectionOrigin::ModelSample(evidence),
        )
    }

    /// Builds a campaign-branch selection and derives its semantic edge.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the value/domain disagrees with the
    /// opportunity or the stored envelope exceeds a limit.
    pub fn new_campaign_branch(
        opportunity: &ChoiceOpportunity,
        domain: &ChoiceDomain,
        value: ChoiceValue,
        branch_point: BranchPointId,
    ) -> Result<Self, CampaignCodecError> {
        let edge = Self::campaign_edge_id(branch_point, domain.semantic_id(), &value);
        Self::new_with_validated_origin(
            opportunity,
            domain,
            value,
            SelectionOrigin::CampaignBranch { branch_point, edge },
        )
    }

    fn new_with_validated_origin(
        opportunity: &ChoiceOpportunity,
        domain: &ChoiceDomain,
        value: ChoiceValue,
        origin: SelectionOrigin,
    ) -> Result<Self, CampaignCodecError> {
        if domain.id()? != opportunity.domain() || !domain.contains(&value) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "selection value or domain disagrees with its opportunity",
            });
        }
        Ok(Self {
            schema_version: SELECTION_SCHEMA_VERSION,
            opportunity: opportunity.id()?,
            domain: domain.id()?,
            value,
            origin,
        })
    }

    /// Returns the stable runtime opportunity identity.
    #[must_use]
    pub const fn opportunity(&self) -> ChoiceOpportunityId {
        self.opportunity
    }

    /// Returns the exact effective domain identity checked at replay.
    #[must_use]
    pub const fn domain(&self) -> ChoiceDomainId {
        self.domain
    }

    /// Returns the concrete legal value.
    #[must_use]
    pub fn value(&self) -> &ChoiceValue {
        &self.value
    }

    /// Returns the modeled delivery mechanism and its provenance.
    #[must_use]
    pub const fn origin(&self) -> SelectionOrigin {
        self.origin
    }

    /// Returns strict schedule-envelope bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one strict canonical selection envelope.
    ///
    /// This is the language-neutral conversion boundary used by execution
    /// schedules. Callers must still resolve the named opportunity and domain
    /// and invoke the appropriate replay validator before applying the value.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, invalid, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    /// Revalidates opportunity identity, domain digest, and value during replay.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when replay reconstructs another
    /// opportunity/domain or the value is no longer legal.
    pub fn validate_replay(
        &self,
        opportunity: &ChoiceOpportunity,
        domain: &ChoiceDomain,
    ) -> Result<(), CampaignCodecError> {
        if self.opportunity != opportunity.id()?
            || self.domain != domain.id()?
            || self.domain != opportunity.domain()
            || !domain.contains(&self.value)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "selection replay identity or domain mismatch",
            });
        }
        match self.origin {
            SelectionOrigin::Default if self.value != *opportunity.default() => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "selection replay default provenance mismatch",
                });
            }
            SelectionOrigin::ModelSample(_) | SelectionOrigin::CampaignBranch { .. } => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "selection replay requires origin-specific evidence validation",
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// Revalidates a model-sampled selection with the named pure model.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for base replay drift or invalid model
    /// identity/draw mapping.
    pub fn validate_model_replay(
        &self,
        opportunity: &ChoiceOpportunity,
        domain: &ChoiceDomain,
        verifier: &dyn ModelSampleVerifier,
    ) -> Result<(), CampaignCodecError> {
        validate_base_replay(self, opportunity, domain)?;
        let SelectionOrigin::ModelSample(evidence) = self.origin else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "selection is not model-sampled",
            });
        };
        if opportunity.model_prior() != Some(evidence.model())
            || !verifier.verifies(evidence, &self.value)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "selection replay model provenance mismatch",
            });
        }
        Ok(())
    }

    /// Revalidates a branch selection against its branch-point identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for base replay drift or an edge mismatch.
    pub fn validate_branch_replay(
        &self,
        opportunity: &ChoiceOpportunity,
        domain: &ChoiceDomain,
        branch_point: BranchPointId,
    ) -> Result<(), CampaignCodecError> {
        validate_base_replay(self, opportunity, domain)?;
        let SelectionOrigin::CampaignBranch {
            branch_point: stored_point,
            edge,
        } = self.origin
        else {
            return Err(CampaignCodecError::InvalidValue {
                reason: "selection is not a campaign branch",
            });
        };
        if stored_point != branch_point
            || edge != derive_branch_edge(branch_point, domain.semantic_id(), &self.value)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "selection branch edge does not match its point/domain/value",
            });
        }
        Ok(())
    }

    /// Revalidates cross-object identity, legality, and self-contained origin data.
    ///
    /// Model samples additionally require [`Selection::validate_model_replay`]
    /// with the model implementation before execution.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for reference drift, an illegal value,
    /// incorrect default/model identity, or an invalid branch edge.
    pub fn validate_resolved_references(
        &self,
        opportunity: &ChoiceOpportunity,
        domain: &ChoiceDomain,
    ) -> Result<(), CampaignCodecError> {
        validate_base_replay(self, opportunity, domain)?;
        match self.origin {
            SelectionOrigin::Default if self.value != *opportunity.default() => {
                Err(CampaignCodecError::InvalidValue {
                    reason: "selection default provenance mismatch",
                })
            }
            SelectionOrigin::ModelSample(evidence)
                if opportunity.model_prior() != Some(evidence.model()) =>
            {
                Err(CampaignCodecError::InvalidValue {
                    reason: "selection model identity mismatch",
                })
            }
            SelectionOrigin::CampaignBranch { branch_point, edge }
                if edge != derive_branch_edge(branch_point, domain.semantic_id(), &self.value) =>
            {
                Err(CampaignCodecError::InvalidValue {
                    reason: "selection branch edge mismatch",
                })
            }
            _ => Ok(()),
        }
    }

    /// Returns the content-derived selection identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<SelectionId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::Selection,
            crate::object::content_children(self.content_children())?,
            self.canonical_bytes(),
        )?;
        SelectionId::from_content_id(envelope.content_id())
    }

    pub(crate) fn content_children(
        &self,
    ) -> Vec<(&'static str, crucible_cas::content_store::ContentId)> {
        vec![
            ("opportunity", self.opportunity.content_id()),
            ("domain", self.domain.content_id()),
        ]
    }
}

impl Canonical for Selection {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.opportunity.encode(encoder);
        self.domain.encode(encoder);
        self.value.encode(encoder);
        self.origin.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != SELECTION_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported selection schema version",
            });
        }
        Ok(Self {
            schema_version: SELECTION_SCHEMA_VERSION,
            opportunity: ChoiceOpportunityId::decode(decoder)?,
            domain: ChoiceDomainId::decode(decoder)?,
            value: ChoiceValue::decode(decoder)?,
            origin: SelectionOrigin::decode(decoder)?,
        })
    }
}

fn validate_base_replay(
    selection: &Selection,
    opportunity: &ChoiceOpportunity,
    domain: &ChoiceDomain,
) -> Result<(), CampaignCodecError> {
    if selection.opportunity != opportunity.id()?
        || selection.domain != domain.id()?
        || selection.domain != opportunity.domain()
        || !domain.contains(&selection.value)
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "selection replay identity or domain mismatch",
        });
    }
    Ok(())
}

fn derive_branch_edge(
    branch_point: BranchPointId,
    domain: ChoiceDomainSemanticId,
    value: &ChoiceValue,
) -> BranchEdgeId {
    let mut encoder = Encoder::new();
    branch_point.encode(&mut encoder);
    Canonical::encode(&domain, &mut encoder);
    value.encode(&mut encoder);
    BranchEdgeId::from_hash(CampaignHash::derive(
        "crucible.branch-edge.v1",
        &encoder.finish(),
    ))
}
