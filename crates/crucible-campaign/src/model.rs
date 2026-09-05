//! Canonical campaign lineage, snapshots, planning basis, and accounting facts.

mod budget;
mod facts;

pub use budget::{CampaignBudgetError, CampaignBudgetLedger};

pub use facts::{
    ActiveAttemptPolicy, BudgetGrant, CampaignControlAction, CampaignDerivation, CampaignFact,
    CampaignState, ControlRequest, NonModeledAttemptDisposition, PinChange, PinRequest,
    PinRetention, PolicyActivation,
};

use std::collections::{BTreeMap, BTreeSet};

use super::codec::{self, Canonical, Decoder, Encoder};
use super::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use super::{
    CampaignCodecError, CampaignFactId, CampaignLineageId, CampaignPolicyId, CampaignSnapshotId,
    CampaignViewId, ConfigurationArtifactId, ConfigurationId, PlannerEngineId, PlannerInvocationId,
    PlannerStateId, PlanningScanPage, PolicyArtifactId, ScenarioArtifactId, ScenarioDefId,
};
use crucible_cas::content_store::ContentId;

const LINEAGE_SCHEMA_VERSION: u32 = 1;
const LEGACY_SNAPSHOT_SCHEMA_VERSION: u32 = 2;
const PLANNING_VIEW_SCHEMA_VERSION: u32 = 1;
const PLANNER_ENGINE_SCHEMA_VERSION: u32 = 1;
const POLICY_ARTIFACT_SCHEMA_VERSION: u32 = 1;
const PLANNER_STATE_SCHEMA_VERSION: u32 = 1;
const PLANNER_INVOCATION_SCHEMA_VERSION: u32 = 2;
const MAX_PLANNER_STATE_BYTES: usize = 1024 * 1024;
const MAX_VERSION_COMPONENTS: usize = 256;
const MAX_ARTIFACT_ARGUMENTS: usize = 1024;
const MAX_POLICY_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// Globally ordered semantic admission sequence used by strict projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdmissionOrdinal(u64);

impl AdmissionOrdinal {
    /// Builds an admission ordinal.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the ordinal value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the next ordinal if it does not overflow.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl Canonical for AdmissionOrdinal {
    fn encode(&self, encoder: &mut Encoder) {
        self.0.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self(u64::decode(decoder)?))
    }
}

/// Immutable compatibility boundary for one campaign lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignLineage {
    schema_version: u32,
    scenario: ScenarioDefId,
    scenario_content: ScenarioArtifactId,
    genesis: ConfigurationId,
    genesis_content: ConfigurationArtifactId,
    crucible_version: String,
    qemu_build: String,
    protocol_versions: BTreeMap<String, u32>,
    scenario_schema: u32,
    exact_closure_schema: u32,
}

impl CampaignLineage {
    /// Builds a validated campaign compatibility lineage.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when a version identifier or schema is
    /// empty, zero, or exceeds its bound.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scenario: ScenarioDefId,
        scenario_content: ScenarioArtifactId,
        genesis: ConfigurationId,
        genesis_content: ConfigurationArtifactId,
        crucible_version: impl Into<String>,
        qemu_build: impl Into<String>,
        protocol_versions: BTreeMap<String, u32>,
        scenario_schema: u32,
        exact_closure_schema: u32,
    ) -> Result<Self, CampaignCodecError> {
        let crucible_version = crucible_version.into();
        let qemu_build = qemu_build.into();
        validate_identifier(&crucible_version, "Crucible version is invalid")?;
        validate_identifier(&qemu_build, "QEMU build identity is invalid")?;
        if protocol_versions.is_empty() || protocol_versions.len() > MAX_VERSION_COMPONENTS {
            return Err(CampaignCodecError::InvalidValue {
                reason: "protocol-version set is empty or oversized",
            });
        }
        for (component, version) in &protocol_versions {
            validate_identifier(component, "protocol component identifier is invalid")?;
            if *version == 0 {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "protocol version is zero",
                });
            }
        }
        if scenario_schema == 0 || exact_closure_schema == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "lineage schema version is zero",
            });
        }
        Ok(Self {
            schema_version: LINEAGE_SCHEMA_VERSION,
            scenario,
            scenario_content,
            genesis,
            genesis_content,
            crucible_version,
            qemu_build,
            protocol_versions,
            scenario_schema,
            exact_closure_schema,
        })
    }

    /// Returns the immutable scenario identity.
    #[must_use]
    pub const fn scenario(&self) -> ScenarioDefId {
        self.scenario
    }

    /// Returns the exact stored scenario-definition artifact.
    #[must_use]
    pub const fn scenario_content(&self) -> ScenarioArtifactId {
        self.scenario_content
    }

    /// Returns the genesis configuration identity.
    #[must_use]
    pub const fn genesis(&self) -> ConfigurationId {
        self.genesis
    }

    /// Returns the exact stored genesis-configuration artifact.
    #[must_use]
    pub const fn genesis_content(&self) -> ConfigurationArtifactId {
        self.genesis_content
    }

    pub(crate) fn content_children(&self) -> [(&'static str, ContentId); 2] {
        [
            ("scenario", self.scenario_content.content_id()),
            ("genesis", self.genesis_content.content_id()),
        ]
    }

    /// Returns the Crucible implementation compatibility version.
    #[must_use]
    pub fn crucible_version(&self) -> &str {
        &self.crucible_version
    }

    /// Returns the QEMU build and patch-series identity.
    #[must_use]
    pub fn qemu_build(&self) -> &str {
        &self.qemu_build
    }

    /// Returns component protocol versions in canonical component order.
    #[must_use]
    pub fn protocol_versions(&self) -> &BTreeMap<String, u32> {
        &self.protocol_versions
    }

    /// Returns the scenario schema version.
    #[must_use]
    pub const fn scenario_schema(&self) -> u32 {
        self.scenario_schema
    }

    /// Returns the exact-checkpoint closure schema version.
    #[must_use]
    pub const fn exact_closure_schema(&self) -> u32 {
        self.exact_closure_schema
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical lineage bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, oversized,
    /// or semantically invalid input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    /// Returns the domain-separated lineage identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<CampaignLineageId, CampaignCodecError> {
        CampaignLineageId::from_content_id(crate::ObjectEnvelope::for_lineage(self)?.content_id())
    }
}

impl Canonical for CampaignLineage {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.scenario.encode(encoder);
        self.scenario_content.encode(encoder);
        self.genesis.encode(encoder);
        self.genesis_content.encode(encoder);
        self.crucible_version.encode(encoder);
        self.qemu_build.encode(encoder);
        self.protocol_versions.encode(encoder);
        self.scenario_schema.encode(encoder);
        self.exact_closure_schema.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(
            u32::decode(decoder)?,
            LINEAGE_SCHEMA_VERSION,
            "campaign-lineage",
        )?;
        Self::new(
            ScenarioDefId::decode(decoder)?,
            ScenarioArtifactId::decode(decoder)?,
            ConfigurationId::decode(decoder)?,
            ConfigurationArtifactId::decode(decoder)?,
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "crucible-version-bytes")?,
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "qemu-build-id-bytes")?,
            decoder.map_bounded_by(
                MAX_VERSION_COMPONENTS,
                "protocol-version-count",
                |decoder| {
                    decoder.string_bounded(MAX_IDENTIFIER_BYTES, "protocol-component-name-bytes")
                },
                u32::decode,
            )?,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// Nine authoritative immutable roots named by a campaign snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CampaignRoots {
    /// Configuration graph, branch points, and semantic edges.
    pub graph: ContentId,
    /// Branch requests, proposals, and candidate sources.
    pub exploration: ContentId,
    /// Canonical observations and modeled evidence.
    pub observations: ContentId,
    /// Retained configurations and mutation corpus.
    pub corpus: ContentId,
    /// Grow-only canonical coverage union.
    pub coverage: ContentId,
    /// Findings and reproduction artifacts.
    pub findings: ContentId,
    /// Semantic user and policy pins.
    pub pins: ContentId,
    /// Budgets, control intent, commands, and admissions.
    pub accounting: ContentId,
    /// Durable coordinator progress excluded from semantic planner input.
    pub coordination: ContentId,
}

impl Canonical for CampaignRoots {
    fn encode(&self, encoder: &mut Encoder) {
        Canonical::encode(&self.graph, encoder);
        Canonical::encode(&self.exploration, encoder);
        Canonical::encode(&self.observations, encoder);
        Canonical::encode(&self.corpus, encoder);
        Canonical::encode(&self.coverage, encoder);
        Canonical::encode(&self.findings, encoder);
        Canonical::encode(&self.pins, encoder);
        Canonical::encode(&self.accounting, encoder);
        Canonical::encode(&self.coordination, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            graph: ContentId::decode(decoder)?,
            exploration: ContentId::decode(decoder)?,
            observations: ContentId::decode(decoder)?,
            corpus: ContentId::decode(decoder)?,
            coverage: ContentId::decode(decoder)?,
            findings: ContentId::decode(decoder)?,
            pins: ContentId::decode(decoder)?,
            accounting: ContentId::decode(decoder)?,
            coordination: ContentId::decode(decoder)?,
        })
    }
}

/// Immutable campaign snapshot named by one authoritative mutable ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignSnapshot {
    schema_version: u32,
    parent: Option<CampaignSnapshotId>,
    lineage: CampaignLineageId,
    active_policy: CampaignPolicyId,
    roots: CampaignRoots,
    transition: Option<CampaignFactId>,
    budget_ledger: Option<crate::CampaignBudgetLedgerId>,
}

impl CampaignSnapshot {
    /// Builds an immutable genesis snapshot.
    ///
    /// Preserves the legacy version-2 encoding until [`Self::with_budget_ledger`]
    /// attaches the version-3 accounting contract. Repository creation always
    /// attaches an empty ledger before publication.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a root is not a Merkle-node object.
    pub fn genesis(
        lineage: CampaignLineageId,
        active_policy: CampaignPolicyId,
        roots: CampaignRoots,
    ) -> Result<Self, CampaignCodecError> {
        validate_roots(roots)?;
        Ok(Self {
            schema_version: LEGACY_SNAPSHOT_SCHEMA_VERSION,
            parent: None,
            lineage,
            active_policy,
            roots,
            transition: None,
            budget_ledger: None,
        })
    }

    /// Builds one immutable successor snapshot and its causal transition.
    ///
    /// Preserves the legacy version-2 encoding until [`Self::with_budget_ledger`]
    /// attaches the version-3 accounting contract. Repository mutations always
    /// attach the authenticated successor ledger before publication.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a root is not a Merkle-node object.
    pub fn successor(
        parent: CampaignSnapshotId,
        lineage: CampaignLineageId,
        active_policy: CampaignPolicyId,
        roots: CampaignRoots,
        transition: CampaignFactId,
    ) -> Result<Self, CampaignCodecError> {
        validate_roots(roots)?;
        Ok(Self {
            schema_version: LEGACY_SNAPSHOT_SCHEMA_VERSION,
            parent: Some(parent),
            lineage,
            active_policy,
            roots,
            transition: Some(transition),
            budget_ledger: None,
        })
    }

    /// Attaches the exact budget ledger and selects the version-3 contract.
    ///
    /// Repository publication authenticates this ledger against the parent and
    /// causal transition. Attaching an arbitrary identity does not authorize
    /// spending or make the snapshot valid.
    #[must_use]
    pub const fn with_budget_ledger(mut self, ledger: crate::CampaignBudgetLedgerId) -> Self {
        self.schema_version = 3;
        self.budget_ledger = Some(ledger);
        self
    }

    /// Returns the indexed budget ledger, absent only in legacy version 2.
    #[must_use]
    pub const fn budget_ledger(&self) -> Option<crate::CampaignBudgetLedgerId> {
        self.budget_ledger
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the linear parent snapshot, if any.
    #[must_use]
    pub const fn parent(&self) -> Option<CampaignSnapshotId> {
        self.parent
    }

    /// Returns the immutable compatibility lineage.
    #[must_use]
    pub const fn lineage(&self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the active policy revision.
    #[must_use]
    pub const fn active_policy(&self) -> CampaignPolicyId {
        self.active_policy
    }

    /// Returns all authoritative snapshot roots.
    #[must_use]
    pub const fn roots(&self) -> CampaignRoots {
        self.roots
    }

    /// Returns the causal control fact for this transition, absent at genesis.
    #[must_use]
    pub const fn transition(&self) -> Option<CampaignFactId> {
        self.transition
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical snapshot bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed or noncanonical input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    /// Returns the domain-separated snapshot identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<CampaignSnapshotId, CampaignCodecError> {
        let content = crate::ObjectEnvelope::for_snapshot(self)?.content_id();
        CampaignSnapshotId::from_content_id(content)
    }

    /// Projects the exact semantic roots a planner may observe.
    #[must_use]
    pub const fn planning_view(&self) -> CampaignPlanningView {
        CampaignPlanningView::from_validated_roots(
            self.roots.graph,
            self.roots.exploration,
            self.roots.observations,
            self.roots.corpus,
            self.roots.coverage,
            self.roots.findings,
            self.roots.accounting,
        )
    }
}

impl Canonical for CampaignSnapshot {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.parent.encode(encoder);
        self.lineage.encode(encoder);
        self.active_policy.encode(encoder);
        self.roots.encode(encoder);
        self.transition.encode(encoder);
        if let Some(ledger) = self.budget_ledger {
            ledger.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let version = u32::decode(decoder)?;
        if !matches!(version, 2 | 3) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported campaign snapshot schema version",
            });
        }
        let parent = Option::decode(decoder)?;
        let lineage = CampaignLineageId::decode(decoder)?;
        let active_policy = CampaignPolicyId::decode(decoder)?;
        let roots = CampaignRoots::decode(decoder)?;
        let transition = Option::decode(decoder)?;
        let snapshot = match (parent, transition) {
            (None, None) => Self::genesis(lineage, active_policy, roots),
            (Some(parent), Some(transition)) => {
                Self::successor(parent, lineage, active_policy, roots, transition)
            }
            _ => Err(CampaignCodecError::InvalidValue {
                reason: "snapshot parent and transition presence disagree",
            }),
        }?;
        if version == 3 {
            Ok(snapshot.with_budget_ledger(crate::CampaignBudgetLedgerId::decode(decoder)?))
        } else {
            Ok(snapshot)
        }
    }
}

/// Complete immutable semantic input roots visible to the planner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CampaignPlanningView {
    schema_version: u32,
    graph: ContentId,
    exploration: ContentId,
    observations: ContentId,
    corpus: ContentId,
    coverage: ContentId,
    findings: ContentId,
    accounting: ContentId,
}

impl CampaignPlanningView {
    /// Builds one complete planning view while excluding pins and placement.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if any root is not a Merkle-node object.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        graph: ContentId,
        exploration: ContentId,
        observations: ContentId,
        corpus: ContentId,
        coverage: ContentId,
        findings: ContentId,
        accounting: ContentId,
    ) -> Result<Self, CampaignCodecError> {
        validate_merkle_roots(&[
            graph,
            exploration,
            observations,
            corpus,
            coverage,
            findings,
            accounting,
        ])?;
        Ok(Self::from_validated_roots(
            graph,
            exploration,
            observations,
            corpus,
            coverage,
            findings,
            accounting,
        ))
    }

    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    const fn from_validated_roots(
        graph: ContentId,
        exploration: ContentId,
        observations: ContentId,
        corpus: ContentId,
        coverage: ContentId,
        findings: ContentId,
        accounting: ContentId,
    ) -> Self {
        Self {
            schema_version: PLANNING_VIEW_SCHEMA_VERSION,
            graph,
            exploration,
            observations,
            corpus,
            coverage,
            findings,
            accounting,
        }
    }

    /// Returns the configuration-graph root.
    #[must_use]
    pub const fn graph(&self) -> ContentId {
        self.graph
    }

    /// Returns the exploration-fact root.
    #[must_use]
    pub const fn exploration(&self) -> ContentId {
        self.exploration
    }

    /// Returns the observation root.
    #[must_use]
    pub const fn observations(&self) -> ContentId {
        self.observations
    }

    /// Returns the mutation-corpus root.
    #[must_use]
    pub const fn corpus(&self) -> ContentId {
        self.corpus
    }

    /// Returns the coverage-union root.
    #[must_use]
    pub const fn coverage(&self) -> ContentId {
        self.coverage
    }

    /// Returns the findings root.
    #[must_use]
    pub const fn findings(&self) -> ContentId {
        self.findings
    }

    /// Returns the accounting and control root.
    #[must_use]
    pub const fn accounting(&self) -> ContentId {
        self.accounting
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Returns the domain-separated planning-view identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<CampaignViewId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlanningView,
            crate::object::content_children(self.content_children())?,
            self.canonical_bytes(),
        )?;
        CampaignViewId::from_content_id(envelope.content_id())
    }

    pub(crate) fn content_children(&self) -> Vec<(&'static str, ContentId)> {
        vec![
            ("root.graph", self.graph),
            ("root.exploration", self.exploration),
            ("root.observations", self.observations),
            ("root.corpus", self.corpus),
            ("root.coverage", self.coverage),
            ("root.findings", self.findings),
            ("root.accounting", self.accounting),
        ]
    }
}

impl Canonical for CampaignPlanningView {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        Canonical::encode(&self.graph, encoder);
        Canonical::encode(&self.exploration, encoder);
        Canonical::encode(&self.observations, encoder);
        Canonical::encode(&self.corpus, encoder);
        Canonical::encode(&self.coverage, encoder);
        Canonical::encode(&self.findings, encoder);
        Canonical::encode(&self.accounting, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(
            u32::decode(decoder)?,
            PLANNING_VIEW_SCHEMA_VERSION,
            "planning-view",
        )?;
        Self::new(
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
        )
    }
}

/// Explicit bounded fuel and output allowance for one planner invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlanningBudget {
    branch_requests: u32,
    proposals: u32,
    input_objects: u32,
    input_bytes: u64,
    fuel: u64,
}

impl PlanningBudget {
    /// Builds a budget with a nonzero bound in every resource dimension.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] if any dimension is zero.
    pub fn new(
        branch_requests: u32,
        proposals: u32,
        input_objects: u32,
        input_bytes: u64,
        fuel: u64,
    ) -> Result<Self, CampaignCodecError> {
        let budget = Self {
            branch_requests,
            proposals,
            input_objects,
            input_bytes,
            fuel,
        };
        budget.validate()?;
        Ok(budget)
    }

    /// Returns the maximum branch requests produced by an invocation.
    #[must_use]
    pub const fn branch_requests(self) -> u32 {
        self.branch_requests
    }

    /// Returns the maximum proposals produced by an invocation.
    #[must_use]
    pub const fn proposals(self) -> u32 {
        self.proposals
    }

    /// Returns the maximum canonical input objects admitted.
    #[must_use]
    pub const fn input_objects(self) -> u32 {
        self.input_objects
    }

    /// Returns the maximum canonical input bytes admitted.
    #[must_use]
    pub const fn input_bytes(self) -> u64 {
        self.input_bytes
    }

    /// Returns the deterministic planner-operation fuel.
    #[must_use]
    pub const fn fuel(self) -> u64 {
        self.fuel
    }

    /// Validates that all resource dimensions are nonzero.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] if any dimension is zero.
    pub fn validate(self) -> Result<(), CampaignCodecError> {
        if self.branch_requests == 0
            || self.proposals == 0
            || self.input_objects == 0
            || self.input_bytes == 0
            || self.fuel == 0
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planning budget contains a zero resource dimension",
            });
        }
        Ok(())
    }
}

impl Canonical for PlanningBudget {
    fn encode(&self, encoder: &mut Encoder) {
        self.branch_requests.encode(encoder);
        self.proposals.encode(encoder);
        self.input_objects.encode(encoder);
        self.input_bytes.encode(encoder);
        self.fuel.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

/// Reproducible identity and capabilities of one pure planner engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerEngine {
    schema_version: u32,
    name: String,
    implementation_version: u32,
    protocol_version: u32,
    capabilities: BTreeSet<String>,
}

impl PlannerEngine {
    /// Builds a closed planner engine descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for invalid identifiers or zero versions.
    pub fn new(
        name: impl Into<String>,
        implementation_version: u32,
        protocol_version: u32,
        capabilities: BTreeSet<String>,
    ) -> Result<Self, CampaignCodecError> {
        let name = name.into();
        validate_identifier(&name, "planner engine name is invalid")?;
        if implementation_version == 0 || protocol_version == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner engine version is zero",
            });
        }
        if capabilities.len() > MAX_VERSION_COMPONENTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "planner-capability-count",
            });
        }
        for capability in &capabilities {
            validate_identifier(capability, "planner capability is invalid")?;
        }
        Ok(Self {
            schema_version: PLANNER_ENGINE_SCHEMA_VERSION,
            name,
            implementation_version,
            protocol_version,
            capabilities,
        })
    }

    /// Returns the stable engine name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the engine implementation version.
    #[must_use]
    pub const fn implementation_version(&self) -> u32 {
        self.implementation_version
    }

    /// Returns the language-neutral planner protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Returns the closed set of advertised semantic capabilities.
    #[must_use]
    pub fn capabilities(&self) -> &BTreeSet<String> {
        &self.capabilities
    }

    /// Returns the domain-separated planner engine identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<PlannerEngineId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerEngine,
            BTreeSet::new(),
            codec::encode(self),
        )?;
        PlannerEngineId::from_content_id(envelope.content_id())
    }
}

impl Canonical for PlannerEngine {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.name.encode(encoder);
        self.implementation_version.encode(encoder);
        self.protocol_version.encode(encoder);
        self.capabilities.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(
            u32::decode(decoder)?,
            PLANNER_ENGINE_SCHEMA_VERSION,
            "planner-engine",
        )?;
        Self::new(
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "planner-engine-name-bytes")?,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            decoder.set_bounded_by(
                MAX_VERSION_COMPONENTS,
                "planner-capability-count",
                |decoder| {
                    decoder.string_bounded(MAX_IDENTIFIER_BYTES, "planner-capability-name-bytes")
                },
            )?,
        )
    }
}

/// Reproducible policy artifact interpreted by one planner engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyArtifact {
    schema_version: u32,
    engine: PlannerEngineId,
    planner_abi: u32,
    dependency_lock: ContentId,
    artifacts: BTreeSet<ContentId>,
    arguments: BTreeMap<String, String>,
}

impl PolicyArtifact {
    /// Builds a bounded portable policy artifact descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for zero ABI, oversized arguments, or
    /// invalid argument names.
    pub fn new(
        engine: PlannerEngineId,
        planner_abi: u32,
        dependency_lock: ContentId,
        artifacts: BTreeSet<ContentId>,
        arguments: BTreeMap<String, String>,
    ) -> Result<Self, CampaignCodecError> {
        if planner_abi == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner ABI version is zero",
            });
        }
        if artifacts.len() > MAX_ARTIFACT_ARGUMENTS || arguments.len() > MAX_ARTIFACT_ARGUMENTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "policy-artifact-entry-count",
            });
        }
        for (name, value) in &arguments {
            validate_identifier(name, "policy artifact argument name is invalid")?;
            validate_identifier(value, "policy artifact argument value is invalid")?;
        }
        let artifact = Self {
            schema_version: POLICY_ARTIFACT_SCHEMA_VERSION,
            engine,
            planner_abi,
            dependency_lock,
            artifacts,
            arguments,
        };
        codec::ensure_encoded_size(
            &artifact,
            MAX_POLICY_ARTIFACT_BYTES,
            "policy-artifact-encoded-bytes",
        )?;
        Ok(artifact)
    }

    /// Returns the engine that interprets this artifact.
    #[must_use]
    pub const fn engine(&self) -> PlannerEngineId {
        self.engine
    }

    /// Returns the planner ABI version.
    #[must_use]
    pub const fn planner_abi(&self) -> u32 {
        self.planner_abi
    }

    /// Returns the exact dependency-lock object.
    #[must_use]
    pub const fn dependency_lock(&self) -> ContentId {
        self.dependency_lock
    }

    /// Returns every source or compiled artifact required to reproduce it.
    #[must_use]
    pub fn artifacts(&self) -> &BTreeSet<ContentId> {
        &self.artifacts
    }

    /// Returns canonical planner arguments.
    #[must_use]
    pub fn arguments(&self) -> &BTreeMap<String, String> {
        &self.arguments
    }

    /// Returns the domain-separated artifact identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<PolicyArtifactId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PolicyArtifact,
            crate::object::content_children(self.content_children())?,
            codec::encode(self),
        )?;
        PolicyArtifactId::from_content_id(envelope.content_id())
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("engine".to_owned(), self.engine.content_id()),
            ("dependency-lock".to_owned(), self.dependency_lock),
        ];
        children.extend(
            self.artifacts
                .iter()
                .enumerate()
                .map(|(index, id)| (format!("artifact.{index:04x}"), *id)),
        );
        children
    }
}

impl Canonical for PolicyArtifact {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.engine.encode(encoder);
        self.planner_abi.encode(encoder);
        Canonical::encode(&self.dependency_lock, encoder);
        self.artifacts.encode(encoder);
        self.arguments.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(
            u32::decode(decoder)?,
            POLICY_ARTIFACT_SCHEMA_VERSION,
            "policy-artifact",
        )?;
        Self::new(
            PlannerEngineId::decode(decoder)?,
            u32::decode(decoder)?,
            ContentId::decode(decoder)?,
            decoder.set_bounded(MAX_ARTIFACT_ARGUMENTS, "policy-artifact-count")?,
            decoder.map_bounded_by(
                MAX_ARTIFACT_ARGUMENTS,
                "policy-artifact-argument-count",
                |decoder| {
                    decoder.string_bounded(MAX_IDENTIFIER_BYTES, "policy-argument-name-bytes")
                },
                |decoder| {
                    decoder.string_bounded(MAX_IDENTIFIER_BYTES, "policy-argument-value-bytes")
                },
            )?,
        )
    }
}

/// Bounded portable planner state, never a serialized native continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerState {
    schema_version: u32,
    engine: PlannerEngineId,
    state_format: String,
    state_format_version: u32,
    bytes: Vec<u8>,
}

impl PlannerState {
    /// Builds bounded portable planner state.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::LimitExceeded`] above one MiB.
    pub fn new(
        engine: PlannerEngineId,
        state_format: impl Into<String>,
        state_format_version: u32,
        bytes: Vec<u8>,
    ) -> Result<Self, CampaignCodecError> {
        let state_format = state_format.into();
        validate_identifier(&state_format, "planner state format is invalid")?;
        if state_format_version == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner state format version is zero",
            });
        }
        if bytes.len() > MAX_PLANNER_STATE_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "planner-state-byte-count",
            });
        }
        Ok(Self {
            schema_version: PLANNER_STATE_SCHEMA_VERSION,
            engine,
            state_format,
            state_format_version,
            bytes,
        })
    }

    /// Returns portable state bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the engine that interprets this state.
    #[must_use]
    pub const fn engine(&self) -> PlannerEngineId {
        self.engine
    }

    /// Returns the stable portable state-format name.
    #[must_use]
    pub fn state_format(&self) -> &str {
        &self.state_format
    }

    /// Returns the portable state-format version.
    #[must_use]
    pub const fn state_format_version(&self) -> u32 {
        self.state_format_version
    }

    /// Returns the domain-separated planner-state identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<PlannerStateId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerState,
            crate::object::content_children([("engine", self.engine.content_id())])?,
            codec::encode(self),
        )?;
        PlannerStateId::from_content_id(envelope.content_id())
    }
}

impl Canonical for PlannerState {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.engine.encode(encoder);
        self.state_format.encode(encoder);
        self.state_format_version.encode(encoder);
        self.bytes.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(
            u32::decode(decoder)?,
            PLANNER_STATE_SCHEMA_VERSION,
            "planner-state",
        )?;
        Self::new(
            PlannerEngineId::decode(decoder)?,
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "planner-state-format-bytes")?,
            u32::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_PLANNER_STATE_BYTES,
                "planner-state-byte-count",
                u8::decode,
            )?,
        )
    }
}

/// Complete immutable basis for one pure planner invocation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlannerInvocation {
    schema_version: u32,
    engine: PlannerEngineId,
    policy_artifact: PolicyArtifactId,
    policy: CampaignPolicyId,
    planner_state: PlannerStateId,
    input_view: CampaignViewId,
    scan_page: PlanningScanPage,
    budget: PlanningBudget,
}

impl PlannerInvocation {
    /// Builds and validates an invocation basis.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when a budget dimension is zero.
    pub fn new(
        engine: PlannerEngineId,
        policy_artifact: PolicyArtifactId,
        policy: CampaignPolicyId,
        planner_state: PlannerStateId,
        input_view: CampaignViewId,
        scan_page: PlanningScanPage,
        budget: PlanningBudget,
    ) -> Result<Self, CampaignCodecError> {
        budget.validate()?;
        Ok(Self {
            schema_version: PLANNER_INVOCATION_SCHEMA_VERSION,
            engine,
            policy_artifact,
            policy,
            planner_state,
            input_view,
            scan_page,
            budget,
        })
    }

    /// Returns the planner implementation identity.
    #[must_use]
    pub const fn engine(&self) -> PlannerEngineId {
        self.engine
    }

    /// Returns the reproducible policy artifact identity.
    #[must_use]
    pub const fn policy_artifact(&self) -> PolicyArtifactId {
        self.policy_artifact
    }

    /// Returns the active campaign policy revision.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the portable pre-invocation state identity.
    #[must_use]
    pub const fn planner_state(&self) -> PlannerStateId {
        self.planner_state
    }

    /// Returns the complete permitted semantic view identity.
    #[must_use]
    pub const fn input_view(&self) -> CampaignViewId {
        self.input_view
    }

    /// Returns the exact bounded continuation page served by the coordinator.
    #[must_use]
    pub const fn scan_page(&self) -> &PlanningScanPage {
        &self.scan_page
    }

    /// Returns the explicit bounded resource allowance.
    #[must_use]
    pub const fn budget(&self) -> PlanningBudget {
        self.budget
    }

    /// Returns the domain-separated invocation identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<PlannerInvocationId, CampaignCodecError> {
        let envelope = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerInvocation,
            crate::object::content_children(self.content_children())?,
            codec::encode(self),
        )?;
        PlannerInvocationId::from_content_id(envelope.content_id())
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("engine".to_owned(), self.engine.content_id()),
            (
                "policy-artifact".to_owned(),
                self.policy_artifact.content_id(),
            ),
            ("policy".to_owned(), self.policy.content_id()),
            ("planner-state".to_owned(), self.planner_state.content_id()),
            ("input-view".to_owned(), self.input_view.content_id()),
        ];
        if let Some(after) = self.scan_page.after() {
            children.push(("scan-after-source".to_owned(), after.source().content_id()));
        }
        children.extend(
            self.scan_page
                .positions()
                .iter()
                .enumerate()
                .map(|(index, position)| {
                    (
                        format!("scan-source.{index:04x}"),
                        position.source().content_id(),
                    )
                }),
        );
        children
    }
}

impl Canonical for PlannerInvocation {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.engine.encode(encoder);
        self.policy_artifact.encode(encoder);
        self.policy.encode(encoder);
        self.planner_state.encode(encoder);
        self.input_view.encode(encoder);
        self.scan_page.encode(encoder);
        self.budget.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(
            u32::decode(decoder)?,
            PLANNER_INVOCATION_SCHEMA_VERSION,
            "planner-invocation",
        )?;
        Self::new(
            PlannerEngineId::decode(decoder)?,
            PolicyArtifactId::decode(decoder)?,
            CampaignPolicyId::decode(decoder)?,
            PlannerStateId::decode(decoder)?,
            CampaignViewId::decode(decoder)?,
            PlanningScanPage::decode(decoder)?,
            PlanningBudget::decode(decoder)?,
        )
    }
}

fn require_schema(
    actual: u32,
    expected: u32,
    _kind: &'static str,
) -> Result<(), CampaignCodecError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported campaign object schema version",
        })
    }
}

fn validate_roots(roots: CampaignRoots) -> Result<(), CampaignCodecError> {
    validate_merkle_roots(&[
        roots.graph,
        roots.exploration,
        roots.observations,
        roots.corpus,
        roots.coverage,
        roots.findings,
        roots.pins,
        roots.accounting,
        roots.coordination,
    ])
}

fn validate_merkle_roots(roots: &[ContentId]) -> Result<(), CampaignCodecError> {
    if roots
        .iter()
        .any(|root| root.kind() != crucible_cas::content_store::ObjectKind::MerkleNode)
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "campaign snapshot root is not a Merkle-node object",
        });
    }
    Ok(())
}
