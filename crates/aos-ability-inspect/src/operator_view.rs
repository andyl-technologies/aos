//! Bounded operator views for interactive deployment inspection.
//!
//! The operator view combines one bounded slice of the immutable desired plan
//! with an optional caller-supplied observation overlay. Plan
//! state and observed state remain separate fields. Frontends can therefore
//! show stale or failed execution without rewriting the desired graph.
//!
//! An operator request has exactly one instance or failing-request focus and
//! selects one of the shared semantic projections. The returned expansion
//! hints are ordinary [`GraphQuery`] values, so terminal, web, and editor
//! clients use the same lazy-expansion contract.
//!
//! ```json
//! {
//!   "schema": "aos.ability.operator-query/v1",
//!   "required_features": [],
//!   "focus": {
//!     "kind": "instance",
//!     "id": {
//!       "environment": {
//!         "authority": "deployment",
//!         "key": "host",
//!         "stage": "host"
//!       },
//!       "key": "nginx"
//!     }
//!   },
//!   "projection": "composition",
//!   "graph": {
//!     "schema": "aos.ability.inspection-query/v1",
//!     "required_features": [],
//!     "roots": [{
//!       "kind": "provider",
//!       "identity": {
//!         "environment": {
//!           "authority": "deployment",
//!           "key": "host",
//!           "stage": "host"
//!         },
//!         "key": "nginx"
//!       }
//!     }],
//!     "direction": "both",
//!     "max_depth": 2,
//!     "max_nodes": 128
//!   }
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use aos_ability_model::{
    ABILITY_LIMITS_V1, EnvironmentId, InstanceId, LocalKey, PlanId, RequestId, RequiredFeature,
    RevisionId,
};
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Direction, GraphQuery, GraphQueryError, GraphSlice, INSPECTION_QUERY_MAX_BYTES,
    INSPECTION_VIEW_MAX_BYTES, INSPECTION_VIEW_MAX_ITEMS, InspectionEdge, InspectionNode,
    InspectionProjection, InspectionProjectionError, InspectionView, NodeKey, ProjectionKind,
    ViewAnchor,
};

/// Exact schema discriminator for one interactive operator query.
pub const OPERATOR_QUERY_SCHEMA: &str = "aos.ability.operator-query/v1";

/// Exact schema discriminator for one caller-supplied observation overlay.
pub const OPERATOR_OBSERVATION_SCHEMA: &str = "aos.ability.operator-observation/v1";

/// Exact schema discriminator for one bounded interactive operator view.
pub const OPERATOR_VIEW_SCHEMA: &str = "aos.ability.operator-view/v1";

/// Maximum canonical bytes accepted for an operator query.
pub const OPERATOR_QUERY_MAX_BYTES: usize = INSPECTION_QUERY_MAX_BYTES;

/// Maximum canonical bytes accepted for an observation overlay.
pub const OPERATOR_OBSERVATION_MAX_BYTES: usize = INSPECTION_VIEW_MAX_BYTES;

/// Maximum canonical bytes emitted for an interactive operator view.
pub const OPERATOR_VIEW_MAX_BYTES: usize = INSPECTION_VIEW_MAX_BYTES.saturating_mul(2);

/// Selects the single stable identity where an interactive view begins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OperatorFocus {
    /// Starts inspection at one deployment instance.
    Instance {
        /// Identifies the selected provider or consumer instance.
        id: InstanceId,
    },
    /// Starts inspection at one request whose failure is being investigated.
    FailingRequest {
        /// Identifies the exact request in the desired plan.
        id: RequestId,
    },
}

impl OperatorFocus {
    /// Returns the shared graph identity used as the bounded-query root.
    #[must_use]
    pub fn node(&self) -> NodeKey {
        match self {
            Self::Instance { id } => NodeKey::Provider(id.clone()),
            Self::FailingRequest { id } => NodeKey::Request(id.clone()),
        }
    }
}

/// Defines one bounded interactive query over a named semantic projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorQuery {
    schema: String,
    required_features: Vec<RequiredFeature>,
    focus: OperatorFocus,
    projection: ProjectionKind,
    graph: GraphQuery,
}

/// Reports why an interactive operator query is not safe to evaluate.
#[derive(Debug, Error)]
pub enum OperatorQueryError {
    /// Bounded strict JSON decoding failed.
    #[error("operator query decoding failed: {0}")]
    Decode(String),
    /// Canonical JSON encoding failed.
    #[error("operator query encoding failed: {0}")]
    Encode(String),
    /// The encoded query exceeds the version-1 byte bound.
    #[error("operator query exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The bytes are valid JSON but are not their canonical representation.
    #[error("operator query is not canonically encoded")]
    NoncanonicalEncoding,
    /// The schema discriminator is unsupported.
    #[error("operator query has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// Version 1 does not support optional query semantics.
    #[error("operator query requires unsupported feature semantics")]
    UnsupportedFeatures,
    /// The embedded graph query violates its bounded contract.
    #[error("operator query contains an invalid graph query: {0}")]
    Graph(#[source] GraphQueryError),
    /// The embedded graph query does not have the selected focus as its only root.
    #[error("operator query focus and graph root are inconsistent")]
    FocusRootMismatch,
}

impl OperatorQuery {
    /// Creates a bidirectional query rooted at one instance or failing request.
    #[must_use]
    pub fn new(
        focus: OperatorFocus,
        projection: ProjectionKind,
        max_depth: usize,
        max_nodes: usize,
    ) -> Self {
        let graph =
            GraphQuery::new([focus.node()], max_depth, max_nodes).with_direction(Direction::Both);
        Self {
            schema: OPERATOR_QUERY_SCHEMA.to_string(),
            required_features: Vec::new(),
            focus,
            projection,
            graph,
        }
    }

    /// Selects how the interactive neighborhood follows typed edges.
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.graph = self.graph.with_direction(direction);
        self
    }

    /// Decodes one strictly bounded canonical operator query.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, noncanonical, unsupported,
    /// or focus-inconsistent input, or when the embedded graph query is invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self, OperatorQueryError> {
        if bytes.len() > OPERATOR_QUERY_MAX_BYTES {
            return Err(OperatorQueryError::EncodedSizeLimit);
        }
        let query = operator_limits(OPERATOR_QUERY_MAX_BYTES)
            .decode::<Self>(bytes, OPERATOR_QUERY_SCHEMA)
            .map_err(|error| OperatorQueryError::Decode(error.to_string()))?;
        query.validate_structure()?;
        if query.encode_canonical()? != bytes {
            return Err(OperatorQueryError::NoncanonicalEncoding);
        }
        Ok(query)
    }

    /// Encodes this query as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the query is invalid, exceeds a version-1 bound,
    /// or cannot be encoded in the canonical AOS JSON dialect.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OperatorQueryError> {
        self.validate_structure()?;
        self.encode_canonical()
    }

    /// Returns the selected instance or failing request.
    #[must_use]
    pub const fn focus(&self) -> &OperatorFocus {
        &self.focus
    }

    /// Returns the selected semantic projection.
    #[must_use]
    pub const fn projection(&self) -> ProjectionKind {
        self.projection
    }

    /// Returns the embedded bounded graph query.
    #[must_use]
    pub const fn graph(&self) -> &GraphQuery {
        &self.graph
    }

    fn validate_structure(&self) -> Result<(), OperatorQueryError> {
        if self.schema != OPERATOR_QUERY_SCHEMA {
            return Err(OperatorQueryError::UnsupportedSchema);
        }
        if !self.required_features.is_empty() {
            return Err(OperatorQueryError::UnsupportedFeatures);
        }
        self.graph
            .canonical_bytes()
            .map_err(OperatorQueryError::Graph)?;
        if self.graph.roots() != [self.focus.node()] {
            return Err(OperatorQueryError::FocusRootMismatch);
        }
        Ok(())
    }

    fn encode_canonical(&self) -> Result<Vec<u8>, OperatorQueryError> {
        let mut writer = BoundedWriter::new(OPERATOR_QUERY_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                OperatorQueryError::EncodedSizeLimit
            } else {
                OperatorQueryError::Encode(error.to_string())
            }
        })?;
        aos_contract::canonical::to_vec(self)
            .map_err(|error| OperatorQueryError::Encode(error.to_string()))
    }
}

/// Names one independent deployment generation axis.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GenerationAxis {
    /// Selects the package-profile generation for an environment.
    PackageProfile,
    /// Selects the materialized configuration generation for an environment.
    Configuration,
    /// Selects the bootable image generation for an environment.
    Image,
    /// Selects one user's independently advanced profile generation.
    UserProfile {
        /// Names the user-scoped generation owner without treating it as a UID.
        user: LocalKey,
    },
}

/// Compares desired and observed revisions on one explicit generation axis.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationObservation {
    /// Identifies the environment owning this generation axis.
    environment: EnvironmentId,
    /// Distinguishes package, configuration, image, and per-user generations.
    axis: GenerationAxis,
    /// Identifies the desired semantic revision.
    desired: RevisionId,
    /// Identifies the observed revision, or records that none was observed.
    observed: Option<RevisionId>,
    /// States whether the independent desired and observed revisions converge.
    convergence: GenerationConvergence,
}

/// Classifies one independent desired/observed generation comparison.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GenerationConvergence {
    /// No observed revision was retained for this axis.
    Unobserved,
    /// The observed revision equals the desired revision.
    Converged,
    /// The observed revision differs from the desired revision.
    Diverged,
}

impl GenerationObservation {
    /// Creates a comparison and derives its convergence classification.
    #[must_use]
    pub fn new(
        environment: EnvironmentId,
        axis: GenerationAxis,
        desired: RevisionId,
        observed: Option<RevisionId>,
    ) -> Self {
        let convergence = generation_convergence(desired, observed);
        Self {
            environment,
            axis,
            desired,
            observed,
            convergence,
        }
    }

    /// Returns the environment owning this generation axis.
    #[must_use]
    pub const fn environment(&self) -> &EnvironmentId {
        &self.environment
    }

    /// Returns the independent generation axis.
    #[must_use]
    pub const fn axis(&self) -> &GenerationAxis {
        &self.axis
    }

    /// Returns the desired semantic revision.
    #[must_use]
    pub const fn desired(&self) -> RevisionId {
        self.desired
    }

    /// Returns the observed revision, when one was retained.
    #[must_use]
    pub const fn observed(&self) -> Option<RevisionId> {
        self.observed
    }

    /// Returns the derived convergence classification.
    #[must_use]
    pub const fn convergence(&self) -> GenerationConvergence {
        self.convergence
    }
}

/// Classifies observed execution evidence without changing desired plan state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservedNodeState {
    /// Retained evidence reports that the subject is currently available.
    Available,
    /// Retained evidence reports a terminal or retained failure.
    Failed,
    /// Evidence exists but is older than its freshness contract permits.
    Stale,
    /// A retained assertion lacks independently authenticated provenance.
    Unverified,
}

/// Associates one stable desired-plan node with caller-supplied execution evidence.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeObservation {
    /// Identifies the exact desired-plan node described by the evidence.
    pub node: NodeKey,
    /// States what the observation establishes.
    pub state: ObservedNodeState,
}

/// Groups observed nodes under one retained transaction identity.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionObservation {
    /// Identifies the retained execution transaction.
    pub transaction: aos_ability_model::TransactionId,
    /// Lists participating desired-plan nodes in stable identity order.
    pub members: Vec<NodeKey>,
}

/// Labels the caller-established provenance of an observation overlay.
///
/// This portable contract validates shape and plan linkage. It does not
/// authenticate the retained source or authorize its disclosure.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OperatorObservationProvenance {
    /// The caller reports the exact evidence object it selected externally.
    CallerAssertedEvidence {
        /// Identifies the caller-selected evidence object.
        evidence: Sha256Digest,
    },
}

/// Carries a caller-supplied live-state overlay for one exact plan.
///
/// The portable constructor checks record shape and graph linkage. Callers must
/// authenticate the evidence source and authorize disclosure independently.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorObservation {
    schema: String,
    required_features: Vec<RequiredFeature>,
    plan: PlanId,
    provenance: OperatorObservationProvenance,
    captured_unix_millis: u64,
    generations: Vec<GenerationObservation>,
    nodes: Vec<NodeObservation>,
    transactions: Vec<TransactionObservation>,
}

/// Reports why an observation overlay cannot be trusted as a bounded contract.
#[derive(Debug, Error)]
pub enum OperatorObservationError {
    /// Bounded strict JSON decoding failed.
    #[error("operator observation decoding failed: {0}")]
    Decode(String),
    /// Canonical JSON encoding failed.
    #[error("operator observation encoding failed: {0}")]
    Encode(String),
    /// The encoded observation exceeds the version-1 byte bound.
    #[error("operator observation exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The bytes are valid JSON but are not their canonical representation.
    #[error("operator observation is not canonically encoded")]
    NoncanonicalEncoding,
    /// The schema discriminator is unsupported.
    #[error("operator observation has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// Version 1 does not support optional observation semantics.
    #[error("operator observation requires unsupported feature semantics")]
    UnsupportedFeatures,
    /// A bounded observation collection exceeds the graph item limit.
    #[error("operator observation exceeds its item limit")]
    ItemLimit,
    /// A stable node has more than one observed state.
    #[error("operator observation repeats a node state")]
    DuplicateNode,
    /// Node observations are not in strict stable-identity order.
    #[error("operator observation node states are not canonically ordered")]
    NoncanonicalNodeOrder,
    /// One environment and generation axis has more than one comparison.
    #[error("operator observation repeats a generation axis")]
    DuplicateGeneration,
    /// Generation comparisons are not in strict environment-and-axis order.
    #[error("operator observation generations are not canonically ordered")]
    NoncanonicalGenerationOrder,
    /// One transaction identity has more than one group.
    #[error("operator observation repeats a transaction")]
    DuplicateTransaction,
    /// Transaction groups are not in strict identity order.
    #[error("operator observation transactions are not canonically ordered")]
    NoncanonicalTransactionOrder,
    /// A transaction repeats one member identity.
    #[error("operator observation transaction repeats a member")]
    DuplicateTransactionMember,
    /// Transaction members are not in strict stable-identity order.
    #[error("operator observation transaction members are not canonically ordered")]
    NoncanonicalTransactionMemberOrder,
    /// A serialized generation convergence value contradicts its revisions.
    #[error("operator observation has an inconsistent generation comparison")]
    InconsistentGenerationComparison,
}

impl OperatorObservation {
    /// Builds a bounded canonical observation overlay for one exact plan.
    ///
    /// Collections are sorted by stable identity. Duplicates fail closed rather
    /// than allowing order-dependent observed state or grouping.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate identities, excessive item or byte size,
    /// or canonical encoding failure.
    pub fn new(
        plan: PlanId,
        evidence: Sha256Digest,
        captured_unix_millis: u64,
        mut generations: Vec<GenerationObservation>,
        mut nodes: Vec<NodeObservation>,
        mut transactions: Vec<TransactionObservation>,
    ) -> Result<Self, OperatorObservationError> {
        generations.sort();
        nodes.sort();
        for transaction in &mut transactions {
            transaction.members.sort();
        }
        transactions.sort();

        let observation = Self {
            schema: OPERATOR_OBSERVATION_SCHEMA.to_string(),
            required_features: Vec::new(),
            plan,
            provenance: OperatorObservationProvenance::CallerAssertedEvidence { evidence },
            captured_unix_millis,
            generations,
            nodes,
            transactions,
        };
        observation.canonical_bytes()?;
        Ok(observation)
    }

    /// Decodes one strictly bounded canonical observation overlay.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, noncanonical, unsupported,
    /// duplicate, or version-limit-exceeding input.
    pub fn decode(bytes: &[u8]) -> Result<Self, OperatorObservationError> {
        if bytes.len() > OPERATOR_OBSERVATION_MAX_BYTES {
            return Err(OperatorObservationError::EncodedSizeLimit);
        }
        let observation = operator_limits(OPERATOR_OBSERVATION_MAX_BYTES)
            .decode::<Self>(bytes, OPERATOR_OBSERVATION_SCHEMA)
            .map_err(|error| OperatorObservationError::Decode(error.to_string()))?;
        observation.validate_structure()?;
        if observation.encode_canonical()? != bytes {
            return Err(OperatorObservationError::NoncanonicalEncoding);
        }
        Ok(observation)
    }

    /// Encodes this observation as bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation violates a version-1 invariant,
    /// exceeds a bound, or cannot be canonically encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OperatorObservationError> {
        self.validate_structure()?;
        self.encode_canonical()
    }

    /// Returns the exact desired effect plan described by this overlay.
    #[must_use]
    pub const fn plan(&self) -> PlanId {
        self.plan
    }

    /// Returns the caller-asserted observation provenance.
    #[must_use]
    pub const fn provenance(&self) -> OperatorObservationProvenance {
        self.provenance
    }

    /// Returns when the retained evidence was captured.
    #[must_use]
    pub const fn captured_unix_millis(&self) -> u64 {
        self.captured_unix_millis
    }

    /// Returns independent desired/observed generation comparisons.
    #[must_use]
    pub fn generations(&self) -> &[GenerationObservation] {
        &self.generations
    }

    /// Returns observed node states in stable identity order.
    #[must_use]
    pub fn nodes(&self) -> &[NodeObservation] {
        &self.nodes
    }

    /// Returns transaction groups in stable identity order.
    #[must_use]
    pub fn transactions(&self) -> &[TransactionObservation] {
        &self.transactions
    }

    fn validate_structure(&self) -> Result<(), OperatorObservationError> {
        if self.schema != OPERATOR_OBSERVATION_SCHEMA {
            return Err(OperatorObservationError::UnsupportedSchema);
        }
        if !self.required_features.is_empty() {
            return Err(OperatorObservationError::UnsupportedFeatures);
        }
        let transaction_members = self.transactions.iter().fold(0usize, |count, transaction| {
            count.saturating_add(transaction.members.len())
        });
        if self.generations.len() > INSPECTION_VIEW_MAX_ITEMS
            || self.nodes.len() > INSPECTION_VIEW_MAX_ITEMS
            || self.transactions.len() > INSPECTION_VIEW_MAX_ITEMS
            || transaction_members > INSPECTION_VIEW_MAX_ITEMS
        {
            return Err(OperatorObservationError::ItemLimit);
        }
        if self.generations.iter().any(|generation| {
            generation.convergence
                != generation_convergence(generation.desired, generation.observed)
        }) {
            return Err(OperatorObservationError::InconsistentGenerationComparison);
        }
        for pair in self.nodes.windows(2) {
            match pair[0].node.cmp(&pair[1].node) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(OperatorObservationError::DuplicateNode);
                }
                std::cmp::Ordering::Greater => {
                    return Err(OperatorObservationError::NoncanonicalNodeOrder);
                }
            }
        }
        for pair in self.generations.windows(2) {
            let before = (&pair[0].environment, &pair[0].axis);
            let after = (&pair[1].environment, &pair[1].axis);
            match before.cmp(&after) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(OperatorObservationError::DuplicateGeneration);
                }
                std::cmp::Ordering::Greater => {
                    return Err(OperatorObservationError::NoncanonicalGenerationOrder);
                }
            }
        }
        for pair in self.transactions.windows(2) {
            match pair[0].transaction.cmp(&pair[1].transaction) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(OperatorObservationError::DuplicateTransaction);
                }
                std::cmp::Ordering::Greater => {
                    return Err(OperatorObservationError::NoncanonicalTransactionOrder);
                }
            }
        }
        for transaction in &self.transactions {
            for pair in transaction.members.windows(2) {
                match pair[0].cmp(&pair[1]) {
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => {
                        return Err(OperatorObservationError::DuplicateTransactionMember);
                    }
                    std::cmp::Ordering::Greater => {
                        return Err(OperatorObservationError::NoncanonicalTransactionMemberOrder);
                    }
                }
            }
        }
        Ok(())
    }

    fn encode_canonical(&self) -> Result<Vec<u8>, OperatorObservationError> {
        let mut writer = BoundedWriter::new(OPERATOR_OBSERVATION_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                OperatorObservationError::EncodedSizeLimit
            } else {
                OperatorObservationError::Encode(error.to_string())
            }
        })?;
        aos_contract::canonical::to_vec(self)
            .map_err(|error| OperatorObservationError::Encode(error.to_string()))
    }
}

/// Gives a stable node an explicit text-renderable operator state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperatorNodeState {
    /// The authenticated contract declares the node without planning it here.
    Declared,
    /// The checked desired graph plans the node or its effect.
    Planned,
    /// Retained evidence reports that the node is available.
    Available,
    /// Planning or retained execution evidence reports a failure.
    Failed,
    /// Retained evidence exists but is outside its freshness contract.
    Stale,
    /// The plan or retained evidence cannot establish the node's state.
    Unverified,
}

/// Keeps checked-plan state separate from an optional execution observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorNodeStatus {
    /// Identifies the exact graph node.
    pub node: NodeKey,
    /// Classifies what the immutable checked plan establishes.
    pub plan_state: OperatorNodeState,
    /// Classifies separately supplied execution evidence, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_state: Option<OperatorNodeState>,
}

/// Names one visual grouping boundary without changing graph identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "identity", rename_all = "kebab-case")]
pub enum OperatorGroupKey {
    /// Groups nodes by their authority-assigned execution environment.
    Environment(EnvironmentId),
    /// Groups requests, bindings, effects, and resources by provider instance.
    Provider(InstanceId),
    /// Groups observed operations under their retained execution transaction.
    Transaction(aos_ability_model::TransactionId),
}

/// Lists stable nodes assigned to one optional frontend grouping boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorGroup {
    /// Identifies the environment, provider, or transaction group.
    pub key: OperatorGroupKey,
    /// Lists visible group members in stable identity order.
    pub members: Vec<NodeKey>,
}

/// Carries operator statuses and visual groups for one assembled graph slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorSliceMetadata {
    statuses: Vec<OperatorNodeStatus>,
    groups: Vec<OperatorGroup>,
}

impl OperatorSliceMetadata {
    /// Returns explicit plan and observed state for every supplied node.
    #[must_use]
    pub fn statuses(&self) -> &[OperatorNodeStatus] {
        &self.statuses
    }

    /// Returns environment, provider, and transaction groups for supplied nodes.
    #[must_use]
    pub fn groups(&self) -> &[OperatorGroup] {
        &self.groups
    }
}

/// Describes graph relationships omitted by the current bounded slice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpansionHint {
    /// Identifies a visible boundary node that has hidden neighbors.
    pub node: NodeKey,
    /// Counts hidden edges directed into the boundary node.
    pub hidden_incoming: usize,
    /// Counts hidden edges directed out of the boundary node.
    pub hidden_outgoing: usize,
    /// Supplies the next direction-specific bounded query for this boundary.
    ///
    /// Its optional exclusive cursor advances through canonical neighbor order.
    pub query: GraphQuery,
}

/// Summarizes the caller-established provenance of an observation overlay.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorObservationSummary {
    /// Retains the explicit caller assertion without treating it as authentication.
    pub provenance: OperatorObservationProvenance,
    /// States when the evidence was captured, without claiming freshness.
    pub captured_unix_millis: u64,
}

/// Owns one bounded interactive view over desired and observed state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorView {
    schema: String,
    required_features: Vec<RequiredFeature>,
    anchor: ViewAnchor,
    plan: PlanId,
    binding_plan: PlanId,
    focus: OperatorFocus,
    projection: ProjectionKind,
    slice: GraphSlice,
    statuses: Vec<OperatorNodeStatus>,
    groups: Vec<OperatorGroup>,
    expansion: Vec<ExpansionHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observation: Option<OperatorObservationSummary>,
    generations: Vec<GenerationObservation>,
}

/// Reports why a bounded interactive operator view cannot be built safely.
#[derive(Debug, Error)]
pub enum OperatorViewError {
    /// The selected semantic projection could not be built.
    #[error("operator view projection failed: {0}")]
    Projection(#[from] InspectionProjectionError),
    /// The bounded graph query could not be evaluated.
    #[error("operator view query failed: {0}")]
    Query(#[from] GraphQueryError),
    /// The operator query violates its own canonical contract.
    #[error("operator view received an invalid operator query: {0}")]
    OperatorQuery(#[from] OperatorQueryError),
    /// The observation overlay violates its own canonical contract.
    #[error("operator view received an invalid observation: {0}")]
    Observation(#[from] OperatorObservationError),
    /// The observation describes another desired plan.
    #[error("operator observation and desired view identify different plans")]
    PlanMismatch,
    /// An observation references a node absent from the checked desired graph.
    #[error("operator observation references an unknown desired-plan node")]
    UnknownObservedNode(Box<NodeKey>),
    /// A transaction references a node absent from the checked desired graph.
    #[error("operator transaction references an unknown desired-plan node")]
    UnknownTransactionNode(Box<NodeKey>),
    /// A generation comparison names an environment absent from the desired graph.
    #[error("operator generation observation references an unknown desired environment")]
    UnknownGenerationEnvironment(Box<EnvironmentId>),
    /// An assembled slice contains a node absent from the selected projection.
    #[error("operator slice contains an unknown or altered projection node")]
    UnknownSliceNode(Box<NodeKey>),
    /// An assembled slice contains an edge absent from the selected projection.
    #[error("operator slice contains an unknown projection edge")]
    UnknownSliceEdge(Box<InspectionEdge>),
    /// An assembled slice edge references a node outside that slice.
    #[error("operator slice contains an edge with a hidden endpoint")]
    DanglingSliceEdge(Box<InspectionEdge>),
    /// A failing-request focus lacks either a plan obligation or failure evidence.
    #[error("operator failing-request focus is not supported by retained failure evidence")]
    FocusedRequestNotFailed(Box<RequestId>),
    /// Canonical operator-view encoding failed.
    #[error("operator view encoding failed: {0}")]
    Encoding(#[source] anyhow::Error),
    /// The operator view exceeds its encoded byte bound.
    #[error("operator view exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The operator view exceeds its item bound.
    #[error("operator view exceeds its item limit")]
    ItemLimit,
}

impl OperatorView {
    /// Builds one interactive slice from a checked view and optional observation.
    ///
    /// The observation is only an overlay: it cannot add nodes or edges and it
    /// never replaces plan state. Callers must authenticate observation bytes
    /// and authorize their disclosure before invoking this constructor.
    ///
    /// # Errors
    ///
    /// Returns an error when the projection or query is invalid, observation
    /// identities do not belong to the desired plan, or the result exceeds a
    /// version-1 item or encoded-byte bound.
    pub fn from_view(
        view: &InspectionView,
        query: &OperatorQuery,
        observation: Option<&OperatorObservation>,
    ) -> Result<Self, OperatorViewError> {
        query.validate_structure()?;
        let projection = view.project(query.projection())?;
        let slice = projection.query(query.graph())?;
        validate_observation(view, observation)?;
        validate_focus(view, query.focus(), observation)?;

        let metadata =
            operator_slice_metadata(&projection, slice.nodes(), slice.edges(), observation)?;
        let visible = slice
            .nodes()
            .iter()
            .map(InspectionNode::key)
            .collect::<BTreeSet<_>>();
        let expansion = projection.continuation_hints(&visible, query.graph().max_nodes())?;
        let generations = observation
            .map(|value| value.generations().to_vec())
            .unwrap_or_default();
        let observation = observation.map(|value| OperatorObservationSummary {
            provenance: value.provenance(),
            captured_unix_millis: value.captured_unix_millis(),
        });

        let operator_view = Self {
            schema: OPERATOR_VIEW_SCHEMA.to_string(),
            required_features: Vec::new(),
            anchor: view.anchor().clone(),
            plan: view.plan(),
            binding_plan: view.binding_plan(),
            focus: query.focus().clone(),
            projection: query.projection(),
            slice,
            statuses: metadata.statuses,
            groups: metadata.groups,
            expansion,
            observation,
            generations,
        };
        operator_view.canonical_bytes()?;
        Ok(operator_view)
    }

    /// Encodes this view as bounded canonical JSON for an interactive client.
    ///
    /// # Errors
    ///
    /// Returns an error if any output collection or the canonical JSON exceeds
    /// its version-1 bound, or if canonical encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OperatorViewError> {
        let group_members = self.groups.iter().fold(0usize, |count, group| {
            count.saturating_add(group.members.len())
        });
        if self.statuses.len() > INSPECTION_VIEW_MAX_ITEMS
            || self.groups.len() > INSPECTION_VIEW_MAX_ITEMS
            || self.expansion.len() > INSPECTION_VIEW_MAX_ITEMS
            || self.generations.len() > INSPECTION_VIEW_MAX_ITEMS
            || group_members > INSPECTION_VIEW_MAX_ITEMS.saturating_mul(3)
        {
            return Err(OperatorViewError::ItemLimit);
        }

        let mut writer = BoundedWriter::new(OPERATOR_VIEW_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                OperatorViewError::EncodedSizeLimit
            } else {
                OperatorViewError::Encoding(error.into())
            }
        })?;
        aos_contract::canonical::to_vec(self).map_err(OperatorViewError::Encoding)
    }

    /// Returns the desired view's source and exact-input integrity status.
    ///
    /// This anchor does not establish that the plan is the current deployment
    /// target or that its policy is authoritative for the reader.
    #[must_use]
    pub const fn anchor(&self) -> &ViewAnchor {
        &self.anchor
    }

    /// Returns the selected focus identity.
    #[must_use]
    pub const fn focus(&self) -> &OperatorFocus {
        &self.focus
    }

    /// Returns the selected semantic projection.
    #[must_use]
    pub const fn projection(&self) -> ProjectionKind {
        self.projection
    }

    /// Returns the bounded desired-plan slice.
    #[must_use]
    pub const fn slice(&self) -> &GraphSlice {
        &self.slice
    }

    /// Returns explicit plan and observed state for every visible node.
    #[must_use]
    pub fn statuses(&self) -> &[OperatorNodeStatus] {
        &self.statuses
    }

    /// Returns optional environment, provider, and transaction groupings.
    #[must_use]
    pub fn groups(&self) -> &[OperatorGroup] {
        &self.groups
    }

    /// Returns lazy-expansion queries for visible boundary nodes.
    #[must_use]
    pub fn expansion(&self) -> &[ExpansionHint] {
        &self.expansion
    }

    /// Returns observation provenance when a live-state overlay was supplied.
    #[must_use]
    pub const fn observation(&self) -> Option<OperatorObservationSummary> {
        self.observation
    }

    /// Returns independent desired/observed generation comparisons.
    #[must_use]
    pub fn generations(&self) -> &[GenerationObservation] {
        &self.generations
    }
}

impl InspectionProjection {
    /// Derives statuses and visual groups for an assembled slice of this projection.
    ///
    /// This supports clients that merge multiple bounded query results. Every
    /// supplied node and edge must be an exact member of this projection, and
    /// every edge endpoint must be present in `nodes`.
    ///
    /// # Errors
    ///
    /// Returns an error if the observation identifies another plan, fails its
    /// structural contract, or if a supplied node or edge is not an exact,
    /// internally closed subset of this projection.
    pub fn operator_slice_metadata(
        &self,
        nodes: &[InspectionNode],
        edges: &[InspectionEdge],
        observation: Option<&OperatorObservation>,
    ) -> Result<OperatorSliceMetadata, OperatorViewError> {
        if let Some(observation) = observation {
            observation.validate_structure()?;
            if observation.plan() != self.plan() {
                return Err(OperatorViewError::PlanMismatch);
            }
        }
        operator_slice_metadata(self, nodes, edges, observation)
    }

    /// Builds direction-specific continuation queries for visible boundaries.
    ///
    /// Each returned cursor follows the longest canonical adjacency prefix
    /// already present in `visible`. Recomputing hints after a page is merged
    /// therefore advances through every neighbor without skipping a gap.
    ///
    /// # Errors
    ///
    /// Returns an error if `query_node_limit` cannot form a valid shared graph
    /// query under the version-1 limits.
    pub fn continuation_hints(
        &self,
        visible: &BTreeSet<NodeKey>,
        query_node_limit: usize,
    ) -> Result<Vec<ExpansionHint>, GraphQueryError> {
        let mut boundaries = BTreeMap::<NodeKey, BoundaryAdjacency>::new();
        for edge in self.edges() {
            if visible.contains(&edge.from) {
                let outgoing = &mut boundaries.entry(edge.from.clone()).or_default().outgoing;
                outgoing.neighbors.insert(edge.to.clone());
                if !visible.contains(&edge.to) {
                    outgoing.hidden_edges += 1;
                }
            }
            if visible.contains(&edge.to) {
                let incoming = &mut boundaries.entry(edge.to.clone()).or_default().incoming;
                incoming.neighbors.insert(edge.from.clone());
                if !visible.contains(&edge.from) {
                    incoming.hidden_edges += 1;
                }
            }
        }

        let mut hints = Vec::new();
        for (node, boundary) in boundaries {
            if boundary.incoming.hidden_edges > 0 {
                hints.push(continuation_hint(
                    &node,
                    Direction::Incoming,
                    &boundary.incoming,
                    visible,
                    query_node_limit,
                )?);
            }
            if boundary.outgoing.hidden_edges > 0 {
                hints.push(continuation_hint(
                    &node,
                    Direction::Outgoing,
                    &boundary.outgoing,
                    visible,
                    query_node_limit,
                )?);
            }
        }
        Ok(hints)
    }
}

fn operator_slice_metadata(
    projection: &InspectionProjection,
    nodes: &[InspectionNode],
    edges: &[InspectionEdge],
    observation: Option<&OperatorObservation>,
) -> Result<OperatorSliceMetadata, OperatorViewError> {
    let projection_nodes = projection
        .nodes()
        .iter()
        .map(|node| (node.key(), node))
        .collect::<BTreeMap<_, _>>();
    if let Some(node) = nodes
        .iter()
        .find(|node| projection_nodes.get(&node.key()).copied() != Some(*node))
    {
        return Err(OperatorViewError::UnknownSliceNode(Box::new(node.key())));
    }

    let visible = nodes
        .iter()
        .map(InspectionNode::key)
        .collect::<BTreeSet<_>>();
    let projection_edges = projection.edges().iter().collect::<BTreeSet<_>>();
    if let Some(edge) = edges.iter().find(|edge| !projection_edges.contains(edge)) {
        return Err(OperatorViewError::UnknownSliceEdge(Box::new(edge.clone())));
    }
    if let Some(edge) = edges
        .iter()
        .find(|edge| !visible.contains(&edge.from) || !visible.contains(&edge.to))
    {
        return Err(OperatorViewError::DanglingSliceEdge(Box::new(edge.clone())));
    }

    let observed_states = observation
        .map(|value| {
            value
                .nodes()
                .iter()
                .map(|node| (node.node.clone(), node.state))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let statuses = nodes
        .iter()
        .map(|node| OperatorNodeStatus {
            node: node.key(),
            plan_state: plan_state(node),
            observed_state: observed_states.get(&node.key()).copied().map(Into::into),
        })
        .collect();
    let groups = operator_groups(nodes, edges, observation);

    Ok(OperatorSliceMetadata { statuses, groups })
}

impl From<ObservedNodeState> for OperatorNodeState {
    fn from(value: ObservedNodeState) -> Self {
        match value {
            ObservedNodeState::Available => Self::Available,
            ObservedNodeState::Failed => Self::Failed,
            ObservedNodeState::Stale => Self::Stale,
            ObservedNodeState::Unverified => Self::Unverified,
        }
    }
}

fn validate_observation(
    view: &InspectionView,
    observation: Option<&OperatorObservation>,
) -> Result<(), OperatorViewError> {
    let Some(observation) = observation else {
        return Ok(());
    };
    observation.validate_structure()?;
    if observation.plan() != view.plan() {
        return Err(OperatorViewError::PlanMismatch);
    }

    let desired_nodes = view
        .nodes()
        .iter()
        .map(InspectionNode::key)
        .collect::<BTreeSet<_>>();
    if let Some(node) = observation
        .nodes()
        .iter()
        .map(|entry| &entry.node)
        .find(|node| !desired_nodes.contains(*node))
    {
        return Err(OperatorViewError::UnknownObservedNode(Box::new(
            node.clone(),
        )));
    }
    if let Some(node) = observation
        .transactions()
        .iter()
        .flat_map(|transaction| &transaction.members)
        .find(|node| !desired_nodes.contains(*node))
    {
        return Err(OperatorViewError::UnknownTransactionNode(Box::new(
            node.clone(),
        )));
    }
    let desired_environments = view
        .nodes()
        .iter()
        .filter_map(node_environment)
        .collect::<BTreeSet<_>>();
    if let Some(environment) = observation
        .generations()
        .iter()
        .map(GenerationObservation::environment)
        .find(|environment| !desired_environments.contains(*environment))
    {
        return Err(OperatorViewError::UnknownGenerationEnvironment(Box::new(
            environment.clone(),
        )));
    }
    Ok(())
}

fn validate_focus(
    view: &InspectionView,
    focus: &OperatorFocus,
    observation: Option<&OperatorObservation>,
) -> Result<(), OperatorViewError> {
    let OperatorFocus::FailingRequest { id } = focus else {
        return Ok(());
    };
    let request = NodeKey::Request(id.clone());
    let plan_failure = view.edges().iter().any(|edge| {
        edge.from == request && edge.relation == crate::InspectionRelation::HasObligation
    });
    let observed_failure = observation.is_some_and(|value| {
        value
            .nodes()
            .iter()
            .any(|node| node.node == request && node.state == ObservedNodeState::Failed)
    });
    if !plan_failure && !observed_failure {
        return Err(OperatorViewError::FocusedRequestNotFailed(Box::new(
            id.clone(),
        )));
    }
    Ok(())
}

fn generation_convergence(
    desired: RevisionId,
    observed: Option<RevisionId>,
) -> GenerationConvergence {
    match observed {
        None => GenerationConvergence::Unobserved,
        Some(observed) if observed.0 == desired.0 => GenerationConvergence::Converged,
        Some(_) => GenerationConvergence::Diverged,
    }
}

fn node_environment(node: &InspectionNode) -> Option<EnvironmentId> {
    match node {
        InspectionNode::Provider { id, .. } => Some(id.environment.clone()),
        InspectionNode::Request { id, .. } => Some(id.consumer.environment.clone()),
        InspectionNode::Binding { provider, .. } => Some(provider.environment.clone()),
        InspectionNode::Aggregate { id } => Some(id.provider.environment.clone()),
        InspectionNode::Resource { id, .. } => Some(id.provider.environment.clone()),
        InspectionNode::Obligation { request, .. } => Some(request.consumer.environment.clone()),
        InspectionNode::Interface { .. }
        | InspectionNode::InterfaceReference { .. }
        | InspectionNode::Package { .. }
        | InspectionNode::Operation { .. }
        | InspectionNode::Decision { .. }
        | InspectionNode::Merge { .. }
        | InspectionNode::Artifact { .. } => None,
    }
}

fn plan_state(node: &InspectionNode) -> OperatorNodeState {
    match node {
        InspectionNode::Interface { .. }
        | InspectionNode::InterfaceReference { .. }
        | InspectionNode::Package { .. }
        | InspectionNode::Request { .. } => OperatorNodeState::Declared,
        InspectionNode::Provider { availability, .. } => match availability {
            crate::view::ProviderAvailability::Declared => OperatorNodeState::Declared,
            crate::view::ProviderAvailability::Planned
            | crate::view::ProviderAvailability::PureComposition => OperatorNodeState::Planned,
            crate::view::ProviderAvailability::Available => OperatorNodeState::Available,
            crate::view::ProviderAvailability::Unavailable => OperatorNodeState::Failed,
            crate::view::ProviderAvailability::Stale => OperatorNodeState::Stale,
            crate::view::ProviderAvailability::Unknown => OperatorNodeState::Unverified,
        },
        InspectionNode::Obligation { .. } => OperatorNodeState::Failed,
        InspectionNode::Binding { .. }
        | InspectionNode::Aggregate { .. }
        | InspectionNode::Operation { .. }
        | InspectionNode::Decision { .. }
        | InspectionNode::Merge { .. }
        | InspectionNode::Artifact { .. }
        | InspectionNode::Resource { .. } => OperatorNodeState::Planned,
    }
}

fn operator_groups(
    nodes: &[InspectionNode],
    edges: &[InspectionEdge],
    observation: Option<&OperatorObservation>,
) -> Vec<OperatorGroup> {
    let visible = nodes
        .iter()
        .map(InspectionNode::key)
        .collect::<BTreeSet<_>>();
    let binding_providers = nodes
        .iter()
        .filter_map(|node| match node {
            InspectionNode::Binding { id, provider, .. } => Some((id.clone(), provider.clone())),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut groups = BTreeMap::<OperatorGroupKey, BTreeSet<NodeKey>>::new();

    for node in nodes {
        let key = node.key();
        for provider in node_providers(node, edges, &binding_providers) {
            groups
                .entry(OperatorGroupKey::Environment(provider.environment.clone()))
                .or_default()
                .insert(key.clone());
            groups
                .entry(OperatorGroupKey::Provider(provider))
                .or_default()
                .insert(key.clone());
        }
    }
    if let Some(observation) = observation {
        for transaction in observation.transactions() {
            let members = transaction
                .members
                .iter()
                .filter(|node| visible.contains(*node))
                .cloned()
                .collect::<BTreeSet<_>>();
            if !members.is_empty() {
                groups.insert(
                    OperatorGroupKey::Transaction(transaction.transaction.clone()),
                    members,
                );
            }
        }
    }

    groups
        .into_iter()
        .map(|(key, members)| OperatorGroup {
            key,
            members: members.into_iter().collect(),
        })
        .collect()
}

fn node_providers(
    node: &InspectionNode,
    edges: &[InspectionEdge],
    binding_providers: &BTreeMap<aos_ability_model::BindingId, InstanceId>,
) -> BTreeSet<InstanceId> {
    let mut providers = BTreeSet::new();
    match node {
        InspectionNode::Provider { id, .. } => {
            providers.insert(id.clone());
        }
        InspectionNode::Request { id, .. } => {
            providers.insert(id.consumer.clone());
        }
        InspectionNode::Binding { provider, .. } => {
            providers.insert(provider.clone());
        }
        InspectionNode::Aggregate { id } => {
            providers.insert(id.provider.clone());
        }
        InspectionNode::Resource { id, .. } => {
            providers.insert(id.provider.clone());
        }
        InspectionNode::Obligation { request, .. } => {
            providers.insert(request.consumer.clone());
        }
        _ => {}
    }

    let key = node.key();
    for edge in edges {
        if edge.from != key && edge.to != key {
            continue;
        }
        let adjacent = if edge.from == key {
            &edge.to
        } else {
            &edge.from
        };
        match adjacent {
            NodeKey::Provider(provider) => {
                providers.insert(provider.clone());
            }
            NodeKey::Binding(binding) => {
                if let Some(provider) = binding_providers.get(binding) {
                    providers.insert(provider.clone());
                }
            }
            _ => {}
        }
    }
    providers
}

#[derive(Default)]
struct BoundaryAdjacency {
    incoming: DirectionalAdjacency,
    outgoing: DirectionalAdjacency,
}

#[derive(Default)]
struct DirectionalAdjacency {
    neighbors: BTreeSet<NodeKey>,
    hidden_edges: usize,
}

fn continuation_hint(
    node: &NodeKey,
    direction: Direction,
    adjacency: &DirectionalAdjacency,
    visible: &BTreeSet<NodeKey>,
    query_node_limit: usize,
) -> Result<ExpansionHint, GraphQueryError> {
    let after = adjacency
        .neighbors
        .iter()
        .take_while(|neighbor| visible.contains(*neighbor))
        .last()
        .cloned();
    let mut query =
        GraphQuery::new([node.clone()], 1, query_node_limit.max(2)).with_direction(direction);
    if let Some(after) = after {
        query = query.with_after(after);
    }
    query.canonical_bytes()?;

    let (hidden_incoming, hidden_outgoing) = match direction {
        Direction::Incoming => (adjacency.hidden_edges, 0),
        Direction::Outgoing => (0, adjacency.hidden_edges),
        Direction::Both => (0, 0),
    };
    Ok(ExpansionHint {
        node: node.clone(),
        hidden_incoming,
        hidden_outgoing,
        query,
    })
}

fn operator_limits(max_bytes: usize) -> JsonLimits {
    JsonLimits {
        max_bytes,
        max_depth: (ABILITY_LIMITS_V1.max_structural_depth as usize).saturating_add(4),
        max_items: INSPECTION_VIEW_MAX_ITEMS,
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    }
}

struct BoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl BoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("operator document exceeds its byte limit"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use aos_ability_model::TransactionId;
    use aos_ability_validate::test_support::checked_effect_plan;

    use super::*;
    use crate::InspectionBundle;

    #[test]
    fn operator_query_round_trip_preserves_single_focus() -> Result<(), Box<dyn std::error::Error>>
    {
        let view = InspectionView::from_checked(&checked_effect_plan())?;
        let provider = first_provider(&view)?;
        let query = OperatorQuery::new(
            OperatorFocus::Instance {
                id: provider.clone(),
            },
            ProjectionKind::Activation,
            2,
            32,
        );

        let bytes = query.canonical_bytes()?;
        let decoded = OperatorQuery::decode(&bytes)?;

        assert_eq!(decoded, query);
        assert_eq!(decoded.graph().roots(), [NodeKey::Provider(provider)]);
        Ok(())
    }

    #[test]
    fn operator_view_separates_plan_and_observed_state_and_groups_transaction()
    -> Result<(), Box<dyn std::error::Error>> {
        let view = InspectionView::from_checked(&checked_effect_plan())?;
        let request = first_request(&view)?;
        let request_key = NodeKey::Request(request.clone());
        let query = OperatorQuery::new(
            OperatorFocus::FailingRequest {
                id: request.clone(),
            },
            ProjectionKind::Composition,
            4,
            64,
        );
        let observation = OperatorObservation::new(
            view.plan(),
            Sha256Digest::of_bytes("authenticated operator observation"),
            1_725_900_000_000,
            vec![GenerationObservation::new(
                request.consumer.environment.clone(),
                GenerationAxis::Configuration,
                RevisionId(Sha256Digest::of_bytes("desired configuration")),
                Some(RevisionId(Sha256Digest::of_bytes("observed configuration"))),
            )],
            vec![NodeObservation {
                node: request_key.clone(),
                state: ObservedNodeState::Failed,
            }],
            vec![TransactionObservation {
                transaction: TransactionId(LocalKey::new("activate-nginx")?),
                members: vec![request_key.clone()],
            }],
        )?;

        let operator = OperatorView::from_view(&view, &query, Some(&observation))?;
        let status = operator
            .statuses()
            .iter()
            .find(|status| status.node == request_key)
            .ok_or("request status missing")?;

        assert_eq!(status.plan_state, OperatorNodeState::Declared);
        assert_eq!(status.observed_state, Some(OperatorNodeState::Failed));
        assert!(operator.groups().iter().any(|group| matches!(
            &group.key,
            OperatorGroupKey::Transaction(transaction)
                if transaction.0.as_str() == "activate-nginx"
        )));
        assert_ne!(
            operator.generations()[0].desired(),
            operator.generations()[0]
                .observed()
                .ok_or("observed generation missing")?
        );
        assert_eq!(
            operator.generations()[0].convergence(),
            GenerationConvergence::Diverged
        );
        let encoded = String::from_utf8(operator.canonical_bytes()?)?;
        assert!(encoded.contains("\"plan_state\":\"declared\""));
        assert!(encoded.contains("\"observed_state\":\"failed\""));
        Ok(())
    }

    #[test]
    fn operator_view_serializes_exact_desired_anchor_without_current_state_claim()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = checked_effect_plan();
        let bundle = InspectionBundle::from_checked(&plan)?;
        let digest = bundle.digest()?;
        let unanchored_view = InspectionView::from_bundle(&bundle.clone().check(None)?)?;
        let anchored_view = InspectionView::from_bundle(&bundle.check(Some(digest))?)?;
        let provider = first_provider(&unanchored_view)?;
        let query = OperatorQuery::new(
            OperatorFocus::Instance { id: provider },
            ProjectionKind::Composition,
            1,
            8,
        );

        let unanchored = OperatorView::from_view(&unanchored_view, &query, None)?;
        let anchored = OperatorView::from_view(&anchored_view, &query, None)?;
        let unanchored_json: serde_json::Value =
            serde_json::from_slice(&unanchored.canonical_bytes()?)?;
        let anchored_json: serde_json::Value =
            serde_json::from_slice(&anchored.canonical_bytes()?)?;

        assert_eq!(unanchored.anchor(), unanchored_view.anchor());
        assert_eq!(anchored.anchor(), anchored_view.anchor());
        assert_eq!(unanchored_json["anchor"]["kind"], "unanchored-bundle");
        assert_eq!(
            anchored_json["anchor"]["kind"],
            "externally-anchored-bundle"
        );
        assert_eq!(unanchored_json["anchor"]["digest"], digest.to_string());
        assert_eq!(anchored_json["anchor"]["digest"], digest.to_string());
        assert!(unanchored_json.get("current").is_none());
        assert!(anchored_json.get("current").is_none());
        assert!(unanchored_json.get("authoritative").is_none());
        assert!(anchored_json.get("authoritative").is_none());
        Ok(())
    }

    #[test]
    fn bounded_slice_exposes_stable_lazy_expansion_queries()
    -> Result<(), Box<dyn std::error::Error>> {
        let view = InspectionView::from_checked(&checked_effect_plan())?;
        let provider = first_provider(&view)?;
        let query = OperatorQuery::new(
            OperatorFocus::Instance { id: provider },
            ProjectionKind::Composition,
            0,
            1,
        );

        let operator = OperatorView::from_view(&view, &query, None)?;
        let projection = view.project(query.projection())?;
        let visible = operator
            .slice()
            .nodes()
            .iter()
            .map(InspectionNode::key)
            .collect::<BTreeSet<_>>();

        assert!(operator.slice().is_truncated());
        assert!(!operator.expansion().is_empty());
        for hint in operator.expansion() {
            assert_eq!(hint.query.roots(), std::slice::from_ref(&hint.node));
            assert_eq!(hint.query.max_depth(), 1);

            let actual_hidden_incoming = projection
                .edges()
                .iter()
                .filter(|edge| edge.to == hint.node && !visible.contains(&edge.from))
                .count();
            let actual_hidden_outgoing = projection
                .edges()
                .iter()
                .filter(|edge| edge.from == hint.node && !visible.contains(&edge.to))
                .count();
            match hint.query.direction() {
                Direction::Incoming => {
                    assert_eq!(hint.hidden_incoming, actual_hidden_incoming);
                    assert!(hint.hidden_incoming > 0);
                    assert_eq!(hint.hidden_outgoing, 0);
                }
                Direction::Outgoing => {
                    assert_eq!(hint.hidden_incoming, 0);
                    assert_eq!(hint.hidden_outgoing, actual_hidden_outgoing);
                    assert!(hint.hidden_outgoing > 0);
                }
                Direction::Both => panic!("continuation queries must be direction-specific"),
            }

            let canonical_query = hint.query.canonical_bytes()?;
            let continuation_query = GraphQuery::decode(&canonical_query)?;
            let continuation = projection.query(&continuation_query)?;
            assert_eq!(continuation.projection(), Some(query.projection()));
            assert!(
                continuation
                    .nodes()
                    .iter()
                    .any(|node| node.key() == hint.node)
            );
            assert!(
                continuation
                    .nodes()
                    .iter()
                    .any(|node| !visible.contains(&node.key()))
            );
        }
        Ok(())
    }

    #[test]
    fn failing_request_focus_requires_retained_failure_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let view = InspectionView::from_checked(&checked_effect_plan())?;
        let request = first_request(&view)?;
        let query = OperatorQuery::new(
            OperatorFocus::FailingRequest {
                id: request.clone(),
            },
            ProjectionKind::Composition,
            2,
            32,
        );

        assert!(matches!(
            OperatorView::from_view(&view, &query, None),
            Err(OperatorViewError::FocusedRequestNotFailed(focused)) if *focused == request
        ));
        Ok(())
    }

    #[test]
    fn overlay_rejects_foreign_nodes_and_plan_identity() -> Result<(), Box<dyn std::error::Error>> {
        let view = InspectionView::from_checked(&checked_effect_plan())?;
        let request = first_request(&view)?;
        let query = OperatorQuery::new(
            OperatorFocus::FailingRequest { id: request },
            ProjectionKind::Composition,
            2,
            32,
        );
        let foreign = NodeKey::Package(Sha256Digest::of_bytes("foreign package"));
        let foreign_node = OperatorObservation::new(
            view.plan(),
            Sha256Digest::of_bytes("observation"),
            1,
            Vec::new(),
            vec![NodeObservation {
                node: foreign.clone(),
                state: ObservedNodeState::Available,
            }],
            Vec::new(),
        )?;
        assert!(matches!(
            OperatorView::from_view(&view, &query, Some(&foreign_node)),
            Err(OperatorViewError::UnknownObservedNode(node)) if *node == foreign
        ));

        let wrong_plan = OperatorObservation::new(
            PlanId(Sha256Digest::of_bytes("another plan")),
            Sha256Digest::of_bytes("observation"),
            1,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?;
        assert!(matches!(
            OperatorView::from_view(&view, &query, Some(&wrong_plan)),
            Err(OperatorViewError::PlanMismatch)
        ));
        Ok(())
    }

    #[test]
    fn observation_decode_rejects_noncanonical_and_duplicate_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let view = InspectionView::from_checked(&checked_effect_plan())?;
        let request = NodeKey::Request(first_request(&view)?);
        let provider_id = first_provider(&view)?;
        let provider = NodeKey::Provider(provider_id.clone());
        let node = NodeObservation {
            node: request,
            state: ObservedNodeState::Unverified,
        };
        let observation = OperatorObservation::new(
            view.plan(),
            Sha256Digest::of_bytes("observation"),
            1,
            Vec::new(),
            vec![node.clone()],
            Vec::new(),
        )?;
        let bytes = observation.canonical_bytes()?;
        assert_eq!(OperatorObservation::decode(&bytes)?, observation);

        let mut noncanonical = b" \n".to_vec();
        noncanonical.extend_from_slice(&bytes);
        assert!(matches!(
            OperatorObservation::decode(&noncanonical),
            Err(OperatorObservationError::NoncanonicalEncoding)
        ));
        assert!(matches!(
            OperatorObservation::new(
                view.plan(),
                Sha256Digest::of_bytes("duplicate"),
                1,
                Vec::new(),
                vec![node.clone(), node.clone()],
                Vec::new(),
            ),
            Err(OperatorObservationError::DuplicateNode)
        ));

        let ordered = OperatorObservation::new(
            view.plan(),
            Sha256Digest::of_bytes("ordering"),
            1,
            Vec::new(),
            vec![
                node.clone(),
                NodeObservation {
                    node: provider,
                    state: ObservedNodeState::Available,
                },
            ],
            Vec::new(),
        )?;
        let mut reordered = serde_json::to_value(ordered)?;
        reordered["nodes"]
            .as_array_mut()
            .ok_or("node observations are not an array")?
            .reverse();
        let reordered = aos_contract::canonical::to_vec(&reordered)?;
        assert!(matches!(
            OperatorObservation::decode(&reordered),
            Err(OperatorObservationError::NoncanonicalNodeOrder)
        ));

        let inconsistent_generation = OperatorObservation::new(
            view.plan(),
            Sha256Digest::of_bytes("generation consistency"),
            1,
            vec![GenerationObservation::new(
                provider_id.environment,
                GenerationAxis::Image,
                RevisionId(Sha256Digest::of_bytes("desired image")),
                Some(RevisionId(Sha256Digest::of_bytes("observed image"))),
            )],
            Vec::new(),
            Vec::new(),
        )?;
        let mut inconsistent_generation = serde_json::to_value(inconsistent_generation)?;
        inconsistent_generation["generations"][0]["convergence"] =
            serde_json::Value::String("converged".to_string());
        let inconsistent_generation = aos_contract::canonical::to_vec(&inconsistent_generation)?;
        assert!(matches!(
            OperatorObservation::decode(&inconsistent_generation),
            Err(OperatorObservationError::InconsistentGenerationComparison)
        ));
        Ok(())
    }

    fn first_provider(view: &InspectionView) -> Result<InstanceId, &'static str> {
        view.nodes()
            .iter()
            .find_map(|node| match node {
                InspectionNode::Provider { id, .. } => Some(id.clone()),
                _ => None,
            })
            .ok_or("provider node missing")
    }

    fn first_request(view: &InspectionView) -> Result<RequestId, &'static str> {
        view.nodes()
            .iter()
            .find_map(|node| match node {
                InspectionNode::Request { id, .. } => Some(id.clone()),
                _ => None,
            })
            .ok_or("request node missing")
    }
}
