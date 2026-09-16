//! Dormant observability APIs and typed effect handoffs.
//!
//! These models make RFC-0021 audit recording, metric export, health reads,
//! and independently enumerated residual inventory constructible without
//! selecting a global recorder, exporter, endpoint, or production worker.

use aos_sandbox_core::ObjectDigest;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

use super::audit_event::CheckedAuditWatchEventV1;
use super::metrics::{
    MAXIMUM_LABELS_PER_OBSERVATION, MAXIMUM_METRIC_OBSERVATIONS, MetricBackendV1,
    MetricCapabilityProfileV1, MetricLabelValueV1, MetricStatusClassV1, MetricValueV1,
    PortableMetricBatchV1, PortableMetricObservationV1, SandboxMetricNameV1,
};
use super::model::{
    AuthorizationRevisionDigestV1, MAXIMUM_OPAQUE_RESPONSE_BYTES, NormalizedQueryDigestV1,
    ObservationSchemaDigestV1, QueryBindingV1, QueryFilterDigestV1, QueryPrincipalDigestV1,
    QuerySortDigestV1, QueryVisibilityDigestV1,
};
use super::resource::PublicResourceTypeV1;

/// Maximum audit rows handed to one dormant observability effect.
pub const MAXIMUM_DORMANT_AUDIT_ROWS_V1: usize = 4_096;
/// Maximum component checks in one health snapshot.
pub const MAXIMUM_DORMANT_HEALTH_CHECKS_V1: usize = 128;
/// Maximum residual rows returned by one bounded inventory call.
pub const MAXIMUM_DORMANT_RESIDUAL_ROWS_V1: usize = 4_096;
/// Maximum bytes in a stable public health code.
pub const MAXIMUM_DORMANT_HEALTH_CODE_BYTES_V1: usize = 128;
/// Maximum consecutive ambiguous sink classifications for one effect stage.
pub const MAXIMUM_DORMANT_OBSERVABILITY_AMBIGUITY_QUERIES_V1: u32 = 3;
/// Maximum canonical content retained in one protected observability record.
pub const MAXIMUM_DORMANT_OBSERVABILITY_CANONICAL_BYTES_V1: usize = 15 * 1024 * 1024;

/// Reports invalid dormant observability input or an injected implementation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantObservabilityErrorV1 {
    /// An identity, generation, sequence, or effect digest uses its zero sentinel.
    #[error("dormant observability input is unspecified")]
    Unspecified,
    /// A bounded collection is oversized, duplicated, or not canonically ordered.
    #[error("dormant observability collection is not canonical")]
    NotCanonical,
    /// A safe public code is empty, oversized, or outside its closed character set.
    #[error("dormant observability public code is invalid")]
    InvalidCode,
    /// An explicitly injected recorder, exporter, or query API rejected the request.
    #[error("dormant observability implementation rejected the request")]
    ImplementationRejected,
}

/// Identifies one bounded public health component.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DormantHealthComponentV1 {
    /// Protected journal provenance and durability.
    Journal,
    /// Controller request admission.
    Controller,
    /// Durable reconciliation progress.
    Reconciler,
    /// Fixed privileged-broker availability.
    Broker,
    /// Runtime backend availability.
    Runtime,
    /// Filesystem-view realization and workers.
    FilesystemView,
    /// Cache admission and residency.
    Cache,
    /// Storage backend and retention.
    Storage,
}

/// Identifies non-collapsed health state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DormantHealthStateV1 {
    /// Current checks prove the component healthy.
    Healthy,
    /// Current checks prove reduced service without violating hard policy.
    Degraded,
    /// The component cannot safely serve its contract.
    Failed,
    /// Current evidence is insufficient.
    Unknown,
}

/// Stores one generation-bound public health check.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DormantHealthCheckV1 {
    component: DormantHealthComponentV1,
    state: DormantHealthStateV1,
    generation: u64,
    safe_code: String,
}

impl DormantHealthCheckV1 {
    /// Constructs one bounded health check.
    ///
    /// # Errors
    ///
    /// Returns [`DormantObservabilityErrorV1`] for generation zero or an unsafe code.
    pub fn new(
        component: DormantHealthComponentV1,
        state: DormantHealthStateV1,
        generation: u64,
        safe_code: String,
    ) -> Result<Self, DormantObservabilityErrorV1> {
        if generation == 0 {
            return Err(DormantObservabilityErrorV1::Unspecified);
        }
        if safe_code.is_empty()
            || safe_code.len() > MAXIMUM_DORMANT_HEALTH_CODE_BYTES_V1
            || !safe_code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(DormantObservabilityErrorV1::InvalidCode);
        }
        Ok(Self {
            component,
            state,
            generation,
            safe_code,
        })
    }

    /// Returns the checked component.
    #[must_use]
    pub const fn component(&self) -> DormantHealthComponentV1 {
        self.component
    }

    /// Returns the component state without collapsing other checks.
    #[must_use]
    pub const fn state(&self) -> DormantHealthStateV1 {
        self.state
    }

    /// Returns the observed configuration/authority generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the bounded public reason code.
    #[must_use]
    pub fn safe_code(&self) -> &str {
        &self.safe_code
    }
}

/// Stores a bounded canonical health response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantHealthSnapshotV1 {
    observation_sequence: u64,
    checks: Vec<DormantHealthCheckV1>,
}

impl DormantHealthSnapshotV1 {
    /// Constructs checks ordered by component with no duplicate component.
    ///
    /// # Errors
    ///
    /// Returns [`DormantObservabilityErrorV1`] for sequence zero or excess,
    /// unordered, duplicate, or empty checks.
    pub fn new(
        observation_sequence: u64,
        checks: Vec<DormantHealthCheckV1>,
    ) -> Result<Self, DormantObservabilityErrorV1> {
        if observation_sequence == 0 {
            return Err(DormantObservabilityErrorV1::Unspecified);
        }
        if checks.is_empty()
            || checks.len() > MAXIMUM_DORMANT_HEALTH_CHECKS_V1
            || !checks
                .windows(2)
                .all(|pair| pair[0].component < pair[1].component)
        {
            Err(DormantObservabilityErrorV1::NotCanonical)
        } else {
            Ok(Self {
                observation_sequence,
                checks,
            })
        }
    }

    /// Returns the producer-owned monotone observation sequence.
    #[must_use]
    pub const fn observation_sequence(&self) -> u64 {
        self.observation_sequence
    }

    /// Returns canonical component checks.
    #[must_use]
    pub fn checks(&self) -> &[DormantHealthCheckV1] {
        &self.checks
    }
}

/// Identifies every independently inventoried residual-resource family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DormantResidualKindV1 {
    /// A process namespace.
    Namespace,
    /// A mounted filesystem object.
    Mount,
    /// A service-manager unit.
    Unit,
    /// A storage dataset or snapshot.
    Dataset,
    /// An ownership or authorization lease.
    Lease,
    /// A UID/GID, network, or capacity allocation.
    Allocation,
    /// A FUSE connection or worker.
    Fuse,
    /// A GC root, cache lease, or content-generation pin.
    CachePin,
}

/// Classifies independently observed residual state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DormantResidualStateV1 {
    /// No durable owner can be resolved.
    Leaked,
    /// The observed object contradicts its durable owner.
    Mismatched,
    /// Ownership cannot be proven and deletion is forbidden.
    Ambiguous,
}

/// Stores one path-free residual inventory row.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DormantResidualResourceV1 {
    kind: DormantResidualKindV1,
    state: DormantResidualStateV1,
    local_identity_digest: ObjectDigest,
    owner_resource_id: Option<[u8; 16]>,
}

impl DormantResidualResourceV1 {
    /// Constructs a residual row using a digest rather than a private host name.
    ///
    /// # Errors
    ///
    /// Returns [`DormantObservabilityErrorV1::Unspecified`] for zero identities.
    pub const fn new(
        kind: DormantResidualKindV1,
        state: DormantResidualStateV1,
        local_identity_digest: ObjectDigest,
        owner_resource_id: Option<[u8; 16]>,
    ) -> Result<Self, DormantObservabilityErrorV1> {
        if local_identity_digest.as_bytes() == &[0; 32]
            || matches!(owner_resource_id, Some([0; 16]))
        {
            Err(DormantObservabilityErrorV1::Unspecified)
        } else {
            Ok(Self {
                kind,
                state,
                local_identity_digest,
                owner_resource_id,
            })
        }
    }

    /// Returns the residual family.
    #[must_use]
    pub const fn kind(&self) -> DormantResidualKindV1 {
        self.kind
    }

    /// Returns the residual classification.
    #[must_use]
    pub const fn state(&self) -> DormantResidualStateV1 {
        self.state
    }

    /// Returns the non-revealing local identity commitment.
    #[must_use]
    pub const fn local_identity_digest(&self) -> ObjectDigest {
        self.local_identity_digest
    }

    /// Returns the resolved portable owner when one exists.
    #[must_use]
    pub const fn owner_resource_id(&self) -> Option<[u8; 16]> {
        self.owner_resource_id
    }
}

/// Stores a bounded canonical residual inventory response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantResidualInventoryV1 {
    inventory_generation: u64,
    observation_sequence: u64,
    resources: Vec<DormantResidualResourceV1>,
}

impl DormantResidualInventoryV1 {
    /// Constructs rows in strict canonical order without duplicates.
    ///
    /// # Errors
    ///
    /// Returns [`DormantObservabilityErrorV1`] for zero counters or excess,
    /// unordered, or duplicate rows.
    pub fn new(
        inventory_generation: u64,
        observation_sequence: u64,
        resources: Vec<DormantResidualResourceV1>,
    ) -> Result<Self, DormantObservabilityErrorV1> {
        if inventory_generation == 0 || observation_sequence == 0 {
            return Err(DormantObservabilityErrorV1::Unspecified);
        }
        if resources.len() > MAXIMUM_DORMANT_RESIDUAL_ROWS_V1
            || !resources.windows(2).all(|pair| pair[0] < pair[1])
        {
            Err(DormantObservabilityErrorV1::NotCanonical)
        } else {
            Ok(Self {
                inventory_generation,
                observation_sequence,
                resources,
            })
        }
    }

    /// Returns the independently enumerated inventory generation.
    #[must_use]
    pub const fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    /// Returns the producer-owned monotone observation sequence.
    #[must_use]
    pub const fn observation_sequence(&self) -> u64 {
        self.observation_sequence
    }

    /// Returns canonical path-free residual rows.
    #[must_use]
    pub fn resources(&self) -> &[DormantResidualResourceV1] {
        &self.resources
    }
}

/// Records structured audit observations through an explicitly supplied implementation.
pub(crate) trait DormantObservationRecorderV1 {
    /// Records or classifies one exact checked audit event idempotently.
    ///
    /// # Errors
    ///
    /// Returns [`DormantObservabilityErrorV1::ImplementationRejected`] when the
    /// supplied recorder cannot retain the observation.
    fn record(
        &mut self,
        query: &DormantObservabilitySinkQueryV1,
        observation: &CheckedAuditWatchEventV1,
    ) -> Result<DormantObservabilitySinkReceiptV1, DormantObservabilityErrorV1>;
}

/// Exports bounded portable metrics through an explicitly supplied implementation.
pub(crate) trait DormantMetricExporterV1 {
    /// Exports or classifies one exact checked metric batch idempotently.
    ///
    /// # Errors
    ///
    /// Returns [`DormantObservabilityErrorV1::ImplementationRejected`] when the
    /// supplied exporter rejects the batch.
    fn export(
        &mut self,
        query: &DormantObservabilitySinkQueryV1,
        metrics: &PortableMetricBatchV1,
    ) -> Result<DormantObservabilitySinkReceiptV1, DormantObservabilityErrorV1>;
}

/// Reads component health through an explicitly supplied dormant API.
pub trait DormantHealthApiV1 {
    /// Returns one bounded non-collapsed health snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`DormantObservabilityErrorV1::ImplementationRejected`] when a
    /// current snapshot cannot be produced.
    fn health(&mut self) -> Result<DormantHealthSnapshotV1, DormantObservabilityErrorV1>;
}

/// Enumerates residual resources through an explicitly supplied dormant API.
pub trait DormantResidualInventoryApiV1 {
    /// Returns one independently observed bounded residual inventory.
    ///
    /// # Errors
    ///
    /// Returns [`DormantObservabilityErrorV1::ImplementationRejected`] when
    /// independent inventory cannot complete.
    fn residual_inventory(
        &mut self,
    ) -> Result<DormantResidualInventoryV1, DormantObservabilityErrorV1>;
}

/// Identifies the exact stage of one idempotent observability effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantObservabilitySinkStageV1 {
    /// Records the zero-based checked audit row.
    AuditRow(u32),
    /// Exports the complete checked metric batch.
    MetricBatch,
}

/// Binds a sink call to one effect and exact stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DormantObservabilitySinkQueryV1 {
    effect_id: ObjectDigest,
    operation_id: [u8; 16],
    resource_type: PublicResourceTypeV1,
    resource_id: [u8; 16],
    resource_version: ObjectDigest,
    stage: DormantObservabilitySinkStageV1,
}

impl DormantObservabilitySinkQueryV1 {
    /// Returns the stable effect identity.
    #[must_use]
    pub const fn effect_id(self) -> ObjectDigest {
        self.effect_id
    }

    /// Returns the exact operation correlated with this sink stage.
    #[must_use]
    pub const fn operation_id(self) -> [u8; 16] {
        self.operation_id
    }

    /// Returns the closed resource family correlated with this sink stage.
    #[must_use]
    pub const fn resource_type(self) -> PublicResourceTypeV1 {
        self.resource_type
    }

    /// Returns the exact resource correlated with this sink stage.
    #[must_use]
    pub const fn resource_id(self) -> [u8; 16] {
        self.resource_id
    }

    /// Returns the canonical commitment of the correlated resource version.
    #[must_use]
    pub const fn resource_version(self) -> ObjectDigest {
        self.resource_version
    }

    /// Returns the exact idempotent sink stage.
    #[must_use]
    pub const fn stage(self) -> DormantObservabilitySinkStageV1 {
        self.stage
    }
}

/// Classifies the authoritative outcome of one exact sink query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantObservabilitySinkDispositionV1 {
    /// The exact stage is durably applied.
    Applied,
    /// The exact stage is authoritatively absent and may be retried.
    NotApplied,
    /// The sink cannot distinguish absent from applied.
    Unknown,
}

/// Seals a sink classification to the exact queried effect stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DormantObservabilitySinkReceiptV1 {
    query: DormantObservabilitySinkQueryV1,
    disposition: DormantObservabilitySinkDispositionV1,
}

impl DormantObservabilitySinkReceiptV1 {
    /// Constructs an exact applied receipt.
    #[must_use]
    pub(crate) const fn applied(query: &DormantObservabilitySinkQueryV1) -> Self {
        Self {
            query: *query,
            disposition: DormantObservabilitySinkDispositionV1::Applied,
        }
    }

    /// Constructs an exact authoritative-absence receipt.
    #[must_use]
    pub(crate) const fn not_applied(query: &DormantObservabilitySinkQueryV1) -> Self {
        Self {
            query: *query,
            disposition: DormantObservabilitySinkDispositionV1::NotApplied,
        }
    }

    /// Constructs an exact ambiguous receipt.
    #[must_use]
    pub(crate) const fn unknown(query: &DormantObservabilitySinkQueryV1) -> Self {
        Self {
            query: *query,
            disposition: DormantObservabilitySinkDispositionV1::Unknown,
        }
    }

    /// Returns the exact effect stage classified by this receipt.
    #[must_use]
    pub const fn query(&self) -> DormantObservabilitySinkQueryV1 {
        self.query
    }

    /// Returns the authoritative sink classification.
    #[must_use]
    pub const fn disposition(&self) -> DormantObservabilitySinkDispositionV1 {
        self.disposition
    }
}

/// Retains the protected health and residual-inventory observation sampled at issuance.
struct DormantObservabilityCurrentObservationV1 {
    health: DormantHealthSnapshotV1,
    residual_inventory: DormantResidualInventoryV1,
}

impl DormantObservabilityCurrentObservationV1 {
    fn new(
        health: DormantHealthSnapshotV1,
        residual_inventory: DormantResidualInventoryV1,
    ) -> Result<Self, DormantObservabilityErrorV1> {
        if health.observation_sequence() != residual_inventory.observation_sequence() {
            return Err(DormantObservabilityErrorV1::NotCanonical);
        }
        Ok(Self {
            health,
            residual_inventory,
        })
    }
}

/// Binds an effect to the exact operation and resource current at issuance.
struct DormantObservabilityEffectContextV1 {
    operation_id: [u8; 16],
    resource_type: PublicResourceTypeV1,
    resource_id: [u8; 16],
    resource_version: Vec<u8>,
    current_observation: DormantObservabilityCurrentObservationV1,
}

/// Retains one bounded recorder/exporter effect before dispatch.
pub(crate) struct DormantObservabilityEffectV1 {
    effect_id: ObjectDigest,
    context: DormantObservabilityEffectContextV1,
    audit: Vec<CheckedAuditWatchEventV1>,
    metrics: PortableMetricBatchV1,
    canonical_content: Vec<u8>,
}

impl DormantObservabilityEffectV1 {
    /// Constructs one canonical correlated observability effect from protected observations.
    ///
    /// # Errors
    ///
    /// Returns [`DormantObservabilityErrorV1`] for unspecified context, excess
    /// content, audit/context disagreement, or non-increasing correlation order.
    fn new(
        operation_id: [u8; 16],
        resource_type: PublicResourceTypeV1,
        resource_id: [u8; 16],
        resource_version: Vec<u8>,
        current_observation: DormantObservabilityCurrentObservationV1,
        audit: Vec<CheckedAuditWatchEventV1>,
        metrics: PortableMetricBatchV1,
    ) -> Result<Self, DormantObservabilityErrorV1> {
        if operation_id == [0; 16]
            || resource_id == [0; 16]
            || resource_version.is_empty()
            || resource_version.len() > MAXIMUM_OPAQUE_RESPONSE_BYTES
        {
            return Err(DormantObservabilityErrorV1::Unspecified);
        }
        if (audit.is_empty() && metrics.as_slice().is_empty())
            || audit.len() > MAXIMUM_DORMANT_AUDIT_ROWS_V1
            || !audit.windows(2).all(|pair| {
                pair[0].event().cursor().binding() == pair[1].event().cursor().binding()
                    && pair[0].event().sequence() < pair[1].event().sequence()
            })
        {
            return Err(DormantObservabilityErrorV1::NotCanonical);
        }

        let context = DormantObservabilityEffectContextV1 {
            operation_id,
            resource_type,
            resource_id,
            resource_version,
            current_observation,
        };
        if audit
            .iter()
            .any(|observation| !audit_observation_matches_context(observation, &context))
        {
            return Err(DormantObservabilityErrorV1::NotCanonical);
        }

        let canonical_content = encode_observability_effect_content(&context, &audit, &metrics)?;
        let effect_id = observability_effect_commitment(&canonical_content);
        Ok(Self {
            effect_id,
            context,
            audit,
            metrics,
            canonical_content,
        })
    }
}

/// Seals a checked observability effect for one explicit composition.
#[must_use = "a dormant observability handoff must be explicitly dispatched or retained"]
pub(crate) struct DormantObservabilityEffectHandoffV1 {
    effect: DormantObservabilityEffectV1,
    next_audit_row: usize,
    ambiguity_queries: u32,
    applied_receipts: Vec<DormantObservabilitySinkReceiptV1>,
}

impl DormantObservabilityEffectHandoffV1 {
    /// Returns the stable effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> ObjectDigest {
        self.effect.effect_id
    }

    /// Returns the checked audit rows.
    #[must_use]
    pub fn audit(&self) -> &[CheckedAuditWatchEventV1] {
        &self.effect.audit
    }

    /// Returns the checked metric batch.
    #[must_use]
    pub const fn metrics(&self) -> &PortableMetricBatchV1 {
        &self.effect.metrics
    }

    /// Returns the first audit row not yet covered by an applied receipt.
    #[must_use]
    pub const fn next_audit_row(&self) -> usize {
        self.next_audit_row
    }

    /// Returns consecutive ambiguous classifications for the current stage.
    #[must_use]
    pub const fn ambiguity_queries(&self) -> u32 {
        self.ambiguity_queries
    }

    /// Returns every exact applied receipt retained before the current stage.
    #[must_use]
    pub fn applied_receipts(&self) -> &[DormantObservabilitySinkReceiptV1] {
        &self.applied_receipts
    }
}

/// Retains exact progress after a sink proves the current stage was not applied.
#[must_use = "a retry token retains an undispatched observability stage"]
pub(crate) struct DormantObservabilityRetryV1(DormantObservabilityEffectHandoffV1);

impl DormantObservabilityRetryV1 {
    /// Returns the exact retained handoff for an idempotent retry.
    #[must_use]
    pub fn into_handoff(self) -> DormantObservabilityEffectHandoffV1 {
        self.0
    }
}

/// Retains exact progress when a sink outcome cannot be classified safely.
#[must_use = "an ambiguity token must be retained until the exact stage is classified"]
pub(crate) struct DormantObservabilityAmbiguityV1 {
    handoff: DormantObservabilityEffectHandoffV1,
    query: DormantObservabilitySinkQueryV1,
}

impl DormantObservabilityAmbiguityV1 {
    /// Returns the exact stage whose applied state remains unknown.
    #[must_use]
    pub const fn query(&self) -> DormantObservabilitySinkQueryV1 {
        self.query
    }

    /// Returns the retained handoff for another idempotent classification query.
    #[must_use]
    pub fn into_handoff(self) -> DormantObservabilityEffectHandoffV1 {
        self.handoff
    }
}

/// Retains an exhausted ambiguous effect without granting another sink call.
#[must_use = "an exhausted ambiguity token requires external operator resolution"]
pub(crate) struct DormantObservabilityAmbiguityExhaustedV1 {
    handoff: DormantObservabilityEffectHandoffV1,
    query: DormantObservabilitySinkQueryV1,
}

impl DormantObservabilityAmbiguityExhaustedV1 {
    /// Returns the effect whose bounded classification budget is exhausted.
    #[must_use]
    pub const fn effect_id(&self) -> ObjectDigest {
        self.handoff.effect.effect_id
    }

    /// Returns the exact unresolved sink stage.
    #[must_use]
    pub const fn query(&self) -> DormantObservabilitySinkQueryV1 {
        self.query
    }

    /// Returns applied receipts retained before the unresolved stage.
    #[must_use]
    pub fn applied_receipts(&self) -> &[DormantObservabilitySinkReceiptV1] {
        &self.handoff.applied_receipts
    }
}

/// Proves that every observability stage has an applied receipt.
pub(crate) struct DormantObservabilityTerminalReceiptV1 {
    effect_id: ObjectDigest,
    recorded_audit_rows: usize,
    metrics_exported: bool,
    applied_receipts: Vec<DormantObservabilitySinkReceiptV1>,
}

impl DormantObservabilityTerminalReceiptV1 {
    /// Returns the completely applied effect identity.
    #[must_use]
    pub const fn effect_id(&self) -> ObjectDigest {
        self.effect_id
    }

    /// Returns the number of audit rows covered by applied receipts.
    #[must_use]
    pub const fn recorded_audit_rows(&self) -> usize {
        self.recorded_audit_rows
    }

    /// Reports whether a nonempty metric batch was covered by an applied receipt.
    #[must_use]
    pub const fn metrics_exported(&self) -> bool {
        self.metrics_exported
    }

    /// Returns the exact applied receipts for every dispatched stage.
    #[must_use]
    pub fn applied_receipts(&self) -> &[DormantObservabilitySinkReceiptV1] {
        &self.applied_receipts
    }
}

/// Returns a terminal receipt or a retained exact retry/ambiguity token.
pub(crate) enum DormantObservabilityDispatchOutcomeV1 {
    /// Every nonempty effect stage is covered by an applied receipt.
    Complete(DormantObservabilityTerminalReceiptV1),
    /// The sink proved the current exact stage absent.
    Retry(DormantObservabilityRetryV1),
    /// The current exact stage remains ambiguous within its bounded budget.
    Ambiguous(DormantObservabilityAmbiguityV1),
    /// The current stage exhausted its bounded ambiguity-query budget.
    AmbiguityExhausted(DormantObservabilityAmbiguityExhaustedV1),
}

/// Composes injected observability implementations without activation or globals.
pub(crate) struct DormantObservabilityCompositionV1<R, E, H, I> {
    recorder: R,
    exporter: E,
    health: H,
    inventory: I,
}

impl<R, E, H, I> DormantObservabilityCompositionV1<R, E, H, I>
where
    R: DormantObservationRecorderV1,
    E: DormantMetricExporterV1,
    H: DormantHealthApiV1,
    I: DormantResidualInventoryApiV1,
{
    /// Constructs a dormant composition without registering an endpoint or worker.
    #[must_use]
    pub(crate) const fn new(recorder: R, exporter: E, health: H, inventory: I) -> Self {
        Self {
            recorder,
            exporter,
            health,
            inventory,
        }
    }

    /// Dispatches a sealed effect to the explicitly injected recorder and exporter.
    ///
    /// Every sink call carries the same effect/stage identity. Partial success
    /// advances only after an exact applied receipt; absence and ambiguity
    /// return tokens retaining the complete undispatched suffix.
    fn dispatch_effect(
        &mut self,
        mut handoff: DormantObservabilityEffectHandoffV1,
    ) -> DormantObservabilityDispatchOutcomeV1 {
        if handoff.ambiguity_queries >= MAXIMUM_DORMANT_OBSERVABILITY_AMBIGUITY_QUERIES_V1 {
            let query = current_observability_sink_query(&handoff);
            return DormantObservabilityDispatchOutcomeV1::AmbiguityExhausted(
                DormantObservabilityAmbiguityExhaustedV1 { handoff, query },
            );
        }
        while handoff.next_audit_row < handoff.effect.audit.len() {
            let query = observability_sink_query(
                &handoff.effect,
                DormantObservabilitySinkStageV1::AuditRow(handoff.next_audit_row as u32),
            );
            let receipt = self
                .recorder
                .record(&query, &handoff.effect.audit[handoff.next_audit_row]);
            match checked_sink_receipt(receipt, query) {
                Some(receipt)
                    if receipt.disposition == DormantObservabilitySinkDispositionV1::Applied =>
                {
                    handoff.next_audit_row += 1;
                    handoff.ambiguity_queries = 0;
                    handoff.applied_receipts.push(receipt);
                }
                Some(receipt)
                    if receipt.disposition == DormantObservabilitySinkDispositionV1::NotApplied =>
                {
                    handoff.ambiguity_queries = 0;
                    return DormantObservabilityDispatchOutcomeV1::Retry(
                        DormantObservabilityRetryV1(handoff),
                    );
                }
                Some(_) | None => {
                    return ambiguous_observability_outcome(handoff, query);
                }
            }
        }
        if handoff.effect.metrics.as_slice().is_empty() {
            return DormantObservabilityDispatchOutcomeV1::Complete(
                DormantObservabilityTerminalReceiptV1 {
                    effect_id: handoff.effect.effect_id,
                    recorded_audit_rows: handoff.next_audit_row,
                    metrics_exported: false,
                    applied_receipts: handoff.applied_receipts,
                },
            );
        }
        let query = observability_sink_query(
            &handoff.effect,
            DormantObservabilitySinkStageV1::MetricBatch,
        );
        match checked_sink_receipt(self.exporter.export(&query, &handoff.effect.metrics), query) {
            Some(receipt)
                if receipt.disposition == DormantObservabilitySinkDispositionV1::Applied =>
            {
                handoff.applied_receipts.push(receipt);
                DormantObservabilityDispatchOutcomeV1::Complete(
                    DormantObservabilityTerminalReceiptV1 {
                        effect_id: handoff.effect.effect_id,
                        recorded_audit_rows: handoff.next_audit_row,
                        metrics_exported: true,
                        applied_receipts: handoff.applied_receipts,
                    },
                )
            }
            Some(receipt)
                if receipt.disposition == DormantObservabilitySinkDispositionV1::NotApplied =>
            {
                handoff.ambiguity_queries = 0;
                DormantObservabilityDispatchOutcomeV1::Retry(DormantObservabilityRetryV1(handoff))
            }
            Some(_) | None => ambiguous_observability_outcome(handoff, query),
        }
    }

    /// Queries the explicitly injected health API.
    ///
    /// # Errors
    ///
    /// Returns the injected API's checked failure.
    pub fn health(&mut self) -> Result<DormantHealthSnapshotV1, DormantObservabilityErrorV1> {
        self.health.health()
    }

    /// Queries the explicitly injected independent residual inventory.
    ///
    /// # Errors
    ///
    /// Returns the injected API's checked failure.
    pub fn residual_inventory(
        &mut self,
    ) -> Result<DormantResidualInventoryV1, DormantObservabilityErrorV1> {
        self.inventory.residual_inventory()
    }

    /// Dismantles the dormant composition into its injected implementations.
    #[must_use]
    pub fn into_parts(self) -> (R, E, H, I) {
        (self.recorder, self.exporter, self.health, self.inventory)
    }
}

fn checked_sink_receipt(
    receipt: Result<DormantObservabilitySinkReceiptV1, DormantObservabilityErrorV1>,
    query: DormantObservabilitySinkQueryV1,
) -> Option<DormantObservabilitySinkReceiptV1> {
    receipt.ok().filter(|receipt| receipt.query == query)
}

fn ambiguous_observability_outcome(
    mut handoff: DormantObservabilityEffectHandoffV1,
    query: DormantObservabilitySinkQueryV1,
) -> DormantObservabilityDispatchOutcomeV1 {
    handoff.ambiguity_queries = handoff.ambiguity_queries.saturating_add(1);
    let exhausted = handoff.ambiguity_queries >= MAXIMUM_DORMANT_OBSERVABILITY_AMBIGUITY_QUERIES_V1;
    if exhausted {
        DormantObservabilityDispatchOutcomeV1::AmbiguityExhausted(
            DormantObservabilityAmbiguityExhaustedV1 { handoff, query },
        )
    } else {
        DormantObservabilityDispatchOutcomeV1::Ambiguous(DormantObservabilityAmbiguityV1 {
            handoff,
            query,
        })
    }
}

fn current_observability_sink_query(
    handoff: &DormantObservabilityEffectHandoffV1,
) -> DormantObservabilitySinkQueryV1 {
    let stage = if handoff.next_audit_row < handoff.effect.audit.len() {
        DormantObservabilitySinkStageV1::AuditRow(handoff.next_audit_row as u32)
    } else {
        DormantObservabilitySinkStageV1::MetricBatch
    };
    observability_sink_query(&handoff.effect, stage)
}

fn observability_sink_query(
    effect: &DormantObservabilityEffectV1,
    stage: DormantObservabilitySinkStageV1,
) -> DormantObservabilitySinkQueryV1 {
    DormantObservabilitySinkQueryV1 {
        effect_id: effect.effect_id,
        operation_id: effect.context.operation_id,
        resource_type: effect.context.resource_type,
        resource_id: effect.context.resource_id,
        resource_version: observability_resource_version_commitment(
            &effect.context.resource_version,
        ),
        stage,
    }
}

const OBSERVABILITY_PROGRESS_MAGIC_V1: &[u8; 8] = b"AOSOBS01";
const OBSERVABILITY_PROGRESS_PREFIX_V1: &[u8] = b"observability/";

/// Owns durable dormant observability progress in the protected effect namespace.
pub(crate) struct DormantObservabilityProtectedOwnerV1<'journal> {
    journal: &'journal mut Journal,
}

/// Retains sink outcome custody when progress commit success is not knowable.
pub(crate) enum DormantObservabilityDurableOutcomeV1 {
    /// Protected progress agrees with the returned sink outcome.
    Committed(DormantObservabilityDispatchOutcomeV1),
    /// The sink outcome is retained while protected progress is ambiguous.
    JournalAmbiguous(DormantObservabilityDispatchOutcomeV1),
    /// Protected progress no longer matches the submitted handoff; no sink ran.
    Rejected(DormantObservabilityEffectHandoffV1),
}

/// Composes protected progress ownership with explicitly selected dormant sinks.
pub(crate) struct DormantObservabilityServiceV1<'journal, R, E, H, I> {
    owner: DormantObservabilityProtectedOwnerV1<'journal>,
    composition: DormantObservabilityCompositionV1<R, E, H, I>,
}

impl<'journal, R, E, H, I> DormantObservabilityServiceV1<'journal, R, E, H, I>
where
    R: DormantObservationRecorderV1,
    E: DormantMetricExporterV1,
    H: DormantHealthApiV1,
    I: DormantResidualInventoryApiV1,
{
    /// Constructs the unregistered service around the controller journal and selected sinks.
    pub(crate) const fn new(
        journal: &'journal mut Journal,
        recorder: R,
        exporter: E,
        health: H,
        inventory: I,
    ) -> Self {
        Self {
            owner: DormantObservabilityProtectedOwnerV1::new(journal),
            composition: DormantObservabilityCompositionV1::new(
                recorder, exporter, health, inventory,
            ),
        }
    }

    /// Collects and validates current component health through the selected provider.
    ///
    /// # Errors
    ///
    /// Returns the provider's checked failure.
    pub(crate) fn health(
        &mut self,
    ) -> Result<DormantHealthSnapshotV1, DormantObservabilityErrorV1> {
        self.composition.health()
    }

    /// Collects and validates current residual inventory through the selected provider.
    ///
    /// # Errors
    ///
    /// Returns the provider's checked failure.
    pub(crate) fn residual_inventory(
        &mut self,
    ) -> Result<DormantResidualInventoryV1, DormantObservabilityErrorV1> {
        self.composition.residual_inventory()
    }

    /// Collects current observations and durably issues exact effect content.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid context, mismatched audit rows, uncorrelated
    /// current observations, oversized canonical content, or journal failure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_current(
        &mut self,
        operation_id: [u8; 16],
        resource_type: PublicResourceTypeV1,
        resource_id: [u8; 16],
        resource_version: Vec<u8>,
        audit: Vec<CheckedAuditWatchEventV1>,
        metrics: PortableMetricBatchV1,
    ) -> Result<DormantObservabilityEffectHandoffV1, DormantObservabilityErrorV1> {
        let health = self.health()?;
        let residual_inventory = self.residual_inventory()?;
        let current_observation =
            DormantObservabilityCurrentObservationV1::new(health, residual_inventory)?;
        let effect = DormantObservabilityEffectV1::new(
            operation_id,
            resource_type,
            resource_id,
            resource_version,
            current_observation,
            audit,
            metrics,
        )?;
        self.owner.prepare(effect)
    }

    /// Dispatches only through the protected progress reducer.
    pub(crate) fn dispatch(
        &mut self,
        handoff: DormantObservabilityEffectHandoffV1,
    ) -> DormantObservabilityDurableOutcomeV1 {
        self.owner.dispatch(&mut self.composition, handoff)
    }

    /// Reopens exact cold progress from its protected canonical content.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected record is absent, malformed, or does
    /// not match its content-derived effect identity.
    pub(crate) fn reopen(
        &mut self,
        effect_id: ObjectDigest,
    ) -> Result<DormantObservabilityEffectHandoffV1, DormantObservabilityErrorV1> {
        self.owner.reopen(effect_id)
    }

    /// Enumerates pending cold-recovery identities.
    ///
    /// # Errors
    ///
    /// Returns an error when protected authority or any pending record is invalid.
    pub(crate) fn pending_effects(&self) -> Result<Vec<ObjectDigest>, DormantObservabilityErrorV1> {
        self.owner.pending_effects()
    }
}

impl<'journal> DormantObservabilityProtectedOwnerV1<'journal> {
    /// Constructs the dormant owner only around the controller's protected journal.
    pub(crate) const fn new(journal: &'journal mut Journal) -> Self {
        Self { journal }
    }

    /// Durably issues a checked effect before any sink may observe it.
    pub(crate) fn prepare(
        &mut self,
        effect: DormantObservabilityEffectV1,
    ) -> Result<DormantObservabilityEffectHandoffV1, DormantObservabilityErrorV1> {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| DormantObservabilityErrorV1::ImplementationRejected)?;
        let handoff = DormantObservabilityEffectHandoffV1 {
            effect,
            next_audit_row: 0,
            ambiguity_queries: 0,
            applied_receipts: Vec::new(),
        };
        if let Some(encoded) = self.journal.get(
            RecordNamespace::Effect,
            &observability_progress_key(handoff.effect.effect_id),
        ) {
            return decode_observability_progress(handoff.effect.effect_id, encoded);
        }
        self.persist_handoff(&handoff)?;
        Ok(handoff)
    }

    /// Reopens exact cold progress by decoding protected committed effect content.
    pub(crate) fn reopen(
        &mut self,
        effect_id: ObjectDigest,
    ) -> Result<DormantObservabilityEffectHandoffV1, DormantObservabilityErrorV1> {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| DormantObservabilityErrorV1::ImplementationRejected)?;
        let encoded = self
            .journal
            .get(
                RecordNamespace::Effect,
                &observability_progress_key(effect_id),
            )
            .ok_or(DormantObservabilityErrorV1::ImplementationRejected)?;
        decode_observability_progress(effect_id, encoded)
    }

    /// Enumerates exact pending effect identities for cold producer replay.
    pub(crate) fn pending_effects(&self) -> Result<Vec<ObjectDigest>, DormantObservabilityErrorV1> {
        self.journal
            .ensure_protected_authority()
            .map_err(|_| DormantObservabilityErrorV1::ImplementationRejected)?;
        let mut pending = Vec::new();
        for (key, encoded) in self.journal.records(RecordNamespace::Effect) {
            let Some(digest) = key.strip_prefix(OBSERVABILITY_PROGRESS_PREFIX_V1) else {
                continue;
            };
            let digest: [u8; 32] = digest
                .try_into()
                .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?;
            let effect_id = ObjectDigest::from_bytes(digest);
            validate_observability_progress_identity(effect_id, encoded)?;
            pending.push(effect_id);
        }
        Ok(pending)
    }

    /// Dispatches from durable progress and retains custody across commit ambiguity.
    pub(crate) fn dispatch<R, E, H, I>(
        &mut self,
        composition: &mut DormantObservabilityCompositionV1<R, E, H, I>,
        handoff: DormantObservabilityEffectHandoffV1,
    ) -> DormantObservabilityDurableOutcomeV1
    where
        R: DormantObservationRecorderV1,
        E: DormantMetricExporterV1,
        H: DormantHealthApiV1,
        I: DormantResidualInventoryApiV1,
    {
        let effect_id = handoff.effect.effect_id;
        if !self.handoff_is_current(&handoff) {
            return DormantObservabilityDurableOutcomeV1::Rejected(handoff);
        }
        let outcome = composition.dispatch_effect(handoff);
        let persisted = match retained_observability_handoff(&outcome) {
            Some(retained) => self.persist_handoff(retained),
            None => self.clear_progress(effect_id),
        };
        if persisted.is_ok() {
            DormantObservabilityDurableOutcomeV1::Committed(outcome)
        } else {
            DormantObservabilityDurableOutcomeV1::JournalAmbiguous(outcome)
        }
    }

    fn persist_handoff(
        &mut self,
        handoff: &DormantObservabilityEffectHandoffV1,
    ) -> Result<(), DormantObservabilityErrorV1> {
        commit_observability_progress(
            self.journal,
            handoff.effect.effect_id,
            JournalRecord::put(
                RecordNamespace::Effect,
                observability_progress_key(handoff.effect.effect_id),
                encode_observability_progress(handoff)?,
            ),
        )
    }

    fn clear_progress(
        &mut self,
        effect_id: ObjectDigest,
    ) -> Result<(), DormantObservabilityErrorV1> {
        commit_observability_progress(
            self.journal,
            effect_id,
            JournalRecord::delete(
                RecordNamespace::Effect,
                observability_progress_key(effect_id),
            ),
        )
    }

    fn handoff_is_current(&self, handoff: &DormantObservabilityEffectHandoffV1) -> bool {
        if self.journal.ensure_protected_authority().is_err() {
            return false;
        }
        let Ok(expected) = encode_observability_progress(handoff) else {
            return false;
        };
        self.journal.get(
            RecordNamespace::Effect,
            &observability_progress_key(handoff.effect.effect_id),
        ) == Some(expected.as_slice())
    }
}

fn retained_observability_handoff(
    outcome: &DormantObservabilityDispatchOutcomeV1,
) -> Option<&DormantObservabilityEffectHandoffV1> {
    match outcome {
        DormantObservabilityDispatchOutcomeV1::Complete(_) => None,
        DormantObservabilityDispatchOutcomeV1::Retry(value) => Some(&value.0),
        DormantObservabilityDispatchOutcomeV1::Ambiguous(value) => Some(&value.handoff),
        DormantObservabilityDispatchOutcomeV1::AmbiguityExhausted(value) => Some(&value.handoff),
    }
}

fn observability_progress_key(effect_id: ObjectDigest) -> Vec<u8> {
    [OBSERVABILITY_PROGRESS_PREFIX_V1, effect_id.as_bytes()].concat()
}

fn encode_observability_progress(
    handoff: &DormantObservabilityEffectHandoffV1,
) -> Result<Vec<u8>, DormantObservabilityErrorV1> {
    let next = u32::try_from(handoff.next_audit_row)
        .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?;
    let count = u32::try_from(handoff.applied_receipts.len())
        .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?;
    let content_length = u32::try_from(handoff.effect.canonical_content.len())
        .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?;
    let mut encoded = Vec::with_capacity(
        56 + handoff.effect.canonical_content.len() + handoff.applied_receipts.len() * 6,
    );
    encoded.extend_from_slice(OBSERVABILITY_PROGRESS_MAGIC_V1);
    encoded.extend_from_slice(handoff.effect.effect_id.as_bytes());
    encoded.extend_from_slice(&content_length.to_be_bytes());
    encoded.extend_from_slice(&handoff.effect.canonical_content);
    encoded.extend_from_slice(&next.to_be_bytes());
    encoded.extend_from_slice(&handoff.ambiguity_queries.to_be_bytes());
    encoded.extend_from_slice(&count.to_be_bytes());
    for receipt in &handoff.applied_receipts {
        let (stage, index) = match receipt.query.stage {
            DormantObservabilitySinkStageV1::AuditRow(index) => (1_u8, index),
            DormantObservabilitySinkStageV1::MetricBatch => (2_u8, 0),
        };
        encoded.push(stage);
        encoded.extend_from_slice(&index.to_be_bytes());
        encoded.push(match receipt.disposition {
            DormantObservabilitySinkDispositionV1::Applied => 1,
            DormantObservabilitySinkDispositionV1::NotApplied => 2,
            DormantObservabilitySinkDispositionV1::Unknown => 3,
        });
    }
    Ok(encoded)
}

fn decode_observability_progress(
    expected_effect_id: ObjectDigest,
    encoded: &[u8],
) -> Result<DormantObservabilityEffectHandoffV1, DormantObservabilityErrorV1> {
    let mut reader = CanonicalReaderV1::new(encoded);
    if reader.take(8)? != OBSERVABILITY_PROGRESS_MAGIC_V1 {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let embedded_effect_id = reader.digest()?;
    if embedded_effect_id != expected_effect_id {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let canonical_content = reader.length_prefixed()?.to_vec();
    let effect = decode_observability_effect_content(expected_effect_id, &canonical_content)?;
    let next_audit_row = reader.u32()? as usize;
    let ambiguity_queries = reader.u32()?;
    let count = reader.u32()? as usize;
    if reader.remaining() != count.saturating_mul(6)
        || next_audit_row > effect.audit.len()
        || count != next_audit_row
        || ambiguity_queries > MAXIMUM_DORMANT_OBSERVABILITY_AMBIGUITY_QUERIES_V1
    {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let mut applied_receipts = Vec::with_capacity(count);
    for expected_index in 0..count {
        let stage = match reader.u8()? {
            1 => {
                let index = reader.u32()?;
                if index as usize != expected_index {
                    return Err(DormantObservabilityErrorV1::NotCanonical);
                }
                DormantObservabilitySinkStageV1::AuditRow(index)
            }
            _ => return Err(DormantObservabilityErrorV1::NotCanonical),
        };
        if reader.u8()? != 1 {
            return Err(DormantObservabilityErrorV1::NotCanonical);
        }
        applied_receipts.push(DormantObservabilitySinkReceiptV1 {
            query: observability_sink_query(&effect, stage),
            disposition: DormantObservabilitySinkDispositionV1::Applied,
        });
    }
    reader.finish()?;
    Ok(DormantObservabilityEffectHandoffV1 {
        effect,
        next_audit_row,
        ambiguity_queries,
        applied_receipts,
    })
}

fn validate_observability_progress_identity(
    effect_id: ObjectDigest,
    encoded: &[u8],
) -> Result<(), DormantObservabilityErrorV1> {
    decode_observability_progress(effect_id, encoded).map(|_| ())
}

const OBSERVABILITY_CONTENT_MAGIC_V1: &[u8; 8] = b"AOSOBSC1";
const OBSERVABILITY_CURRENT_MAGIC_V1: &[u8; 8] = b"AOSOBSO1";

fn observability_effect_commitment(canonical_content: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.observability-effect-content.v1\0")
            .chain_update(canonical_content)
            .finalize()
            .into(),
    )
}

fn observability_resource_version_commitment(resource_version: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.observability-resource-version.v1\0")
            .chain_update((resource_version.len() as u64).to_be_bytes())
            .chain_update(resource_version)
            .finalize()
            .into(),
    )
}

fn encode_observability_effect_content(
    context: &DormantObservabilityEffectContextV1,
    audit: &[CheckedAuditWatchEventV1],
    metrics: &PortableMetricBatchV1,
) -> Result<Vec<u8>, DormantObservabilityErrorV1> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(OBSERVABILITY_CONTENT_MAGIC_V1);
    encoded.extend_from_slice(&context.operation_id);
    encoded.push(resource_type_tag(context.resource_type));
    encoded.extend_from_slice(&context.resource_id);
    push_length_prefixed(&mut encoded, &context.resource_version)?;

    let current = encode_current_observation(&context.current_observation)?;
    push_length_prefixed(&mut encoded, &current)?;
    push_u32(&mut encoded, audit.len())?;
    for observation in audit {
        encode_query_binding(&mut encoded, observation.event().cursor().binding());
        push_length_prefixed(
            &mut encoded,
            &observation.event().full_proto().encode_to_vec(),
        )?;
    }
    push_u32(&mut encoded, metrics.as_slice().len())?;
    for observation in metrics.as_slice() {
        encode_metric_observation(&mut encoded, observation)?;
    }
    if encoded.len() > MAXIMUM_DORMANT_OBSERVABILITY_CANONICAL_BYTES_V1 {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    Ok(encoded)
}

fn decode_observability_effect_content(
    effect_id: ObjectDigest,
    canonical_content: &[u8],
) -> Result<DormantObservabilityEffectV1, DormantObservabilityErrorV1> {
    if canonical_content.len() > MAXIMUM_DORMANT_OBSERVABILITY_CANONICAL_BYTES_V1
        || observability_effect_commitment(canonical_content) != effect_id
    {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let mut reader = CanonicalReaderV1::new(canonical_content);
    if reader.take(8)? != OBSERVABILITY_CONTENT_MAGIC_V1 {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let operation_id = reader.array_16()?;
    let resource_type = decode_resource_type(reader.u8()?)?;
    let resource_id = reader.array_16()?;
    let resource_version = reader.length_prefixed()?.to_vec();
    let current_observation = decode_current_observation(reader.length_prefixed()?)?;

    let audit_count = reader.u32()? as usize;
    if audit_count > MAXIMUM_DORMANT_AUDIT_ROWS_V1 {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let mut audit = Vec::with_capacity(audit_count);
    for _ in 0..audit_count {
        let binding = decode_query_binding(&mut reader)?;
        let wire = aos_proto::aos::sandbox::v1::Event::decode(reader.length_prefixed()?)
            .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?;
        audit.push(
            CheckedAuditWatchEventV1::from_response(binding, wire)
                .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?,
        );
    }
    let metric_count = reader.u32()? as usize;
    if metric_count > MAXIMUM_METRIC_OBSERVATIONS {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let mut metric_observations = Vec::with_capacity(metric_count);
    for _ in 0..metric_count {
        metric_observations.push(decode_metric_observation(&mut reader)?);
    }
    reader.finish()?;
    let metrics = PortableMetricBatchV1::new(metric_observations)
        .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?;
    let effect = DormantObservabilityEffectV1::new(
        operation_id,
        resource_type,
        resource_id,
        resource_version,
        current_observation,
        audit,
        metrics,
    )?;
    if effect.effect_id != effect_id || effect.canonical_content != canonical_content {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    Ok(effect)
}

fn audit_observation_matches_context(
    observation: &CheckedAuditWatchEventV1,
    context: &DormantObservabilityEffectContextV1,
) -> bool {
    let wire = observation.event().full_proto();
    let Some(resource) = wire.resource.as_option() else {
        return false;
    };
    wire.operation_id.as_slice() == context.operation_id.as_slice()
        && resource.resource_type == resource_type_name(context.resource_type)
        && resource.resource_id.as_slice() == context.resource_id.as_slice()
        && resource.resource_version.as_slice() == context.resource_version.as_slice()
        && wire.resource_version.as_slice() == context.resource_version.as_slice()
}

fn encode_current_observation(
    current: &DormantObservabilityCurrentObservationV1,
) -> Result<Vec<u8>, DormantObservabilityErrorV1> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(OBSERVABILITY_CURRENT_MAGIC_V1);
    encoded.extend_from_slice(&current.health.observation_sequence().to_be_bytes());
    push_u32(&mut encoded, current.health.checks().len())?;
    for check in current.health.checks() {
        encoded.push(health_component_tag(check.component()));
        encoded.push(health_state_tag(check.state()));
        encoded.extend_from_slice(&check.generation().to_be_bytes());
        push_length_prefixed(&mut encoded, check.safe_code().as_bytes())?;
    }
    encoded.extend_from_slice(
        &current
            .residual_inventory
            .inventory_generation()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &current
            .residual_inventory
            .observation_sequence()
            .to_be_bytes(),
    );
    push_u32(&mut encoded, current.residual_inventory.resources().len())?;
    for resource in current.residual_inventory.resources() {
        encoded.push(residual_kind_tag(resource.kind()));
        encoded.push(residual_state_tag(resource.state()));
        encoded.extend_from_slice(resource.local_identity_digest().as_bytes());
        match resource.owner_resource_id() {
            Some(owner) => {
                encoded.push(1);
                encoded.extend_from_slice(&owner);
            }
            None => encoded.push(0),
        }
    }
    Ok(encoded)
}

fn decode_current_observation(
    encoded: &[u8],
) -> Result<DormantObservabilityCurrentObservationV1, DormantObservabilityErrorV1> {
    let mut reader = CanonicalReaderV1::new(encoded);
    if reader.take(8)? != OBSERVABILITY_CURRENT_MAGIC_V1 {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let health_sequence = reader.u64()?;
    let health_count = reader.u32()? as usize;
    if health_count > MAXIMUM_DORMANT_HEALTH_CHECKS_V1 {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let mut checks = Vec::with_capacity(health_count);
    for _ in 0..health_count {
        let component = decode_health_component(reader.u8()?)?;
        let state = decode_health_state(reader.u8()?)?;
        let generation = reader.u64()?;
        let safe_code = std::str::from_utf8(reader.length_prefixed()?)
            .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?
            .to_owned();
        checks.push(DormantHealthCheckV1::new(
            component, state, generation, safe_code,
        )?);
    }
    let health = DormantHealthSnapshotV1::new(health_sequence, checks)?;
    let inventory_generation = reader.u64()?;
    let inventory_sequence = reader.u64()?;
    let resource_count = reader.u32()? as usize;
    if resource_count > MAXIMUM_DORMANT_RESIDUAL_ROWS_V1 {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let mut resources = Vec::with_capacity(resource_count);
    for _ in 0..resource_count {
        let kind = decode_residual_kind(reader.u8()?)?;
        let state = decode_residual_state(reader.u8()?)?;
        let identity = reader.digest()?;
        let owner = match reader.u8()? {
            0 => None,
            1 => Some(reader.array_16()?),
            _ => return Err(DormantObservabilityErrorV1::NotCanonical),
        };
        resources.push(DormantResidualResourceV1::new(
            kind, state, identity, owner,
        )?);
    }
    reader.finish()?;
    let residual_inventory =
        DormantResidualInventoryV1::new(inventory_generation, inventory_sequence, resources)?;
    DormantObservabilityCurrentObservationV1::new(health, residual_inventory)
}

fn encode_query_binding(encoded: &mut Vec<u8>, binding: QueryBindingV1) {
    encoded.extend_from_slice(binding.query().digest().as_bytes());
    encoded.extend_from_slice(binding.filters().digest().as_bytes());
    encoded.extend_from_slice(binding.sort().digest().as_bytes());
    encoded.extend_from_slice(binding.principal().digest().as_bytes());
    encoded.extend_from_slice(binding.visibility().digest().as_bytes());
    encoded.extend_from_slice(binding.authorization().digest().as_bytes());
    encoded.extend_from_slice(binding.schema().digest().as_bytes());
}

fn decode_query_binding(
    reader: &mut CanonicalReaderV1<'_>,
) -> Result<QueryBindingV1, DormantObservabilityErrorV1> {
    Ok(QueryBindingV1::new(
        NormalizedQueryDigestV1::from_digest(reader.digest()?),
        QueryFilterDigestV1::from_digest(reader.digest()?),
        QuerySortDigestV1::from_digest(reader.digest()?),
        QueryPrincipalDigestV1::from_digest(reader.digest()?),
        QueryVisibilityDigestV1::from_digest(reader.digest()?),
        AuthorizationRevisionDigestV1::from_digest(reader.digest()?),
        ObservationSchemaDigestV1::from_digest(reader.digest()?),
    ))
}

fn encode_metric_observation(
    encoded: &mut Vec<u8>,
    observation: &PortableMetricObservationV1,
) -> Result<(), DormantObservabilityErrorV1> {
    push_length_prefixed(encoded, observation.name().as_str().as_bytes())?;
    match observation.value() {
        MetricValueV1::Counter(value) => {
            encoded.push(1);
            encoded.extend_from_slice(&value.to_be_bytes());
        }
        MetricValueV1::Gauge(value) => {
            encoded.push(2);
            encoded.extend_from_slice(&value.to_be_bytes());
        }
        MetricValueV1::DurationNanoseconds(value) => {
            encoded.push(3);
            encoded.extend_from_slice(&value.to_be_bytes());
        }
    }
    push_u32(encoded, observation.labels().len())?;
    for label in observation.labels() {
        match label {
            MetricLabelValueV1::Project(value) => {
                encoded.push(1);
                encoded.extend_from_slice(value);
            }
            MetricLabelValueV1::Backend(value) => {
                encoded.push(2);
                encoded.push(metric_backend_tag(*value));
            }
            MetricLabelValueV1::Node(value) => {
                encoded.push(3);
                encoded.extend_from_slice(value);
            }
            MetricLabelValueV1::StatusClass(value) => {
                encoded.push(4);
                encoded.push(metric_status_tag(*value));
            }
            MetricLabelValueV1::CapabilityProfile(value) => {
                encoded.push(5);
                encoded.push(metric_capability_tag(*value));
            }
        }
    }
    Ok(())
}

fn decode_metric_observation(
    reader: &mut CanonicalReaderV1<'_>,
) -> Result<PortableMetricObservationV1, DormantObservabilityErrorV1> {
    let name = std::str::from_utf8(reader.length_prefixed()?)
        .ok()
        .and_then(SandboxMetricNameV1::from_stable_name)
        .ok_or(DormantObservabilityErrorV1::NotCanonical)?;
    let value = match reader.u8()? {
        1 => MetricValueV1::Counter(reader.u64()?),
        2 => MetricValueV1::Gauge(reader.u64()?),
        3 => MetricValueV1::DurationNanoseconds(reader.u64()?),
        _ => return Err(DormantObservabilityErrorV1::NotCanonical),
    };
    let label_count = reader.u32()? as usize;
    if label_count > MAXIMUM_LABELS_PER_OBSERVATION {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    let mut labels = Vec::with_capacity(label_count);
    for _ in 0..label_count {
        labels.push(match reader.u8()? {
            1 => MetricLabelValueV1::Project(reader.array_16()?),
            2 => MetricLabelValueV1::Backend(decode_metric_backend(reader.u8()?)?),
            3 => MetricLabelValueV1::Node(reader.array_16()?),
            4 => MetricLabelValueV1::StatusClass(decode_metric_status(reader.u8()?)?),
            5 => MetricLabelValueV1::CapabilityProfile(decode_metric_capability(reader.u8()?)?),
            _ => return Err(DormantObservabilityErrorV1::NotCanonical),
        });
    }
    PortableMetricObservationV1::new(name, value, labels)
        .map_err(|_| DormantObservabilityErrorV1::NotCanonical)
}

fn push_u32(encoded: &mut Vec<u8>, value: usize) -> Result<(), DormantObservabilityErrorV1> {
    encoded.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?
            .to_be_bytes(),
    );
    Ok(())
}

fn push_length_prefixed(
    encoded: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), DormantObservabilityErrorV1> {
    push_u32(encoded, value.len())?;
    encoded.extend_from_slice(value);
    if encoded.len() > MAXIMUM_DORMANT_OBSERVABILITY_CANONICAL_BYTES_V1 {
        return Err(DormantObservabilityErrorV1::NotCanonical);
    }
    Ok(())
}

struct CanonicalReaderV1<'a> {
    remaining: &'a [u8],
}

impl<'a> CanonicalReaderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn remaining(&self) -> usize {
        self.remaining.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DormantObservabilityErrorV1> {
        if length > self.remaining.len() {
            return Err(DormantObservabilityErrorV1::NotCanonical);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, DormantObservabilityErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, DormantObservabilityErrorV1> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, DormantObservabilityErrorV1> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?,
        ))
    }

    fn array_16(&mut self) -> Result<[u8; 16], DormantObservabilityErrorV1> {
        self.take(16)?
            .try_into()
            .map_err(|_| DormantObservabilityErrorV1::NotCanonical)
    }

    fn digest(&mut self) -> Result<ObjectDigest, DormantObservabilityErrorV1> {
        let bytes: [u8; 32] = self
            .take(32)?
            .try_into()
            .map_err(|_| DormantObservabilityErrorV1::NotCanonical)?;
        if bytes == [0; 32] {
            return Err(DormantObservabilityErrorV1::NotCanonical);
        }
        Ok(ObjectDigest::from_bytes(bytes))
    }

    fn length_prefixed(&mut self) -> Result<&'a [u8], DormantObservabilityErrorV1> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn finish(self) -> Result<(), DormantObservabilityErrorV1> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(DormantObservabilityErrorV1::NotCanonical)
        }
    }
}

macro_rules! closed_observability_tags {
    ($encode:ident, $decode:ident, $kind:ty, { $($variant:path => $tag:literal),+ $(,)? }) => {
        const fn $encode(value: $kind) -> u8 {
            match value {
                $($variant => $tag),+
            }
        }

        fn $decode(value: u8) -> Result<$kind, DormantObservabilityErrorV1> {
            match value {
                $($tag => Ok($variant)),+,
                _ => Err(DormantObservabilityErrorV1::NotCanonical),
            }
        }
    };
}

closed_observability_tags!(resource_type_tag, decode_resource_type, PublicResourceTypeV1, {
    PublicResourceTypeV1::Sandbox => 1,
    PublicResourceTypeV1::Execution => 2,
    PublicResourceTypeV1::Snapshot => 3,
    PublicResourceTypeV1::FilesystemView => 4,
    PublicResourceTypeV1::Attachment => 5,
    PublicResourceTypeV1::Capability => 6,
    PublicResourceTypeV1::Operation => 7,
});

const fn resource_type_name(value: PublicResourceTypeV1) -> &'static str {
    match value {
        PublicResourceTypeV1::Sandbox => "sandbox",
        PublicResourceTypeV1::Execution => "execution",
        PublicResourceTypeV1::Snapshot => "snapshot",
        PublicResourceTypeV1::FilesystemView => "filesystem-view",
        PublicResourceTypeV1::Attachment => "attachment",
        PublicResourceTypeV1::Capability => "capability",
        PublicResourceTypeV1::Operation => "operation",
    }
}

closed_observability_tags!(health_component_tag, decode_health_component, DormantHealthComponentV1, {
    DormantHealthComponentV1::Journal => 1,
    DormantHealthComponentV1::Controller => 2,
    DormantHealthComponentV1::Reconciler => 3,
    DormantHealthComponentV1::Broker => 4,
    DormantHealthComponentV1::Runtime => 5,
    DormantHealthComponentV1::FilesystemView => 6,
    DormantHealthComponentV1::Cache => 7,
    DormantHealthComponentV1::Storage => 8,
});

closed_observability_tags!(health_state_tag, decode_health_state, DormantHealthStateV1, {
    DormantHealthStateV1::Healthy => 1,
    DormantHealthStateV1::Degraded => 2,
    DormantHealthStateV1::Failed => 3,
    DormantHealthStateV1::Unknown => 4,
});

closed_observability_tags!(residual_kind_tag, decode_residual_kind, DormantResidualKindV1, {
    DormantResidualKindV1::Namespace => 1,
    DormantResidualKindV1::Mount => 2,
    DormantResidualKindV1::Unit => 3,
    DormantResidualKindV1::Dataset => 4,
    DormantResidualKindV1::Lease => 5,
    DormantResidualKindV1::Allocation => 6,
    DormantResidualKindV1::Fuse => 7,
    DormantResidualKindV1::CachePin => 8,
});

closed_observability_tags!(residual_state_tag, decode_residual_state, DormantResidualStateV1, {
    DormantResidualStateV1::Leaked => 1,
    DormantResidualStateV1::Mismatched => 2,
    DormantResidualStateV1::Ambiguous => 3,
});

closed_observability_tags!(metric_backend_tag, decode_metric_backend, MetricBackendV1, {
    MetricBackendV1::Nspawn => 1,
    MetricBackendV1::NativeMount => 2,
    MetricBackendV1::Fuse => 3,
    MetricBackendV1::Cache => 4,
    MetricBackendV1::Zfs => 5,
    MetricBackendV1::Controller => 6,
});

closed_observability_tags!(metric_capability_tag, decode_metric_capability, MetricCapabilityProfileV1, {
    MetricCapabilityProfileV1::BaseV1 => 1,
    MetricCapabilityProfileV1::NativeMountV1 => 2,
    MetricCapabilityProfileV1::FuseFallbackV1 => 3,
    MetricCapabilityProfileV1::ZfsSnapshotV1 => 4,
    MetricCapabilityProfileV1::CacheMetadataV1 => 5,
    MetricCapabilityProfileV1::CacheBalancedV1 => 6,
    MetricCapabilityProfileV1::CacheStreamingV1 => 7,
});

closed_observability_tags!(metric_status_tag, decode_metric_status, MetricStatusClassV1, {
    MetricStatusClassV1::SandboxRequested => 1,
    MetricStatusClassV1::SandboxPreparing => 2,
    MetricStatusClassV1::SandboxStarting => 3,
    MetricStatusClassV1::SandboxReady => 4,
    MetricStatusClassV1::SandboxFreezing => 5,
    MetricStatusClassV1::SandboxFrozen => 6,
    MetricStatusClassV1::SandboxStopping => 7,
    MetricStatusClassV1::SandboxStopped => 8,
    MetricStatusClassV1::SandboxHibernated => 9,
    MetricStatusClassV1::SandboxDeleting => 10,
    MetricStatusClassV1::SandboxDeleted => 11,
    MetricStatusClassV1::SandboxError => 12,
    MetricStatusClassV1::SandboxLost => 13,
    MetricStatusClassV1::ExecutionRequested => 14,
    MetricStatusClassV1::ExecutionAdmitted => 15,
    MetricStatusClassV1::ExecutionStarting => 16,
    MetricStatusClassV1::ExecutionRunning => 17,
    MetricStatusClassV1::ExecutionExited => 18,
    MetricStatusClassV1::ExecutionCanceled => 19,
    MetricStatusClassV1::ExecutionFailed => 20,
    MetricStatusClassV1::ExecutionLost => 21,
    MetricStatusClassV1::Pending => 22,
    MetricStatusClassV1::Ready => 23,
    MetricStatusClassV1::Degraded => 24,
    MetricStatusClassV1::Blocked => 25,
    MetricStatusClassV1::Fenced => 26,
    MetricStatusClassV1::Residual => 27,
    MetricStatusClassV1::Complete => 28,
    MetricStatusClassV1::Failed => 29,
    MetricStatusClassV1::Leaked => 30,
    MetricStatusClassV1::Mismatched => 31,
    MetricStatusClassV1::OperationLifecycle => 32,
    MetricStatusClassV1::OperationExecution => 33,
    MetricStatusClassV1::OperationFilesystem => 34,
    MetricStatusClassV1::OperationSnapshot => 35,
    MetricStatusClassV1::OperationCache => 36,
    MetricStatusClassV1::OperationReconciliation => 37,
    MetricStatusClassV1::OperationCleanup => 38,
});

fn commit_observability_progress(
    journal: &mut Journal,
    effect_id: ObjectDigest,
    record: JournalRecord,
) -> Result<(), DormantObservabilityErrorV1> {
    journal
        .ensure_protected_authority()
        .map_err(|_| DormantObservabilityErrorV1::ImplementationRejected)?;
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.observability-progress.v1\0");
    digest.update(effect_id.as_bytes());
    digest.update(record.key());
    if let Some(value) = record.value() {
        digest.update(value);
    }
    let digest: [u8; 32] = digest.finalize().into();
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    let transaction = JournalTransaction::new(transaction_id, vec![record])
        .map_err(|_| DormantObservabilityErrorV1::ImplementationRejected)?;
    match journal.commit(&transaction) {
        Ok(_) => Ok(()),
        Err(_)
            if transaction.records().iter().all(|expected| {
                journal.get(expected.namespace(), expected.key()) == expected.value()
            }) =>
        {
            Ok(())
        }
        Err(_) => Err(DormantObservabilityErrorV1::ImplementationRejected),
    }
}
