//! Scenario-bound guest selectable request resolution.
//!
//! This module is the semantic boundary between one node-qualified, paused
//! guest ABI request and the campaign choice model. It resolves only exact
//! scenario declarations, decodes an optional narrowed domain under the
//! declaration contract, derives a stable opportunity coordinate, and builds
//! replies from already validated selections. It performs no QEMU operation or
//! repository write.

use crucible::{NodeId, ScenarioDefForm};
use crucible_campaign::{
    AttemptId, CampaignCodecError, CampaignHash, ChoiceCoordinate, ChoiceDiscovery, ChoiceDomain,
    ChoiceOpportunity, ConfigurationId, ScenarioDefId, SelectableId, Selection,
    SelectionReplayMismatch,
};
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
use crucible_protocol::{SelectableProtocolError, SelectionReply};
use thiserror::Error;

/// Failure while resolving or replying to one guest selectable request.
#[derive(Debug, Error)]
pub enum GuestSelectableError {
    /// The frozen scenario catalog does not declare the requested name.
    #[error("guest requested unknown scenario selectable `{0}`")]
    UnknownSelectable(String),
    /// The declaration belongs to another producer or guest node.
    #[error("guest selectable `{selectable}` is not owned by node `{node}`")]
    SourceMismatch {
        /// Requested stable selectable name.
        selectable: String,
        /// Node that produced the pending request.
        node: String,
    },
    /// The narrowed domain or derived choice records violate the campaign model.
    #[error("guest selectable campaign contract failed: {0}")]
    Campaign(#[from] CampaignCodecError),
    /// A replayed selection disagreed with the freshly resolved guest request.
    #[error("guest selectable replay contract failed: {0}")]
    ReplayMismatch(#[source] Box<GuestSelectableReplayMismatch>),
    /// The selected reply cannot be represented by the guest ABI.
    #[error("guest selectable reply encoding failed: {0}")]
    Protocol(#[from] SelectableProtocolError),
}

/// Identifies the deterministic phase that resolved a guest replay request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestSelectableReplayPhase {
    /// A fresh QEMU process reconstructed an attempt's configured start.
    FreshStart,
}

impl std::fmt::Display for GuestSelectableReplayPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FreshStart => formatter.write_str("fresh-start"),
        }
    }
}

/// States how the correlated semantic attempt participates in replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestSelectableReplayAttemptRole {
    /// The identifier names the attempt being executed.
    ExecutingAttempt,
    /// The identifier names an earlier attempt replayed as continuation input.
    ReplaySource,
}

/// Caller-owned identities and coordinates attached to a replay mismatch.
pub(crate) struct GuestSelectableReplayCorrelation {
    pub(crate) phase: GuestSelectableReplayPhase,
    pub(crate) attempt_role: GuestSelectableReplayAttemptRole,
    pub(crate) attempt: AttemptId,
    pub(crate) replayed_configuration: ConfigurationId,
    pub(crate) decision_index: usize,
    pub(crate) node: String,
    pub(crate) selectable: String,
    pub(crate) request_instance: String,
    pub(crate) request_sequence: u64,
    pub(crate) request_icount: u64,
    pub(crate) request_vcpu_index: u32,
    pub(crate) expected_opportunity: Option<GuestSelectableReplayOpportunityContext>,
    pub(crate) replayed_opportunity: GuestSelectableReplayOpportunityContext,
}

impl std::fmt::Display for GuestSelectableReplayAttemptRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExecutingAttempt => formatter.write_str("executing-attempt"),
            Self::ReplaySource => formatter.write_str("replay-source"),
        }
    }
}

/// Authenticated choice metadata retained for replay diagnosis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestSelectableReplayOpportunityContext {
    declaration: SelectableId,
    coordinate: ChoiceCoordinate,
    instance: String,
}

impl GuestSelectableReplayOpportunityContext {
    pub(crate) fn from_opportunity(opportunity: &ChoiceOpportunity) -> Self {
        Self {
            declaration: opportunity.declaration(),
            coordinate: opportunity.coordinate(),
            instance: opportunity.instance().to_owned(),
        }
    }

    /// Returns the authenticated selectable declaration identity.
    #[must_use]
    pub const fn declaration(&self) -> SelectableId {
        self.declaration
    }

    /// Returns the authenticated scheduler and producer coordinate.
    #[must_use]
    pub const fn coordinate(&self) -> ChoiceCoordinate {
        self.coordinate
    }

    /// Returns the producer-defined stable instance key.
    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }
}

/// Actionable deterministic context for one guest selection replay mismatch.
#[derive(Debug)]
pub struct GuestSelectableReplayMismatch {
    phase: GuestSelectableReplayPhase,
    attempt_role: GuestSelectableReplayAttemptRole,
    attempt: AttemptId,
    replayed_configuration: ConfigurationId,
    decision_index: usize,
    node: String,
    selectable: String,
    request_instance: String,
    request_sequence: u64,
    request_icount: u64,
    request_vcpu_index: u32,
    expected_opportunity: Option<GuestSelectableReplayOpportunityContext>,
    replayed_opportunity: GuestSelectableReplayOpportunityContext,
    mismatch: SelectionReplayMismatch,
    source: CampaignCodecError,
}

impl GuestSelectableReplayMismatch {
    pub(crate) fn new(
        correlation: GuestSelectableReplayCorrelation,
        mismatch: SelectionReplayMismatch,
        source: CampaignCodecError,
    ) -> Self {
        Self {
            phase: correlation.phase,
            attempt_role: correlation.attempt_role,
            attempt: correlation.attempt,
            replayed_configuration: correlation.replayed_configuration,
            decision_index: correlation.decision_index,
            node: correlation.node,
            selectable: correlation.selectable,
            request_instance: correlation.request_instance,
            request_sequence: correlation.request_sequence,
            request_icount: correlation.request_icount,
            request_vcpu_index: correlation.request_vcpu_index,
            expected_opportunity: correlation.expected_opportunity,
            replayed_opportunity: correlation.replayed_opportunity,
            mismatch,
            source,
        }
    }

    /// Returns the deterministic replay phase.
    #[must_use]
    pub const fn phase(&self) -> GuestSelectableReplayPhase {
        self.phase
    }

    /// Returns how the correlated attempt participates in replay.
    #[must_use]
    pub const fn attempt_role(&self) -> GuestSelectableReplayAttemptRole {
        self.attempt_role
    }

    /// Returns the correlated semantic attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the configuration prefix present before the failed decision.
    #[must_use]
    pub const fn replayed_configuration(&self) -> ConfigurationId {
        self.replayed_configuration
    }

    /// Returns the zero-based target schedule decision index.
    #[must_use]
    pub const fn decision_index(&self) -> usize {
        self.decision_index
    }

    /// Returns the QEMU node that owns the request.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Returns the stable selectable declaration name from the guest request.
    #[must_use]
    pub fn selectable(&self) -> &str {
        &self.selectable
    }

    /// Returns the guest request's logical instance key.
    #[must_use]
    pub fn request_instance(&self) -> &str {
        &self.request_instance
    }

    /// Returns the guest transport request sequence.
    #[must_use]
    pub const fn request_sequence(&self) -> u64 {
        self.request_sequence
    }

    /// Returns the instruction count reported with the replayed guest request.
    #[must_use]
    pub const fn request_icount(&self) -> u64 {
        self.request_icount
    }

    /// Returns the vCPU that issued the replayed guest request.
    #[must_use]
    pub const fn request_vcpu_index(&self) -> u32 {
        self.request_vcpu_index
    }

    /// Returns authenticated expected metadata when the replay closure retains it.
    #[must_use]
    pub const fn expected_opportunity(&self) -> Option<&GuestSelectableReplayOpportunityContext> {
        self.expected_opportunity.as_ref()
    }

    /// Returns the metadata reconstructed from the live guest request.
    #[must_use]
    pub const fn replayed_opportunity(&self) -> &GuestSelectableReplayOpportunityContext {
        &self.replayed_opportunity
    }

    /// Returns the classified identity/domain mismatch.
    #[must_use]
    pub const fn mismatch(&self) -> SelectionReplayMismatch {
        self.mismatch
    }
}

impl std::fmt::Display for GuestSelectableReplayMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "phase={} attempt-role={} attempt={} replayed-configuration={} decision-index={} failed-predicate={} expected-opportunity={} replayed-opportunity={} expected-domain={} replayed-domain={} replayed-opportunity-domain={} value-in-replayed-domain={} node={} selectable={} request-instance={} request-sequence={} request-icount={} request-vcpu={} replayed-declaration={} replayed-choice-scheduler-coordinate={} replayed-choice-producer-coordinate={} replayed-choice-instance={}",
            self.phase,
            self.attempt_role,
            self.attempt,
            self.replayed_configuration,
            self.decision_index,
            self.mismatch.kind(),
            self.mismatch.expected_opportunity(),
            self.mismatch.replayed_opportunity(),
            self.mismatch.expected_domain(),
            self.mismatch.replayed_domain(),
            self.mismatch.replayed_opportunity_domain(),
            self.mismatch.value_in_replayed_domain(),
            self.node,
            self.selectable,
            self.request_instance,
            self.request_sequence,
            self.request_icount,
            self.request_vcpu_index,
            self.replayed_opportunity.declaration,
            self.replayed_opportunity.coordinate.scheduler,
            self.replayed_opportunity.coordinate.producer,
            self.replayed_opportunity.instance,
        )?;
        match &self.expected_opportunity {
            Some(expected) => write!(
                formatter,
                " expected-declaration={} expected-choice-scheduler-coordinate={} expected-choice-producer-coordinate={} expected-choice-instance={}",
                expected.declaration,
                expected.coordinate.scheduler,
                expected.coordinate.producer,
                expected.instance,
            )?,
            None => formatter.write_str(" expected-choice-context=unavailable")?,
        }
        write!(formatter, ": {}", self.source)
    }
}

impl std::error::Error for GuestSelectableReplayMismatch {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Resolves one exact paused guest request into self-contained choice records.
///
/// The scheduler coordinate commits to the node, trap instruction count, and
/// vCPU. The producer coordinate commits to the scenario declaration's
/// semantic identity and guest protocol version. The request's logical
/// instance remains the opportunity instance key; transport sequence numbers
/// deliberately do not perturb semantic identity.
///
/// # Errors
///
/// Returns [`GuestSelectableError`] when the name is absent, the declaration
/// belongs to another source, narrowed-domain bytes are malformed or broaden
/// the scenario declaration, or canonical record construction fails.
pub(crate) fn resolve_guest_selectable(
    scenario: ScenarioDefId,
    source: &ScenarioDefForm,
    node: &NodeId,
    pending: &SelectablePlanPendingRequest,
) -> Result<ChoiceDiscovery, GuestSelectableError> {
    let request = pending.request();
    let declaration = source
        .selectables()
        .declaration(request.selectable_id())
        .ok_or_else(|| {
            GuestSelectableError::UnknownSelectable(request.selectable_id().to_owned())
        })?;
    let protocol_version = match declaration.source() {
        crucible_campaign::ChoiceSource::Guest {
            node: owner,
            protocol_version,
        } if owner == &node.name => *protocol_version,
        _ => {
            return Err(GuestSelectableError::SourceMismatch {
                selectable: request.selectable_id().to_owned(),
                node: node.name.clone(),
            });
        }
    };
    let domain = request.narrowed_domain().map_or_else(
        || Ok(declaration.domain().clone()),
        ChoiceDomain::from_canonical_bytes,
    )?;
    let coordinate = ChoiceCoordinate {
        scheduler: scheduler_coordinate(node, pending),
        producer: producer_coordinate(declaration.semantic_id().as_hash(), protocol_version),
    };
    let opportunity = ChoiceOpportunity::new(
        scenario,
        declaration,
        &domain,
        coordinate,
        request.instance_key(),
        None,
    )?;
    ChoiceDiscovery::new(declaration.clone(), domain, opportunity).map_err(Into::into)
}

/// Builds one exact ABI reply from a replay-validated selection.
///
/// # Errors
///
/// Returns [`GuestSelectableError`] when the selection does not name the
/// resolved opportunity/domain or the ABI cannot encode its canonical value.
pub(crate) fn selected_guest_reply(
    pending: &SelectablePlanPendingRequest,
    discovery: &ChoiceDiscovery,
    selection: &Selection,
) -> Result<SelectionReply, GuestSelectableError> {
    selection.validate_resolved_references(discovery.opportunity(), discovery.domain())?;
    let opportunity = discovery.opportunity().id()?.content_id().digest();
    let domain = discovery.domain().id()?.content_id().digest();
    SelectionReply::selected(
        pending.request().sequence(),
        opportunity,
        domain,
        selection.value().canonical_bytes(),
    )
    .map_err(Into::into)
}

fn scheduler_coordinate(node: &NodeId, pending: &SelectablePlanPendingRequest) -> CampaignHash {
    let mut material = Vec::with_capacity(8 + node.name.len() + 8 + 4);
    material.extend_from_slice(&(node.name.len() as u64).to_be_bytes());
    material.extend_from_slice(node.name.as_bytes());
    material.extend_from_slice(&pending.icount().to_be_bytes());
    material.extend_from_slice(&pending.vcpu_index().to_be_bytes());
    CampaignHash::derive(
        "crucible.guest-selectable.scheduler-coordinate.v1",
        &material,
    )
}

fn producer_coordinate(declaration: CampaignHash, protocol_version: u32) -> CampaignHash {
    let mut material = Vec::with_capacity(36);
    material.extend_from_slice(&declaration.as_bytes());
    material.extend_from_slice(&protocol_version.to_be_bytes());
    CampaignHash::derive(
        "crucible.guest-selectable.producer-coordinate.v1",
        &material,
    )
}

#[cfg(test)]
mod tests;
