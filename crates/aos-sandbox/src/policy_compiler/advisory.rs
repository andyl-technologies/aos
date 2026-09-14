//! Portable advisory selection with authority, operation, and equivalence proof.
//!
//! Normative selection order survives core-profile lowering in:
//!
//! ```text
//! u64be(domain-length) || "aos.sandbox.portable-advisory-program.v1" ||
//! u64be(payload-length) || canonical-json(decisions)
//! ```

use std::collections::BTreeSet;

use aos_sandbox_core::format::descriptor_for_bytes;
use aos_sandbox_core::model::{Optimization, OptimizationKind, OptimizationProfile};
use aos_sandbox_core::{
    MediaType, ObjectDescriptor, Operation, OperationSet, PortableMediaType, ResourceId,
    ResourceKind, Selector,
};
use serde::Serialize;

use super::authority::AuthorityPlanV1;
use super::model::{
    AdvisoryPlanCommitmentV1, ExplanationDecisionV1, ExplanationEntryV1, ExplanationReasonV1,
    ExplanationStageV1, InputSourceV1, PolicyCompilerInputV1, PolicyModelError, RedactedSubjectV1,
    canonical_bytes, digest,
};
use super::namespace::NamespacePlanV1;

/// Names all eight portable optimization kinds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AdvisoryKindV1 {
    /// Prefetch structural metadata.
    PrefetchMetadata,
    /// Prefetch immutable content.
    PrefetchContent,
    /// Perform bounded readahead.
    Readahead,
    /// Retain or eagerly build a directory index.
    DirectoryIndex,
    /// Prefer verified passthrough.
    Passthrough,
    /// Extend bounded residency.
    Keepalive,
    /// Assign cache replacement weight.
    CacheWeight,
    /// Pool compatible workers.
    WorkerPooling,
}
impl AdvisoryKindV1 {
    fn core(self) -> OptimizationKind {
        match self {
            Self::PrefetchMetadata => OptimizationKind::PrefetchMetadata,
            Self::PrefetchContent => OptimizationKind::PrefetchContent,
            Self::Readahead => OptimizationKind::Readahead,
            Self::DirectoryIndex => OptimizationKind::DirectoryIndex,
            Self::Passthrough => OptimizationKind::Passthrough,
            Self::Keepalive => OptimizationKind::Keepalive,
            Self::CacheWeight => OptimizationKind::CacheWeight,
            Self::WorkerPooling => OptimizationKind::WorkerPooling,
        }
    }
    fn operations(self) -> OperationSet {
        match self {
            Self::PrefetchMetadata | Self::DirectoryIndex => {
                OperationSet::one(Operation::MetadataRead)
            }
            Self::PrefetchContent | Self::Readahead | Self::Passthrough | Self::Keepalive => {
                OperationSet::one(Operation::ContentRead)
            }
            Self::CacheWeight => OperationSet::one(Operation::Discover),
            Self::WorkerPooling => OperationSet::one(Operation::Execute),
        }
    }
}

/// Selects explicit behavior when advice cannot be selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AdvisoryDegradationV1 {
    /// Omit the action without changing hard semantics.
    Omit,
}

/// Stores one advisory request tied to an exact namespace source equivalence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdvisoryActionV1 {
    kind: AdvisoryKindV1,
    source: ResourceId,
    resource_kind: ResourceKind,
    target: Selector,
    bounded_value: u64,
    priority: u16,
    degradation: AdvisoryDegradationV1,
}
impl AdvisoryActionV1 {
    /// Constructs one advisory rule.
    #[must_use]
    pub const fn new(
        kind: AdvisoryKindV1,
        source: ResourceId,
        resource_kind: ResourceKind,
        target: Selector,
        bounded_value: u64,
        priority: u16,
        degradation: AdvisoryDegradationV1,
    ) -> Self {
        Self {
            kind,
            source,
            resource_kind,
            target,
            bounded_value,
            priority,
            degradation,
        }
    }
    /// Returns its kind.
    #[must_use]
    pub const fn kind(&self) -> AdvisoryKindV1 {
        self.kind
    }
    /// Returns its namespace source handle.
    #[must_use]
    pub const fn source(&self) -> ResourceId {
        self.source
    }
    /// Returns the exact authority kind.
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }
    /// Returns the exact selector.
    #[must_use]
    pub const fn target(&self) -> &Selector {
        &self.target
    }
    /// Returns the bounded value.
    #[must_use]
    pub const fn bounded_value(&self) -> u64 {
        self.bounded_value
    }
    /// Returns equal-specificity tie priority.
    #[must_use]
    pub const fn priority(&self) -> u16 {
        self.priority
    }
    /// Returns unavailable behavior.
    #[must_use]
    pub const fn degradation(&self) -> AdvisoryDegradationV1 {
        self.degradation
    }
}

/// Selects an advisory decision outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AdvisoryStatusV1 {
    /// Selected and lowered.
    Active,
    /// Omitted because a ceiling denied it.
    OmittedByCeiling,
    /// Omitted because the backend lacks the kind.
    OmittedUnavailable,
    /// Lost an equal-target priority tie.
    Superseded,
}

/// Stores one request and its explicit outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdvisoryDecisionV1 {
    action: AdvisoryActionV1,
    status: AdvisoryStatusV1,
    effective_value: Option<u64>,
}
impl AdvisoryDecisionV1 {
    /// Returns the request.
    #[must_use]
    pub const fn action(&self) -> &AdvisoryActionV1 {
        &self.action
    }
    /// Returns its outcome.
    #[must_use]
    pub const fn status(&self) -> AdvisoryStatusV1 {
        self.status
    }
    /// Returns the selected value.
    #[must_use]
    pub const fn effective_value(&self) -> Option<u64> {
        self.effective_value
    }
}

/// Stores every advisory decision and the totally lowered core profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AdvisoryPlanV1 {
    commitment: AdvisoryPlanCommitmentV1,
    decisions: Vec<AdvisoryDecisionV1>,
    #[serde(skip)]
    core_profile: OptimizationProfile,
    program: PortableAdvisoryProgramV1,
}

/// Stores canonical specificity/priority decisions omitted by the core profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PortableAdvisoryProgramV1 {
    decisions: Vec<AdvisoryDecisionV1>,
    descriptor: ObjectDescriptor,
    bytes: Vec<u8>,
}
impl PortableAdvisoryProgramV1 {
    fn new(decisions: Vec<AdvisoryDecisionV1>) -> Result<Self, PolicyModelError> {
        let bytes = canonical_bytes(b"aos.sandbox.portable-advisory-program.v1", &decisions)?;
        let media = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| PolicyModelError::RegisteredMediaType)?;
        let descriptor = descriptor_for_bytes(media, &bytes);
        Ok(Self {
            decisions,
            descriptor,
            bytes,
        })
    }
    /// Returns decisions in normative specificity/priority order.
    #[must_use]
    pub fn decisions(&self) -> &[AdvisoryDecisionV1] {
        &self.decisions
    }
    /// Returns the exact program descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ObjectDescriptor {
        &self.descriptor
    }
    /// Returns exact canonical program bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl AdvisoryPlanV1 {
    /// Returns the commitment.
    #[must_use]
    pub const fn commitment(&self) -> AdvisoryPlanCommitmentV1 {
        self.commitment
    }
    /// Returns every selected, omitted, and superseded decision.
    #[must_use]
    pub fn decisions(&self) -> &[AdvisoryDecisionV1] {
        &self.decisions
    }
    /// Returns the portable core optimization profile.
    #[must_use]
    pub const fn core_profile(&self) -> &OptimizationProfile {
        &self.core_profile
    }
    /// Returns the committed normative specificity/priority program.
    #[must_use]
    pub const fn program(&self) -> &PortableAdvisoryProgramV1 {
        &self.program
    }
}

pub(crate) fn canonicalize_advisory_actions(
    actions: Vec<AdvisoryActionV1>,
) -> Result<Vec<AdvisoryActionV1>, PolicyModelError> {
    let mut identities = BTreeSet::new();
    for action in &actions {
        let identity = digest(
            b"aos.sandbox.advisory-semantic-key.v1",
            &(action.kind(), action.target(), action.priority()),
        )?;
        if !identities.insert(identity) {
            return Err(PolicyModelError::AmbiguousAdvisoryRule);
        }
    }
    let mut keyed = actions
        .into_iter()
        .map(|action| Ok((advisory_key(&action)?, action)))
        .collect::<Result<Vec<_>, PolicyModelError>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    if keyed
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
    {
        return Err(PolicyModelError::CanonicalEncoding);
    }
    Ok(keyed.into_iter().map(|(_, action)| action).collect())
}

pub(crate) fn compile_advisory(
    input: &PolicyCompilerInputV1,
    authority: &AuthorityPlanV1,
    namespace: &NamespacePlanV1,
) -> Result<(AdvisoryPlanV1, Vec<ExplanationEntryV1>), AdvisoryCompilationError> {
    let actions =
        canonicalize_advisory_actions(input.request().layer().advisory_actions().to_vec())?;
    let mut decisions = Vec::with_capacity(actions.len());
    let mut core = Vec::new();
    let mut explanation = Vec::with_capacity(actions.len());
    for action in actions {
        let source = namespace
            .source(action.source())
            .ok_or(AdvisoryCompilationError::UnknownSource)?;
        if !namespace.source_is_reachable(action.source()) {
            return Err(AdvisoryCompilationError::SourceNotReachable);
        }
        if source.resource_kind() != action.resource_kind() || source.selector() != action.target()
        {
            return Err(AdvisoryCompilationError::TargetNotEquivalent);
        }
        if !authority.admits(
            action.resource_kind(),
            action.kind().operations(),
            action.target(),
        ) {
            return Err(AdvisoryCompilationError::OperationNotAuthorized);
        }
        let mut ceiling = Some(action.bounded_value());
        let mut ceiling_causes = Vec::new();
        for (ceiling_source, layer, _) in input.ceiling_layers() {
            let values = layer
                .advisory_actions()
                .iter()
                .filter(|candidate| {
                    candidate.kind() == action.kind()
                        && candidate.source() == action.source()
                        && candidate.resource_kind() == action.resource_kind()
                        && candidate.target().contains(action.target())
                })
                .map(AdvisoryActionV1::bounded_value)
                .collect::<Vec<_>>();
            if values.is_empty() {
                ceiling_causes.push(ceiling_source);
                ceiling = None;
                break;
            }
            let minimum = values
                .into_iter()
                .min()
                .ok_or(AdvisoryCompilationError::CeilingDenied)?;
            ceiling = ceiling.map(|value| {
                if minimum < value {
                    ceiling_causes.push(ceiling_source);
                }
                value.min(minimum)
            });
        }
        let won_tie = !decisions.iter().any(|decision: &AdvisoryDecisionV1| {
            decision.status() == AdvisoryStatusV1::Active
                && equivalent_target(decision.action(), &action)
                && decision.action().priority() > action.priority()
        });
        let available = input
            .backend()
            .advisory()
            .binary_search(&action.kind())
            .is_ok();
        let (status, effective_value) = match (ceiling, available, won_tie) {
            (_, _, false) => (AdvisoryStatusV1::Superseded, None),
            (None, _, true) => (AdvisoryStatusV1::OmittedByCeiling, None),
            (Some(_), false, true) => (AdvisoryStatusV1::OmittedUnavailable, None),
            (Some(value), true, true) => {
                core.push(Optimization::new(
                    action.kind().core(),
                    action.target().clone(),
                    value,
                ));
                (AdvisoryStatusV1::Active, Some(value))
            }
        };
        let decision = AdvisoryDecisionV1 {
            action,
            status,
            effective_value,
        };
        let admitted = status == AdvisoryStatusV1::Active;
        let narrowed = admitted && effective_value != Some(decision.action().bounded_value());
        let causes = match status {
            AdvisoryStatusV1::Active | AdvisoryStatusV1::OmittedByCeiling => ceiling_causes,
            AdvisoryStatusV1::OmittedUnavailable => vec![InputSourceV1::Backend],
            AdvisoryStatusV1::Superseded => vec![InputSourceV1::Request],
        };
        explanation.push(ExplanationEntryV1::new(
            ExplanationStageV1::Advisory,
            if narrowed {
                ExplanationDecisionV1::Narrowed
            } else if admitted {
                ExplanationDecisionV1::Admitted
            } else {
                ExplanationDecisionV1::Degraded
            },
            if admitted {
                ExplanationReasonV1::AdvisorySelected
            } else {
                ExplanationReasonV1::AdvisoryDegraded
            },
            if available {
                InputSourceV1::Request
            } else {
                InputSourceV1::Backend
            },
            RedactedSubjectV1::for_value(&decision)?,
            causes,
        ));
        decisions.push(decision);
    }
    let core_profile =
        OptimizationProfile::new(core).map_err(|_| AdvisoryCompilationError::CoreModel)?;
    let program = PortableAdvisoryProgramV1::new(decisions.clone())?;
    let commitment = AdvisoryPlanCommitmentV1::new(digest(
        b"aos.sandbox.advisory-plan.v2",
        &(&decisions, program.descriptor()),
    )?);
    Ok((
        AdvisoryPlanV1 {
            commitment,
            decisions,
            core_profile,
            program,
        },
        explanation,
    ))
}

fn equivalent_target(left: &AdvisoryActionV1, right: &AdvisoryActionV1) -> bool {
    // Source handle and capability kind are proof inputs, but the portable
    // optimization object carries only family and selector. Ties therefore
    // use exactly the semantic identity that survives lowering.
    left.kind() == right.kind() && left.target() == right.target()
}
fn advisory_key(
    action: &AdvisoryActionV1,
) -> Result<(AdvisoryKindV1, u16, u16, aos_sandbox_core::ObjectDigest), PolicyModelError> {
    let specificity = selector_specificity(action.target())?;
    Ok((
        action.kind(),
        u16::MAX - specificity,
        u16::MAX - action.priority(),
        digest(b"aos.sandbox.advisory-tiebreak.v1", action)?,
    ))
}
fn selector_specificity(selector: &Selector) -> Result<u16, PolicyModelError> {
    match selector {
        Selector::Path { prefix, .. } => u16::try_from(prefix.components().len())
            .map_err(|_| PolicyModelError::AmbiguousAdvisoryRule),
        _ => Ok(u16::MAX),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdvisoryCompilationError {
    UnknownSource,
    SourceNotReachable,
    TargetNotEquivalent,
    OperationNotAuthorized,
    CeilingDenied,
    CoreModel,
    Model(PolicyModelError),
}
impl From<PolicyModelError> for AdvisoryCompilationError {
    fn from(value: PolicyModelError) -> Self {
        Self::Model(value)
    }
}
