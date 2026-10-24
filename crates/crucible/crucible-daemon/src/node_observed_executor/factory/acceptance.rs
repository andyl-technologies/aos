//! Enforces explicitly installed behavioral policy on ordinary host preparation.
//!
//! Source-qualified closed profiles remain the default. Installing this policy
//! adds complete behavioral acceptance before native allocation and again at
//! actual graph admission. It cannot turn a decoded report into native custody.

use std::{collections::BTreeSet, rc::Rc};

use crucible_engine::node_admission::{AdmissionEvidence, EvidenceError, QualificationClaim};
use crucible_node_format::{
    BindingCompatibility, CaptureScope, ContentRef, GuaranteeProfile, Id, ImplementationIdentity,
    NodeBinding, OperatingMode, Repeatability, SchemaRef, Validate, canonical,
};

use super::{InstalledNodeCatalog, NodeObservedError, native_state, refused};
use crate::{
    node_qualification::{
        AcceptanceLimits, AcceptanceScope, Applicability, BehavioralAdmissionEvidence,
        CaseEvidence, InstalledAcceptancePolicy, InstalledQualificationAuthority,
        QualificationClass, QualificationError, QualificationUnit,
    },
    node_scenario::NodeScenario,
};

pub(super) struct InstalledBehavioralAcceptance {
    pub(super) policy: Rc<dyn InstalledAcceptancePolicy>,
    pub(super) limits: AcceptanceLimits,
}

impl InstalledNodeCatalog {
    /// Installs independent behavioral acceptance for subsequent host preparation.
    ///
    /// The policy owns finite original evidence and freshly measures the exact
    /// selected unit. It derives scope from installed artifacts, not request
    /// reports. This additional gate preserves all native source qualification.
    /// No currently incomplete reference report becomes ordinarily qualified.
    /// The fixed four-owner gem5 group rechecks this same policy around actual
    /// preparation and complete graph admission. Other specialized native paths
    /// remain refused until they support that same conjunction.
    ///
    /// # Errors
    /// Refuses replacement, outstanding host custody or ceilings larger than the
    /// independent default limits. No portable selection can install this policy.
    pub fn install_behavioral_acceptance(
        &mut self,
        policy: Box<dyn InstalledAcceptancePolicy + Send>,
        limits: AcceptanceLimits,
    ) -> Result<(), NodeObservedError> {
        let policy: Rc<dyn InstalledAcceptancePolicy + Send> = Rc::from(policy);
        let policy: Rc<dyn InstalledAcceptancePolicy> = policy;
        self.install_shared_behavioral_acceptance(policy, limits)
    }

    // Actor-local installations retain the SAME normal policy in the catalog
    // and provider; the portable selector cannot supply or replace it.
    pub(crate) fn install_shared_behavioral_acceptance(
        &mut self,
        policy: Rc<dyn InstalledAcceptancePolicy>,
        limits: AcceptanceLimits,
    ) -> Result<(), NodeObservedError> {
        let defaults = AcceptanceLimits::default();
        let selected = limits.qualification;
        let maximum = defaults.qualification;
        if self.behavioral_acceptance.is_some()
            || self.custody.reserved_worlds() != 0
            || limits.maximum_record_bytes == 0
            || limits.maximum_record_bytes > defaults.maximum_record_bytes
            || selected.maximum_claim_bytes == 0
            || selected.maximum_claim_bytes > maximum.maximum_claim_bytes
            || selected.maximum_cases > maximum.maximum_cases
            || selected.maximum_evidence_objects > maximum.maximum_evidence_objects
            || selected.maximum_evidence_bytes > maximum.maximum_evidence_bytes
            || selected.maximum_total_evidence_bytes > maximum.maximum_total_evidence_bytes
        {
            return Err(refused(
                "invalid installed behavioral acceptance policy or ceilings",
            ));
        }
        self.behavioral_acceptance = Some(InstalledBehavioralAcceptance { policy, limits });
        Ok(())
    }

    pub(super) fn original_gem5_behavioral_projection(
        &self,
        scenario: &NodeScenario,
    ) -> Result<
        Option<std::rc::Rc<native_state::behavioral::projection::OriginalReportProjection>>,
        NodeObservedError,
    > {
        let Some(installed) = &self.behavioral_acceptance else {
            return Ok(None);
        };
        let evidence = BehavioralAdmissionEvidence::new(
            &PreallocationCheck,
            installed.policy.as_ref(),
            installed.limits,
        );
        let mut selected = std::collections::BTreeMap::new();
        let mut original: Option<(ContentRef, Vec<u8>)> = None;
        for source in &scenario.compatibility {
            let scope = installed
                .policy
                .scope_for_node(&source.node_id)
                .map_err(|error| refused(&error.to_string()))?;
            if scope.required_classes != required_classes(scenario, source)? {
                return Err(refused(
                    "behavioral original classes differ from selected source",
                ));
            }
            evidence
                .qualify(QualificationClaim::Node {
                    binding: scope.binding,
                    binding_hash: &scope.binding.identity()?,
                    qualification_refs: &scope.binding.qualification_refs,
                })
                .map_err(|error| refused(&error.to_string()))?;
            if let Some((reference, bytes)) = &original {
                if reference != scope.original_claim || bytes.as_slice() != scope.original_bytes {
                    return Err(refused("four owners have different accepted originals"));
                }
            } else {
                original = Some((scope.original_claim.clone(), scope.original_bytes.to_vec()));
            }
            selected.insert(source.node_id.clone(), scope.binding.clone());
        }
        let (reference, bytes) =
            original.ok_or_else(|| refused("behavioral original report absent"))?;
        Ok(Some(std::rc::Rc::new(
            native_state::behavioral::projection::OriginalReportProjection::checked(
                scenario, selected, reference, &bytes,
            )?,
        )))
    }

    pub(super) fn require_behavioral_host_scope(&self) -> Result<(), NodeObservedError> {
        if self.behavioral_acceptance.is_some() {
            return Err(refused(
                "behavioral acceptance is not installed for specialized native preparation",
            ));
        }
        Ok(())
    }

    /// Adds installed behavioral acceptance to the complete original group graph.
    ///
    /// The original evidence still authenticates every native enrollment and
    /// source predicate. Behavioral claims are checked again after preparation;
    /// source qualification alone cannot satisfy an installed accepted report.
    pub(super) fn admit_behavioral_native_group(
        &self,
        scenario: &NodeScenario,
        bindings: &[NodeBinding],
        original: &dyn AdmissionEvidence,
        capabilities: Option<&super::ResolvedCapabilityWorld>,
        limits: crucible_engine::node_admission::AdmissionLimits,
    ) -> Result<crucible_engine::node_admission::AdmittedGraph, NodeObservedError> {
        let selected = self
            .behavioral_acceptance
            .as_ref()
            .map(|installed| SourceBindingPolicy::new(installed.policy.as_ref(), scenario));
        let behavioral = self
            .behavioral_acceptance
            .as_ref()
            .zip(selected.as_ref())
            .map(|(installed, policy)| {
                BehavioralAdmissionEvidence::new(original, policy, installed.limits)
            });
        let qualified: &dyn AdmissionEvidence = match &behavioral {
            Some(behavioral) => behavioral,
            None => original,
        };
        let capability =
            capabilities.map(
                |resolved| super::capabilities::admission::CapabilityAdmission {
                    original: qualified,
                    resolved,
                },
            );
        let admission: &dyn AdmissionEvidence = match &capability {
            Some(capability) => capability,
            None => qualified,
        };
        Ok(scenario.admit(bindings, admission, limits)?)
    }

    pub(super) fn preflight_behavioral_acceptance(
        &self,
        selections: &[super::InstalledNodeSelection],
        scenario: &NodeScenario,
    ) -> Result<(), NodeObservedError> {
        let source_limited = selections
            .iter()
            .all(|selection| has_closed_source_qualification(&selection.kind));
        let Some(installed) = &self.behavioral_acceptance else {
            return if source_limited {
                Ok(())
            } else {
                Err(refused(
                    "selected implementation requires installed original behavioral acceptance",
                ))
            };
        };
        let selected = SourceBindingPolicy::new(installed.policy.as_ref(), scenario);
        let evidence =
            BehavioralAdmissionEvidence::new(&PreallocationCheck, &selected, installed.limits);
        for binding in &scenario.compatibility {
            evidence
                .qualify(QualificationClaim::Node {
                    binding,
                    binding_hash: &binding.identity()?,
                    qualification_refs: &binding.qualification_refs,
                })
                .map_err(|error| refused(&error.to_string()))?;
        }
        Ok(())
    }
}

// This exhaustive source table preserves only the independently qualified
// closed scopes. A future vendor/general selector cannot inherit a wildcard
// exemption: it must explicitly require complete installed behavioral policy.
// Exact regenerated scenario equality remains mandatory before this decision.
fn has_closed_source_qualification(kind: &super::InstalledNodeKind) -> bool {
    use super::InstalledNodeKind;

    match kind {
        InstalledNodeKind::InstalledVendor { .. } => false,
        InstalledNodeKind::HostClock
        | InstalledNodeKind::HostRateAlarmClock { .. }
        | InstalledNodeKind::HostRateAlarmClockProducer { .. }
        | InstalledNodeKind::HostSemantics { .. }
        | InstalledNodeKind::Gem5ArmRoot
        | InstalledNodeKind::Gem5X86Root
        | InstalledNodeKind::HostConditionDebug { .. }
        | InstalledNodeKind::HostConditionDebugPreserving { .. }
        | InstalledNodeKind::Gem5Closed { .. }
        | InstalledNodeKind::Gem5ClosedPreserving { .. }
        | InstalledNodeKind::Gem5ClosedEpochPreserving { .. }
        | InstalledNodeKind::HostIo { .. }
        | InstalledNodeKind::HostRecordedBlock { .. }
        | InstalledNodeKind::HostRecordedBlockPreserving { .. }
        | InstalledNodeKind::HostScripted { .. }
        | InstalledNodeKind::HostPacketReceiver { .. }
        | InstalledNodeKind::HostSeededLink { .. }
        | InstalledNodeKind::HostControlledFaultLink { .. }
        | InstalledNodeKind::HostFaultedLink { .. }
        | InstalledNodeKind::HostNetLink { .. }
        | InstalledNodeKind::ReferenceNativeLinked { .. }
        | InstalledNodeKind::ReferenceDevice { .. } => true,
    }
}

pub(super) struct SourceBindingPolicy<'a> {
    installed: &'a dyn InstalledAcceptancePolicy,
    scenario: &'a NodeScenario,
}

impl<'a> SourceBindingPolicy<'a> {
    pub(super) fn new(
        installed: &'a dyn InstalledAcceptancePolicy,
        scenario: &'a NodeScenario,
    ) -> Self {
        Self {
            installed,
            scenario,
        }
    }
}

impl InstalledAcceptancePolicy for SourceBindingPolicy<'_> {
    fn provider_revision(
        &self,
        scope: &crucible_engine::node_contract::ProviderAuthorizationScope,
    ) -> Result<crucible_engine::node_contract::ProviderAuthorizationLease, QualificationError>
    {
        self.installed.provider_revision(scope)
    }

    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        let binding = self
            .scenario
            .compatibility
            .iter()
            .find(|binding| &binding.node_id == node)
            .ok_or(QualificationError::Refused(
                "node absent from actual regenerated selection",
            ))?;
        let classes = required_classes(self.scenario, binding)
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        let scope = self.installed.scope_for_node(node)?;
        if scope.binding != binding || scope.required_classes != classes {
            return Err(QualificationError::Refused(
                "installed acceptance scope differs from regenerated binding or guarantee classes",
            ));
        }
        Ok(scope)
    }
}

impl InstalledQualificationAuthority for SourceBindingPolicy<'_> {
    fn authenticate_claim(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        claim: &crate::node_qualification::QualificationClaim,
    ) -> Result<(), QualificationError> {
        self.installed.authenticate_claim(reference, bytes, claim)
    }

    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<std::collections::BTreeMap<String, Applicability>, QualificationError> {
        self.installed.applicability(unit, classes, policy)
    }

    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        self.installed
            .verify_evidence(reference, maximum_bytes, maximum_dependencies)
    }

    fn authenticate_case(
        &self,
        unit: &QualificationUnit,
        requirement: &str,
        case: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        self.installed.authenticate_case(unit, requirement, case)
    }
}

// This projection is host code over the freshly regenerated descriptor binding
// and verified guarantee object. A vendor's claim.classes cannot reduce it.
pub(super) fn required_classes(
    scenario: &NodeScenario,
    binding: &BindingCompatibility,
) -> Result<BTreeSet<QualificationClass>, NodeObservedError> {
    let entry = scenario
        .content
        .iter()
        .find(|entry| entry.reference == binding.guarantees_ref)
        .ok_or_else(|| refused("installed acceptance guarantee object absent"))?;
    if entry.bytes.len() > 65_536 {
        return Err(refused(
            "installed acceptance guarantee object exceeds its ceiling",
        ));
    }
    entry.reference.verify(&entry.bytes)?;
    let value = canonical::parse_json(&entry.bytes, 65_536)?;
    if canonical::canonical_json(&value)? != entry.bytes {
        return Err(refused(
            "noncanonical installed acceptance guarantee object",
        ));
    }
    let guarantees: GuaranteeProfile = serde_json::from_value(value)?;
    guarantees.validate()?;
    binding.operating_contract.validate()?;

    let mut classes = BTreeSet::from([
        QualificationClass::BaseProvider,
        QualificationClass::RoleProfile,
        match binding.operating_contract.mode {
            OperatingMode::Exact => QualificationClass::ExactTiming,
            OperatingMode::Quantized => QualificationClass::QuantizedTiming,
        },
    ]);
    if guarantees.repeatability == Repeatability::Qualified {
        classes.insert(QualificationClass::Repeatable);
    }
    match guarantees.capture_scope {
        CaptureScope::None => {}
        CaptureScope::Architectural => {
            classes.insert(QualificationClass::CaptureArchitectural);
        }
        CaptureScope::CompleteModel => {
            classes.insert(QualificationClass::CaptureModeledLive);
        }
    }
    if guarantees.durable_restart {
        classes.insert(QualificationClass::CaptureModeledDurable);
    }
    if guarantees.isolated_fork {
        classes.insert(QualificationClass::BranchIsolated);
    }
    if guarantees.conditional_replay {
        classes.insert(QualificationClass::ConditionalReplay);
    }
    Ok(classes)
}

// Preflight authenticates original behavioral evidence only. It neither owns a
// prepared child nor grants graph/native authority; actual admission follows.
struct PreallocationCheck;

impl AdmissionEvidence for PreallocationCheck {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        Err(EvidenceError {
            message: "preflight cannot supply native content".into(),
        })
    }

    fn authenticate_implementation(&self, _: &ImplementationIdentity) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "preflight cannot authenticate native enrollment".into(),
        })
    }

    fn authenticate_authority(&self, _: &NodeBinding) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "preflight cannot authenticate native authority".into(),
        })
    }

    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        Err(EvidenceError {
            message: "preflight cannot install native schemas".into(),
        })
    }

    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError> {
        match claim {
            QualificationClaim::Node { .. } => Ok(()),
            _ => Err(EvidenceError {
                message: "preflight supports only behavioral Node evidence".into(),
            }),
        }
    }
}

#[cfg(test)]
#[path = "acceptance_tests.rs"]
mod tests;

mod ordinary_projection;
