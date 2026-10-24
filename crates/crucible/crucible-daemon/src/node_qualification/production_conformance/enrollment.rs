//! Enrolls a runner's unchanged original population under its same installed source.
//!
//! Enrollment owns all original observations before invoking acceptance callbacks.
//! A complete accepted ledger can install a local class revision; missing or
//! adverse coverage retains its original population in the returned failure.
//! The source, native lifecycle and whole-world authorities remain independent.

use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    thread::{self, ThreadId},
};

use crucible_engine::node_contract::{
    InstalledProviderRevision, ProviderAuthorityKind, ProviderAuthorizationLease,
    ProviderAuthorizationScope, ProviderPlanningRequest, ProviderPreparationPlan,
};
use crucible_node_format::{
    BindingCompatibility, ContentRef, HashRef, Id, ResourceLimits, Validate,
};

use super::{CollectedConformance, InstalledConformanceAuthority, ProductionConformanceRunner};
use crate::node_qualification::{
    AcceptanceDecision, AcceptanceLimits, AcceptanceRecord, AcceptanceScope, Applicability,
    CaseEvidence, InstalledAcceptancePolicy, InstalledQualificationAuthority, QualificationClaim,
    QualificationClass, QualificationError, QualificationUnit, accept_claim, evaluate_acceptance,
};

/// Retains an original collection and its independently installed source owner.
///
/// Only consuming the actual runner constructs this capsule. It has no decoder,
/// report insertion or mutable observation API. External original runtime tokens
/// and native resources remain under their existing source supervisor.
pub struct OriginalConformanceEnrollment {
    source: Rc<dyn InstalledConformanceAuthority>,
    process: u32,
    thread: ThreadId,
    same_source: bool,
    node: Id,
    binding: HashRef,
    plan: super::WitnessPlan,
    originals: CollectedConformance,
    record: Option<AcceptanceRecord>,
    unissued: Option<super::WitnessPopulation>,
}

/// Retains every original observation after an enrollment refusal or callback unwind.
pub struct OriginalConformanceEnrollmentFailure {
    /// Contains the original failure without replacing adverse case verdicts.
    pub error: QualificationError,
    /// Owns the unchanged population and same installed source after refusal.
    pub original: Box<OriginalConformanceEnrollment>,
}

/// Retains normal accepted originals and their exact local class revision owner.
///
/// This owner is constructed only after the ordinary full acceptance gate. The
/// revision is a monotonic withdrawal fence, not source or native permission.
/// Each ordinary admission still reopens the same source and original evidence.
pub struct InstalledOriginalConformanceAcceptance {
    original: OriginalConformanceEnrollment,
    binding: BindingCompatibility,
    scope: ProviderAuthorizationScope,
    revision: InstalledProviderRevision,
    limits: AcceptanceLimits,
    local: OriginalProviderPlan,
}

impl ProductionConformanceRunner<'_> {
    /// Enrolls this runner's original population for one exact installed local plan.
    ///
    /// The supplied source must be the same allocation borrowed by the runner.
    /// Its current scope must independently acknowledge the unchanged issued
    /// claim, complete classes and original collecting binding. The target plan
    /// selects a distinct future ordinary birth: all durable compatibility fields
    /// stay exact, and its qualification roster retains every original reference
    /// plus this newly issued report. No acquired native binding is modified.
    /// Caller-supplied Accepted data
    /// cannot install this owner. No peer or native process is created here.
    ///
    /// # Errors
    /// Retains the original collection on foreign source, incomplete/adverse
    /// coverage, stale installed scope, changed planning, exhausted credit or
    /// source callback unwind. Native originals remain with their supervisor.
    pub fn finish_for_installation(
        self,
        source: Rc<dyn InstalledConformanceAuthority>,
        selection: ProviderPlanningRequest<'_>,
        plan: &ProviderPreparationPlan,
        limits: AcceptanceLimits,
    ) -> Result<InstalledOriginalConformanceAcceptance, OriginalConformanceEnrollmentFailure> {
        let same_source = std::ptr::addr_eq(self.authority, source.as_ref());
        let Self {
            process,
            owner_thread,
            node,
            binding,
            plan: population_plan,
            population,
            attempts,
            observations,
            source_inspections,
            clock_state_observations,
            clock_adverse_observations,
            exact_observations,
            quantized_observations,
            ..
        } = self;
        let (attempts, issued, unissued) =
            if process == std::process::id() && owner_thread == thread::current().id() {
                let (attempts, issued) = attempts.finish(|| population.finish());
                (attempts, issued, None)
            } else {
                // Keep the original population without encoding or source callbacks.
                (
                    attempts,
                    Err(refused("foreign original enrollment creator")),
                    Some(population),
                )
            };
        let originals = CollectedConformance {
            attempts,
            issued,
            observations,
            source_inspections,
            clock_state_observations,
            clock_adverse_observations,
            exact_observations,
            quantized_observations,
        };
        let mut original = Box::new(OriginalConformanceEnrollment {
            source,
            process,
            thread: owner_thread,
            same_source,
            node,
            binding,
            plan: population_plan,
            originals,
            record: None,
            unissued,
        });

        // The complete original capsule precedes every installed callback. Even
        // a panic returns this same owner, never a reconstructed report suffix.
        let enrolled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.enroll(selection, plan, limits)
        }))
        .map_err(|_| refused("original enrollment source callback panicked"));
        match enrolled {
            Ok(Ok((binding, scope, local))) => Ok(InstalledOriginalConformanceAcceptance {
                original: *original,
                binding,
                revision: InstalledProviderRevision::new(
                    scope.clone(),
                    ProviderAuthorityKind::CatalogClass,
                ),
                scope,
                limits,
                local,
            }),
            Ok(Err(error)) | Err(error) => {
                Err(OriginalConformanceEnrollmentFailure { error, original })
            }
        }
    }
}

impl OriginalConformanceEnrollment {
    fn origin(&self) -> Result<(), QualificationError> {
        if self.process != std::process::id() || self.thread != thread::current().id() {
            return Err(refused(
                "original enrollment creator or installed source differs",
            ));
        }
        Ok(())
    }

    /// Borrows every retained original, including failed or unissued coverage.
    ///
    /// # Errors
    /// Refuses another creator. Foreign-source refusals retain readable data for the original creator.
    pub fn originals(&self) -> Result<&CollectedConformance, QualificationError> {
        self.origin()?;
        Ok(&self.originals)
    }

    /// Borrows the full acceptance decision if evaluation reached that boundary.
    ///
    /// # Errors
    /// Refuses another creator; None preserves an earlier enrollment refusal.
    pub fn record(&self) -> Result<Option<&AcceptanceRecord>, QualificationError> {
        self.origin()?;
        Ok(self.record.as_ref())
    }

    fn issued(&self) -> Result<&super::super::IssuedQualification, QualificationError> {
        self.originals
            .issued
            .as_ref()
            .map_err(|_| refused("original population was not issued"))
    }

    fn current_scope(&self) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.origin()?;
        if !self.same_source {
            return Err(refused(
                "runner and enrolled source are different original allocations",
            ));
        }
        let issued = self.issued()?;
        let scope = self.source.scope_for_node(&self.node)?;
        if scope.binding.node_id != self.node
            || scope.binding.identity()? != self.binding
            || scope.current_unit != self.plan.unit
            || scope.required_classes != self.plan.classes
            || scope.original_claim != issued.reference()
            || scope.original_bytes != issued.bytes()
        {
            return Err(refused(
                "current source no longer owns the complete original enrollment",
            ));
        }
        Ok(scope)
    }

    fn enroll(
        &mut self,
        selection: ProviderPlanningRequest<'_>,
        plan: &ProviderPreparationPlan,
        limits: AcceptanceLimits,
    ) -> Result<
        (
            BindingCompatibility,
            ProviderAuthorizationScope,
            OriginalProviderPlan,
        ),
        QualificationError,
    > {
        self.origin()?;
        if self.unissued.is_some() {
            return Err(refused("original population was not issued"));
        }
        // This is the existing finite serialized metadata contract, not a claim
        // that encoded bytes measure heap allocations or the whole native peak.
        super::super::record::bounded(
            &(
                plan,
                selection.profile,
                selection.configuration,
                selection.nodes,
                selection.resources,
            ),
            limits.maximum_record_bytes,
        )?;
        let scope = self.current_scope()?;
        if selection.nodes != std::slice::from_ref(&self.node)
            || plan.bindings.len() != 1
            || plan.descriptors.len() != 1
            || plan.descriptors[0].id != self.node
            || plan.descriptors[0].identity()? != scope.binding.descriptor_hash
            || selection.configuration != &scope.binding.configuration_ref
        {
            return Err(refused("original enrollment local plan differs"));
        }
        let target = plan
            .bindings
            .first()
            .ok_or_else(|| refused("future ordinary binding is absent"))?;
        authenticate_future_binding(scope.binding, target, self.issued()?.reference())?;
        self.source
            .authenticate_original_provider_plan(selection, plan)?;
        let authorization = ProviderAuthorizationScope::from_plan(selection, plan)
            .map_err(|error| QualificationError::Evidence(error.message))?;
        let binding = target.clone();
        let local = OriginalProviderPlan {
            profile: selection.profile.clone(),
            configuration: selection.configuration.clone(),
            nodes: selection.nodes.to_vec(),
            resources: selection.resources.clone(),
            plan: plan.clone(),
            limits: selection.limits,
        };
        let issued = self.issued()?;
        let evaluated = evaluate_acceptance(
            issued.bytes(),
            issued.reference(),
            &scope.current_unit,
            &scope.required_classes,
            self.source.as_ref(),
            limits,
        )?;
        self.record = Some(evaluated.into_record());
        if self
            .record
            .as_ref()
            .is_none_or(|record| record.decision != AcceptanceDecision::Accepted)
        {
            return Err(refused(
                "original enrollment has unresolved normal class coverage",
            ));
        }
        let scope = self.current_scope()?;
        let issued = self.issued()?;
        accept_claim(
            issued.bytes(),
            issued.reference(),
            &scope.current_unit,
            &scope.required_classes,
            self.source.as_ref(),
            limits.qualification,
        )?;
        let final_scope = self.final_scope_after_evidence(&local)?;
        authenticate_future_binding(final_scope.binding, &binding, self.issued()?.reference())?;
        Ok((binding, authorization, local))
    }
}

// The actual admitted local selection is retained for source reauthentication;
// a terminal revision must not outlive its concrete profile/resource meaning.
struct OriginalProviderPlan {
    profile: Id,
    configuration: ContentRef,
    nodes: Vec<Id>,
    resources: ResourceLimits,
    plan: ProviderPreparationPlan,
    limits: crucible_engine::node_contract::ProviderRegistryLimits,
}

impl OriginalProviderPlan {
    fn authenticate(
        &self,
        source: &dyn InstalledConformanceAuthority,
    ) -> Result<(), QualificationError> {
        let selection = ProviderPlanningRequest {
            profile: &self.profile,
            configuration: &self.configuration,
            nodes: &self.nodes,
            resources: &self.resources,
            limits: self.limits,
        };
        source.authenticate_original_provider_plan(selection, &self.plan)
    }
}

impl OriginalConformanceEnrollment {
    fn final_scope_after_evidence(
        &self,
        local: &OriginalProviderPlan,
    ) -> Result<AcceptanceScope<'_>, QualificationError> {
        self.origin()?;
        local.authenticate(self.source.as_ref())?;
        // No installed callback follows this current-source observation before
        // issuance/return. Evidence and source-plan callbacks may revoke scope.
        self.current_scope()
    }

    fn terminal_scope<'a>(
        &'a self,
        local: &OriginalProviderPlan,
        binding: &BindingCompatibility,
        revision: &InstalledProviderRevision,
        scope: &ProviderAuthorizationScope,
    ) -> Result<AcceptanceScope<'a>, QualificationError> {
        let current = self.final_scope_after_evidence(local)?;
        authenticate_future_binding(current.binding, binding, self.issued()?.reference())?;
        // A callback may withdraw this SAME installed owner while leaving its
        // source data unchanged. No callback follows this terminal fence.
        revision
            .lease()
            .authenticate(scope, ProviderAuthorityKind::CatalogClass)
            .map_err(|error| QualificationError::Evidence(error.message))?;
        Ok(current)
    }
}

impl InstalledOriginalConformanceAcceptance {
    /// Borrows the complete retained original population without granting execution.
    ///
    /// # Errors
    /// Refuses another creator or a foreign original source allocation.
    pub fn originals(&self) -> Result<&CollectedConformance, QualificationError> {
        self.original.originals()
    }

    /// Permanently withdraws this accepted installation and all outstanding leases.
    pub fn revoke(&self) {
        self.revision.revoke();
    }

    fn check_currency(&self) -> Result<(), QualificationError> {
        self.original.origin()?;
        self.revision
            .lease()
            .authenticate(&self.scope, ProviderAuthorityKind::CatalogClass)
            .map_err(|error| QualificationError::Evidence(error.message))
    }

    fn current(&self) -> Result<AcceptanceScope<'_>, QualificationError> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.original.origin()?;
            self.revision
                .lease()
                .authenticate(&self.scope, ProviderAuthorityKind::CatalogClass)
                .map_err(|error| QualificationError::Evidence(error.message))?;
            let current = self.original.current_scope()?;
            let issued = self.original.issued()?;
            authenticate_future_binding(current.binding, &self.binding, issued.reference())?;
            accept_claim(
                issued.bytes(),
                issued.reference(),
                &current.current_unit,
                &current.required_classes,
                self.original.source.as_ref(),
                self.limits.qualification,
            )?;
            self.original
                .terminal_scope(&self.local, &self.binding, &self.revision, &self.scope)
        }))
        .map_err(|_| refused("installed enrollment source callback panicked"))
        .and_then(|value| value);
        if result.is_err() {
            self.revision.revoke();
        }
        result
    }
}

impl InstalledAcceptancePolicy for InstalledOriginalConformanceAcceptance {
    fn scope_for_node(&self, node: &Id) -> Result<AcceptanceScope<'_>, QualificationError> {
        if node != &self.original.node {
            return Err(refused("foreign enrolled node"));
        }
        let current = self.current()?;
        let issued = self.original.issued()?;
        let record = self
            .original
            .record
            .as_ref()
            .ok_or_else(|| refused("accepted original record absent"))?;
        Ok(AcceptanceScope {
            binding: &self.binding,
            current_unit: current.current_unit,
            required_classes: current.required_classes,
            original_bytes: issued.bytes(),
            original_claim: issued.reference(),
            record,
        })
    }

    fn provider_revision(
        &self,
        scope: &ProviderAuthorizationScope,
    ) -> Result<ProviderAuthorizationLease, QualificationError> {
        self.original.origin()?;
        if scope != &self.scope {
            return Err(refused("foreign enrolled provider scope"));
        }
        self.current()?;
        Ok(self.revision.lease())
    }
}

impl InstalledQualificationAuthority for InstalledOriginalConformanceAcceptance {
    fn authenticate_claim(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        claim: &QualificationClaim,
    ) -> Result<(), QualificationError> {
        self.check_currency()?;
        let issued = self.original.issued()?;
        if reference != issued.reference() || bytes != issued.bytes() {
            return Err(refused("foreign enrollment claim"));
        }
        self.original
            .source
            .authenticate_claim(reference, bytes, claim)
    }

    fn applicability(
        &self,
        unit: &QualificationUnit,
        classes: &BTreeSet<QualificationClass>,
        policy: &ContentRef,
    ) -> Result<BTreeMap<String, Applicability>, QualificationError> {
        self.check_currency()?;
        self.original.source.applicability(unit, classes, policy)
    }

    fn verify_evidence(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Vec<ContentRef>, QualificationError> {
        self.check_currency()?;
        self.original
            .source
            .verify_evidence(reference, maximum_bytes, maximum_dependencies)
    }

    fn authenticate_case(
        &self,
        unit: &QualificationUnit,
        requirement: &str,
        case: &CaseEvidence,
    ) -> Result<(), QualificationError> {
        self.check_currency()?;
        self.original
            .source
            .authenticate_case(unit, requirement, case)
    }
}

fn refused(message: &'static str) -> QualificationError {
    QualificationError::Refused(message)
}

#[cfg(test)]
mod tests;

/// Checks a separately authenticated FUTURE birth's qualification extension.
///
/// This never edits an original/live binding or authorizes adopting its native
/// state. Source plan authentication remains a separate required conjunction.
fn authenticate_future_binding(
    original: &BindingCompatibility,
    target: &BindingCompatibility,
    report: &ContentRef,
) -> Result<(), QualificationError> {
    target.validate()?;
    let BindingCompatibility {
        schema_version,
        node_id,
        descriptor_hash,
        implementation,
        profile_ref,
        configuration_ref,
        operating_contract,
        execution_owner,
        capture_owner,
        capabilities_ref,
        guarantees_ref,
        qualification_refs,
        extensions,
    } = original;
    // The exhaustive pattern above makes new durable fields a compile-time
    // review obligation. Only the qualification roster can grow for new birth.
    if schema_version != &target.schema_version
        || node_id != &target.node_id
        || descriptor_hash != &target.descriptor_hash
        || implementation != &target.implementation
        || profile_ref != &target.profile_ref
        || configuration_ref != &target.configuration_ref
        || operating_contract != &target.operating_contract
        || execution_owner != &target.execution_owner
        || capture_owner != &target.capture_owner
        || capabilities_ref != &target.capabilities_ref
        || guarantees_ref != &target.guarantees_ref
        || extensions != &target.extensions
        || !target.qualification_refs.contains(report)
        || qualification_refs
            .iter()
            .any(|reference| !target.qualification_refs.contains(reference))
        || target
            .qualification_refs
            .iter()
            .any(|reference| reference != report && !qualification_refs.contains(reference))
    {
        return Err(refused(
            "future ordinary binding changes source compatibility or drops original qualification provenance",
        ));
    }
    Ok(())
}

impl OriginalConformanceEnrollment {
    pub(crate) fn charge_original_clock_storage_data(
        &self,
        expected_source: &dyn InstalledConformanceAuthority,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            source,
            process,
            thread,
            same_source,
            node,
            binding,
            plan,
            originals,
            record,
            unissued,
        } = self;
        if *process != std::process::id()
            || *thread != std::thread::current().id()
            || !*same_source
            || !std::ptr::addr_eq(source.as_ref(), expected_source)
        {
            return Err(refused("foreign Clock original enrollment storage owner"));
        }
        // The enclosing actual programme already charged this same Source Rc.
        // This handle's inline slot is in Self, not another source allocation.
        counter.charge(node)?;
        counter.charge(binding)?;
        counter.charge(plan)?;
        counter.charge(originals)?;
        counter.charge(record)?;
        counter.charge(unissued)
    }
}

impl OriginalConformanceEnrollmentFailure {
    pub(crate) fn charge_original_clock_storage_data(
        &self,
        expected_source: &dyn InstalledConformanceAuthority,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self { error, original } = self;
        counter.charge(error)?;
        counter.add(std::mem::size_of::<OriginalConformanceEnrollment>())?;
        original.charge_original_clock_storage_data(expected_source, counter)
    }
}

impl InstalledOriginalConformanceAcceptance {
    pub(crate) fn charge_original_clock_storage_data(
        &self,
        expected_source: &dyn InstalledConformanceAuthority,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            original,
            binding,
            scope,
            revision,
            limits: _,
            local,
        } = self;
        original.charge_original_clock_storage_data(expected_source, counter)?;
        counter.charge(binding)?;
        counter.add(
            scope
                .retained_requested_storage_precredit_data(counter.remaining())
                .map_err(|_| refused("Clock accepted scope storage unavailable"))?,
        )?;
        counter.add(
            revision
                .retained_requested_storage_precredit_data(counter.remaining())
                .map_err(|_| refused("Clock accepted revision storage unavailable"))?,
        )?;
        let OriginalProviderPlan {
            profile,
            configuration,
            nodes,
            resources,
            plan,
            limits: _,
        } = local;
        counter.charge(profile)?;
        counter.charge(configuration)?;
        counter.charge(nodes)?;
        counter.charge(resources)?;
        counter.charge(plan)
    }
}
