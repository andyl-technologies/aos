//! Owns normal Clock source identity and the exact original observation bank.
//!
//! The private constructor receives the actual retained pre-Arm programme. A
//! weak programme identity and the same opaque activation prevent substitution
//! with another equal portable graph or decoded report. No passing status,
//! source plan or acceptance record can construct this source.

use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::BTreeMap,
    rc::{Rc, Weak},
};

use crate::node_qualification::{
    CaseVerdict, OriginalCompletionObservation, OriginalCompletionWitness, QualificationError,
};

use super::*;

mod adverse;
mod authority;
mod enrollment;
mod evidence;
mod failures;
mod population;
mod requested_storage;
mod unit;

struct ExpectedCase {
    oracle: InputPayload,
    expected: oracle::ExpectedClockCase,
}

struct RetainedResult {
    reference: ContentRef,
    bytes: Vec<u8>,
    authenticated: bool,
}

/// Retains the concrete Clock source and its original independent oracle bank.
///
/// The actual service programme retains this same owner before creating its
/// runner. Native models, retired state and both fresh continuations stay in
/// that programme. This owner does not install a class or bypass the ordinary
/// full requirement population and normal enrollment gate.
#[must_use = "retain the same concrete source through original normal enrollment"]
pub struct OriginalNormalClockSource {
    origin: ClockOrigin,
    lifetime: Weak<()>,
    aggregate: Rc<OriginalClockAggregateResources>,
    profile: InstalledNormalClockProfile,
    unit: unit::Unit,
    population: population::Population,
    issued: OnceCell<crate::node_qualification::IssuedQualification>,
    record: OnceCell<crate::node_qualification::AcceptanceRecord>,
    evidence: RefCell<evidence::Evidence>,
    expected: BTreeMap<String, ExpectedCase>,
    proposal: crucible_engine::node_contract::ActivationRecord,
    adverse_executions: [ExecutionId; 2],
    publication_executions: [ExecutionId; 2],
    activation: RefCell<Option<WorldActivation>>,
    results: RefCell<BTreeMap<String, RetainedResult>>,
    failed: Cell<bool>,
}

fn failure(_: impl std::fmt::Debug) -> QualificationError {
    QualificationError::Refused("normal Clock actual source observation failed")
}

fn reject(message: &'static str) -> QualificationError {
    QualificationError::Refused(message)
}

impl OriginalNormalClockSource {
    pub(super) fn new(
        profile: &InstalledNormalClockProfile,
        original: &OriginalClockQualificationRun,
        aggregate: Rc<OriginalClockAggregateResources>,
        adverse: &super::adverse::OriginalClockAdverseProgramme,
        publication_executions: [ExecutionId; 2],
    ) -> Result<Self, QualificationError> {
        original.current().map_err(failure)?;
        aggregate.authenticate_current().map_err(failure)?;
        if profile.scenario.compatibility.len() != 1
            || profile.scenario.descriptors.len() != 1
            || profile.scenario.owners.len() != 1
        {
            return Err(reject("Clock complete source inventory differs"));
        }
        if original.arm_attempted
            || original.activation.is_some()
            || original.next != 0
            || original.failed
            || original.runtime.is_none()
            || original.scenario.canonical_bytes().map_err(failure)?
                != profile.scenario.canonical_bytes().map_err(failure)?
        {
            return Err(reject("normal Clock source must precede original Arm"));
        }
        if super::super::acceptance::required_classes(
            &profile.scenario,
            &profile.scenario.compatibility[0],
        )
        .map_err(failure)?
            != population::classes()
        {
            return Err(reject("Clock source-derived required classes differ"));
        }
        let unit = unit::derive(profile, &original.origin, &aggregate, original)?;
        let mut expected = BTreeMap::new();
        for case in &original.cases {
            expected.insert(
                case.name.to_owned(),
                ExpectedCase {
                    oracle: case.oracle.clone(),
                    expected: oracle::ExpectedClockCase {
                        request: case.expected.request.clone(),
                        outcome: case.expected.outcome.clone(),
                        objects: case.expected.objects.clone(),
                    },
                },
            );
        }
        if expected.len() != CASES.len() {
            return Err(reject("normal Clock complete case population changed"));
        }
        let adverse_executions = adverse.original_executions_data();
        let population = population::Population::new(
            &unit,
            original,
            adverse_executions,
            publication_executions,
        )?;
        Ok(Self {
            origin: original.origin.clone(),
            lifetime: Rc::downgrade(&original.source_lifetime),
            aggregate,
            profile: profile.clone(),
            evidence: RefCell::new(evidence::Evidence::new(&unit, &population)?),
            unit,
            population,
            issued: OnceCell::new(),
            record: OnceCell::new(),
            expected,
            proposal: original.proposal.clone(),
            adverse_executions,
            publication_executions,
            activation: RefCell::new(None),
            results: RefCell::new(BTreeMap::new()),
            failed: Cell::new(false),
        })
    }

    pub(super) fn original_plan_data(&self) -> (&[u8], &ContentRef) {
        (&self.population.bytes, &self.population.reference)
    }

    pub(super) fn source_inspection_case_data() -> &'static str {
        population::IDENTITY
    }

    pub(super) fn adverse_case_data(&self) -> Result<(&str, &ContentRef), QualificationError> {
        let case = self
            .population
            .plan
            .cases
            .iter()
            .find(|case| case.id == population::ADVERSE)
            .ok_or(reject("Clock original adverse case absent"))?;
        Ok((&case.id, &case.oracle))
    }

    pub(super) fn state_case_data(&self) -> (&'static str, &ContentRef) {
        (population::STATE, &self.unit.state_oracle)
    }

    pub(super) fn resources_data(&self) -> &crucible_node_format::ResourceLimits {
        self.aggregate.limits_data()
    }

    pub(super) fn withdraw(&self) {
        self.failed.set(true);
    }

    /// Reauthenticates the same live source, kernel, process and aggregate policy.
    ///
    /// This check grants no class or native operation. Source withdrawal is
    /// sticky; a later matching executable or quota cannot renew this owner.
    ///
    /// # Errors
    /// Refuses a dropped original programme, changed executable/kernel/creator,
    /// failed prior observation or stale actual aggregate enforcement.
    pub fn authenticate_current(&self) -> Result<(), QualificationError> {
        if self.failed.get() {
            return Err(reject("normal Clock source already withdrawn"));
        }
        self.failed.set(true);
        // The raw creator check in current() precedes executable I/O and every
        // owner loan. A foreign thread cannot acquire the original source bank.
        self.origin.current().map_err(failure)?;
        if self.lifetime.strong_count() == 0 || unit::current_kernel()? != self.unit.kernel {
            return Err(reject(
                "normal Clock original source lifetime or kernel changed",
            ));
        }
        self.aggregate.authenticate_current().map_err(failure)?;
        if self.aggregate.process_ceiling_data().map_err(failure)? != self.unit.ceilings
            || self.aggregate.environment_data().map_err(failure)? != self.unit.writable_environment
        {
            return Err(reject("normal Clock original process ceiling changed"));
        }
        self.failed.set(false);
        Ok(())
    }

    pub(super) fn retain_original_activation(
        &self,
        original: &OriginalClockQualificationRun,
    ) -> Result<(), QualificationError> {
        self.authenticate_current()?;
        self.failed.set(true);
        if !Weak::ptr_eq(&self.lifetime, &Rc::downgrade(&original.source_lifetime))
            || original.proposal != self.proposal
            || original.scenario.canonical_bytes().map_err(failure)?
                != self.profile.scenario.canonical_bytes().map_err(failure)?
        {
            return Err(reject(
                "normal Clock source names another original programme",
            ));
        }
        let activation = original
            .activation
            .as_ref()
            .ok_or_else(|| reject("normal Clock actual activation absent"))?;
        if activation.record() != &original.proposal {
            return Err(reject(
                "normal Clock actual activation differs from original proposal",
            ));
        }
        let mut slot = self
            .activation
            .try_borrow_mut()
            .map_err(|_| reject("normal Clock original activation busy"))?;
        if slot.is_some() {
            return Err(reject("normal Clock original activation already retained"));
        }
        *slot = Some(activation.clone());
        drop(slot);
        self.failed.set(false);
        self.authenticate_current()
    }

    fn retain_first_result(
        &self,
        case: &str,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), QualificationError> {
        let maximum = if case == population::ADVERSE {
            512 * 1024
        } else {
            state_witness::MAXIMUM_STATE_BYTES
        };
        if bytes.len() > maximum || case.len() > 128 {
            return Err(reject("normal Clock original result extent"));
        }
        reference.verify(bytes)?;
        let mut originals = self
            .results
            .try_borrow_mut()
            .map_err(|_| reject("normal Clock source result bank busy"))?;
        if originals.len() >= self.population.plan.cases.len() || originals.contains_key(case) {
            return Err(reject(
                "normal Clock source original result already retained",
            ));
        }
        // Store the first full body before inspecting its semantic verdict.
        originals.insert(
            case.to_owned(),
            RetainedResult {
                reference: reference.clone(),
                bytes: bytes.to_vec(),
                authenticated: false,
            },
        );
        Ok(())
    }

    fn mark_authenticated(&self, case: &str) -> Result<(), QualificationError> {
        let mut originals = self
            .results
            .try_borrow_mut()
            .map_err(|_| reject("normal Clock source result bank busy"))?;
        originals
            .get_mut(case)
            .ok_or_else(|| reject("normal Clock retained original absent"))?
            .authenticated = true;
        Ok(())
    }

    pub(super) fn retain_exact_original(
        &self,
        case: &str,
        oracle: &ContentRef,
        witness: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<(), QualificationError> {
        self.authenticate_current()?;
        self.failed.set(true);
        self.retain_first_result(case, witness.reference(), witness.bytes())?;
        let expected = self
            .expected
            .get(case)
            .ok_or_else(|| reject("normal Clock source case absent"))?;
        let activation = self
            .activation
            .try_borrow()
            .map_err(|_| reject("normal Clock original activation busy"))?;
        let original = witness.original();
        let admission = original.admission();
        if oracle != &expected.oracle.reference
            || !activation
                .as_ref()
                .is_some_and(|actual| admission.activation().same_authority(actual))
            || admission.request() != &expected.expected.request
            || admission.inputs().is_some()
            || witness.native_input().is_some()
            || original.outcome() != &expected.expected.outcome
            || !original.acknowledged()
        {
            return Err(reject(
                "normal Clock actual original permission/outcome/ACK changed",
            ));
        }
        let OriginalCompletionObservation::Exact(observation) = witness.observation() else {
            return Err(reject("normal Clock original is not exact"));
        };
        if observation.case != case {
            return Err(reject("normal Clock original case body changed"));
        }
        expected
            .expected
            .authenticate_objects(&observation.objects)
            .map_err(failure)?;
        {
            let mut evidence = self
                .evidence
                .try_borrow_mut()
                .map_err(|_| reject("Clock evidence bank busy"))?;
            evidence.retain_exact(witness)?;
        }
        drop(activation);
        self.mark_authenticated(case)?;
        self.failed.set(false);
        self.authenticate_current()
    }

    pub(super) fn retain_state_original(
        &self,
        case: &str,
        population: &ContentRef,
        oracle: &ContentRef,
        witness: &OriginalClockStateWitness<'_>,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<CaseVerdict, QualificationError> {
        self.authenticate_current()?;
        self.failed.set(true);
        self.retain_first_result(case, reference, bytes)?;
        if case != "clock/state-and-repeatability"
            || oracle != &self.unit.state_oracle
            || !Weak::ptr_eq(
                &self.lifetime,
                &Rc::downgrade(&witness.original.source_lifetime),
            )
            || witness.original.proposal != self.proposal
            || witness
                .original
                .scenario
                .canonical_bytes()
                .map_err(failure)?
                != self.profile.scenario.canonical_bytes().map_err(failure)?
        {
            return Err(reject(
                "normal Clock state belongs to another original programme",
            ));
        }
        let activation = self
            .activation
            .try_borrow()
            .map_err(|_| reject("normal Clock original activation busy"))?;
        if !activation.as_ref().is_some_and(|actual| {
            witness
                .original
                .activation
                .as_ref()
                .is_some_and(|original| original.same_authority(actual))
        }) || !witness.original.pause.complete()
            || witness
                .programme
                .profile
                .scenario
                .canonical_bytes()
                .map_err(failure)?
                != self.profile.scenario.canonical_bytes().map_err(failure)?
        {
            return Err(reject("normal Clock state source/pause/activation changed"));
        }
        let data = witness.observation_data().map_err(failure)?;
        let expected = canonical::canonical_json(
            &serde_json::to_value((
                "crucible.original-clock-state-observation/1",
                population,
                case,
                oracle,
                &data,
            ))
            .map_err(crucible_node_format::ContractError::from)?,
        )?;
        if expected != bytes || canonical::content_ref(&expected, "application/json")? != *reference
        {
            return Err(reject("normal Clock source original state report changed"));
        }
        self.evidence
            .try_borrow_mut()
            .map_err(|_| reject("Clock evidence bank busy"))?
            .retain_state(witness)?;
        drop(activation);
        self.mark_authenticated(case)?;
        self.failed.set(false);
        self.authenticate_current()?;
        Ok(CaseVerdict::Passed)
    }
}
