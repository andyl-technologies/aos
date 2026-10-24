//! Owns fresh singleton adverse plans and their nonrenewing original attempts.
//!
//! Existing protocol oracles are reused on this actual singleton installation;
//! no pair observation or completed resend history enters this population.
//! Completed subsets remain data. Missing loss, reconnect and resource branches
//! prevent completion of the full adverse case and every dependent clause.

use std::{cell::RefCell, thread::ThreadId};

use crucible_engine::node_adapters::cnp::{CnpLaunchGuard, CnpReferencePreparation};
use crucible_node_format::{Bytes, ContentRef, Id, canonical};
use crucible_node_transport::{
    ProviderError,
    client::{
        ObservationHandle, OriginalConflictLimits, OriginalConflictObservationHandle,
        OriginalConflictReservation,
    },
};
use serde_json::{Value, json};

use super::{
    installation::SourcePublicReferenceInstallation, singleton_conflict::SingletonConflictPlan,
    singleton_unit::SingletonQualificationUnit, source_pre_activation_execution,
    source_pre_activation_probe::SourcePreActivationProbePlan, source_probe::SourceProbePlan,
    source_probe_execution,
};

const MAXIMUM_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct SingletonAdversePopulation {
    pub(super) reference: ContentRef,
    pub(super) bytes: Vec<u8>,
    process: u32,
    thread: ThreadId,
    unit: crate::node_qualification::QualificationUnit,
    pre_realization: SourceProbePlan,
    prepared: SourcePreActivationProbePlan,
    conflicts: SingletonConflictPlan,
    conflict_custody: RefCell<ConflictCustody>,
    originals: RefCell<[OriginalAttempt; 3]>,
}

#[derive(Default)]
struct ConflictCustody {
    reservation_attempted: bool,
    reservation: Option<OriginalConflictReservation>,
    observer: Option<OriginalConflictObservationHandle>,
}

#[derive(Default)]
enum OriginalAttempt {
    #[default]
    Unattempted,
    Started,
    Completed {
        observation: Value,
        snapshot: Bytes,
    },
}

impl OriginalAttempt {
    fn begin(&mut self) -> Result<(), ProviderError> {
        if !matches!(self, Self::Unattempted) {
            return Err(ProviderError::Correlation(
                "singleton adverse original already attempted",
            ));
        }
        *self = Self::Started;
        Ok(())
    }

    fn complete(&mut self, observation: Value, snapshot: Vec<u8>) -> Result<(), ProviderError> {
        if !matches!(self, Self::Started) || snapshot.len() > MAXIMUM_BYTES / 2 {
            return Err(ProviderError::Correlation(
                "singleton adverse original completion differs",
            ));
        }
        *self = Self::Completed {
            observation,
            snapshot: Bytes::new(snapshot),
        };
        Ok(())
    }
}

impl SingletonAdversePopulation {
    /// Seals exact source recipes before any native allocation.
    ///
    /// # Errors
    /// Refuses a foreign singleton unit/profile or an unbounded original fixture.
    pub(super) fn new(
        installed: &SourcePublicReferenceInstallation,
        unit: &SingletonQualificationUnit,
    ) -> Result<Self, ProviderError> {
        if installed.profile.descriptor.id.as_str() != "singleton"
            || installed.profile.owner.id.as_str() != "singleton-owner"
            || installed.profile.owner.participant_ids != [installed.profile.descriptor.id.clone()]
        {
            return Err(ProviderError::Correlation(
                "adverse population is not the original singleton",
            ));
        }
        let pre_realization = SourceProbePlan::build_singleton_resources(installed)?;
        let prepared = SourcePreActivationProbePlan::build(installed)?;
        let conflicts = SingletonConflictPlan::build(&pre_realization)?;
        let bytes = canonical::canonical_json(&json!({
            "schema":"crucible.reference.singleton-adverse-population.v1",
            "unit":unit.identity, "classes":unit.classes,
            "pre_realization":pre_realization.reference,
            "prepared":prepared.reference, "conflicts":conflicts.reference,
            "source":canonical::content_ref(include_bytes!("singleton_adverse.rs"),"text/plain")?,
            "original_rule":"one predeclared attempt per phase; native controls and original snapshot owned by this singleton actor; no pair outcome reuse",
            "missing":["stale-session-and-incarnation","conflicting-original-body","reconnect","lost-reply","resource-exhaustion","unsupported-ingress"],
            "whole_adverse_case":"NotExecuted until every selected branch has its own authenticated original native observation"
        }))?;
        if bytes.len() > MAXIMUM_BYTES / 2 {
            return Err(ProviderError::ResourceExhausted(
                "singleton adverse fixture credit",
            ));
        }
        Ok(Self {
            reference: canonical::content_ref(&bytes, "application/json")?,
            bytes,
            process: std::process::id(),
            thread: std::thread::current().id(),
            unit: unit.identity.clone(),
            pre_realization,
            prepared,
            conflicts,
            conflict_custody: RefCell::new(ConflictCustody::default()),
            originals: RefCell::new(std::array::from_fn(|_| OriginalAttempt::default())),
        })
    }

    /// Reserves this original recorder before native allocation.
    ///
    /// # Errors
    /// Refuses a repeated or foreign attempt and unavailable finite storage.
    pub(super) fn reserve_conflicts(
        &self,
        installed: &SourcePublicReferenceInstallation,
        connection: &Id,
    ) -> Result<(), ProviderError> {
        self.require_owner()?;
        let mut original = self
            .conflict_custody
            .try_borrow_mut()
            .map_err(|_| ProviderError::Correlation("singleton conflict custody borrowed"))?;
        if original.reservation_attempted {
            return Err(ProviderError::Correlation(
                "singleton conflict reservation already attempted",
            ));
        }
        original.reservation_attempted = true;
        original.reservation = Some(OriginalConflictReservation::reserve(
            installed.bootstrap.authority.session_id.clone(),
            installed.bootstrap.authority.incarnation_id.clone(),
            connection.clone(),
            OriginalConflictLimits {
                maximum_transmissions: 3,
                maximum_bytes: MAXIMUM_BYTES / 2,
            },
            &installed.bootstrap.admission_token,
        )?);
        Ok(())
    }

    /// Runs the original source-bound pre-realization population once.
    ///
    /// # Errors
    /// Refuses foreign custody or a repeated attempt; dispatched failures retain
    /// the same started attempt, original guard and incomplete observation.
    pub(super) fn collect_pre_realization(
        &self,
        installed: &SourcePublicReferenceInstallation,
        guard: &mut CnpLaunchGuard,
        observations: &ObservationHandle,
    ) -> Result<(), ProviderError> {
        self.require_owner()?;
        {
            let mut original = self
                .conflict_custody
                .try_borrow_mut()
                .map_err(|_| ProviderError::Correlation("singleton conflict custody borrowed"))?;
            if original.observer.is_some() {
                return Err(ProviderError::Correlation(
                    "singleton conflict archive already installed",
                ));
            }
            original.observer = Some(
                guard
                    .install_pre_realization_conflict_archive(installed, &mut original.reservation)
                    .map_err(|error| ProviderError::Io(std::io::Error::other(error.reason)))?,
            );
        }
        self.originals.borrow_mut()[0].begin()?;
        let (original, bytes) =
            source_probe_execution::collect(installed, guard, &self.pre_realization, observations)?;
        let observation =
            serde_json::to_value(original).map_err(crucible_node_format::ContractError::from)?;
        self.originals.borrow_mut()[0].complete(observation, bytes)?;
        self.originals.borrow_mut()[2].begin()?;
        let original = self
            .conflict_custody
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("singleton conflict custody borrowed"))?;
        let observer = original
            .observer
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "singleton conflict recorder absent",
            ))?;
        let (observation, snapshot) = self.conflicts.collect(
            installed,
            guard,
            &self.pre_realization,
            observations,
            observer,
        )?;
        self.originals.borrow_mut()[2].complete(observation, snapshot)
    }

    /// Runs the original source-bound inactive preparation population once.
    ///
    /// # Errors
    /// Refuses foreign custody or a repeated attempt; native or observation
    /// failure retains this same attempt and the original preparation owner.
    pub(super) fn collect_prepared(
        &self,
        installed: &SourcePublicReferenceInstallation,
        prepared: &mut CnpReferencePreparation,
        observations: &ObservationHandle,
    ) -> Result<(), ProviderError> {
        self.require_owner()?;
        self.originals.borrow_mut()[1].begin()?;
        let (original, bytes) = source_pre_activation_execution::collect(
            installed,
            prepared,
            &self.prepared,
            observations,
        )?;
        let observation =
            serde_json::to_value(original).map_err(crucible_node_format::ContractError::from)?;
        self.originals.borrow_mut()[1].complete(observation, bytes)
    }

    /// Borrows completed subset facts while preserving whole-case incompletion.
    ///
    /// # Errors
    /// Refuses foreign custody or any unattempted, started or incomplete subset.
    pub(super) fn observation(&self) -> Result<Value, ProviderError> {
        self.require_owner()?;
        let originals = self.originals.borrow();
        let mut subsets = Vec::with_capacity(3);
        for original in originals.iter() {
            let OriginalAttempt::Completed {
                observation,
                snapshot,
            } = original
            else {
                return Err(ProviderError::Correlation(
                    "singleton adverse original remains unresolved",
                ));
            };
            subsets.push(json!({"observation":observation,"original_snapshot":snapshot}));
        }
        Ok(json!({
            "schema":"crucible.reference.singleton-original-adverse-subsets.v1",
            "unit":self.unit,"population":self.reference,"original_subsets":subsets,
            "whole_case":"NotExecuted",
            "missing":["stale-session-and-incarnation","reconnect","lost-reply","resource-exhaustion","unsupported-ingress"]
        }))
    }

    fn require_owner(&self) -> Result<(), ProviderError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "singleton adverse population has a foreign owner",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_attempt_never_renews_after_start_or_completion() {
        let mut original = OriginalAttempt::default();
        assert!(original.complete(Value::Null, vec![]).is_err());
        assert!(original.begin().is_ok());
        assert!(original.begin().is_err());
        assert!(original.complete(Value::Null, vec![]).is_ok());
        assert!(original.begin().is_err());
        assert!(original.complete(Value::Null, vec![]).is_err());
    }
}
