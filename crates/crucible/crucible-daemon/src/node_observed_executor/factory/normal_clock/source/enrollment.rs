//! Seals the unchanged original population before normal source enrollment.

use crate::node_qualification::{
    AcceptanceLimits, CaseVerdict, WitnessPopulation, evaluate_acceptance,
};
use crucible_engine::node_contract::{ProviderPreparationPlan, ProviderRegistryLimits};

use super::*;

impl OriginalNormalClockSource {
    pub(in super::super) fn seal_original_population(&self) -> Result<(), QualificationError> {
        self.authenticate_current()?;
        if self.issued.get().is_some() || self.record.get().is_some() {
            return Err(reject("Clock original population already sealed"));
        }
        let mut population = WitnessPopulation::install(
            &self.population.bytes,
            &self.population.reference,
            self,
            crate::node_qualification::QualificationLimits::default(),
        )?;
        {
            let originals = self
                .results
                .try_borrow()
                .map_err(|_| reject("Clock actual result bank busy"))?;
            for (id, original) in originals.iter() {
                // Only the actual once-retained callbacks set authenticated.
                // Missing/failed callbacks stay in the original bank and are
                // never replaced by a new observation or a decoded report.
                if original.authenticated {
                    population.record(
                        id,
                        CaseVerdict::Passed,
                        &original.reference,
                        &original.bytes,
                        self,
                    )?;
                }
            }
        }
        let issued = population.finish()?;
        {
            let mut evidence = self
                .evidence
                .try_borrow_mut()
                .map_err(|_| reject("Clock evidence bank busy"))?;
            evidence.retain_result(issued.reference(), issued.bytes())?;
            for (reference, bytes) in issued.objects() {
                evidence.retain_result(reference, bytes.as_slice())?;
            }
        }
        self.issued
            .set(issued)
            .map_err(|_| reject("Clock original claim slot occupied"))?;
        let issued = self
            .issued
            .get()
            .ok_or(reject("Clock original claim absent"))?;
        let evaluated = evaluate_acceptance(
            issued.bytes(),
            issued.reference(),
            &self.unit.value,
            &self.population.plan.classes,
            self,
            AcceptanceLimits::default(),
        )?;
        self.record
            .set(evaluated.into_record())
            .map_err(|_| reject("Clock original audit slot occupied"))?;
        self.authenticate_current()
    }

    pub(in super::super) fn future_plan(
        &self,
    ) -> Result<(Id, ProviderPreparationPlan), QualificationError> {
        self.authenticate_current()?;
        let issued = self.issued.get().ok_or(reject(
            "Clock actual original population has not been sealed",
        ))?;
        let mut binding = self.profile.scenario.compatibility[0].clone();
        if !binding.qualification_refs.contains(issued.reference()) {
            binding.qualification_refs.push(issued.reference().clone());
            binding.qualification_refs.sort_by(|left, right| {
                (&left.hash.domain, &left.hash.digest)
                    .cmp(&(&right.hash.domain, &right.hash.digest))
            });
        }
        let plan = ProviderPreparationPlan {
            descriptors: self.profile.scenario.descriptors.clone(),
            bindings: vec![binding],
        };
        Ok((Id::new("crucible/normal-public-clock-v1")?, plan))
    }

    pub(in super::super) fn metadata_limits() -> ProviderRegistryLimits {
        ProviderRegistryLimits {
            providers: 1,
            profiles: 1,
            nodes: 1,
            metadata_bytes: 4 * 1024 * 1024,
        }
    }
}
