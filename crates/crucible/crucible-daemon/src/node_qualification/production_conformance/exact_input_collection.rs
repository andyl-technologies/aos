//! Collects a separately declared exact full-input report under pre-Begin custody.

use super::*;

impl ProductionConformanceRunner<'_> {
    /// Consumes the original case reservation to inspect a full-cut exact input witness.
    ///
    /// The same runtime authenticates producer lineage, native Stage, actual ACK
    /// and source-consumed commitment before this method reads a terminal result.
    /// It neither executes nor acknowledges work. Legacy exact collectors keep
    /// their original no-nonempty-input behavior and format.
    ///
    /// # Errors
    /// Refuses a foreign/used reservation, missing original input/source reader,
    /// changed full cut or outcome, withdrawn authority or exceeded body credit.
    pub fn collect_exact_input_witness_reserved(
        &mut self,
        case: ExactCompletionCase,
        runtime: &mut crucible_engine::node_contract::OriginalRuntimeWitness<'_>,
        token: &crucible_engine::node_contract::OperationToken,
        reservation: OriginalRealizedCaseReservation,
    ) -> Result<&ExactCompletionObservation, QualificationError> {
        self.require_reserved_exact(&case, &reservation)?;
        let planned = self
            .plan
            .cases
            .iter()
            .find(|planned| planned.id == case.case)
            .ok_or(QualificationError::Refused("unplanned exact collection"))?;
        if planned.kind != CaseKind::RealizedProvider || planned.oracle != case.oracle {
            return Err(QualificationError::Refused("changed original exact case"));
        }
        protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )?;
        self.authority
            .authenticate_exact_fixture(&self.plan, &case)?;
        let (observation, matches, native_input) =
            super::exact_input::collect(runtime, None, token, &case)?;
        self.exact_observations
            .insert(case.case.clone(), observation);
        let retained =
            self.exact_observations
                .get(&case.case)
                .ok_or(QualificationError::Refused(
                    "original exact observation unavailable",
                ))?;
        let current = protocol::current_scope(
            self.authority,
            &self.node,
            &self.binding,
            &self.plan.unit,
            &self.plan.classes,
        )
        .is_ok();
        let verdict = if matches && current {
            CaseVerdict::Passed
        } else {
            CaseVerdict::Failed
        };
        protocol::precharge(retained, self.limits.maximum_claim_bytes)?;
        let bytes = canonical::canonical_json(
            &serde_json::to_value(retained).map_err(crucible_node_format::ContractError::from)?,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let completion = runtime
            .original_completed_operation(token)
            .map_err(|error| QualificationError::Evidence(error.to_string()))?;
        let original = OriginalCompletionWitness::exact_with_input(
            &completion,
            retained,
            native_input.as_ref(),
            &reference,
            &bytes,
        )?;
        self.authority.retain_original_runtime_witness(
            &self.plan,
            &case.case,
            &case.oracle,
            &original,
        )?;
        self.population
            .record(&case.case, verdict, &reference, &bytes, self.authority)?;
        self.attempts.authenticate(&case.case)?;
        Ok(retained)
    }
}
