//! Exact replay of source transition constructor calls.
//!
//! The source fixed point may return a fragment or explicitly skip a call.
//! Replay checks every selected input and result against the retained transcript
//! before accepting the independently anchored effect-plan identity.

use aos_ability_model::{
    AbilityValue, LocalKey, ModuleLocator, PlanId, ProviderImplementationReference,
};
use aos_ability_validate::CheckedBindingPlan;
use aos_contract::Sha256Digest;

use crate::{
    CompositionEvaluator, EvaluationError, SourceEvaluationRequest, SourceStageFixedPoint,
};

use super::{
    SourceTransitionPlan, SourceTransitionTemplate, TransitionError, TransitionEvaluation,
    TransitionEvaluationResult, TransitionPlanner,
};

struct SourceTransitionTranscriptEvaluator<'a> {
    evaluations: &'a [TransitionEvaluation],
    called: bool,
    mismatch: Option<String>,
}

impl<'a> SourceTransitionTranscriptEvaluator<'a> {
    const fn new(evaluations: &'a [TransitionEvaluation]) -> Self {
        Self {
            evaluations,
            called: false,
            mismatch: None,
        }
    }

    fn finish(self) -> Result<(), TransitionError> {
        if let Some(message) = self.mismatch {
            return Err(TransitionError::Transcript(message));
        }
        if !self.called {
            return Err(TransitionError::Transcript(
                "source transition transcript was not replayed".to_string(),
            ));
        }
        Ok(())
    }
}

impl CompositionEvaluator for SourceTransitionTranscriptEvaluator<'_> {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _module: &ModuleLocator,
        _entry: &LocalKey,
        _input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let message = "source transition replay requires the complete call batch";
        self.mismatch = Some(message.to_string());
        Err(EvaluationError::new(message))
    }

    fn evaluate_source_batch(
        &mut self,
        requests: &[SourceEvaluationRequest],
    ) -> Result<Vec<Result<Option<AbilityValue>, EvaluationError>>, EvaluationError> {
        if self.called || requests.len() != self.evaluations.len() {
            let message = "source transition transcript has a different number of calls";
            self.mismatch = Some(message.to_string());
            return Err(EvaluationError::new(message));
        }
        self.called = true;

        let mut results = Vec::with_capacity(requests.len());
        for (request, retained) in requests.iter().zip(self.evaluations) {
            if retained.implementation != request.implementation
                || retained.entry != request.entry
                || retained.input != request.input
            {
                let message = "source transition transcript differs from the selected call";
                self.mismatch = Some(message.to_string());
                return Err(EvaluationError::new(message));
            }
            results.push(match &retained.result {
                TransitionEvaluationResult::Returned { value } => Ok(Some(value.clone())),
                TransitionEvaluationResult::Skipped => Ok(None),
                TransitionEvaluationResult::Failed { message } => {
                    Err(EvaluationError::new(message.clone()))
                }
            });
        }
        Ok(results)
    }
}

impl TransitionPlanner<'_> {
    /// Reconstructs one source plan from every retained pure constructor result.
    ///
    /// The caller must independently anchor `expected_plan`. This method does
    /// not execute provider code; it checks every selected call, including
    /// calls that produced no fragment, before accepting the reconstructed plan.
    ///
    /// # Errors
    ///
    /// Returns an error when a call, input, result, or reconstructed plan
    /// differs from the retained authority.
    pub fn verify_source_transcript(
        &self,
        authority: Sha256Digest,
        binding: &CheckedBindingPlan,
        fixed_point: &SourceStageFixedPoint,
        evaluations: &[TransitionEvaluation],
        expected_plan: PlanId,
    ) -> Result<SourceTransitionPlan, TransitionError> {
        let mut evaluator = SourceTransitionTranscriptEvaluator::new(evaluations);
        let rebuilt = self.plan_source(authority, binding, fixed_point, &mut evaluator);
        if rebuilt.is_err() && evaluator.mismatch.is_none() {
            return rebuilt;
        }
        evaluator.finish()?;
        let rebuilt = rebuilt?;
        if rebuilt.checked_effect().id() != expected_plan || rebuilt.evaluations() != evaluations {
            return Err(TransitionError::Transcript(
                "reconstructed source plan differs from its retained identity or transcript"
                    .to_string(),
            ));
        }
        Ok(rebuilt)
    }

    /// Reconstructs an offline source template from retained constructor calls.
    ///
    /// The caller must anchor `expected_plan` independently. Every selected
    /// call, including a call with no fragment, is checked before the template
    /// identity is accepted.
    ///
    /// # Errors
    ///
    /// Returns an error when a call, input, result, or template identity differs.
    pub fn verify_source_template_transcript(
        &self,
        authority: Sha256Digest,
        binding: &CheckedBindingPlan,
        fixed_point: &SourceStageFixedPoint,
        evaluations: &[TransitionEvaluation],
        expected_plan: PlanId,
    ) -> Result<SourceTransitionTemplate, TransitionError> {
        let mut evaluator = SourceTransitionTranscriptEvaluator::new(evaluations);
        let rebuilt = self.plan_source_template(authority, binding, fixed_point, &mut evaluator);
        if rebuilt.is_err() && evaluator.mismatch.is_none() {
            return rebuilt;
        }
        evaluator.finish()?;
        let rebuilt = rebuilt?;
        if rebuilt.effect_template().id() != expected_plan || rebuilt.evaluations() != evaluations {
            return Err(TransitionError::Transcript(
                "reconstructed source template differs from its retained identity or transcript"
                    .to_string(),
            ));
        }
        Ok(rebuilt)
    }
}
