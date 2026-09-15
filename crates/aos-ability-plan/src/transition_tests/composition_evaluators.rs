//! Composition evaluators shared by transition fixture families.

use super::*;

pub(super) struct EmptyCompositionEvaluator;

pub(super) struct LifecycleCompositionEvaluator {
    pub(super) expanding_provider: Option<InstanceId>,
    pub(super) manager_request: BindingRequest,
}

impl CompositionEvaluator for LifecycleCompositionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _module: &aos_ability_model::ModuleLocator,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let context: CompositionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        let expands = self.expanding_provider.as_ref() == Some(&context.provider);
        let requests = expands
            .then(|| vec![self.manager_request.clone()])
            .unwrap_or_default();
        let fragment = CompositionFragment {
            schema: "aos.ability.composition-fragment/v1".to_string(),
            requests,
            contributions: Vec::new(),
            resources: Vec::new(),
            outputs: Vec::new(),
            controllers: Vec::new(),
        };
        AbilityValue::new(
            serde_json::to_value(fragment)
                .map_err(|error| EvaluationError::new(error.to_string()))?,
        )
        .map_err(|error| EvaluationError::new(error.to_string()))
    }
}

impl CompositionEvaluator for EmptyCompositionEvaluator {
    fn evaluate(
        &mut self,
        _implementation: &ProviderImplementationReference,
        _module: &aos_ability_model::ModuleLocator,
        _entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let _: CompositionContext = serde_json::from_value(input.as_json().clone())
            .map_err(|error| EvaluationError::new(error.to_string()))?;
        let fragment = CompositionFragment {
            schema: "aos.ability.composition-fragment/v1".to_string(),
            requests: Vec::new(),
            contributions: Vec::new(),
            resources: Vec::new(),
            outputs: Vec::new(),
            controllers: Vec::new(),
        };
        AbilityValue::new(
            serde_json::to_value(fragment)
                .map_err(|error| EvaluationError::new(error.to_string()))?,
        )
        .map_err(|error| EvaluationError::new(error.to_string()))
    }
}
