//! Runtime validation of typed completion and graph output values.

use std::collections::BTreeMap;

use aos_ability_model::{
    AbilityValue, LocalKey, MethodReference, Operation, ProviderAssignment, ProviderReadiness,
    ScopedOperationKey,
};
use thiserror::Error;

use crate::authority::{
    ValueAuthorizationError, authorize_materialized_references, selected_grant,
};
use crate::schema::validate_materialized_value;
use crate::{CheckedEffectPlan, ValidationErrors};

/// Reports why materialized operation inputs cannot enter trusted admission.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InputValidationError {
    /// The supplied operation is not an exact member of the checked plan.
    #[error("operation is absent from the checked effect plan")]
    UnknownOperation,
    /// The operation's exact interface or method is unavailable.
    #[error("operation method is absent from the checked interface catalog")]
    MissingMethod,
    /// The operation's exact binding is unavailable.
    #[error("operation binding is absent from the checked binding plan")]
    MissingBinding,
    /// The selected provider role is not authorized by the checked binding.
    #[error("operation authority is invalid: {0}")]
    InvalidAuthority(#[source] crate::InvocationAuthorizationError),
    /// The value does not satisfy the primary method's closed parameter schema.
    #[error("materialized input does not satisfy its checked schema")]
    InvalidValue(#[source] ValidationErrors),
    /// A nested typed reference exceeds retained artifact or resource authority.
    #[error("materialized input reference is unauthorized: {0}")]
    UnauthorizedReference(#[source] ValueAuthorizationError),
}

/// Reports why runtime evidence or an output value does not match its checked contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OutputValidationError {
    /// The supplied operation is not an exact member of the checked plan.
    #[error("operation is absent from the checked effect plan")]
    UnknownOperation,
    /// The operation's exact interface is unavailable.
    #[error("operation interface is absent from the checked interface catalog")]
    MissingInterface,
    /// The operation's primary method is unavailable.
    #[error("operation method is absent from its exact interface descriptor")]
    MissingMethod,
    /// The method is not declared as this operation's primary or recovery method.
    #[error("method is not declared by the checked operation")]
    UndeclaredMethod,
    /// The checked binding grant does not authorize the declared method.
    #[error("checked operation method authority is invalid: {0}")]
    InvalidMethodAuthority(#[source] crate::InvocationAuthorizationError),
    /// The operation's exact binding is unavailable.
    #[error("operation binding is absent from the checked binding plan")]
    MissingBinding,
    /// The named method or merge output does not exist.
    #[error("output is absent from its checked descriptor")]
    MissingOutput,
    /// The supplied output map omits or invents a checked output port.
    #[error("output set differs from its checked descriptor")]
    OutputSetMismatch,
    /// The value does not satisfy the checked closed schema.
    #[error("value does not satisfy its checked output schema")]
    InvalidValue(#[source] ValidationErrors),
    /// A nested typed reference exceeds retained artifact or caller authority.
    #[error("output reference is unauthorized: {0}")]
    UnauthorizedReference(#[source] ValueAuthorizationError),
}

/// Reports why runtime assignment evidence does not satisfy a planned binding.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderReadinessError {
    /// The declaration is not an exact member of the checked effect plan.
    #[error("provider readiness declaration is absent from the checked effect plan")]
    UnknownReadiness,
    /// The declaration's producer operation is unavailable.
    #[error("provider readiness producer is absent from the checked effect plan")]
    MissingProducer,
    /// The declaration's planned binding is unavailable.
    #[error("provider readiness binding is absent from the checked binding plan")]
    MissingBinding,
    /// The producer output violates its checked typed output contract.
    #[error("provider readiness output is invalid: {0}")]
    InvalidOutput(#[source] OutputValidationError),
    /// The output is not an exact closed provider-assignment record.
    #[error("provider readiness output is not an exact provider assignment")]
    InvalidAssignment,
    /// The assignment names a different provider, interface, or implementation.
    #[error("provider assignment subject differs from its exact planned binding")]
    SubjectMismatch,
}

impl CheckedEffectPlan {
    /// Returns the exact checked outcome semantics for one operation's primary method.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation or missing exact interface or method.
    pub fn operation_outcome_semantics(
        &self,
        operation: &Operation,
    ) -> Result<&aos_ability_model::OutcomeSemantics, OutputValidationError> {
        self.operation_method(operation)
            .map(|method| &method.outcome)
    }

    /// Returns the checked outcome semantics for one exact recovery method.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation, an undeclared method, invalid
    /// checked method authority, or a missing exact interface or method.
    pub fn method_outcome_semantics(
        &self,
        operation: &Operation,
        method: &MethodReference,
    ) -> Result<&aos_ability_model::OutcomeSemantics, OutputValidationError> {
        self.operation_method_reference(operation, method)
            .map(|descriptor| &descriptor.outcome)
    }

    /// Validates fully materialized primary-method inputs before adapter preparation.
    ///
    /// This check resolves the exact primary parameter schema and independently
    /// rechecks nested artifact and resource references against the retained
    /// effect catalog and selected caller/provider grant.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation, missing exact method or
    /// binding, invalid authority role, schema-invalid value, or unauthorized
    /// nested typed reference.
    pub fn validate_operation_inputs(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
    ) -> Result<(), InputValidationError> {
        if self.operation(&operation.key) != Some(operation) {
            return Err(InputValidationError::UnknownOperation);
        }
        let method = self
            .operation_method(operation)
            .map_err(|_| InputValidationError::MissingMethod)?;
        validate_materialized_value(&method.parameters, inputs)
            .map_err(InputValidationError::InvalidValue)?;

        let binding = self
            .binding_plan()
            .binding(&operation.binding)
            .ok_or(InputValidationError::MissingBinding)?;
        let grant = selected_grant(binding, operation.authority)
            .map_err(InputValidationError::InvalidAuthority)?;
        let resources = self
            .binding_plan()
            .document()
            .resources
            .iter()
            .map(|revision| revision.resource.clone())
            .collect();
        authorize_materialized_references(
            &self.interfaces,
            binding,
            grant,
            &method.parameters,
            inputs,
            &self.artifact_index,
            &resources,
            binding.lifetime,
            None,
        )
        .map_err(InputValidationError::UnauthorizedReference)
    }

    /// Validates and resolves fresh assignment evidence for one declared planned binding.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign declaration, missing producer or binding,
    /// invalid typed output, malformed assignment, or assignment whose exact
    /// provider, interface, or implementation differs from the planned binding.
    pub fn validate_provider_assignment(
        &self,
        readiness: &ProviderReadiness,
        value: &AbilityValue,
    ) -> Result<ProviderAssignment, ProviderReadinessError> {
        if self.provider_readiness(&readiness.binding) != Some(readiness) {
            return Err(ProviderReadinessError::UnknownReadiness);
        }
        let producer = self
            .operation(&readiness.producer)
            .ok_or(ProviderReadinessError::MissingProducer)?;
        self.validate_operation_output(producer, &readiness.output, value)
            .map_err(ProviderReadinessError::InvalidOutput)?;

        let assignment = serde_json::from_value::<ProviderAssignment>(value.as_json().clone())
            .map_err(|_| ProviderReadinessError::InvalidAssignment)?;
        let binding = self
            .binding_plan()
            .binding(&readiness.binding)
            .ok_or(ProviderReadinessError::MissingBinding)?;
        if assignment.provider != binding.provider
            || assignment.interface != binding.interface
            || assignment.implementation != binding.implementation
        {
            return Err(ProviderReadinessError::SubjectMismatch);
        }

        Ok(assignment)
    }

    /// Validates successful provider evidence against the primary method's
    /// completion-evidence schema.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation, missing exact descriptor, or
    /// value that violates the method's closed completion-evidence schema.
    pub fn validate_completion_evidence(
        &self,
        operation: &Operation,
        evidence: &AbilityValue,
    ) -> Result<(), OutputValidationError> {
        let method = MethodReference {
            interface: operation.interface.clone(),
            method: operation.method.clone(),
        };
        self.validate_method_completion_evidence(operation, &method, evidence)
    }

    /// Validates successful evidence against one exact authorized method.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation, an undeclared method, invalid
    /// checked method authority, a missing exact descriptor, or a value that
    /// violates the selected method's completion-evidence schema.
    pub fn validate_method_completion_evidence(
        &self,
        operation: &Operation,
        method: &MethodReference,
        evidence: &AbilityValue,
    ) -> Result<(), OutputValidationError> {
        let method = self.operation_method_reference(operation, method)?;
        self.validate_operation_value(
            operation,
            &method.outcome.completion_evidence,
            evidence,
            None,
        )
    }

    /// Validates rejected, indeterminate, reconciliation, and cancellation
    /// evidence against the primary method's observation schema.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation, missing exact descriptor, or
    /// value that violates the method's closed observation-evidence schema.
    pub fn validate_observation_evidence(
        &self,
        operation: &Operation,
        evidence: &AbilityValue,
    ) -> Result<(), OutputValidationError> {
        let method = MethodReference {
            interface: operation.interface.clone(),
            method: operation.method.clone(),
        };
        self.validate_method_observation_evidence(operation, &method, evidence)
    }

    /// Validates observation evidence against one exact authorized method.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation, an undeclared method, invalid
    /// checked method authority, a missing exact descriptor, or a value that
    /// violates the selected method's observation-evidence schema.
    pub fn validate_method_observation_evidence(
        &self,
        operation: &Operation,
        method: &MethodReference,
        evidence: &AbilityValue,
    ) -> Result<(), OutputValidationError> {
        let method = self.operation_method_reference(operation, method)?;
        self.validate_operation_value(
            operation,
            &method.outcome.observation_evidence,
            evidence,
            None,
        )
    }

    /// Validates the complete exact output set of one primary method.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation, missing exact descriptor,
    /// omitted or invented ports, or any value that violates its port schema.
    pub fn validate_operation_outputs(
        &self,
        operation: &Operation,
        outputs: &BTreeMap<LocalKey, AbilityValue>,
    ) -> Result<(), OutputValidationError> {
        let method = MethodReference {
            interface: operation.interface.clone(),
            method: operation.method.clone(),
        };
        self.validate_method_outputs(operation, &method, outputs)
    }

    /// Validates the complete exact output set of one authorized method.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation, an undeclared method, invalid
    /// checked method authority, a missing exact descriptor, omitted or
    /// invented ports, or a value outside its checked schema.
    pub fn validate_method_outputs(
        &self,
        operation: &Operation,
        method: &MethodReference,
        outputs: &BTreeMap<LocalKey, AbilityValue>,
    ) -> Result<(), OutputValidationError> {
        let method = self.operation_method_reference(operation, method)?;
        if outputs.len() != method.outputs.len()
            || outputs
                .keys()
                .any(|output| !method.outputs.contains_key(output))
        {
            return Err(OutputValidationError::OutputSetMismatch);
        }
        for (output, value) in outputs {
            let descriptor = method
                .outputs
                .get(output)
                .ok_or(OutputValidationError::MissingOutput)?;
            self.validate_operation_value(
                operation,
                &descriptor.schema,
                value,
                Some(descriptor.lifetime),
            )?;
        }
        Ok(())
    }

    /// Validates one primary method output value against its exact output port.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign operation, missing exact descriptor or
    /// port, or value that violates the port's closed schema.
    pub fn validate_operation_output(
        &self,
        operation: &Operation,
        output: &LocalKey,
        value: &AbilityValue,
    ) -> Result<(), OutputValidationError> {
        let method = self.operation_method(operation)?;
        let descriptor = method
            .outputs
            .get(output)
            .ok_or(OutputValidationError::MissingOutput)?;
        self.validate_operation_value(
            operation,
            &descriptor.schema,
            value,
            Some(descriptor.lifetime),
        )
    }

    /// Validates one completed merge output against its common all-branch port.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown merge or port, or a value that violates
    /// the merge's closed common schema.
    pub fn validate_merge_output(
        &self,
        merge: &ScopedOperationKey,
        output: &LocalKey,
        value: &AbilityValue,
    ) -> Result<(), OutputValidationError> {
        let merge = self
            .merge(merge)
            .ok_or(OutputValidationError::MissingOutput)?;
        let descriptor = merge
            .outputs
            .get(output)
            .ok_or(OutputValidationError::MissingOutput)?;
        validate_ability_value(&descriptor.descriptor.schema, value)
    }

    /// Validates the complete exact output set of one completed merge.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown merge, omitted or invented ports, or
    /// any value that violates its common all-branch output schema.
    pub fn validate_merge_outputs(
        &self,
        merge: &ScopedOperationKey,
        outputs: &BTreeMap<LocalKey, AbilityValue>,
    ) -> Result<(), OutputValidationError> {
        let merge = self
            .merge(merge)
            .ok_or(OutputValidationError::MissingOutput)?;
        if outputs.len() != merge.outputs.len()
            || outputs
                .keys()
                .any(|output| !merge.outputs.contains_key(output))
        {
            return Err(OutputValidationError::OutputSetMismatch);
        }
        for (output, value) in outputs {
            let descriptor = merge
                .outputs
                .get(output)
                .ok_or(OutputValidationError::MissingOutput)?;
            validate_ability_value(&descriptor.descriptor.schema, value)?;
        }
        Ok(())
    }

    fn operation_method(
        &self,
        operation: &Operation,
    ) -> Result<&aos_ability_model::MethodDescriptor, OutputValidationError> {
        if self.operation(&operation.key) != Some(operation) {
            return Err(OutputValidationError::UnknownOperation);
        }
        let interface = self
            .interfaces
            .get(&operation.interface)
            .ok_or(OutputValidationError::MissingInterface)?;
        interface
            .interface
            .methods
            .get(&operation.method)
            .ok_or(OutputValidationError::MissingMethod)
    }

    fn operation_method_reference(
        &self,
        operation: &Operation,
        method: &MethodReference,
    ) -> Result<&aos_ability_model::MethodDescriptor, OutputValidationError> {
        if self.operation(&operation.key) != Some(operation) {
            return Err(OutputValidationError::UnknownOperation);
        }
        let primary = MethodReference {
            interface: operation.interface.clone(),
            method: operation.method.clone(),
        };
        let declared = method == &primary
            || operation.recovery.reconcile.as_ref() == Some(method)
            || operation.recovery.cancel.as_ref() == Some(method)
            || operation.recovery.compensate.as_ref() == Some(method);
        if !declared {
            return Err(OutputValidationError::UndeclaredMethod);
        }
        self.authorize_invocation(operation, method)
            .map_err(OutputValidationError::InvalidMethodAuthority)?;
        let interface = self
            .interfaces
            .get(&method.interface)
            .ok_or(OutputValidationError::MissingInterface)?;
        interface
            .interface
            .methods
            .get(&method.method)
            .ok_or(OutputValidationError::MissingMethod)
    }

    fn validate_operation_value(
        &self,
        operation: &Operation,
        schema: &aos_ability_model::ValueSchema,
        value: &AbilityValue,
        required_lifetime: Option<aos_ability_model::ResourceLifetime>,
    ) -> Result<(), OutputValidationError> {
        validate_ability_value(schema, value)?;
        let binding = self
            .binding_plan()
            .binding(&operation.binding)
            .ok_or(OutputValidationError::MissingBinding)?;
        let resources = self
            .binding_plan()
            .document()
            .resources
            .iter()
            .map(|revision| revision.resource.clone())
            .collect();
        authorize_materialized_references(
            &self.interfaces,
            binding,
            &binding.caller_grant,
            schema,
            value,
            &self.artifact_index,
            &resources,
            binding.lifetime,
            required_lifetime,
        )
        .map_err(OutputValidationError::UnauthorizedReference)
    }
}

fn validate_ability_value(
    schema: &aos_ability_model::ValueSchema,
    value: &AbilityValue,
) -> Result<(), OutputValidationError> {
    validate_materialized_value(schema, value).map_err(OutputValidationError::InvalidValue)
}
