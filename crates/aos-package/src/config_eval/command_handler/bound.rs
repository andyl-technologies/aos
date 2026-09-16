//! Binding-native admission and invocation through the command-handler ABI.

use std::io;

use aos_ability_model::{
    AbilityValue, InterfaceDocument, MethodReference, ProviderAssignment, ResourceReference,
};
use aos_ability_runtime::adapter::RuntimeControl;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, DurableRequest, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition as HandlerInvocationDisposition,
    InvocationPurpose as HandlerInvocationPurpose, InvocationResult, REQUEST_SCHEMA, RESULT_SCHEMA,
    RecoveryMethods, ResourceContext, native_context_digest, resource_set_digest,
};

use super::{
    AuthenticatedCommandHandler, CommandHandlerResourceSpec, authenticate, authenticate_interface,
    authenticate_method_contract, authenticate_method_target, bind_native_context, decode, encode,
    err, handler_schema_contract, invalid, invocation_control, invoke, method_semantics_for,
    resource_spec,
};
use crate::config_eval::handler_process::FixedBudgetControl;
use crate::config_eval::transaction_blob::TransactionBlobStore;
use crate::package_contract::VerifiedPackageContract;

/// Executes one package-authenticated handler without depending on an effect graph.
///
/// The caller must still supply a checked binding and resource authority. This
/// transport owns only the package, interface, admission, and invocation ABI
/// checks shared by graph-driven and binding-driven calls.
pub(in crate::config_eval) struct BoundCommandHandler {
    assignment: ProviderAssignment,
    interface: InterfaceDocument,
    handler: AuthenticatedCommandHandler,
}

impl BoundCommandHandler {
    /// Authenticates the exact terminal handler selected by a live assignment.
    ///
    /// # Errors
    ///
    /// Returns an error when the package, interface, implementation, artifact,
    /// or executable differs from the selected assignment.
    pub(in crate::config_eval) fn new(
        package: &VerifiedPackageContract,
        assignment: ProviderAssignment,
        interface: InterfaceDocument,
    ) -> Result<Self, io::Error> {
        let handler = authenticate(package, &assignment.interface, &assignment.implementation)?;
        authenticate_interface(&interface, &assignment)?;

        Ok(Self {
            assignment,
            interface,
            handler,
        })
    }

    /// Admits one exact target and returns its complete bound resource context.
    ///
    /// # Errors
    ///
    /// Returns an error when authority or schemas differ, the admission call
    /// fails, or the provider does not admit the exact desired revision.
    pub(in crate::config_eval) fn admit(
        &self,
        method: &MethodReference,
        target: &ResourceReference,
        resource_interface: &InterfaceDocument,
        spec: &CommandHandlerResourceSpec,
        resources: Vec<ResourceContext>,
        required_purposes: Vec<HandlerInvocationPurpose>,
        remaining_millis: u64,
    ) -> Result<ResourceContext, io::Error> {
        authenticate_method_contract(&self.handler, &self.interface, method)?;
        authenticate_method_target(&self.interface, resource_interface, method, target, spec)?;
        aos_provider_protocol::validate_resource_contexts(&resources).map_err(err)?;

        let request = AdmissionRequest {
            schema: ADMISSION_REQUEST_SCHEMA.into(),
            method: method.clone(),
            semantics: method_semantics_for(&self.interface, method)?,
            contract: handler_schema_contract(&self.handler, &self.interface, method)?,
            target: target.clone(),
            assignment: self.assignment.clone(),
            resource_spec: resource_spec(spec),
            resources,
            control: invocation_control(remaining_millis, remaining_millis, false),
        };
        aos_provider_protocol::validate_admission_resource(&request).map_err(err)?;

        let output = invoke(
            &self.handler.executable,
            "admit",
            &encode(&request)?,
            &FixedBudgetControl::new(remaining_millis),
            &[],
        )?;
        let admission: AdmissionResult = decode(&output)?;
        let descriptor = self
            .interface
            .interface
            .methods
            .get(&method.method)
            .ok_or_else(|| invalid("admission method disappeared from its interface"))?;
        aos_ability_validate::validate_value(
            &descriptor.outcome.observation_evidence,
            &aos_ability_model::ValueExpression::Literal {
                value: admission.observation.clone(),
            },
        )
        .map_err(|errors| invalid(format!("invalid handler admission observation: {errors:?}")))?;
        if admission.schema != ADMISSION_SCHEMA
            || admission.disposition != AdmissionDisposition::Admitted
            || admission.incarnation.as_ref() != Some(&self.assignment.incarnation)
            || admission.native_context.as_json().is_null()
            || !required_purposes
                .iter()
                .all(|purpose| admission.supported_purposes.contains(*purpose))
        {
            return Err(invalid("command handler returned invalid admission"));
        }

        let revision = match admission.revision {
            AdmissionRevision::Present { revision } if revision == spec.revision => revision,
            AdmissionRevision::Absent | AdmissionRevision::Unknown => {
                return Err(invalid(
                    "command handler did not admit the desired revision",
                ));
            }
            AdmissionRevision::Present { .. } => {
                return Err(invalid(
                    "command handler admitted a different resource revision",
                ));
            }
        };
        let native_context = bind_native_context(spec, admission.native_context)?;
        let native_context_digest = native_context_digest(&native_context).map_err(err)?;

        Ok(ResourceContext {
            reference: target.clone(),
            assignment: self.assignment.clone(),
            revision,
            observation: admission.observation,
            native_context,
            native_context_digest,
        })
    }

    /// Builds the canonical durable request for one binding-driven call.
    ///
    /// # Errors
    ///
    /// Returns an error when inputs, recovery methods, or resource contexts do
    /// not satisfy the authenticated interface contract.
    pub(in crate::config_eval) fn durable_request(
        &self,
        method: MethodReference,
        target: ResourceReference,
        inputs: AbilityValue,
        resources: Vec<ResourceContext>,
        recovery: RecoveryMethods,
    ) -> Result<DurableRequest, io::Error> {
        authenticate_method_contract(&self.handler, &self.interface, &method)?;
        let semantics = method_semantics_for(&self.interface, &method)?;
        aos_ability_validate::validate_value(
            &self
                .interface
                .interface
                .methods
                .get(&method.method)
                .ok_or_else(|| invalid("bound method disappeared from its interface"))?
                .parameters,
            &aos_ability_model::ValueExpression::Literal {
                value: inputs.clone(),
            },
        )
        .map_err(|errors| invalid(format!("invalid bound-handler inputs: {errors:?}")))?;
        aos_provider_protocol::validate_resource_contexts(&resources).map_err(err)?;

        for recovery_method in [
            recovery.reconcile.as_ref(),
            recovery.cancel.as_ref(),
            recovery.compensate.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            authenticate_method_contract(&self.handler, &self.interface, recovery_method)?;
        }

        Ok(DurableRequest {
            schema: REQUEST_SCHEMA.into(),
            handler: self.handler.name.clone(),
            method,
            semantics,
            recovery,
            target,
            inputs,
            native_context_digest: resource_set_digest(&resources).map_err(err)?,
            resources,
        })
    }

    /// Executes one invocation through the shared bounded handler transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the request names no authorized method, bounded
    /// execution fails, or the result violates its exact schemas and context.
    pub(in crate::config_eval) fn invoke(
        &self,
        request: &DurableRequest,
        purpose: HandlerInvocationPurpose,
        control: &dyn RuntimeControl,
        blobs: &TransactionBlobStore,
    ) -> Result<InvocationResult, io::Error> {
        let method = request
            .method_for(purpose)
            .cloned()
            .ok_or_else(|| invalid("bound invocation purpose has no authorized method"))?;
        let invocation = Invocation {
            schema: INVOCATION_SCHEMA.into(),
            purpose,
            semantics: method_semantics_for(&self.interface, &method)?,
            contract: handler_schema_contract(&self.handler, &self.interface, &method)?,
            method,
            request: request.clone(),
            control: invocation_control(
                control.attempt_remaining_millis(),
                control.recovery_remaining_millis(),
                control.is_cancelled(),
            ),
        };
        let blob_invocation = blobs.prepare(request)?;
        let output = invoke(
            &self.handler.executable,
            purpose_name_from_handler(purpose),
            &encode(&invocation)?,
            control,
            &blob_invocation.environment(),
        )?;
        let mut result: InvocationResult = decode(&output)?;
        if result.disposition == HandlerInvocationDisposition::Completed {
            blobs.finalize_outputs(&blob_invocation, &mut result.outputs)?;
        }
        if result.schema != RESULT_SCHEMA
            || result.native_context_digest != request.native_context_digest
        {
            return Err(invalid(
                "command handler result is not bound to admitted context",
            ));
        }
        let descriptor = self
            .interface
            .interface
            .methods
            .get(&invocation.method.method)
            .ok_or_else(|| invalid("invoked method disappeared from its interface"))?;
        let evidence_schema = if result.disposition == HandlerInvocationDisposition::Completed {
            &descriptor.outcome.completion_evidence
        } else {
            &descriptor.outcome.observation_evidence
        };
        aos_ability_validate::validate_value(
            evidence_schema,
            &aos_ability_model::ValueExpression::Literal {
                value: result.evidence.clone(),
            },
        )
        .map_err(|errors| invalid(format!("invalid bound-handler evidence: {errors:?}")))?;
        if result.disposition == HandlerInvocationDisposition::Completed {
            if result.outputs.len() != descriptor.outputs.len()
                || result
                    .outputs
                    .keys()
                    .any(|output| !descriptor.outputs.contains_key(output))
            {
                return Err(invalid("bound-handler result has an invalid output set"));
            }
            for (name, value) in &result.outputs {
                let output = descriptor
                    .outputs
                    .get(name)
                    .ok_or_else(|| invalid("bound-handler result has an unknown output"))?;
                aos_ability_validate::validate_value(
                    &output.schema,
                    &aos_ability_model::ValueExpression::Literal {
                        value: value.clone(),
                    },
                )
                .map_err(|errors| invalid(format!("invalid bound-handler output: {errors:?}")))?;
            }
        } else if !result.outputs.is_empty() {
            return Err(invalid(
                "non-completed bound-handler result carries successful outputs",
            ));
        }
        Ok(result)
    }
}

const fn purpose_name_from_handler(purpose: HandlerInvocationPurpose) -> &'static str {
    match purpose {
        HandlerInvocationPurpose::Effect => "effect",
        HandlerInvocationPurpose::Reconcile => "reconcile",
        HandlerInvocationPurpose::Cancel => "cancel",
        HandlerInvocationPurpose::Compensate => "compensate",
        HandlerInvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}
