//! Generic transport for authenticated package-owned native handlers.
//!
//! A fixed protocol selector and purpose are the only argv values. All checked
//! operation data crosses bounded canonical JSON on stdin; package-specific
//! argument construction remains in the signed handler executable.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::Command;

use aos_ability_model::{
    AbilityValue, AccessMode, InterfaceDocument, InterfaceName, LocalKey, MethodReference,
    MethodSemantics, Operation, ProviderAssignment, ProviderImplementationReference,
    ResourceAccess, ResourceId, ResourceLifetime, ResourceReference, RevisionId, ValueSchema,
};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CatalogReservation,
    EffectDisposition, InvocationPurpose as RuntimeInvocationPurpose, ReconcileDisposition,
    ReservationContext, ResourceAdmissionEvidence, ResourceHandle, ResourceRevisionObservation,
    RuntimeControl, TrustedAdapter, TrustedResourceCatalog,
};
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, BoundNativeContext, DurableRequest, HANDLER_ABI_ARGUMENT,
    INVOCATION_SCHEMA, Invocation, InvocationControl,
    InvocationDisposition as HandlerInvocationDisposition,
    InvocationPurpose as HandlerInvocationPurpose, InvocationResult, MAX_HANDLER_RESULT_BYTES,
    REQUEST_SCHEMA, RESOURCE_CONTEXT_SCHEMA, RESULT_SCHEMA, RecoveryMethods, ResourceContext,
    ResourceSpec, native_context_digest, resource_set_digest,
};
use serde::{Deserialize, Serialize};

use super::handler_process::{DescendantPolicy, FixedBudgetControl, run_bounded};
use super::transaction_blob::TransactionBlobStore;
use crate::package_contract::{VerifiedPackageContract, VerifiedPackageContractSet};

#[derive(Clone, Debug)]
/// Retains one checked fixed-point resource for provider admission.
pub(crate) struct CommandHandlerResourceSpec {
    /// Identifies the provider-owned logical resource.
    pub(crate) resource: ResourceId,
    /// Identifies the canonical interface that owns the resource value.
    pub(crate) kind: InterfaceName,
    /// Declares the resource retention boundary.
    pub(crate) lifetime: ResourceLifetime,
    /// Identifies the semantic desired content.
    pub(crate) revision: RevisionId,
    /// Carries the provider-neutral desired value checked against the selected
    /// method's resource schema.
    pub(crate) value: AbilityValue,
    /// Carries the provider-owned realization after activation checked it
    /// against the selected implementation's declared realization schema.
    pub(crate) realization: AbilityValue,
}

#[derive(Clone, Debug)]
/// Holds one decoded durable request and transport-failure evidence.
pub(crate) struct CommandHandlerRequest {
    durable: DurableRequest,
    failure: CommandHandlerRecord,
}

#[derive(Clone, Debug)]
/// Carries durable evidence and typed outputs returned by a provider handler.
pub(crate) struct CommandHandlerRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for CommandHandlerRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for CommandHandlerRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

#[derive(Clone, Debug)]
/// Pins one admitted native resource context to its full checked authority.
pub(crate) struct CommandHandlerResourceHandle {
    reference: ResourceReference,
    assignment: ProviderAssignment,
    revision: RevisionId,
    observation: AbilityValue,
    native_context: AbilityValue,
    native_context_digest: Sha256Digest,
}

#[derive(Clone)]
/// Binds one resolved resource to its selected package handler and interface.
pub(crate) struct CommandHandlerResourceEntry {
    assignment: ProviderAssignment,
    handler_interface: InterfaceDocument,
    resource_interface: InterfaceDocument,
    handler: AuthenticatedCommandHandler,
    spec: CommandHandlerResourceSpec,
}

impl CommandHandlerResourceEntry {
    /// Authenticates one resource entry against its selected package and interface.
    ///
    /// # Errors
    ///
    /// Returns an error when the assignment does not resolve the exact terminal
    /// handler or canonical interface document.
    pub(crate) fn new(
        package: &VerifiedPackageContract,
        assignment: ProviderAssignment,
        handler_interface: InterfaceDocument,
        resource_interface: InterfaceDocument,
        spec: CommandHandlerResourceSpec,
    ) -> Result<Self, io::Error> {
        let handler = authenticate(package, &assignment.interface, &assignment.implementation)?;
        authenticate_interface(&handler_interface, &assignment)?;
        if resource_interface.interface_key().map_err(err)?.name != spec.kind {
            return Err(invalid(
                "command handler resource interface differs from its resolved kind",
            ));
        }

        Ok(Self {
            assignment,
            handler_interface,
            resource_interface,
            handler,
            spec,
        })
    }
}

/// Admits a closed fixed-point resource set through package-owned handlers.
pub(crate) struct CommandHandlerResourceCatalog {
    resources: BTreeMap<ResourceId, CommandHandlerResourceEntry>,
}

impl CommandHandlerResourceCatalog {
    /// Constructs a catalog with exactly one authenticated entry per resource.
    ///
    /// # Errors
    ///
    /// Returns an error when the input repeats a logical resource.
    pub(crate) fn new(
        resources: impl IntoIterator<Item = CommandHandlerResourceEntry>,
    ) -> Result<Self, io::Error> {
        let mut indexed = BTreeMap::new();
        for entry in resources {
            let resource = entry.spec.resource.clone();
            if indexed.insert(resource, entry).is_some() {
                return Err(invalid("command handler catalog repeats a resource"));
            }
        }
        Ok(Self { resources: indexed })
    }

    /// Resolves every resource needed by an operation from its checked plan.
    ///
    /// # Errors
    ///
    /// Returns an error when a reference has no exact resource revision,
    /// provider binding, package, interface, or live assignment.
    pub(crate) fn for_operation(
        plan: &CheckedEffectPlan,
        packages: &VerifiedPackageContractSet,
        operation: &Operation,
        mut assignment_for: impl FnMut(&Operation) -> Result<ProviderAssignment, io::Error>,
    ) -> Result<Self, io::Error> {
        let references = closed_resource_references_from_plan(operation, plan)?;
        let mut entries = Vec::with_capacity(references.len());

        for reference in references.values() {
            let owner = resource_owner_operation(plan, operation, reference)?;
            let binding = plan
                .binding_plan()
                .binding(&owner.binding)
                .ok_or_else(|| invalid("resource owner binding disappeared from checked plan"))?;
            let package_digest = binding.provider_package.ok_or_else(|| {
                invalid("command handler binding is not owned by an authenticated package")
            })?;
            let package = packages
                .iter()
                .find(|package| package.package_digest() == package_digest)
                .ok_or_else(|| {
                    invalid("command handler package is absent from authenticated package set")
                })?;
            let assignment = assignment_for(owner)?;
            if assignment.provider != binding.provider
                || assignment.interface != binding.interface
                || assignment.implementation != binding.implementation
            {
                return Err(invalid(
                    "live provider assignment differs from checked resource owner binding",
                ));
            }
            let handler_interface = plan
                .interfaces()
                .get(&assignment.interface)
                .cloned()
                .ok_or_else(|| invalid("handler interface disappeared from checked plan"))?;
            let resource_interface = plan
                .interfaces()
                .get(&reference.interface)
                .cloned()
                .ok_or_else(|| invalid("resource interface disappeared from checked plan"))?;
            let revision = resolved_resource_revision(plan, &reference.resource)?;
            let spec = CommandHandlerResourceSpec {
                resource: revision.resource.clone(),
                kind: revision.kind.clone(),
                lifetime: revision.lifetime,
                revision: revision.revision,
                value: revision.value.clone(),
                realization: revision.realization.clone(),
            };
            entries.push(CommandHandlerResourceEntry::new(
                package,
                assignment,
                handler_interface,
                resource_interface,
                spec,
            )?);
        }

        Self::new(entries)
    }

    /// Returns exact selected assignments in canonical provider/interface order.
    #[must_use]
    pub(crate) fn assignments(&self) -> Vec<ProviderAssignment> {
        let mut assignments = self
            .resources
            .values()
            .map(|entry| entry.assignment.clone())
            .collect::<Vec<_>>();
        assignments.sort_by(|left, right| {
            left.provider
                .cmp(&right.provider)
                .then_with(|| left.interface.cmp(&right.interface))
        });
        assignments.dedup();
        assignments
    }

    /// Classifies one resource with an effect-free admission call.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation's referenced-resource closure is not
    /// exact or the handler cannot establish an authoritative revision.
    pub(crate) fn classify(
        &self,
        operation: &Operation,
        resource: &ResourceId,
    ) -> Result<aos_ability_plan::RuntimeResourceState, io::Error> {
        let entry = self
            .resources
            .get(resource)
            .ok_or_else(|| invalid("command handler resource is outside its catalog"))?;
        let references = closed_resource_references(operation, &self.resources)?;
        let reference = references
            .get(resource)
            .ok_or_else(|| invalid("operation access has no exact checked ResourceReference"))?;
        let admission = self.admit_resource(operation, reference, 30_000)?;
        let state = match admission.revision {
            AdmissionRevision::Absent => aos_ability_plan::RuntimeResourceState::Absent,
            AdmissionRevision::Present { revision } => {
                let health = if revision == entry.spec.revision {
                    aos_ability_plan::RuntimeResourceHealth::Healthy
                } else {
                    aos_ability_plan::RuntimeResourceHealth::Divergent
                };
                aos_ability_plan::RuntimeResourceState::Present { revision, health }
            }
            AdmissionRevision::Unknown => {
                return Err(invalid(
                    "command handler admission returned an unknown revision",
                ));
            }
        };
        Ok(state)
    }

    fn admit_resource(
        &self,
        operation: &Operation,
        target: &ResourceReference,
        remaining_millis: u64,
    ) -> Result<AuthenticatedAdmission, io::Error> {
        let references = if target.resource == operation.target.resource {
            closed_resource_references(operation, &self.resources)?
        } else {
            resource_reference_closure(target, &self.resources)?
        };
        let mut admitted = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        for reference in references.values() {
            self.admit_dependency(
                operation,
                reference,
                remaining_millis,
                &mut visiting,
                &mut admitted,
            )?;
        }

        // A plain reference cycle does not necessarily imply an effect cycle.
        // The recursive pass above obtains effect-free provisional contexts;
        // canonical passes then require every handler to admit against its full
        // referenced set and converge on one stable result.
        let maximum_passes = references
            .len()
            .checked_add(1)
            .ok_or_else(|| invalid("referenced-resource set is too large"))?;
        for _ in 0..maximum_passes {
            let mut changed = false;
            for reference in references.values() {
                let entry = self
                    .resources
                    .get(&reference.resource)
                    .ok_or_else(|| invalid("command handler resource is outside its catalog"))?;
                let closure = resource_reference_closure(reference, &self.resources)?;
                let contexts = admitted_contexts(&closure, &reference.resource, &admitted)?;
                let required = (reference.resource == operation.target.resource)
                    .then(|| required_purposes(operation))
                    .unwrap_or_default();
                let admission = entry.admit(
                    reference,
                    admission_method(operation, reference, entry)?,
                    contexts,
                    required,
                    remaining_millis,
                )?;
                let refreshed = AdmittedResourceContext::new(reference.clone(), entry, admission);

                let authority_changed = admitted
                    .get(&reference.resource)
                    .is_none_or(|current| !current.same_authority(&refreshed));
                admitted.insert(reference.resource.clone(), refreshed);
                if authority_changed {
                    changed = true;
                }
            }
            if !changed {
                return admitted
                    .remove(&target.resource)
                    .map(AdmittedResourceContext::into_admission)
                    .ok_or_else(|| invalid("command handler target was not admitted"));
            }
        }

        Err(invalid(
            "cyclic referenced-resource admission did not converge on stable contexts",
        ))
    }

    fn admit_dependency(
        &self,
        operation: &Operation,
        target: &ResourceReference,
        remaining_millis: u64,
        visiting: &mut BTreeSet<ResourceId>,
        admitted: &mut BTreeMap<ResourceId, AdmittedResourceContext>,
    ) -> Result<(), io::Error> {
        if admitted.contains_key(&target.resource) {
            return Ok(());
        }
        let entry = self
            .resources
            .get(&target.resource)
            .ok_or_else(|| invalid("referenced command-handler resource is outside its catalog"))?;
        if !visiting.insert(target.resource.clone()) {
            let admission = entry.admit(
                target,
                admission_method(operation, target, entry)?,
                Vec::new(),
                Vec::new(),
                remaining_millis,
            )?;
            admitted.insert(
                target.resource.clone(),
                AdmittedResourceContext::new(target.clone(), entry, admission),
            );
            return Ok(());
        }

        let closure = resource_reference_closure(target, &self.resources)?;
        for dependency in closure.values() {
            if dependency.resource != target.resource {
                self.admit_dependency(operation, dependency, remaining_millis, visiting, admitted)?;
            }
        }
        let contexts = admitted_contexts(&closure, &target.resource, admitted)?;
        let admission = entry.admit(
            target,
            admission_method(operation, target, entry)?,
            contexts,
            Vec::new(),
            remaining_millis,
        )?;
        admitted.insert(
            target.resource.clone(),
            AdmittedResourceContext::new(target.clone(), entry, admission),
        );
        visiting.remove(&target.resource);
        Ok(())
    }
}

impl CommandHandlerResourceEntry {
    fn admit(
        &self,
        target: &ResourceReference,
        method: MethodReference,
        resources: Vec<ResourceContext>,
        required_purposes: Vec<HandlerInvocationPurpose>,
        remaining_millis: u64,
    ) -> Result<AuthenticatedAdmission, io::Error> {
        authenticate_method_contract(&self.handler, &self.handler_interface, &method)?;
        authenticate_method_target(
            &self.handler_interface,
            &self.resource_interface,
            &method,
            target,
            &self.spec,
        )?;
        let semantics = method_semantics_for(&self.handler_interface, &method)?;
        let request = AdmissionRequest {
            schema: ADMISSION_REQUEST_SCHEMA.into(),
            method,
            semantics,
            target: target.clone(),
            assignment: self.assignment.clone(),
            resource_spec: resource_spec(&self.spec),
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
        let observation_schema = &self
            .handler_interface
            .interface
            .methods
            .get(&request.method.method)
            .ok_or_else(|| invalid("admission method disappeared from its interface"))?
            .outcome
            .observation_evidence;
        aos_ability_validate::validate_value(
            observation_schema,
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
        let native_context = bind_native_context(&self.spec, admission.native_context)?;
        let native_context_digest = native_context_digest(&native_context).map_err(err)?;

        Ok(AuthenticatedAdmission {
            revision: admission.revision,
            observation: admission.observation,
            native_context,
            native_context_digest,
        })
    }
}

impl TrustedResourceCatalog for CommandHandlerResourceCatalog {
    type Handle = CommandHandlerResourceHandle;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        let entry = self
            .resources
            .get(&access.resource)
            .ok_or_else(|| invalid("command handler resource is outside its catalog"))?;
        if access.resource == operation.target.resource
            && context
                .expected_provider
                .is_some_and(|expected| expected != &entry.assignment)
        {
            return Err(invalid("command handler assignment or access is stale"));
        }
        let references = closed_resource_references(operation, &self.resources)?;
        let reference = references
            .get(&access.resource)
            .ok_or_else(|| invalid("operation access has no exact checked ResourceReference"))?;
        let admission =
            self.admit_resource(operation, reference, context.recovery_remaining_millis)?;
        let revision = match admission.revision {
            AdmissionRevision::Absent => ResourceRevisionObservation::Absent,
            AdmissionRevision::Present { revision } => {
                ResourceRevisionObservation::Present(revision)
            }
            AdmissionRevision::Unknown => ResourceRevisionObservation::Unknown,
        };
        let evidence = ResourceAdmissionEvidence::new_with_provider_and_revision_observation(
            access.resource.clone(),
            entry.assignment.clone(),
            revision,
            admission.observation.clone(),
        );
        Ok(CatalogReservation::new(
            CommandHandlerResourceHandle {
                reference: reference.clone(),
                assignment: entry.assignment.clone(),
                revision: entry.spec.revision,
                observation: admission.observation.clone(),
                native_context: admission.native_context,
                native_context_digest: admission.native_context_digest,
            },
            evidence,
        ))
    }

    fn release(
        &mut self,
        resource: &ResourceId,
        handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        if &handle.reference.resource != resource {
            return Err(invalid("command handler release is stale"));
        }
        Ok(())
    }
}

/// Executes every authenticated package handler through the shared command ABI.
pub(crate) struct CommandHandlerAdapter {
    assignment: ProviderAssignment,
    interface: InterfaceDocument,
    handler: AuthenticatedCommandHandler,
    blobs: TransactionBlobStore,
}

/// Authenticates the terminal handler selected by one provider assignment.
///
/// # Errors
///
/// Returns an error when the package does not contain the exact implementation,
/// handler, artifact, and executable selected by the assignment.
pub(crate) fn preflight_command_handler(
    package: &VerifiedPackageContract,
    assignment: &ProviderAssignment,
) -> Result<(), io::Error> {
    authenticate(package, &assignment.interface, &assignment.implementation).map(|_| ())
}

/// Authenticates a selected implementation before its live incarnation exists.
///
/// # Errors
///
/// Returns an error when the signed package does not bind the exact interface,
/// implementation, handler, artifact, and executable.
pub(crate) fn preflight_selected_handler(
    package: &VerifiedPackageContract,
    interface: &aos_ability_model::InterfaceKey,
    implementation: &ProviderImplementationReference,
) -> Result<(), io::Error> {
    authenticate(package, interface, implementation).map(|_| ())
}

impl CommandHandlerAdapter {
    /// Constructs an adapter after authenticating its selected handler and interface.
    ///
    /// # Errors
    ///
    /// Returns an error when either descriptor differs from the assignment.
    pub(crate) fn new(
        package: &VerifiedPackageContract,
        assignment: ProviderAssignment,
        interface: InterfaceDocument,
        blobs: TransactionBlobStore,
    ) -> Result<Self, io::Error> {
        let authenticated =
            authenticate(package, &assignment.interface, &assignment.implementation)?;
        authenticate_interface(&interface, &assignment)?;
        Ok(Self {
            handler: authenticated,
            assignment,
            interface,
            blobs,
        })
    }
    fn call(
        &self,
        request: &CommandHandlerRequest,
        purpose: RuntimeInvocationPurpose,
        control: &dyn RuntimeControl,
    ) -> Result<InvocationResult, io::Error> {
        let method = invocation_method(&request.durable, purpose)?;
        let invocation = Invocation {
            schema: INVOCATION_SCHEMA.into(),
            purpose: handler_purpose(purpose)?,
            semantics: method_semantics_for(&self.interface, &method)?,
            method,
            request: request.durable.clone(),
            control: invocation_control(
                control.attempt_remaining_millis(),
                control.recovery_remaining_millis(),
                control.is_cancelled(),
            ),
        };
        let blob_invocation = self.blobs.prepare(&request.durable)?;
        let output = invoke(
            &self.handler.executable,
            purpose_name(purpose),
            &encode(&invocation)?,
            control,
            &blob_invocation.environment(),
        )?;
        let mut result: InvocationResult = decode(&output)?;
        if result.disposition == HandlerInvocationDisposition::Completed {
            self.blobs
                .finalize_outputs(&blob_invocation, &mut result.outputs)?;
        }
        if result.schema != RESULT_SCHEMA
            || request.durable.native_context_digest != result.native_context_digest
        {
            return Err(invalid(
                "command handler result is not bound to admitted context",
            ));
        }
        let legal = match purpose {
            RuntimeInvocationPurpose::Effect => matches!(
                result.disposition,
                HandlerInvocationDisposition::Completed
                    | HandlerInvocationDisposition::RejectedBeforeEffect
                    | HandlerInvocationDisposition::Indeterminate
            ),
            RuntimeInvocationPurpose::Reconcile => matches!(
                result.disposition,
                HandlerInvocationDisposition::Completed
                    | HandlerInvocationDisposition::RejectedBeforeEffect
                    | HandlerInvocationDisposition::SafeToRetry
                    | HandlerInvocationDisposition::StillIndeterminate
                    | HandlerInvocationDisposition::InterventionRequired
            ),
            RuntimeInvocationPurpose::Cancel => matches!(
                result.disposition,
                HandlerInvocationDisposition::Completed
                    | HandlerInvocationDisposition::RejectedBeforeEffect
                    | HandlerInvocationDisposition::Indeterminate
            ),
            RuntimeInvocationPurpose::Compensate => matches!(
                result.disposition,
                HandlerInvocationDisposition::Completed
                    | HandlerInvocationDisposition::RejectedBeforeEffect
                    | HandlerInvocationDisposition::Indeterminate
            ),
            RuntimeInvocationPurpose::ReconcileCompensation => matches!(
                result.disposition,
                HandlerInvocationDisposition::Completed
                    | HandlerInvocationDisposition::RejectedBeforeEffect
                    | HandlerInvocationDisposition::SafeToRetry
                    | HandlerInvocationDisposition::StillIndeterminate
                    | HandlerInvocationDisposition::InterventionRequired
            ),
        };
        if !legal {
            return Err(invalid(
                "command handler returned a disposition illegal for its invocation purpose",
            ));
        }
        Ok(result)
    }
    fn failure(request: &CommandHandlerRequest) -> CommandHandlerRecord {
        request.failure.clone()
    }
}

impl TrustedAdapter for CommandHandlerAdapter {
    type Request = CommandHandlerRequest;
    type Completion = CommandHandlerRecord;
    type Observation = CommandHandlerRecord;
    type Handle = CommandHandlerResourceHandle;
    type PrepareError = io::Error;
    fn authenticates(
        &self,
        implementation: &ProviderImplementationReference,
        method: &MethodReference,
        purpose: RuntimeInvocationPurpose,
    ) -> bool {
        implementation == &self.assignment.implementation
            && method.interface == self.assignment.interface
            && authenticate_method_contract(&self.handler, &self.interface, method).is_ok()
            && matches!(
                purpose,
                RuntimeInvocationPurpose::Effect
                    | RuntimeInvocationPurpose::Reconcile
                    | RuntimeInvocationPurpose::Cancel
                    | RuntimeInvocationPurpose::Compensate
                    | RuntimeInvocationPurpose::ReconcileCompensation
            )
    }

    fn supports_compensation(&self) -> bool {
        true
    }
    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        let method = MethodReference {
            interface: operation.interface.clone(),
            method: operation.method.clone(),
        };
        authenticate_method_contract(&self.handler, &self.interface, &method)?;
        let references = checked_resource_references(operation, inputs, resources)?;

        let resource_contexts = resources
            .iter()
            .zip(references)
            .map(|(resource, reference)| ResourceContext {
                reference,
                assignment: resource.native().assignment.clone(),
                revision: resource.native().revision,
                observation: resource.native().observation.clone(),
                native_context: resource.native().native_context.clone(),
                native_context_digest: resource.native().native_context_digest,
            })
            .collect::<Vec<_>>();
        let native_context_digest = resource_set_digest(&resource_contexts).map_err(err)?;

        encode_value(&DurableRequest {
            schema: REQUEST_SCHEMA.into(),
            method,
            semantics: method_semantics(&self.interface, operation)?,
            recovery: RecoveryMethods {
                reconcile: operation.recovery.reconcile.clone(),
                cancel: operation.recovery.cancel.clone(),
                compensate: operation.recovery.compensate.clone(),
            },
            target: operation.target.clone(),
            inputs: inputs.clone(),
            resources: resource_contexts,
            native_context_digest,
        })
    }
    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        let request: DurableRequest =
            serde_json::from_value(durable.as_json().clone()).map_err(err)?;
        if request.schema != REQUEST_SCHEMA
            || request.resources.len() != resources.len()
            || resource_set_digest(&request.resources).map_err(err)?
                != request.native_context_digest
            || request
                .resources
                .iter()
                .zip(resources)
                .any(|(saved, fresh)| {
                    saved.reference != fresh.native().reference
                        || saved.assignment != fresh.native().assignment
                        || saved.revision != fresh.native().revision
                        || saved.observation != fresh.native().observation
                        || saved.native_context != fresh.native().native_context
                        || saved.native_context_digest != fresh.native().native_context_digest
                })
        {
            return Err(invalid(
                "command handler durable request differs from fresh admission",
            ));
        }
        authenticate_method_contract(&self.handler, &self.interface, &request.method)?;
        for recovery_method in [
            request.recovery.reconcile.as_ref(),
            request.recovery.cancel.as_ref(),
            request.recovery.compensate.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            authenticate_method_contract(&self.handler, &self.interface, recovery_method)?;
        }
        let failure = CommandHandlerRecord {
            durable: target_observation(&request.target, &request.resources)?.clone(),
            outputs: BTreeMap::new(),
        };

        Ok(CommandHandlerRequest {
            durable: request,
            failure,
        })
    }
    fn execute(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        match self.call(request, RuntimeInvocationPurpose::Effect, control) {
            Ok(result) => match result.disposition {
                HandlerInvocationDisposition::Completed => {
                    EffectDisposition::Completed(command_record(result))
                }
                HandlerInvocationDisposition::RejectedBeforeEffect => {
                    EffectDisposition::RejectedBeforeEffect(command_record(result))
                }
                _ => EffectDisposition::Indeterminate(command_record(result)),
            },
            Err(_) => EffectDisposition::Indeterminate(Self::failure(request)),
        }
    }
    fn reconcile(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        match self.call(request, RuntimeInvocationPurpose::Reconcile, control) {
            Ok(result) => match result.disposition {
                HandlerInvocationDisposition::Completed => {
                    ReconcileDisposition::Completed(command_record(result))
                }
                HandlerInvocationDisposition::RejectedBeforeEffect => {
                    ReconcileDisposition::RejectedBeforeEffect(command_record(result))
                }
                HandlerInvocationDisposition::SafeToRetry => {
                    ReconcileDisposition::SafeToRetry(command_record(result))
                }
                HandlerInvocationDisposition::InterventionRequired => {
                    ReconcileDisposition::InterventionRequired(command_record(result))
                }
                _ => ReconcileDisposition::StillIndeterminate(command_record(result)),
            },
            Err(_) => ReconcileDisposition::StillIndeterminate(Self::failure(request)),
        }
    }
    fn cancel(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        match self.call(request, RuntimeInvocationPurpose::Cancel, control) {
            Ok(result) => match result.disposition {
                HandlerInvocationDisposition::Completed => {
                    CancellationDisposition::Completed(command_record(result))
                }
                HandlerInvocationDisposition::RejectedBeforeEffect => {
                    CancellationDisposition::RejectedBeforeEffect(command_record(result))
                }
                _ => CancellationDisposition::Indeterminate(command_record(result)),
            },
            Err(_) => CancellationDisposition::Indeterminate(Self::failure(request)),
        }
    }

    fn compensate(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> Option<EffectDisposition<Self::Completion, Self::Observation>> {
        Some(
            match self.call(request, RuntimeInvocationPurpose::Compensate, control) {
                Ok(result) => match result.disposition {
                    HandlerInvocationDisposition::Completed => {
                        EffectDisposition::Completed(command_record(result))
                    }
                    HandlerInvocationDisposition::RejectedBeforeEffect => {
                        EffectDisposition::RejectedBeforeEffect(command_record(result))
                    }
                    _ => EffectDisposition::Indeterminate(command_record(result)),
                },
                Err(_) => EffectDisposition::Indeterminate(Self::failure(request)),
            },
        )
    }

    fn reconcile_compensation(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> Option<ReconcileDisposition<Self::Completion, Self::Observation>> {
        Some(
            match self.call(
                request,
                RuntimeInvocationPurpose::ReconcileCompensation,
                control,
            ) {
                Ok(result) => match result.disposition {
                    HandlerInvocationDisposition::Completed => {
                        ReconcileDisposition::Completed(command_record(result))
                    }
                    HandlerInvocationDisposition::RejectedBeforeEffect => {
                        ReconcileDisposition::RejectedBeforeEffect(command_record(result))
                    }
                    HandlerInvocationDisposition::SafeToRetry => {
                        ReconcileDisposition::SafeToRetry(command_record(result))
                    }
                    HandlerInvocationDisposition::InterventionRequired => {
                        ReconcileDisposition::InterventionRequired(command_record(result))
                    }
                    _ => ReconcileDisposition::StillIndeterminate(command_record(result)),
                },
                Err(_) => ReconcileDisposition::StillIndeterminate(Self::failure(request)),
            },
        )
    }
}

#[derive(Clone)]
struct AuthenticatedAdmission {
    revision: AdmissionRevision,
    observation: AbilityValue,
    native_context: AbilityValue,
    native_context_digest: Sha256Digest,
}

#[derive(Clone, Eq, PartialEq)]
struct AdmittedResourceContext {
    revision: AdmissionRevision,
    context: ResourceContext,
}

impl AdmittedResourceContext {
    fn new(
        reference: ResourceReference,
        entry: &CommandHandlerResourceEntry,
        admission: AuthenticatedAdmission,
    ) -> Self {
        let revision = admission.revision.clone();
        Self {
            revision,
            context: resource_context(reference, entry, admission),
        }
    }

    fn into_admission(self) -> AuthenticatedAdmission {
        AuthenticatedAdmission {
            revision: self.revision,
            observation: self.context.observation,
            native_context: self.context.native_context,
            native_context_digest: self.context.native_context_digest,
        }
    }

    fn same_authority(&self, other: &Self) -> bool {
        self.revision == other.revision
            && self.context.reference == other.context.reference
            && self.context.assignment == other.context.assignment
            && self.context.revision == other.context.revision
            && self.context.native_context_digest == other.context.native_context_digest
    }
}

#[derive(Clone)]
struct AuthenticatedCommandHandler {
    executable: PathBuf,
    arguments: ValueSchema,
    result: ValueSchema,
}

fn authenticate_method_contract(
    authenticated: &AuthenticatedCommandHandler,
    interface: &InterfaceDocument,
    method: &MethodReference,
) -> Result<(), io::Error> {
    let interface_key = interface.interface_key().map_err(err)?;
    if method.interface != interface_key {
        return Err(invalid(
            "command handler method differs from authenticated interface",
        ));
    }
    let descriptor = interface
        .interface
        .methods
        .get(&method.method)
        .ok_or_else(|| invalid("command handler method is absent from authenticated interface"))?;
    if authenticated.arguments != descriptor.parameters
        || authenticated.result != descriptor.outcome.completion_evidence
        || authenticated.result != descriptor.outcome.observation_evidence
    {
        return Err(invalid(
            "command handler schemas differ from the selected method contract",
        ));
    }
    Ok(())
}

fn authenticate_method_target(
    handler_interface: &InterfaceDocument,
    resource_interface: &InterfaceDocument,
    method: &MethodReference,
    target: &ResourceReference,
    spec: &CommandHandlerResourceSpec,
) -> Result<(), io::Error> {
    let descriptor = handler_interface
        .interface
        .methods
        .get(&method.method)
        .ok_or_else(|| invalid("command handler method is absent from authenticated interface"))?;
    let resource_interface = resource_interface.interface_key().map_err(err)?;
    if descriptor.target_resource != spec.kind
        || target.interface != resource_interface
        || target.interface.name != descriptor.target_resource
        || target.resource != spec.resource
        || target.lifetime != spec.lifetime
    {
        return Err(invalid(
            "command handler method target differs from its authenticated resource",
        ));
    }
    Ok(())
}

fn authenticate_interface(
    interface: &InterfaceDocument,
    assignment: &ProviderAssignment,
) -> Result<(), io::Error> {
    let key = interface.interface_key().map_err(err)?;
    if key != assignment.interface {
        return Err(invalid(
            "command handler interface document differs from authenticated assignment",
        ));
    }
    Ok(())
}

fn method_semantics(
    interface: &InterfaceDocument,
    operation: &Operation,
) -> Result<MethodSemantics, io::Error> {
    let key = interface.interface_key().map_err(err)?;
    if key != operation.interface {
        return Err(invalid(
            "command handler operation differs from authenticated interface",
        ));
    }
    method_semantics_for(
        interface,
        &MethodReference {
            interface: operation.interface.clone(),
            method: operation.method.clone(),
        },
    )
}

fn method_semantics_for(
    interface: &InterfaceDocument,
    method: &MethodReference,
) -> Result<MethodSemantics, io::Error> {
    let key = interface.interface_key().map_err(err)?;
    if key != method.interface {
        return Err(invalid(
            "command handler method differs from authenticated interface",
        ));
    }
    interface
        .interface
        .methods
        .get(&method.method)
        .map(|method| method.semantics.clone())
        .ok_or_else(|| invalid("command handler method is absent from authenticated interface"))
}

fn authenticate(
    package: &VerifiedPackageContract,
    interface: &aos_ability_model::InterfaceKey,
    implementation: &ProviderImplementationReference,
) -> Result<AuthenticatedCommandHandler, io::Error> {
    let key = implementation
        .handler
        .as_ref()
        .ok_or_else(|| invalid("command handler assignment has no handler"))?;
    let terminal = package
        .resolve_terminal_handler(implementation.descriptor, key)
        .ok_or_else(|| invalid("package does not resolve command handler"))?;
    if terminal.provider().interface != *interface
        || terminal.provider().artifact != implementation.artifact
        || terminal.handler().artifact != implementation.artifact
    {
        return Err(invalid(
            "command handler differs from authenticated assignment",
        ));
    }
    let executable = authenticate_handler_executable(
        &terminal.handler().artifact,
        &terminal.handler().entry_point,
        "package command",
    )?;
    Ok(AuthenticatedCommandHandler {
        executable,
        arguments: terminal.handler().arguments.clone(),
        result: terminal.handler().result.clone(),
    })
}

/// Resolves an executable while keeping it beneath its authenticated artifact.
fn authenticate_handler_executable(
    artifact: &aos_ability_model::ArtifactReference,
    entry_point: &str,
    subject: &str,
) -> Result<PathBuf, io::Error> {
    let relative = Path::new(entry_point);
    if entry_point.is_empty()
        || entry_point.len() as u64 > aos_ability_model::ABILITY_LIMITS_V1.max_string_bytes
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(invalid(format!(
            "signed {subject} handler entry point is not a safe relative path"
        )));
    }

    let artifact_root = std::fs::canonicalize(&artifact.store_path).map_err(|error| {
        invalid(format!(
            "resolving signed {subject} handler artifact: {error}"
        ))
    })?;
    let executable = std::fs::canonicalize(artifact_root.join(relative)).map_err(|error| {
        invalid(format!(
            "resolving signed {subject} handler executable: {error}"
        ))
    })?;
    if !executable.starts_with(&artifact_root) {
        return Err(invalid(format!(
            "signed {subject} handler executable escapes its authenticated artifact"
        )));
    }

    let metadata = std::fs::metadata(&executable).map_err(|error| {
        invalid(format!(
            "reading signed {subject} handler executable metadata: {error}"
        ))
    })?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(invalid(format!(
            "signed {subject} handler entry point is not a regular executable file"
        )));
    }

    Ok(executable)
}
fn invoke(
    executable: &Path,
    purpose: &str,
    input: &[u8],
    control: &dyn RuntimeControl,
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Vec<u8>, io::Error> {
    let mut command = Command::new(executable);
    command.arg(HANDLER_ABI_ARGUMENT).arg(purpose);
    let output = run_bounded(
        &mut command,
        Some(input),
        MAX_HANDLER_RESULT_BYTES,
        DescendantPolicy::Reap,
        control,
        environment,
    )?;
    if !output.status.success() {
        return Err(invalid("command handler exited unsuccessfully"));
    }
    Ok(output.stdout)
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, io::Error> {
    aos_contract::canonical::to_vec(value).map_err(err)
}
fn encode_value<T: Serialize>(value: &T) -> Result<AbilityValue, io::Error> {
    AbilityValue::new(serde_json::to_value(value).map_err(err)?).map_err(err)
}
fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, io::Error> {
    serde_json::from_value(
        aos_contract::canonical::parse_json(bytes, "command handler message").map_err(err)?,
    )
    .map_err(err)
}
fn bind_native_context(
    spec: &CommandHandlerResourceSpec,
    provider_context: AbilityValue,
) -> Result<AbilityValue, io::Error> {
    encode_value(&BoundNativeContext {
        schema: RESOURCE_CONTEXT_SCHEMA.into(),
        resource_spec: resource_spec(spec),
        provider_context,
    })
}

fn resource_spec(spec: &CommandHandlerResourceSpec) -> ResourceSpec {
    ResourceSpec {
        resource: spec.resource.clone(),
        kind: spec.kind.clone(),
        lifetime: spec.lifetime,
        value: spec.value.clone(),
        realization: spec.realization.clone(),
        revision: spec.revision,
    }
}

fn target_observation<'a>(
    target: &ResourceReference,
    resources: &'a [ResourceContext],
) -> Result<&'a AbilityValue, io::Error> {
    resources
        .iter()
        .find(|context| context.reference.resource == target.resource)
        .map(|context| &context.observation)
        .ok_or_else(|| invalid("command handler target has no admitted observation"))
}

/// Recovers the exact checked references that authorized every acquired handle.
///
/// Resolved inputs retain typed references as their canonical wire objects. A
/// handler receives those complete references so it can echo protected outputs
/// without reconstructing an interface, operation set, or lifetime.
fn checked_resource_references(
    operation: &Operation,
    inputs: &AbilityValue,
    resources: &[ResourceHandle<CommandHandlerResourceHandle>],
) -> Result<Vec<ResourceReference>, io::Error> {
    let mut references = BTreeMap::new();
    insert_reference(&mut references, operation.target.clone())?;
    collect_resource_references(inputs.as_json(), &mut references)?;

    resources
        .iter()
        .map(|resource| {
            let reference = references
                .get(resource.resource())
                .ok_or_else(|| invalid("acquired resource has no checked ResourceReference"))?;
            if reference != &resource.native().reference {
                return Err(invalid(
                    "acquired resource handle differs from its checked ResourceReference",
                ));
            }
            Ok(reference.clone())
        })
        .collect()
}

fn collect_resource_references(
    value: &serde_json::Value,
    references: &mut BTreeMap<ResourceId, ResourceReference>,
) -> Result<(), io::Error> {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_resource_references(value, references)?;
            }
        }
        serde_json::Value::Object(values) => {
            if let Ok(reference) = serde_json::from_value::<ResourceReference>(
                serde_json::Value::Object(values.clone()),
            ) {
                insert_reference(references, reference)?;
                return Ok(());
            }
            for value in values.values() {
                collect_resource_references(value, references)?;
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
    Ok(())
}

fn closed_resource_references_from_plan(
    operation: &Operation,
    plan: &CheckedEffectPlan,
) -> Result<BTreeMap<ResourceId, ResourceReference>, io::Error> {
    let mut references = BTreeMap::new();
    insert_reference(&mut references, operation.target.clone())?;
    let inputs = serde_json::to_value(&operation.inputs).map_err(err)?;
    collect_resource_references(&inputs, &mut references)?;

    loop {
        let resources_to_scan = references.keys().cloned().collect::<Vec<_>>();
        let previous_count = resources_to_scan.len();
        for resource in resources_to_scan {
            let revision = resolved_resource_revision(plan, &resource)?;
            collect_resource_references(revision.value.as_json(), &mut references)?;
            collect_resource_references(revision.realization.as_json(), &mut references)?;
        }
        if references.len() == previous_count {
            break;
        }
    }

    for reference in references.values() {
        let revision = resolved_resource_revision(plan, &reference.resource)?;
        let interface = plan
            .interfaces()
            .get(&reference.interface)
            .ok_or_else(|| invalid("referenced interface is outside the checked plan"))?;
        if interface.interface_key().map_err(err)? != reference.interface
            || reference.interface.name != revision.kind
            || reference.lifetime != revision.lifetime
            || reference.operations.is_empty()
        {
            return Err(invalid(
                "checked ResourceReference differs from its resolved resource",
            ));
        }
    }
    for reference in references.values() {
        if !operation
            .accesses
            .iter()
            .any(|access| access.resource == reference.resource)
        {
            return Err(invalid(
                "checked ResourceReference lacks an operation resource access",
            ));
        }
    }
    if operation
        .accesses
        .iter()
        .any(|access| !references.contains_key(&access.resource))
    {
        return Err(invalid(
            "operation access has no exact checked ResourceReference",
        ));
    }

    Ok(references)
}

fn resolved_resource_revision<'a>(
    plan: &'a CheckedEffectPlan,
    resource: &ResourceId,
) -> Result<&'a aos_ability_model::ResourceRevision, io::Error> {
    let desired = plan
        .document()
        .desired_revisions
        .binary_search_by(|revision| revision.resource.cmp(resource))
        .ok()
        .map(|index| &plan.document().desired_revisions[index]);
    let current = plan
        .document()
        .current_revisions
        .binary_search_by(|revision| revision.resource.cmp(resource))
        .ok()
        .map(|index| &plan.document().current_revisions[index]);

    desired
        .or(current)
        .ok_or_else(|| invalid("referenced resource is absent from the checked plan"))
}

fn resource_owner_operation<'a>(
    plan: &'a CheckedEffectPlan,
    selected: &'a Operation,
    reference: &ResourceReference,
) -> Result<&'a Operation, io::Error> {
    if selected.target.resource == reference.resource {
        return Ok(selected);
    }

    let mut candidates = plan.operations().iter().filter(|candidate| {
        candidate.target.resource == reference.resource
            && candidate.target.interface == reference.interface
    });
    let owner = candidates
        .next()
        .ok_or_else(|| invalid("referenced resource has no checked provider operation"))?;
    let binding = plan
        .binding_plan()
        .binding(&owner.binding)
        .ok_or_else(|| invalid("referenced resource owner binding is absent"))?;
    for candidate in candidates {
        let candidate_binding = plan
            .binding_plan()
            .binding(&candidate.binding)
            .ok_or_else(|| invalid("referenced resource owner binding is absent"))?;
        if candidate_binding.provider != binding.provider
            || candidate_binding.interface != binding.interface
            || candidate_binding.implementation != binding.implementation
            || candidate_binding.provider_package != binding.provider_package
        {
            return Err(invalid(
                "referenced resource has ambiguous checked handler ownership",
            ));
        }
    }

    Ok(owner)
}

fn closed_resource_references(
    operation: &Operation,
    resources: &BTreeMap<ResourceId, CommandHandlerResourceEntry>,
) -> Result<BTreeMap<ResourceId, ResourceReference>, io::Error> {
    let mut references = BTreeMap::new();
    insert_reference(&mut references, operation.target.clone())?;
    let inputs = serde_json::to_value(&operation.inputs).map_err(err)?;
    collect_resource_references(&inputs, &mut references)?;
    expand_reference_closure(&mut references, resources)?;

    for reference in references.values() {
        if !operation
            .accesses
            .iter()
            .any(|access| access.resource == reference.resource)
        {
            return Err(invalid(
                "checked ResourceReference lacks an operation resource access",
            ));
        }
    }
    if operation
        .accesses
        .iter()
        .any(|access| !references.contains_key(&access.resource))
    {
        return Err(invalid(
            "operation access has no exact checked ResourceReference",
        ));
    }
    Ok(references)
}

fn resource_reference_closure(
    target: &ResourceReference,
    resources: &BTreeMap<ResourceId, CommandHandlerResourceEntry>,
) -> Result<BTreeMap<ResourceId, ResourceReference>, io::Error> {
    let mut references = BTreeMap::new();
    insert_reference(&mut references, target.clone())?;
    expand_reference_closure(&mut references, resources)?;
    Ok(references)
}

fn admitted_contexts(
    references: &BTreeMap<ResourceId, ResourceReference>,
    target: &ResourceId,
    admitted: &BTreeMap<ResourceId, AdmittedResourceContext>,
) -> Result<Vec<ResourceContext>, io::Error> {
    references
        .keys()
        .filter(|resource| *resource != target)
        .map(|resource| {
            admitted
                .get(resource)
                .map(|admission| admission.context.clone())
                .ok_or_else(|| invalid("dependency closure was not admitted exactly once"))
        })
        .collect()
}

fn expand_reference_closure(
    references: &mut BTreeMap<ResourceId, ResourceReference>,
    resources: &BTreeMap<ResourceId, CommandHandlerResourceEntry>,
) -> Result<(), io::Error> {
    loop {
        let resources_to_scan = references.keys().cloned().collect::<Vec<_>>();
        let previous_count = resources_to_scan.len();
        for resource in resources_to_scan {
            let entry = resources.get(&resource).ok_or_else(|| {
                invalid("checked realization references a resource outside resolved resources")
            })?;
            collect_resource_references(entry.spec.value.as_json(), references)?;
            collect_resource_references(entry.spec.realization.as_json(), references)?;
        }
        if references.len() == previous_count {
            break;
        }
    }

    for reference in references.values() {
        let entry = resources.get(&reference.resource).ok_or_else(|| {
            invalid("checked realization references a resource outside resolved resources")
        })?;
        authenticate_resource_reference(reference, entry)?;
    }
    Ok(())
}

fn authenticate_resource_reference(
    reference: &ResourceReference,
    entry: &CommandHandlerResourceEntry,
) -> Result<(), io::Error> {
    let resource_interface = entry.resource_interface.interface_key().map_err(err)?;
    if reference.interface != resource_interface
        || reference.interface.name != entry.spec.kind
        || reference.resource != entry.spec.resource
        || reference.lifetime != entry.spec.lifetime
        || reference.operations.is_empty()
    {
        return Err(invalid(
            "checked ResourceReference differs from its resolved handler resource",
        ));
    }
    Ok(())
}

fn admission_method(
    operation: &Operation,
    reference: &ResourceReference,
    entry: &CommandHandlerResourceEntry,
) -> Result<MethodReference, io::Error> {
    let method = if reference.resource == operation.target.resource {
        if operation.target != *reference {
            return Err(invalid(
                "command handler target differs from its checked ResourceReference",
            ));
        }
        &operation.method
    } else {
        dependency_admission_method(reference, &entry.handler_interface)?
    };
    if reference.operations.binary_search(method).is_err() {
        return Err(invalid(
            "selected operation is outside its checked ResourceReference authority",
        ));
    }
    Ok(MethodReference {
        interface: entry.assignment.interface.clone(),
        method: method.clone(),
    })
}

fn dependency_admission_method<'a>(
    reference: &'a ResourceReference,
    interface: &InterfaceDocument,
) -> Result<&'a LocalKey, io::Error> {
    let declared_method = |method: &&LocalKey| interface.interface.methods.get(*method);

    reference
        .operations
        .iter()
        .find(|method| {
            declared_method(method).is_some_and(|descriptor| {
                descriptor.semantics.required_target_access == AccessMode::Read
            })
        })
        .or_else(|| {
            reference
                .operations
                .iter()
                .find(|method| declared_method(method).is_some())
        })
        .ok_or_else(|| {
            invalid("dependency ResourceReference grants no selected handler admission method")
        })
}

fn resource_context(
    reference: ResourceReference,
    entry: &CommandHandlerResourceEntry,
    admission: AuthenticatedAdmission,
) -> ResourceContext {
    ResourceContext {
        reference,
        assignment: entry.assignment.clone(),
        revision: entry.spec.revision,
        observation: admission.observation,
        native_context: admission.native_context,
        native_context_digest: admission.native_context_digest,
    }
}

fn insert_reference(
    references: &mut BTreeMap<ResourceId, ResourceReference>,
    reference: ResourceReference,
) -> Result<(), io::Error> {
    if references
        .insert(reference.resource.clone(), reference.clone())
        .is_some_and(|existing| existing != reference)
    {
        return Err(invalid(
            "one resource resolved to conflicting checked ResourceReferences",
        ));
    }
    Ok(())
}

const fn purpose_name(purpose: RuntimeInvocationPurpose) -> &'static str {
    match purpose {
        RuntimeInvocationPurpose::Effect => "effect",
        RuntimeInvocationPurpose::Reconcile => "reconcile",
        RuntimeInvocationPurpose::Cancel => "cancel",
        RuntimeInvocationPurpose::Compensate => "compensate",
        RuntimeInvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}

fn handler_purpose(
    purpose: RuntimeInvocationPurpose,
) -> Result<HandlerInvocationPurpose, io::Error> {
    match purpose {
        RuntimeInvocationPurpose::Effect => Ok(HandlerInvocationPurpose::Effect),
        RuntimeInvocationPurpose::Reconcile => Ok(HandlerInvocationPurpose::Reconcile),
        RuntimeInvocationPurpose::Cancel => Ok(HandlerInvocationPurpose::Cancel),
        RuntimeInvocationPurpose::Compensate => Ok(HandlerInvocationPurpose::Compensate),
        RuntimeInvocationPurpose::ReconcileCompensation => {
            Ok(HandlerInvocationPurpose::ReconcileCompensation)
        }
    }
}

fn required_purposes(operation: &Operation) -> Vec<HandlerInvocationPurpose> {
    let mut purposes = vec![HandlerInvocationPurpose::Effect];
    if operation.recovery.reconcile.is_some() {
        purposes.push(HandlerInvocationPurpose::Reconcile);
    }
    if operation.recovery.cancel.is_some() {
        purposes.push(HandlerInvocationPurpose::Cancel);
    }
    if operation.recovery.compensate.is_some() {
        purposes.push(HandlerInvocationPurpose::Compensate);
        if operation.recovery.reconcile.is_some() {
            purposes.push(HandlerInvocationPurpose::ReconcileCompensation);
        }
    }
    purposes
}

fn invocation_method(
    request: &DurableRequest,
    purpose: RuntimeInvocationPurpose,
) -> Result<MethodReference, io::Error> {
    let method = match purpose {
        RuntimeInvocationPurpose::Effect => Some(&request.method),
        RuntimeInvocationPurpose::Reconcile | RuntimeInvocationPurpose::ReconcileCompensation => {
            request.recovery.reconcile.as_ref()
        }
        RuntimeInvocationPurpose::Cancel => request.recovery.cancel.as_ref(),
        RuntimeInvocationPurpose::Compensate => request.recovery.compensate.as_ref(),
    };
    method
        .cloned()
        .ok_or_else(|| invalid("command handler invocation purpose has no authorized method"))
}

const fn invocation_control(
    attempt_remaining_millis: u64,
    recovery_remaining_millis: u64,
    cancelled: bool,
) -> InvocationControl {
    InvocationControl {
        attempt_remaining_millis,
        recovery_remaining_millis,
        cancelled,
    }
}

fn command_record(result: InvocationResult) -> CommandHandlerRecord {
    CommandHandlerRecord {
        durable: result.evidence,
        outputs: result.outputs,
    }
}

fn err(error: impl std::fmt::Display) -> io::Error {
    invalid(error.to_string())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_ability_model::{
        AggregationContract, AggregationScope, IndeterminateSemantics, InterfaceDescriptor,
        LifecycleSemantics, MethodDescriptor, OutcomeSemantics,
    };

    use super::*;

    fn interface_document(name: &str, target_resource: Option<&str>) -> InterfaceDocument {
        let methods = target_resource
            .map(|target_resource| {
                BTreeMap::from([(
                    LocalKey::new("apply").expect("method name is valid"),
                    MethodDescriptor {
                        description: "Applies the test resource.".into(),
                        semantics: MethodSemantics::ordinary(
                            aos_ability_model::AccessMode::ExclusiveWrite,
                        ),
                        parameters: ValueSchema::Boolean,
                        target_resource: InterfaceName::new(target_resource)
                            .expect("target resource name is valid"),
                        outputs: BTreeMap::new(),
                        permitted_operations: Vec::new(),
                        guarantees: Vec::new(),
                        outcome: OutcomeSemantics {
                            completion_evidence: ValueSchema::Boolean,
                            observation_evidence: ValueSchema::Boolean,
                            supports_rejected_before_effect: true,
                            indeterminate: IndeterminateSemantics::Reconcile,
                        },
                    },
                )])
            })
            .unwrap_or_default();

        InterfaceDocument {
            schema: "aos.ability.interface/v1".into(),
            required_features: Vec::new(),
            interface: InterfaceDescriptor {
                name: InterfaceName::new(name).expect("interface name is valid"),
                abi: NonZeroU32::MIN,
                description: "Defines a test interface.".into(),
                request: ValueSchema::Boolean,
                configuration: None,
                outputs: BTreeMap::new(),
                methods,
                lifecycle: LifecycleSemantics {
                    persistent_delete_method: None,
                },
                aggregation: AggregationContract {
                    scope: AggregationScope::ProviderInstance,
                    key: LocalKey::new("slot").expect("aggregation key is valid"),
                    controller_group: LocalKey::new("test").expect("controller group is valid"),
                    reject_slot_collisions: true,
                    merge_contract: None,
                },
                guarantees: Vec::new(),
            },
        }
    }

    fn resource_reference(key: &str, operations: &[&str]) -> ResourceReference {
        serde_json::from_value(serde_json::json!({
            "interface": {
                "name": "aos.test.resource",
                "abi": 1,
                "descriptor": format!("sha256:{}", "0".repeat(64)),
            },
            "resource": {
                "provider": {
                    "environment": {
                        "authority": "test",
                        "key": "host",
                        "stage": "host",
                    },
                    "key": "provider",
                },
                "key": key,
            },
            "operations": operations,
            "lifetime": "instance",
        }))
        .expect("resource reference is valid")
    }

    #[test]
    fn dependency_admission_prefers_declared_read_semantics() {
        let mut interface = interface_document("aos.test.terminal", Some("aos.test.resource"));
        let mut read_method = interface
            .interface
            .methods
            .get("apply")
            .expect("write method is declared")
            .clone();
        read_method.semantics.required_target_access = AccessMode::Read;
        interface.interface.methods.insert(
            LocalKey::new("read-state").expect("method name is valid"),
            read_method,
        );
        let reference = resource_reference("dependency", &["apply", "read-state"]);

        let selected = dependency_admission_method(&reference, &interface)
            .expect("a declared admission method is selected");

        assert_eq!(selected.as_str(), "read-state");
    }

    #[test]
    fn terminal_method_authenticates_a_distinct_controller_resource_interface() {
        let handler_interface = interface_document("aos.test.terminal", Some("aos.test.resource"));
        let resource_interface = interface_document("aos.test.resource", None);
        let method = MethodReference {
            interface: handler_interface
                .interface_key()
                .expect("handler interface key is valid"),
            method: LocalKey::new("apply").expect("method name is valid"),
        };
        let target = resource_reference("service", &["apply"]);
        let spec = resource_spec(serde_json::json!({"enabled": true}));

        authenticate_method_target(
            &handler_interface,
            &resource_interface,
            &method,
            &target,
            &spec,
        )
        .expect("terminal method may target its declared controller resource");

        let wrong_resource_interface = interface_document("aos.test.other-resource", None);
        assert!(
            authenticate_method_target(
                &handler_interface,
                &wrong_resource_interface,
                &method,
                &target,
                &spec,
            )
            .is_err()
        );

        let wrong_handler_interface =
            interface_document("aos.test.terminal", Some("aos.test.other-resource"));
        assert!(
            authenticate_method_target(
                &wrong_handler_interface,
                &resource_interface,
                &method,
                &target,
                &spec,
            )
            .is_err()
        );
    }

    fn resource_spec(value: serde_json::Value) -> CommandHandlerResourceSpec {
        CommandHandlerResourceSpec {
            resource: resource_reference("service", &["start"]).resource,
            kind: InterfaceName::new("aos.test.resource").expect("resource kind is valid"),
            lifetime: ResourceLifetime::Instance,
            revision: RevisionId(Sha256Digest::of_bytes("resource revision")),
            value: AbilityValue::new(value).expect("desired value is bounded"),
            realization: AbilityValue::new(serde_json::json!({
                "schema": "aos.test.realization/v1",
                "unit": "example.service",
            }))
            .expect("realization is bounded"),
        }
    }

    fn admitted_context(reference: ResourceReference) -> AdmittedResourceContext {
        let native_context = AbilityValue::new(serde_json::json!({"loaded": false}))
            .expect("native context is bounded");
        let assignment = serde_json::from_value(serde_json::json!({
            "provider": reference.resource.provider.clone(),
            "interface": reference.interface.clone(),
            "implementation": {
                "descriptor": format!("sha256:{}", "2".repeat(64)),
                "artifact": {
                    "content": format!("sha256:{}", "3".repeat(64)),
                    "store_path": "/nix/store/00000000000000000000000000000000-fixture",
                    "nar_hash": format!("sha256:{}", "4".repeat(64)),
                    "closure": format!("sha256:{}", "5".repeat(64)),
                },
                "handler": "fixture",
            },
            "incarnation": "fixture-incarnation",
        }))
        .expect("provider assignment fixture is valid");
        let revision = RevisionId(Sha256Digest::of_bytes("resource revision"));

        AdmittedResourceContext {
            revision: AdmissionRevision::Present { revision },
            context: ResourceContext {
                reference,
                assignment,
                revision,
                observation: AbilityValue::new(serde_json::json!({"ready": true}))
                    .expect("observation is bounded"),
                native_context_digest: native_context_digest(&native_context)
                    .expect("context hashes"),
                native_context,
            },
        }
    }

    #[test]
    fn resolved_inputs_preserve_complete_resource_reference_authority() {
        let dependency = resource_reference("dependency", &["observe"]);
        let input = AbilityValue::new(serde_json::json!({
            "nested": [{"source": dependency}],
        }))
        .expect("resolved input is bounded");
        let mut references = BTreeMap::new();

        collect_resource_references(input.as_json(), &mut references)
            .expect("references are collected");

        let preserved = references.values().next().expect("reference is present");
        assert_eq!(preserved.operations[0].as_str(), "observe");
        assert_eq!(
            preserved.lifetime,
            aos_ability_model::ResourceLifetime::Instance
        );
    }

    #[test]
    fn conflicting_authority_for_one_resource_is_rejected() {
        let observe = resource_reference("dependency", &["observe"]);
        let mutate = resource_reference("dependency", &["materialize"]);
        let mut references = BTreeMap::new();

        insert_reference(&mut references, observe).expect("first reference is accepted");
        let error = insert_reference(&mut references, mutate)
            .expect_err("conflicting operations cannot be merged");

        assert!(error.to_string().contains("conflicting checked"));
    }

    #[test]
    fn cyclic_admission_requires_every_peer_context() {
        let first = resource_reference("first", &["observe"]);
        let second = resource_reference("second", &["observe"]);
        let references = BTreeMap::from([
            (first.resource.clone(), first.clone()),
            (second.resource.clone(), second.clone()),
        ]);
        let mut admitted = BTreeMap::new();

        let missing = admitted_contexts(&references, &first.resource, &admitted)
            .expect_err("a cycle seed cannot masquerade as a complete admission");
        assert!(missing.to_string().contains("not admitted exactly once"));

        admitted.insert(second.resource.clone(), admitted_context(second.clone()));
        let contexts = admitted_contexts(&references, &first.resource, &admitted)
            .expect("the complete peer set is accepted");
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].reference, second);
    }

    #[test]
    fn admitted_context_binds_checked_value_and_realization() {
        let provider_context = AbilityValue::new(serde_json::json!({"loaded": false}))
            .expect("provider context is bounded");
        let first = bind_native_context(
            &resource_spec(serde_json::json!({"enabled": true})),
            provider_context.clone(),
        )
        .expect("context binds");
        let second = bind_native_context(
            &resource_spec(serde_json::json!({"enabled": false})),
            provider_context,
        )
        .expect("context binds");

        assert_eq!(
            first.as_json()["resource_spec"]["realization"]["unit"],
            "example.service"
        );
        assert_eq!(first.as_json()["resource_spec"]["value"]["enabled"], true);
        assert_ne!(
            native_context_digest(&first).expect("first context hashes"),
            native_context_digest(&second).expect("second context hashes")
        );
    }

    #[test]
    fn transport_failure_reuses_the_admitted_target_observation() {
        let target = resource_reference("service", &["start"]);
        let dependency = resource_reference("credential", &["observe"]);
        let observation = AbilityValue::new(serde_json::json!({
            "schema": "aos.test.service-observation/v1",
            "expected": {
                "credential": dependency,
            },
            "state": "unknown",
        }))
        .expect("observation is bounded");
        let native_context =
            AbilityValue::new(serde_json::json!({"loaded": false})).expect("context is bounded");
        let resources = vec![ResourceContext {
            reference: target.clone(),
            assignment: serde_json::from_value(serde_json::json!({
                "provider": target.resource.provider,
                "interface": {
                    "name": "aos.test.lifecycle",
                    "abi": 1,
                    "descriptor": format!("sha256:{}", "1".repeat(64)),
                },
                "implementation": {
                    "descriptor": format!("sha256:{}", "2".repeat(64)),
                    "artifact": {
                        "content": format!("sha256:{}", "3".repeat(64)),
                        "store_path": "/nix/store/00000000000000000000000000000000-fixture",
                        "nar_hash": format!("sha256:{}", "4".repeat(64)),
                        "closure": format!("sha256:{}", "5".repeat(64)),
                    },
                    "handler": "fixture",
                },
                "incarnation": "fixture-incarnation",
            }))
            .expect("provider assignment fixture is valid"),
            revision: RevisionId(Sha256Digest::of_bytes("resource revision")),
            observation: observation.clone(),
            native_context_digest: native_context_digest(&native_context).expect("context hashes"),
            native_context,
        }];

        assert_eq!(
            target_observation(&target, &resources).expect("target observation is present"),
            &observation
        );
        assert!(
            target_observation(&resource_reference("other", &["observe"]), &resources).is_err()
        );
    }
}
