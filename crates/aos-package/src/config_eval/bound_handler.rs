//! Binding-native calls to authenticated package handlers.
//!
//! A bound call is authorized by a checked [`Binding`], one exact interface
//! method, a live provider assignment, and complete typed resource context. It
//! does not require or synthesize an effect-plan operation.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, Binding, BindingId, InterfaceDocument, LocalKey, MethodReference,
    ProviderAssignment, ResourceReference, TransactionId,
};
use aos_ability_runtime::adapter::RuntimeControl;
use aos_ability_validate::CheckedBindingPlan;
use aos_provider_protocol::{
    DurableRequest, InvocationDisposition, InvocationPurpose, InvocationResult, RecoveryMethods,
    ResourceContext, ResourceSpec, TransactionBlobReference,
};
use serde::{Deserialize, Serialize};

use super::bound_handler_store::{BoundCallJournal, BoundCallPhase, BoundCallStore};
use super::command_handler::{BoundCommandHandler, CommandHandlerResourceSpec};
use super::transaction_blob::TransactionBlobStore;
use crate::package_contract::VerifiedPackageContractSet;

const DEFAULT_CALL_BUDGET_MILLIS: u64 = 60_000;

/// Removes abandoned drafts and terminal call state during runtime startup.
///
/// Prepared and executing calls remain available for explicit recovery.
///
/// # Errors
///
/// Returns an error when the runtime contains malformed state or cleanup fails.
pub fn recover_bound_handler_runtime(runtime_root: &Path) -> Result<()> {
    super::bound_handler_store::recover_runtime(runtime_root)
        .context("recovering bound-handler runtime state")
}

/// Selects one method from an exact checked binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundHandlerSelector {
    /// Identifies the binding retained by the checked fixed point.
    pub binding: BindingId,
    /// Names one method on the binding's selected interface.
    pub method: LocalKey,
}

/// Supplies the target and supporting contexts for one binding-native method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundHandlerTarget {
    /// Carries the complete target resource authority.
    pub reference: ResourceReference,
    /// Authenticates the interface that owns the target resource value.
    pub interface: InterfaceDocument,
    /// Carries the desired and realized target selected by the fixed point.
    pub resource: ResourceSpec,
    /// Carries already admitted supporting resources in canonical order.
    pub resources: Vec<ResourceContext>,
    /// Declares the methods allowed to settle an interrupted call.
    pub recovery: RecoveryMethods,
}

/// Identifies the immutable route retained by a bound handler client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundHandlerIdentity {
    /// Authenticates the complete checked binding plan.
    pub binding_plan: aos_ability_model::PlanId,
    /// Retains the exact checked binding and its complete caller authority.
    pub binding: Binding,
    /// Retains the exact selected interface document.
    pub interface: InterfaceDocument,
    /// Identifies the live provider assignment.
    pub assignment: ProviderAssignment,
    /// Identifies the selected interface method.
    pub method: MethodReference,
    /// Retains the exact target resource and supporting contexts.
    pub target: BoundHandlerTarget,
}

/// Retains one checked binding-native provider route for repeated calls.
pub struct BoundHandlerClient {
    identity: BoundHandlerIdentity,
    runtime_root: PathBuf,
    transport: Box<dyn BoundHandlerTransport>,
    budget_millis: u64,
}

trait BoundHandlerTransport {
    fn admit(
        &self,
        method: &MethodReference,
        target: &ResourceReference,
        resource_interface: &InterfaceDocument,
        spec: &CommandHandlerResourceSpec,
        resources: Vec<ResourceContext>,
        required_purposes: Vec<InvocationPurpose>,
        remaining_millis: u64,
    ) -> Result<ResourceContext, std::io::Error>;

    fn durable_request(
        &self,
        method: MethodReference,
        target: ResourceReference,
        inputs: AbilityValue,
        resources: Vec<ResourceContext>,
        recovery: RecoveryMethods,
    ) -> Result<DurableRequest, std::io::Error>;

    fn invoke(
        &self,
        request: &DurableRequest,
        purpose: InvocationPurpose,
        control: &dyn RuntimeControl,
        blobs: &TransactionBlobStore,
    ) -> Result<InvocationResult, std::io::Error>;
}

impl BoundHandlerTransport for BoundCommandHandler {
    fn admit(
        &self,
        method: &MethodReference,
        target: &ResourceReference,
        resource_interface: &InterfaceDocument,
        spec: &CommandHandlerResourceSpec,
        resources: Vec<ResourceContext>,
        required_purposes: Vec<InvocationPurpose>,
        remaining_millis: u64,
    ) -> Result<ResourceContext, std::io::Error> {
        Self::admit(
            self,
            method,
            target,
            resource_interface,
            spec,
            resources,
            required_purposes,
            remaining_millis,
        )
    }

    fn durable_request(
        &self,
        method: MethodReference,
        target: ResourceReference,
        inputs: AbilityValue,
        resources: Vec<ResourceContext>,
        recovery: RecoveryMethods,
    ) -> Result<DurableRequest, std::io::Error> {
        Self::durable_request(self, method, target, inputs, resources, recovery)
    }

    fn invoke(
        &self,
        request: &DurableRequest,
        purpose: InvocationPurpose,
        control: &dyn RuntimeControl,
        blobs: &TransactionBlobStore,
    ) -> Result<InvocationResult, std::io::Error> {
        Self::invoke(self, request, purpose, control, blobs)
    }
}

/// Owns one draft or recoverable handler call.
pub struct BoundHandlerCall<'client> {
    client: &'client BoundHandlerClient,
    transaction: TransactionId,
    store: Option<BoundCallStore>,
}

/// Owns a terminal result and removes all call state when consumed or dropped.
pub struct BoundHandlerResult {
    result: InvocationResult,
    store: Option<BoundCallStore>,
}

/// Describes the durable state left after a bound invocation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundHandlerFailureState {
    /// The draft call was removed before an effect intent became durable.
    CleanedBeforePreparation,
    /// The draft could not be removed and startup cleanup remains necessary.
    CleanupPending,
    /// A prepared or executing call remains available to [`BoundHandlerClient::recover`].
    RetainedForRecovery,
}

/// Reports a failed invocation together with its exact durable call identity.
#[derive(Debug)]
pub struct BoundHandlerInvocationError {
    transaction: TransactionId,
    state: BoundHandlerFailureState,
    source: anyhow::Error,
}

/// Returns either a terminal handler result or a state-aware invocation error.
pub type BoundHandlerInvocationResult =
    std::result::Result<BoundHandlerResult, BoundHandlerInvocationError>;

impl BoundHandlerInvocationError {
    /// Returns the transaction allocated to the failed call.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// Returns the durable state left by the failed invocation.
    #[must_use]
    pub const fn state(&self) -> BoundHandlerFailureState {
        self.state
    }

    /// Returns the transaction when the call can be passed to recovery.
    #[must_use]
    pub fn recovery_transaction(&self) -> Option<&TransactionId> {
        (self.state == BoundHandlerFailureState::RetainedForRecovery).then_some(&self.transaction)
    }

    fn new(
        transaction: TransactionId,
        state: BoundHandlerFailureState,
        source: anyhow::Error,
    ) -> Self {
        Self {
            transaction,
            state,
            source,
        }
    }
}

impl std::fmt::Display for BoundHandlerInvocationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "bound-handler invocation {} failed with {:?} state: {:#}",
            self.transaction.0, self.state, self.source
        )
    }
}

impl std::error::Error for BoundHandlerInvocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl BoundHandlerClient {
    /// Authenticates a binding, method, assignment, package, and resource context.
    ///
    /// # Errors
    ///
    /// Returns an error when any supplied record differs from the checked
    /// binding or package contract, exceeds the caller grant, or relies on an
    /// ambient executable path.
    pub fn bind(
        bindings: &CheckedBindingPlan,
        packages: &VerifiedPackageContractSet,
        interface: InterfaceDocument,
        assignment: ProviderAssignment,
        selector: BoundHandlerSelector,
        target: BoundHandlerTarget,
        runtime_root: impl Into<PathBuf>,
    ) -> Result<Self> {
        ensure!(
            bindings.is_executable(),
            "bound-handler binding plan is not executable"
        );
        let binding = selected_binding(bindings, &selector.binding)?.clone();
        let package_digest = binding
            .provider_package
            .context("bound-handler binding has no authenticated package")?;
        let package = packages
            .iter()
            .find(|candidate| candidate.package_digest() == package_digest)
            .context("bound-handler package is absent from the authenticated package set")?;
        let method = MethodReference {
            interface: binding.interface.clone(),
            method: selector.method,
        };

        validate_fixed_point_resources(bindings, &target)?;
        validate_template(&binding, &interface, &assignment, &method, &target)?;
        let transport = BoundCommandHandler::new(package, assignment.clone(), interface.clone())
            .context("authenticating bound-handler executable")?;
        let identity = BoundHandlerIdentity {
            binding_plan: bindings.id(),
            binding,
            interface,
            assignment,
            method,
            target,
        };
        let runtime_root = runtime_root.into();
        Ok(Self {
            identity,
            runtime_root,
            transport: Box::new(transport),
            budget_millis: DEFAULT_CALL_BUDGET_MILLIS,
        })
    }

    /// Returns the complete immutable identity of this route.
    #[must_use]
    pub const fn identity(&self) -> &BoundHandlerIdentity {
        &self.identity
    }

    /// Starts one independently journaled call.
    ///
    /// # Errors
    ///
    /// Returns an error when the private call directory, artifact root, blob
    /// store, or draft journal cannot be created durably.
    pub fn begin_call(&self) -> Result<BoundHandlerCall<'_>> {
        let transaction = new_transaction_id()?;
        let journal = BoundCallJournal::draft(transaction.clone(), self.identity.clone());
        let store = BoundCallStore::create(
            &self.runtime_root,
            journal,
            Path::new(&self.identity.binding.implementation.artifact.store_path),
        )
        .context("creating bound-handler call state")?;
        Ok(BoundHandlerCall {
            client: self,
            transaction,
            store: Some(store),
        })
    }

    /// Reopens and settles one prepared or interrupted call.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal belongs to another checked route, fresh
    /// admission differs from its durable request, reconciliation is absent or
    /// inconclusive, or handler execution fails.
    pub fn recover(
        &self,
        transaction: &TransactionId,
        control: &dyn RuntimeControl,
    ) -> Result<BoundHandlerResult> {
        let store = BoundCallStore::open(&self.runtime_root, transaction)
            .context("opening retained bound-handler call")?;
        ensure!(
            store.journal().authority == self.identity,
            "retained bound-handler call belongs to another checked route"
        );
        if store.journal().phase == BoundCallPhase::Draft {
            store.cleanup().context("removing abandoned draft call")?;
            bail!("retained bound-handler call ended before durable preparation");
        }
        if store.journal().phase == BoundCallPhase::Terminal {
            let result = store
                .journal()
                .result
                .clone()
                .context("terminal bound-handler journal has no result")?;
            return Ok(BoundHandlerResult {
                result,
                store: Some(store),
            });
        }

        let request = store
            .journal()
            .request
            .clone()
            .context("prepared bound-handler journal has no request")?;
        let refreshed = self.prepare_request(request.inputs.clone())?;
        ensure!(
            refreshed == request,
            "fresh bound-handler admission differs from the durable request"
        );

        match store.journal().phase {
            BoundCallPhase::Prepared => self.execute_effect(store, control),
            BoundCallPhase::Executing => self.reconcile_effect(store, control),
            BoundCallPhase::Draft | BoundCallPhase::Terminal => {
                bail!("bound-handler journal phase changed during recovery")
            }
        }
    }

    fn prepare_request(&self, inputs: AbilityValue) -> Result<DurableRequest> {
        let mut resources = self.identity.target.resources.clone();
        let admitted = self
            .transport
            .admit(
                &self.identity.method,
                &self.identity.target.reference,
                &self.identity.target.interface,
                &resource_spec(&self.identity.target.resource),
                resources.clone(),
                required_purposes(&self.identity.target.recovery),
                self.budget_millis,
            )
            .context("admitting bound-handler target")?;
        resources.push(admitted);
        resources.sort_by(|left, right| left.reference.resource.cmp(&right.reference.resource));

        self.transport
            .durable_request(
                self.identity.method.clone(),
                self.identity.target.reference.clone(),
                inputs,
                resources,
                self.identity.target.recovery.clone(),
            )
            .context("constructing durable bound-handler request")
    }

    fn execute_effect(
        &self,
        mut store: BoundCallStore,
        control: &dyn RuntimeControl,
    ) -> Result<BoundHandlerResult> {
        let request = store
            .journal()
            .request
            .clone()
            .context("prepared bound-handler call has no durable request")?;
        let mut executing = store.journal().clone();
        executing.phase = BoundCallPhase::Executing;
        store
            .replace(executing)
            .context("journaling bound-handler intent")?;

        let result = self
            .transport
            .invoke(&request, InvocationPurpose::Effect, control, store.blobs())
            .context("executing bound handler")?;
        match result.disposition {
            InvocationDisposition::Completed | InvocationDisposition::RejectedBeforeEffect => {
                terminal_result(store, result)
            }
            InvocationDisposition::Indeterminate => {
                bail!("bound-handler effect is indeterminate and requires recovery")
            }
            _ => bail!("bound-handler effect returned an illegal disposition"),
        }
    }

    fn reconcile_effect(
        &self,
        mut store: BoundCallStore,
        control: &dyn RuntimeControl,
    ) -> Result<BoundHandlerResult> {
        let request = store
            .journal()
            .request
            .clone()
            .context("executing bound-handler call has no durable request")?;
        ensure!(
            request.recovery.reconcile.is_some(),
            "interrupted bound-handler call declares no reconcile method"
        );
        let result = self
            .transport
            .invoke(
                &request,
                InvocationPurpose::Reconcile,
                control,
                store.blobs(),
            )
            .context("reconciling bound handler")?;
        match result.disposition {
            InvocationDisposition::Completed | InvocationDisposition::RejectedBeforeEffect => {
                terminal_result(store, result)
            }
            InvocationDisposition::SafeToRetry => {
                let mut prepared = store.journal().clone();
                prepared.phase = BoundCallPhase::Prepared;
                store
                    .replace(prepared)
                    .context("journaling safe bound-handler retry")?;
                self.execute_effect(store, control)
            }
            InvocationDisposition::StillIndeterminate
            | InvocationDisposition::InterventionRequired => {
                bail!("bound-handler recovery remains indeterminate")
            }
            _ => bail!("bound-handler reconciliation returned an illegal disposition"),
        }
    }
}

impl BoundHandlerCall<'_> {
    /// Returns the durable identity used to recover this call after interruption.
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// Publishes bytes for use through a typed transaction-blob reference.
    ///
    /// # Errors
    ///
    /// Returns an error when the call is no longer a draft or publication
    /// violates the blob size or durability contract.
    pub fn publish_blob(&self, slot: &LocalKey, bytes: &[u8]) -> Result<TransactionBlobReference> {
        let store = self
            .store
            .as_ref()
            .context("bound-handler call is closed")?;
        ensure!(
            store.journal().phase == BoundCallPhase::Draft,
            "bound-handler inputs are immutable after preparation"
        );
        store
            .blobs()
            .publish_bytes(slot, bytes)
            .context("publishing bound-handler input blob")
    }

    /// Admits and executes this call through the bound route.
    ///
    /// # Errors
    ///
    /// Returns [`BoundHandlerInvocationError`] when input validation, admission,
    /// durable publication, execution, or settlement fails. Its state reports
    /// whether the call was cleaned, still needs cleanup, or remains available
    /// to [`BoundHandlerClient::recover`].
    pub fn invoke(
        mut self,
        inputs: AbilityValue,
        control: &dyn RuntimeControl,
    ) -> BoundHandlerInvocationResult {
        let transaction = self.transaction.clone();
        let mut store = match self.store.take() {
            Some(store) => store,
            None => {
                return Err(BoundHandlerInvocationError::new(
                    transaction,
                    BoundHandlerFailureState::CleanedBeforePreparation,
                    anyhow::anyhow!("bound-handler call is closed"),
                ));
            }
        };
        let request = match self.client.prepare_request(inputs) {
            Ok(request) => request,
            Err(error) => {
                return Err(clean_before_preparation(store, transaction, error));
            }
        };
        let prepared = BoundCallJournal::prepared(
            store.journal().transaction.clone(),
            self.client.identity.clone(),
            request,
        );
        if let Err(error) = store.replace(prepared) {
            return Err(clean_before_preparation(
                store,
                transaction,
                anyhow::Error::from(error).context("preparing bound-handler call"),
            ));
        }
        self.client
            .execute_effect(store, control)
            .map_err(|source| {
                BoundHandlerInvocationError::new(
                    transaction,
                    BoundHandlerFailureState::RetainedForRecovery,
                    source,
                )
            })
    }
}

impl Drop for BoundHandlerCall<'_> {
    fn drop(&mut self) {
        if let Some(store) = self.store.take() {
            let _ = store.cleanup();
        }
    }
}

impl BoundHandlerResult {
    /// Returns the exact provider result.
    #[must_use]
    pub const fn invocation(&self) -> &InvocationResult {
        &self.result
    }

    /// Reads and revalidates one output blob before terminal cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference names another call or its retained
    /// bytes differ from the authenticated identity.
    pub fn read_blob(&self, reference: &TransactionBlobReference) -> Result<Vec<u8>> {
        self.store
            .as_ref()
            .context("bound-handler result is closed")?
            .blobs()
            .read_reference(reference)
            .context("reading bound-handler output blob")
    }

    /// Removes the call directory, journal, blobs, and artifact root.
    ///
    /// # Errors
    ///
    /// Returns an error when durable terminal cleanup fails.
    pub fn finish(mut self) -> Result<()> {
        self.store
            .take()
            .context("bound-handler result is closed")?
            .cleanup()
            .context("cleaning terminal bound-handler call")
    }
}

impl Drop for BoundHandlerResult {
    fn drop(&mut self) {
        if let Some(store) = self.store.take() {
            let _ = store.cleanup();
        }
    }
}

fn selected_binding<'a>(
    bindings: &'a CheckedBindingPlan,
    binding: &BindingId,
) -> Result<&'a Binding> {
    bindings
        .binding(binding)
        .context("bound-handler selector names no checked binding")
}

fn validate_fixed_point_resources(
    bindings: &CheckedBindingPlan,
    target: &BoundHandlerTarget,
) -> Result<()> {
    validate_fixed_point_resource(bindings, &target.resource)?;
    for context in &target.resources {
        let bound = aos_provider_protocol::validate_resource_context(context)?;
        validate_fixed_point_resource(bindings, &bound.resource_spec)?;
    }
    Ok(())
}

fn validate_fixed_point_resource(
    bindings: &CheckedBindingPlan,
    resource: &ResourceSpec,
) -> Result<()> {
    let expected = bindings
        .document()
        .resources
        .binary_search_by(|candidate| candidate.resource.cmp(&resource.resource))
        .ok()
        .map(|index| &bindings.document().resources[index])
        .context("bound-handler resource is absent from the checked fixed point")?;
    ensure!(
        expected.kind == resource.kind
            && expected.lifetime == resource.lifetime
            && expected.value == resource.value
            && expected.realization == resource.realization
            && expected.revision == resource.revision,
        "bound-handler resource differs from the checked fixed point"
    );
    Ok(())
}

fn validate_template(
    binding: &Binding,
    interface: &InterfaceDocument,
    assignment: &ProviderAssignment,
    method: &MethodReference,
    target: &BoundHandlerTarget,
) -> Result<()> {
    ensure!(
        interface.interface_key()? == binding.interface,
        "bound-handler interface differs from the checked binding"
    );
    ensure!(
        assignment.provider == binding.provider
            && assignment.interface == binding.interface
            && assignment.implementation == binding.implementation,
        "bound-handler assignment differs from the checked binding"
    );
    let descriptor = interface
        .interface
        .methods
        .get(&method.method)
        .context("bound-handler method is absent from the selected interface")?;
    ensure!(
        binding
            .caller_grant
            .methods
            .binary_search(&method.method)
            .is_ok(),
        "bound-handler method is absent from the caller grant"
    );
    ensure!(
        target.interface.interface_key()? == target.reference.interface
            && descriptor.target_resource == target.reference.interface.name
            && target.reference.resource == target.resource.resource
            && target.reference.interface.name == target.resource.kind
            && target.reference.lifetime == target.resource.lifetime
            && target.reference.lifetime <= binding.lifetime,
        "bound-handler target differs from its typed resource context"
    );
    ensure!(
        target
            .reference
            .operations
            .binary_search(&method.method)
            .is_ok(),
        "bound-handler target does not authorize the selected method"
    );
    ensure!(
        target
            .reference
            .operations
            .iter()
            .all(|operation| descriptor
                .permitted_operations
                .binary_search(operation)
                .is_ok()),
        "bound-handler target projection exceeds the selected method"
    );
    let permission = binding
        .caller_grant
        .resources
        .iter()
        .find(|permission| permission.resource == target.reference.resource)
        .context("bound-handler target is outside the caller resource grant")?;
    ensure!(
        permission
            .access
            .permits(descriptor.semantics.required_target_access)
            && permission.operations.binary_search(&method.method).is_ok(),
        "bound-handler method exceeds the caller resource grant"
    );
    for recovery in [
        target.recovery.reconcile.as_ref(),
        target.recovery.cancel.as_ref(),
        target.recovery.compensate.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let recovery_descriptor = interface
            .interface
            .methods
            .get(&recovery.method)
            .context("bound-handler recovery method is absent from the selected interface")?;
        ensure!(
            recovery.interface == binding.interface
                && recovery_descriptor.target_resource == target.reference.interface.name
                && permission
                    .access
                    .permits(recovery_descriptor.semantics.required_target_access)
                && target
                    .reference
                    .operations
                    .binary_search(&recovery.method)
                    .is_ok()
                && binding
                    .caller_grant
                    .methods
                    .binary_search(&recovery.method)
                    .is_ok()
                && permission
                    .operations
                    .binary_search(&recovery.method)
                    .is_ok(),
            "bound-handler recovery method exceeds the checked binding"
        );
    }
    if descriptor.outcome.indeterminate == aos_ability_model::IndeterminateSemantics::Reconcile {
        ensure!(
            target.recovery.reconcile.is_some(),
            "bound-handler method requires a reconcile method"
        );
    }
    aos_provider_protocol::validate_resource_contexts(&target.resources)?;
    ensure!(
        target
            .resources
            .iter()
            .all(|context| context.reference.resource != target.reference.resource),
        "bound-handler supporting context repeats the target resource"
    );
    for context in &target.resources {
        let permission = binding
            .caller_grant
            .resources
            .iter()
            .find(|permission| permission.resource == context.reference.resource)
            .context("bound-handler supporting context is outside the caller resource grant")?;
        ensure!(
            context.reference.lifetime <= binding.lifetime
                && context
                    .reference
                    .operations
                    .iter()
                    .all(|operation| permission.operations.binary_search(operation).is_ok()),
            "bound-handler supporting context exceeds the caller resource grant"
        );
    }
    Ok(())
}

fn resource_spec(spec: &ResourceSpec) -> CommandHandlerResourceSpec {
    CommandHandlerResourceSpec {
        resource: spec.resource.clone(),
        kind: spec.kind.clone(),
        lifetime: spec.lifetime,
        revision: spec.revision,
        value: spec.value.clone(),
        realization: spec.realization.clone(),
    }
}

fn required_purposes(recovery: &RecoveryMethods) -> Vec<InvocationPurpose> {
    let mut purposes = vec![InvocationPurpose::Effect];
    if recovery.reconcile.is_some() {
        purposes.push(InvocationPurpose::Reconcile);
    }
    if recovery.cancel.is_some() {
        purposes.push(InvocationPurpose::Cancel);
    }
    if recovery.compensate.is_some() {
        purposes.push(InvocationPurpose::Compensate);
        if recovery.reconcile.is_some() {
            purposes.push(InvocationPurpose::ReconcileCompensation);
        }
    }
    purposes
}

fn terminal_result(
    mut store: BoundCallStore,
    result: InvocationResult,
) -> Result<BoundHandlerResult> {
    let mut journal = store.journal().clone();
    journal.phase = BoundCallPhase::Terminal;
    journal.result = Some(result.clone());
    store
        .replace(journal)
        .context("journaling terminal bound-handler result")?;
    Ok(BoundHandlerResult {
        result,
        store: Some(store),
    })
}

fn clean_before_preparation(
    store: BoundCallStore,
    transaction: TransactionId,
    source: anyhow::Error,
) -> BoundHandlerInvocationError {
    match store.cleanup() {
        Ok(()) => BoundHandlerInvocationError::new(
            transaction,
            BoundHandlerFailureState::CleanedBeforePreparation,
            source,
        ),
        Err(cleanup) => BoundHandlerInvocationError::new(
            transaction,
            BoundHandlerFailureState::CleanupPending,
            anyhow::Error::from(cleanup).context(format!(
                "cleaning call after pre-preparation failure: {source:#}"
            )),
        ),
    }
}

fn new_transaction_id() -> Result<TransactionId> {
    let random = rand::random::<u128>();
    Ok(TransactionId(LocalKey::new(format!(
        "bound-call-{random:032x}"
    ))?))
}

#[cfg(test)]
#[path = "bound_handler_tests.rs"]
pub(super) mod tests;
