//! Ordinary trusted-adapter boundary for the native A/B rollout backend.

use std::collections::BTreeMap;
use std::io;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_ability_model::builtin::{
    AB_IMAGE_ROLLOUT_INTERFACE_NAME, AB_IMAGE_ROLLOUT_OBSERVATION_SCHEMA,
    AB_IMAGE_ROLLOUT_STATE_OUTPUT, ab_image_rollout_handler, ab_image_rollout_handler_key,
    ab_image_rollout_provider,
};
use aos_ability_model::{
    AbilityValue, ImageRolloutAction, LocalKey, MethodReference, Operation, OperationFamily,
    ProviderAssignment, ProviderImplementationReference, ResourceAccess, ResourceId, RevisionId,
};
use aos_ability_plan::AbRolloutRequest;
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CatalogReservation,
    EffectDisposition, InvocationPurpose, ReconcileDisposition, ReservationContext,
    ResourceAdmissionEvidence, ResourceHandle, ResourceRevisionObservation, RuntimeControl,
    TrustedAdapter, TrustedResourceCatalog,
};

use super::process::run_bounded_command;
use super::{
    AbilityRolloutOutcome, AbilityRolloutPhase, AbilityRolloutState, NativeAbRolloutBackend,
};
use crate::ability_package::VerifiedAbilityPackage;
use crate::config_eval::ability_store::{
    NativeQualifiedResource, NativeResourceInventory, NativeResourceReservation,
};

const DURABLE_REQUEST_SCHEMA: &str = "aos.ability.native-ab-image-rollout-request/v1";
const MOUNT: &str = "/run/current-system/sw/bin/mount";
const BOOTCTL: &str = "/run/current-system/sw/bin/bootctl";
const SYSTEMCTL: &str = "/run/current-system/sw/bin/systemctl";
const ROLLOUT_DRAIN: &str = "/run/current-system/sw/bin/aos-rollout-drain";
const ROLLOUT_HEALTH: &str = "/run/current-system/sw/bin/aos-rollout-health";

/// Supplies disruptive host operations separately from portable rollout state.
pub(crate) trait NativeAbRolloutPlatform {
    /// Runs one physical ESP mutation inside the platform's writable bracket.
    ///
    /// # Errors
    ///
    /// Returns an error when ESP validation, remounting, the effect, or the
    /// read-only restoration fails.
    fn with_writable_boot<T>(
        &mut self,
        control: &dyn RuntimeControl,
        effect: impl FnOnce() -> Result<T, io::Error>,
    ) -> Result<T, io::Error>;
    /// Drains current workloads before boot admission changes.
    ///
    /// # Errors
    ///
    /// Returns an error when no drain mechanism completes successfully.
    fn drain(&mut self, control: &dyn RuntimeControl) -> Result<(), io::Error>;
    /// Runs the current image's rollout health assessment.
    ///
    /// # Errors
    ///
    /// Returns an error when the hook cannot run to a conclusive result.
    fn health(&mut self, control: &dyn RuntimeControl) -> Result<bool, io::Error>;
    /// Selects one exact installed boot entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the ESP cannot be mutated or selection fails.
    fn select(&mut self, entry_id: &str, control: &dyn RuntimeControl) -> Result<(), io::Error>;
    /// Requests the reboot that applies the selected entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the system manager rejects the reboot request.
    fn reboot(&mut self, control: &dyn RuntimeControl) -> Result<(), io::Error>;
    /// Returns restart-stable wall time for lease eligibility.
    fn now_millis(&self) -> u64;
}

/// Uses the current image's drain hook, systemd-boot selection, and reboot path.
pub(crate) struct SystemAbRolloutPlatform;

impl NativeAbRolloutPlatform for SystemAbRolloutPlatform {
    fn with_writable_boot<T>(
        &mut self,
        control: &dyn RuntimeControl,
        effect: impl FnOnce() -> Result<T, io::Error>,
    ) -> Result<T, io::Error> {
        crate::sysroot::with_writable_boot_controlled(
            |boot_root, writable| {
                let mode = if writable { "remount,rw" } else { "remount,ro" };
                let boot_root = boot_root
                    .to_str()
                    .ok_or_else(|| invalid("EFI mount path is not UTF-8"))?;
                run_command(
                    MOUNT,
                    &["-o", mode, boot_root],
                    "remounting the EFI System Partition",
                    control,
                )
                .map_err(anyhow::Error::from)
            },
            || effect().map_err(Into::into),
        )
        .map_err(store_error)
    }

    fn drain(&mut self, control: &dyn RuntimeControl) -> Result<(), io::Error> {
        run_command(ROLLOUT_DRAIN, &[], "draining the current image", control)
    }

    fn health(&mut self, control: &dyn RuntimeControl) -> Result<bool, io::Error> {
        let status = run_bounded_command(&mut Command::new(ROLLOUT_HEALTH), control)?;
        match status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(invalid(format!(
                "assessing rollout health failed with {status}"
            ))),
        }
    }

    fn select(&mut self, entry_id: &str, control: &dyn RuntimeControl) -> Result<(), io::Error> {
        self.with_writable_boot(control, || {
            run_command(
                BOOTCTL,
                &["set-default", entry_id],
                "selecting the exact next boot image",
                control,
            )
        })
    }

    fn reboot(&mut self, control: &dyn RuntimeControl) -> Result<(), io::Error> {
        run_command(
            SYSTEMCTL,
            &["reboot"],
            "requesting the rollout reboot",
            control,
        )
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "retirement eligibility uses restart-stable host time and never enters deterministic evaluation"
    )]
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(u64::MAX, |duration| {
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// Acquires one rollout resource only under the current runtime assignment.
pub(crate) struct NativeAbRolloutCatalog {
    assignment: ProviderAssignment,
    resource: ResourceId,
    revision: RevisionId,
    request: AbRolloutRequest,
    backend: NativeAbRolloutBackend,
    inventory: NativeResourceInventory,
    qualified: NativeQualifiedResource,
}

/// Holds an exclusive runtime reservation for one exact rollout revision.
#[derive(Debug)]
pub(crate) struct NativeAbRolloutHandle {
    resource: ResourceId,
    revision: RevisionId,
    request: AbRolloutRequest,
    reservation: NativeResourceReservation,
}

impl NativeAbRolloutCatalog {
    /// Constructs a catalog for one statically qualified machine rollout.
    ///
    /// # Errors
    ///
    /// Returns an error when the native physical-resource identity is invalid.
    pub(crate) fn new(
        assignment: ProviderAssignment,
        resource: ResourceId,
        revision: RevisionId,
        request: AbRolloutRequest,
        backend: NativeAbRolloutBackend,
        inventory: NativeResourceInventory,
    ) -> Result<Self, io::Error> {
        let qualified = NativeQualifiedResource::host_resource(
            resource.clone(),
            "ab-image-rollout",
            "aos-host-runtime",
            "machine",
        )
        .map_err(store_error)?;
        Ok(Self {
            assignment,
            resource,
            revision,
            request,
            backend,
            inventory,
            qualified,
        })
    }
}

impl TrustedResourceCatalog for NativeAbRolloutCatalog {
    type Handle = NativeAbRolloutHandle;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        if context
            .expected_provider
            .is_some_and(|assignment| assignment != &self.assignment)
            || operation.target.resource != self.resource
            || access.resource != self.resource
        {
            return Err(invalid("rollout assignment or resource is stale"));
        }
        let context = ReservationContext {
            expected_provider: Some(&self.assignment),
            ..context
        };
        self.backend
            .preflight_operation(
                &self.request,
                operation.method.as_str(),
                system_now_millis(),
            )
            .map_err(store_error)?;
        if matches!(operation.method.as_str(), "retain" | "select") {
            self.backend
                .candidate_entry_id(&self.request)
                .map_err(store_error)?;
        }
        let reservation = self
            .inventory
            .reserve(&self.qualified, context, operation, access)
            .map_err(store_error)?;
        let observation = AbilityValue::new(serde_json::Value::Bool(true)).map_err(store_error)?;
        Ok(CatalogReservation::new(
            NativeAbRolloutHandle {
                resource: self.resource.clone(),
                revision: self.revision,
                request: self.request.clone(),
                reservation,
            },
            ResourceAdmissionEvidence::new_with_revision_observation(
                self.resource.clone(),
                Some(self.assignment.incarnation.clone()),
                ResourceRevisionObservation::Present(self.revision),
                observation,
            ),
        ))
    }

    fn release(
        &mut self,
        resource: &ResourceId,
        handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        if resource != &handle.resource || handle.reservation.logical() != resource {
            return Err(invalid("rollout resource release is stale"));
        }
        handle.reservation.release().map_err(store_error)
    }
}

/// Executes the exact built-in rollout contract through the ordinary runtime.
pub(crate) struct NativeAbRolloutAdapter<P> {
    assignment: ProviderAssignment,
    backend: NativeAbRolloutBackend,
    platform: P,
}

impl<P> NativeAbRolloutAdapter<P> {
    /// Constructs the adapter for one exact assignment and physical backend.
    pub(crate) fn new(
        assignment: ProviderAssignment,
        backend: NativeAbRolloutBackend,
        platform: P,
    ) -> Self {
        Self {
            assignment,
            backend,
            platform,
        }
    }
}

/// Authenticates a selected assignment against the sealed built-in rollout contract.
///
/// # Errors
///
/// Returns an error when the package, interface, handler, descriptor, or
/// artifact differs from the built-in terminal provider contract.
pub(crate) fn preflight_native_ab_rollout(
    package: &VerifiedAbilityPackage,
    assignment: &ProviderAssignment,
) -> Result<(), io::Error> {
    let handler_key = ab_image_rollout_handler_key().map_err(store_error)?;
    if assignment.interface.name.as_str() != AB_IMAGE_ROLLOUT_INTERFACE_NAME
        || assignment.implementation.handler.as_ref() != Some(&handler_key)
    {
        return Err(invalid(
            "native rollout assignment selects another contract",
        ));
    }
    let terminal = package
        .resolve_terminal_handler(assignment.implementation.descriptor, &handler_key)
        .ok_or_else(|| invalid("native rollout handler is absent from its package"))?;
    let artifact = terminal.handler().artifact.clone();
    let expected_provider = ab_image_rollout_provider(artifact.clone()).map_err(store_error)?;
    let expected_handler = ab_image_rollout_handler(artifact).map_err(store_error)?;
    if terminal.provider() != &expected_provider
        || terminal.handler() != &expected_handler
        || assignment.interface != expected_provider.interface
        || assignment.implementation.artifact != terminal.handler().artifact
    {
        return Err(invalid(
            "native rollout assignment differs from the sealed contract",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct DurableRolloutRequest {
    schema: String,
    method: String,
    resource: ResourceId,
    revision: RevisionId,
    request: AbRolloutRequest,
}

/// Retains one recovered rollout request and its schema-valid rejection record.
#[derive(Clone, Debug)]
pub(crate) struct NativeAbRolloutRequest {
    durable: DurableRolloutRequest,
    rejection: NativeAbRolloutRecord,
}

/// Carries durable rollout evidence and checked operation outputs.
#[derive(Clone, Debug)]
pub(crate) struct NativeAbRolloutRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for NativeAbRolloutRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for NativeAbRolloutRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

impl<P: NativeAbRolloutPlatform> TrustedAdapter for NativeAbRolloutAdapter<P> {
    type Request = NativeAbRolloutRequest;
    type Completion = NativeAbRolloutRecord;
    type Observation = NativeAbRolloutRecord;
    type Handle = NativeAbRolloutHandle;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        implementation: &ProviderImplementationReference,
        method: &MethodReference,
        _purpose: InvocationPurpose,
    ) -> bool {
        implementation == &self.assignment.implementation
            && method.interface == self.assignment.interface
            && self.assignment.interface.name.as_str() == AB_IMAGE_ROLLOUT_INTERFACE_NAME
            && method_action(method.method.as_str()).is_some()
    }

    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        let action = require_operation(operation)?;
        let expected = method_action(operation.method.as_str())
            .ok_or_else(|| invalid("unsupported rollout method"))?;
        if action != expected || operation.interface != self.assignment.interface {
            return Err(invalid(
                "rollout operation differs from its built-in method",
            ));
        }
        let [resource] = resources else {
            return Err(invalid("rollout operation requires exactly one resource"));
        };
        let request: AbRolloutRequest = serde_json::from_value(inputs.as_json().clone())
            .map_err(|error| invalid(format!("invalid rollout request: {error}")))?;
        if resource.resource() != &operation.target.resource
            || resource.native().resource != operation.target.resource
            || resource.native().request != request
        {
            return Err(invalid("rollout handle differs from the checked operation"));
        }
        ability_value(serde_json::to_value(DurableRolloutRequest {
            schema: DURABLE_REQUEST_SCHEMA.to_string(),
            method: operation.method.as_str().to_string(),
            resource: resource.native().resource.clone(),
            revision: resource.native().revision,
            request,
        })?)
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        let request: DurableRolloutRequest = serde_json::from_value(durable.as_json().clone())
            .map_err(|error| invalid(format!("invalid durable rollout request: {error}")))?;
        let [resource] = resources else {
            return Err(invalid("rollout recovery requires exactly one resource"));
        };
        if request.schema != DURABLE_REQUEST_SCHEMA
            || request.resource != resource.native().resource
            || request.revision != resource.native().revision
            || request.request != resource.native().request
            || method_action(&request.method).is_none()
        {
            return Err(invalid(
                "durable rollout request differs from fresh authority",
            ));
        }
        let rejection = rejection_record(&request)?;
        Ok(NativeAbRolloutRequest {
            durable: request,
            rejection,
        })
    }

    fn execute(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        if control.is_cancelled() {
            return EffectDisposition::RejectedBeforeEffect(request.rejection.clone());
        }
        match self.execute_request(&request.durable, control) {
            Ok(Some(record)) => EffectDisposition::Completed(record),
            Ok(None) | Err(_) => EffectDisposition::Indeterminate(request.rejection.clone()),
        }
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        match self.reconcile_request(&request.durable, control) {
            Ok(Some(record)) => ReconcileDisposition::Completed(record),
            Ok(None) => ReconcileDisposition::StillIndeterminate(request.rejection.clone()),
            Err(_) => ReconcileDisposition::InterventionRequired(request.rejection.clone()),
        }
    }

    fn cancel(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        match self.reconcile(request, control) {
            ReconcileDisposition::Completed(record) => CancellationDisposition::Completed(record),
            ReconcileDisposition::RejectedBeforeEffect(record)
            | ReconcileDisposition::SafeToRetry(record) => {
                CancellationDisposition::RejectedBeforeEffect(record)
            }
            ReconcileDisposition::StillIndeterminate(record)
            | ReconcileDisposition::InterventionRequired(record) => {
                CancellationDisposition::Indeterminate(record)
            }
        }
    }
}

impl<P: NativeAbRolloutPlatform> NativeAbRolloutAdapter<P> {
    fn execute_request(
        &mut self,
        durable: &DurableRolloutRequest,
        control: &dyn RuntimeControl,
    ) -> Result<Option<NativeAbRolloutRecord>, io::Error> {
        let request = &durable.request;
        let state = match durable.method.as_str() {
            "retain" => self
                .platform
                .with_writable_boot(control, || {
                    self.backend.retain(request).map_err(store_error)
                })
                .map_err(Into::into),
            "prepare" => self.backend.prepare(request),
            "drain" => self
                .backend
                .drain(request, || self.platform.drain(control).map_err(Into::into)),
            "select" => {
                let entry = self
                    .backend
                    .candidate_entry_id(request)
                    .map_err(store_error)?;
                let state = self
                    .backend
                    .select(request, &entry, |entry| {
                        self.platform.select(entry, control).map_err(Into::into)
                    })
                    .map_err(store_error)?;
                self.platform.reboot(control)?;
                return Ok(completion_if_ready(durable, &state)?);
            }
            "observe-boot" => self.backend.reconcile(request),
            "observe-health" => self.execute_health(request, control).map_err(Into::into),
            "withdraw" => return self.execute_withdrawal(durable, control),
            "hold" => self.backend.hold(request),
            "retire" => {
                let now_millis = self.platform.now_millis();
                self.platform
                    .with_writable_boot(control, || {
                        self.backend
                            .retire(request, now_millis)
                            .map_err(store_error)
                    })
                    .map_err(Into::into)
            }
            _ => return Err(invalid("unsupported rollout method")),
        }
        .map_err(store_error)?;
        completion_if_ready(durable, &state)
    }

    fn reconcile_request(
        &mut self,
        durable: &DurableRolloutRequest,
        control: &dyn RuntimeControl,
    ) -> Result<Option<NativeAbRolloutRecord>, io::Error> {
        if control.is_cancelled()
            || control.attempt_remaining_millis() == 0
            || control.recovery_remaining_millis() == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "rollout observation has no live runtime budget",
            ));
        }
        if durable.method == "observe-health" {
            let state = self.execute_health(&durable.request, control)?;
            return completion_if_ready(durable, &state);
        }
        if durable.method == "withdraw" {
            return self.execute_withdrawal(durable, control);
        }
        let state = self
            .backend
            .observe_operation(&durable.request, &durable.method)
            .map_err(store_error)?;
        completion_if_ready(durable, &state)
    }

    fn execute_health(
        &mut self,
        request: &AbRolloutRequest,
        control: &dyn RuntimeControl,
    ) -> Result<AbilityRolloutState, io::Error> {
        match self
            .backend
            .health_assessment_if_recorded(request)
            .map_err(store_error)?
        {
            Some(state) => Ok(state),
            None => {
                let healthy = self.platform.health(control)?;
                self.backend
                    .record_health(request, healthy)
                    .map_err(store_error)
            }
        }
    }

    fn execute_withdrawal(
        &mut self,
        durable: &DurableRolloutRequest,
        control: &dyn RuntimeControl,
    ) -> Result<Option<NativeAbRolloutRecord>, io::Error> {
        let state = self
            .backend
            .withdraw(&durable.request)
            .map_err(store_error)?;
        if state.phase == AbilityRolloutPhase::CandidateBooted {
            self.platform.reboot(control)?;
            return Ok(None);
        }
        completion_if_ready(durable, &state)
    }
}

fn completion_if_ready(
    durable: &DurableRolloutRequest,
    state: &AbilityRolloutState,
) -> Result<Option<NativeAbRolloutRecord>, io::Error> {
    let ready = match durable.method.as_str() {
        "select" | "observe-boot" => matches!(
            state.phase,
            AbilityRolloutPhase::CandidateBooted
                | AbilityRolloutPhase::HealthyRetained
                | AbilityRolloutPhase::FallbackRetained
        ),
        "observe-health" => state.outcome.is_some(),
        "hold" => matches!(
            state.phase,
            AbilityRolloutPhase::HealthyRetained | AbilityRolloutPhase::FallbackRetained
        ),
        "withdraw" => state.phase == AbilityRolloutPhase::FallbackRetained,
        "retire" => state.phase == AbilityRolloutPhase::Retired,
        _ => true,
    };
    ready.then(|| completion_record(durable, state)).transpose()
}

fn require_operation(operation: &Operation) -> Result<ImageRolloutAction, io::Error> {
    let OperationFamily::ImageRollout { action } = operation.family else {
        return Err(invalid("operation is not an image rollout"));
    };
    Ok(action)
}

fn method_action(method: &str) -> Option<ImageRolloutAction> {
    Some(match method {
        "retain" => ImageRolloutAction::Retain,
        "prepare" => ImageRolloutAction::Prepare,
        "drain" => ImageRolloutAction::Drain,
        "select" => ImageRolloutAction::Select,
        "observe-boot" => ImageRolloutAction::ObserveBoot,
        "observe-health" => ImageRolloutAction::ObserveHealth,
        "withdraw" => ImageRolloutAction::Withdraw,
        "hold" => ImageRolloutAction::Hold,
        "retire" => ImageRolloutAction::Retire,
        _ => return None,
    })
}

fn completion_record(
    durable: &DurableRolloutRequest,
    state: &AbilityRolloutState,
) -> Result<NativeAbRolloutRecord, io::Error> {
    let (active_image, healthy) = match state.outcome {
        Some(AbilityRolloutOutcome::CandidateHealthy) => ("candidate", Some(true)),
        Some(AbilityRolloutOutcome::CandidateUnhealthy) => ("candidate", Some(false)),
        Some(AbilityRolloutOutcome::PredecessorFallback) => ("predecessor", Some(false)),
        None if matches!(
            state.phase,
            AbilityRolloutPhase::Retained
                | AbilityRolloutPhase::Prepared
                | AbilityRolloutPhase::Drained
        ) =>
        {
            ("predecessor", None)
        }
        None if matches!(
            state.phase,
            AbilityRolloutPhase::Selected | AbilityRolloutPhase::CandidateBooted
        ) =>
        {
            ("candidate", None)
        }
        None => {
            return Err(invalid(
                "terminal rollout state has no authenticated outcome",
            ));
        }
    };
    let lease_expires_at_millis = if state.phase == AbilityRolloutPhase::Retired {
        None
    } else {
        Some(state.request.retention_expires_at_millis)
    };
    let observation = ability_value(serde_json::json!({
        "active-image": active_image,
        "candidate-prepared": !matches!(state.phase, AbilityRolloutPhase::Retained),
        "drained": !matches!(state.phase, AbilityRolloutPhase::Retained | AbilityRolloutPhase::Prepared),
        "healthy": healthy,
        "lease-expires-at-millis": lease_expires_at_millis,
        "phase": phase_name(state.phase),
        "schema": AB_IMAGE_ROLLOUT_OBSERVATION_SCHEMA,
    }))?;
    let mut outputs = BTreeMap::from([(
        LocalKey::new(AB_IMAGE_ROLLOUT_STATE_OUTPUT).map_err(store_error)?,
        observation.clone(),
    )]);
    if durable.method == "observe-health" {
        if let Some(healthy) = healthy {
            outputs.insert(
                LocalKey::new("healthy").map_err(store_error)?,
                ability_value(serde_json::Value::Bool(healthy))?,
            );
        }
    }
    Ok(NativeAbRolloutRecord {
        durable: observation,
        outputs,
    })
}

fn rejection_record(durable: &DurableRolloutRequest) -> Result<NativeAbRolloutRecord, io::Error> {
    Ok(NativeAbRolloutRecord {
        durable: ability_value(serde_json::to_value(durable)?)?,
        outputs: BTreeMap::new(),
    })
}

fn phase_name(phase: AbilityRolloutPhase) -> &'static str {
    match phase {
        AbilityRolloutPhase::Retained => "retained",
        AbilityRolloutPhase::Prepared => "prepared",
        AbilityRolloutPhase::Drained => "drained",
        AbilityRolloutPhase::Selected => "selected",
        AbilityRolloutPhase::CandidateBooted => "booted",
        AbilityRolloutPhase::HealthyRetained => "healthy-retained",
        AbilityRolloutPhase::FallbackRetained => "fallback-retained",
        AbilityRolloutPhase::Retiring => "retiring",
        AbilityRolloutPhase::Retired => "retired",
    }
}

fn ability_value(value: serde_json::Value) -> Result<AbilityValue, io::Error> {
    AbilityValue::new(value).map_err(store_error)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn store_error(error: impl std::fmt::Display) -> io::Error {
    invalid(error.to_string())
}

fn run_command(
    command: &str,
    arguments: &[&str],
    action: &str,
    control: &dyn RuntimeControl,
) -> Result<(), io::Error> {
    let status = run_bounded_command(Command::new(command).args(arguments), control)?;
    if status.success() {
        Ok(())
    } else {
        Err(invalid(format!("{action} failed with {status}")))
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "rollout admission uses restart-stable host time and never enters deterministic evaluation"
)]
fn system_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{EnvironmentId, ExecutionStage, InstanceId};
    use aos_contract::Sha256Digest;

    use super::*;

    fn resource() -> ResourceId {
        ResourceId {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("test").unwrap(),
                    key: LocalKey::new("host").unwrap(),
                    stage: ExecutionStage::Host,
                },
                key: LocalKey::new("rollout-provider").unwrap(),
            },
            key: LocalKey::new("machine").unwrap(),
        }
    }

    fn image(seed: char) -> aos_ability_plan::RolloutImageIdentity {
        aos_ability_plan::RolloutImageIdentity {
            toplevel: format!("/nix/store/{}-system", seed.to_string().repeat(32)),
            uki: format!("EFI/Linux/aos-{seed}+3.efi"),
            executor: format!("/nix/store/{}-executor", seed.to_string().repeat(32)),
            state_format: "7".into(),
        }
    }

    fn rollout_request() -> AbRolloutRequest {
        AbRolloutRequest {
            strategy: "single-host-ab-v1".into(),
            concurrency: 1,
            predecessor: image('a'),
            candidate: image('b'),
            retention_expires_at_millis: 2_000,
        }
    }

    fn durable(method: &str) -> DurableRolloutRequest {
        DurableRolloutRequest {
            schema: DURABLE_REQUEST_SCHEMA.into(),
            method: method.into(),
            resource: resource(),
            revision: RevisionId(Sha256Digest::of_bytes(b"rollout-revision")),
            request: rollout_request(),
        }
    }

    fn state(phase: AbilityRolloutPhase) -> AbilityRolloutState {
        let outcome = match phase {
            AbilityRolloutPhase::HealthyRetained => Some(AbilityRolloutOutcome::CandidateHealthy),
            AbilityRolloutPhase::FallbackRetained => {
                Some(AbilityRolloutOutcome::PredecessorFallback)
            }
            _ => None,
        };
        AbilityRolloutState {
            schema: "aos.ability.native-ab-image-rollout-state/v1".into(),
            request: rollout_request(),
            predecessor_generation: 1,
            candidate_generation: 2,
            phase,
            outcome,
        }
    }

    fn retired_state(outcome: AbilityRolloutOutcome) -> AbilityRolloutState {
        AbilityRolloutState {
            outcome: Some(outcome),
            ..state(AbilityRolloutPhase::Retired)
        }
    }

    #[test]
    fn adapter_waits_for_authenticated_boot_and_terminal_health() {
        assert!(
            completion_if_ready(&durable("select"), &state(AbilityRolloutPhase::Selected))
                .unwrap()
                .is_none()
        );
        assert!(
            completion_if_ready(
                &durable("observe-boot"),
                &state(AbilityRolloutPhase::Selected)
            )
            .unwrap()
            .is_none()
        );
        assert!(
            completion_if_ready(
                &durable("select"),
                &state(AbilityRolloutPhase::CandidateBooted)
            )
            .unwrap()
            .is_some()
        );
        assert!(
            completion_if_ready(
                &durable("observe-health"),
                &state(AbilityRolloutPhase::CandidateBooted)
            )
            .unwrap()
            .is_none()
        );

        let completed = completion_if_ready(
            &durable("observe-health"),
            &state(AbilityRolloutPhase::HealthyRetained),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            completed.outputs[&LocalKey::new("healthy").unwrap()].as_json(),
            &serde_json::Value::Bool(true)
        );
    }

    #[test]
    fn retirement_outputs_preserve_exact_terminal_branch_and_clear_the_lease() {
        for (outcome, active_image, healthy) in [
            (AbilityRolloutOutcome::CandidateHealthy, "candidate", true),
            (
                AbilityRolloutOutcome::PredecessorFallback,
                "predecessor",
                false,
            ),
        ] {
            let completed = completion_record(&durable("retire"), &retired_state(outcome))
                .expect("retirement completion is representable");
            assert_eq!(completed.outputs.len(), 1);
            assert_eq!(
                completed.outputs[&LocalKey::new(AB_IMAGE_ROLLOUT_STATE_OUTPUT).unwrap()].as_json(),
                &serde_json::json!({
                    "active-image": active_image,
                    "candidate-prepared": true,
                    "drained": true,
                    "healthy": healthy,
                    "lease-expires-at-millis": null,
                    "phase": "retired",
                    "schema": AB_IMAGE_ROLLOUT_OBSERVATION_SCHEMA,
                })
            );
        }
    }
}
