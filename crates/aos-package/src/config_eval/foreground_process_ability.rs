//! Application-container foreground process supervision.
//!
//! The adapter owns one exact executable and argument vector inside the
//! application container. It records intent before spawning, tags the child
//! with a resource/revision ownership token, and records the Linux process
//! identity after the spawn. Recovery may adopt one matching process in the
//! same user, namespace, and cgroup confinement; zero matches are safe to
//! retry, while multiple or foreign matches require intervention.
//!
//! ```json
//! {"schema":"aos.ability.foreground-process-request/v1","action":"start","resource":{"provider":"example","key":"service"},"revision":"sha256:<digest>","artifact":{"content":"sha256:<digest>","store_path":"/nix/store/<artifact>","nar_hash":"sha256:<digest>","closure":"sha256:<digest>"},"entry_point":"bin/nginx","arguments":["-g","daemon off;"]}
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::process::CommandExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aos_ability_model::builtin::{
    FOREGROUND_PROCESS_OBSERVATION_SCHEMA, foreground_process_handler_key,
    foreground_process_interface_key, foreground_process_provider,
};
use aos_ability_model::{
    AbilityValue, ArtifactReference, LocalKey, MethodReference, Operation, ProviderAssignment,
    ProviderImplementationReference, ResourceAccess, ResourceId, RevisionId,
};
use aos_ability_plan::{RuntimeResourceHealth, RuntimeResourceState};
use aos_ability_runtime::adapter::{
    AdapterCompletion, AdapterRecord, CancellationDisposition, CatalogReservation,
    EffectDisposition, InvocationPurpose, ReconcileDisposition, ReservationContext,
    ResourceAdmissionEvidence, ResourceHandle, ResourceRevisionObservation, RuntimeControl,
    TrustedAdapter, TrustedResourceCatalog,
};
use aos_contract::Sha256Digest;
use rustix::fs::FlockOperation;
use serde::{Deserialize, Serialize};

use crate::ability_package::VerifiedAbilityPackageSet;
use crate::config_eval::ability_store::NativeResourceInventory;
use crate::config_eval::ability_store::inventory::{
    NativeQualifiedResource, NativeResourceReservation,
};

const REQUEST_SCHEMA: &str = "aos.ability.foreground-process-request/v1";
const STATE_SCHEMA: &str = "aos.ability.foreground-process-state/v1";
const OWNERSHIP_ENVIRONMENT: &str = "AOS_FOREGROUND_PROCESS_OWNERSHIP";
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Authenticates a foreground provider and executable without opening runtime state.
///
/// # Errors
///
/// Returns an error when the provider differs from the built-in contract, the
/// executable artifact is absent from the verified package union, or the
/// command escapes or exceeds its authenticated artifact.
pub(crate) fn preflight_native_foreground(
    packages: &VerifiedAbilityPackageSet,
    assignment: &ProviderAssignment,
    spec: &ForegroundProcessResourceSpec,
) -> Result<(), io::Error> {
    authenticate_assignment(assignment)?;
    packages
        .authenticate_artifact(&spec.artifact)
        .map_err(|error| invalid(format!("authenticating foreground artifact: {error}")))?;
    QualifiedCommand::new(spec).map(|_| ())
}

/// Binds one logical application-container resource to an exact foreground command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForegroundProcessResourceSpec {
    /// Names the provider-owned logical resource.
    pub resource: ResourceId,
    /// Pins the semantic revision represented by the process.
    pub revision: RevisionId,
    /// Pins the authenticated artifact containing the executable.
    pub artifact: ArtifactReference,
    /// Names a relative executable path inside [`Self::artifact`].
    pub entry_point: String,
    /// Supplies the exact argument vector following argv zero.
    pub arguments: Vec<String>,
}

/// Reports the independently observed state of one owned foreground process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForegroundProcessObservation {
    /// Is true only while the exact owned process is live in this confinement.
    pub running: bool,
    /// Identifies the boot, PID, and start time when a process is live.
    pub process_identity: Option<String>,
}

/// Supervises exact foreground commands below one private durable state root.
pub struct ForegroundProcessSupervisor {
    state_root: PathBuf,
    children: BTreeMap<u32, Child>,
}

impl ForegroundProcessSupervisor {
    /// Constructs a supervisor using a private application-container state root.
    ///
    /// # Errors
    ///
    /// Returns an error if the root is not absolute, is a symlink, or cannot be
    /// created with owner-only permissions.
    pub fn new(state_root: impl Into<PathBuf>) -> Result<Self, io::Error> {
        let state_root = state_root.into();
        if !state_root.is_absolute() {
            return Err(invalid("foreground state root must be absolute"));
        }
        ensure_private_directory(&state_root)?;
        ensure_private_directory(&state_root.join("locks"))?;
        ensure_private_directory(&state_root.join("processes"))?;

        Ok(Self {
            state_root,
            children: BTreeMap::new(),
        })
    }

    /// Starts or adopts the one process owned by `spec`.
    ///
    /// Intent is synced before spawn. A recovery after a crash adopts exactly
    /// one matching process and rejects ambiguous ownership.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid executable, foreign or ambiguous live
    /// process, confinement mismatch, state corruption, spawn failure, or
    /// exhausted runtime budget.
    pub fn start(
        &mut self,
        spec: &ForegroundProcessResourceSpec,
        control: &dyn RuntimeControl,
    ) -> Result<ForegroundProcessObservation, io::Error> {
        let command = QualifiedCommand::new(spec)?;
        let confinement = Confinement::current()?;
        let token = ownership_token(spec, &confinement)?;
        let state_path = self.state_path(&spec.resource)?;
        let mut state = self.load_or_create_intent(spec, &command, &confinement, &token)?;

        match locate_owned_process(&command, &confinement, &token, state.identity.as_ref())? {
            LocatedProcess::One(identity) => {
                state.identity = Some(identity.clone());
                write_state(&state_path, &state)?;
                return Ok(observation(Some(identity)));
            }
            LocatedProcess::Many => {
                return Err(invalid(
                    "multiple foreground processes claim the same logical ownership token",
                ));
            }
            LocatedProcess::None => {}
        }

        require_budget(control)?;
        let mut child = Command::new(&command.executable)
            .args(&command.arguments)
            .env_clear()
            .env(OWNERSHIP_ENVIRONMENT, &token)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();

        let identity = match qualify_spawned_child(&mut child, &command, &confinement, &token) {
            Ok(identity) => identity,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error);
            }
        };
        state.identity = Some(identity.clone());
        if let Err(error) = write_state(&state_path, &state) {
            terminate_child(&mut child);
            return Err(error);
        }
        self.children.insert(pid, child);

        Ok(observation(Some(identity)))
    }

    /// Observes the exact process without treating an unrelated PID as owned.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is corrupt, ownership is ambiguous,
    /// or a claimed process differs from the authenticated command or current
    /// application-container confinement.
    pub fn observe(
        &self,
        spec: &ForegroundProcessResourceSpec,
    ) -> Result<ForegroundProcessObservation, io::Error> {
        let command = QualifiedCommand::new(spec)?;
        let confinement = Confinement::current()?;
        let token = ownership_token(spec, &confinement)?;
        let Some(state) = read_state(&self.state_path(&spec.resource)?)? else {
            return Ok(observation(None));
        };
        state.authenticate(spec, &command, &confinement, &token)?;

        match locate_owned_process(&command, &confinement, &token, state.identity.as_ref())? {
            LocatedProcess::None => Ok(observation(None)),
            LocatedProcess::One(identity) => Ok(observation(Some(identity))),
            LocatedProcess::Many => Err(invalid(
                "multiple foreground processes claim the same logical ownership token",
            )),
        }
    }

    /// Terminates the exact owned process group and durably clears its receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for foreign or ambiguous ownership, signalling failure,
    /// state corruption, or an exhausted runtime budget. The receipt is kept
    /// whenever absence has not been established.
    pub fn stop(
        &mut self,
        spec: &ForegroundProcessResourceSpec,
        control: &dyn RuntimeControl,
    ) -> Result<ForegroundProcessObservation, io::Error> {
        let command = QualifiedCommand::new(spec)?;
        let confinement = Confinement::current()?;
        let token = ownership_token(spec, &confinement)?;
        let state_path = self.state_path(&spec.resource)?;
        let Some(state) = read_state(&state_path)? else {
            return Ok(observation(None));
        };
        state.authenticate(spec, &command, &confinement, &token)?;

        let identity =
            match locate_owned_process(&command, &confinement, &token, state.identity.as_ref())? {
                LocatedProcess::None => {
                    if !matches!(
                        locate_owned_process(&command, &confinement, &token, None)?,
                        LocatedProcess::None
                    ) {
                        return Err(invalid(
                            "an owned foreground process appeared before state removal",
                        ));
                    }
                    remove_state(&state_path)?;
                    return Ok(observation(None));
                }
                LocatedProcess::One(identity) => identity,
                LocatedProcess::Many => {
                    return Err(invalid(
                        "multiple foreground processes claim the same logical ownership token",
                    ));
                }
            };

        let pid = rustix::process::Pid::from_raw(identity.pid as i32)
            .ok_or_else(|| invalid("foreground process PID is zero"))?;
        if identity.pid != identity.process_group {
            return Err(invalid(
                "foreground process identity is not its live process-group leader",
            ));
        }
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
        // Linux uses the live group leader's PID as its PGID and cannot reuse
        // that PID for another group while the leader exists. The pidfd pins
        // the exact leader identity; the post-open read proves it is still the
        // authenticated live leader immediately before the group signal.
        if ProcessIdentity::read(identity.pid, &command, &confinement, &token)? != identity {
            return Err(invalid(
                "foreground process identity changed before termination",
            ));
        }
        let process_group = rustix::process::Pid::from_raw(identity.process_group as i32)
            .ok_or_else(|| invalid("foreground process group is zero"))?;
        rustix::process::kill_process_group(process_group, rustix::process::Signal::TERM)?;
        if !wait_for_group_exit(identity.process_group, control)? {
            rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL)?;
            if !wait_for_group_exit(identity.process_group, control)? {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "foreground process did not exit within the durable deadline",
                ));
            }
        }
        if let Some(mut child) = self.children.remove(&identity.pid) {
            let _ = child.wait();
        }
        drop(pidfd);
        match locate_owned_process(&command, &confinement, &token, None)? {
            LocatedProcess::None => {}
            LocatedProcess::One(_) | LocatedProcess::Many => {
                return Err(invalid(
                    "another owned foreground process group remains after stop",
                ));
            }
        }
        remove_state(&state_path)?;

        Ok(observation(None))
    }

    fn state_path(&self, resource: &ResourceId) -> Result<PathBuf, io::Error> {
        let digest =
            Sha256Digest::of_canonical("aos.ability.foreground-process-state-key/v1", resource)
                .map_err(|error| {
                    invalid(format!("encoding foreground resource identity: {error}"))
                })?;
        Ok(self
            .state_root
            .join("processes")
            .join(format!("{}.json", digest.hex())))
    }

    fn load_or_create_intent(
        &self,
        spec: &ForegroundProcessResourceSpec,
        command: &QualifiedCommand,
        confinement: &Confinement,
        token: &str,
    ) -> Result<ForegroundState, io::Error> {
        let path = self.state_path(&spec.resource)?;
        if let Some(state) = read_state(&path)? {
            state.authenticate(spec, command, confinement, token)?;
            return Ok(state);
        }

        let state = ForegroundState::intent(spec, command, confinement, token);
        write_state(&path, &state)?;
        Ok(state)
    }
}

/// Holds one process-scoped resource reservation for trusted runtime dispatch.
#[derive(Debug)]
pub struct ForegroundProcessHandle {
    spec: ForegroundProcessResourceSpec,
    _lock: File,
    reservation: NativeResourceReservation,
}

/// Resolves foreground logical resources and serializes supervisors per resource.
pub struct ForegroundProcessResourceCatalog {
    assignment: ProviderAssignment,
    inventory: Option<NativeResourceInventory>,
    state_root: PathBuf,
    resources: BTreeMap<ResourceId, ForegroundProcessResourceSpec>,
    qualified: BTreeMap<ResourceId, NativeQualifiedResource>,
}

impl ForegroundProcessResourceCatalog {
    /// Constructs a catalog for one exact foreground assignment and resource set.
    ///
    /// # Errors
    ///
    /// Returns an error for another interface or handler, duplicate resources
    /// or commands, unsafe commands, or an unusable private state root.
    pub fn new(
        packages: &VerifiedAbilityPackageSet,
        assignment: ProviderAssignment,
        state_root: impl Into<PathBuf>,
        resources: impl IntoIterator<Item = ForegroundProcessResourceSpec>,
    ) -> Result<Self, io::Error> {
        authenticate_assignment(&assignment)?;
        let state_root = state_root.into();
        let _ = ForegroundProcessSupervisor::new(&state_root)?;
        let mut by_resource = BTreeMap::new();
        let mut qualified = BTreeMap::new();
        let mut commands = BTreeSet::new();
        for spec in resources {
            preflight_native_foreground(packages, &assignment, &spec)?;
            let command = QualifiedCommand::new(&spec)?;
            let command_key = (command.executable, command.arguments);
            if !commands.insert(command_key) {
                return Err(invalid(
                    "two foreground resources claim the same executable and argument vector",
                ));
            }
            let resource = spec.resource.clone();
            let object = Sha256Digest::of_canonical(
                "aos.ability.foreground-process-command/v1",
                &ForegroundDurableRequest::new(ForegroundAction::Start, &spec),
            )
            .map_err(|error| invalid(format!("describing foreground command: {error}")))?;
            qualified.insert(
                resource.clone(),
                NativeQualifiedResource::foreground_process(resource.clone(), &object.to_string())
                    .map_err(|error| invalid(format!("qualifying foreground command: {error}")))?,
            );
            if by_resource.insert(resource, spec).is_some() {
                return Err(invalid("duplicate foreground logical resource"));
            }
        }
        Ok(Self {
            assignment,
            inventory: None,
            state_root,
            resources: by_resource,
            qualified,
        })
    }

    /// Binds this validated catalog to the session's durable native inventory.
    #[must_use]
    pub(crate) fn with_inventory(mut self, inventory: NativeResourceInventory) -> Self {
        self.inventory = Some(inventory);
        self
    }

    /// Classifies one exact foreground process from live ownership evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when the resource is absent, state is corrupt, or
    /// process ownership is ambiguous or outside the current confinement.
    pub(crate) fn classify_runtime_revision(
        &self,
        resource: &ResourceId,
    ) -> Result<(NativeQualifiedResource, RuntimeResourceState), io::Error> {
        let spec = self
            .resources
            .get(resource)
            .ok_or_else(|| invalid("foreground resource is not catalogued"))?;
        let qualified = self
            .qualified
            .get(resource)
            .ok_or_else(|| invalid("foreground resource lost its qualification"))?
            .clone();
        let observed = ForegroundProcessSupervisor::new(&self.state_root)?.observe(spec)?;
        let state = if observed.running {
            RuntimeResourceState::Present {
                revision: spec.revision,
                health: RuntimeResourceHealth::Healthy,
            }
        } else {
            RuntimeResourceState::Absent
        };
        Ok((qualified, state))
    }
}

impl TrustedResourceCatalog for ForegroundProcessResourceCatalog {
    type Handle = ForegroundProcessHandle;
    type Error = io::Error;

    fn acquire(
        &mut self,
        context: ReservationContext<'_>,
        operation: &Operation,
        access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        authenticate_assignment(&self.assignment)?;
        if context
            .expected_provider
            .is_some_and(|expected| expected != &self.assignment)
        {
            return Err(invalid("foreground provider assignment is absent or stale"));
        }
        if &access.resource != &operation.target.resource {
            return Err(invalid("foreground access differs from operation target"));
        }
        let spec = self
            .resources
            .get(&access.resource)
            .ok_or_else(|| invalid("foreground resource is not catalogued"))?
            .clone();
        validate_operation(operation)?;
        let qualified = self
            .qualified
            .get(&access.resource)
            .ok_or_else(|| invalid("foreground resource lost its qualification"))?;
        let inventory = self
            .inventory
            .as_ref()
            .ok_or_else(|| invalid("foreground catalog has no durable native inventory"))?;
        let context = ReservationContext {
            expected_provider: Some(&self.assignment),
            ..context
        };
        let reservation = inventory
            .reserve(qualified, context, operation, access)
            .map_err(|error| invalid(error.to_string()))?;

        let lock_path = self
            .state_root
            .join("locks")
            .join(format!("{}.lock", resource_key(&spec.resource)?));
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error))?;

        let supervisor = ForegroundProcessSupervisor::new(&self.state_root)?;
        let observed = supervisor.observe(&spec)?;
        let revision = if observed.running {
            ResourceRevisionObservation::Present(spec.revision)
        } else {
            ResourceRevisionObservation::Absent
        };
        let evidence = ResourceAdmissionEvidence::new_with_revision_observation(
            spec.resource.clone(),
            Some(self.assignment.incarnation.clone()),
            revision,
            observation_value(&observed)?,
        );
        Ok(CatalogReservation::new(
            ForegroundProcessHandle {
                spec,
                _lock: lock,
                reservation,
            },
            evidence,
        ))
    }

    fn release(
        &mut self,
        resource: &ResourceId,
        handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        if resource != &handle.spec.resource {
            return Err(invalid("foreground release differs from its reservation"));
        }
        if handle.reservation.logical() != resource {
            return Err(invalid(
                "foreground native reservation differs from its logical resource",
            ));
        }
        handle
            .reservation
            .release()
            .map_err(|error| invalid(error.to_string()))
    }
}

/// Durable request reconstructed with a freshly acquired foreground handle.
#[derive(Clone, Debug)]
pub struct ForegroundProcessRequest {
    durable: ForegroundDurableRequest,
    spec: ForegroundProcessResourceSpec,
}

/// Completion and observation evidence for foreground lifecycle calls.
#[derive(Clone, Debug)]
pub struct ForegroundProcessRecord {
    durable: AbilityValue,
    outputs: BTreeMap<LocalKey, AbilityValue>,
}

impl AdapterRecord for ForegroundProcessRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for ForegroundProcessRecord {
    fn outputs(&self) -> &BTreeMap<LocalKey, AbilityValue> {
        &self.outputs
    }
}

/// Executes the built-in application-container foreground-process contract.
pub struct NativeForegroundProcessAdapter {
    assignment: ProviderAssignment,
    supervisor: ForegroundProcessSupervisor,
    failure: ForegroundProcessRecord,
}

impl NativeForegroundProcessAdapter {
    /// Constructs an adapter for one exact foreground assignment.
    ///
    /// # Errors
    ///
    /// Returns an error unless the assignment names the built-in interface and
    /// handler or the private state root cannot be established.
    pub fn new(
        assignment: ProviderAssignment,
        state_root: impl Into<PathBuf>,
    ) -> Result<Self, io::Error> {
        authenticate_assignment(&assignment)?;
        let failure = record(&ForegroundProcessObservation {
            running: false,
            process_identity: None,
        })?;
        Ok(Self {
            assignment,
            supervisor: ForegroundProcessSupervisor::new(state_root)?,
            failure,
        })
    }

    /// Invokes one already authenticated foreground resource specification.
    ///
    /// This entry point backs the production container qualification driver;
    /// normal activation reaches the same action implementation through
    /// [`TrustedAdapter`]. The caller must first admit `spec` through a
    /// [`ForegroundProcessResourceCatalog`] built from the verified package set.
    ///
    /// # Errors
    ///
    /// Returns an error when `method` is unsupported or process observation,
    /// start, or termination cannot establish exact ownership.
    pub fn invoke_qualified(
        &mut self,
        method: &str,
        spec: &ForegroundProcessResourceSpec,
        control: &dyn RuntimeControl,
    ) -> Result<ForegroundProcessObservation, io::Error> {
        let action = match method {
            "observe" => ForegroundAction::Observe,
            "start" => ForegroundAction::Start,
            "stop" => ForegroundAction::Stop,
            _ => return Err(invalid("unsupported foreground process method")),
        };
        let request = ForegroundProcessRequest {
            durable: ForegroundDurableRequest::new(action, spec),
            spec: spec.clone(),
        };
        self.apply(&request, control)
    }
}

impl TrustedAdapter for NativeForegroundProcessAdapter {
    type Request = ForegroundProcessRequest;
    type Completion = ForegroundProcessRecord;
    type Observation = ForegroundProcessRecord;
    type Handle = ForegroundProcessHandle;
    type PrepareError = io::Error;

    fn authenticates(
        &self,
        implementation: &ProviderImplementationReference,
        method: &MethodReference,
        purpose: InvocationPurpose,
    ) -> bool {
        implementation == &self.assignment.implementation
            && method.interface == self.assignment.interface
            && matches!(method.method.as_str(), "observe" | "start" | "stop")
            && matches!(
                purpose,
                InvocationPurpose::Effect
                    | InvocationPurpose::Reconcile
                    | InvocationPurpose::Cancel
            )
    }

    fn prepare_durable(
        &self,
        operation: &Operation,
        inputs: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        validate_operation(operation)?;
        if inputs.as_json() != &serde_json::Value::Bool(true) {
            return Err(invalid("foreground method parameter must be true"));
        }
        let [resource] = resources else {
            return Err(invalid(
                "foreground operation requires exactly one resource",
            ));
        };
        if resource.resource() != &operation.target.resource {
            return Err(invalid("foreground handle differs from operation target"));
        }
        let durable =
            ForegroundDurableRequest::new(action_for(operation)?, &resource.native().spec);
        AbilityValue::new(serde_json::to_value(durable).map_err(invalid_serde)?)
            .map_err(|error| invalid(format!("encoding foreground request: {error}")))
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        let request: ForegroundDurableRequest =
            serde_json::from_value(durable.as_json().clone()).map_err(invalid_serde)?;
        let [resource] = resources else {
            return Err(invalid("foreground recovery requires exactly one resource"));
        };
        let expected = ForegroundDurableRequest::new(request.action, &resource.native().spec);
        if request != expected || request.schema != REQUEST_SCHEMA {
            return Err(invalid(
                "durable foreground request differs from fresh resource acquisition",
            ));
        }
        Ok(ForegroundProcessRequest {
            durable: request,
            spec: resource.native().spec.clone(),
        })
    }

    fn execute(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        if control.is_cancelled() {
            return EffectDisposition::RejectedBeforeEffect(self.failure.clone());
        }
        if let Err(error) = self.supervisor.observe(&request.spec) {
            return if error.kind() == io::ErrorKind::InvalidData {
                EffectDisposition::RejectedBeforeEffect(self.failure.clone())
            } else {
                EffectDisposition::Indeterminate(self.failure.clone())
            };
        }
        match self.apply(request, control) {
            Ok(observed) => EffectDisposition::Completed(self.record(observed)),
            Err(_) => EffectDisposition::Indeterminate(self.failure.clone()),
        }
    }

    fn reconcile(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        let observed = match self.supervisor.observe(&request.spec) {
            Ok(observed) => observed,
            Err(_) => {
                return ReconcileDisposition::InterventionRequired(self.failure.clone());
            }
        };
        match request.durable.action {
            ForegroundAction::Observe => ReconcileDisposition::Completed(self.record(observed)),
            ForegroundAction::Start if observed.running => {
                ReconcileDisposition::Completed(self.record(observed))
            }
            ForegroundAction::Start => match self.supervisor.start(&request.spec, control) {
                Ok(observed) => ReconcileDisposition::Completed(self.record(observed)),
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    ReconcileDisposition::StillIndeterminate(self.record(observed))
                }
                Err(_) => ReconcileDisposition::InterventionRequired(self.record(observed)),
            },
            ForegroundAction::Stop if !observed.running => {
                ReconcileDisposition::Completed(self.record(observed))
            }
            ForegroundAction::Stop => match self.supervisor.stop(&request.spec, control) {
                Ok(observed) => ReconcileDisposition::Completed(self.record(observed)),
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    ReconcileDisposition::StillIndeterminate(self.record(observed))
                }
                Err(_) => ReconcileDisposition::InterventionRequired(self.record(observed)),
            },
        }
    }

    fn cancel(
        &mut self,
        request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        if request.durable.action == ForegroundAction::Start {
            return match self.supervisor.observe(&request.spec) {
                Ok(observed) if observed.running => {
                    CancellationDisposition::Completed(self.record(observed))
                }
                Ok(observed) => {
                    CancellationDisposition::RejectedBeforeEffect(self.record(observed))
                }
                Err(_) => CancellationDisposition::Indeterminate(self.failure.clone()),
            };
        }
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

impl NativeForegroundProcessAdapter {
    fn record(&self, observed: ForegroundProcessObservation) -> ForegroundProcessRecord {
        match record(&observed) {
            Ok(record) => record,
            Err(_) => self.failure.clone(),
        }
    }

    fn apply(
        &mut self,
        request: &ForegroundProcessRequest,
        control: &dyn RuntimeControl,
    ) -> Result<ForegroundProcessObservation, io::Error> {
        match request.durable.action {
            ForegroundAction::Observe => self.supervisor.observe(&request.spec),
            ForegroundAction::Start => self.supervisor.start(&request.spec, control),
            ForegroundAction::Stop => self.supervisor.stop(&request.spec, control),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ForegroundAction {
    Observe,
    Start,
    Stop,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ForegroundDurableRequest {
    schema: String,
    action: ForegroundAction,
    resource: ResourceId,
    revision: RevisionId,
    artifact: ArtifactReference,
    entry_point: String,
    arguments: Vec<String>,
}

impl ForegroundDurableRequest {
    fn new(action: ForegroundAction, spec: &ForegroundProcessResourceSpec) -> Self {
        Self {
            schema: REQUEST_SCHEMA.to_string(),
            action,
            resource: spec.resource.clone(),
            revision: spec.revision,
            artifact: spec.artifact.clone(),
            entry_point: spec.entry_point.clone(),
            arguments: spec.arguments.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ForegroundState {
    schema: String,
    request: ForegroundDurableRequest,
    executable: String,
    confinement: Confinement,
    ownership_token: String,
    identity: Option<ProcessIdentity>,
}

impl ForegroundState {
    fn intent(
        spec: &ForegroundProcessResourceSpec,
        command: &QualifiedCommand,
        confinement: &Confinement,
        token: &str,
    ) -> Self {
        Self {
            schema: STATE_SCHEMA.to_string(),
            request: ForegroundDurableRequest::new(ForegroundAction::Start, spec),
            executable: command.executable.to_string_lossy().into_owned(),
            confinement: confinement.clone(),
            ownership_token: token.to_string(),
            identity: None,
        }
    }

    fn authenticate(
        &self,
        spec: &ForegroundProcessResourceSpec,
        command: &QualifiedCommand,
        confinement: &Confinement,
        token: &str,
    ) -> Result<(), io::Error> {
        if self.schema != STATE_SCHEMA
            || self.request != ForegroundDurableRequest::new(ForegroundAction::Start, spec)
            || self.executable != command.executable.to_string_lossy()
            || &self.confinement != confinement
            || self.ownership_token != token
        {
            return Err(invalid(
                "foreground state is foreign to the authenticated resource or confinement",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Confinement {
    uid: u32,
    cgroup: String,
    mount_namespace: String,
    network_namespace: String,
    pid_namespace: String,
    user_namespace: String,
}

impl Confinement {
    fn current() -> Result<Self, io::Error> {
        Ok(Self {
            uid: rustix::process::getuid().as_raw(),
            cgroup: read_bounded("/proc/self/cgroup", 16 * 1024)?,
            mount_namespace: read_namespace("/proc/self/ns/mnt")?,
            network_namespace: read_namespace("/proc/self/ns/net")?,
            pid_namespace: read_namespace("/proc/self/ns/pid")?,
            user_namespace: read_namespace("/proc/self/ns/user")?,
        })
    }

    fn for_process(pid: u32) -> Result<Self, io::Error> {
        let prefix = PathBuf::from("/proc").join(pid.to_string());
        Ok(Self {
            uid: read_process_uid(&prefix.join("status"))?,
            cgroup: read_bounded(prefix.join("cgroup"), 16 * 1024)?,
            mount_namespace: read_namespace(prefix.join("ns/mnt"))?,
            network_namespace: read_namespace(prefix.join("ns/net"))?,
            pid_namespace: read_namespace(prefix.join("ns/pid"))?,
            user_namespace: read_namespace(prefix.join("ns/user"))?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentity {
    boot_id: String,
    pid: u32,
    process_group: u32,
    session: u32,
    start_time: u64,
}

impl ProcessIdentity {
    fn read(
        pid: u32,
        command: &QualifiedCommand,
        confinement: &Confinement,
        token: &str,
    ) -> Result<Self, io::Error> {
        let prefix = PathBuf::from("/proc").join(pid.to_string());
        let actual_executable = fs::canonicalize(prefix.join("exe"))?;
        if actual_executable != command.observed_executable {
            return Err(invalid("foreground executable differs after spawn"));
        }
        let cmdline = read_nul_fields(&prefix.join("cmdline"), 512 * 1024)?;
        let expected = std::iter::once(command.executable.to_string_lossy().into_owned())
            .chain(command.arguments.iter().cloned())
            .collect::<Vec<_>>();
        if cmdline != expected {
            return Err(invalid(format!(
                "foreground argument vector differs after spawn: expected {expected:?}, observed {cmdline:?}"
            )));
        }
        if Confinement::for_process(pid)? != *confinement {
            return Err(invalid("foreground process escaped executor confinement"));
        }
        let environment = read_nul_fields(&prefix.join("environ"), 512 * 1024)?;
        if !environment
            .iter()
            .any(|entry| entry == &format!("{OWNERSHIP_ENVIRONMENT}={token}"))
        {
            return Err(invalid("foreground process lacks its ownership token"));
        }
        let stat = read_bounded(prefix.join("stat"), 16 * 1024)?;
        let (_, process_group, session, start_time) = parse_stat(&stat)?;
        Ok(Self {
            boot_id: read_bounded("/proc/sys/kernel/random/boot_id", 128)?
                .trim()
                .to_string(),
            pid,
            process_group,
            session,
            start_time,
        })
    }

    fn still_exists(&self) -> bool {
        let path = PathBuf::from("/proc")
            .join(self.pid.to_string())
            .join("stat");
        read_bounded(path, 16 * 1024)
            .and_then(|stat| parse_stat(&stat))
            .is_ok_and(|(state, _, _, start_time)| state != 'Z' && start_time == self.start_time)
    }
}

struct QualifiedCommand {
    executable: PathBuf,
    observed_executable: PathBuf,
    arguments: Vec<String>,
}

impl QualifiedCommand {
    fn new(spec: &ForegroundProcessResourceSpec) -> Result<Self, io::Error> {
        validate_entry_point(&spec.entry_point)?;
        if spec.arguments.len() > 128
            || spec
                .arguments
                .iter()
                .any(|argument| argument.len() > 4_096 || argument.as_bytes().contains(&0))
        {
            return Err(invalid("foreground arguments exceed the contract bounds"));
        }
        let artifact = fs::canonicalize(&spec.artifact.store_path)?;
        let executable = artifact.join(&spec.entry_point);
        let observed_executable = fs::canonicalize(&executable)?;
        let observed_metadata = fs::metadata(&observed_executable)?;
        use std::os::unix::fs::MetadataExt as _;
        if !observed_executable.starts_with(&artifact)
            || !observed_metadata.is_file()
            || observed_metadata.mode() & 0o111 == 0
        {
            return Err(invalid(
                "foreground entry point is outside its authenticated artifact or is not executable",
            ));
        }
        Ok(Self {
            executable,
            observed_executable,
            arguments: spec.arguments.clone(),
        })
    }
}

enum LocatedProcess {
    None,
    One(ProcessIdentity),
    Many,
}

fn locate_owned_process(
    command: &QualifiedCommand,
    confinement: &Confinement,
    token: &str,
    retained: Option<&ProcessIdentity>,
) -> Result<LocatedProcess, io::Error> {
    let mut groups = BTreeMap::new();
    let mut claimed_groups = BTreeSet::new();
    let retained_pid = if let Some(identity) = retained
        && identity.still_exists()
    {
        let observed = ProcessIdentity::read(identity.pid, command, confinement, token)?;
        claimed_groups.insert(observed.process_group);
        if observed.pid == observed.process_group {
            groups.insert(observed.process_group, observed);
        }
        Some(identity.pid)
    } else {
        None
    };
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if retained_pid == Some(pid) {
            continue;
        }
        match claimed_process_group(pid, confinement, token) {
            Ok(Some(group)) => {
                claimed_groups.insert(group);
            }
            Ok(None) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
        match ProcessIdentity::read(pid, command, confinement, token) {
            Ok(identity) if identity.pid == identity.process_group => {
                groups.insert(identity.process_group, identity);
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidData
                ) => {}
            Err(error) => return Err(error),
        }
        if claimed_groups.len() > 1 {
            return Ok(LocatedProcess::Many);
        }
    }
    if groups.is_empty() && !claimed_groups.is_empty() {
        return Err(invalid(
            "foreground ownership token has no live exact process-group leader",
        ));
    }
    Ok(groups
        .into_values()
        .next()
        .map_or(LocatedProcess::None, LocatedProcess::One))
}

fn claimed_process_group(
    pid: u32,
    confinement: &Confinement,
    token: &str,
) -> Result<Option<u32>, io::Error> {
    let prefix = PathBuf::from("/proc").join(pid.to_string());
    let environment = read_nul_fields(&prefix.join("environ"), 512 * 1024)?;
    if !environment
        .iter()
        .any(|entry| entry == &format!("{OWNERSHIP_ENVIRONMENT}={token}"))
    {
        return Ok(None);
    }
    if Confinement::for_process(pid)? != *confinement {
        return Err(invalid(
            "foreground ownership token escaped executor confinement",
        ));
    }
    let stat = read_bounded(prefix.join("stat"), 16 * 1024)?;
    let (state, process_group, _, _) = parse_stat(&stat)?;
    Ok((state != 'Z').then_some(process_group))
}

fn qualify_spawned_child(
    child: &mut Child,
    command: &QualifiedCommand,
    confinement: &Confinement,
    token: &str,
) -> Result<ProcessIdentity, io::Error> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(250))
        .ok_or_else(|| invalid("foreground qualification deadline overflowed"))?;
    loop {
        match ProcessIdentity::read(child.id(), command, confinement, token) {
            Ok(identity) => return Ok(identity),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                if child.try_wait()?.is_some() || Instant::now() >= deadline {
                    return Err(error);
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn authenticate_assignment(assignment: &ProviderAssignment) -> Result<(), io::Error> {
    let interface = foreground_process_interface_key()
        .map_err(|error| invalid(format!("building foreground interface: {error}")))?;
    let expected = foreground_process_provider(assignment.implementation.artifact.clone())
        .map_err(|error| invalid(format!("building foreground provider: {error}")))?;
    let descriptor = expected
        .descriptor_digest()
        .map_err(|error| invalid(format!("describing foreground provider: {error}")))?;
    let handler = foreground_process_handler_key()
        .map_err(|error| invalid(format!("building foreground handler: {error}")))?;
    if assignment.interface != interface
        || assignment.implementation.descriptor != descriptor
        || assignment.implementation.handler.as_ref() != Some(&handler)
        || assignment.implementation.artifact != expected.artifact
    {
        return Err(invalid(
            "assignment does not name the built-in foreground interface and handler",
        ));
    }
    Ok(())
}

fn validate_operation(operation: &Operation) -> Result<(), io::Error> {
    let interface = foreground_process_interface_key()
        .map_err(|error| invalid(format!("building foreground interface: {error}")))?;
    if operation.interface != interface {
        return Err(invalid("foreground operation uses another interface"));
    }
    action_for(operation).map(|_| ())
}

fn action_for(operation: &Operation) -> Result<ForegroundAction, io::Error> {
    match operation.method.as_str() {
        "observe" => Ok(ForegroundAction::Observe),
        "start" => Ok(ForegroundAction::Start),
        "stop" => Ok(ForegroundAction::Stop),
        _ => Err(invalid("unsupported foreground process method")),
    }
}

fn ownership_token(
    spec: &ForegroundProcessResourceSpec,
    confinement: &Confinement,
) -> Result<String, io::Error> {
    #[derive(Serialize)]
    struct Ownership<'a> {
        resource: &'a ResourceId,
        revision: RevisionId,
        artifact: &'a ArtifactReference,
        entry_point: &'a str,
        arguments: &'a [String],
        confinement: &'a Confinement,
    }
    Sha256Digest::of_canonical(
        "aos.ability.foreground-process-ownership/v1",
        &Ownership {
            resource: &spec.resource,
            revision: spec.revision,
            artifact: &spec.artifact,
            entry_point: &spec.entry_point,
            arguments: &spec.arguments,
            confinement,
        },
    )
    .map(|digest| digest.to_string())
    .map_err(|error| invalid(format!("encoding foreground ownership: {error}")))
}

fn observation(identity: Option<ProcessIdentity>) -> ForegroundProcessObservation {
    ForegroundProcessObservation {
        running: identity.is_some(),
        process_identity: identity.map(|identity| {
            format!(
                "boot={};pid={};start={};pgid={};sid={}",
                identity.boot_id,
                identity.pid,
                identity.start_time,
                identity.process_group,
                identity.session
            )
        }),
    }
}

fn record(observed: &ForegroundProcessObservation) -> Result<ForegroundProcessRecord, io::Error> {
    Ok(ForegroundProcessRecord {
        durable: observation_value(observed)?,
        outputs: BTreeMap::new(),
    })
}

fn observation_value(observed: &ForegroundProcessObservation) -> Result<AbilityValue, io::Error> {
    AbilityValue::new(serde_json::json!({
        "schema": FOREGROUND_PROCESS_OBSERVATION_SCHEMA,
        "running": observed.running,
        "process_identity": observed.process_identity
    }))
    .map_err(|error| invalid(format!("encoding foreground observation: {error}")))
}

fn wait_for_group_exit(
    process_group: u32,
    control: &dyn RuntimeControl,
) -> Result<bool, io::Error> {
    let budget = control
        .attempt_remaining_millis()
        .min(control.recovery_remaining_millis());
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(budget))
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "invalid process deadline"))?;
    while process_group_exists(process_group)? {
        if control.is_cancelled() || Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(POLL_INTERVAL);
    }
    Ok(true)
}

fn process_group_exists(process_group: u32) -> Result<bool, io::Error> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(_) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match read_bounded(entry.path().join("stat"), 16 * 1024) {
            Ok(stat) => stat,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let (state, observed_group, _, _) = parse_stat(&stat)?;
        if state != 'Z' && observed_group == process_group {
            return Ok(true);
        }
    }
    Ok(false)
}

fn require_budget(control: &dyn RuntimeControl) -> Result<(), io::Error> {
    if control.is_cancelled()
        || control.attempt_remaining_millis() == 0
        || control.recovery_remaining_millis() == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "foreground operation exhausted its durable runtime budget",
        ));
    }
    Ok(())
}

fn terminate_child(child: &mut Child) {
    if let Some(group) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
    let _ = child.wait();
}

fn ensure_private_directory(path: &Path) -> Result<(), io::Error> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("foreground state path is not a real directory"));
        }
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != rustix::process::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(invalid(
                "foreground state directory is not private to the supervisor user",
            ));
        }
        return Ok(());
    }
    fs::create_dir_all(path)?;
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn write_state(path: &Path, state: &ForegroundState) -> Result<(), io::Error> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let bytes = aos_contract::canonical::to_vec(state)
        .map_err(|error| invalid(format!("encoding foreground state: {error}")))?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    sync_parent(path)
}

fn read_state(path: &Path) -> Result<Option<ForegroundState>, io::Error> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if bytes.len() > 512 * 1024 {
        return Err(invalid("foreground state exceeds its size bound"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(invalid_serde)
}

fn remove_state(path: &Path) -> Result<(), io::Error> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn sync_parent(path: &Path) -> Result<(), io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("foreground state has no parent directory"))?;
    File::open(parent)?.sync_all()
}

fn resource_key(resource: &ResourceId) -> Result<String, io::Error> {
    Sha256Digest::of_canonical("aos.ability.foreground-process-lock/v1", resource)
        .map(|digest| digest.hex())
        .map_err(|error| invalid(format!("encoding foreground lock identity: {error}")))
}

fn validate_entry_point(entry_point: &str) -> Result<(), io::Error> {
    let path = Path::new(entry_point);
    if entry_point.is_empty()
        || entry_point.len() > 4_096
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(invalid(
            "foreground entry point is not a safe relative path",
        ));
    }
    Ok(())
}

fn read_namespace(path: impl AsRef<Path>) -> Result<String, io::Error> {
    fs::read_link(path).map(|target| target.to_string_lossy().into_owned())
}

fn read_process_uid(path: &Path) -> Result<u32, io::Error> {
    let status = read_bounded(path, 64 * 1024)?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| invalid("process status has no UID"))?;
    line.split_ascii_whitespace()
        .nth(2)
        .and_then(|uid| uid.parse().ok())
        .ok_or_else(|| invalid("process status has an invalid effective UID"))
}

fn read_bounded(path: impl AsRef<Path>, limit: usize) -> Result<String, io::Error> {
    let bytes = fs::read(path)?;
    if bytes.len() > limit {
        return Err(invalid("proc observation exceeds its size bound"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("proc observation is not UTF-8"))
}

fn read_nul_fields(path: &Path, limit: usize) -> Result<Vec<String>, io::Error> {
    let bytes = fs::read(path)?;
    if bytes.len() > limit {
        return Err(invalid("process vector exceeds its size bound"));
    }
    bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .map(|field| {
            String::from_utf8(field.to_vec())
                .map_err(|_| invalid("process vector contains non-UTF-8 data"))
        })
        .collect()
}

fn parse_stat(stat: &str) -> Result<(char, u32, u32, u64), io::Error> {
    let end = stat
        .rfind(')')
        .ok_or_else(|| invalid("process stat has no command terminator"))?;
    let fields = stat[end + 1..].split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() <= 19 {
        return Err(invalid("process stat is truncated"));
    }
    let process_group = fields[2]
        .parse()
        .map_err(|_| invalid("process stat has an invalid process group"))?;
    let session = fields[3]
        .parse()
        .map_err(|_| invalid("process stat has an invalid session"))?;
    let start_time = fields[19]
        .parse()
        .map_err(|_| invalid("process stat has an invalid start time"))?;
    let state = fields[0]
        .chars()
        .next()
        .ok_or_else(|| invalid("process stat has no state"))?;
    Ok((state, process_group, session, start_time))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_serde(error: serde_json::Error) -> io::Error {
    invalid(format!("invalid foreground JSON: {error}"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use aos_ability_model::{EnvironmentId, ExecutionStage, InstanceId};

    use super::*;

    struct TestControl;

    impl RuntimeControl for TestControl {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn elapsed_millis(&self) -> u64 {
            0
        }

        fn attempt_remaining_millis(&self) -> u64 {
            5_000
        }

        fn recovery_remaining_millis(&self) -> u64 {
            5_000
        }
    }

    #[test]
    fn supervisor_starts_observes_and_stops_exact_process() {
        use std::os::unix::fs::MetadataExt as _;

        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let spec = sleep_spec("lifecycle");
        let mut supervisor = ForegroundProcessSupervisor::new(temporary.path().join("state"))
            .expect("state root is valid");

        let started = supervisor
            .start(&spec, &TestControl)
            .expect("foreground process starts");
        assert!(started.running);
        assert!(started.process_identity.is_some());
        let state_path = supervisor
            .state_path(&spec.resource)
            .expect("state path is valid");
        assert_eq!(
            fs::metadata(state_path)
                .expect("durable state exists")
                .mode()
                & 0o777,
            0o600
        );

        let observed = supervisor
            .observe(&spec)
            .expect("foreground process is observable");
        assert_eq!(observed, started);

        let stopped = supervisor
            .stop(&spec, &TestControl)
            .expect("foreground process stops");
        assert!(!stopped.running);
        assert_eq!(
            supervisor.observe(&spec).expect("absence is observable"),
            stopped
        );
    }

    #[test]
    fn changed_command_cannot_reuse_durable_ownership() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let mut spec = sleep_spec("changed-command");
        let mut supervisor = ForegroundProcessSupervisor::new(temporary.path().join("state"))
            .expect("state root is valid");
        supervisor
            .start(&spec, &TestControl)
            .expect("foreground process starts");

        spec.arguments = vec!["31".to_string()];
        let error = supervisor
            .observe(&spec)
            .expect_err("changed command must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        spec.arguments = vec!["30".to_string()];
        supervisor
            .stop(&spec, &TestControl)
            .expect("original process remains owned");
    }

    #[test]
    fn supervisor_rejects_state_visible_to_other_users() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let state_root = temporary.path().join("state");
        fs::create_dir(&state_root).expect("state root is created");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o755))
            .expect("state permissions are changed");

        let error = match ForegroundProcessSupervisor::new(state_root) {
            Ok(_) => panic!("shared state root must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn qualified_command_rejects_artifact_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let artifact = temporary.path().join("artifact");
        fs::create_dir(&artifact).expect("artifact directory is created");
        symlink(find_executable("sleep"), artifact.join("sleep"))
            .expect("escaping executable symlink is created");
        let mut spec = sleep_spec("symlink-escape");
        spec.artifact.store_path = artifact.to_string_lossy().into_owned();
        spec.entry_point = "sleep".to_string();

        let error = match QualifiedCommand::new(&spec) {
            Ok(_) => panic!("artifact-local symlink escape must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn preflight_rejects_executable_outside_verified_artifact_catalog() {
        let spec = sleep_spec("unverified-artifact");
        let assignment = foreground_assignment(&spec.artifact);
        let packages = VerifiedAbilityPackageSet::default();

        let error = preflight_native_foreground(&packages, &assignment, &spec)
            .expect_err("unverified executable metadata must fail before dispatch");

        assert!(error.to_string().contains("exact metadata"));
    }

    #[test]
    fn cancelling_absent_start_never_spawns_the_process() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let spec = sleep_spec("cancel-absent-start");
        let assignment = foreground_assignment(&spec.artifact);
        let mut adapter =
            NativeForegroundProcessAdapter::new(assignment, temporary.path().join("state"))
                .expect("foreground adapter is valid");
        let request = ForegroundProcessRequest {
            durable: ForegroundDurableRequest::new(ForegroundAction::Start, &spec),
            spec: spec.clone(),
        };

        let disposition = adapter.cancel(&request, &TestControl);

        assert!(matches!(
            disposition,
            CancellationDisposition::RejectedBeforeEffect(_)
        ));
        assert!(
            !adapter
                .supervisor
                .observe(&spec)
                .expect("absence remains observable")
                .running
        );
    }

    #[test]
    fn adapter_rejects_changed_foreground_authority_before_effect() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let state_root = temporary.path().join("state");
        let spec = sleep_spec("foreign-authority");
        let assignment = foreground_assignment(&spec.artifact);
        let mut adapter = NativeForegroundProcessAdapter::new(assignment, &state_root)
            .expect("foreground adapter is valid");
        adapter
            .supervisor
            .start(&spec, &TestControl)
            .expect("owned process starts before authority changes");
        let state_path = adapter
            .supervisor
            .state_path(&spec.resource)
            .expect("state path is derivable");
        let mut state = read_state(&state_path)
            .expect("state is readable")
            .expect("started process has a receipt");
        let original_state = state.clone();
        state.request.resource.key =
            LocalKey::new("foreign-authority").expect("foreign key is valid");
        write_state(&state_path, &state).expect("foreign receipt is durable");
        let request = ForegroundProcessRequest {
            durable: ForegroundDurableRequest::new(ForegroundAction::Start, &spec),
            spec: spec.clone(),
        };

        assert!(matches!(
            adapter.execute(&request, &TestControl),
            EffectDisposition::RejectedBeforeEffect(_)
        ));

        write_state(&state_path, &original_state).expect("owned receipt is restored");
        assert!(
            adapter
                .supervisor
                .observe(&spec)
                .expect("restored process remains observable")
                .running
        );
        adapter
            .supervisor
            .stop(&spec, &TestControl)
            .expect("foreground process stops during cleanup");
    }

    #[test]
    fn retained_identity_does_not_hide_a_second_owned_process_group() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let spec = sleep_spec("duplicate-claimant");
        let mut supervisor = ForegroundProcessSupervisor::new(temporary.path().join("state"))
            .expect("state root is valid");
        supervisor
            .start(&spec, &TestControl)
            .expect("first foreground process starts");

        let command = QualifiedCommand::new(&spec).expect("command is qualified");
        let confinement = Confinement::current().expect("current confinement is readable");
        let token = ownership_token(&spec, &confinement).expect("ownership token is encodable");
        let mut claimant = Command::new(&command.executable)
            .args(&command.arguments)
            .env_clear()
            .env(OWNERSHIP_ENVIRONMENT, &token)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("second claimant starts");
        qualify_spawned_child(&mut claimant, &command, &confinement, &token)
            .expect("second claimant is observable");

        let error = supervisor
            .observe(&spec)
            .expect_err("two owned groups must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        terminate_child(&mut claimant);
        supervisor
            .stop(&spec, &TestControl)
            .expect("original process remains stoppable after duplicate cleanup");
    }

    #[test]
    fn multiple_claimants_in_the_owned_group_are_not_ambiguous() {
        let temporary = tempfile::tempdir().expect("temporary directory is available");
        let spec = sleep_spec("same-group-claimant");
        let mut supervisor = ForegroundProcessSupervisor::new(temporary.path().join("state"))
            .expect("state root is valid");
        supervisor
            .start(&spec, &TestControl)
            .expect("group leader starts");
        let command = QualifiedCommand::new(&spec).expect("command is qualified");
        let confinement = Confinement::current().expect("current confinement is readable");
        let token = ownership_token(&spec, &confinement).expect("ownership token is encodable");
        let LocatedProcess::One(identity) =
            locate_owned_process(&command, &confinement, &token, None)
                .expect("owned group is discoverable")
        else {
            panic!("exactly one owned group must exist")
        };
        assert_eq!(
            identity.pid, identity.process_group,
            "the retained identity must pin the live group leader"
        );
        let mut member = Command::new(&command.executable)
            .args(&command.arguments)
            .env_clear()
            .env(OWNERSHIP_ENVIRONMENT, &token)
            .process_group(identity.process_group as i32)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("group member starts");
        qualify_spawned_child(&mut member, &command, &confinement, &token)
            .expect("group member is observable");

        assert!(
            supervisor
                .observe(&spec)
                .expect("one owned group remains unambiguous")
                .running
        );
        supervisor
            .stop(&spec, &TestControl)
            .expect("the complete owned group stops");
        let _ = member.wait();
    }

    fn foreground_assignment(artifact: &ArtifactReference) -> ProviderAssignment {
        let provider = foreground_process_provider(artifact.clone())
            .expect("built-in foreground provider is valid");
        ProviderAssignment {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("test").expect("authority is valid"),
                    key: LocalKey::new("assignment").expect("environment is valid"),
                    stage: ExecutionStage::ApplicationContainer,
                },
                key: LocalKey::new("executor").expect("instance is valid"),
            },
            interface: provider.interface.clone(),
            implementation: ProviderImplementationReference {
                descriptor: provider
                    .descriptor_digest()
                    .expect("provider descriptor is valid"),
                artifact: provider.artifact,
                handler: Some(foreground_process_handler_key().expect("handler key is valid")),
            },
            incarnation: aos_ability_model::IncarnationId::new("test-foreground")
                .expect("incarnation is valid"),
        }
    }

    fn sleep_spec(label: &str) -> ForegroundProcessResourceSpec {
        let executable = find_executable("sleep");
        let store_path = store_root(&executable);
        let entry_point = executable
            .strip_prefix(&store_path)
            .expect("sleep executable belongs to its store root")
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string();
        ForegroundProcessResourceSpec {
            resource: ResourceId {
                provider: InstanceId {
                    environment: EnvironmentId {
                        authority: LocalKey::new("test").expect("authority is valid"),
                        key: LocalKey::new(label).expect("environment is valid"),
                        stage: ExecutionStage::ApplicationContainer,
                    },
                    key: LocalKey::new("nginx").expect("instance is valid"),
                },
                key: LocalKey::new("service").expect("resource is valid"),
            },
            revision: RevisionId(Sha256Digest::of_bytes("foreground-test-revision")),
            artifact: ArtifactReference {
                content: Sha256Digest::of_bytes("foreground-test-content"),
                store_path: store_path.to_string_lossy().into_owned(),
                nar_hash: Sha256Digest::of_bytes("foreground-test-nar"),
                closure: Sha256Digest::of_bytes("foreground-test-closure"),
            },
            entry_point,
            arguments: vec!["30".to_string()],
        }
    }

    fn find_executable(name: &str) -> PathBuf {
        let candidate = std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set"))
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
            .expect("sleep exists in the hermetic test PATH");
        let artifact = store_root(
            &candidate
                .canonicalize()
                .expect("sleep resolves to its canonical executable"),
        );
        let executable = artifact.join("bin").join(name);
        assert!(executable.is_file(), "sleep is exposed by its artifact");
        executable
    }

    fn store_root(path: &Path) -> PathBuf {
        let mut components = path.components();
        let root = components.next().expect("store path has root");
        let nix = components.next().expect("store path has nix component");
        let store = components.next().expect("store path has store component");
        let object = components.next().expect("store path has object component");
        [
            root.as_os_str(),
            nix.as_os_str(),
            store.as_os_str(),
            object.as_os_str(),
        ]
        .iter()
        .collect()
    }
}
