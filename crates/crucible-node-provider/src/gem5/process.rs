//! Private native process ownership and retained original event-prefix receipts.

use crate::operational_time::OperationalDeadline;

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::OwnedFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use crucible_node_contract::{ContentRef, Id, Phase, Position, U64, Validate};
use serde_json::{Value, json};

use super::protocol::{Bootstrap, Ready};
use super::{
    GEM5_NATIVE_FRAME_BYTES, GEM5_NATIVE_PROTOCOL, Gem5Boundary, Gem5Completion,
    Gem5ProcessImageTools, Gem5Run,
};
use crate::{
    ProviderError,
    transport::{FrameReader, write_frame},
};

#[path = "image_process.rs"]
pub(crate) mod image_process;

#[path = "preparation.rs"]
mod preparation;

use preparation::PreparationOrigin;
pub use preparation::{Gem5PreparationCustody, Gem5PreparedSession};

#[path = "closure.rs"]
mod closure;

#[path = "exact.rs"]
mod exact;

#[path = "containment.rs"]
mod containment;

pub use containment::{Gem5CensusDiagnostic, Gem5QuarantineCustody, Gem5ReclamationProof};

pub use exact::{Gem5ExactAuthority, Gem5ExactProfileVerifier};
use exact::{same_native_state, validate_exact_completion, validate_exact_request};

pub use closure::{Gem5DiagnosticObject, Gem5OpaqueProfileVerifier, Gem5ProcessClosure};

#[cfg(test)]
#[path = "publication_tests.rs"]
mod publication_tests;

#[cfg(test)]
#[path = "installation_tests.rs"]
mod installation_tests;

/// Binds a trusted launch path to its exact measured immutable contents.
#[derive(Clone, Debug)]
pub struct Gem5LaunchArtifact {
    /// Gives a privately installed path; public content references are never paths.
    pub path: PathBuf,
    /// Commits to the complete original artifact bytes.
    pub content: ContentRef,
}

/// Specifies the complete explicit resources of the native mechanism profile.
#[derive(Clone, Debug)]
pub struct Gem5Launch {
    /// Measures the actual source-built ALL native executable.
    pub executable: Gem5LaunchArtifact,
    /// Measures the installed private native control script.
    pub owner_script: Gem5LaunchArtifact,
    /// Measures its explicitly selected CPU/memory realization script.
    pub model_script: Gem5LaunchArtifact,
    /// Measures the complete freestanding guest executable.
    pub guest: Gem5LaunchArtifact,
    /// Selects exactly x86_64 or aarch64 for the installed mechanism profile.
    pub guest_isa: String,
    /// Names its indivisible execution owner.
    pub owner: Id,
    /// Names its original native incarnation.
    pub incarnation: Id,
    /// Fences older native incarnations without wrapping.
    pub generation: U64,
    /// Names an existing private canonical resource directory.
    pub resource_root: PathBuf,
    /// Bounds all private native requests in operational host time.
    pub timeout: Duration,
    /// Installs genuine process-image tools, or refuses durable image capture.
    pub process_images: Option<Gem5ProcessImageTools>,
}

/// Transfers actual native handles and every original obligation to supervision.
pub struct Gem5NativeCustody {
    // Sealed at spawn before any exit observation can release the kernel PID.
    kernel_identity: Option<containment::KernelIdentity>,
    /// Retains the real child until actual reaping, never merely a kill request.
    pub child: Child,
    /// Retains the genuine control session rather than making the native owner exit.
    pub stream: Option<UnixStream>,
    /// Retains the installed private endpoint for unchanged original reconnection.
    pub listener: Option<UnixListener>,
    /// Retains the last authenticated stopped event boundary, when established.
    pub boundary: Option<Gem5Boundary>,
    /// Retains its private writable root and immutable measured launch facts.
    pub launch: Gem5Launch,
    /// Retains every genuine completed event-prefix receipt.
    pub completed: BTreeMap<Id, Gem5Completion>,
    /// Retains a possibly started original operation after uncertain transport.
    pub unresolved: Option<Gem5Run>,
    /// Retains the original pending output until authentic publication ACK.
    pub pending: Option<Id>,
    /// Retains the latest authentic ACK identity for unchanged retries.
    pub last_acknowledged: Option<Id>,
    /// Retains an uncertain original image-capture operation.
    pub unresolved_capture: Option<Id>,
    /// Retains the complete sealed source image for any live reconstructed child.
    pub source_image: Option<crate::gem5::Gem5CapturedImage>,
    /// Retains original Ready bytes even when native preparation validation fails.
    pub preparation: Gem5PreparationCustody,
    /// Retains original process-group termination and actual reaping progress.
    pub quarantine: Option<Gem5QuarantineCustody>,
}

/// Supplies a preallocated persistent native custody slot before spawning.
pub trait Gem5CustodySlot {
    /// Retains actual child resources and original obligations infallibly.
    ///
    /// The capsule must outlive the driver. A supervisor may request termination
    /// but cannot discharge modeled output or state without authentic settlement.
    fn retain(self: Box<Self>, custody: Gem5NativeCustody);
}

/// Owns actual native gem5 control while preserving original receipt custody.
///
/// Construction establishes mechanical owner control. It does not manufacture
/// public exact qualification. [`Self::require_complete_inventory`] refuses
/// incomplete native observers; [`Self::qualify_exact`] separately requires an
/// independently audited complete opaque capture and installed closed policy.
pub struct Gem5NativeProcess {
    child: Option<Child>,
    kernel_identity: Option<containment::KernelIdentity>,
    launch: Gem5Launch,
    stream: Option<UnixStream>,
    // Keeps the installed private endpoint reserved for this native incarnation.
    listener: Option<UnixListener>,
    boundary: Gem5Boundary,
    completed: BTreeMap<Id, Gem5Completion>,
    pending: Option<Id>,
    last_acknowledged: Option<Id>,
    unresolved: Option<Gem5Run>,
    unresolved_capture: Option<Id>,
    source_image: Option<crate::gem5::Gem5CapturedImage>,
    quarantine: Option<Gem5QuarantineCustody>,
    preparation: Gem5PreparationCustody,
    supervisor: Option<Box<dyn Gem5CustodySlot>>,
}

impl Gem5NativeProcess {
    /// Launches measured native resources beneath a closed controller gate.
    ///
    /// # Errors
    /// Rejects changed artifacts, nonprivate roots, invalid selected models,
    /// occupied control resources, missing native peer custody or bad readiness.
    pub fn spawn(
        launch: Gem5Launch,
        supervisor: Box<dyn Gem5CustodySlot>,
    ) -> Result<Self, ProviderError> {
        preflight(&launch)?;
        let script = install(
            &launch.owner_script,
            &launch.resource_root.join("native-owner.py"),
        )?;
        install(
            &launch.model_script,
            &launch.resource_root.join("native-owner-model.py"),
        )?;
        let guest = install(&launch.guest, &launch.resource_root.join("guest.elf"))?;
        let socket = launch.resource_root.join("control.sock");
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let (mut private, inherited) = UnixStream::pair()?;
        let inherited: OwnedFd = inherited.into();
        let stdout = File::create(launch.resource_root.join("native.stdout"))?;
        let stderr = File::create(launch.resource_root.join("native.stderr"))?;
        let mut command = if let Some(tools) = &launch.process_images {
            let mut command = Command::new(&tools.launcher.path);
            command
                .args([
                    "--new-coordinator",
                    "--coord-port",
                    "0",
                    "--interval",
                    "0",
                    "--no-gzip",
                    "--ckpt-signal",
                    "40",
                ])
                .arg("--with-plugin")
                .arg(&tools.resource_helper.path)
                .arg("--ckptdir")
                .arg(&tools.image_root)
                .arg("--tmpdir")
                .arg(&tools.temporary_root)
                .arg(&launch.executable.path)
                .env("CRUCIBLE_CAPTURE_RESOURCE_ROOT", &launch.resource_root);
            command
        } else {
            Command::new(&launch.executable.path)
        };
        let bootstrap = Bootstrap {
            schema: GEM5_NATIVE_PROTOCOL,
            owner: launch.owner.clone(),
            incarnation: launch.incarnation.clone(),
            generation: launch.generation,
            controller_uid: U64::new(u64::from(rustix::process::getuid().as_raw())),
            guest_isa: launch.guest_isa.clone(),
            executable: path_text(&guest)?,
            resource_root: path_text(&launch.resource_root)?,
            control_socket: path_text(&socket)?,
        };
        let mut child = command
            .current_dir(
                launch
                    .process_images
                    .as_ref()
                    .map_or(&launch.resource_root, |tools| &tools.temporary_root),
            )
            .process_group(0)
            .arg(format!(
                "--outdir={}",
                launch.resource_root.join("output").display()
            ))
            .arg(&script)
            .stdin(Stdio::from(inherited))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        let mut kernel_identity = None;
        let mut preparation = Gem5PreparationCustody::AwaitingReady;
        let mut prepared_stream = None;
        let ready = (|| {
            kernel_identity = Some(containment::capture_identity(&child)?);
            write_frame(
                &mut private,
                &serde_json::to_value(bootstrap)
                    .map_err(|_| ProviderError::Frame("gem5 bootstrap encoding"))?,
                GEM5_NATIVE_FRAME_BYTES,
            )?;
            drop(private);
            prepared_stream = Some(connect(&listener, &mut child, launch.timeout)?);
            let stream = prepared_stream.as_mut().ok_or(ProviderError::Correlation(
                "gem5 original preparation control session is absent",
            ))?;
            let frame = exchange_read_retained(stream, launch.timeout)?;
            preparation = Gem5PreparationCustody::Received(frame.bytes);
            let ready: Ready = serde_json::from_value(frame.value)
                .map_err(|_| ProviderError::Frame("invalid gem5 native readiness"))?;
            if ready.kind != "ready"
                || ready.schema != GEM5_NATIVE_PROTOCOL
                || ready.owner != launch.owner
                || ready.incarnation != launch.incarnation
                || ready.generation != launch.generation
                || ready.continuation != "original"
                || ready.boundary.tick.get() != 0
                || ready.boundary.ordinal.get() != 0
                || crate::conformance::measure_executable(Path::new(&format!(
                    "/proc/{}/exe",
                    child.id()
                )))? != launch.executable.content
            {
                return Err(ProviderError::Correlation(
                    "actual gem5 initial native custody differs",
                ));
            }
            let boundary = ready.boundary.clone();
            preparation.authenticate(&child, &launch, ready, PreparationOrigin::Original)?;
            Ok(boundary)
        })();
        let boundary = match ready {
            Ok(ready) => ready,
            Err(error) => {
                supervisor.retain(Gem5NativeCustody {
                    kernel_identity,
                    child,
                    stream: prepared_stream.take(),
                    listener: Some(listener),
                    boundary: None,
                    launch,
                    completed: BTreeMap::new(),
                    unresolved: None,
                    pending: None,
                    last_acknowledged: None,
                    unresolved_capture: None,
                    source_image: None,
                    preparation,
                    quarantine: None,
                });
                return Err(error);
            }
        };
        Ok(Self {
            kernel_identity,
            child: Some(child),
            launch,
            stream: prepared_stream,
            listener: Some(listener),
            boundary,
            completed: BTreeMap::new(),
            pending: None,
            last_acknowledged: None,
            unresolved: None,
            unresolved_capture: None,
            source_image: None,
            preparation,
            quarantine: None,
            supervisor: Some(supervisor),
        })
    }

    /// Returns immutable original live native identity and measured resources.
    pub fn launch(&self) -> &Gem5Launch {
        &self.launch
    }

    /// Returns actual current native pre-event coordinates.
    pub fn boundary(&self) -> &Gem5Boundary {
        &self.boundary
    }

    /// Returns the retained original prefix still awaiting native acknowledgment.
    ///
    /// Reading this receipt conveys no execution or publication authority.
    pub fn pending_completion(&self) -> Option<&Gem5Completion> {
        self.pending
            .as_ref()
            .and_then(|operation| self.completed.get(operation))
    }

    /// Iterates immutable original native prefixes in canonical operation order.
    ///
    /// Reading or cloning a raw receipt conveys no submission or ACK authority.
    pub fn completed_prefixes(&self) -> impl ExactSizeIterator<Item = &Gem5Completion> {
        self.completed.values()
    }

    /// Returns the latest original native ACK identity retained for retry safety.
    pub fn last_acknowledged(&self) -> Option<&Id> {
        self.last_acknowledged.as_ref()
    }

    /// Refuses public exact admission when the native modeled-state closure is incomplete.
    ///
    /// # Errors
    /// Rejects missing native observers or any unsupported modeled domain. Passing
    /// this check still requires separate installed implementation qualification.
    pub fn require_complete_inventory(&self) -> Result<(), ProviderError> {
        if !self.boundary.has_complete_inventory() {
            return Err(ProviderError::Correlation(
                "gem5 complete modeled state is not qualified",
            ));
        }
        Ok(())
    }

    /// Reads actual native readiness without executing a modeled event.
    ///
    /// # Errors
    /// Rejects uncertain effects, disconnected peers or changed clock/ordinal.
    pub fn observe(&mut self) -> Result<Gem5Boundary, ProviderError> {
        let value = self.exchange(json!({"kind":"observe"}))?;
        let object = value
            .as_object()
            .ok_or(ProviderError::Frame("gem5 observation is not an object"))?;
        if object.len() != 2 || object.get("kind").and_then(Value::as_str) != Some("observed") {
            return Err(ProviderError::Correlation(
                "gem5 native observation kind differs",
            ));
        }
        let observed: Gem5Boundary = serde_json::from_value(
            object
                .get("boundary")
                .cloned()
                .ok_or(ProviderError::Frame("gem5 native boundary absent"))?,
        )
        .map_err(|_| ProviderError::Frame("gem5 native boundary shape"))?;
        if observed != self.boundary {
            return Err(ProviderError::Correlation(
                "observing gem5 changed its native event frontier",
            ));
        }
        Ok(observed)
    }

    /// Executes one original bounded native prefix and retains all output before release.
    ///
    /// # Errors
    /// Refuses changed retries, held output, invalid bounds, transport uncertainty,
    /// overshoot or native receipts inconsistent with actual retained custody.
    pub fn run(&mut self, original: Gem5Run) -> Result<Gem5Completion, ProviderError> {
        if original.exact_range.is_some() {
            return Err(ProviderError::Correlation(
                "gem5 exact range needs sealed live profile authority",
            ));
        }
        self.run_internal(original)
    }

    fn run_internal(&mut self, original: Gem5Run) -> Result<Gem5Completion, ProviderError> {
        if let Some(old) = self.completed.get(&original.operation) {
            if old.original != original {
                return Err(ProviderError::Conflict("gem5 original run changed"));
            }
            return Ok(old.clone());
        }
        if original.kind != "run"
            || self.quarantine.is_some()
            || self.pending.is_some()
            || self.unresolved.is_some()
            || self.unresolved_capture.is_some()
            || original.maximum_events.get() == 0
            || original.maximum_events.get() > 10_000_000
            || original.exclusive_tick < self.boundary.tick
            || self.completed.len() >= 65536
        {
            return Err(ProviderError::Conflict(
                "gem5 native original run custody unavailable",
            ));
        }
        validate_exact_request(&self.boundary, &original)?;
        self.unresolved = Some(original.clone());
        let response = self.exchange(
            serde_json::to_value(&original)
                .map_err(|_| ProviderError::Frame("gem5 run encoding"))?,
        )?;
        let receipt: Gem5Completion = serde_json::from_value(response)
            .map_err(|_| ProviderError::Frame("gem5 native receipt shape"))?;
        validate_completion(&self.boundary, &original, &receipt)?;
        validate_output_sequence(self.completed.values(), &receipt)?;
        self.boundary = receipt.after.clone();
        self.pending = Some(original.operation.clone());
        self.completed.insert(original.operation, receipt.clone());
        self.unresolved = None;
        Ok(receipt)
    }

    /// Authenticates an original receipt against this live native owner's custody.
    ///
    /// # Errors
    /// Rejects caller-created, changed, foreign or forgotten native completions.
    pub fn validate_completion(&self, receipt: &Gem5Completion) -> Result<(), ProviderError> {
        if self.completed.get(&receipt.operation) != Some(receipt) {
            return Err(ProviderError::Correlation(
                "gem5 completion lacks original actual native custody",
            ));
        }
        Ok(())
    }

    /// Acknowledges original native output after trusted coordinator publication.
    ///
    /// # Errors
    /// Refuses premature, foreign or changed release and retains uncertain custody.
    pub fn acknowledge(&mut self, operation: &Id) -> Result<(), ProviderError> {
        if self.last_acknowledged.as_ref() == Some(operation) {
            return Ok(());
        }
        if self.pending.as_ref() != Some(operation) {
            return Err(ProviderError::Correlation(
                "gem5 publication lacks original pending output",
            ));
        }
        let response = self.exchange(json!({"kind":"acknowledge","operation":operation}))?;
        if response != json!({"kind":"acknowledged","operation":operation}) {
            return Err(ProviderError::Correlation(
                "gem5 native acknowledgment differs",
            ));
        }
        self.pending = None;
        self.last_acknowledged = Some(operation.clone());
        Ok(())
    }

    /// Exposes the already reserved native process identifier for authenticated supervision.
    pub fn child_pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Reconnects actual surviving native custody without replacing an uncertain run.
    ///
    /// If a run response was lost, its exact original operation is observed again.
    /// Recovery cannot execute an absent original operation.
    /// An uncertain capture remains blocked until separately authenticated.
    ///
    /// # Errors
    /// Rejects a live session, missing original handles, changed native identity,
    /// unproved progress or an uncertain image-capture obligation.
    pub fn reconnect(&mut self) -> Result<(), ProviderError> {
        if self.stream.is_some() || self.unresolved_capture.is_some() {
            return Err(ProviderError::Conflict(
                "gem5 original reconnection unavailable",
            ));
        }
        let listener = self.listener.as_ref().ok_or(ProviderError::Correlation(
            "gem5 original listener custody omitted",
        ))?;
        let child = self.child.as_mut().ok_or(ProviderError::Correlation(
            "gem5 original child custody omitted",
        ))?;
        let mut stream = connect(listener, child, self.launch.timeout)?;
        let ready: Ready = serde_json::from_value(exchange_read(&mut stream, self.launch.timeout)?)
            .map_err(|_| ProviderError::Frame("gem5 reconnected readiness shape"))?;
        if ready.kind != "ready"
            || ready.schema != GEM5_NATIVE_PROTOCOL
            || ready.owner != self.launch.owner
            || ready.incarnation != self.launch.incarnation
            || ready.generation != self.launch.generation
            || ready.continuation != "reconnected"
            || (self.unresolved.is_none() && ready.boundary != self.boundary)
        {
            return Err(ProviderError::Correlation(
                "gem5 reconnected actual original custody differs",
            ));
        }
        self.stream = Some(stream);
        if let Some(original) = self.unresolved.clone() {
            let response =
                self.exchange(json!({"kind":"recover","operation":original.operation}))?;
            if response == json!({"kind":"not_started","operation":original.operation}) {
                return Err(ProviderError::Correlation(
                    "gem5 original run has no native completion; explicit no-effect reconciliation required",
                ));
            }
            let receipt: Gem5Completion = serde_json::from_value(response)
                .map_err(|_| ProviderError::Frame("gem5 original run recovery shape"))?;
            validate_completion(&self.boundary, &original, &receipt)?;
            validate_output_sequence(self.completed.values(), &receipt)?;
            if receipt.after != ready.boundary {
                return Err(ProviderError::Correlation(
                    "gem5 original recovered frontier differs",
                ));
            }
            self.boundary = receipt.after.clone();
            self.pending = Some(original.operation.clone());
            self.completed.insert(original.operation, receipt);
            self.unresolved = None;
        }
        Ok(())
    }

    fn exchange(&mut self, request: Value) -> Result<Value, ProviderError> {
        if self.quarantine.is_some() {
            return Err(ProviderError::Conflict("gem5 native owner is quarantined"));
        }
        let stream = self.stream.as_mut().ok_or(ProviderError::Correlation(
            "gem5 native controller is disconnected",
        ))?;
        let mut io = DeadlineIo {
            stream,
            deadline: deadline(self.launch.timeout)?,
        };
        let result = (|| {
            write_frame(&mut io, &request, GEM5_NATIVE_FRAME_BYTES)?;
            FrameReader::new(&mut io, GEM5_NATIVE_FRAME_BYTES)?
                .read()?
                .ok_or(ProviderError::Correlation(
                    "gem5 native peer disconnected before receipt",
                ))
        })();
        if result.is_err() {
            self.stream = None;
        }
        result
    }
}

impl Drop for Gem5NativeProcess {
    fn drop(&mut self) {
        // Both fields are installed together before a live driver exists, and
        // only Drop consumes them. The reserved slot transfers custody once.
        if let (Some(child), Some(supervisor)) = (self.child.take(), self.supervisor.take()) {
            supervisor.retain(Gem5NativeCustody {
                kernel_identity: self.kernel_identity.take(),
                child,
                stream: self.stream.take(),
                listener: self.listener.take(),
                boundary: Some(self.boundary.clone()),
                launch: self.launch.clone(),
                completed: std::mem::take(&mut self.completed),
                unresolved: self.unresolved.take(),
                pending: self.pending.take(),
                last_acknowledged: self.last_acknowledged.take(),
                unresolved_capture: self.unresolved_capture.take(),
                source_image: self.source_image.take(),
                preparation: std::mem::replace(
                    &mut self.preparation,
                    Gem5PreparationCustody::AwaitingReady,
                ),
                quarantine: self.quarantine.take(),
            });
        }
    }
}

pub(super) fn validate_completion(
    before: &Gem5Boundary,
    original: &Gem5Run,
    receipt: &Gem5Completion,
) -> Result<(), ProviderError> {
    let delta = receipt
        .after
        .ordinal
        .get()
        .checked_sub(before.ordinal.get());
    if receipt.kind != "completed"
        || receipt.operation != original.operation
        || &receipt.original != original
        || &receipt.before != before
        || receipt.after.tick < before.tick
        || (receipt.processed_events.get() == 0 && receipt.after.tick != before.tick)
        || receipt.after.tick_ordinal > receipt.after.ordinal
        || (receipt.processed_events.get() == 0 && !same_native_state(before, &receipt.after))
        || (receipt.after.tick == before.tick
            && receipt
                .after
                .tick_ordinal
                .get()
                .checked_sub(before.tick_ordinal.get())
                != Some(receipt.processed_events.get()))
        || (receipt.after.tick > before.tick
            && (receipt.after.tick_ordinal.get() == 0
                || receipt.after.tick_ordinal > receipt.processed_events))
        || receipt.processed_events > original.maximum_events
        || delta != Some(receipt.processed_events.get())
        || (original.exact_range.is_none()
            && receipt.processed_events.get() > 0
            && receipt.after.tick >= original.exclusive_tick)
        || receipt.output.len() > 65536
        || !matches!(
            receipt.reason.as_str(),
            "horizon" | "idle" | "event_budget" | "output" | "guest_exit"
        )
        || (receipt.reason == "guest_exit") != receipt.exit_cause.is_some()
        || (receipt.reason == "guest_exit") != receipt.exit_code.is_some()
        || (receipt.reason == "output" && receipt.output.is_empty())
        || (original.exact_range.is_none()
            && receipt.reason == "horizon"
            && (!receipt.after.has_next_event || receipt.after.next_tick < original.exclusive_tick))
        || (receipt.reason == "idle" && receipt.after.has_next_event)
        || (receipt.reason == "event_budget" && receipt.processed_events != original.maximum_events)
        || (receipt.after.has_next_event && receipt.after.next_tick < receipt.after.tick)
        || receipt
            .after
            .inventory
            .get("native_tick")
            .and_then(Value::as_str)
            != Some(receipt.after.tick.get().to_string().as_str())
    {
        return Err(ProviderError::Correlation(
            "gem5 native completion violates its original prefix",
        ));
    }
    validate_publications(receipt)?;
    validate_exact_completion(receipt)?;
    Ok(())
}

fn validate_output_sequence<'a>(
    completed: impl Iterator<Item = &'a Gem5Completion>,
    receipt: &Gem5Completion,
) -> Result<(), ProviderError> {
    let mut last = completed
        .flat_map(|prefix| prefix.publications.iter())
        .map(|publication| publication.output_id.get())
        .max()
        .unwrap_or(0);
    for publication in &receipt.publications {
        let next = last.checked_add(1).ok_or(ProviderError::ResourceExhausted(
            "native output identity exhausted",
        ))?;
        if publication.output_id.get() != next {
            return Err(ProviderError::Correlation(
                "native output original FIFO sequence differs",
            ));
        }
        last = next;
    }
    Ok(())
}

fn validate_publications(receipt: &Gem5Completion) -> Result<(), ProviderError> {
    let mut previous = None;
    let mut bytes = 0usize;
    for publication in &receipt.publications {
        bytes = bytes
            .checked_add(publication.payload.len())
            .ok_or(ProviderError::Frame(
                "native output payload length overflow",
            ))?;
        if publication.output_id.get() == 0
            || publication.guest_fd != 1
            || publication.payload.is_empty()
            || publication.tick < receipt.before.tick
            || publication.tick != receipt.after.tick
            || publication.event_ordinal <= receipt.before.ordinal
            || publication.event_ordinal != receipt.after.ordinal
            || publication.tick_ordinal.get() == 0
            || publication.tick_ordinal != receipt.after.tick_ordinal
            || previous.is_some_and(|prior| publication.output_id <= prior)
            || bytes > 65536
        {
            return Err(ProviderError::Correlation(
                "native console birth lies outside its original stopped event",
            ));
        }
        previous = Some(publication.output_id);
    }
    if !receipt.publications.is_empty()
        && (bytes != receipt.output.len()
            || !receipt
                .publications
                .iter()
                .flat_map(|publication| publication.payload.iter())
                .eq(receipt.output.iter()))
    {
        return Err(ProviderError::Correlation(
            "native output differs from its retained original publications",
        ));
    }
    Ok(())
}

fn preflight(launch: &Gem5Launch) -> Result<(), ProviderError> {
    if launch.generation.get() == 0
        || launch.timeout.is_zero()
        || !matches!(launch.guest_isa.as_str(), "x86_64" | "aarch64")
    {
        return Err(ProviderError::Frame("invalid gem5 original launch profile"));
    }
    let metadata = fs::metadata(&launch.resource_root)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::getuid().as_raw()
        || fs::canonicalize(&launch.resource_root)? != launch.resource_root
    {
        return Err(ProviderError::Correlation(
            "gem5 resource root is not canonically private",
        ));
    }
    for artifact in [
        &launch.executable,
        &launch.owner_script,
        &launch.model_script,
        &launch.guest,
    ] {
        artifact.content.validate()?;
        let bytes = fs::read(&artifact.path)?;
        artifact.content.verify(&bytes)?;
    }
    if let Some(tools) = &launch.process_images {
        super::images::validate_private_directory(&tools.image_root)?;
        super::images::validate_private_directory(&tools.temporary_root)?;
        if tools.image_root.starts_with(&launch.resource_root)
            || tools.temporary_root.starts_with(&launch.resource_root)
            || fs::read_dir(&tools.image_root)?.next().is_some()
        {
            return Err(ProviderError::Correlation(
                "gem5 image resources are not privately separated",
            ));
        }
        for artifact in [
            &tools.launcher,
            &tools.restarter,
            &tools.reconstruction_executable,
            &tools.resource_helper,
        ] {
            artifact.content.verify(&fs::read(&artifact.path)?)?;
        }
    }
    Ok(())
}

fn install(artifact: &Gem5LaunchArtifact, target: &Path) -> Result<PathBuf, ProviderError> {
    let bytes = fs::read(&artifact.path)?;
    artifact.content.verify(&bytes)?;
    // The native checkpoint records these permissions. A later reconstruction
    // must not inherit broader access from the launching process's umask.
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(target.to_owned())
}

fn path_text(path: &Path) -> Result<String, ProviderError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(ProviderError::Frame("gem5 native path is not UTF-8"))
}

fn connect(
    listener: &UnixListener,
    child: &mut Child,
    timeout: Duration,
) -> Result<UnixStream, ProviderError> {
    let end = deadline(timeout)?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let peer =
                    rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
                if peer.pid.as_raw_nonzero().get() != child.id() as i32
                    || peer.uid != rustix::process::getuid()
                {
                    return Err(ProviderError::Correlation(
                        "gem5 native kernel peer differs",
                    ));
                }
                return Ok(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        // Keep the exited leader waitable until containment has authenticated
        // and signalled its original private group. Child::try_wait would reap
        // it here and release the only kernel anchor before fallback custody.
        if containment::observe_exit(child)?.is_some() {
            return Err(ProviderError::Correlation(
                "gem5 native child exited before controller readiness",
            ));
        }
        if end.is_expired() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "gem5 native readiness timeout",
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn exchange_read(stream: &mut UnixStream, timeout: Duration) -> Result<Value, ProviderError> {
    let mut io = DeadlineIo {
        stream,
        deadline: deadline(timeout)?,
    };
    FrameReader::new(&mut io, GEM5_NATIVE_FRAME_BYTES)?
        .read()?
        .ok_or(ProviderError::Correlation(
            "gem5 native readiness disconnected",
        ))
}

fn deadline(timeout: Duration) -> Result<OperationalDeadline, ProviderError> {
    OperationalDeadline::after(timeout)
        .ok_or(ProviderError::ResourceExhausted("gem5 native deadline"))
}

struct DeadlineIo<'a> {
    stream: &'a mut UnixStream,
    deadline: OperationalDeadline,
}

impl DeadlineIo<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .remaining()
            .filter(|value| !value.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "gem5 native total request budget exhausted",
                )
            })
    }
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Reads one original native packet without discarding its wire body.
fn exchange_read_retained(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<crate::transport::RetainedFrame, ProviderError> {
    let mut io = DeadlineIo {
        stream,
        deadline: deadline(timeout)?,
    };
    FrameReader::new(&mut io, GEM5_NATIVE_FRAME_BYTES)?
        .read_retained()?
        .ok_or(ProviderError::Correlation(
            "gem5 native peer disconnected before preparation receipt",
        ))
}
