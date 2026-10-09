//! Authentic native ARM root-model launch and retained original preparation.
//!
//! The private control connection and real kernel child remain in preallocated
//! custody through every fallible step. Parsing a Ready packet never creates
//! public node authority, and restored construction remains a distinct origin.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Read,
    os::{
        fd::OwnedFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

use crucible_node_contract::{ContentRef, HashRef, Id, canonical};
use serde_json::{Value, json};

use super::arm_root_budget::HostBudget;
use super::arm_root_group::ArmRootGroup;
use super::arm_root_io::{NativeDeadlineIo, deadline};
use super::images::{measure_file, measure_image_file};
use super::model::{Gem5ArmNativeReady, Gem5ModelAsset, Gem5ModelSelection};
use super::{ArmRootLaunch, GEM5_NATIVE_FRAME_BYTES, Gem5Boundary};
use crate::{
    ProviderError,
    transport::{FrameReader, write_frame},
};

/// Transfers real native resources to reserved supervision on error or drop.
pub trait ArmRootCustodySlot: Send {
    /// Retains original handles and packets without acknowledging modeled work.
    fn retain(self: Box<Self>, custody: ArmRootNativeCustody);
}

/// Owns every construction-stage effect until a live process adopts the pair.
pub(crate) struct ArmRootConstruction {
    parts: Option<(ArmRootNativeCustody, Box<dyn ArmRootCustodySlot>)>,
}

impl ArmRootConstruction {
    pub(crate) fn new(custody: ArmRootNativeCustody, slot: Box<dyn ArmRootCustodySlot>) -> Self {
        Self {
            parts: Some((custody, slot)),
        }
    }

    pub(crate) fn custody_mut(&mut self) -> Result<&mut ArmRootNativeCustody, ProviderError> {
        self.parts
            .as_mut()
            .map(|(custody, _)| custody)
            .ok_or(ProviderError::Frame("ARM construction already adopted"))
    }

    pub(crate) fn adopt(
        mut self,
    ) -> Result<(ArmRootNativeCustody, Box<dyn ArmRootCustodySlot>), ProviderError> {
        self.parts
            .take()
            .ok_or(ProviderError::Frame("ARM construction custody absent"))
    }
}

impl Drop for ArmRootConstruction {
    fn drop(&mut self) {
        if let Some((custody, slot)) = self.parts.take() {
            slot.retain(custody);
        }
    }
}

pub(crate) fn reserve_control_frames(
    custody: &mut ArmRootNativeCustody,
    count: usize,
) -> Result<(), ProviderError> {
    reserve_frame_storage(&mut custody.control_frames, count)
}

fn reserve_frame_storage(frames: &mut Vec<Vec<u8>>, count: usize) -> Result<(), ProviderError> {
    if frames
        .len()
        .checked_add(count)
        .is_none_or(|total| total > 1024)
    {
        return Err(ProviderError::ResourceExhausted(
            "ARM original control-frame ledger",
        ));
    }
    frames
        .try_reserve(count)
        .map_err(|_| ProviderError::ResourceExhausted("ARM reserved control-frame storage"))
}

/// Retains original kernel ownership and transport uncertainty for supervision.
pub struct ArmRootNativeCustody {
    pub(crate) group: Option<ArmRootGroup>,
    pub(crate) unenrolled: Option<Child>,
    pub(crate) launch: ArmRootLaunch,
    pub(crate) stream: Option<UnixStream>,
    pub(crate) listener: Option<UnixListener>,
    pub(crate) received_ready: Option<Vec<u8>>,
    pub(crate) control_frames: Vec<Vec<u8>>,
    pub(crate) history: super::ArmRootControlHistory,
    pub(crate) audit_workers: Vec<ArmRootGroup>,
    pub(crate) unenrolled_helpers: Vec<Child>,
    pub(crate) host_ledger: Box<ArmRootHostLedger>,
}

impl ArmRootNativeCustody {
    /// Borrows the entire original and uncertain host continuation on transfer.
    pub fn host_ledger(&self) -> &ArmRootHostLedger {
        &self.host_ledger
    }

    /// Requests termination only against an authenticated original group anchor.
    ///
    /// # Errors
    /// Refuses unknown child custody, changed kernel identity, or failed signaling.
    pub fn begin_quarantine(&mut self) -> Result<(), ProviderError> {
        if self.group.is_none() {
            self.group = Some(ArmRootGroup::enroll_retained(&mut self.unenrolled)?);
        }
        self.stream.take();
        while !self.unenrolled_helpers.is_empty() {
            self.audit_workers.try_reserve(1).map_err(|_| {
                ProviderError::ResourceExhausted("ARM reserved helper retirement storage")
            })?;
            self.audit_workers
                .push(ArmRootGroup::enroll_helper(&mut self.unenrolled_helpers)?);
        }
        for worker in &mut self.audit_workers {
            worker.begin_retirement()?;
        }
        self.group
            .as_mut()
            .ok_or(ProviderError::Correlation("ARM original group omitted"))?
            .begin_retirement()
    }

    /// Polls actual single reaping and complete finite helper-group disappearance.
    ///
    /// # Errors
    /// Refuses absent retirement, unknown wait ownership, census failures or timeout.
    pub fn poll_reclamation(&mut self) -> Result<bool, ProviderError> {
        let mut reclaimed = true;
        for worker in &mut self.audit_workers {
            reclaimed &= worker.poll_retirement()?;
        }
        reclaimed &= self
            .group
            .as_mut()
            .ok_or(ProviderError::Correlation("ARM original group omitted"))?
            .poll_retirement()?;
        Ok(reclaimed)
    }
}

/// Retains complete host-side original and uncertain operation custody on transfer.
pub struct ArmRootHostLedger {
    pub(crate) prepared: Option<ArmRootPreparedSession>,
    pub(crate) boundary: Option<Gem5Boundary>,
    pub(crate) completed: BTreeMap<Id, super::arm_root_capture::ArmRootRunOutcome>,
    pub(crate) pending: Option<Id>,
    pub(crate) last_acknowledged: Option<Id>,
    pub(crate) unresolved: Option<Value>,
    pub(crate) unresolved_capture: Option<Id>,
}

impl ArmRootHostLedger {
    pub(crate) fn reserve() -> Box<Self> {
        // This bounded capsule is allocated before a native child can exist.
        // Transfer fills the existing storage by moving each authoritative body.
        Box::new(Self {
            prepared: None,
            boundary: None,
            completed: BTreeMap::new(),
            pending: None,
            last_acknowledged: None,
            unresolved: None,
            unresolved_capture: None,
        })
    }

    /// Borrows original preparation provenance, if validation reached that state.
    pub fn prepared(&self) -> Option<&ArmRootPreparedSession> {
        self.prepared.as_ref()
    }

    /// Borrows the last authentic observed native cut without claiming no later effects.
    pub fn boundary(&self) -> Option<&Gem5Boundary> {
        self.boundary.as_ref()
    }

    /// Borrows every original successful or refused native prefix retained by the owner.
    pub fn operations(&self) -> impl ExactSizeIterator<Item = (&Id, &super::ArmRootRunOutcome)> {
        self.completed.iter()
    }

    /// Borrows the original attempted request whose transport effects remain uncertain.
    pub fn unresolved(&self) -> Option<&Value> {
        self.unresolved.as_ref()
    }

    /// Borrows original capture uncertainty independently from modeled prefix progress.
    pub fn unresolved_capture(&self) -> Option<&Id> {
        self.unresolved_capture.as_ref()
    }

    /// Borrows held prefix custody without acknowledging native output or refusal.
    pub fn pending(&self) -> Option<&Id> {
        self.pending.as_ref()
    }

    /// Borrows the latest original ACK identity without granting replacement custody.
    pub fn last_acknowledged(&self) -> Option<&Id> {
        self.last_acknowledged.as_ref()
    }
}

/// Owns one supervised stopped ARM native process and its original Ready packet.
pub struct ArmRootNativeProcess {
    pub(crate) custody: Option<ArmRootNativeCustody>,
    pub(crate) slot: Option<Box<dyn ArmRootCustodySlot>>,
    pub(crate) ready: Gem5ArmNativeReady,
    pub(crate) prepared: Option<ArmRootPreparedSession>,
    pub(crate) boundary: Gem5Boundary,
    pub(crate) completed: BTreeMap<Id, super::arm_root_capture::ArmRootRunOutcome>,
    pub(crate) pending: Option<Id>,
    pub(crate) last_acknowledged: Option<Id>,
    pub(crate) unresolved: Option<Value>,
    pub(crate) unresolved_capture: Option<Id>,
}

pub(crate) enum ArmRootOrigin {
    Original,
    Restored { source_capture: Id },
}

/// Retains genuine original preparation bytes without a public minting constructor.
pub struct ArmRootPreparedSession {
    pub(crate) pid: u32,
    pub(crate) start_ticks: String,
    pub(crate) source_scope: HashRef,
    pub(crate) packet: ContentRef,
    pub(crate) bytes: Vec<u8>,
    pub(crate) transcript: ContentRef,
    pub(crate) transcript_bytes: Vec<u8>,
    pub(crate) token: Id,
    pub(crate) origin: ArmRootOrigin,
}

impl ArmRootPreparedSession {
    /// Returns the immutable token of this original native control session.
    pub fn token(&self) -> &Id {
        &self.token
    }

    /// Borrows native reconstruction lineage installed only by the actual restarter.
    pub fn source_capture(&self) -> Option<&Id> {
        match &self.origin {
            ArmRootOrigin::Original => None,
            ArmRootOrigin::Restored { source_capture } => Some(source_capture),
        }
    }

    /// Borrows the unchanged first validated Ready wire packet and its commitment.
    pub fn packet(&self) -> (&ContentRef, &[u8]) {
        (&self.packet, &self.bytes)
    }

    /// Borrows the authenticated owning-session provenance and its commitment.
    pub fn transcript(&self) -> (&ContentRef, &[u8]) {
        (&self.transcript, &self.transcript_bytes)
    }
}

impl ArmRootNativeProcess {
    /// Installs exact model assets and starts one private native owner.
    ///
    /// This establishes mechanical preparation only. Public Ready additionally
    /// requires a current independently audited capture and installed qualifier.
    ///
    /// # Errors
    /// Retains actual child and original packet custody on native launch, peer,
    /// bootstrap, artifact, readiness, or bounded transport failures.
    pub fn spawn(
        launch: ArmRootLaunch,
        slot: Box<dyn ArmRootCustodySlot>,
    ) -> Result<Self, ProviderError> {
        let staged = stage(&launch)?;
        let endpoint = launch.tools.temporary_root.join("control.sock");
        let listener = UnixListener::bind(&endpoint)?;
        listener.set_nonblocking(true)?;
        let (mut bootstrap, child_bootstrap) = UnixStream::pair()?;
        bootstrap.set_write_timeout(Some(launch.timeout))?;
        let output = launch.resource_root.join("native.stderr");
        let errors = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)?;
        let mut command = Command::new(&launch.tools.launcher.path);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .env("PYTHONHASHSEED", "0")
            .env("PYTHONNOUSERSITE", "1")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("CRUCIBLE_CAPTURE_RESOURCE_ROOT", &launch.resource_root)
            .args([
                "--new-coordinator",
                "--coord-port",
                "0",
                "--no-gzip",
                "--interval",
                "0",
                "--ckpt-signal",
                "40",
                "--with-plugin",
            ])
            .arg(&launch.tools.resource_helper.path)
            .arg("--ckptdir")
            .arg(&launch.tools.image_root)
            .arg(launch.artifact("native_executable")?.path.clone())
            .arg("--listener-mode=off")
            .arg(format!(
                "--outdir={}",
                launch.resource_root.join("output").display()
            ))
            .arg(launch.resource_root.join("native-controller-arm-root.py"))
            .current_dir(&launch.tools.temporary_root)
            .process_group(0)
            .stdin(Stdio::from(OwnedFd::from(child_bootstrap)))
            .stdout(Stdio::null())
            .stderr(errors);
        let host_ledger = ArmRootHostLedger::reserve();
        let mut history = super::ArmRootControlHistory::empty();
        history.reserve(3)?;
        history.reserve_session()?;
        let child = command.spawn()?;
        let custody = ArmRootNativeCustody {
            group: None,
            unenrolled: Some(child),
            launch,
            stream: None,
            listener: Some(listener),
            received_ready: None,
            control_frames: Vec::new(),
            history,
            audit_workers: Vec::new(),
            unenrolled_helpers: Vec::new(),
            host_ledger,
        };
        let mut construction = ArmRootConstruction::new(custody, slot);
        let outcome = (|| {
            let custody = construction.custody_mut()?;
            custody.group = Some(ArmRootGroup::enroll_retained(&mut custody.unenrolled)?);
            let native_bootstrap = json!({"schema":"crucible.gem5.arm-linux-native/1",
                "owner":custody.launch.owner,"incarnation":custody.launch.incarnation,
                "generation":custody.launch.generation,"controller_uid":rustix::process::getuid().as_raw().to_string(),
                "guest_isa":"aarch64","executable":"","resource_root":custody.launch.resource_root,
                "control_socket":endpoint,"model":staged});
            // Retain the attempted bootstrap before its first transport effect.
            custody.history.request(&native_bootstrap)?;
            custody.host_ledger.unresolved = Some(native_bootstrap.clone());
            let mut io = NativeDeadlineIo::new(&mut bootstrap, deadline(custody.launch.timeout)?);
            write_frame(&mut io, &native_bootstrap, GEM5_NATIVE_FRAME_BYTES)?;
            let stream = connect(custody, false)?;
            custody.stream = Some(stream);
            let frame = read(custody)?;
            custody
                .history
                .push(super::ArmRootControlKind::Ready, frame.1.clone())?;
            custody.received_ready = Some(frame.1);
            let ready: Gem5ArmNativeReady = serde_json::from_value(frame.0)
                .map_err(|_| ProviderError::Frame("ARM typed Ready shape"))?;
            let selection = selection(&custody.launch)?;
            ready.validate_selection(
                &selection,
                &custody.launch.owner,
                &custody.launch.incarnation,
                custody.launch.generation,
            )?;
            if ready.continuation != "original"
                || ready.boundary.ordinal.get() != 0
                || ready.boundary.tick.get() != 0
                || ready.boundary.logical_position.time_ps.get() != 0
            {
                return Err(ProviderError::Correlation(
                    "ARM original preparation starts after modeled execution",
                ));
            }
            let group = custody
                .group
                .as_ref()
                .ok_or(ProviderError::Frame("ARM kernel group omitted"))?;
            group.require_live()?;
            let (pid, start_ticks) = group.identity();
            let source_scope = custody.launch.scope()?;
            let bytes = custody
                .received_ready
                .as_ref()
                .ok_or(ProviderError::Frame("ARM original Ready omitted"))?
                .clone();
            let packet = canonical::content_ref(&bytes, "application/json")?;
            let transcript_bytes = canonical::canonical_json(&json!({
                "format":"crucible.gem5.arm-root-prepared-session","version":1,"origin":"original",
                "pid":pid,"start_ticks":start_ticks,"source_scope":source_scope,
                "profile":custody.launch.profile,"ready_packet":packet,
                "owner":custody.launch.owner,"incarnation":custody.launch.incarnation,
                "generation":custody.launch.generation}))?;
            let transcript = canonical::content_ref(&transcript_bytes, "application/json")?;
            let token = Id::new(format!("gem5/arm-root/prepared/{}", transcript.hash.digest))?;
            let prepared = ArmRootPreparedSession {
                pid,
                start_ticks: start_ticks.to_owned(),
                source_scope,
                packet,
                bytes,
                transcript,
                transcript_bytes,
                token,
                origin: ArmRootOrigin::Original,
            };
            custody.history.prepared(&prepared)?;
            Ok((ready, prepared))
        })();
        match outcome {
            Ok((ready, prepared)) => {
                let (mut custody, slot) = construction.adopt()?;
                custody.host_ledger.unresolved = None;
                let boundary = ready.boundary.clone();
                Ok(Self {
                    custody: Some(custody),
                    slot: Some(slot),
                    ready,
                    prepared: Some(prepared),
                    boundary,
                    completed: BTreeMap::new(),
                    pending: None,
                    last_acknowledged: None,
                    unresolved: None,
                    unresolved_capture: None,
                })
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn exchange(&mut self, request: Value) -> Result<Value, ProviderError> {
        let custody = self
            .custody
            .as_mut()
            .ok_or(ProviderError::Frame("ARM custody transferred"))?;
        custody
            .group
            .as_ref()
            .ok_or(ProviderError::Frame("ARM kernel peer omitted"))?
            .require_live()?;
        // Retain every original wire packet before interpreting the response.
        // Caller marks modeled requests unresolved before transport can begin.
        reserve_control_frames(custody, 1)?;
        custody.history.reserve(2)?;
        custody.history.request(&request)?;
        let original_deadline = deadline(custody.launch.timeout)?;
        let stream = custody
            .stream
            .as_mut()
            .ok_or(ProviderError::Frame("ARM control absent"))?;
        write_frame(
            &mut NativeDeadlineIo::new(stream, original_deadline),
            &request,
            GEM5_NATIVE_FRAME_BYTES,
        )?;
        let frame = read_with_deadline(custody, original_deadline)?;
        custody.control_frames.push(frame.1);
        custody.history.push(
            super::ArmRootControlKind::Response,
            custody
                .control_frames
                .last()
                .ok_or(ProviderError::Frame("ARM retained response omitted"))?
                .clone(),
        )?;
        Ok(frame.0)
    }

    /// Borrows every actual original control body and preparation transcript.
    ///
    /// # Errors
    /// Refuses already transferred custody rather than reconstructing lost bodies.
    pub fn control_history(&self) -> Result<&super::ArmRootControlHistory, ProviderError> {
        Ok(&self
            .custody
            .as_ref()
            .ok_or(ProviderError::Frame("ARM custody transferred"))?
            .history)
    }

    /// Borrows the exact source-installed launch record of this actual owner.
    ///
    /// # Errors
    /// Refuses custody already transferred to supervision.
    pub fn launch(&self) -> Result<&ArmRootLaunch, ProviderError> {
        Ok(&self
            .custody
            .as_ref()
            .ok_or(ProviderError::Frame("ARM custody transferred"))?
            .launch)
    }

    /// Borrows the latest authentic parked native and logical frontier.
    pub fn boundary(&self) -> &Gem5Boundary {
        &self.boundary
    }

    /// Borrows the original typed private readiness without granting public authority.
    pub fn native_ready(&self) -> &Gem5ArmNativeReady {
        &self.ready
    }
}

impl Drop for ArmRootNativeProcess {
    fn drop(&mut self) {
        if let (Some(slot), Some(mut custody)) = (self.slot.take(), self.custody.take()) {
            *custody.host_ledger = ArmRootHostLedger {
                prepared: self.prepared.take(),
                // The unobservable Drop-only placeholder allocates no storage
                // and can never qualify a session or escape through an accessor.
                boundary: Some(std::mem::replace(&mut self.boundary, vacant_boundary())),
                completed: std::mem::take(&mut self.completed),
                pending: self.pending.take(),
                last_acknowledged: self.last_acknowledged.take(),
                unresolved: self.unresolved.take(),
                unresolved_capture: self.unresolved_capture.take(),
            };
            slot.retain(custody);
        }
    }
}

pub(crate) fn connect(
    custody: &ArmRootNativeCustody,
    restored: bool,
) -> Result<UnixStream, ProviderError> {
    let deadline = HostBudget::after(custody.launch.timeout)?;
    let listener = custody
        .listener
        .as_ref()
        .ok_or(ProviderError::Frame("ARM private listener omitted"))?;
    loop {
        custody
            .group
            .as_ref()
            .ok_or(ProviderError::Frame("ARM original kernel group omitted"))?
            .require_live()?;
        match listener.accept() {
            Ok((stream, _)) => {
                let credentials =
                    rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
                let group = custody
                    .group
                    .as_ref()
                    .ok_or(ProviderError::Frame("ARM group omitted"))?;
                if credentials.pid.as_raw_nonzero().get() as u32 != group.identity().0
                    || credentials.uid != rustix::process::getuid()
                {
                    return Err(ProviderError::Correlation(
                        "ARM control peer differs from original kernel child",
                    ));
                }
                stream.set_read_timeout(Some(custody.launch.timeout))?;
                stream.set_write_timeout(Some(custody.launch.timeout))?;
                let exe = fs::read_link(format!("/proc/{}/exe", group.identity().0))?;
                let expected_executable = if restored {
                    "mtcp_restart"
                } else {
                    "native_executable"
                };
                if measure_image_file(&exe)?
                    != custody.launch.artifact(expected_executable)?.content
                {
                    return Err(ProviderError::Correlation(
                        "ARM actual native executable differs",
                    ));
                }
                if restored {
                    let mappings = fs::read(format!("/proc/{}/maps", group.identity().0))?;
                    if mappings.len() > 16 * 1024 * 1024 {
                        return Err(ProviderError::ResourceExhausted(
                            "ARM reconstruction map credit",
                        ));
                    }
                    let mappings = std::str::from_utf8(&mappings).map_err(|_| {
                        ProviderError::Frame("ARM reconstruction kernel maps encoding")
                    })?;
                    for role in ["native_executable", "image_guard"] {
                        let required = custody
                            .launch
                            .artifact(role)?
                            .path
                            .to_str()
                            .ok_or(ProviderError::Frame("ARM reconstructed artifact route"))?;
                        if !mappings.lines().any(|row| {
                            let fields: Vec<_> = row.split_whitespace().collect();
                            fields.len() == 6
                                && fields[5] == required
                                && (role == "image_guard" || fields[1].contains('x'))
                        }) {
                            return Err(ProviderError::Correlation(
                                "ARM reconstructed native/helper code omitted",
                            ));
                        }
                    }
                }
                return Ok(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if deadline.is_expired() {
                    return Err(ProviderError::Frame("ARM readiness deadline"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn read(custody: &mut ArmRootNativeCustody) -> Result<(Value, Vec<u8>), ProviderError> {
    read_with_deadline(custody, deadline(custody.launch.timeout)?)
}

pub(crate) fn read_with_deadline(
    custody: &mut ArmRootNativeCustody,
    // crucible-lint: allow host-nondeterminism-state -- Frame reads borrow the original opaque transport deadline without changing native or logical time.
    original_deadline: crate::operational_time::OperationalDeadline,
) -> Result<(Value, Vec<u8>), ProviderError> {
    let stream = custody
        .stream
        .as_mut()
        .ok_or(ProviderError::Frame("ARM control session omitted"))?;
    let mut io = NativeDeadlineIo::new(stream, original_deadline);
    let frame = FrameReader::new(&mut io, GEM5_NATIVE_FRAME_BYTES)?
        .read_retained()?
        .ok_or(ProviderError::Frame("ARM native control disconnected"))?;
    Ok((frame.value, frame.bytes))
}

pub(crate) fn selection(launch: &ArmRootLaunch) -> Result<Gem5ModelSelection, ProviderError> {
    let asset = |role: &str, file: &str| -> Result<Box<Gem5ModelAsset>, ProviderError> {
        Ok(Box::new(Gem5ModelAsset {
            file: file.to_owned(),
            content: launch.artifact(role)?.content.clone(),
            sha256: launch.metadata["artifacts"][role]["sha256"]
                .as_str()
                .ok_or(ProviderError::Frame("ARM installed SHA omitted"))?
                .to_owned(),
        }))
    };
    Ok(Gem5ModelSelection::ArmLinuxRoot {
        kernel: asset("kernel", "kernel.elf")?,
        initramfs: asset("initramfs", "initrd.img")?,
        firmware: asset("firmware", "boot_v2.arm64")?,
        configuration: serde_json::from_value(
            launch.metadata["model"]["configuration_tree"].clone(),
        )
        .map_err(|_| ProviderError::Frame("ARM configuration binding"))?,
    })
}

fn stage(launch: &ArmRootLaunch) -> Result<Value, ProviderError> {
    for (role, file) in [
        ("controller", "native-controller.py"),
        ("entrypoint", "native-controller-arm-root.py"),
        ("model", "native-controller-arm-root-model.py"),
        ("board_model", "native-controller-arm-model.py"),
        ("publication_model", "native-controller-models.py"),
        ("asset_checker", "native-model-assets.py"),
        ("auditor", "full-system-process-image-audit.py"),
        ("auditor_core", "process-image-audit-core.py"),
        ("kernel", "kernel.elf"),
        ("initramfs", "initrd.img"),
        ("firmware", "boot_v2.arm64"),
    ] {
        copy(launch.artifact(role)?, &launch.resource_root.join(file))?;
    }
    let config = launch.metadata["configuration_root"]
        .as_str()
        .ok_or(ProviderError::Frame(
            "ARM installed configuration root omitted",
        ))?;
    copy_configuration(
        Path::new(config),
        &launch.resource_root.join("configs"),
        0,
        &mut (0, 0),
    )?;
    let mut assets = BTreeMap::new();
    for (role, file) in [
        ("kernel", "kernel.elf"),
        ("initramfs", "initrd.img"),
        ("firmware", "boot_v2.arm64"),
    ] {
        assets.insert(
            role,
            json!({"file":file,"bytes":launch.metadata["artifacts"][role]["length"],
            "sha256":launch.metadata["artifacts"][role]["sha256"]}),
        );
    }
    Ok(
        json!({"schema":"crucible.gem5.arm-linux-root-model.v1","assets":assets,
        "configs":launch.metadata["model"]["configuration_tree"]}),
    )
}

fn copy(artifact: &super::Gem5LaunchArtifact, target: &Path) -> Result<(), ProviderError> {
    if measure_image_file(&artifact.path)? != artifact.content {
        return Err(ProviderError::Correlation(
            "ARM staged source artifact changed",
        ));
    }
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&artifact.path)?;
    let mut target_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(target)?;
    std::io::copy(
        &mut source.by_ref().take(artifact.content.length.get() + 1),
        &mut target_file,
    )?;
    target_file.sync_all()?;
    if measure_image_file(target)? != artifact.content {
        return Err(ProviderError::Correlation(
            "ARM private staged artifact differs",
        ));
    }
    Ok(())
}

fn copy_configuration(
    source: &Path,
    target: &Path,
    depth: usize,
    credit: &mut (usize, u64),
) -> Result<(), ProviderError> {
    if depth > 32 {
        return Err(ProviderError::ResourceExhausted("ARM configuration depth"));
    }
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_dir() || metadata.mode() & 0o222 != 0 {
        return Err(ProviderError::Correlation(
            "ARM installed configuration directory changed",
        ));
    }
    fs::create_dir(target)?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            copy_configuration(
                &entry.path(),
                &target.join(entry.file_name()),
                depth + 1,
                credit,
            )?;
        } else {
            if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o222 != 0 {
                return Err(ProviderError::Correlation(
                    "ARM configuration leaf has aliases",
                ));
            }
            credit.0 = credit
                .0
                .checked_add(1)
                .ok_or(ProviderError::ResourceExhausted("ARM configuration count"))?;
            credit.1 = credit
                .1
                .checked_add(metadata.len())
                .ok_or(ProviderError::ResourceExhausted("ARM configuration bytes"))?;
            if credit.0 > 4096 || credit.1 > 64 * 1024 * 1024 {
                return Err(ProviderError::ResourceExhausted("ARM configuration census"));
            }
            let artifact = super::Gem5LaunchArtifact {
                path: entry.path(),
                content: measure_file(&entry.path())?,
            };
            copy(&artifact, &target.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn vacant_boundary() -> Gem5Boundary {
    Gem5Boundary {
        tick: 0.into(),
        logical_position: crucible_node_contract::Position::new(
            0.into(),
            0.into(),
            crucible_node_contract::Phase::BoundaryControl,
        ),
        ordinal: 0.into(),
        tick_ordinal: 0.into(),
        has_next_event: false,
        next_tick: 0.into(),
        next_priority: 0,
        inventory: Value::Null,
    }
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- invalid test fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- fixture construction and counterexample assertions are test-only.
#[allow(clippy::unwrap_used)]
mod construction_tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    #[test]
    fn capture_frame_pair_is_reserved_before_any_partial_effect() {
        let mut frames = vec![Vec::new(); 1023];
        assert!(reserve_frame_storage(&mut frames, 2).is_err());
        assert_eq!(frames.len(), 1023);
        reserve_frame_storage(&mut frames, 1).unwrap();
        assert_eq!(frames.len(), 1023);
        frames.push(Vec::new());
        assert!(reserve_frame_storage(&mut frames, 1).is_err());
        assert!(reserve_frame_storage(&mut frames, usize::MAX).is_err());
    }

    struct Slot(Arc<Mutex<Vec<ArmRootNativeCustody>>>);

    impl ArmRootCustodySlot for Slot {
        fn retain(self: Box<Self>, custody: ArmRootNativeCustody) {
            self.0.lock().unwrap().push(custody);
        }
    }

    #[test]
    fn constructor_unwind_retains_actual_child_and_original_journal() {
        let capsules = Arc::new(Mutex::new(Vec::with_capacity(1)));
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "no-such-construction-test"])
            .process_group(0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let actual_pid = child.id();
        let artifact = super::super::Gem5LaunchArtifact {
            path: PathBuf::from("/inert-test/native"),
            content: canonical::content_ref(b"test", "application/octet-stream").unwrap(),
        };
        let launch = ArmRootLaunch {
            owner: Id::new("original").unwrap(),
            incarnation: Id::new("incarnation").unwrap(),
            generation: 1.into(),
            resource_root: "/inert-test/resources".into(),
            timeout: Duration::from_secs(10),
            tools: super::super::Gem5ProcessImageTools {
                launcher: artifact.clone(),
                restarter: artifact.clone(),
                reconstruction_executable: artifact.clone(),
                resource_helper: artifact.clone(),
                image_root: "/inert-test/images".into(),
                temporary_root: "/inert-test/tmp".into(),
            },
            artifacts: BTreeMap::new(),
            profile: artifact.content,
            metadata: json!({}),
        };
        let mut host_ledger = ArmRootHostLedger::reserve();
        host_ledger.unresolved_capture = Some(Id::new("original-capture").unwrap());
        host_ledger.unresolved = Some(json!({"kind":"original-bootstrap","owner":"original"}));
        let custody = ArmRootNativeCustody {
            group: None,
            unenrolled: Some(child),
            launch,
            stream: None,
            listener: None,
            received_ready: Some(b"original-ready".to_vec()),
            control_frames: vec![b"original-frame".to_vec()],
            history: crate::gem5::ArmRootControlHistory::empty(),
            audit_workers: Vec::new(),
            unenrolled_helpers: Vec::new(),
            host_ledger,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _construction = ArmRootConstruction::new(custody, Box::new(Slot(capsules.clone())));
            panic!("forced construction unwind after actual child creation");
        }));
        assert!(result.is_err());
        let mut capsules = capsules.lock().unwrap();
        assert_eq!(capsules.len(), 1);
        let capsule = &mut capsules[0];
        assert_eq!(capsule.unenrolled.as_ref().unwrap().id(), actual_pid);
        assert_eq!(
            capsule.received_ready.as_deref(),
            Some(b"original-ready".as_slice())
        );
        assert_eq!(capsule.control_frames, vec![b"original-frame".to_vec()]);
        assert_eq!(
            capsule.host_ledger.unresolved_capture,
            Some(Id::new("original-capture").unwrap())
        );
        assert_eq!(
            capsule.host_ledger.unresolved,
            Some(json!({"kind":"original-bootstrap","owner":"original"}))
        );
        capsule.begin_quarantine().unwrap();
        while !capsule.poll_reclamation().unwrap() {
            std::thread::yield_now();
        }
        assert!(capsule.poll_reclamation().unwrap());
    }
}
