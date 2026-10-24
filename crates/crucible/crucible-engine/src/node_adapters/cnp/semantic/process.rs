//! Pre-reserved actual generic provider process and original control custody.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::rc::Rc;

use crucible_node_format::{ContentRef, U64};
use crucible_node_transport::{
    ProviderError,
    client::CnpController,
    handshake::{ExtensionHandshake, Handshake},
};
use rustix::process::{Pid, Signal, getpgid, kill_process_group};

#[path = "process/current.rs"]
mod current;
pub use current::CnpSemanticSourceRead;
pub(in crate::node_adapters::cnp::semantic) use current::OriginalFreshQueryReadCall;
pub(super) use current::ReadCall;
pub(in crate::node_adapters::cnp::semantic) use executable_guard::FreshCurrentScratch;

mod complete_registry;
mod executable_guard;
mod original_child;
mod precredit_storage;
mod retained_storage;

mod reservation;
pub use reservation::{CnpSemanticLaunchReservation, CnpSemanticReservationFailure};

/// Reserves independent native and original journal custody before process creation.
///
/// Implementations belong to the trusted host supervisor. Their reserved slot
/// must remain alive independently of runtime borrowers and retain this entire
/// capsule on transport failure, unwind, quarantine or caller drop.
pub trait CnpSemanticProcessSlot {
    /// Counts actual descriptors retained by this same concrete slot as data.
    ///
    /// Unknown erased backing returns None. Implementations perform no I/O,
    /// formatting, descriptor duplication or currentness callback.
    ///
    /// # Errors
    /// Refuses foreign, busy or unsupported original ownership as a raw enum.
    fn retained_descriptor_views_precredit_data(
        &self,
    ) -> Result<Option<usize>, crate::node_contract::RuntimeError> {
        Ok(None)
    }

    /// Identifies the actual finite reservation without granting native authority.
    ///
    /// The pre-Child reservation reads this callback before spawning. Its result
    /// is cached; later guard identity reads do not invoke installed callbacks.
    fn identity(&self) -> U64;

    /// Observes actual nested backing before allocation credit, using raw failures.
    ///
    /// Implementations walk the same concrete owner without heap allocation,
    /// formatting, serialization, I/O, or currentness callbacks. The caller
    /// separately charges the actual outer allocation and observer scratch.
    /// `None` retains an unknown owner. This default never calls the legacy
    /// allocating-error observer and grants no native or allocation authority.
    ///
    /// # Errors
    /// Returns a typed origin, busy-loan, unsupported-layout or checked-bound
    /// refusal without constructing an owned diagnostic.
    fn retained_requested_storage_precredit_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, crate::node_contract::RuntimeError> {
        Ok(None)
    }

    /// Observes actual backing heaps of the same concrete supervision slot.
    ///
    /// The caller counts this slot's actual Box inline layout separately. A
    /// supported implementation walks its retained original typed owners and
    /// charges shared backing conservatively per view; it performs no retention,
    /// native operation, Cell extraction, source callback or ownership transfer.
    /// None identifies missing backing observation, never a zero-byte owner.
    /// This data-only result confers no supervision or reclamation permission.
    ///
    /// # Errors
    /// Refuses an unsupported mutable/returned phase, changed original owner or
    /// requested storage above maximum. The default reports unknown ownership.
    fn retained_requested_storage_data(
        &self,
        _maximum: usize,
    ) -> Result<Option<usize>, crate::node_contract::OperationFailure> {
        Ok(None)
    }

    /// Retains the original process and complete immutable request/content journals.
    ///
    /// The trusted supervisor preallocates this mailbox before Child and must
    /// accept the whole incoming capsule without unwinding or losing its owners.
    fn retain(&mut self, custody: CnpSemanticProcessCustody);
}

/// Retains actual generic provider resources without a checksum companion assumption.
///
/// This holder is neither serializable nor reconstructible from wire fields.
/// Reaping the original Child and observing its empty private group are required
/// before the supervisor may discharge its actual native obligations.
pub struct CnpSemanticProcessCustody {
    creator_process: u32,
    child: Option<Child>,
    original_child: Option<original_child::OriginalChild>,
    provider_pid: u32,
    pub(super) directory: PathBuf,
    pub(super) controller: Option<CnpController>,
    pub(super) protocol_supervisor:
        std::cell::RefCell<Option<crucible_node_transport::connection::OriginalProtocolSupervisor>>,
    pub(super) handshake: Option<Handshake>,
    pub(super) extension_handshake: Option<ExtensionHandshake>,
    pub(super) expected_executable: ContentRef,
    pub(super) installation_kind: Option<super::registry::SemanticInstallationKind>,
    pub(super) registration: Option<Rc<dyn super::CnpSemanticRegistrationPolicy>>,
    pub(super) installed_identity: Option<crucible_node_format::HashRef>,
    pub(super) source: Option<Rc<dyn super::CnpSemanticSource>>,
    pub(super) acceptance: Option<Rc<dyn super::CnpSemanticAcceptance>>,
    pub(super) conformance: Option<Rc<dyn super::CnpSemanticConformanceAuthority>>,
    pub(super) collection_plan: Option<crate::node_admission::InstalledConformancePlan>,
    pub(super) runtime: Option<super::state::SemanticRuntimeCustody>,
    pub(super) completed_ack_protocol_started: bool,
    pub(super) completed_ack_admission: std::cell::RefCell<
        Option<super::packet_complete_source::OriginalCompletedCanonicalAckWorldAdmission>,
    >,
    rejected_control: Option<(CnpController, Handshake)>,
    group: Option<Pid>,
    killed: bool,
    reaped: Option<ExitStatus>,
    pub(super) read_owner: Rc<current::ReadOwner>,
    kernel_identity: Option<current::KernelIdentity>,
    executable_guard: Option<Rc<executable_guard::OriginalExecutable>>,
}

impl CnpSemanticProcessCustody {
    fn has_original_child(&self) -> bool {
        self.child.is_some() || self.original_child.is_some()
    }

    fn try_wait_original_child(&mut self) -> Result<Option<ExitStatus>, ProviderError> {
        self.ensure_origin()?;
        match (&mut self.child, &mut self.original_child) {
            (Some(child), None) => child.try_wait().map_err(ProviderError::from),
            (None, Some(child)) => child.try_wait(),
            _ => Err(ProviderError::Correlation(
                "generic original child custody is absent or conflicting",
            )),
        }
    }

    pub(super) fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator_process != std::process::id() {
            return Err(ProviderError::Correlation(
                "generic original custody belongs to another process",
            ));
        }
        Ok(())
    }

    pub(super) fn retain_original_complete_protocol_supervisor(&self) -> Result<(), ProviderError> {
        self.authenticate_process()?;
        let call = ReadCall::begin(Rc::clone(&self.read_owner))?;
        let result = (|| {
            let controller = self.controller.as_ref().ok_or(ProviderError::Correlation(
                "original supervisor controller absent",
            ))?;
            let mut witness = self
                .protocol_supervisor
                .try_borrow_mut()
                .map_err(|_| ProviderError::Conflict("original supervisor witness borrowed"))?;
            if witness.is_none() {
                *witness = Some(controller.retain_original_protocol_supervisor()?);
            }
            controller.original_owned11_metadata_facts_with_supervisor(witness.as_ref().ok_or(
                ProviderError::Correlation("original supervisor witness absent"),
            )?)?;
            Ok(())
        })();
        call.finish(result.is_ok());
        result
    }

    /// Returns the original actual provider Child ID for native diagnostics.
    pub fn provider_pid(&self) -> u32 {
        self.provider_pid
    }

    /// Borrows the original private operational directory.
    pub fn private_directory(&self) -> &Path {
        &self.directory
    }

    /// Borrows retained original control and content custody when attached.
    pub fn controller(&self) -> Option<&CnpController> {
        self.controller.as_ref()
    }

    /// Checks current actual native process identity independently of its JSON claims.
    ///
    /// This authenticates process resources only. Source code separately proves
    /// the selected model, closed gate, receipt semantics and role capabilities.
    ///
    /// # Errors
    /// Refuses a foreign creator process before inherited state access, then a
    /// dead or changed Child, foreign process group, expired attached
    /// session or different measured actual executable.
    pub fn authenticate_process(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if let Some(child) = &self.original_child {
            child.ensure_unreaped()?;
        }
        let executable = self
            .executable_guard
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "generic original executable guard absent",
            ))?;
        executable.ensure_origin()?;
        let identity = self
            .kernel_identity
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "generic original kernel identity absent",
            ))?;
        executable.ensure_current(identity)?;

        let directory = fs::symlink_metadata(&self.directory)?;
        if !directory.is_dir()
            || directory.mode() & 0o777 != 0o700
            || directory.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(ProviderError::Correlation(
                "generic native directory is not current private custody",
            ));
        }
        if self.killed || self.reaped.is_some() {
            return Err(ProviderError::Correlation(
                "generic native process is contained",
            ));
        }
        let group = self.group.ok_or(ProviderError::Correlation(
            "generic native group unavailable",
        ))?;
        if getpgid(Some(group)).map_err(std::io::Error::from)? != group {
            return Err(ProviderError::Correlation("generic native process changed"));
        }
        if let Some(controller) = &self.controller {
            controller.authority().ensure_live()?;
            if controller.peer_pid() != self.provider_pid
                || controller.peer_executable() != &self.expected_executable
            {
                return Err(ProviderError::Correlation("generic control peer changed"));
            }
        }
        executable.ensure_current(identity)
    }

    /// Reads actual completed child reaping and the unchanged empty original group.
    ///
    /// This checks only kernel process resources. The installed source separately
    /// authenticates complete native device/handle and semantic obligation release.
    ///
    /// # Errors
    /// Refuses foreign creator processes, malformed or overwide current kernel
    /// census; absence is not assumed.
    pub fn kernel_resources_reclaimed(&self) -> Result<bool, ProviderError> {
        self.ensure_origin()?;
        Ok(self.reaped.is_some() && group_empty(self.provider_pid)?)
    }

    /// Requests containment and polls actual original reaping and empty-group proof.
    ///
    /// Signals are issued only while the actual Child remains unreaped; a later
    /// numeric PID reuse cannot authorize another kill. Native census failures
    /// retain the same whole capsule and do not imply successful cleanup.
    ///
    /// # Errors
    /// Refuses foreign creator processes before inherited state or signaling.
    /// Retains custody on foreign group, signaling/wait failure or malformed or
    /// overwide kernel census. Returns false while actual cleanup is outstanding.
    pub fn poll_reclamation(&mut self) -> Result<bool, ProviderError> {
        self.ensure_origin()?;
        self.read_owner.revoke();
        if let Some(handshake) = &mut self.handshake {
            handshake.contain();
        }
        if let Some(handshake) = &mut self.extension_handshake {
            handshake.contain();
        }
        if let Some(controller) = &mut self.controller {
            controller.fence();
        }
        if let Some((controller, handshake)) = &mut self.rejected_control {
            controller.fence();
            handshake.contain();
        }
        if self.reaped.is_none() {
            self.reaped = self.try_wait_original_child()?;
        }
        if self.reaped.is_some() {
            return group_empty(self.provider_pid);
        }
        if !self.killed {
            let group = self.group.ok_or(ProviderError::Correlation(
                "generic native group unavailable",
            ))?;
            if getpgid(Some(group)).map_err(std::io::Error::from)? != group {
                return Err(ProviderError::Correlation(
                    "generic process escaped its group",
                ));
            }
            kill_process_group(group, Signal::KILL).map_err(std::io::Error::from)?;
            self.killed = true;
        }
        self.reaped = self.try_wait_original_child()?;
        Ok(self.reaped.is_some() && group_empty(self.provider_pid)?)
    }
}

impl Drop for CnpSemanticProcessCustody {
    fn drop(&mut self) {
        if self.creator_process == std::process::id() {
            return;
        }
        // A foreign copy cannot close/fence shared sockets, invoke installed
        // policy destructors, or discharge the parent's actual Child. Only the
        // duplicate allocations are retained until that foreign process exits.
        std::mem::forget(self.child.take());
        std::mem::forget(self.original_child.take());
        std::mem::forget(self.controller.take());
        std::mem::forget(self.protocol_supervisor.get_mut().take());
        std::mem::forget(self.handshake.take());
        std::mem::forget(self.extension_handshake.take());
        std::mem::forget(self.registration.take());
        std::mem::forget(self.source.take());
        std::mem::forget(self.acceptance.take());
        std::mem::forget(self.conformance.take());
        std::mem::forget(self.collection_plan.take());
        std::mem::forget(self.runtime.take());
        std::mem::forget(self.completed_ack_admission.get_mut().take());
        std::mem::forget(self.rejected_control.take());
        std::mem::forget(self.executable_guard.take());
    }
}

/// Owns pre-reserved generic CNP process custody throughout failed preparation.
#[must_use = "retain original native custody until actual supervised reclamation"]
pub struct CnpSemanticLaunchGuard {
    creator_process: u32,
    pub(super) custody: Option<Box<CnpSemanticProcessCustody>>,
    slot: Option<Box<dyn CnpSemanticProcessSlot>>,
    supervision_id: U64,
}

/// Preserves original actual native resources on launch validation failure.
pub struct CnpSemanticLaunchFailure {
    /// Describes the failure without claiming native reclamation.
    pub error: ProviderError,
    /// Retains actual original Child and independent finite supervisor slot.
    pub guard: CnpSemanticLaunchGuard,
}

impl CnpSemanticLaunchGuard {
    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator_process != std::process::id() {
            return Err(ProviderError::Correlation(
                "generic original launch guard belongs to another process",
            ));
        }
        Ok(())
    }

    /// Takes an actual newly launched private process into its pre-reserved slot.
    ///
    /// The launcher must reserve `slot` before spawning and use a private process
    /// group. Independently installed executable bytes are checked against the
    /// actual Child before any discovery or realization may proceed.
    ///
    /// # Errors
    /// Returns complete guarded custody on foreign native group, changed actual
    /// executable, invalid Child identity or unavailable kernel evidence.
    ///
    /// # Panics
    /// An installed identity callback may unwind. The guard already owns Child
    /// and transfers it to the original infallible supervisor mailbox on unwind.
    /// Callers requiring pre-Child allocation use [`CnpSemanticLaunchReservation`].
    pub fn new(
        child: Child,
        directory: PathBuf,
        executable: ContentRef,
        slot: Box<dyn CnpSemanticProcessSlot>,
    ) -> Result<Self, CnpSemanticLaunchFailure> {
        let provider_pid = child.id();
        let group = i32::try_from(provider_pid).ok().and_then(Pid::from_raw);
        let creator_process = std::process::id();
        let mut guard = Self {
            creator_process,
            custody: Some(Box::new(CnpSemanticProcessCustody {
                creator_process,
                child: Some(child),
                original_child: None,
                provider_pid,
                directory,
                controller: None,
                protocol_supervisor: std::cell::RefCell::new(None),
                handshake: None,
                extension_handshake: None,
                expected_executable: executable,
                installation_kind: None,
                registration: None,
                installed_identity: None,
                source: None,
                acceptance: None,
                conformance: None,
                collection_plan: None,
                runtime: None,
                completed_ack_protocol_started: false,
                completed_ack_admission: std::cell::RefCell::new(None),
                rejected_control: None,
                group,
                killed: false,
                reaped: None,
                read_owner: Rc::new(current::ReadOwner::new(U64::new(0))),
                kernel_identity: None,
                executable_guard: None,
            })),
            slot: Some(slot),
            supervision_id: U64::new(0),
        };
        // The legacy post-spawn API owns Child before its installed identity
        // callback too. No provisional identity can escape an unsealed guard.
        let result = (|| {
            guard.ensure_origin()?;
            let identity = guard
                .slot
                .as_ref()
                .ok_or(ProviderError::Correlation("generic original slot absent"))?
                .identity();
            guard.supervision_id = identity;
            let custody = guard
                .custody
                .as_mut()
                .ok_or(ProviderError::Correlation("generic custody transferred"))?;
            Rc::get_mut(&mut custody.read_owner)
                .ok_or(ProviderError::Correlation(
                    "generic owner issued before launch seal",
                ))?
                .set_initial_identity(identity);
            let identity = current::KernelIdentity::capture(custody.provider_pid)?;
            custody.kernel_identity = Some(identity);
            custody.executable_guard = Some(Rc::new(executable_guard::OriginalExecutable::open(
                custody.provider_pid,
                &custody.expected_executable,
                &identity,
            )?));
            custody.authenticate_process()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(guard),
            Err(error) => Err(CnpSemanticLaunchFailure { error, guard }),
        }
    }

    /// Attaches only the original generic controller and its live host registrar.
    ///
    /// # Errors
    /// Refuses duplicate attachment, another native Child or executable, fenced
    /// registration or unavailable original custody.
    pub fn attach(
        mut self,
        controller: CnpController,
        handshake: Handshake,
    ) -> Result<Self, CnpSemanticAttachmentFailure> {
        let result = self.attach_preflight(&controller, &handshake);
        if let Err(error) = result {
            if let Some(custody) = self.custody.as_mut() {
                custody.rejected_control = Some((controller, handshake));
            }
            return Err(CnpSemanticAttachmentFailure { error, guard: self });
        }
        let Some(custody) = self.custody.as_mut() else {
            return Err(CnpSemanticAttachmentFailure {
                error: ProviderError::Correlation("generic custody transferred"),
                guard: self,
            });
        };
        custody.handshake = Some(handshake);
        custody.controller = Some(controller);
        Ok(self)
    }

    fn attach_preflight(
        &self,
        controller: &CnpController,
        handshake: &Handshake,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        let custody = self
            .custody
            .as_ref()
            .ok_or(ProviderError::Correlation("generic custody transferred"))?;
        custody.authenticate_process()?;
        handshake.validate_registration(controller.authority())?;
        if custody.controller.is_some()
            || custody.extension_handshake.is_some()
            || controller.peer_pid() != custody.provider_pid()
            || controller.peer_executable() != &custody.expected_executable
        {
            return Err(ProviderError::Correlation(
                "generic controller is not original Child",
            ));
        }
        Ok(())
    }

    /// Attaches the same original controller under its surviving typed Hello.
    ///
    /// The caller retains both owning input slots outside its failure/unwind
    /// boundary. Validation borrows them before transfer; every refusal leaves
    /// their original controller, registration, typed selection and banks in
    /// those slots. Success installs both into this original guarded capsule
    /// without unwrapping or downgrading the typed handshake.
    ///
    /// # Errors
    /// Refuses foreign origin, absent inputs, an already attached or transferred
    /// capsule, changed actual Child/executable, revoked registration or another
    /// original typed handshake. No input owner moves on refusal.
    pub fn attach_extensions_owned(
        &mut self,
        controller: &mut Option<CnpController>,
        handshake: &mut Option<ExtensionHandshake>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        let original_controller = controller.as_ref().ok_or(ProviderError::Correlation(
            "generic typed attachment controller absent",
        ))?;
        let original_handshake = handshake.as_ref().ok_or(ProviderError::Correlation(
            "generic typed attachment handshake absent",
        ))?;
        let custody = self.custody.as_ref().ok_or(ProviderError::Correlation(
            "generic typed attachment custody transferred",
        ))?;
        custody.authenticate_process()?;
        original_handshake.verify_authority(original_controller.authority())?;
        if custody.controller.is_some()
            || custody.handshake.is_some()
            || custody.extension_handshake.is_some()
            || original_controller.peer_pid() != custody.provider_pid()
            || original_controller.peer_executable() != &custody.expected_executable
        {
            return Err(ProviderError::Correlation(
                "generic typed attachment is repeated or not original Child",
            ));
        }
        // This immutable SDK read also authenticates its actual protocol owner
        // before transfer. Matching registration labels alone are insufficient.
        original_controller.original_registrar_read_extensions(original_handshake)?;

        let custody = self.custody.as_mut().ok_or(ProviderError::Correlation(
            "generic typed attachment custody transferred",
        ))?;
        match (controller.take(), handshake.take()) {
            (Some(original_controller), Some(original_handshake)) => {
                custody.controller = Some(original_controller);
                custody.extension_handshake = Some(original_handshake);
                Ok(())
            }
            (original_controller, original_handshake) => {
                *controller = original_controller;
                *handshake = original_handshake;
                Err(ProviderError::Correlation(
                    "generic typed attachment original input slots changed",
                ))
            }
        }
    }

    /// Borrows actual original native custody for installed independent source oracles.
    ///
    /// # Errors
    /// Refuses a foreign creator process or unavailable or transferred custody.
    pub fn custody(&self) -> Result<&CnpSemanticProcessCustody, ProviderError> {
        self.ensure_origin()?;
        self.custody
            .as_deref()
            .filter(|custody| custody.has_original_child())
            .ok_or(ProviderError::Correlation(
                "generic custody unavailable or not launched",
            ))
    }

    /// Transfers actual original native custody while retaining this guard shell.
    ///
    /// The original reserved supervisor receives the same complete native and
    /// transport journals. No resource replacement or reclamation is implied.
    /// A copied foreign-process guard detaches its duplicate allocations before
    /// any supervisor callback; the original process retains its native owners.
    ///
    /// # Panics
    /// The trusted preallocated slot must retain without unwinding. Violation
    /// of that supervisor contract is outside callback containment, as on Drop.
    pub fn retire_original(&mut self) {
        if self.creator_process != std::process::id() {
            // These allocations are inherited copies. The original process
            // still owns its reservation and native resources; copied trait
            // callbacks and destructors must not enter its SDK or supervisor.
            std::mem::forget(self.custody.take());
            std::mem::forget(self.slot.take());
            return;
        }
        if let Some(custody) = self.custody.take() {
            custody.read_owner.revoke();
            if custody.has_original_child() {
                if let Some(slot) = self.slot.as_mut() {
                    slot.retain(*custody);
                } else {
                    // A missing private reservation cannot discharge Child.
                    std::mem::forget(custody);
                }
            }
        }
    }

    /// Returns the original host-issued finite reservation identity.
    pub fn supervision_id(&self) -> U64 {
        self.supervision_id
    }
}

impl Drop for CnpSemanticLaunchGuard {
    fn drop(&mut self) {
        self.retire_original();
    }
}

fn group_empty(group: u32) -> Result<bool, ProviderError> {
    let mut count = 0usize;
    for entry in fs::read_dir("/proc")? {
        count += 1;
        if count > 100_000 {
            return Err(ProviderError::ResourceExhausted("generic native census"));
        }
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .is_none()
        {
            continue;
        }
        let file = match File::open(entry.path().join("stat")) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(65_537).read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err(ProviderError::ResourceExhausted(
                "generic kernel census row",
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ProviderError::Frame("generic kernel census encoding"))?;
        let close = text
            .rfind(')')
            .ok_or(ProviderError::Frame("generic kernel census shape"))?;
        let actual = text[close + 1..]
            .split_ascii_whitespace()
            .nth(2)
            .ok_or(ProviderError::Frame("generic kernel group absent"))?
            .parse::<u32>()
            .map_err(|_| ProviderError::Frame("generic kernel group invalid"))?;
        if actual == group {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Retains complete original control journals when native attachment refuses.
#[must_use = "retain rejected original control custody with its actual native owner"]
pub struct CnpSemanticAttachmentFailure {
    /// Describes the current native/registration mismatch without releasing resources.
    pub error: ProviderError,
    /// Retains native resources and both accepted and rejected original journals.
    ///
    /// The holder has no recovery constructor. Dropping this failure transfers
    /// the whole capsule to its already reserved supervisor, including rejected
    /// transport/registrar custody, rather than discarding those originals.
    guard: CnpSemanticLaunchGuard,
}

impl CnpSemanticAttachmentFailure {
    /// Transfers the same rejected native custody while retaining its original error.
    ///
    /// # Panics
    /// The original trusted supervisor must retain without unwinding or dropping
    /// incoming custody; violation remains outside this guard's containment.
    pub fn retire_original(&mut self) {
        self.guard.retire_original();
    }

    /// Borrows the complete original native capsule without permitting reattachment.
    ///
    /// # Errors
    /// Refuses unavailable or already transferred native custody.
    pub fn custody(&self) -> Result<&CnpSemanticProcessCustody, ProviderError> {
        self.guard.custody()
    }
}

#[path = "process/host_startup.rs"]
mod host_startup;
pub(in crate::node_adapters::cnp::semantic) use host_startup::OriginalHostLaunchIdentity;

#[path = "process/initial_lifecycle_storage.rs"]
mod initial_lifecycle_storage;
pub(in crate::node_adapters::cnp::semantic) use host_startup::OriginalHostInitialLifecycleGuardIdentity;

#[path = "process/metadata_origin17.rs"]
mod metadata_origin17;
