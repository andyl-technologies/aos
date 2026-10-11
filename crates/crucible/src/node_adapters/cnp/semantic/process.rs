//! Pre-reserved actual generic provider process and original control custody.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::rc::Rc;

use crucible_node_contract::{ContentRef, U64};
use crucible_node_provider::{
    ProviderError, client::CnpController, conformance::measure_executable, handshake::Handshake,
};
use rustix::process::{Pid, Signal, getpgid, kill_process_group};

#[path = "process/current.rs"]
mod current;
pub use current::CnpSemanticSourceRead;
pub(super) use current::ReadCall;

mod reservation;
pub use reservation::{CnpSemanticLaunchReservation, CnpSemanticReservationFailure};

/// Reserves independent native and original journal custody before process creation.
///
/// Implementations belong to the trusted host supervisor. Their reserved slot
/// must remain alive independently of runtime borrowers and retain this entire
/// capsule on transport failure, unwind, quarantine or caller drop.
pub trait CnpSemanticProcessSlot {
    /// Identifies the actual finite reservation without granting native authority.
    ///
    /// The pre-Child reservation reads this callback before spawning. Its result
    /// is cached; later guard identity reads do not invoke installed callbacks.
    fn identity(&self) -> U64;

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
    pub(super) child: Option<Child>,
    provider_pid: u32,
    pub(super) directory: PathBuf,
    pub(super) controller: Option<CnpController>,
    pub(super) handshake: Option<Handshake>,
    pub(super) expected_executable: ContentRef,
    pub(super) registration: Option<Rc<dyn super::CnpSemanticRegistrationPolicy>>,
    pub(super) installed_identity: Option<crucible_node_contract::HashRef>,
    pub(super) source: Option<Rc<dyn super::CnpSemanticSource>>,
    pub(super) acceptance: Option<Rc<dyn super::CnpSemanticAcceptance>>,
    pub(super) conformance: Option<Rc<dyn super::CnpSemanticConformanceAuthority>>,
    pub(super) collection_plan: Option<crate::node_admission::InstalledConformancePlan>,
    pub(super) runtime: Option<super::state::SemanticRuntimeCustody>,
    rejected_control: Option<(CnpController, Handshake)>,
    group: Option<Pid>,
    killed: bool,
    reaped: Option<ExitStatus>,
    pub(super) read_owner: Rc<current::ReadOwner>,
    kernel_identity: Option<current::KernelIdentity>,
}

impl CnpSemanticProcessCustody {
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
    /// Refuses a dead or changed Child, foreign process group, expired attached
    /// session or different measured actual executable.
    pub fn authenticate_process(&self) -> Result<(), ProviderError> {
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
        if let Some(identity) = &self.kernel_identity {
            identity.ensure_current()?;
        }
        let group = self.group.ok_or(ProviderError::Correlation(
            "generic native group unavailable",
        ))?;
        if getpgid(Some(group)).map_err(std::io::Error::from)? != group
            || measure_executable(Path::new(&format!("/proc/{}/exe", self.provider_pid)))?
                != self.expected_executable
        {
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
        Ok(())
    }

    /// Reads actual completed child reaping and the unchanged empty original group.
    ///
    /// This checks only kernel process resources. The installed source separately
    /// authenticates complete native device/handle and semantic obligation release.
    ///
    /// # Errors
    /// Refuses malformed or overwide current kernel census; absence is not assumed.
    pub fn kernel_resources_reclaimed(&self) -> Result<bool, ProviderError> {
        Ok(self.reaped.is_some() && group_empty(self.provider_pid)?)
    }

    /// Requests containment and polls actual original reaping and empty-group proof.
    ///
    /// Signals are issued only while the actual Child remains unreaped; a later
    /// numeric PID reuse cannot authorize another kill. Native census failures
    /// retain the same whole capsule and do not imply successful cleanup.
    ///
    /// # Errors
    /// Retains custody on foreign group, signaling/wait failure or malformed or
    /// overwide kernel census. Returns false while actual cleanup is outstanding.
    pub fn poll_reclamation(&mut self) -> Result<bool, ProviderError> {
        self.read_owner.revoke();
        if let Some(handshake) = &mut self.handshake {
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
            self.reaped = self
                .child
                .as_mut()
                .ok_or(ProviderError::Correlation("generic original Child absent"))?
                .try_wait()?;
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
        self.reaped = self
            .child
            .as_mut()
            .ok_or(ProviderError::Correlation("generic original Child absent"))?
            .try_wait()?;
        Ok(self.reaped.is_some() && group_empty(self.provider_pid)?)
    }
}

/// Owns pre-reserved generic CNP process custody throughout failed preparation.
#[must_use = "retain original native custody until actual supervised reclamation"]
pub struct CnpSemanticLaunchGuard {
    pub(super) custody: Option<Box<CnpSemanticProcessCustody>>,
    slot: Box<dyn CnpSemanticProcessSlot>,
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
        let mut guard = Self {
            custody: Some(Box::new(CnpSemanticProcessCustody {
                child: Some(child),
                provider_pid,
                directory,
                controller: None,
                handshake: None,
                expected_executable: executable,
                registration: None,
                installed_identity: None,
                source: None,
                acceptance: None,
                conformance: None,
                collection_plan: None,
                runtime: None,
                rejected_control: None,
                group,
                killed: false,
                reaped: None,
                read_owner: Rc::new(current::ReadOwner::new(U64::new(0))),
                kernel_identity: None,
            })),
            slot,
            supervision_id: U64::new(0),
        };
        // The legacy post-spawn API owns Child before its installed identity
        // callback too. No provisional identity can escape an unsealed guard.
        let result = (|| {
            let identity = guard.slot.identity();
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
            guard.custody()?.authenticate_process()?;
            let identity = current::KernelIdentity::capture(guard.custody()?.provider_pid())?;
            guard
                .custody
                .as_mut()
                .ok_or(ProviderError::Correlation("generic custody transferred"))?
                .kernel_identity = Some(identity);
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
        let custody = self
            .custody
            .as_ref()
            .ok_or(ProviderError::Correlation("generic custody transferred"))?;
        custody.authenticate_process()?;
        handshake.validate_registration(controller.authority())?;
        if custody.controller.is_some()
            || controller.peer_pid() != custody.provider_pid()
            || controller.peer_executable() != &custody.expected_executable
        {
            return Err(ProviderError::Correlation(
                "generic controller is not original Child",
            ));
        }
        Ok(())
    }

    /// Borrows actual original native custody for installed independent source oracles.
    ///
    /// # Errors
    /// Refuses unavailable or already transferred original custody.
    pub fn custody(&self) -> Result<&CnpSemanticProcessCustody, ProviderError> {
        self.custody
            .as_deref()
            .filter(|custody| custody.child.is_some())
            .ok_or(ProviderError::Correlation(
                "generic custody unavailable or not launched",
            ))
    }

    /// Returns the original host-issued finite reservation identity.
    pub fn supervision_id(&self) -> U64 {
        self.supervision_id
    }
}

impl Drop for CnpSemanticLaunchGuard {
    fn drop(&mut self) {
        if let Some(custody) = self.custody.take() {
            custody.read_owner.revoke();
            if custody.child.is_some() {
                self.slot.retain(*custody);
            }
        }
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
    /// Borrows the complete original native capsule without permitting reattachment.
    ///
    /// # Errors
    /// Refuses unavailable or already transferred native custody.
    pub fn custody(&self) -> Result<&CnpSemanticProcessCustody, ProviderError> {
        self.guard.custody()
    }
}
