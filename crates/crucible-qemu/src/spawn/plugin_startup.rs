//! Owns the original Setup operation across the real plugin handshake.
//!
//! Registered ordinary and private launches use the already-admitted world
//! service account. The same process-contract event survives exec under its
//! explicit descriptor role; no pager, later operation or replacement event
//! supplies startup authority. Native Source and complete allocation-peak
//! qualification remain separate from this host custody splice. Registered
//! startup currently refuses before Setup or descriptor effects because the
//! installed native preconstructor profile and receiver are not yet issued.

use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, Read};

use crucible_linux_resource::host_services::{HostServiceError, HostServiceLease};
use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};
use crucible_protocol::plugin_setup_plan::{
    StartupOperation, StartupOperationError, StartupOperationFields,
};

use super::QemuChildProcessContract;

const FDINFO_BYTES: usize = 4096;

/// Retains the real startup operation and its original host-side control loan.
#[derive(Debug)]
pub(crate) struct OriginalPluginStartup {
    // The initialized body and its allocation close before this external loan.
    body: Box<Option<PluginStartupState>>,
    _control: HostServiceLease,
}

#[derive(Debug)]
struct PluginStartupState {
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    workspace: Option<super::OriginalDeviceDigestWorkspace>,
    original: HostOperationGuard,
    record: StartupOperation,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PluginStartupCause {
    #[error("the installed native preconstructor profile is unavailable")]
    InstalledProfileUnavailable,
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    #[error("device workspace issuance refused: {0}")]
    Workspace(#[source] super::DeviceDigestWorkspaceIssueError),
    #[error("original startup host-service admission refused: {0}")]
    Account(#[source] HostServiceError),
    #[error("original startup operation refused: {0}")]
    Original(#[source] HostSupervisionError),
    #[error("original startup cancellation role failed: {0}")]
    Kernel(#[source] io::Error),
    #[error("original startup record refused: {0}")]
    Record(#[source] StartupOperationError),
    #[error("original startup control extent is unrepresentable")]
    Geometry,
}

/// Preserves the initiating startup refusal and an independent original postcut.
#[derive(Debug, thiserror::Error)]
#[error("{source}; original: {original_after:?}")]
pub struct PluginStartupError {
    #[source]
    source: PluginStartupCause,
    original_after: Option<HostSupervisionError>,
    _control: Option<HostServiceLease>,
}

impl OriginalPluginStartup {
    pub(crate) fn prepare(
        supervisor: &HostOperationSupervisor,
        contract: &QemuChildProcessContract,
        registration: &crate::ram_control::RamControlRegistration,
        process_generation: u64,
    ) -> Result<Self, PluginStartupError> {
        let refuse_before = |source| PluginStartupError {
            source,
            original_after: None,
            _control: None,
        };
        // Installer acquisition occurs after native context allocation and
        // module constructors. The current installed tuple has no prior issued
        // namespace purpose, so refuse before this host creates Setup or aliases.
        require_installed_native_profile().map_err(refuse_before)?;

        // These are actual hosted holder/scratch bodies, not a native W floor.
        // The existing supervisor/world must retain its own allocation custody;
        // this loan does not substitute for its transitive Source/control proof.
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<Option<PluginStartupState>>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PluginStartupState>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PluginStartupError>()))
            .and_then(|bytes| bytes.checked_add(HostServiceLease::metadata_bytes() as usize))
            .and_then(|bytes| bytes.checked_add(FDINFO_BYTES + 1))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| refuse_before(PluginStartupCause::Geometry))?;
        let control = registration
            .host_services
            .reserve_resources(0, 1, bytes)
            .map_err(|source| refuse_before(PluginStartupCause::Account(source)))?;
        // The fixed body is admitted and allocated before any startup operation
        // or descriptor effect. Its temporary live state is included above.
        let mut body = Box::new(None);
        let original = match supervisor.begin_control(HostOperationClass::Setup) {
            Ok(original) => original,
            Err(source) => {
                return Err(PluginStartupError {
                    source: PluginStartupCause::Original(source),
                    original_after: None,
                    _control: Some(control),
                });
            }
        };
        let observed = (|| {
            let metadata = rustix::fs::fstat(&contract.cancellation_event)
                .map_err(|source| PluginStartupCause::Kernel(source.into()))?;
            let event_id = event_identity(contract.cancellation_event.as_raw_fd())
                .map_err(PluginStartupCause::Kernel)?;
            // The temporary fdinfo owner is already physically closed. The
            // persistent subscriber has a distinct prepaid FD/control loan.
            let subscriber = registration
                .host_services
                .reserve_resources(
                    0,
                    1,
                    HostOperationGuard::original_setup_cancellation_bytes(),
                )
                .map_err(PluginStartupCause::Account)?;
            let descriptor = rustix::io::fcntl_dupfd_cloexec(
                &contract.cancellation_event,
                super::CHILD_SOURCE_FD_MIN,
            )
            .map_err(|error| PluginStartupCause::Kernel(error.into()))?;
            original
                .retain_original_setup_cancellation(descriptor, subscriber)
                .map_err(PluginStartupCause::Original)?;
            let basis = original
                .serialize_original_setup_basis()
                .map_err(PluginStartupCause::Original)?;
            let mut cap_id = [0; 32];
            cap_id.copy_from_slice(&basis[16..48]);
            let u64_at = |offset: usize| {
                let mut value = [0; 8];
                value.copy_from_slice(&basis[offset..offset + 8]);
                u64::from_be_bytes(value)
            };
            let record = StartupOperation::new(StartupOperationFields {
                cap_id,
                operation_id: u64_at(48),
                original_start_ns: u64_at(56),
                absolute_end_ns: u64_at(64),
                poll_ns: u64_at(72),
                process_generation,
                original_total_metadata_bytes: registration.resources.metadata_bytes,
                cancellation_device: metadata.st_dev,
                cancellation_inode: metadata.st_ino,
                cancellation_event_id: event_id,
                cancellation_descriptor: super::QEMU_STARTUP_CANCELLATION_FD,
            })
            .map_err(PluginStartupCause::Record)?;
            original
                .check_original_setup_cancellation()
                .map_err(PluginStartupCause::Original)?;
            Ok(record)
        })();
        // This raw cut remains independent even when an earlier kernel step
        // refused before a subscription could be published.
        let after = original.wait_slice().err();
        match (observed, after) {
            (Ok(record), None) => {
                *body = Some(PluginStartupState {
                    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
                    workspace: None,
                    original,
                    record,
                });
                Ok(Self {
                    body,
                    _control: control,
                })
            }
            (Ok(_), Some(source)) => Err(PluginStartupError {
                source: PluginStartupCause::Original(source),
                original_after: None,
                _control: Some(control),
            }),
            (Err(source), original_after) => Err(PluginStartupError {
                source,
                original_after,
                _control: Some(control),
            }),
        }
    }

    // Both owners remain distinct: the native purpose keeps the outer original,
    // while this registered Setup keeps its conserved world/service boundary.
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn retain_workspace(
        &mut self,
        workspace: super::OriginalDeviceDigestWorkspace,
    ) -> Result<(), PluginStartupError> {
        let state = self.state_mut().map_err(Self::state_refusal)?;
        let refuse = |source| PluginStartupError {
            source: PluginStartupCause::Workspace(source),
            original_after: state.original.wait_slice().err(),
            _control: None,
        };
        if state.workspace.is_some() {
            return Err(refuse(super::DeviceDigestWorkspaceIssueError::Unavailable));
        }
        // Store before validation so refusal and unwind retain the same body.
        state.workspace = Some(workspace);
        let body = state
            .workspace
            .as_ref()
            .ok_or_else(|| refuse(super::DeviceDigestWorkspaceIssueError::Unavailable))?
            .setup_view()
            .map_err(&refuse)?;
        let fields = body.record().map_err(&refuse)?.fields();
        let startup = state.record.fields();
        if fields.process_generation != startup.process_generation
            || fields.original_total_metadata_bytes != startup.original_total_metadata_bytes
        {
            return Err(refuse(super::DeviceDigestWorkspaceIssueError::Geometry));
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn workspace_view(
        &self,
    ) -> Result<Option<std::sync::Arc<super::DeviceDigestWorkspaceBody>>, PluginStartupError> {
        let state = self.state().map_err(Self::state_refusal)?;
        state
            .workspace
            .as_ref()
            .map(super::OriginalDeviceDigestWorkspace::setup_view)
            .transpose()
            .map_err(|source| PluginStartupError {
                source: PluginStartupCause::Workspace(source),
                original_after: state.original.wait_slice().err(),
                _control: None,
            })
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn begin_workspace_handover(&mut self) -> Result<(), PluginStartupError> {
        let state = self.state_mut().map_err(Self::state_refusal)?;
        if let Some(workspace) = state.workspace.as_mut() {
            workspace
                .begin_handover()
                .map_err(|source| PluginStartupError {
                    source: PluginStartupCause::Workspace(source),
                    original_after: state.original.wait_slice().err(),
                    _control: None,
                })?;
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn retire_workspace_after_reap(&mut self) {
        let Ok(state) = self.state_mut() else {
            return;
        };
        if let Some(workspace) = state.workspace.as_mut() {
            // The holder itself retains the terminal owner if physical aliases
            // or the same original prevent census closure. No new error owner
            // is allocated in child teardown.
            if workspace.retire_after_reap().is_ok() {
                state.workspace = None;
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    pub(crate) fn workspace_refusal(
        &self,
        source: super::DeviceDigestWorkspaceIssueError,
    ) -> PluginStartupError {
        PluginStartupError {
            source: PluginStartupCause::Workspace(source),
            original_after: self
                .state()
                .and_then(|state| state.original.wait_slice().map(|_| ()))
                .err(),
            _control: None,
        }
    }

    pub(crate) fn record(&self) -> Result<StartupOperation, PluginStartupError> {
        self.state()
            .map(|state| state.record)
            .map_err(Self::state_refusal)
    }

    pub(crate) fn check(&self) -> Result<(), HostSupervisionError> {
        self.state()?.original.check_original_setup_cancellation()
    }

    pub(crate) fn complete(&self) -> Result<(), HostSupervisionError> {
        self.state()?.original.complete().map(|_| ())
    }

    fn state(&self) -> Result<&PluginStartupState, HostSupervisionError> {
        self.body
            .as_ref()
            .as_ref()
            .ok_or(HostSupervisionError::Unavailable)
    }

    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    fn state_mut(&mut self) -> Result<&mut PluginStartupState, HostSupervisionError> {
        self.body
            .as_mut()
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)
    }

    fn state_refusal(source: HostSupervisionError) -> PluginStartupError {
        PluginStartupError {
            source: PluginStartupCause::Original(source),
            original_after: None,
            _control: None,
        }
    }
}

use std::os::fd::AsRawFd as _;

struct DescriptorPath {
    bytes: [u8; 40],
    len: usize,
}

impl fmt::Write for DescriptorPath {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn invalid_event() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

fn event_identity(descriptor: i32) -> io::Result<u64> {
    let mut path = DescriptorPath {
        bytes: [0; 40],
        len: 0,
    };
    write!(path, "/proc/self/fdinfo/{descriptor}").map_err(|_| invalid_event())?;
    let path = std::str::from_utf8(&path.bytes[..path.len]).map_err(|_| invalid_event())?;
    let mut file = File::open(path)?;
    let mut bytes = [0; FDINFO_BYTES + 1];
    let mut length = 0;
    while length < bytes.len() {
        let read = file.read(&mut bytes[length..])?;
        if read == 0 {
            break;
        }
        length += read;
    }
    drop(file);
    if length > FDINFO_BYTES {
        return Err(invalid_event());
    }
    let text = std::str::from_utf8(&bytes[..length]).map_err(|_| invalid_event())?;
    let mut event_id = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("eventfd-id:") {
            if event_id.is_some() {
                return Err(invalid_event());
            }
            event_id = Some(
                value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| invalid_event())?
                    .checked_add(1)
                    .ok_or_else(invalid_event)?,
            );
        }
    }
    event_id.ok_or_else(invalid_event)
}

// This closed refusal is temporary. A positive replacement must consume the
// actual preissued installed-profile purpose from the same process owner;
// native TOTAL, a file hash, or installer completion cannot substitute for it.
fn require_installed_native_profile() -> Result<(), PluginStartupCause> {
    Err(PluginStartupCause::InstalledProfileUnavailable)
}

#[cfg(test)]
mod tests;
