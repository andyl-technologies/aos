//! Owns the original Setup operation across the real plugin handshake.
//!
//! Ordinary initial Source launches borrow the actual Main-funded Source
//! admission independently of RAM-controller registration. Setup keeps its
//! original operation and process-contract event; the separate standing owner
//! retains live policy and cancellation after Setup completes. No pager or
//! replacement operation supplies either authority. The matched native Source
//! receiver and complete allocation-peak qualification remain required before
//! selected process birth; a late setup frame cannot substitute for them.

use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, Read};

use crucible_host_resources::host_services::process_birth::{
    ServiceBirthError, SourceHostControlLease,
};
use crucible_host_resources::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};
use crucible_qemu_protocol::plugin_setup_plan::{
    StartupOperation, StartupOperationError, StartupOperationFields,
};

use super::QemuChildProcessContract;

const FDINFO_BYTES: usize = 4096;

/// Retains the real startup operation and its original host-side control loan.
#[derive(Debug)]
pub(crate) struct OriginalPluginStartup {
    // The initialized body and its allocation close before this external loan.
    body: Box<Option<PluginStartupState>>,
    _control: SourceHostControlLease,
}

#[derive(Debug)]
struct PluginStartupState {
    #[cfg(target_os = "linux")]
    workspace: Option<super::OriginalDeviceDigestWorkspace>,
    #[cfg(target_os = "linux")]
    source: crate::linux_attempt_host::InstalledSourceAdmission,
    #[cfg(target_os = "linux")]
    standing: super::source_supervision::OriginalSourceSupervision,
    original: HostOperationGuard,
    record: StartupOperation,
}

// Keeps the physically constructed owners with their observation until the
// same Setup's independent post permits installation in the retained body.
struct PreparedStartupObservation {
    record: StartupOperation,
    #[cfg(target_os = "linux")]
    standing: super::source_supervision::OriginalSourceSupervision,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PluginStartupCause {
    #[error("the installed native preconstructor profile is unavailable")]
    InstalledProfileUnavailable,
    #[cfg(target_os = "linux")]
    #[error("issued installed process purpose refused: {0}")]
    Purpose(#[source] crate::linux_attempt_host::InstalledProcessPurposeError),
    #[cfg(target_os = "linux")]
    #[error("matched native preexec receiver artifact refused: {0}")]
    Receiver(#[source] crate::artifact_identity::NativeReceiverError),
    #[cfg(target_os = "linux")]
    #[error("device workspace issuance refused: {0}")]
    Workspace(#[source] super::DeviceDigestWorkspaceIssueError),
    #[cfg(target_os = "linux")]
    #[error("standing Source supervision refused: {0}")]
    Standing(#[source] super::source_supervision::SourceSupervisionError),
    #[error("original Source host control refused: {0}")]
    SourceHost(#[source] ServiceBirthError),
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
    _control: Option<SourceHostControlLease>,
}

impl OriginalPluginStartup {
    #[cfg(target_os = "linux")]
    pub(crate) fn admission_refusal(
        source: crate::linux_attempt_host::InstalledProcessPurposeError,
    ) -> PluginStartupError {
        PluginStartupError {
            source: PluginStartupCause::Purpose(source),
            original_after: None,
            _control: None,
        }
    }

    /// Reports the Source's hosted startup bodies and Setup cancellation control.
    ///
    /// The actual containing Main reserves this peak before Source admission.
    /// Physical startup borrows a disjoint piece of that same retained payer;
    /// no RAM registration is required. Standing publication, preexec aliases
    /// and native construction peaks are accounted independently.
    ///
    /// # Errors
    /// Returns a geometry refusal if a target extent or checked sum overflows.
    #[cfg(target_os = "linux")]
    pub(crate) fn host_allocation_extent() -> Result<u64, PluginStartupError> {
        Self::control_allocation_extent()
            .and_then(|bytes| {
                bytes.checked_add(HostOperationGuard::original_setup_cancellation_bytes())
            })
            .ok_or(PluginStartupError {
                source: PluginStartupCause::Geometry,
                original_after: None,
                _control: None,
            })
    }

    fn control_allocation_extent() -> Option<u64> {
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<Option<PluginStartupState>>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PluginStartupState>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PluginStartupError>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<SourceHostControlLease>() as u64)
            })
            .and_then(|bytes| bytes.checked_add((FDINFO_BYTES + 1) as u64))
    }

    pub(crate) fn prepare(
        supervisor: &HostOperationSupervisor,
        contract: &QemuChildProcessContract,
        registration: Option<&crate::ram_control::RamControlRegistration>,
        process_generation: u64,
        #[cfg(target_os = "linux")] binding: Option<
            &crate::linux_attempt_host::OriginalNativeNodeBinding,
        >,
        #[cfg(target_os = "linux")] admission: Option<
            &crate::linux_attempt_host::InstalledSourceAdmission,
        >,
    ) -> Result<Self, PluginStartupError> {
        let refuse_before = |source| PluginStartupError {
            source,
            original_after: None,
            _control: None,
        };
        // The node keeper borrows its actual issued family assignment. No
        // supervisor, configured ceiling or artifact label can mint this loan.
        #[cfg(target_os = "linux")]
        let source = admission
            .ok_or_else(|| refuse_before(PluginStartupCause::InstalledProfileUnavailable))?;
        #[cfg(target_os = "linux")]
        binding
            .ok_or_else(|| refuse_before(PluginStartupCause::InstalledProfileUnavailable))?
            .verify_source_admission(contract, supervisor, source, process_generation)
            .map_err(|error| refuse_before(PluginStartupCause::Purpose(error)))?;
        #[cfg(target_os = "linux")]
        if let Some(registration) = registration {
            binding
                .ok_or_else(|| refuse_before(PluginStartupCause::InstalledProfileUnavailable))?
                .verify_installed_process_purpose(
                    contract,
                    supervisor,
                    registration,
                    process_generation,
                )
                .map_err(|error| refuse_before(PluginStartupCause::Purpose(error)))?;
        }
        #[cfg(not(target_os = "linux"))]
        require_installed_process_purpose().map_err(refuse_before)?;

        // These are actual hosted holder/scratch bodies, not a native W floor.
        // The existing supervisor/world must retain its own allocation custody;
        // this loan does not substitute for its transitive Source/control proof.
        let bytes = Self::control_allocation_extent()
            .ok_or_else(|| refuse_before(PluginStartupCause::Geometry))?;
        #[cfg(target_os = "linux")]
        let control = source
            .host_purpose()
            .reserve_controls(1, bytes)
            .map_err(|source| refuse_before(PluginStartupCause::SourceHost(source)))?;
        #[cfg(not(target_os = "linux"))]
        let control: SourceHostControlLease = return Err(refuse_before(
            PluginStartupCause::InstalledProfileUnavailable,
        ));
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
        // The admission already owns its paid canonical slot. Save a born
        // issuer there before its independent Setup post, so even refusal
        // cannot discard or reissue the actual node's delegation.
        #[cfg(target_os = "linux")]
        if let Err(source) = source.delegate_cleanup_issuer(&original) {
            return Err(PluginStartupError {
                source: PluginStartupCause::Original(source),
                original_after: original.wait_slice().err(),
                _control: Some(control),
            });
        }
        // Both bodies remain under the same admitted host peak. Enter the
        // actual Setup before allocating or constructing its physical controls.
        let mut body = Box::new(None);
        let (observed, after) = observe_startup_under_original(&original, || {
            let metadata = rustix::fs::fstat(&contract.cancellation_event)
                .map_err(|source| PluginStartupCause::Kernel(source.into()))?;
            let event_id = event_identity(contract.cancellation_event.as_raw_fd())
                .map_err(PluginStartupCause::Kernel)?;
            // The temporary fdinfo owner is already physically closed. The
            // persistent subscriber has a distinct prepaid FD/control loan.
            #[cfg(target_os = "linux")]
            let subscriber = source
                .host_purpose()
                .reserve_controls(1, HostOperationGuard::original_setup_cancellation_bytes())
                .map_err(PluginStartupCause::SourceHost)?;
            #[cfg(not(target_os = "linux"))]
            let subscriber: SourceHostControlLease =
                return Err(PluginStartupCause::InstalledProfileUnavailable);
            let descriptor = rustix::io::fcntl_dupfd_cloexec(
                &contract.cancellation_event,
                super::CHILD_SOURCE_FD_MIN,
            )
            .map_err(|error| PluginStartupCause::Kernel(error.into()))?;
            original
                .retain_source_setup_cancellation(descriptor, subscriber)
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
                original_total_metadata_bytes: {
                    #[cfg(target_os = "linux")]
                    {
                        source.original_metadata_bytes()
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        0
                    }
                },
                cancellation_device: metadata.st_dev,
                cancellation_inode: metadata.st_ino,
                cancellation_event_id: event_id,
                cancellation_descriptor: super::QEMU_STARTUP_CANCELLATION_FD,
            })
            .map_err(PluginStartupCause::Record)?;
            original
                .check_original_setup_cancellation()
                .map_err(PluginStartupCause::Original)?;
            // Standing birth also observes the actual inherited cancellation
            // event through this same Setup, after its real subscriber is held.
            #[cfg(target_os = "linux")]
            let standing = super::source_supervision::OriginalSourceSupervision::prepare(source)
                .map_err(PluginStartupCause::Standing)?;
            Ok(PreparedStartupObservation {
                record,
                #[cfg(target_os = "linux")]
                standing,
            })
        });
        match (observed, after) {
            (Ok(observation), None) => {
                *body = Some(PluginStartupState {
                    #[cfg(target_os = "linux")]
                    source: source.clone(),
                    #[cfg(target_os = "linux")]
                    standing: observation.standing,
                    #[cfg(target_os = "linux")]
                    workspace: None,
                    original,
                    record: observation.record,
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
    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

    /// Checks the receiver declaration retained by this exact admitted Source.
    ///
    /// # Errors
    /// Refuses the original Setup, changed Source custody, or the actual matched
    /// artifact's receiver declaration. Independent original postcut remains
    /// visible without completing Setup or releasing the caller's controls.
    pub(crate) fn require_preexec_receiver(&self) -> Result<(), PluginStartupError> {
        let state = self.state().map_err(Self::state_refusal)?;
        check_receiver_under_original(&state.original, || {
            #[cfg(target_os = "linux")]
            {
                state.source.check().map_err(|source| {
                    PluginStartupCause::Purpose(
                        crate::linux_attempt_host::OriginalActorAccountError::from(source).into(),
                    )
                })?;
                state
                    .source
                    .receiver_artifact()
                    .check_source_activation()
                    .map_err(PluginStartupCause::Receiver)
            }
            #[cfg(not(target_os = "linux"))]
            Err(PluginStartupCause::InstalledProfileUnavailable)
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn standing(
        &self,
    ) -> Result<&super::source_supervision::OriginalSourceSupervision, PluginStartupError> {
        self.state()
            .map(|state| &state.standing)
            .map_err(Self::state_refusal)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn admission(
        &self,
    ) -> Result<&crate::linux_attempt_host::InstalledSourceAdmission, HostSupervisionError> {
        self.state().map(|state| &state.source)
    }

    pub(crate) fn record(&self) -> Result<StartupOperation, PluginStartupError> {
        self.state()
            .map(|state| state.record)
            .map_err(Self::state_refusal)
    }

    pub(crate) fn check(&self) -> Result<(), HostSupervisionError> {
        self.state()?.original.check_original_setup_cancellation()
    }

    /// Admits encoded-plan and alias owners from the same actual Source payer.
    pub(super) fn reserve_preexec(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<SourceHostControlLease, PluginStartupError> {
        let state = self.state().map_err(Self::state_refusal)?;
        state
            .original
            .check_original_setup_cancellation()
            .map_err(Self::state_refusal)?;
        #[cfg(target_os = "linux")]
        let result = state
            .source
            .host_purpose()
            .reserve_controls(descriptors, bytes);
        #[cfg(not(target_os = "linux"))]
        let result: Result<SourceHostControlLease, ServiceBirthError> = Err(
            ServiceBirthError::policy("Source host payer is unavailable"),
        );
        let after = state.original.wait_slice().err();
        match (result, after) {
            (Ok(control), None) => Ok(control),
            (Err(source), original_after) => Err(PluginStartupError {
                source: PluginStartupCause::SourceHost(source),
                original_after,
                _control: None,
            }),
            (Ok(control), Some(source)) => Err(PluginStartupError {
                source: PluginStartupCause::Original(source),
                original_after: None,
                _control: Some(control),
            }),
        }
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

    #[cfg(target_os = "linux")]
    fn state_mut(&mut self) -> Result<&mut PluginStartupState, HostSupervisionError> {
        self.body
            .as_mut()
            .as_mut()
            .ok_or(HostSupervisionError::Unavailable)
    }

    pub(super) fn state_refusal(source: HostSupervisionError) -> PluginStartupError {
        PluginStartupError {
            source: PluginStartupCause::Original(source),
            original_after: None,
            _control: None,
        }
    }
}

use std::os::fd::{AsRawFd as _, OwnedFd};

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

pub(super) fn event_identity(descriptor: i32) -> io::Result<u64> {
    let (path, length) = event_identity_path(descriptor)?;
    let path = std::str::from_utf8(&path[..length]).map_err(|_| invalid_event())?;
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
    decode_event_identity(&bytes[..length])
}

pub(super) fn event_identity_path(descriptor: i32) -> io::Result<([u8; 40], usize)> {
    let mut path = DescriptorPath {
        bytes: [0; 40],
        len: 0,
    };
    write!(path, "/proc/self/fdinfo/{descriptor}").map_err(|_| invalid_event())?;
    Ok((path.bytes, path.len))
}

pub(super) fn decode_event_identity(bytes: &[u8]) -> io::Result<u64> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_event())?;
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

// This build has no genuine private issuer. Keep ordinary registered startup
// closed rather than treating a selected artifact or supervisor as a purpose.
#[cfg(not(target_os = "linux"))]
fn require_installed_process_purpose() -> Result<(), PluginStartupCause> {
    Err(PluginStartupCause::InstalledProfileUnavailable)
}

// The actual caller retains its paid control and any resulting physical owners.
// The independent post also runs when construction refuses before a cancellation
// subscription exists; neither failure replaces the other.
fn observe_startup_under_original<T>(
    original: &HostOperationGuard,
    observe: impl FnOnce() -> Result<T, PluginStartupCause>,
) -> (Result<T, PluginStartupCause>, Option<HostSupervisionError>) {
    let first = original
        .wait_slice()
        .map_err(PluginStartupCause::Original)
        .and_then(|_| observe());
    let after = original.wait_slice().err();

    (first, after)
}

// The actual startup remains the owner of its body/control on either refusal.
// A component control may exercise this first/post ordering with a real guard
// and final-file observation without constructing a Source or startup owner.
fn check_receiver_under_original(
    original: &HostOperationGuard,
    observe: impl FnOnce() -> Result<(), PluginStartupCause>,
) -> Result<(), PluginStartupError> {
    let first = original
        .check_original_setup_cancellation()
        .map_err(PluginStartupCause::Original)
        .and_then(|()| observe());
    let original_after = original.wait_slice().err();
    match (first, original_after) {
        (Ok(()), None) => Ok(()),
        (Ok(()), Some(source)) => Err(PluginStartupError {
            source: PluginStartupCause::Original(source),
            original_after: None,
            _control: None,
        }),
        (Err(source), original_after) => Err(PluginStartupError {
            source,
            original_after,
            _control: None,
        }),
    }
}

#[cfg(test)]
mod tests;

/// Reopens only the real retained publication's read-only open file description.
pub(super) fn reopen_readonly(descriptor: i32) -> io::Result<OwnedFd> {
    let mut path = DescriptorPath {
        bytes: [0; 40],
        len: 0,
    };
    write!(path, "/proc/self/fd/{descriptor}").map_err(|_| invalid_event())?;
    let path = std::str::from_utf8(&path.bytes[..path.len]).map_err(|_| invalid_event())?;
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(Into::into)
}
