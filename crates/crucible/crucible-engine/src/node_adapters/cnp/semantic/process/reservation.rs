//! Preallocates original native custody before a source peer can exist.
//!
//! Slot identity, the complete process holder and its original readonly owner
//! are constructed before spawn. Launch first moves the actual Child into that
//! holder, then authenticates it. Failure or unwind keeps the same reservation.

use std::{path::PathBuf, process::Command, rc::Rc};

use crucible_node_format::ContentRef;
use crucible_node_transport::ProviderError;
use rustix::process::Pid;

use super::{CnpSemanticLaunchGuard, CnpSemanticProcessCustody, CnpSemanticProcessSlot, current};

/// Reserves the complete original process holder before Child creation.
///
/// This non-cloneable, non-serializable owner never exposes an unlaunched native
/// custody object. Its slot identity callback and all holder allocations precede
/// spawn. Allocation failure outside the bounded host contract is not claimed
/// to be recoverable; the trusted supervisor's retention callback must not unwind.
#[must_use = "retain the original reservation until supervised reclamation"]
pub struct CnpSemanticLaunchReservation {
    guard: CnpSemanticLaunchGuard,
    complete_bytes: bool,
    original_pidfd: bool,
    native_startup: bool,
    attempted: bool,
    authenticated: bool,
}

/// Retains the same original launch reservation when guard transfer is refused.
pub struct CnpSemanticReservationFailure {
    /// Describes refusal without claiming that native resources were reclaimed.
    pub error: ProviderError,
    /// Owns the same actual Child, cached identity and supervisor reservation.
    pub original: CnpSemanticLaunchReservation,
}

#[path = "reservation_storage.rs"]
mod retained_storage;

impl CnpSemanticLaunchReservation {
    /// Allocates the complete holder and reads its installed identity before spawn.
    ///
    /// The launcher supplies the independently measured executable and its fresh
    /// private directory. This reserves custody only, not source qualification.
    ///
    /// # Panics
    /// Propagates a trusted slot identity callback panic before any Child exists.
    pub fn reserve(
        directory: PathBuf,
        executable: ContentRef,
        slot: Box<dyn CnpSemanticProcessSlot>,
    ) -> Self {
        Self::reserve_selected(directory, executable, slot, false, false)
    }

    /// Reserves complete-only executable custody without creating a lease worker.
    ///
    /// The immutable choice precedes the slot identity callback and all Child
    /// effects. Every executable check still reads and hashes the complete
    /// retained descriptor, with positional EOF/kernel/PID/namespace fences.
    /// This reservation grants neither source admission nor execution permission.
    /// It never converts an already acquired lease to a byte-validation path.
    ///
    /// # Panics
    /// Propagates a trusted slot identity callback panic before any Child exists.
    pub fn reserve_complete_bytes(
        directory: PathBuf,
        executable: ContentRef,
        slot: Box<dyn CnpSemanticProcessSlot>,
    ) -> Self {
        Self::reserve_selected(directory, executable, slot, true, false)
    }

    /// Fixes complete-byte custody and concrete original-child ownership before birth.
    ///
    /// This selected Source entry retains the actual std child through every
    /// descriptor and identity check. Unsupported acquisition refuses with that
    /// child still owned; no legacy handle or PID fallback is substituted.
    ///
    /// # Panics
    /// Propagates a trusted slot identity callback panic before any child exists.
    pub(in crate::node_adapters::cnp::semantic) fn reserve_complete_original_child(
        directory: PathBuf,
        executable: ContentRef,
        slot: Box<dyn CnpSemanticProcessSlot>,
    ) -> Self {
        Self::reserve_selected(directory, executable, slot, true, true)
    }

    pub(in crate::node_adapters::cnp::semantic) fn reserve_original_native_startup(
        directory: PathBuf,
        executable: ContentRef,
        slot: Box<dyn CnpSemanticProcessSlot>,
    ) -> Self {
        let mut original = Self::reserve_selected(directory, executable, slot, true, true);
        original.native_startup = true;
        original
    }

    fn reserve_selected(
        directory: PathBuf,
        executable: ContentRef,
        slot: Box<dyn CnpSemanticProcessSlot>,
        complete_bytes: bool,
        original_pidfd: bool,
    ) -> Self {
        let creator_process = std::process::id();
        let supervision_id = slot.identity();
        let read_owner = Rc::new(current::ReadOwner::new(supervision_id));
        let custody = Box::new(CnpSemanticProcessCustody {
            creator_process,
            child: None,
            original_child: None,
            provider_pid: 0,
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
            group: None,
            killed: false,
            reaped: None,
            read_owner,
            kernel_identity: None,
            executable_guard: None,
        });

        Self {
            guard: CnpSemanticLaunchGuard {
                creator_process,
                custody: Some(custody),
                slot: Some(slot),
                supervision_id,
            },
            complete_bytes,
            original_pidfd,
            native_startup: false,
            attempted: false,
            authenticated: false,
        }
    }

    /// Spawns once and installs the actual Child before authenticating its identity.
    ///
    /// The command must create a private process group. The caller keeps this
    /// reservation outside its unwind boundary; no slot callback occurs between
    /// successful spawn and moving Child into the preallocated original holder.
    /// A failed validation does not permit another spawn.
    ///
    /// # Errors
    /// Refuses a repeated attempt, unavailable holder, spawn failure, foreign
    /// group, changed actual executable or unavailable original kernel evidence.
    pub fn launch(&mut self, command: &mut Command) -> Result<(), ProviderError> {
        self.guard.ensure_origin()?;
        if self.attempted {
            return Err(ProviderError::Correlation(
                "generic launch already attempted",
            ));
        }
        self.attempted = true;
        let mut native_scratch = if self.native_startup {
            Some(
                super::executable_guard::FreshCurrentScratch::for_original_native_startup()
                    .map_err(|_| {
                        ProviderError::ResourceExhausted("selected native launch scratch")
                    })?,
            )
        } else {
            None
        };
        let custody = self
            .guard
            .custody
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "generic reserved custody transferred",
            ))?;
        // This assignment transfers ownership before any process/source verifier.
        custody.child = Some(command.spawn()?);
        let child = custody.child.as_ref().ok_or(ProviderError::Correlation(
            "generic original Child absent after spawn",
        ))?;
        custody.provider_pid = child.id();
        custody.group = i32::try_from(child.id()).ok().and_then(Pid::from_raw);

        let identity = if let Some(scratch) = native_scratch.as_mut() {
            current::KernelIdentity::capture_original_native_startup(custody.provider_pid, scratch)
                .map_err(|_| {
                    ProviderError::Correlation("selected native kernel acquisition refused")
                })?
        } else {
            current::KernelIdentity::capture(custody.provider_pid)?
        };
        custody.kernel_identity = Some(identity);
        let executable = if let Some(scratch) = native_scratch.as_mut() {
            super::executable_guard::OriginalExecutable::open_original_native_startup(
                custody.provider_pid,
                &custody.expected_executable,
                &identity,
                scratch,
            )
            .map_err(|_| {
                ProviderError::Correlation("selected native executable acquisition refused")
            })?
        } else if self.complete_bytes {
            super::executable_guard::OriginalExecutable::open_complete_bytes(
                custody.provider_pid,
                &custody.expected_executable,
                &identity,
            )?
        } else {
            super::executable_guard::OriginalExecutable::open(
                custody.provider_pid,
                &custody.expected_executable,
                &identity,
            )?
        };
        custody.executable_guard = Some(Rc::new(executable));
        custody.authenticate_process()?;
        if self.original_pidfd {
            if custody.original_child.is_some() {
                return Err(ProviderError::Correlation(
                    "selected original descriptor was already retained",
                ));
            }
            // The original std Child is still in this same private holder. No
            // callback or competing reaper receives it during birth transfer.
            let child = custody.child.as_ref().ok_or(ProviderError::Correlation(
                "selected birth child is absent before descriptor transfer",
            ))?;
            let executable =
                custody
                    .executable_guard
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "selected birth executable guard is absent",
                    ))?;
            let original = super::original_child::OriginalChild::capture(
                child,
                custody.provider_pid,
                &identity,
                executable,
            )?;
            // All fallible checks finished. Retain the concrete owner before
            // dropping std Child, whose drop never reaps. Parent streams are None.
            custody.original_child = Some(original);
            drop(custody.child.take());
        }
        self.authenticated = true;
        Ok(())
    }

    /// Transfers only the same successfully authenticated launch into its guard.
    ///
    /// # Errors
    /// Returns this whole reservation when no original successful authentication
    /// exists; it never substitutes another Child or reconstructs a reservation.
    pub fn into_guard(self) -> Result<CnpSemanticLaunchGuard, CnpSemanticReservationFailure> {
        if let Err(error) = self.guard.ensure_origin() {
            return Err(CnpSemanticReservationFailure {
                error,
                original: self,
            });
        }
        if !self.authenticated {
            return Err(CnpSemanticReservationFailure {
                error: ProviderError::Correlation("generic original launch not authenticated"),
                original: self,
            });
        }
        Ok(self.guard)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod origin_tests;

impl CnpSemanticLaunchReservation {
    pub(super) fn original_host_startup_unlaunched_data(&self) -> bool {
        self.native_startup && !self.attempted && !self.authenticated
    }

    pub(super) fn original_host_startup_guard_data(&self) -> &CnpSemanticLaunchGuard {
        &self.guard
    }
}
