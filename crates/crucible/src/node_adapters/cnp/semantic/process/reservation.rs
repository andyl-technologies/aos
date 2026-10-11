//! Preallocates original native custody before a source peer can exist.
//!
//! Slot identity, the complete process holder and its original readonly owner
//! are constructed before spawn. Launch first moves the actual Child into that
//! holder, then authenticates it. Failure or unwind keeps the same reservation.

use std::{path::PathBuf, process::Command, rc::Rc};

use crucible_node_contract::ContentRef;
use crucible_node_provider::ProviderError;
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
        let supervision_id = slot.identity();
        let read_owner = Rc::new(current::ReadOwner::new(supervision_id));
        let custody = Box::new(CnpSemanticProcessCustody {
            child: None,
            provider_pid: 0,
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
            group: None,
            killed: false,
            reaped: None,
            read_owner,
            kernel_identity: None,
        });

        Self {
            guard: CnpSemanticLaunchGuard {
                custody: Some(custody),
                slot,
                supervision_id,
            },
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
        if self.attempted {
            return Err(ProviderError::Correlation(
                "generic launch already attempted",
            ));
        }
        self.attempted = true;
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

        custody.authenticate_process()?;
        custody.kernel_identity = Some(current::KernelIdentity::capture(custody.provider_pid)?);
        self.authenticated = true;
        Ok(())
    }

    /// Transfers only the same successfully authenticated launch into its guard.
    ///
    /// # Errors
    /// Returns this whole reservation when no original successful authentication
    /// exists; it never substitutes another Child or reconstructs a reservation.
    pub fn into_guard(self) -> Result<CnpSemanticLaunchGuard, CnpSemanticReservationFailure> {
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
