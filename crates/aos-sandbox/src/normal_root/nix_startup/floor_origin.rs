//! Borrows authentic original Nix startup custody without minting a floor.
//!
//! Controller loans borrow the same admitted selector and its twelve protected
//! public credentials. Owner loans borrow the actual root control startup;
//! configured nonroot builder identities are not that owner's credentials.
//! Every public observation checks the existing retained owner. The loans are
//! move-only, borrow-bound and permanently closed after any failed or
//! interrupted check. Each real observation arms the fence before its call.
//! Neither a projection nor a helper check grants Session, NV, journal, build
//! or operation authority. The Nix service barrier compares current PID1
//! policy; it does not prove population drain. Helper-loader process mappings
//! and an authenticated physical floor require separate genuine later owners.

use std::path::Path;

use aos_sandbox_linux::pidfd::PidFd;

use crate::production_operation_compiler::{
    ControllerNixPublicDataLoanV2, ControllerNixStartRecipeSelectorV2,
    NixFixedDomainPinsDataV2, NixStartAdmissionErrorV2,
};
use crate::public_api_session::PinnedSystemdCredential;

use super::{Error, ProductionNixOwnerStartupV1, owner_public::original_node_id};

#[derive(Default)]
pub(super) struct OriginFailureLatchV2 {
    closed: bool,
}

impl OriginFailureLatchV2 {
    pub(super) fn begin(&mut self) -> Option<OriginObservationV2<'_>> {
        if self.closed {
            return None;
        }

        self.closed = true;
        Some(OriginObservationV2 { health: self })
    }
}

// The exclusive borrow permits reopening only the same previously-open
// observation. Dropping it without success, including unwinding, stays closed.
#[must_use = "complete the armed observation or leave the loan fenced"]
pub(super) struct OriginObservationV2<'observation> {
    health: &'observation mut OriginFailureLatchV2,
}

impl OriginObservationV2<'_> {
    pub(super) fn finish<T, E>(self, result: Result<T, E>) -> Result<T, E> {
        if result.is_ok() {
            self.health.closed = false;
        }

        result
    }
}

/// Borrows one genuine Controller selector's original startup and credentials.
///
/// This cannot outlive its original selector, be cloned, or be constructed
/// from pins or historical data. Projections are nonauthorizing DATA; later
/// Security coordination must keep this loan live and recheck it itself.
#[must_use = "retain the original selector borrow throughout later purpose coordination"]
pub struct ControllerNixSessionFloorOriginV2<'origin> {
    selector: &'origin ControllerNixStartRecipeSelectorV2,
    node: PinnedSystemdCredential,
    health: OriginFailureLatchV2,
}

impl ControllerNixStartRecipeSelectorV2 {
    /// Borrows the same original selector for later Nix058 floor coordination.
    ///
    /// This creates neither a Session nor an NV observation. It selects no new
    /// recipe, assignment, operation or time bound. Only this new floor loan
    /// additionally retains the fixed Controller node original outside the
    /// selector's unchanged twelve-public set and ordinary admission API.
    ///
    /// # Errors
    ///
    /// Returns the actual retained startup or credential error if either
    /// original owner changes or cannot be observed.
    pub fn borrow_session_floor_origin_v2(
        &self,
    ) -> Result<ControllerNixSessionFloorOriginV2<'_>, NixStartAdmissionErrorV2> {
        self.recheck_session_floor_origin()?;
        let node = PinnedSystemdCredential::load_nix_controller_node_id()?;
        if original_node_id(&node)? != self.session_floor_pins().node() {
            return Err(NixStartAdmissionErrorV2::Invalid);
        }
        let mut origin = ControllerNixSessionFloorOriginV2 {
            selector: self,
            node,
            health: OriginFailureLatchV2::default(),
        };
        origin.recheck()?;
        Ok(origin)
    }
}

impl ControllerNixSessionFloorOriginV2<'_> {
    /// Rechecks the original selector bookends, separate node, then startup.
    ///
    /// # Errors
    ///
    /// Preserves the underlying startup or credential failure. Any failure
    /// or interrupted check permanently closes this loan; subsequent calls
    /// return `Invalid`. This is per-instance fencing, not a cause archive.
    pub fn recheck(&mut self) -> Result<(), NixStartAdmissionErrorV2> {
        let observation = self
            .health
            .begin()
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;

        let result = Self::recheck_originals(self.selector, &self.node);
        observation.finish(result)
    }

    fn recheck_originals(
        selector: &ControllerNixStartRecipeSelectorV2,
        node: &PinnedSystemdCredential,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        selector.recheck_session_floor_origin()?;
        node.recheck()?;
        selector.session_floor_startup().recheck()?;
        Ok(())
    }

    /// Requires both current Nix service-barrier flights to match the originals.
    ///
    /// This compares PID1 policy, not live population drain, manager image after
    /// reexec, cross-flight bus-owner identity, or a physical TPM observation.
    ///
    /// # Errors
    /// Returns the original typed startup/credential failure and fences this
    /// loan on failure or interruption; a closed loan returns `Invalid`.
    pub fn require_physical_service_barrier(
        &mut self,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        self.recheck()?;

        let observation = self
            .health
            .begin()
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;
        let result = self
            .selector
            .session_floor_startup()
            .require_physical_service_barrier()
            .map_err(NixStartAdmissionErrorV2::from);
        observation.finish(result)?;
        self.recheck()
    }

    /// Compares a live child against the original Controller helper checks.
    ///
    /// This calls the existing executed-helper, parent/credential, cgroup, MAC,
    /// capability and startup checks. It does not prove complete helper-loader
    /// process mappings, acquire a child, send HELLO or authenticate a TPM.
    ///
    /// # Errors
    ///
    /// Rejects a closed loan, changed original credentials/startup, or any
    /// actual retained helper-check failure, and permanently closes this loan.
    pub fn require_floor_helper(
        &mut self,
        process: &PidFd,
    ) -> Result<(), NixStartAdmissionErrorV2> {
        self.recheck()?;
        let observation = self
            .health
            .begin()
            .ok_or(NixStartAdmissionErrorV2::Invalid)?;

        let result = self.selector
            .session_floor_startup()
            .require_floor_helper(process)
            .map_err(NixStartAdmissionErrorV2::from);
        observation.finish(result)?;
        self.recheck()
    }

    /// Returns the original measured helper path as launch DATA after recheck.
    ///
    /// This does not accept or authorize a replacement executable path.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/credential custody.
    pub fn helper_path(&mut self) -> Result<&Path, NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.selector.session_floor_startup().retained.helper.path())
    }

    /// Returns the independently measured original helper-loader path as DATA.
    ///
    /// This proves neither executed-loader mappings nor physical helper custody.
    ///
    /// # Errors
    /// Rejects changed or closed original startup/credential custody.
    pub fn helper_loader_path(&mut self) -> Result<&Path, NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(Path::new(
            &self.selector.session_floor_startup().retained.profile.helper_loader.path,
        ))
    }

    /// Returns the original immutable startup profile path as comparison DATA.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/credential custody.
    pub fn profile_path(&mut self) -> Result<&Path, NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.selector.session_floor_startup().profile_path())
    }

    /// Returns the original selected invocation identifier as comparison DATA.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/credential custody.
    pub fn invocation_id(&mut self) -> Result<[u8; 16], NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.selector.session_floor_startup().invocation())
    }

    /// Returns the original decoded fixed-domain claims as nonauthorizing DATA.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup/credential custody.
    pub fn fixed_domain_pins(
        &mut self,
    ) -> Result<&NixFixedDomainPinsDataV2, NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.selector.session_floor_pins())
    }

    /// Lends guarded access to twelve original public preimages in fixed order.
    ///
    /// The returned move-only loan retains the actual selector's guard. Its
    /// preimages borrow that loan without copying or extracting lower DATA.
    /// Drop it before another observation on this selector; other shared
    /// observations refuse contention rather than blocking or reacquiring it.
    /// This return type intentionally replaces the former bare slice array.
    /// It is nonauthorizing DATA, not a floor, currentness or drain receipt.
    ///
    /// # Errors
    ///
    /// Rejects changed/closed custody or unavailable guard access. Recheck can
    /// fail before a DATA loan exists; the actual selector separately lends
    /// its resident cause through retained_credential_failure, without retry.
    pub fn public_preimages(
        &mut self,
    ) -> Result<ControllerNixPublicDataLoanV2<'_>, NixStartAdmissionErrorV2> {
        self.recheck()?;
        self.selector.session_floor_public_preimages()
    }

    /// Borrows the separate original node bytes outside the twelve-pin set.
    ///
    /// # Errors
    /// Rejects changed or closed original startup/credential/node custody.
    pub fn node_preimage(&mut self) -> Result<&[u8], NixStartAdmissionErrorV2> {
        self.recheck()?;
        Ok(self.node.bytes())
    }
}

/// Borrows genuine Nix059 root control startup, not a nonroot builder owner.
///
/// This loan has no secret/public endpoint credentials or physical floor.
/// The later Security owner must independently retain those actual inputs.
/// Its lifetime requires an externally retained original startup; it cannot
/// make a self-borrowing Session owner from a consumed startup capture.
#[must_use = "retain the original root control startup throughout later purpose coordination"]
pub struct NixOwnerSessionFloorStartupV2<'origin> {
    startup: &'origin ProductionNixOwnerStartupV1,
    health: OriginFailureLatchV2,
}

impl ProductionNixOwnerStartupV1 {
    /// Borrows the original root control startup for later Nix059 coordination.
    ///
    /// It preserves the existing root UID/GID and 0xc0 capability policy and
    /// does not substitute configured nonroot builders for the control owner.
    ///
    /// # Errors
    ///
    /// Returns the actual original startup failure if its selected images,
    /// process, unit, invocation, credentials or confinement cannot recheck.
    pub fn borrow_session_floor_origin_v2(
        &self,
    ) -> Result<NixOwnerSessionFloorStartupV2<'_>, Error> {
        let mut origin = NixOwnerSessionFloorStartupV2 {
            startup: self,
            health: OriginFailureLatchV2::default(),
        };
        origin.recheck()?;
        Ok(origin)
    }
}

impl NixOwnerSessionFloorStartupV2<'_> {
    /// Rechecks the same actual root control-owner startup.
    ///
    /// # Errors
    ///
    /// Preserves the underlying startup failure and permanently closes the
    /// loan. Interrupted checks also leave it closed. Subsequent calls return
    /// the existing `Service` error; no resident cause archive is retained.
    pub fn recheck(&mut self) -> Result<(), Error> {
        let observation = self.health.begin().ok_or(Error::Service)?;

        let result = self.startup.recheck();
        observation.finish(result)
    }

    /// Compares a live child against the original Nix059 helper checks.
    ///
    /// This preserves the existing root helper credentials, zero effective/
    /// permitted/inheritable caps, bounding 0xc0, NNP, parent, cgroup, MAC and
    /// executed-helper checks. It does not authenticate the TPM or prove the
    /// complete loader mappings or the PID1 population crash barrier.
    ///
    /// # Errors
    ///
    /// Rejects closed/changed original custody or actual helper failure and
    /// permanently closes this loan.
    pub fn require_floor_helper(&mut self, process: &PidFd) -> Result<(), Error> {
        self.recheck()?;
        let observation = self.health.begin().ok_or(Error::Service)?;

        let result = self.startup.require_floor_helper(process);
        observation.finish(result)?;
        self.recheck()
    }

    /// Returns the original measured helper path as launch DATA after recheck.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup custody.
    pub fn helper_path(&mut self) -> Result<&Path, Error> {
        self.recheck()?;
        Ok(self.startup.retained.helper.path())
    }

    /// Returns the original immutable startup profile path as comparison DATA.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup custody.
    pub fn profile_path(&mut self) -> Result<&Path, Error> {
        self.recheck()?;
        Ok(self.startup.profile_path())
    }

    /// Returns the original selected invocation identifier as comparison DATA.
    ///
    /// # Errors
    ///
    /// Rejects changed or closed original startup custody.
    pub fn invocation_id(&mut self) -> Result<[u8; 16], Error> {
        self.recheck()?;
        Ok(self.startup.invocation())
    }
}

#[cfg(test)]
mod tests {
    use super::OriginFailureLatchV2;

    // Pure latch state cannot construct a loan, startup, endpoint or floor.
    #[test]
    fn a_failed_observation_closes_the_latch_without_erasing_its_cause() {
        let mut health = OriginFailureLatchV2::default();
        let observation = health.begin().unwrap();

        let result = observation.finish::<(), _>(Err("original typed failure"));

        assert_eq!(result, Err("original typed failure"));
        assert!(health.closed);
    }

    #[test]
    fn later_success_never_reopens_a_failed_observation() {
        let mut health = OriginFailureLatchV2::default();
        health.begin().unwrap().finish::<(), &str>(Ok(())).unwrap();
        assert!(!health.closed);
        assert!(
            health
                .begin()
                .unwrap()
                .finish::<(), _>(Err("changed"))
                .is_err()
        );

        assert!(health.begin().is_none());

        assert!(health.closed);
    }

    #[test]
    fn an_interrupted_observation_stays_closed() {
        let mut health = OriginFailureLatchV2::default();

        {
            let _observation = health.begin().unwrap();
        }

        assert!(health.closed);
        assert!(health.begin().is_none());
    }

    #[test]
    fn a_caught_unwind_cannot_reopen_the_observation() {
        let mut health = OriginFailureLatchV2::default();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _observation = health.begin().unwrap();
            panic!("interrupted private latch observation");
        }));

        assert!(result.is_err());
        assert!(health.closed);
        assert!(health.begin().is_none());
    }
}
