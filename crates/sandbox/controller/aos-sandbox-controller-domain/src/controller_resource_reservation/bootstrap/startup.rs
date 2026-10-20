//! Moves the SAME paired first-table startup into its actual Bank coordinator.
//!
//! The original C and profile admission remain siblings in this owner. No raw
//! file, independent profile, caller layout or decoded resource DATA can enter
//! this handoff. A failed constructor owns the whole untouched startup prefix.

use std::sync::Arc;

use aos_sandbox_broker::controller_receiving::{
    ControllerBankOpeningFailureV1, ControllerReceivingErrorV1,
    ControllerStartupOpeningV1, ControllerStartupFailureRefV1,
};
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;

use super::{ControllerResourceBankOpeningV1, ResourceReservationErrorV1};

impl ControllerResourceBankOpeningV1 {
    /// Moves the actual first-table pair into its sole Bank startup coordinator.
    ///
    /// The actual native-layout producer remains private to Domain. An ordinary
    /// no-C table cannot construct this selected coordinator, and an invalid
    /// handoff remains owned in the returned error without a legacy fallback.
    ///
    /// # Errors
    /// Retains the entire startup on absent original or a different actual
    /// Controller layout. This performs no native observation or Bank mutation.
    pub fn begin_selected_startup(
        mut startup: ControllerStartupOpeningV1,
    ) -> Result<Self, ControllerBankOpeningFailureV1> {
        if !startup.matches_native_layout(super::super::q04_intake::native_layout()) {
            return Err(startup.into_bank_handoff_failure_v1(ControllerReceivingErrorV1::Conflict));
        }
        let Some(original) = startup.original().map(Arc::clone) else {
            return Err(startup.into_bank_handoff_failure_v1(ControllerReceivingErrorV1::EnrollmentUnavailable));
        };
        let writer_opening = match startup.take_fixed_writer_opening_once() {
            Ok(opening) => opening,
            Err(cause) => return Err(startup.into_bank_handoff_failure_v1(cause)),
        };
        let launch = startup.take_bank_launch_once();
        Ok(Self {
            startup,
            wrapper_debit: None,
            original,
            writer_opening: std::cell::RefCell::new(Some(writer_opening)),
            launch,
            bank_observation: aos_sandbox_broker::controller_receiving::ControllerOriginalObservationV1::new(),
            bank_mutation: None,
            bank_native_post: None,
            bank_native_post_entry: None,
            bank_native_post_disposition: None,
            launch_result: None,
            launch_admission: None,
            selected_prefix: None,
            runtime_startup: None,
            source_issue_debit: None,
            source_credentials: None,
            source_credentials_taken: false,
            public_credentials: None,
            public_credentials_taken: false,
            enrolled_disposition: None,
            serving_disposition: None,
            publisher_receiving: None,
            publisher_receiving_taken: false,
            initial_sessions: [const { None }; super::super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
            initial_sessions_taken: [false; super::super::initial_session::ControllerInitialBrokerSessionRoleV1::COUNT],
            cache_import: None,
            preopen: None,
            preopen_attempted: false,
            nix_intake_attempted: false,
            q04_intake_attempted: false,
            create_intake_attempted: false,
            observed: None,
            prepared: None,
            names: None,
            native: None,
            readback: None,
            journal_post: None,
            profile_post: None,
            attempted: false,
        })
    }

    /// Admits only this owner's SAME first-table profile/C pair once.
    ///
    /// Configured UID/GID are comparison DATA. The lower owner reserves its
    /// actual fixed receiver before profile decode and retains any refusal.
    #[doc(hidden)]
    #[must_use]
    pub fn admit_selected_profile_once(&mut self, uid: u32, gid: u32) -> bool {
        if self.selected_prefix.is_some() || self.preopen_attempted || self.attempted {
            return false;
        }
        let admitted = self.startup.admit_selected_profile_once(uid, gid);
        if admitted {
            // The lower profile already owns its four native archives. Charge
            // only the remaining upper wrappers, Bank coordinator and owning
            // negative destination before moving that admitted profile.
            self.wrapper_debit = Some(self.coordinator_representation_demand_v1()
                .and_then(|demand| self.original.debit_coordinator_representation_v1(demand)));
        }
        let admitted = admitted && matches!(self.wrapper_debit, Some(Ok(())));
        self.selected_prefix = Some(if admitted {
            Ok(())
        } else {
            // The rich native/profile cause stays in startup; this marker is
            // only the same coordinator's permanently closed stopping state.
            Err(ResourceReservationErrorV1::EnrollmentUnavailable)
        });
        admitted
    }

    /// Lends the actual retained profile/native refusal without copying it.
    #[doc(hidden)]
    #[must_use]
    pub fn profile_admission_failure(&self) -> Option<ControllerStartupFailureRefV1<'_>> {
        self.startup.first_failure().or_else(|| {
            self.wrapper_debit.as_ref().and_then(|result| result.as_ref().err())
                .map(ControllerStartupFailureRefV1::Receiving)
        })
    }

    // Exhaustive pattern keeps the named resident census tied to this actual
    // owner: adding a field requires updating this producer at compile time.


    fn coordinator_representation_demand_v1(&self) -> Result<aos_sandbox_model::ResourceVector, ControllerReceivingErrorV1> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let invalid = || ControllerReceivingErrorV1::Conflict;
        let upper = std::mem::size_of::<crate::normal_root::ProductionControllerNormalRootProfileV1>();
        let lower = std::mem::size_of::<ControllerSelfProfileOriginalV1>();
        let delta = upper.checked_sub(lower).ok_or_else(invalid)?;
        // Native admission now owns all four actual origin/archive slots.
        // Its compiled startup-opening prefix prices those before construction.
        let wrappers = delta.checked_mul(2).ok_or_else(invalid)?;
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ControllerBankOpeningFailureV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(wrappers))
            // The genuine original includes the SAME 21-owner residual ledger
            // and four actual claimed-role latches; no copied account exists.
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_broker::controller_receiving::ControllerReceivingOriginalV1>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<usize>().checked_mul(4)?))
            .ok_or_else(invalid)?;
        let source = aos_sandbox_broker::controller_receiving::ControllerSourcePreBankConstructionLoanV1::
            receiving_demand_v1()?;
        let observation = aos_sandbox_broker::controller_receiving::ControllerOriginalObservationV1::
            receiving_demand_v1().ok_or_else(invalid)?;
        // A failed primary pair can coexist with the independently owed
        // Source and Controller post pairs. Positive observations retire only
        // their temporary boot input, preserving the startup's original one.
        let mut observations = ResourceVector::ZERO;
        for _ in 0..3 { observations = observations.checked_add(observation)?; }
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .checked_add(source)?.checked_add(observations)?
            .checked_add(aos_sandbox_broker::controller_receiving::ControllerCachePreBankImportLoanV1::
                receiving_demand_v1()?)
            .map_err(ControllerReceivingErrorV1::from)
    }

    /// Moves the SAME complete lower profile once to its existing Domain owner.
    #[doc(hidden)]
    #[must_use]
    fn take_admitted_profile_once(&mut self) -> Option<ControllerSelfProfileOriginalV1> {
        if !matches!(self.selected_prefix, Some(Ok(()))) {
            return None;
        }
        self.startup.take_admitted_profile_once()
    }
    /// Moves only this actual Bank's completed profile into its typed binding.
    #[doc(hidden)]
    #[must_use]
    pub fn take_admitted_profile_binding_once(
        &mut self,
    ) -> Option<crate::normal_root::ControllerAdmittedStartupProfileV1> {
        let original = self.take_admitted_profile_once()?;
        Some(crate::normal_root::ControllerAdmittedStartupProfileV1::from_completed_admission(
            Some(crate::normal_root::ProductionControllerNormalRootProfileV1::from_admitted_original_v1(original)),
        ))
    }

}
