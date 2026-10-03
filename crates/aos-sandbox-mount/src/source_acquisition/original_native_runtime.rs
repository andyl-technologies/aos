//! Held-runtime entry and progress for one genuine original Root native flight.
//!
//! These crate-private methods register no broker handler or readiness path.
//! Mount retains the actual Live admission before the first fallible step and
//! reborrows the same physical writer, table, native index, and current Session.
//! The guarantee starts from genuine Live and Session custody; initial hello,
//! Live admission production, process loss and panic-abort are outside it.

use aos_sandbox_protocol::LiveValidatedAcquireMountSourceRequest;
use aos_sandbox_source_provider_security::CurrentRootMountSourceProviderSessionV1;

use super::{
    FixedMountSourceAcquisitionOwnerV2, format::state_error,
    native_selection::OriginalNativeAcquireFlightV5,
};
use crate::Result;

/// Covers early missing-owner and writer-claim failures as well as stage unwind.
struct OriginalRuntimeBoundaryV5<'owner, 'journal, 'session> {
    owner: &'owner mut FixedMountSourceAcquisitionOwnerV2<'journal>,
    session: &'session mut CurrentRootMountSourceProviderSessionV1,
    succeeded: bool,
}

impl<'owner, 'journal, 'session> OriginalRuntimeBoundaryV5<'owner, 'journal, 'session> {
    fn new(
        owner: &'owner mut FixedMountSourceAcquisitionOwnerV2<'journal>,
        session: &'session mut CurrentRootMountSourceProviderSessionV1,
    ) -> Self {
        Self {
            owner,
            session,
            succeeded: false,
        }
    }

    fn run<R>(
        &mut self,
        operation: impl FnOnce(
            &mut FixedMountSourceAcquisitionOwnerV2<'journal>,
            &mut CurrentRootMountSourceProviderSessionV1,
        ) -> Result<R>,
    ) -> Result<R> {
        let result = operation(self.owner, self.session);
        self.succeeded = result.is_ok();
        result
    }
}

impl Drop for OriginalRuntimeBoundaryV5<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.owner.runtime.invalidate_original_inventory_v6(self.session);
        }
    }
}

impl FixedMountSourceAcquisitionOwnerV2<'_> {
    /// Parks the real admission before any catalog, signature, or journal work.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_original_native_acquire_v5(
        &mut self,
        live: LiveValidatedAcquireMountSourceRequest,
        request: Vec<u8>,
        plan: [u8; 32],
        lease: [u8; 32],
        publication: Vec<u8>,
        catalog: Vec<u8>,
        selection: Option<Vec<u8>>,
        deadline: i64,
    ) -> core::result::Result<(), (crate::MountError, LiveValidatedAcquireMountSourceRequest)> {
        if let Err(error) = self.require_original_start_slot_v5() {
            return Err((error, live));
        }
        self.runtime.pending_original_native = Some(OriginalNativeAcquireFlightV5::new(
            live,
            request,
            plan,
            lease,
            publication,
            catalog,
            selection,
            deadline,
        ));
        Ok(())
    }

    /// Moves genuine Live directly from its caller's slot into the retained flight.
    ///
    /// The caller uses the original entry boundary, which already borrows the
    /// actual Session before broker health and attachment. This method has no
    /// fallible operation after taking Live and does not manufacture admission.
    ///
    /// # Errors
    ///
    /// Preserves Live for an occupied runtime or missing admission slot.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_original_native_acquire_retaining_v5(
        &mut self,
        live: &mut Option<LiveValidatedAcquireMountSourceRequest>,
        request: Vec<u8>,
        plan: [u8; 32],
        lease: [u8; 32],
        publication: Vec<u8>,
        catalog: Vec<u8>,
        selection: Option<Vec<u8>>,
        deadline: i64,
    ) -> Result<()> {
        self.require_original_start_slot_v5()?;
        if live.is_none() {
            return Err(state_error("original Live admission slot is empty"));
        }
        self.runtime.pending_original_native = live.take().map(|live| {
            OriginalNativeAcquireFlightV5::new(
                live,
                request,
                plan,
                lease,
                publication,
                catalog,
                selection,
                deadline,
            )
        });
        Ok(())
    }

    fn require_original_start_slot_v5(&self) -> Result<()> {
        if self.runtime.pending_original_native.is_some()
            || self.runtime.pending_provider.is_some()
            || self.runtime.pending_provider_send.is_some()
            || self.runtime.pending_release_preparation.is_some()
            || !self.runtime.cold_pending_attempts.is_empty()
        {
            return Err(state_error("another original provider owner is retained"));
        }
        Ok(())
    }

    /// Advances one owned original stage, retaining the flight on every error.
    pub(crate) fn advance_original_native_acquire_v5(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<bool> {
        OriginalRuntimeBoundaryV5::new(self, session).run(|owner, session| {
            owner.require_no_original_inventory_v6(session)?;
            let flight = owner
                .runtime
                .pending_original_native
                .as_mut()
                .ok_or_else(|| state_error("original native runtime owner is absent"))?;
            if flight.needs_catalog() {
                let mut authority = owner
                    .protected
                    .source_acquisition_authority()
                    .map_err(|error| state_error(&error.to_string()))?;
                authority.with_authority(|journal| {
                    flight.advance_catalog(&mut owner.runtime.table, journal, session)
                })?;
                return Ok(false);
            }
            let mut writer = owner
                .protected
                .root_original_native_authority_v5()
                .map_err(|error| state_error(&error.to_string()))?;
            let finished = flight.advance(
                &mut owner.runtime.table,
                &mut owner.runtime.original_native_sidecars,
                &mut writer,
                session,
            )?;
            if finished {
                if owner.runtime.pending_provider.is_some() {
                    return Err(state_error("original sent response slot is occupied"));
                }
                if let Some(sent) = flight.take_sent() {
                    // This is the actual same-carrier sent authorization, not a
                    // row-derived outcome permit. Retain the rest of the flight.
                    owner.runtime.pending_provider = Some(sent);
                }
            }
            Ok(finished)
        })
    }

    /// Advances the Pending-only continuation without releasing original custody.
    pub(crate) fn advance_original_native_pending_v5(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<bool> {
        OriginalRuntimeBoundaryV5::new(self, session).run(|owner, session| {
            owner.require_no_original_inventory_v6(session)?;
            let flight = owner
                .runtime
                .pending_original_native
                .as_mut()
                .ok_or_else(|| state_error("original Pending runtime owner is absent"))?;
            let sent = owner
                .runtime
                .pending_provider
                .as_ref()
                .ok_or_else(|| state_error("original Pending actual sent custody is absent"))?;
            let mut writer = owner
                .protected
                .root_original_native_authority_v5()
                .map_err(|error| state_error(&error.to_string()))?;
            flight.advance_pending(
                &mut owner.runtime.table,
                &mut owner.runtime.original_native_sidecars,
                &mut writer,
                session,
                sent,
            )
        })
    }

    /// Advances only original8 through retained signing, storage and local send.
    ///
    /// # Errors
    ///
    /// Retains the original flight and Sent owner on writer/currentness/effect
    /// failure. Successful local send keeps the same owner gate and native2 debt.
    pub(crate) fn advance_original_native_root_closed_v5(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) -> Result<bool> {
        OriginalRuntimeBoundaryV5::new(self, session).run(|owner, session| {
            owner.require_no_original_inventory_v6(session)?;
            let result = (|| {
                let flight = owner
                    .runtime
                    .pending_original_native
                    .as_mut()
                    .ok_or_else(|| state_error("original8 runtime owner is absent"))?;
                let sent = owner
                    .runtime
                    .pending_provider
                    .as_ref()
                    .ok_or_else(|| state_error("original8 actual Sent custody is absent"))?;
                let mut writer = owner
                    .protected
                    .root_original_native_authority_v5()
                    .map_err(|error| state_error(&error.to_string()))?;
                flight.advance_root_closed(
                    &mut owner.runtime.table,
                    &mut owner.runtime.original_native_sidecars,
                    &mut writer,
                    session,
                    sent,
                )
            })();

            // Missing Sent custody and writer-opening failures occur before the
            // flight's stage wrapper. They must revoke the same retained effects.
            if result.is_err() {
                if let Some(flight) = owner.runtime.pending_original_native.as_mut() {
                    flight.stop_root_closed();
                }
                session.invalidate_native_acquire_commit_v3();
            }

            result
        })
    }

    /// Keeps unrelated legacy operations away from retained original owners.
    pub(super) fn require_no_original_native_flight(&self) -> Result<()> {
        if self.runtime.pending_original_native.is_some() {
            return Err(state_error(
                "retained original native flight requires its named continuation",
            ));
        }
        Ok(())
    }
}
