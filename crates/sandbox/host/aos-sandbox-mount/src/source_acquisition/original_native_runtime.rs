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

    /// Parks every selected original input before any native stage can run.
    ///
    /// Occupancy and all mandatory slots are checked before taking originals.
    /// The tuple fallback restores the same objects without I/O or allocation;
    /// successful assembly is the existing infallible flight constructor.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_signed_original_native_acquire_v5(
        &mut self,
        live: &mut Option<LiveValidatedAcquireMountSourceRequest>,
        request: &mut Option<Vec<u8>>,
        plan: [u8; 32],
        lease: [u8; 32],
        publication: &mut Option<Vec<u8>>,
        catalog: &mut Option<Vec<u8>>,
        selection: &mut Option<Vec<u8>>,
        deadline: i64,
    ) -> Result<()> {
        self.require_original_start_slot_v5()?;
        if live.is_none() || request.is_none() || publication.is_none() || catalog.is_none() {
            return Err(state_error("selected original input slots are incomplete"));
        }

        match (live.take(), request.take(), publication.take(), catalog.take()) {
            (Some(live), Some(request), Some(publication), Some(catalog)) => {
                self.runtime.pending_original_native = Some(OriginalNativeAcquireFlightV5::new(
                    live,
                    request,
                    plan,
                    lease,
                    publication,
                    catalog,
                    selection.take(),
                    deadline,
                ));
                Ok(())
            }
            (actual_live, actual_request, actual_publication, actual_catalog) => {
                *live = actual_live;
                *request = actual_request;
                *publication = actual_publication;
                *catalog = actual_catalog;
                Err(state_error("selected original input association changed"))
            }
        }
    }

    /// Advances the same recipe under the genuine reopened domain-effect loan.
    pub(crate) fn advance_signed_original_native_acquire_v5(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        effect: &mut crate::broker::OriginalMountSignedEffectLoanV1<'_>,
    ) -> Result<bool> {
        OriginalRuntimeBoundaryV5::new(self, session).run(|owner, session| {
            effect.check_before_original_effect()?;
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
                effect.check_before_original_effect()?;
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
            effect.check_before_original_effect()?;
            Ok(finished)
        })
    }

    /// Borrows the existing writer/runtime/effect around the named response.
    pub(crate) fn advance_signed_original_response_v5(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        effect: &mut crate::broker::OriginalMountSignedEffectLoanV1<'_>,
    ) -> Result<crate::broker::OriginalMountResponseProgressV5> {
        OriginalRuntimeBoundaryV5::new(self, session).run(|owner, session| {
            effect.check_before_original_effect()?;
            owner.require_no_original_inventory_v6(session)?;
            let flight = owner.runtime.pending_original_native.as_mut()
                .ok_or_else(|| state_error("original response flight absent"))?;
            let sent = owner.runtime.pending_provider.as_ref()
                .ok_or_else(|| state_error("original response Sent custody absent"))?;
            let terminal = flight.prearm_original_terminal_claim_v5()?;
            let claimed = owner.protected.root_original_native_authority_v5();
            let mut writer = match claimed {
                Ok(writer) => {
                    if terminal {
                        flight.complete_original_terminal_claim_v5();
                    }
                    writer
                }
                Err(cause) if terminal => {
                    flight.retain_original_terminal_claim_error_v5(cause);
                    return Err(state_error("original terminal writer claim failed; actual cause retained"));
                }
                Err(cause) => return Err(state_error(&cause.to_string())),
            };
            let progress = flight.advance_original_response_v5(
                &mut owner.runtime.table,
                &mut owner.runtime.original_native_sidecars,
                &mut writer,
                session,
                sent,
            )?;
            effect.check_before_original_effect()?;
            Ok(progress)
        })
    }

    /// Parks the independently admitted Release in the existing original flight.
    pub(crate) fn begin_signed_original_release_v1(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        live: &mut Option<aos_sandbox_protocol::LiveValidatedReleaseMountSourceAcquisitionRequest>,
        body: &mut Option<Vec<u8>>,
        deadline: i64,
    ) -> Result<()> {
        OriginalRuntimeBoundaryV5::new(self, session).run(|owner, _session| {
            let flight = owner.runtime.pending_original_native.as_mut()
                .ok_or_else(|| state_error("original Release flight is absent"))?;
            flight.begin_original_release_v1(live, body, deadline)
        })
    }

    /// Reborrows the same writer for the independently admitted Release.
    pub(crate) fn advance_signed_original_release_v1(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        effect: &mut crate::broker::OriginalMountReleaseEffectLoanV1<'_>,
    ) -> Result<crate::broker::OriginalMountReleaseProgressV1> {
        OriginalRuntimeBoundaryV5::new(self, session).run(|owner, session| {
            effect.check_before_release_effect()?;
            let flight = owner.runtime.pending_original_native.as_mut()
                .ok_or_else(|| state_error("original Release flight is absent"))?;
            let sent = owner.runtime.pending_provider.as_ref()
                .ok_or_else(|| state_error("original Release Sent custody is absent"))?;
            flight.prearm_original_release_claim_v1()?;
            let claimed = owner.protected.root_original_native_authority_v5();
            let mut writer = match claimed {
                Ok(writer) => {
                    flight.retain_original_release_claim_v1(Ok(()));
                    writer
                }
                Err(cause) => {
                    flight.retain_original_release_claim_v1(Err(cause));
                    return Err(state_error("original Release writer claim failed; actual cause retained"));
                }
            };
            flight.advance_original_release_v1(
                &mut owner.runtime.table,
                &mut owner.runtime.original_native_sidecars,
                &mut writer,
                session,
                sent,
                effect,
            )
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

impl super::SourceAcquisitionRuntimeV2 {
    pub(crate) fn original_release_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.pending_original_native.as_ref()
            .and_then(OriginalNativeAcquireFlightV5::original_release_failure_v1)
    }

    pub(crate) fn original_release_postcheck_debt_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.pending_original_native.as_ref()
            .and_then(OriginalNativeAcquireFlightV5::original_release_postcheck_debt_v1)
    }

    pub(crate) fn original_response_failure_v5(
        &self,
    ) -> Option<crate::broker::OriginalMountResponseFailureV5<'_>> {
        self.pending_original_native.as_ref()
            .and_then(OriginalNativeAcquireFlightV5::original_response_failure_v5)
    }

    pub(crate) fn original_response_postcheck_debt_v5(
        &self,
    ) -> Option<&aos_sandbox_source_provider_security::SourceProviderSecurityError> {
        self.pending_original_native.as_ref()
            .and_then(OriginalNativeAcquireFlightV5::original_response_postcheck_debt_v5)
    }
}
