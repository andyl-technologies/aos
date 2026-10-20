//! Retained original8 sign, store, installation and same-carrier send stages.
//!
//! All operations reborrow P's actual token and Sent authorization. The first-R
//! append/readback remain parked independently of the signature-store attempt;
//! neither successful local send nor failure releases the original-flight gate.

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ClosedStage {
    Sign,
    PrepareStore,
    CommitStore,
    Install,
    Send,
    Sent,
}

/// Retains the exact signature-store attempt and its actual physical readback.
pub(super) struct OriginalRootClosedFlightV5 {
    stage: ClosedStage,
    append: Option<PreparedOriginalRootAppendV5>,
}

impl OriginalRootClosedFlightV5 {
    /// Initializes progress beside P's separately retained first-R state.
    pub(super) fn new() -> Self {
        Self {
            stage: ClosedStage::Sign,
            append: None,
        }
    }
}

impl OriginalNativeAcquireFlightV5 {
    /// Borrows actual original owners without refreshing historical readback.
    ///
    /// # Errors
    /// Rejects incomplete/stopped original custody or a substituted Sent/origin.
    pub(in crate::source_acquisition) fn borrow_root_closed_for_inventory_v6<'a>(
        &'a self,
        sent: &'a SentProviderQueryV2,
    ) -> Result<(
        &'a aos_sandbox_source_provider_security::AuthorizedMountProviderOutcomeV2,
        &'a aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5,
        &'a OriginalRootProtectedReadbackV5,
    )> {
        if self.stopped
            || self.stage != Stage::Finished
            || self.sent.is_some()
            || self.pending.stage != PendingStage::Complete
            || self.pending.closed.stage != ClosedStage::Sent
        {
            return Err(state_error("Query requires genuine completed original Closed custody"));
        }
        let received = self.pending.received.as_ref()
            .ok_or_else(|| state_error("original packet absent"))?;
        let origin = self.pending.closed.append.as_ref()
            .ok_or_else(|| state_error("original Closed append absent"))?.readback()?;
        let original = self.attempt.as_ref()
            .ok_or_else(|| state_error("original Attempt absent"))?;
        let (attempt, authorization) = sent.security_parts();
        if attempt != original.attempt_id
            || attempt != origin.attempt()
            || origin.graph().sidecars().get(&attempt)
                .is_none_or(|sidecar| sidecar.suffix().phase() != 11)
        {
            return Err(state_error("original Query borrow has foreign Sent/origin"));
        }

        Ok((authorization, received, origin))
    }

    /// Revokes the actual retained token even when the ready-state borrow fails.
    pub(in crate::source_acquisition) fn stop_original_inventory_v6(
        &mut self,
        session: &mut CurrentRootMountSourceProviderSessionV1,
    ) {
        self.stopped = true;
        session.invalidate_original_inventory_continuation_v6(self.pending.received.as_ref());
    }

    /// Permanently stops original8 without releasing any retained owner or debt.
    pub(in crate::source_acquisition) fn stop_root_closed(&mut self) {
        self.stopped = true;
    }

    /// Advances original8 while retaining P's actual packet and all effect debt.
    ///
    /// # Errors
    ///
    /// Stops the flight and revokes Session effects on any missing custody,
    /// stale readback/guard, signing, append, installation or fatal send failure.
    pub(in crate::source_acquisition) fn advance_root_closed(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        native_index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<bool> {
        OriginalFlightBoundaryV5::new(self, session).run(|flight, session| {
            let result = flight.advance_root_closed_stage(table, native_index, writer, session, sent);
            if result.is_err() {
                flight.stop_root_closed();
                session.invalidate_native_acquire_commit_v3();
            }

            result
        })
    }

    fn advance_root_closed_stage(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        native_index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<bool> {
        if self.stopped
            || self.stage != Stage::Finished
            || self.sent.is_some()
            || self.pending.stage != PendingStage::Complete
        {
            return Err(state_error(
                "original8 requires retained completed Pending custody",
            ));
        }

        let (attempt, authorization) = sent.security_parts();
        let phase10 = self
            .pending
            .append
            .as_ref()
            .ok_or_else(|| state_error("original8 first-R append absent"))?
            .readback()?;
        if phase10.attempt() != attempt {
            return Err(state_error("original8 Sent owner mismatch"));
        }
        let received = self
            .pending
            .received
            .as_mut()
            .ok_or_else(|| state_error("original8 actual Pending packet absent"))?;

        match self.pending.closed.stage {
            ClosedStage::Sign => {
                Self::install(table, native_index, writer, phase10)?;
                session
                    .sign_original_root_closed_v5(writer, phase10, authorization, received)
                    .map_err(|_| {
                        state_error("original8 signature/currentness failed; custody retained")
                    })?;
                self.pending.closed.stage = ClosedStage::PrepareStore;
            }
            ClosedStage::PrepareStore => {
                session
                    .revalidate_original_root_closed_v5(writer, phase10, authorization, received)
                    .map_err(|_| state_error("original8 store preparation lost currentness"))?;
                let signed = received
                    .signed_closed()
                    .ok_or_else(|| state_error("original8 retained signature absent"))?;
                writer.prepare_root_closed_store_v5(phase10, signed, &mut self.pending.closed.append)?;
                session
                    .revalidate_original_root_closed_v5(writer, phase10, authorization, received)
                    .map_err(|_| state_error("original8 prepared store lost currentness"))?;
                self.pending.closed.stage = ClosedStage::CommitStore;
            }
            ClosedStage::CommitStore => {
                session
                    .revalidate_original_root_closed_v5(writer, phase10, authorization, received)
                    .map_err(|_| state_error("original8 commit lost currentness"))?;
                let append = self
                    .pending
                    .closed
                    .append
                    .as_mut()
                    .ok_or_else(|| state_error("original8 store append absent"))?;
                writer.commit_prepared_retaining_v5(append)?;

                // Park the real readback and leave Commit before all postchecks.
                self.pending.closed.stage = ClosedStage::Install;
                let phase11 = self
                    .pending
                    .closed
                    .append
                    .as_ref()
                    .ok_or_else(|| state_error("original8 stored append absent"))?
                    .readback()?;
                session
                    .revalidate_original_root_closed_v5(writer, phase11, authorization, received)
                    .map_err(|_| state_error("original8 actual store lost currentness"))?;
            }
            ClosedStage::Install => {
                let phase11 = self
                    .pending
                    .closed
                    .append
                    .as_ref()
                    .ok_or_else(|| state_error("original8 install append absent"))?
                    .readback()?;
                session
                    .revalidate_original_root_closed_v5(writer, phase11, authorization, received)
                    .map_err(|_| state_error("original8 preinstall lost currentness"))?;
                Self::install(table, native_index, writer, phase11)?;
                session
                    .revalidate_original_root_closed_v5(writer, phase11, authorization, received)
                    .map_err(|_| state_error("original8 installed cut lost currentness"))?;
                self.pending.closed.stage = ClosedStage::Send;
            }
            ClosedStage::Send | ClosedStage::Sent => {
                let phase11 = self
                    .pending
                    .closed
                    .append
                    .as_ref()
                    .ok_or_else(|| state_error("original8 send append absent"))?
                    .readback()?;
                Self::install(table, native_index, writer, phase11)?;
                if !session
                    .send_original_root_closed_v5(writer, phase11, authorization, received)
                    .map_err(|_| {
                        state_error("original8 send/currentness failed; possible debt retained")
                    })?
                {
                    return Ok(false);
                }
                self.pending.closed.stage = ClosedStage::Sent;
                return Ok(true);
            }
        }

        Ok(false)
    }
}
