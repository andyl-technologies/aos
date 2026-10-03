//! Owned Pending receive, first Closed append, readback and table installation.
//!
//! The actual Sent authorization remains in the runtime's named response slot.
//! This continuation borrows it without releasing the original flight, received
//! packet, unsigned8, tentative owners or attempted coupled append on failure.

use aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5;

use super::*;
use crate::source_acquisition::reservation::SentProviderQueryV2;

mod root_closed;

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingStage {
    Receive,
    PrepareOwners,
    PrepareUnsigned,
    PrepareAppend,
    Commit,
    Complete,
}

pub(super) struct OriginalNativePendingFlightV5 {
    stage: PendingStage,
    received: Option<OriginalNativeReceivedOutcomeV5>,
    owners: Option<JournalTransaction>,
    tentative: Option<SourceAcquisitionTableV2>,
    append: Option<PreparedOriginalRootAppendV5>,
    closed: root_closed::OriginalRootClosedFlightV5,
}

impl OriginalNativePendingFlightV5 {
    pub(super) fn new() -> Self {
        Self {
            stage: PendingStage::Receive,
            received: None,
            owners: None,
            tentative: None,
            append: None,
            closed: root_closed::OriginalRootClosedFlightV5::new(),
        }
    }
}

impl OriginalNativeAcquireFlightV5 {
    /// Advances only actual original zero-FD Pending; positive paths stay closed.
    pub(in crate::source_acquisition) fn advance_pending(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        native_index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<bool> {
        OriginalFlightBoundaryV5::new(self, session).run(|flight, session| {
            if flight.stopped || flight.stage != Stage::Finished || flight.sent.is_some() {
                return Err(state_error(
                    "original Pending requires retained completed send custody",
                ));
            }

            let result = flight.advance_pending_stage(table, native_index, writer, session, sent);
            if result.is_err() {
                flight.stopped = true;
                session.invalidate_native_acquire_commit_v3();
            }
            result
        })
    }

    fn advance_pending_stage(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        native_index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<bool> {
        let phase1 = self
            .root1_append
            .as_ref()
            .ok_or_else(|| state_error("original Pending stored Root1 append absent"))?
            .readback()?;
        let (attempt, authorization) = sent.security_parts();
        if phase1.attempt() != attempt {
            return Err(state_error("original Pending sent owner mismatch"));
        }

        match self.pending.stage {
            PendingStage::Receive => {
                Self::install(table, native_index, writer, phase1)?;
                if !session
                    .advance_original_native_outcome_receive_v5(
                        writer,
                        phase1,
                        authorization,
                        &mut self.pending.received,
                    )
                    .map_err(|_| state_error("original Pending receive is retained/closed"))?
                {
                    return Ok(false);
                }
                self.pending.stage = PendingStage::PrepareOwners;
            }
            PendingStage::PrepareOwners => {
                let received = self
                    .pending
                    .received
                    .as_ref()
                    .ok_or_else(|| state_error("original Pending packet absent"))?;
                session
                    .revalidate_original_pending_receipt_v5(writer, phase1, authorization, received)
                    .map_err(|_| state_error("original Pending owner currentness failed"))?;
                let outcome = received
                    .verified_pending()
                    .ok_or_else(|| state_error("original Pending verifier absent"))?;
                let (owners, tentative) =
                    table.prepare_original_pending_disposition_v5(attempt, outcome)?;

                self.pending.owners = Some(owners);
                self.pending.tentative = Some(tentative);
                self.pending.stage = PendingStage::PrepareUnsigned;
            }
            PendingStage::PrepareUnsigned => {
                let received = self
                    .pending
                    .received
                    .as_mut()
                    .ok_or_else(|| state_error("original Pending packet absent"))?;
                let owners = self
                    .pending
                    .owners
                    .as_ref()
                    .ok_or_else(|| state_error("original Pending owners absent"))?;
                session
                    .prepare_original_pending_closed_v5(
                        writer,
                        phase1,
                        authorization,
                        received,
                        owners,
                    )
                    .map_err(|_| state_error("original Pending unsigned8 preparation failed"))?;
                self.pending.stage = PendingStage::PrepareAppend;
            }
            PendingStage::PrepareAppend => {
                let received = self
                    .pending
                    .received
                    .as_ref()
                    .ok_or_else(|| state_error("original Pending packet absent"))?;
                session
                    .revalidate_original_pending_receipt_v5(writer, phase1, authorization, received)
                    .map_err(|_| state_error("original Pending append currentness failed"))?;
                let owners = self
                    .pending
                    .owners
                    .as_ref()
                    .ok_or_else(|| state_error("original Pending owners absent"))?;
                let unsigned = received
                    .unsigned_closed()
                    .ok_or_else(|| state_error("original Pending unsigned8 absent"))?;

                writer.prepare_original_pending_closed_v5(
                    phase1,
                    owners,
                    unsigned,
                    &mut self.pending.append,
                )?;
                self.pending.stage = PendingStage::Commit;
            }
            PendingStage::Commit => {
                let received = self
                    .pending
                    .received
                    .as_ref()
                    .ok_or_else(|| state_error("original Pending packet absent"))?;
                session
                    .revalidate_original_pending_receipt_v5(writer, phase1, authorization, received)
                    .map_err(|_| state_error("original Pending commit currentness failed"))?;

                // The exact coupled append stays borrowed through an ambiguous
                // commit. Its transaction identity is never reminted on retry.
                let append = self
                    .pending
                    .append
                    .as_mut()
                    .ok_or_else(|| state_error("original Pending append absent"))?;
                writer.commit_prepared_retaining_v5(append)?;
                let readback = append.readback()?;
                session
                    .revalidate_original_pending_receipt_v5(writer, readback, authorization, received)
                    .map_err(|_| state_error("original Pending actual readback differs from receipt"))?;
                if self
                    .pending
                    .tentative
                    .as_ref()
                    .is_none_or(|expected| !expected.matches_state(readback.graph().legacy()))
                {
                    return Err(state_error(
                        "original Pending proposal differs from physical successor",
                    ));
                }

                Self::install(table, native_index, writer, readback)?;
                session
                    .revalidate_original_pending_receipt_v5(writer, readback, authorization, received)
                    .map_err(|_| state_error("original Pending installed cut lost currentness"))?;
                self.pending.stage = PendingStage::Complete;
            }
            PendingStage::Complete => {
                let readback = self
                    .pending
                    .append
                    .as_ref()
                    .ok_or_else(|| state_error("original Pending append absent"))?
                    .readback()?;
                Self::install(table, native_index, writer, readback)?;
                let received = self
                    .pending
                    .received
                    .as_ref()
                    .ok_or_else(|| state_error("original Pending packet absent"))?;
                session
                    .revalidate_original_pending_receipt_v5(writer, readback, authorization, received)
                    .map_err(|_| state_error("original Pending completed cut lost currentness"))?;
                return Ok(true);
            }
        }

        Ok(self.pending.stage == PendingStage::Complete)
    }
}
