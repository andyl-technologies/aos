//! Connected original Held/Complete CAS and locally stored RootAccepted4.
//!
//! Four exact transactions use the existing Root native writer/reducer and
//! conserved floor. The child retains every proposal, tentative table, append
//! and actual readback. The named response continuation can send stored Root4
//! once; it cannot settle interest or mint a manager SourceRoot capability.

use aos_sandbox::{JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldCompletionSuffixV1, NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1,
    NativeHeldSectionTagV1 as Tag,
    assertion::RootNativeDispositionAssertionV1,
};
use aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::native_root_sidecar_key_v2;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::source_acquisition::reservation::SentProviderQueryV2;

mod terminal;

#[derive(Clone, Copy, Eq, PartialEq)]
enum PositiveStage {
    PrepareHeld,
    CommitHeld,
    ReceiveComplete,
    PrepareComplete,
    CommitComplete,
    PrepareAccepted,
    PrepareAcceptedAppend,
    CommitAccepted,
    Sign,
    PrepareSigned,
    CommitSigned,
    Complete,
}

/// Retains fixed local phase2-5 legs without a new writer, parser or floor.
pub(super) struct OriginalNativePositiveFlightV5 {
    stage: PositiveStage,
    owners: [Option<JournalTransaction>; 4],
    appends: [Option<PreparedOriginalRootAppendV5>; 4],
    tentative: Option<SourceAcquisitionTableV2>,
    assertion_transaction: Option<[u8; 16]>,
    first_failure: Option<crate::MountError>,
    terminal: terminal::OriginalRootTerminalFlightV5,
}

impl OriginalNativePositiveFlightV5 {
    pub(super) fn new() -> Self {
        Self {
            stage: PositiveStage::PrepareHeld,
            owners: [None, None, None, None],
            appends: [None, None, None, None],
            tentative: None,
            assertion_transaction: None,
            first_failure: None,
            terminal: terminal::OriginalRootTerminalFlightV5::new(),
        }
    }
}

impl OriginalNativeAcquireFlightV5 {
    pub(super) fn original_terminal_selected_v5(&self) -> bool {
        self.positive.terminal.selected()
    }

    pub(super) fn send_stored_positive(
        &mut self,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<bool> {
        OriginalFlightBoundaryV5::new(self, session).run(|flight, session| {
            let result = (|| {
                if flight.stopped || flight.stage != Stage::Finished
                    || flight.sent.is_some() || flight.positive.stage != PositiveStage::Complete
                {
                    return Err(state_error("Root4 requires the actual stored positive endpoint"));
                }
                let phase5 = flight.positive.appends[3].as_ref()
                    .ok_or_else(|| state_error("stored Root4 append absent"))?.readback()?;
                let (attempt, authorization) = sent.security_parts();
                original_sidecar(phase5, attempt, 5)?;
                let received = flight.pending.received.as_mut()
                    .ok_or_else(|| state_error("Root4 original receiver absent"))?;
                session.send_original_root_accepted_v5(writer, phase5, authorization, received)
                    .map_err(|_| state_error("Root4 send or currentness failed; actual cause retained"))
            })();
            match result {
                Ok(sent) => {
                    if sent {
                        flight.positive.terminal.select_after_root4();
                    }
                    Ok(sent)
                }
                Err(cause) => {
                    flight.positive.first_failure.get_or_insert(cause);
                    Err(state_error("Root4 continuation remains retained"))
                }
            }
        })
    }

    pub(in crate::source_acquisition) fn original_response_failure_v5(
        &self,
    ) -> Option<crate::broker::OriginalMountResponseFailureV5<'_>> {
        if self.positive.terminal.selected() {
            return self.original_terminal_failure_v5()
                .map(crate::broker::OriginalMountResponseFailureV5::Terminal);
        }
        if let Some(received) = self.pending.received.as_ref() {
            if let Some(cause) = received.original_accepted_send_failure_v5() {
                return Some(crate::broker::OriginalMountResponseFailureV5::Native(cause));
            }
            let (cause, debt) = received.original_positive_failures_v5();
            if let Some(cause) = cause {
                return Some(crate::broker::OriginalMountResponseFailureV5::Security(cause));
            }
            if let Some(debt) = debt {
                return Some(crate::broker::OriginalMountResponseFailureV5::Security(debt));
            }
        }
        self.positive.first_failure.as_ref()
            .map(crate::broker::OriginalMountResponseFailureV5::Mount)
    }

    pub(in crate::source_acquisition) fn original_response_postcheck_debt_v5(
        &self,
    ) -> Option<&aos_sandbox_source_provider_security::SourceProviderSecurityError> {
        if self.positive.terminal.selected() {
            return self.original_terminal_security_debt_v5();
        }
        self.pending.received.as_ref()
            .and_then(|received| received.original_positive_failures_v5().1)
    }

    pub(super) fn advance_positive(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<bool> {
        let result = self.advance_positive_stage(table, index, writer, session, sent);
        match result {
            Ok(ready) => Ok(ready),
            Err(error) => {
                self.positive.first_failure.get_or_insert(error);
                self.stopped = true;
                session.invalidate_original_inventory_continuation_v6(self.pending.received.as_ref());
                Err(state_error(
                    "original positive continuation failed; owners and cause retained",
                ))
            }
        }
    }

    fn advance_positive_stage(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<bool> {
        if self.stopped || self.stage != Stage::Finished || self.sent.is_some() {
            return Err(state_error("original positive requires the same completed send owner"));
        }
        let (attempt, authorization) = sent.security_parts();
        let received = self.pending.received.as_mut()
            .ok_or_else(|| state_error("original positive received owner absent"))?;
        if !received.has_original_held_v5() {
            return Err(state_error("original positive Held absent"));
        }

        match self.positive.stage {
            PositiveStage::PrepareHeld => {
                let phase1 = self.root1_append.as_ref()
                    .ok_or_else(|| state_error("original positive Root1 absent"))?.readback()?;
                session.revalidate_original_positive_v5(writer, phase1, authorization, received)
                    .map_err(|_| state_error("original Held preappend currentness"))?;
                let old = original_sidecar(phase1, attempt, 1)?;
                let held = received.original_held_v5()
                    .ok_or_else(|| state_error("original positive Held absent"))?;
                let transaction = phase_transaction(old, 2)?;
                let mut controls = old.suffix().controls().to_vec();
                controls.push(held.clone());
                let suffix = NativeHeldCompletionSuffixV1::new(
                    NativeHeldOwnerV1::Root, 2, held.scope().flight, None, controls,
                )
                .map_err(|_| state_error("original Held suffix"))?;
                let next = RootNativeHeldSidecarV2::new(
                    *held.scope(), old.response_transaction(), None, None, None,
                    suffix, old.admission_cut().clone(), None, None,
                )
                .map_err(|_| state_error("original Held sidecar"))?;

                self.positive.owners[0] = Some(sidecar_transaction(transaction, attempt, &next)?);
                writer.prepare_transition_retaining_v5(
                    self.positive.owners[0].as_ref()
                        .ok_or_else(|| state_error("Held proposal absent"))?,
                    attempt,
                    &mut self.positive.appends[0],
                )?;
                session.revalidate_original_positive_v5(writer, phase1, authorization, received)
                    .map_err(|_| state_error("original Held postprepare currentness"))?;
                self.positive.stage = PositiveStage::CommitHeld;
            }
            PositiveStage::CommitHeld => {
                let phase1 = self.root1_append.as_ref()
                    .ok_or_else(|| state_error("original positive Root1 absent"))?.readback()?;
                session.revalidate_original_positive_v5(writer, phase1, authorization, received)
                    .map_err(|_| state_error("original Held precommit currentness"))?;

                let append = self.positive.appends[0].as_mut()
                    .ok_or_else(|| state_error("original Held append absent"))?;
                writer.commit_prepared_retaining_v5(append)?;
                let phase2 = append.readback()?;
                original_sidecar(phase2, attempt, 2)?;
                session.revalidate_original_positive_v5(writer, phase2, authorization, received)
                    .map_err(|_| state_error("actual Held readback currentness"))?;
                Self::install(table, index, writer, phase2)?;
                session.revalidate_original_positive_v5(writer, phase2, authorization, received)
                    .map_err(|_| state_error("installed Held currentness"))?;
                self.positive.stage = PositiveStage::ReceiveComplete;
            }
            PositiveStage::ReceiveComplete => {
                let phase2 = self.positive.appends[0].as_ref()
                    .ok_or_else(|| state_error("original Held readback absent"))?.readback()?;
                if !session.receive_original_complete_v5(writer, phase2, authorization, received)
                    .map_err(|_| state_error("original Complete receive retained"))?
                {
                    return Ok(false);
                }
                self.positive.stage = PositiveStage::PrepareComplete;
            }
            PositiveStage::PrepareComplete => {
                let phase2 = self.positive.appends[0].as_ref()
                    .ok_or_else(|| state_error("original Held readback absent"))?.readback()?;
                session.revalidate_original_positive_v5(writer, phase2, authorization, received)
                    .map_err(|_| state_error("original Complete pre-CAS currentness"))?;
                let old = original_sidecar(phase2, attempt, 2)?;
                let (owners, tentative) =
                    table.prepare_original_complete_disposition_v5(attempt, received)?;
                self.positive.owners[1] = Some(owners);
                self.positive.tentative = Some(tentative);

                let owners = self.positive.owners[1].as_ref()
                    .ok_or_else(|| state_error("original Complete owners absent"))?;
                let suffix = NativeHeldCompletionSuffixV1::new(
                    NativeHeldOwnerV1::Root, 3, old.original_scope().flight,
                    None, old.suffix().controls().to_vec(),
                )
                .map_err(|_| state_error("original Complete suffix"))?;
                let next = RootNativeHeldSidecarV2::new(
                    *old.original_scope(), *owners.id(), None, None, None,
                    suffix, old.admission_cut().clone(), None, None,
                )
                .map_err(|_| state_error("original Complete sidecar"))?;

                // Preserve the existing semantic T/C/H order; sidecar then
                // actual floor DEL/PUT complete the single coupled transaction.
                let mut records = owners.records().to_vec();
                records.extend(sidecar_transaction(*owners.id(), attempt, &next)?.records().iter().cloned());
                self.positive.owners[1] = Some(JournalTransaction::new(*owners.id(), records)?);
                writer.prepare_transition_retaining_v5(
                    self.positive.owners[1].as_ref()
                        .ok_or_else(|| state_error("Complete proposal absent"))?,
                    attempt,
                    &mut self.positive.appends[1],
                )?;
                session.revalidate_original_positive_v5(writer, phase2, authorization, received)
                    .map_err(|_| state_error("original Complete postprepare currentness"))?;
                self.positive.stage = PositiveStage::CommitComplete;
            }
            PositiveStage::CommitComplete => {
                let phase2 = self.positive.appends[0].as_ref()
                    .ok_or_else(|| state_error("original Held readback absent"))?.readback()?;
                session.revalidate_original_positive_v5(writer, phase2, authorization, received)
                    .map_err(|_| state_error("original Complete precommit currentness"))?;

                let append = self.positive.appends[1].as_mut()
                    .ok_or_else(|| state_error("original Complete append absent"))?;
                writer.commit_prepared_retaining_v5(append)?;
                let phase3 = append.readback()?;
                original_sidecar(phase3, attempt, 3)?;
                if self.positive.tentative.as_ref()
                    .is_none_or(|expected| !expected.matches_state(phase3.graph().legacy()))
                {
                    return Err(state_error("Complete proposal differs from actual readback"));
                }
                session.revalidate_original_positive_v5(writer, phase3, authorization, received)
                    .map_err(|_| state_error("actual Complete CAS currentness/physical original"))?;
                Self::install(table, index, writer, phase3)?;
                session.revalidate_original_positive_v5(writer, phase3, authorization, received)
                    .map_err(|_| state_error("installed Complete CAS currentness"))?;
                self.positive.stage = PositiveStage::PrepareAccepted;
            }
            PositiveStage::PrepareAccepted => {
                let phase3 = self.positive.appends[1].as_ref()
                    .ok_or_else(|| state_error("original Complete readback absent"))?.readback()?;
                let old = original_sidecar(phase3, attempt, 3)?;
                let transaction = phase_transaction(old, 4)?;
                self.positive.assertion_transaction = Some(transaction);
                let sequence = phase3.sequence().checked_add(5)
                    .ok_or_else(|| state_error("original RootAccepted sequence exhausted"))?;
                session.prepare_original_root_accepted_v5(
                    writer, phase3, authorization, received, transaction, sequence,
                )
                .map_err(|_| state_error("original RootAccepted preparation retained"))?;
                self.positive.stage = PositiveStage::PrepareAcceptedAppend;
            }
            PositiveStage::PrepareAcceptedAppend => {
                let phase3 = self.positive.appends[1].as_ref()
                    .ok_or_else(|| state_error("original Complete readback absent"))?.readback()?;
                session.revalidate_original_positive_v5(writer, phase3, authorization, received)
                    .map_err(|_| state_error("original RootAccepted preappend currentness"))?;
                let old = original_sidecar(phase3, attempt, 3)?;
                let next = accepted_successor(old, received, 4)?;
                let transaction = self.positive.assertion_transaction
                    .ok_or_else(|| state_error("original RootAccepted transaction absent"))?;
                self.positive.owners[2] = Some(sidecar_transaction(transaction, attempt, &next)?);
                writer.prepare_transition_retaining_v5(
                    self.positive.owners[2].as_ref()
                        .ok_or_else(|| state_error("RootAccepted proposal absent"))?,
                    attempt,
                    &mut self.positive.appends[2],
                )?;
                session.revalidate_original_positive_v5(writer, phase3, authorization, received)
                    .map_err(|_| state_error("original RootAccepted postprepare currentness"))?;
                self.positive.stage = PositiveStage::CommitAccepted;
            }
            PositiveStage::CommitAccepted => {
                let phase3 = self.positive.appends[1].as_ref()
                    .ok_or_else(|| state_error("original Complete readback absent"))?.readback()?;
                session.revalidate_original_positive_v5(writer, phase3, authorization, received)
                    .map_err(|_| state_error("original RootAccepted precommit currentness"))?;

                let append = self.positive.appends[2].as_mut()
                    .ok_or_else(|| state_error("original RootAccepted append absent"))?;
                writer.commit_prepared_retaining_v5(append)?;
                let phase4 = append.readback()?;
                original_sidecar(phase4, attempt, 4)?;
                session.revalidate_original_positive_v5(writer, phase4, authorization, received)
                    .map_err(|_| state_error("actual unsigned RootAccepted readback currentness"))?;
                Self::install(table, index, writer, phase4)?;
                session.revalidate_original_positive_v5(writer, phase4, authorization, received)
                    .map_err(|_| state_error("installed unsigned RootAccepted currentness"))?;
                self.positive.stage = PositiveStage::Sign;
            }
            PositiveStage::Sign => {
                let phase4 = self.positive.appends[2].as_ref()
                    .ok_or_else(|| state_error("original RootAccepted readback absent"))?.readback()?;
                session.sign_original_root_accepted_v5(writer, phase4, authorization, received)
                    .map_err(|_| state_error("original RootAccepted signature retained"))?;
                self.positive.stage = PositiveStage::PrepareSigned;
            }
            PositiveStage::PrepareSigned => {
                let phase4 = self.positive.appends[2].as_ref()
                    .ok_or_else(|| state_error("original RootAccepted readback absent"))?.readback()?;
                session.revalidate_original_positive_v5(writer, phase4, authorization, received)
                    .map_err(|_| state_error("signed RootAccepted preappend currentness"))?;
                let old = original_sidecar(phase4, attempt, 4)?;
                let next = accepted_successor(old, received, 5)?;
                self.positive.owners[3] = Some(sidecar_transaction(
                    phase_transaction(old, 5)?, attempt, &next,
                )?);
                writer.prepare_transition_retaining_v5(
                    self.positive.owners[3].as_ref()
                        .ok_or_else(|| state_error("signed RootAccepted proposal absent"))?,
                    attempt,
                    &mut self.positive.appends[3],
                )?;
                session.revalidate_original_positive_v5(writer, phase4, authorization, received)
                    .map_err(|_| state_error("signed RootAccepted postprepare currentness"))?;
                self.positive.stage = PositiveStage::CommitSigned;
            }
            PositiveStage::CommitSigned => {
                let phase4 = self.positive.appends[2].as_ref()
                    .ok_or_else(|| state_error("original RootAccepted readback absent"))?.readback()?;
                session.revalidate_original_positive_v5(writer, phase4, authorization, received)
                    .map_err(|_| state_error("signed RootAccepted precommit currentness"))?;

                let append = self.positive.appends[3].as_mut()
                    .ok_or_else(|| state_error("signed RootAccepted append absent"))?;
                writer.commit_prepared_retaining_v5(append)?;
                let phase5 = append.readback()?;
                original_sidecar(phase5, attempt, 5)?;
                session.revalidate_original_positive_v5(writer, phase5, authorization, received)
                    .map_err(|_| state_error("actual signed RootAccepted currentness"))?;
                Self::install(table, index, writer, phase5)?;
                session.revalidate_original_positive_v5(writer, phase5, authorization, received)
                    .map_err(|_| state_error("installed signed RootAccepted currentness"))?;
                self.positive.stage = PositiveStage::Complete;
            }
            PositiveStage::Complete => {
                let phase5 = self.positive.appends[3].as_ref()
                    .ok_or_else(|| state_error("signed RootAccepted endpoint absent"))?.readback()?;
                original_sidecar(phase5, attempt, 5)?;
                session.revalidate_original_positive_v5(writer, phase5, authorization, received)
                    .map_err(|_| state_error("stored RootAccepted endpoint currentness"))?;
                return Ok(true);
            }
        }
        Ok(self.positive.stage == PositiveStage::Complete)
    }
}

fn original_sidecar(
    readback: &OriginalRootProtectedReadbackV5,
    attempt: [u8; 32],
    phase: u8,
) -> Result<&RootNativeHeldSidecarV2> {
    if readback.attempt() != attempt {
        return Err(state_error("original positive readback belongs to another attempt"));
    }
    readback.graph().sidecars().get(&attempt)
        .filter(|sidecar| sidecar.suffix().phase() == phase)
        .ok_or_else(|| state_error("original positive phase mismatch"))
}

fn phase_transaction(old: &RootNativeHeldSidecarV2, phase: u8) -> Result<[u8; 16]> {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.root.original-positive.transaction.v5\0");
    digest.update([phase]);
    digest.update(old.to_canonical_bytes().map_err(|_| state_error("original predecessor encoding"))?);
    let digest: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(id)
}

fn sidecar_transaction(
    id: [u8; 16],
    attempt: [u8; 32],
    sidecar: &RootNativeHeldSidecarV2,
) -> Result<JournalTransaction> {
    let key = native_root_sidecar_key_v2(attempt).map_err(|_| state_error("original sidecar key"))?;
    let value = sidecar.to_canonical_bytes().map_err(|_| state_error("original sidecar encoding"))?;
    Ok(JournalTransaction::new(
        id,
        vec![JournalRecord::put(RecordNamespace::MountSourceAcquisition, key, value)],
    )?)
}

fn accepted_successor(
    old: &RootNativeHeldSidecarV2,
    received: &aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5,
    phase: u8,
) -> Result<RootNativeHeldSidecarV2> {
    let unsigned = received.original_unsigned_accepted_v5()
        .ok_or_else(|| state_error("original unsigned RootAccepted absent"))?;
    let assertion = RootNativeDispositionAssertionV1::from_canonical_bytes(
        unsigned.section(Tag::RootDispositionAssertion)
            .ok_or_else(|| state_error("original RootAccepted assertion absent"))?,
    )
    .map_err(|_| state_error("original RootAccepted assertion"))?;
    let mut controls = old.suffix().controls().to_vec();
    let prepared = match phase {
        4 => Some(unsigned.clone()),
        5 => {
            controls.push(received.original_signed_accepted_v5()
                .ok_or_else(|| state_error("original signed RootAccepted absent"))?.clone());
            None
        }
        _ => return Err(state_error("unsupported original positive successor")),
    };
    let suffix = NativeHeldCompletionSuffixV1::new(
        NativeHeldOwnerV1::Root, phase, old.original_scope().flight, prepared, controls,
    )
    .map_err(|_| state_error("original RootAccepted suffix"))?;
    RootNativeHeldSidecarV2::new(
        *old.original_scope(), old.response_transaction(), Some(assertion), None,
        None, suffix, old.admission_cut().clone(),
        Some(received.original_accepted_cut_v5()
            .ok_or_else(|| state_error("original RootAccepted cut absent"))?
            .clone()),
        None,
    )
    .map_err(|_| state_error("original RootAccepted sidecar"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_flight_is_staging_not_a_root_owner_or_phase5_result() {
        let progress = OriginalNativePositiveFlightV5::new();

        assert!(progress.stage == PositiveStage::PrepareHeld);
        assert!(progress.owners.iter().all(Option::is_none));
        assert!(progress.appends.iter().all(Option::is_none));
        assert!(progress.tentative.is_none());
        assert!(progress.assertion_transaction.is_none());
        assert!(progress.first_failure.is_none());
    }
}
