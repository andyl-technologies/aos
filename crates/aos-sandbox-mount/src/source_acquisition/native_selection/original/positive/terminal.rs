//! Original phase5 -> phase6/7 append custody and same-carrier Root13 delivery.
//!
//! The parent retains phase2..5 and the genuine received owner. Only its actual
//! successful Root4 call selects this inline child; no public phase or progress
//! DATA can initialize it. Every append Result and typed claim cause stays here.

use aos_sandbox::{JournalError, JournalLimits, MountManagerSourceInventoryError};
use aos_sandbox_source_provider_protocol::native_held_completion::assertion::NativeHeldSettlementV1;

use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum TerminalStage {
    Dormant,
    Receive,
    PrepareUnsigned,
    PrepareAppend,
    CommitUnsigned,
    Sign,
    PrepareSigned,
    CommitSigned,
    Send,
    Complete,
}

#[derive(Clone, Copy)]
enum FirstFailure {
    Claim,
    Journal,
    Prepare(usize),
    Commit(usize),
    Install(usize, usize),
    InstallStatus(usize),
    Security,
    Mount,
}

pub(super) struct OriginalRootTerminalFlightV5 {
    stage: TerminalStage,
    claim_pending: bool,
    claim_failure: Option<MountManagerSourceInventoryError>,
    journal_failure: Option<JournalError>,
    first: Option<FirstFailure>,
    mount_failure: Option<crate::MountError>,
    mount_debt: Option<crate::MountError>,
    limits: Option<JournalLimits>,
    owners: [Option<JournalTransaction>; 2],
    appends: [Option<PreparedOriginalRootAppendV5>; 2],
    preparations: [Option<std::result::Result<(), JournalError>>; 2],
    commits: [Option<std::result::Result<(), JournalError>>; 2],
    installations: [[Option<std::result::Result<(), JournalError>>; 2]; 2],
    installation_results: [Option<Result<()>>; 2],
    installation_pending: Option<usize>,
    transaction: Option<[u8; 16]>,
    observed_materialized_bytes: usize,
    observed_materialized_records: usize,
}

impl OriginalRootTerminalFlightV5 {
    pub(super) fn new() -> Self {
        Self {
            stage: TerminalStage::Dormant,
            claim_pending: false,
            claim_failure: None,
            journal_failure: None,
            first: None,
            mount_failure: None,
            mount_debt: None,
            limits: None,
            owners: [None, None],
            appends: [None, None],
            preparations: [None, None],
            commits: [None, None],
            installations: [[None, None], [None, None]],
            installation_results: [None, None],
            installation_pending: None,
            transaction: None,
            observed_materialized_bytes: 0,
            observed_materialized_records: 0,
        }
    }

    pub(super) fn selected(&self) -> bool {
        self.stage != TerminalStage::Dormant
    }

    pub(super) fn select_after_root4(&mut self) {
        if self.stage == TerminalStage::Dormant {
            self.stage = TerminalStage::Receive;
        }
    }

    fn failure<'a>(
        &'a self,
        received: Option<&'a aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5>,
    ) -> Option<&'a (dyn std::error::Error + 'static)> {
        let first = self.first.or_else(|| {
            // Even a display unwind happens AFTER the actual Err was parked.
            let phase = self.installation_pending?;
            self.installations[phase].iter().position(|result| matches!(result, Some(Err(_))))
                .map(|site| FirstFailure::Install(phase, site))
        })?;
        match first {
            FirstFailure::Claim => self.claim_failure.as_ref().map(|cause| cause as &dyn std::error::Error),
            FirstFailure::Journal => self.journal_failure.as_ref().map(|cause| cause as &dyn std::error::Error),
            FirstFailure::Prepare(index) => self.preparations[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error),
            FirstFailure::Commit(index) => self.commits[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error),
            FirstFailure::Install(phase, site) => self.installations[phase][site].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error),
            FirstFailure::InstallStatus(phase) => self.installation_results[phase].as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error),
            FirstFailure::Security => received.and_then(|received| received.original_terminal_failure_v5()),
            FirstFailure::Mount => self.mount_failure.as_ref().map(|cause| cause as &dyn std::error::Error),
        }
    }

}

// The error is moved before the caller can stringify it or observe another
// owner. Successful readback is only borrowed, never stored inside this child.
fn retained_readback<'append>(
    append: &'append Option<PreparedOriginalRootAppendV5>,
    cause: &mut Option<JournalError>,
    first: &mut Option<FirstFailure>,
) -> Result<&'append OriginalRootProtectedReadbackV5> {
    if cause.is_some() {
        return Err(state_error("original terminal readback cause already resident"));
    }
    let append = append.as_ref().ok_or_else(|| state_error("original terminal append absent"))?;
    match append.readback() {
        Ok(readback) => Ok(readback),
        Err(error) => {
            *cause = Some(error);
            first.get_or_insert(FirstFailure::Journal);
            Err(state_error("original terminal readback refused; actual cause retained"))
        }
    }
}

impl OriginalNativeAcquireFlightV5 {
    /// Returns only private routing DATA; ordinary selection performs no IO.
    pub(in crate::source_acquisition) fn prearm_original_terminal_claim_v5(&mut self) -> Result<bool> {
        let terminal = &mut self.positive.terminal;
        if !terminal.selected() {
            return Ok(false);
        }
        if self.stopped || terminal.claim_pending || terminal.first.is_some()
            || terminal.claim_failure.is_some()
        {
            return Err(state_error("original terminal writer claim ended"));
        }
        terminal.claim_pending = true;
        Ok(true)
    }

    pub(in crate::source_acquisition) fn complete_original_terminal_claim_v5(&mut self) {
        self.positive.terminal.claim_pending = false;
    }

    // The closed caller checked the destination before the SAME single claim;
    // no other field mutation/observation occurs between its Err and this park.
    pub(in crate::source_acquisition) fn retain_original_terminal_claim_error_v5(
        &mut self,
        cause: MountManagerSourceInventoryError,
    ) {
        let terminal = &mut self.positive.terminal;
        terminal.claim_failure = Some(cause);
        terminal.first = Some(FirstFailure::Claim);
        self.stopped = true;
    }

    pub(super) fn original_terminal_failure_v5(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.positive.terminal.failure(self.pending.received.as_ref())
    }

    pub(super) fn original_terminal_security_debt_v5(
        &self,
    ) -> Option<&aos_sandbox_source_provider_security::SourceProviderSecurityError> {
        let received = self.pending.received.as_ref()?;
        let postcheck = received.original_terminal_postcheck_debt_v5();
        if matches!(self.positive.terminal.first, Some(FirstFailure::Security)) {
            postcheck
        } else {
            let owner = received.original_terminal_owner_post_v5()
                .and_then(|result| result.as_ref().err());
            let clock = received.original_terminal_clock_post_v5()
                .and_then(|result| result.as_ref().err());
            owner.or(clock).or(postcheck)
                .or_else(|| received.original_terminal_security_failure_v5())
        }
    }

    pub(in crate::source_acquisition::native_selection::original) fn advance_original_terminal_v5(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<crate::broker::OriginalMountResponseProgressV5> {
        OriginalFlightBoundaryV5::new(self, session).run(|flight, session| {
            let result = flight.advance_original_terminal_stage_v5(table, index, writer, session, sent);
            if let Err(cause) = result {
                let terminal = &mut flight.positive.terminal;
                if terminal.first.is_none() {
                    if flight.pending.received.as_ref()
                        .and_then(|received| received.original_terminal_failure_v5()).is_some()
                    {
                        terminal.first = Some(FirstFailure::Security);
                    } else {
                        terminal.mount_failure = Some(cause);
                        terminal.first = Some(FirstFailure::Mount);
                    }
                } else if terminal.mount_debt.is_none() {
                    terminal.mount_debt = Some(cause);
                }
                return Err(state_error("original terminal remains resident and ended"));
            }
            result
        })
    }

    fn advance_original_terminal_stage_v5(
        &mut self,
        table: &mut SourceAcquisitionTableV2,
        index: &mut BTreeMap<[u8; 32], RootNativeHeldSidecarV2>,
        writer: &mut MountOriginalNativeJournalAuthorityV5<'_>,
        session: &mut CurrentRootMountSourceProviderSessionV1,
        sent: &SentProviderQueryV2,
    ) -> Result<crate::broker::OriginalMountResponseProgressV5> {
        use crate::broker::OriginalMountResponseProgressV5 as Progress;
        let terminal = &mut self.positive.terminal;
        if self.stopped || self.stage != Stage::Finished || self.sent.is_some()
            || !terminal.selected() || terminal.first.is_some() || terminal.claim_pending
        {
            return Err(state_error("original terminal requires the same healthy Root4 owner"));
        }
        let (attempt, authorization) = sent.security_parts();
        let received = self.pending.received.as_mut()
            .ok_or_else(|| state_error("original terminal receiver absent"))?;
        {
            let before_slot = match terminal.stage {
                TerminalStage::Receive | TerminalStage::PrepareUnsigned
                | TerminalStage::PrepareAppend | TerminalStage::CommitUnsigned => &self.positive.appends[3],
                TerminalStage::Sign | TerminalStage::PrepareSigned
                | TerminalStage::CommitSigned => &terminal.appends[0],
                TerminalStage::Send | TerminalStage::Complete => &terminal.appends[1],
                TerminalStage::Dormant => return Err(state_error("original terminal not selected")),
            };
            let before = retained_readback(before_slot, &mut terminal.journal_failure, &mut terminal.first)?;

            // Account the complete current graph before allocating another
            // proposal or append copy. This is not a runtime funding proof.
            let opened = writer.configured_limits();
            if terminal.limits.is_some_and(|previous| previous != opened) {
                return Err(state_error("original terminal opened ceilings changed"));
            }
            terminal.limits = Some(opened);
            let rows = before.graph().canonical_records();
            terminal.observed_materialized_bytes = rows.iter().try_fold(0usize, |bytes, (key, value)| {
                bytes.checked_add(key.len()).and_then(|bytes| bytes.checked_add(value.len()))
                    .ok_or_else(|| state_error("original terminal graph byte overflow"))
            })?;
            terminal.observed_materialized_records = rows.len();
            if terminal.observed_materialized_bytes > opened.maximum_materialized_bytes
                || terminal.observed_materialized_records > opened.maximum_materialized_records
            {
                return Err(state_error("original terminal graph exceeds opened ceilings"));
            }
        }

        match terminal.stage {
            TerminalStage::Receive => {
                let before = retained_readback(&self.positive.appends[3], &mut terminal.journal_failure, &mut terminal.first)?;
                if !session.receive_original_provider_settled_v5(writer, before, authorization, received)
                    .map_err(|_| state_error("original Source7 reception retained"))?
                {
                    return Ok(Progress::Waiting);
                }
                terminal.stage = TerminalStage::PrepareUnsigned;
            }
            TerminalStage::PrepareUnsigned => {
                let before = retained_readback(&self.positive.appends[3], &mut terminal.journal_failure, &mut terminal.first)?;
                let old = original_sidecar(before, attempt, 5)?;
                let transaction = phase_transaction(old, 6)?;
                terminal.transaction = Some(transaction);
                let sequence = before.sequence().checked_add(5)
                    .ok_or_else(|| state_error("original terminal sequence exhausted"))?;
                session.prepare_original_root_terminal_v5(
                    writer, before, authorization, received, transaction, sequence,
                ).map_err(|_| state_error("original Root13 preparation retained"))?;
                terminal.stage = TerminalStage::PrepareAppend;
            }
            TerminalStage::PrepareAppend | TerminalStage::PrepareSigned => {
                let phase = if terminal.stage == TerminalStage::PrepareAppend { 6 } else { 7 };
                let [unsigned_append, signed_append] = &mut terminal.appends;
                let (before_slot, destination) = if phase == 6 {
                    (&self.positive.appends[3], unsigned_append)
                } else {
                    (&*unsigned_append, signed_append)
                };
                let before = retained_readback(before_slot, &mut terminal.journal_failure, &mut terminal.first)?;
                session.revalidate_original_terminal_v5(writer, before, authorization, received)
                    .map_err(|_| state_error("original terminal preprepare currentness"))?;
                let slot = usize::from(phase == 7);
                if terminal.owners[slot].is_some() || destination.is_some()
                    || terminal.preparations[slot].is_some()
                {
                    return Err(state_error("original terminal preparation already occupied"));
                }
                let old = original_sidecar(before, attempt, phase - 1)?;
                let next = terminal_successor(old, received, phase)?;
                let transaction = if phase == 6 {
                    terminal.transaction.ok_or_else(|| state_error("original terminal TX absent"))?
                } else {
                    phase_transaction(old, phase)?
                };
                terminal.owners[slot] = Some(sidecar_transaction(transaction, attempt, &next)?);
                let owners = terminal.owners[slot].as_ref()
                    .ok_or_else(|| state_error("original terminal owner TX absent"))?;
                // The actual encoded owner TX is resident before the final
                // original owner/paired-clock check at the Core prepare entry.
                session.revalidate_original_terminal_v5(writer, before, authorization, received)
                    .map_err(|_| state_error("original terminal prepared TX currentness"))?;
                terminal.preparations[slot] = Some(writer.prepare_transition_retaining_v5(
                    owners, attempt, destination,
                ));
                let failed = matches!(terminal.preparations[slot], Some(Err(_)));
                if failed {
                    terminal.first.get_or_insert(FirstFailure::Prepare(slot));
                }
                let after = session.observe_original_terminal_posts_v5(writer, before, authorization, received);
                if failed {
                    return Err(state_error("original terminal native preparation cause retained"));
                }
                after.map_err(|_| state_error("original terminal postprepare debt retained"))?;
                terminal.stage = if phase == 6 { TerminalStage::CommitUnsigned } else { TerminalStage::CommitSigned };
            }
            TerminalStage::CommitUnsigned | TerminalStage::CommitSigned => {
                let phase = if terminal.stage == TerminalStage::CommitUnsigned { 6 } else { 7 };
                let [unsigned_append, signed_append] = &mut terminal.appends;
                let (before_slot, destination) = if phase == 6 {
                    (&self.positive.appends[3], unsigned_append)
                } else {
                    (&*unsigned_append, signed_append)
                };
                let before = retained_readback(before_slot, &mut terminal.journal_failure, &mut terminal.first)?;
                session.revalidate_original_terminal_v5(writer, before, authorization, received)
                    .map_err(|_| state_error("original terminal precommit currentness"))?;
                let slot = usize::from(phase == 7);
                if terminal.commits[slot].is_some() {
                    return Err(state_error("original terminal native commit already attempted"));
                }
                let append = destination.as_mut()
                    .ok_or_else(|| state_error("original terminal candidate absent"))?;
                terminal.commits[slot] = Some(writer.commit_prepared_retaining_v5(append));
                if matches!(terminal.commits[slot], Some(Err(_))) {
                    terminal.first.get_or_insert(FirstFailure::Commit(slot));
                    // Preserve chronological native cause while the genuine
                    // failed/currentness owner captures any independent debt.
                    let _after = session.observe_original_terminal_posts_v5(writer, before, authorization, received);
                    return Err(state_error("original terminal native commit cause retained"));
                }
                let actual = retained_readback(destination, &mut terminal.journal_failure, &mut terminal.first)?;
                original_sidecar(actual, attempt, phase)?;
                session.revalidate_original_terminal_v5(writer, actual, authorization, received)
                    .map_err(|_| state_error("actual terminal readback currentness"))?;
                if terminal.installation_results[slot].is_some() {
                    return Err(state_error("original terminal installation already attempted"));
                }
                terminal.installation_pending = Some(slot);
                terminal.installation_results[slot] = Some(Self::install_original_terminal_retaining_v5(
                    table, index, writer, actual, &mut terminal.installations[slot],
                ));
                let failed = matches!(terminal.installation_results[slot], Some(Err(_)));
                if failed {
                    if let Some(site) = terminal.installations[slot].iter()
                        .position(|result| matches!(result, Some(Err(_))))
                    {
                        terminal.first.get_or_insert(FirstFailure::Install(slot, site));
                    } else {
                        terminal.first.get_or_insert(FirstFailure::InstallStatus(slot));
                    }
                }

                // Both actual validation Results and the complete returned
                // action Result are resident BEFORE either independent post.
                // Validation1 Err still skips validation2 in the shared body.
                let after = session.observe_original_terminal_posts_v5(writer, actual, authorization, received);
                if failed {
                    return Err(state_error("original terminal installation cause retained"));
                }
                after.map_err(|_| state_error("installed terminal readback currentness"))?;
                terminal.installation_pending = None;
                terminal.stage = if phase == 6 { TerminalStage::Sign } else { TerminalStage::Send };
            }
            TerminalStage::Sign => {
                let before = retained_readback(&terminal.appends[0], &mut terminal.journal_failure, &mut terminal.first)?;
                session.sign_original_root_terminal_v5(writer, before, authorization, received)
                    .map_err(|_| state_error("original Root13 signing cause retained"))?;
                terminal.stage = TerminalStage::PrepareSigned;
            }
            TerminalStage::Send | TerminalStage::Complete => {
                let before = retained_readback(&terminal.appends[1], &mut terminal.journal_failure, &mut terminal.first)?;
                if session.send_original_root_terminal_v5(writer, before, authorization, received)
                    .map_err(|_| state_error("original Root13 local native send retained"))?
                {
                    terminal.stage = TerminalStage::Complete;
                    return Ok(Progress::RootTerminalRecordedSent);
                }
            }
            TerminalStage::Dormant => return Err(state_error("original terminal not selected")),
        }
        Ok(Progress::Waiting)
    }
}

fn terminal_successor(
    old: &RootNativeHeldSidecarV2,
    received: &aos_sandbox_source_provider_security::OriginalNativeReceivedOutcomeV5,
    phase: u8,
) -> Result<RootNativeHeldSidecarV2> {
    let seven = received.original_provider_settled_v5()
        .ok_or_else(|| state_error("original Source7 absent"))?;
    let unsigned = received.original_unsigned_terminal_v5()
        .ok_or_else(|| state_error("original unsigned Root13 absent"))?;
    let settlement = NativeHeldSettlementV1::from_canonical_bytes(
        seven.section(Tag::Settlement).ok_or_else(|| state_error("original Source7 tuple absent"))?,
    ).map_err(|_| state_error("original Source7 tuple"))?;
    let mut controls = old.suffix().controls().to_vec();
    let prepared = match phase {
        6 => {
            controls.push(seven.clone());
            Some(unsigned.clone())
        }
        7 => {
            controls.push(received.original_signed_terminal_v5()
                .ok_or_else(|| state_error("original signed Root13 absent"))?.clone());
            None
        }
        _ => return Err(state_error("unsupported original terminal phase")),
    };
    let suffix = NativeHeldCompletionSuffixV1::new(
        NativeHeldOwnerV1::Root, phase, old.original_scope().flight, prepared, controls,
    ).map_err(|_| state_error("original terminal suffix"))?;
    RootNativeHeldSidecarV2::new(
        *old.original_scope(), old.response_transaction(), old.disposition().cloned(),
        Some(settlement), None, suffix, old.admission_cut().clone(),
        old.disposition_cut().cloned(), None,
    ).map_err(|_| state_error("original terminal sidecar"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dormant_terminal_is_not_a_live_owner_or_claim() {
        let terminal = OriginalRootTerminalFlightV5::new();

        assert!(!terminal.selected());
        assert!(!terminal.claim_pending);
        assert!(terminal.claim_failure.is_none());
        assert!(terminal.owners.iter().all(Option::is_none));
        assert!(terminal.appends.iter().all(Option::is_none));
        assert!(terminal.limits.is_none());
    }

    #[test]
    fn selected_routing_never_restarts_an_advanced_stage() {
        let mut terminal = OriginalRootTerminalFlightV5::new();
        terminal.select_after_root4();
        terminal.stage = TerminalStage::Send;

        terminal.select_after_root4();

        assert!(terminal.stage == TerminalStage::Send);
    }
}
