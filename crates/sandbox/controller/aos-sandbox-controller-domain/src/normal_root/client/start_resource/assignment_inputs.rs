//! Owns only the accepted Start's pre-Ownership signed-policy input opening.
//!
//! The private shared opening engine retains its socket, paired clocks, raw
//! peer samples and first refusal. Only the genuine completed native Start turn
//! can join its C after; raw reply bytes cannot manufacture that conjunction.

use super::*;
use aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::StartAssignmentInputsReplyDataV2;

#[derive(Clone, Copy)]
enum InputsFirstV2 {
    Opening,
    OriginalAfter,
    Reentry,
}

/// Retains the read-only Root input flight through its real C and Root posts.
#[doc(hidden)]
#[must_use = "retain the complete signed-policy input flight through all posts"]
pub struct RootStartAssignmentInputsClientOriginalV2 {
    opening: RootHostLaunchClientOriginalV1,
    identity: Option<Arc<()>>,
    original_after: Option<Result<(), ResourceReservationErrorV1>>,
    completed: Option<CompletedInputsDataV2>,
    first: Option<InputsFirstV2>,
}

impl RootStartAssignmentInputsClientOriginalV2 {
    /// Creates inert destinations without a socket, observation or grant.
    #[must_use]
    pub fn new() -> Self {
        Self { opening: RootHostLaunchClientOriginalV1::new(), identity: None,
            original_after: None, completed: None, first: None }
    }

    /// Opens the exact lease-free input purpose on the genuine new Start turn.
    ///
    /// # Errors
    /// Retains reentry, original mismatch, payment, transport, clock and peer
    /// failures. Every reached independent Root post runs in the shared engine.
    pub fn begin_inputs_once_v2(&mut self,
        loan: &mut crate::OriginalStartAssignmentInputsLoanV2<'_, '_>, controller: &Journal,
        ready: &[u8], preparation: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        if self.identity.is_some() || self.first.is_some() {
            self.first.get_or_insert(InputsFirstV2::Reentry);
            return Err(CLOSED);
        }
        // This is the original Entry's existing Arc, without a new allocation.
        self.identity = Some(loan.retained_identity_v2());
        let result = self.opening.begin_opening_once_v2(StartOpeningPurposeV2::AssignmentInputs,
            StartOpeningLoanV2::AssignmentInputs(loan), controller, ready, preparation, &[]);
        if result.is_err() {
            self.first = Some(InputsFirstV2::Opening);
        }
        result
    }

    /// Joins only the actual same-turn native completion after the Root posts.
    ///
    /// `None` closes a refused original without admitting DATA or issuing IO.
    /// The actual Entry retains and diagnoses that earlier original refusal.
    ///
    /// # Errors
    /// Retains absent, foreign, incomplete or repeated native completion.
    pub fn finish_inputs_after_original_once_v2(&mut self,
        completed: Option<&crate::StartAssignmentInputsCompletedTurnV2<'_>>, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        if self.original_after.is_some() {
            self.first.get_or_insert(InputsFirstV2::Reentry);
            return Err(CLOSED);
        }
        self.original_after = Some((|| {
            let state = self.opening.state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let identity = self.identity.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            if state.purpose != StartOpeningPurposeV2::AssignmentInputs {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            completed.ok_or(ResourceReservationErrorV1::Conflict)?.require_same_context_v2(
                state.parent, state.native_turn, identity, state.profile.as_ref(), controller,
            )
        })());
        self.opening.retain_controller_after_from_entry_v1(self.original_after.as_ref());
        if !matches!(self.original_after, Some(Ok(()))) {
            self.first.get_or_insert(InputsFirstV2::OriginalAfter);
        }
        if self.first.is_some() || self.opening.first.is_some() {
            return Err(CLOSED);
        }
        let Some(state) = self.opening.state.as_ref() else { return Err(CLOSED); };
        if state.purpose != StartOpeningPurposeV2::AssignmentInputs || state.stable.is_none()
            || !matches!(state.request_end, Some(Ok(())))
            || !matches!(state.reply_ended, Some(Ok(()))) || !state.reply_eof.completed_exact()
            || state.chunk.is_some() || state.peer_before.is_some() || state.peer_after.is_some()
            || !matches!(self.opening.outer_after, Some(Ok(()))) {
            self.first = Some(InputsFirstV2::OriginalAfter);
            return Err(CLOSED);
        }
        let before = *state.before_sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        let after = *state.after_sample.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        let Some(mut state) = self.opening.state.take() else { return Err(CLOSED); };
        let data = CompletedInputsDataV2 {
            received: std::mem::take(&mut state.received), before, after,
        };
        // The same socket has WriteEOF + hostile EOF, both Root samples have
        // settled and the genuine same-turn C post joined above. Retain only
        // the original response/model bytes and typed pairs; dispose the WHOLE
        // successful native connection/anchor/clock/IO prefix before completion.
        drop(state);
        self.opening.terminal_complete = true;
        self.completed = Some(data);
        Ok(())
    }

    /// Borrows signed input DATA only after the actual same-turn conjunction.
    ///
    /// Signature, policy and accepted-request verification remain with the
    /// genuine upper Start owner; this borrower supplies no resource authority.
    ///
    /// # Errors
    /// Refuses failed, incomplete, substituted or malformed retained input DATA.
    pub fn borrow_completed_inputs_v2(&self)
        -> Result<StartAssignmentInputsReplyDataV2<'_>, RootHostLaunchClientClosedV1> {
        if self.first.is_some() || self.opening.first.is_some()
            || !matches!(self.original_after, Some(Ok(()))) {
            return Err(CLOSED);
        }
        let data = self.completed.as_ref().ok_or(CLOSED)?;
        if !self.opening.terminal_complete || !matches!(self.opening.outer_after, Some(Ok(()))) {
            return Err(CLOSED);
        }
        StartAssignmentInputsReplyDataV2::decode_v2(data.received.bytes()).map_err(|_| CLOSED)
    }

    /// Borrows the actual paired samples retained across positive disposal.
    ///
    /// # Errors
    /// Refuses an incomplete or failed read-only input flight.
    pub fn completed_clock_data_v2(&self) -> Result<(RawPairedClockSample, RawPairedClockSample), RootHostLaunchClientClosedV1> {
        self.borrow_completed_inputs_v2()?;
        let data = self.completed.as_ref().ok_or(CLOSED)?;
        Ok((data.before, data.after))
    }

    /// Supplies the actual retained DATA shape after complete native disposal.
    ///
    /// This passive shape neither credits a ledger nor resets earlier traffic.
    /// The upper genuine Start owner carries it beside all other survivors.
    ///
    /// # Errors
    /// Refuses incomplete completion or checked compiled-layout overflow.
    pub fn completed_resident_receiving_demand_v2(&self) -> Result<ResourceVector, RootHostLaunchClientClosedV1> {
        self.borrow_completed_inputs_v2()?;
        let data = self.completed.as_ref().ok_or(CLOSED)?;
        let memory = size_of::<Self>().checked_add(data.received.retained_backing_bytes_v2())
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CLOSED)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
    }

    /// Borrows the actual earliest failure while the whole original stays held.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first {
            Some(InputsFirstV2::Opening) => self.opening.failure(),
            Some(InputsFirstV2::OriginalAfter) => cause(&self.original_after).or(Some(&CLOSED)),
            Some(InputsFirstV2::Reentry) => Some(&CLOSED),
            None => self.opening.failure(),
        }
    }

    /// Formats the retained worker cause while its actual archive guard is held.
    ///
    /// # Errors
    /// Returns the formatter's error when writing the retained diagnosis fails.
    pub fn fmt_failure_v2(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if matches!(self.first, Some(InputsFirstV2::Opening)) {
            if let Some(view) = self.opening.failure_view_v2() {
                return std::fmt::Display::fmt(&view, formatter);
            }
        }
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original Start policy-input failure is unavailable"),
        }
    }
}

impl Default for RootStartAssignmentInputsClientOriginalV2 {
    fn default() -> Self { Self::new() }
}

// This private owned DATA is constructed only after actual native disposal.
// It is never accepted as a Start owner, Root admission or financial grant.
struct CompletedInputsDataV2 {
    received: RetainedSubjectStreamReadV1,
    before: RawPairedClockSample,
    after: RawPairedClockSample,
}

// The old native response owner and the moved completed DATA constructor can
// overlap before successful native disposal. This prices their typed carriers;
// the same original byte buffer moves, without another allocation or copy.
pub(super) fn completion_construction_bytes_v2() -> Option<usize> {
    size_of::<CompletedInputsDataV2>().checked_mul(2)
}
