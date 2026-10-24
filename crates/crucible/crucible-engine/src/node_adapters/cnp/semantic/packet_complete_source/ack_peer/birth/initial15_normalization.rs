//! Lends the same retained planned registration before private boot starts.
//!
//! A genuine caller separately proves its target authority, plan and archive
//! ticket. This short DATA loan never constructs a lease or mapping and never
//! exposes the private birth key. Its callback ends before either postguard.

use super::*;
use crate::node_adapters::cnp::semantic::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics;
use crate::node_adapters::cnp::semantic::packet_complete_source::PacketCompleteSemanticSource;
use crucible_node_transport::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection;
use std::cell::Ref;
use std::mem::size_of;

type BirthLoan<'a> = Ref<'a, Option<OriginalAckPeerBirth>>;
type BirthLoanResult<'a> = Result<BirthLoan<'a>, std::cell::BorrowError>;

impl PacketCompleteSemanticSource {
    /// Lends the exact retained planned registration for prebirth DATA geometry.
    ///
    /// The callback is synchronous beneath one immutable birth loan. Its result
    /// cannot borrow the registration bank. Whole-owner observers, callbacks
    /// that change birth state, actual bank construction and native effects
    /// belong outside this loan and require their own prior admission.
    ///
    /// The caller independently authenticates its actual target Source/plan and
    /// archive ticket before and after entry. No startup-member completion is
    /// required or inferred: carrier finalization has not happened at this cut.
    ///
    /// # Errors
    /// Refuses foreign origin, another restoration selection, unreserved or
    /// unfinished/failed birth, started boot, a busy owner, missing registration,
    /// callback refusal or a changed original birth after the callback.
    pub fn with_original_initial15_prebirth_normalization_registration_data<R>(
        &self,
        inspect: impl FnOnce(&[u8]) -> Result<R, OperationFailure>,
    ) -> Result<R, OperationFailure> {
        self.authenticate_initial15_normalization_prebirth_data()?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| refused("Initial15 planned registration owner is busy"))?;
        let birth = slot
            .as_ref()
            .ok_or_else(|| refused("Initial15 planned registration owner is absent"))?;
        birth.authenticate_unstarted_storage_phase()?;
        if birth.expected_host_registration.is_empty() {
            return Err(refused("Initial15 planned registration bank is absent"));
        }
        let original = birth as *const OriginalAckPeerBirth;
        let bank = birth.expected_host_registration.as_ptr();
        let length = birth.expected_host_registration.len();
        let result = inspect(&birth.expected_host_registration);
        drop(slot);

        // Release every private Ref before the both-outcome origin/phase fence.
        // A callback that started boot cannot return a usable prospective row.
        self.authenticate_initial15_normalization_prebirth_data()?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| refused("Initial15 planned registration postguard is busy"))?;
        let birth = slot
            .as_ref()
            .ok_or_else(|| refused("Initial15 planned registration postguard is absent"))?;
        birth.authenticate_unstarted_storage_phase()?;
        if !std::ptr::eq(birth, original)
            || birth.expected_host_registration.as_ptr() != bank
            || birth.expected_host_registration.len() != length
        {
            return Err(refused("Initial15 planned registration owner changed"));
        }
        drop(slot);
        self.ensure_origin()?;
        result
    }

    /// Names the actual short registration-loan and provenance controls.
    ///
    /// `R` names the real callback result. Callback closure captures and its
    /// defining prospective projection controls remain separate caller terms.
    pub fn original_initial15_prebirth_normalization_registration_counter_scratch_data<R>() -> usize
    {
        OriginalInitialLifecycleDiagnostics::counter_scratch_bytes()
            + size_of::<&Self>()
            + size_of::<BirthLoan<'static>>()
            + size_of::<BirthLoanResult<'static>>()
            + size_of::<&OriginalAckPeerBirth>()
            + size_of::<Option<&OriginalAckPeerBirth>>()
            + size_of::<*const OriginalAckPeerBirth>()
            + size_of::<*const u8>()
            + size_of::<&[u8]>()
            + size_of::<usize>()
            + size_of::<[usize; 3]>()
            + size_of::<R>()
            + size_of::<Result<R, OperationFailure>>()
            + size_of::<Result<(), OperationFailure>>()
            + size_of::<PacketNative5CompleteRestoreSelection>()
            + size_of::<Option<PacketNative5CompleteRestoreSelection>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<OperationFailure>()
            + size_of::<[&str; 4]>()
            + size_of::<std::array::IntoIter<&'static str, 4>>()
    }

    /// Declares independent diagnostic backing before the short borrowed loan.
    ///
    /// The listed static messages dominate the local refusal lengths. The
    /// defining selected-diagnostic formatter can add its own bounded prefix.
    /// No birth, registration, key or callback is inspected by this prewalk.
    pub fn original_initial15_prebirth_normalization_registration_prewalk_data<R>() -> (usize, usize)
    {
        let diagnostic = OriginalInitialLifecycleDiagnostics::requested_bytes();
        let largest_local = [
            "Initial15 planned registration postguard is absent",
            "Initial15 planned registration prebirth selection differs",
            "original private birth is not ready and unstarted",
            "complete source belongs to another creator process",
        ]
        .into_iter()
        .fold(0usize, |largest, reason| largest.max(reason.len()));
        let scratch =
            Self::original_initial15_prebirth_normalization_registration_counter_scratch_data::<R>(
            );
        (diagnostic.max(largest_local), scratch)
    }

    fn authenticate_initial15_normalization_prebirth_data(&self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if !self.ack_birth_attempted
            || self.complete_restore_selection.flatten()
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Err(refused(
                "Initial15 planned registration prebirth selection differs",
            ));
        }
        Ok(())
    }
}
