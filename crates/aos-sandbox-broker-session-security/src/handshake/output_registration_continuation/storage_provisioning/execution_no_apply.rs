//! Keeps the same Host Session and actual Source/C18 across finite NoApply turns.
//!
//! All five SDK flights use the existing provisioning driver. The concrete Core
//! loan owns phase selection, request encoding, original deadline and funding;
//! only genuine C prepare/CAS producers may make the last two phases available.
//! No archive DATA, new Session or Apply disposal can enter this continuation.

use super::*;
use crate::recovery::{ProtectedBrokerSessionOwnerV1, RetainedStorageClientOwnerPostV1};
use aos_sandbox::Journal;
use aos_sandbox::controller_execution_operation::{
    ControllerExecutionNoApplyClientLoanV2, ControllerExecutionNoApplyDisposedOriginalV2,
    ControllerExecutionNoApplyOriginalV2, ControllerExecutionNoApplyTerminalRetirementV2,
    ControllerExecutionPositiveDisposalV1, ControllerExecutionReadReceivingLoanV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, VerifiedBrokerSessionTranscriptV1,
};
use aos_sandbox_linux::seqpacket::{ConnectionPeerIdentity, SeqpacketSocket};

/// Retains every SDK packet, native receipt, failed prefix and independently owed post.
#[must_use = "retain all NoApply originals until genuine terminal disposition"]
pub struct HostExecutionNoApplySessionIoOriginalV2 {
    flights: [ProvisioningFlightV1; 5],
    association: Option<Result<(), OutputPreparationClosedV1>>,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    protected: Option<BrokerSessionSecurityError>,
    controller_cut: Option<Result<(), ResourceReservationErrorV1>>,
    root_nonce: Option<Result<(), ResourceReservationErrorV1>>,
    root: aos_sandbox::normal_root::RootExecutionNoApplyClientOriginalV2,
    controller_prepare: Option<Result<(), ResourceReservationErrorV1>>,
    controller_cas: Option<Result<(), ResourceReservationErrorV1>>,
    controller_root_selected: [bool; 2],
    retirement:
        Option<Result<ControllerExecutionNoApplyTerminalRetirementV2, ResourceReservationErrorV1>>,
    closed: Option<OutputPreparationClosedV1>,
    entered: bool,
    first_flight: usize,
    cleanup_history: Option<Result<(
        aos_sandbox_protocol::host_execution_no_apply::ClosedHostTerminalArchiveDataV2,
        aos_sandbox_protocol::host_execution_availability::observation::HostExecutionAvailabilityObservationV2,
    ), BrokerSessionSecurityError>>,
    acquisition: Option<Result<(), aos_sandbox::normal_root::RootExecutionNoApplyClientClosedV2>>,
    recovery_metadata_entered: bool,
    recovery_metadata_completed: bool,
    recovery_metadata: Option<Result<aos_sandbox::controller_execution_operation::ControllerExecutionNoApplyRecoveredMetadataV2, ResourceReservationErrorV1>>,
}

impl Default for HostExecutionNoApplySessionIoOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl HostExecutionNoApplySessionIoOriginalV2 {
    /// Constructs inert inline destinations without admission, allocation or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flights: std::array::from_fn(|_| {
                ProvisioningFlightV1::new(ProvisioningKindV4::ExecutionNoApply)
            }),
            association: None,
            entry: None,
            protected: None,
            controller_cut: None,
            root_nonce: None,
            root: aos_sandbox::normal_root::RootExecutionNoApplyClientOriginalV2::new(),
            controller_prepare: None,
            controller_cas: None,
            controller_root_selected: [false; 2],
            retirement: None,
            closed: None,
            entered: false,
            first_flight: 0,
            cleanup_history: None,
            acquisition: None,
            recovery_metadata_entered: false,
            recovery_metadata_completed: false,
            recovery_metadata: None,
        }
    }

    /// Borrows the earliest SDK cause without releasing any owning prefix.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        for (result, root_selected) in [
            (&self.controller_prepare, self.controller_root_selected[0]),
            (&self.controller_cas, self.controller_root_selected[1]),
        ] {
            if let Some(Err(cause)) = result {
                return if root_selected {
                    self.root.failure_v2().or(Some(cause as _))
                } else {
                    Some(cause as _)
                };
            }
        }
        self.cleanup_history
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.association
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.entry
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.protected.as_ref().map(|cause| cause as _))
            .or_else(|| {
                self.flights[..2]
                    .iter()
                    .find_map(ProvisioningFlightV1::failure)
            })
            .or_else(|| {
                self.controller_cut
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.root.failure_v2())
            .or_else(|| {
                self.acquisition
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.root_nonce
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.flights[2..]
                    .iter()
                    .find_map(ProvisioningFlightV1::failure)
            })
            .or_else(|| {
                self.retirement
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
            .or_else(|| {
                self.recovery_metadata
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
    }

    /// Reports when the selected marker belongs to the same concrete Core original.
    #[must_use]
    pub fn original_failure_selected_v2(&self) -> bool {
        if self.recovery_metadata.as_ref().is_some_and(Result::is_err) {
            return true;
        }
        if self.controller_prepare.as_ref().is_some_and(Result::is_err) {
            return !self.controller_root_selected[0];
        }
        if self.controller_cas.as_ref().is_some_and(Result::is_err) {
            return !self.controller_root_selected[1];
        }
        if self.cleanup_history.as_ref().is_some_and(Result::is_err) {
            return false;
        }
        if self.association.as_ref().is_some_and(Result::is_err) {
            return false;
        }
        if self.entry.as_ref().is_some_and(Result::is_err) {
            return true;
        }
        if self.protected.is_some() {
            return false;
        }
        if self.root.original_failure_selected_v2() {
            return true;
        }
        for (index, flight) in self.flights.iter().enumerate() {
            if index == 2
                && (self.controller_cut.as_ref().is_some_and(Result::is_err)
                    || self.root_nonce.as_ref().is_some_and(Result::is_err))
            {
                return true;
            }
            if flight.first.is_some() {
                return flight.selected_original_failure();
            }
        }
        self.retirement.as_ref().is_some_and(Result::is_err)
    }

    /// Drops the completed SDK/Core originals under their same Source resource disposal.
    ///
    /// This returns only an opaque disposed association. The real Source/C18
    /// disposal must still complete before any usable terminal witness exists.
    ///
    /// # Errors
    /// Refuses a failed or incomplete flight, missing causal Root confirmation,
    /// another Core/Source operation or a missing genuine retirement association.
    pub fn retire_no_apply_before_native_disposal_v2(
        &mut self,
        core: &mut ControllerExecutionNoApplyOriginalV2,
        disposal: &ControllerExecutionPositiveDisposalV1<'_>,
    ) -> Result<ControllerExecutionNoApplyDisposedOriginalV2, ResourceReservationErrorV1> {
        if !self.entered
            || self.failure_v2().is_some()
            || !self.flights[self.first_flight..]
                .iter()
                .all(|flight| flight.completed)
            || self.root.require_complete_v2().is_err()
            || (self.first_flight == 1 && !self.recovery_metadata_completed)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let retirement = self
            .retirement
            .take()
            .and_then(Result::ok)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let disposed = retirement.retire_core_before_native_disposal_v2(core, disposal)?;
        drop(std::mem::replace(self, Self::new()));
        Ok(disposed)
    }

    fn refuse_closed_v2(&mut self) -> OutputPreparationClosedV1 {
        if self.failure_v2().is_none() {
            self.closed = Some(OutputPreparationClosedV1);
        }
        OutputPreparationClosedV1
    }

    pub(crate) fn borrow_cleanup_once_v2<'turn, 'scope, 'owner>(
        &'turn mut self,
        host: &'turn mut DormantAuthenticatedBrokerSessionV1,
        source: &'turn mut aos_sandbox::controller_execution_operation::ControllerExecutionCleanupSourceLoanV2<'scope, 'owner>,
        native_original: &'turn mut ControllerExecutionNoApplyOriginalV2,
        controller: &'turn mut Journal,
        bank: &'turn aos_sandbox::ControllerResourceBankOpeningV1,
        profile: &'turn aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<
        HostExecutionNoApplyClientSessionBorrowV2<'turn, 'turn, 'owner>,
        OutputPreparationClosedV1,
    > {
        if self.entered {
            return Err(self.refuse_closed_v2());
        }
        self.entered = true;
        self.first_flight = 1;
        // The selector's actual installed schema loan pays its dynamic native
        // programme. Reserve this additional SDK result/owner before retaining
        // any selected history comparison or entering the Core constructor.
        self.entry = Some((|| {
            let demand = std::mem::size_of::<Self>()
                .checked_mul(2)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            source.admit_stage_v2(bank,controller,profile,
                aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(
                    aos_sandbox_core::ResourceVector::ZERO.with(aos_sandbox_core::ResourceDimension::MemoryBytes,demand)))
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(OutputPreparationClosedV1);
        }
        let target = match source.target_operation_data_v2() {
            Ok(target) => target,
            Err(cause) => {
                self.entry = Some(Err(cause));
                return Err(OutputPreparationClosedV1);
            }
        };
        // The actual cold Source/Session receiving bridge retained in this
        // owner funds its complete native/schema programme. The sole archive
        // engine refuses an absent installed schema loan; no raw DTO enters.
        self.cleanup_history = Some(
            host.owner
                .select_execution_no_apply_cleanup_history_v2(target),
        );
        let (terminal, availability) = self
            .cleanup_history
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(OutputPreparationClosedV1)?;
        let journal = match host.owner.execution_no_apply_client_journal_v2() {
            Ok(journal) => journal,
            Err(cause) => {
                self.protected = Some(cause);
                return Err(OutputPreparationClosedV1);
            }
        };
        let native = match source.borrow_no_apply_client_once_v2(
            native_original,
            controller,
            bank,
            profile,
            terminal,
            availability,
            journal,
            &host.socket,
            &host.transcript,
        ) {
            Ok(native) => {
                self.entry = Some(Ok(()));
                native
            }
            Err(cause) => {
                self.entry = Some(Err(cause));
                return Err(OutputPreparationClosedV1);
            }
        };
        Ok(HostExecutionNoApplyClientSessionBorrowV2 {
            host,
            original: self,
            native,
        })
    }

    pub(crate) fn borrow_active_once_v2<'turn, 'source, 'original>(
        &'turn mut self,
        host: &'turn mut DormantAuthenticatedBrokerSessionV1,
        availability: &'turn ExecutionAvailabilitySessionIoOriginalV2,
        native_original: &'turn mut ControllerExecutionNoApplyOriginalV2,
        controller: &'turn mut Journal,
        bank: &'turn aos_sandbox::ControllerResourceBankOpeningV1,
        profile: &'turn aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        receiving: &'turn mut ControllerExecutionReadReceivingLoanV1<'source, 'original>,
    ) -> Result<
        HostExecutionNoApplyClientSessionBorrowV2<'turn, 'source, 'original>,
        OutputPreparationClosedV1,
    > {
        if self.entered {
            return Err(self.refuse_closed_v2());
        }
        self.entered = true;
        let association = match availability.no_apply_retirement_original_v2() {
            Ok(association) => {
                self.association = Some(Ok(()));
                association
            }
            Err(cause) => {
                self.association = Some(Err(cause));
                return Err(OutputPreparationClosedV1);
            }
        };
        let journal = match host.owner.execution_no_apply_client_journal_v2() {
            Ok(journal) => journal,
            Err(cause) => {
                self.protected = Some(cause);
                return Err(OutputPreparationClosedV1);
            }
        };
        let native = match native_original.borrow_active_no_apply_client_once_v2(
            controller,
            bank,
            profile,
            receiving,
            association,
            journal,
            &host.socket,
            &host.transcript,
        ) {
            Ok(native) => {
                self.entry = Some(Ok(()));
                native
            }
            Err(cause) => {
                self.entry = Some(Err(cause));
                return Err(OutputPreparationClosedV1);
            }
        };
        Ok(HostExecutionNoApplyClientSessionBorrowV2 {
            host,
            original: self,
            native,
        })
    }
}

/// Continuously borrows the original Host Session, SDK destinations and Source/C18.
#[must_use = "keep the same physical Session and financial originals through settlement"]
pub struct HostExecutionNoApplyClientSessionBorrowV2<'turn, 'source, 'original> {
    host: &'turn mut DormantAuthenticatedBrokerSessionV1,
    original: &'turn mut HostExecutionNoApplySessionIoOriginalV2,
    native: ControllerExecutionNoApplyClientLoanV2<'turn, 'source, 'original>,
}

impl HostExecutionNoApplyClientSessionBorrowV2<'_, '_, '_> {
    fn run_phase_once_v2(&mut self, expected: usize) -> Result<(), OutputPreparationClosedV1> {
        if expected < self.original.first_flight
            || self.native.no_apply_phase_data_v2() != expected
            || self.original.failure_v2().is_some()
            || self.original.flights[self.original.first_flight..expected]
                .iter()
                .any(|flight| !flight.completed)
        {
            return Err(self.original.refuse_closed_v2());
        }
        let flight = self
            .original
            .flights
            .get_mut(expected)
            .ok_or(OutputPreparationClosedV1)?;
        StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
            flight,
            self.host,
            &mut self.native,
            &(),
            false,
        )
    }

    /// Acquires genuine Root cleanup authority before new Host42/43 exists.
    ///
    /// The same actual fresh Source/C18 and physical Root connection stay held
    /// through all later phases. Acquisition installation uses the opaque
    /// actual-response borrower, never a caller-supplied canonical packet.
    ///
    /// # Errors
    /// Retains reentry, non-cleanup origin, funding, native Root, framing,
    /// acquisition association and independently owed post failures.
    pub fn acquire_root_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if self.original.first_flight != 1
            || self.original.acquisition.is_some()
            || self.original.failure_v2().is_some()
            || self.native.no_apply_phase_data_v2() != 1
        {
            return Err(self.original.refuse_closed_v2());
        }
        self.original.acquisition = Some((|| {
            self.original
                .root
                .begin_acquisition_once_v2(&mut self.native)?;
            self.original
                .root
                .install_acquisition_once_v2(&mut self.native)
        })());
        if matches!(self.original.acquisition, Some(Ok(()))) {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Executes genuine closed39 and retains its complete immutable signed group.
    ///
    /// # Errors
    /// Retains reentry, native/Source/C, Session, IO, canonical response and post failures.
    pub fn terminal_no_apply_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.run_phase_once_v2(0)
    }

    /// Executes preliminary42 while continuously holding the same actual Host Session.
    ///
    /// # Errors
    /// Refuses missing closed39 completion, reentry or any actual IO/native/post failure.
    pub fn preliminary_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.run_phase_once_v2(1)
    }

    /// Captures the genuine whole-C cut while the same Source/C18 and Session stay held.
    ///
    /// # Errors
    /// Retains missing preliminary completion, reentry, Source funding, native
    /// currentness, paired-clock and separately owed after-observation failures.
    pub fn prepare_controller_cut_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if self.original.controller_cut.is_some()
            || !self.original.flights[1].completed
            || self.original.failure_v2().is_some()
        {
            return Err(self.original.refuse_closed_v2());
        }
        self.original.controller_cut = Some(self.native.prepare_controller_cut_once_v2());
        if matches!(self.original.controller_cut, Some(Ok(()))) {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Borrows nonauthorizing whole-C DATA from the still-held actual native original.
    ///
    /// # Errors
    /// Refuses missing or failed capture and any unrelated global Controller advance.
    pub fn controller_cut_data_v2(&self)
    -> Result<aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2, ResourceReservationErrorV1>{
        self.native.controller_cut_data_v2()
    }

    /// Borrows the native wall second and six intended row digests as comparison DATA.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or stale native cut; grants no append or CAS.
    pub fn controller_rows_data_v2(
        &self,
    ) -> Result<(i64, [[u8; 32]; 3], [[u8; 32]; 3]), ResourceReservationErrorV1> {
        self.native.controller_rows_data_v2()
    }

    /// Prepares the genuine Root nonce query on the same immutable original cutoff.
    ///
    /// # Errors
    /// Retains missing preliminary completion, repeated or invalid nonce and Source refusal.
    pub fn prepare_root_nonce_query_once_v2(
        &mut self,
        root_nonce: [u8; 32],
    ) -> Result<(), OutputPreparationClosedV1> {
        if !matches!(self.original.controller_cut, Some(Ok(())))
            || self.original.root_nonce.is_some()
            || !self.original.flights[1].completed
            || self.original.failure_v2().is_some()
        {
            return Err(self.original.refuse_closed_v2());
        }
        self.original.root_nonce = Some(self.native.prepare_root_nonce_query_once_v2(root_nonce));
        if matches!(self.original.root_nonce, Some(Ok(()))) {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Executes nonce-bound43 through the sole paid native sender and archive engine.
    ///
    /// # Errors
    /// Refuses an unprepared Root nonce, wrong phase or any retained IO/native/post failure.
    pub fn root_nonce_query_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if !matches!(self.original.root_nonce, Some(Ok(()))) {
            return Err(self.original.refuse_closed_v2());
        }
        self.run_phase_once_v2(2)
    }

    /// Opens the actual Root child on the same Source/C18 and held whole-C cut.
    ///
    /// # Errors
    /// Retains actual Root payment, connection, native peer and opening posts.
    pub fn begin_root_exchange_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if !matches!(self.original.controller_cut, Some(Ok(())))
            || self.original.failure_v2().is_some()
        {
            return Err(self.original.refuse_closed_v2());
        }
        self.original
            .root
            .begin_once_v2(&mut self.native)
            .map_err(|_| OutputPreparationClosedV1)
    }

    /// Executes Host43 with the actual nonce from the continuously held Root stream.
    ///
    /// # Errors
    /// Refuses an incomplete Root opening or any paid Host/Source/native/post refusal.
    pub fn query_root_nonce_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        let nonce = self
            .original
            .root
            .root_read_nonce_data_v2()
            .map_err(|_| OutputPreparationClosedV1)?;
        self.prepare_root_nonce_query_once_v2(nonce)?;
        self.root_nonce_query_once_v2()
    }

    /// Receives the actual Root floor after the same Host43 and unchanged C cut.
    ///
    /// # Errors
    /// Refuses missing native43 completion, mismatched floor or Root/Source/posts.
    pub fn receive_root_floor_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if !self.original.flights[2].completed || self.original.failure_v2().is_some() {
            return Err(self.original.refuse_closed_v2());
        }
        self.original
            .root
            .receive_floor_once_v2(&mut self.native)
            .map_err(|_| OutputPreparationClosedV1)
    }

    /// Enters genuine Cprepare while borrowing the actual completed Root response.
    ///
    /// # Errors
    /// Retains actual Source, Root bookends, native C append/readback and owed posts.
    pub fn prepare_controller_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if self.original.controller_prepare.is_some() || self.original.failure_v2().is_some() {
            return Err(self.original.refuse_closed_v2());
        }
        let mut floor = self
            .original
            .root
            .borrow_floor_v2(&self.native)
            .map_err(|_| OutputPreparationClosedV1)?;
        self.original.controller_prepare = Some(self.native.prepare_controller_once_v2(&mut floor));
        self.original.controller_root_selected[0] = self.native.root_failure_selected_v2();
        if matches!(self.original.controller_prepare, Some(Ok(()))) {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Enters genuine three-row CAS after native Host Seal on this same Session.
    ///
    /// # Errors
    /// Refuses missing actual Seal, changed prepared C/floor, native or owed posts.
    pub fn commit_controller_cas_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if !self.original.flights[3].completed || self.original.failure_v2().is_some() {
            return Err(self.original.refuse_closed_v2());
        }
        let mut floor = self
            .original
            .root
            .borrow_prepared_floor_v2(&mut self.native)
            .map_err(|_| OutputPreparationClosedV1)?;
        self.original.controller_cas = Some(self.native.commit_controller_cas_once_v2(&mut floor));
        self.original.controller_root_selected[1] = self.native.root_failure_selected_v2();
        if matches!(self.original.controller_cas, Some(Ok(()))) {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Completes the actual Root flight only after native Host ACK, Root confirmation and EOF.
    ///
    /// # Errors
    /// Retains failed native ACK, Root final proof/disposition, IO and owed posts.
    pub fn finish_root_exchange_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if !self.original.flights[4].completed || self.original.failure_v2().is_some() {
            return Err(self.original.refuse_closed_v2());
        }
        self.original
            .root
            .send_acknowledgement_once_v2(&mut self.native)
            .map_err(|_| OutputPreparationClosedV1)?;
        self.original
            .root
            .require_complete_v2()
            .map_err(|_| OutputPreparationClosedV1)?;
        if !self.original.flights[self.original.first_flight..]
            .iter()
            .all(|flight| flight.completed)
            || self.original.retirement.is_some()
        {
            return Err(self.original.refuse_closed_v2());
        }
        self.original.retirement = Some(
            self.native
                .positive_no_apply_retirement_once_v2(&self.original.root),
        );
        if matches!(self.original.retirement, Some(Ok(_))) {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Completes the one native Recover status row after actual Root finality.
    ///
    /// The same loan retains all native metadata append/readback/clock posts.
    /// Returned metadata cannot become a public success before SDK/Core/cold
    /// graph disposal and the genuine fresh Source/C18 positive boundary.
    ///
    /// # Errors
    /// Refuses an active origin, incomplete five-phase continuation, repeated
    /// metadata, failed actual Root confirmation or native C/Source/posts.
    pub fn complete_recovery_metadata_once_v2(
        &mut self,
    ) -> Result<
        aos_sandbox::controller_execution_operation::ControllerExecutionNoApplyRecoveredMetadataV2,
        OutputPreparationClosedV1,
    > {
        if self.original.first_flight != 1
            || self.original.recovery_metadata_entered
            || self.original.failure_v2().is_some()
            || !matches!(self.original.retirement, Some(Ok(_)))
            || self.original.root.require_complete_v2().is_err()
        {
            return Err(self.original.refuse_closed_v2());
        }
        self.original.recovery_metadata_entered = true;
        self.original.recovery_metadata = Some(
            self.native
                .complete_recovery_metadata_once_v2(&self.original.root),
        );
        if !matches!(self.original.recovery_metadata, Some(Ok(_))) {
            return Err(OutputPreparationClosedV1);
        }
        let metadata = self
            .original
            .recovery_metadata
            .take()
            .and_then(Result::ok)
            .ok_or(OutputPreparationClosedV1)?;
        self.original.recovery_metadata_completed = true;
        Ok(metadata)
    }

    /// Executes Seal42 only after the same Core owner selects a genuine native prepare.
    ///
    /// # Errors
    /// Refuses an unavailable native continuation, incomplete prefix or actual IO/post failure.
    pub fn floor_seal_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.run_phase_once_v2(3)
    }

    /// Executes ACK42 only after the same Core owner selects the actual Controller CAS.
    ///
    /// # Errors
    /// Refuses an unavailable native continuation, incomplete prefix or actual IO/post failure.
    pub fn acknowledge_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        self.run_phase_once_v2(4)
    }

    /// Borrows the selected actual cause while retaining the whole native programme.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        if self.original.original_failure_selected_v2() {
            self.native
                .failure_v2()
                .or_else(|| self.original.failure_v2())
        } else {
            self.original
                .failure_v2()
                .or_else(|| self.native.failure_v2())
        }
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(in crate::handshake) fn require_execution_no_apply_client_v2(
        &self,
        method: BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        if !matches!(
            method,
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
        ) || self.transcript.protocol() != BrokerSessionProtocolV1::Host
            || self.transcript.audience()
                != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.owner.execution_no_apply_client_journal_v2()?;
        crate::handshake::require_negotiated_method(&self.transcript, method)
    }
}

impl ProvisioningMemberV4 for ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    type Prepared = ();
    member::common_turns!();

    fn matches_kind_v2(&self, kind: ProvisioningKindV4, _: &()) -> bool {
        matches!(kind, ProvisioningKindV4::ExecutionNoApply)
    }

    fn flight_owner_inline_bytes_v4() -> Option<usize> {
        size_of::<HostExecutionNoApplySessionIoOriginalV2>()
            .checked_mul(2)?
            .checked_add(ProvisioningFlightV1::body_slots_receiving_bytes_v5(5)?)?
            .checked_add(
                size_of::<HostExecutionNoApplyClientSessionBorrowV2<'static, 'static, 'static>>()
                    .checked_mul(2)?,
            )
    }
    fn extra_inline_bytes_v4(&self) -> Option<usize> {
        Some(0)
    }
    fn request_packet_bound_v4(&self, _: &(), inventory: bool) -> Option<usize> {
        if inventory {
            None
        } else {
            self.no_apply_request_bound_v2()
        }
    }

    fn admit_v4(
        &mut self,
        _: &(),
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: aos_sandbox::StorageProvisioningSessionIoShapeDataV1,
        inventory: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if inventory {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.admit_no_apply_io_once_v2(journal, socket, transcript, shape)
    }

    fn prepare_request_v4(
        &mut self,
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        _: &(),
        inventory: bool,
        maximum_request: usize,
    ) -> bool {
        let inputs = (|| {
            if inventory {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let method = self.no_apply_method_data_v2();
            session.require_execution_no_apply_client_v2(method)?;
            let journal = self.session_journal_v1(&session.owner)?;
            let header = self
                .no_apply_request_header_data_v2(journal, &session.transcript)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let coordinates = session.execution_client_coordinates_data_v2(&header)?;
            let envelope = self
                .no_apply_request_envelope_v2(&coordinates.request_header())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if envelope.method.as_known() != Some(method) {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok((coordinates, envelope))
        })();
        match inputs {
            Ok((coordinates, envelope)) => {
                flight.shared.inner.coordinates = Some(Ok(coordinates));
                flight.unsigned = Some(envelope);
                match flight.unsigned.as_ref() {
                    Some(envelope) => flight.shared.inner.prepare_captured_engine_v1(
                        session,
                        envelope.clone(),
                        Some(maximum_request),
                        match flight.request_originals.as_mut() {
                            Some(capture) => Some(capture.as_mut()),
                            None => return false,
                        },
                    ),
                    None => false,
                }
            }
            Err(cause) => {
                flight.shared.inner.coordinates = Some(Err(cause));
                flight.mark(First::Coordinates);
                false
            }
        }
    }

    fn bind_request_v4(
        &mut self,
        _: &(),
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.bind_no_apply_request_once_v2(request)
    }

    fn observe_owner_v4(
        owner: &mut ProtectedBrokerSessionOwnerV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        owner.observe_execution_availability_client_owner_v2(transcript, peer)
    }

    fn compare_predecessor_v4(
        owner: &mut ProtectedBrokerSessionOwnerV1,
        currentness: &crate::recovery::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
        originals: &mut crate::recovery::OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        owner.compare_execution_no_apply_predecessor_v2(currentness, peer, originals)
    }

    fn finish_terminal_v4(
        &mut self,
        _: &(),
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_no_apply_terminal_once_v2(journal, outcome)
    }

    fn observe_terminal_post_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.observe_no_apply_terminal_post_once_v2(journal, socket, transcript)
    }
}
