//! Retains a genuinely new Start Network Client on the shared HELLO driver.
//!
//! The actual Start/Root loan prices its compiled representation before the
//! lazy driver exists. The named captured Journal stays resident through all
//! refusals and the independent outer C and Root posts remain with the caller.

use super::selected_client_open::{SelectedClientCaptureV1, SelectedClientReceivingV1};
use super::*;
use crate::recovery::{FixedServiceColdJournalReceivingV4, ProtectedBrokerSessionFixedEndpointV1};
use aos_sandbox::journal::{
    CapturedJournalOpenModeV1, ControllerStartResourceSessionCapturedJournalOpenV4,
};
use aos_sandbox::{ResourceReservationErrorV1, StartResourceSessionOpeningLoanV2};
use aos_sandbox_broker_session_protocol::BrokerSessionDurableEndpointV1;

/// Reports refusal while the actual Start opening and all reached owners remain held.
#[derive(Debug, thiserror::Error)]
#[error("the original Start Network Session remains closed")]
pub struct StartResourceSessionClosedV4;

#[derive(Clone, Copy)]
enum First {
    Reentry,
    Shape,
    Payment,
    Horizon,
    Capture,
    NativeFinish,
    Disposal,
}

/// Owns one new Start Network Client without borrowing an initial boot role.
#[must_use = "retain this owner through the original C and Root afters"]
pub struct StartResourceSessionOpenOriginalV4 {
    capture: Option<Box<SelectedClientCaptureV1>>,
    captured_journal: ControllerStartResourceSessionCapturedJournalOpenV4,
    completed: Option<Box<DormantAuthenticatedBrokerSessionV1>>,
    disposal: Option<aos_sandbox::StartResourceHelloDisposalErrorV4>,
    native_primary: bool,
    shape: Option<
        Result<aos_sandbox::ControllerInitialBrokerSessionShapeV1, StartResourceSessionClosedV4>,
    >,
    payment: Option<Result<(), ResourceReservationErrorV1>>,
    horizon:
        Option<Result<(aos_sandbox_core::RawPairedClockSample, u64), ResourceReservationErrorV1>>,
    cutoff: Option<Result<u64, StartResourceSessionClosedV4>>,
    result: Option<Result<(), super::controller_initial::ControllerInitialClientClosedV1>>,
    native_finish: Option<Result<(), ResourceReservationErrorV1>>,
    current: Option<Result<(), ResourceReservationErrorV1>>,
    prefix: Option<Result<(), ResourceReservationErrorV1>>,
    captured_native_selected: bool,
    first: Option<First>,
}

impl StartResourceSessionOpenOriginalV4 {
    /// Creates only inert inline destinations, without allocation or native IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            capture: None,
            captured_journal: ControllerStartResourceSessionCapturedJournalOpenV4::new(),
            completed: None,
            disposal: None,
            native_primary: false,
            shape: None,
            payment: None,
            horizon: None,
            cutoff: None,
            result: None,
            native_finish: None,
            current: None,
            prefix: None,
            captured_native_selected: false,
            first: None,
        }
    }

    fn receiving_shape_v4(role: aos_sandbox::ControllerInitialBrokerSessionRoleV1) -> Option<aos_sandbox::ControllerInitialBrokerSessionShapeV1> {
        let mut shape =
            super::controller_initial::ControllerInitialSessionOpenV1::receiving_shape_v1(
                role,
            )?;
        shape.hello.actual_inline_bytes = size_of::<Self>()
            .checked_mul(2)?
            .checked_add(size_of::<SelectedClientCaptureV1>().checked_mul(2)?)?
            .checked_add(size_of::<DormantAuthenticatedBrokerSessionV1>().checked_mul(2)?)?;
        // This new finite recipe invoices named paths through the actual
        // native suppliers. Parser/control fields are Memory, not namespaces.
        shape.hello.actual_failure_cells = 0;
        // This new entry retains actual named file/proc/socket rows. Legacy
        // suppliers also count Stat/Result/Vec/control fields; those fields
        // remain covered by Memory and create no namespace in this recipe.
        let files = crate::protected_files::ProtectedEndpointFilesOpeningV1::opened_file_bound_v1();
        let observation =
            aos_sandbox_linux::self_execution::SelfExecutionObservationV1::opened_file_bound_v1();
        let guard_files = aos_sandbox_linux::self_execution::RetainedSelfExecutionGuard::selected_capture_opened_file_bound_v1()
            .checked_sub(1)?; // The current-self pidfd is not a filesystem name.
        shape.endpoint.metadata_cells = files
            .checked_add(
                crate::protected_files::ProtectedEndpointFilesRevalidationV1::opened_file_bound_v1(
                ),
            )?
            .checked_add(guard_files)?
            .checked_add(observation)?;
        shape.endpoint_revalidation.metadata_cells = 2_usize
            .checked_mul(
                crate::protected_files::ProtectedEndpointFilesRevalidationV1::opened_file_bound_v1(
                ),
            )?
            .checked_add(4_usize.checked_mul(observation)?)?;
        if role != aos_sandbox::ControllerInitialBrokerSessionRoleV1::Storage {
            // These fixed roles have no mode/TPM floor namespace.
            shape.floor.metadata_cells = 0;
            shape.floor_revalidation.metadata_cells = 0;
        }
        // Four retained/active proc-stat readers plus the four existing rooted
        // names in /run/aos/sandbox-network/control.sock.
        shape.process.metadata_cells = 4_usize
            .checked_mul(
                aos_sandbox_linux::pidfd::PidFdProcObservationsV1::stat_opened_file_bound_v1(),
            )?
            .checked_add(4)?;
        Some(shape)
    }

    /// Opens the actual Network Client through the existing retained engine.
    ///
    /// # Errors
    /// Retains geometry, funding, endpoint, transport, HELLO, Journal and native
    /// refusal. The enclosing caller still finishes its independent C/Root posts.
    pub fn open_once_v4(
        &mut self,
        loan: &mut StartResourceSessionOpeningLoanV2<'_>,
    ) -> Result<(), StartResourceSessionClosedV4> {
        if self.shape.is_some() || self.first.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(StartResourceSessionClosedV4);
        }
        self.shape = Some(Self::receiving_shape_v4(loan.actual_role_v2()).ok_or(StartResourceSessionClosedV4));
        let Some(Ok(shape)) = self.shape.as_ref() else {
            self.first = Some(First::Shape);
            return Err(StartResourceSessionClosedV4);
        };
        self.payment = Some(loan.admit_actual_capture_shape_once_v2(*shape));
        if !matches!(self.payment, Some(Ok(()))) {
            self.native_primary = loan.original_failure_entered_v4();
            self.first = Some(First::Payment);
            return Err(StartResourceSessionClosedV4);
        }
        self.horizon = Some(loan.original_horizon_v2());
        self.cutoff = Some(match self.horizon.as_ref() {
            Some(Ok((_, root))) if *root != 0 && *root != u64::MAX => Ok(*root),
            _ => Err(StartResourceSessionClosedV4),
        });
        let Some(Ok(cutoff)) = self.cutoff.as_ref() else {
            self.native_primary = loan.original_failure_entered_v4();
            self.first = Some(First::Horizon);
            self.native_finish = Some(loan.finish_capture_once_v2());
            return Err(StartResourceSessionClosedV4);
        };
        self.capture = Some(Box::new(SelectedClientCaptureV1::start_network(
            OriginalBrokerColdDeadlineV1::storage_accept(*cutoff),
        )));
        let mut context = StartResourceColdReceivingV4 {
            loan,
            journal: &mut self.captured_journal,
            current: &mut self.current,
            prefix: &mut self.prefix,
            captured_native_selected: &mut self.captured_native_selected,
        };
        let Some(capture) = self.capture.as_mut() else {
            std::process::abort()
        };
        self.result =
            Some(capture.drive_once(SelectedClientReceivingV1::StartResource(&mut context)));
        if !matches!(self.result, Some(Ok(()))) {
            self.first = Some(First::Capture);
        }
        // Latch actual native/original refusal before the later independent
        // loan join can fail. The Root caller resolves that original only when
        // this specific earlier body gate selected it.
        self.native_primary = context.loan.original_failure_entered_v4();
        drop(context);
        if self.first.is_some() {
            self.native_finish = Some(loan.finish_capture_once_v2());
            return Err(StartResourceSessionClosedV4);
        }
        self.complete_native_v4(loan)
    }

    fn complete_native_v4(
        &mut self,
        loan: &mut StartResourceSessionOpeningLoanV2<'_>,
    ) -> Result<(), StartResourceSessionClosedV4> {
        let Some(capture) = self.capture.as_mut() else {
            self.first = Some(First::Disposal);
            return Err(StartResourceSessionClosedV4);
        };
        let Some((sent, broker_hello)) = capture.take_start_resource_controls_v4() else {
            self.first = Some(First::Disposal);
            self.native_finish = Some(loan.finish_capture_once_v2());
            return Err(StartResourceSessionClosedV4);
        };
        let Some(Ok(session)) = capture.completed.as_mut() else {
            std::process::abort()
        };
        let journal = match session.owner.start_resource_journal_v4() {
            Ok(journal) => journal,
            Err(_) => std::process::abort(),
        };
        let completed = {
            let prepared = loan.prepare_completed_hello_disposal_v4(
                &self.captured_journal,
                journal,
                &session.socket,
                &session.transcript,
                &session.checkpoint,
                sent,
                broker_hello,
            );
            match prepared {
                Err(cause) => {
                    self.disposal = Some(cause);
                    false
                }
                Ok(disposal) => {
                    let Some(Ok(session)) = capture.completed.take() else {
                        std::process::abort()
                    };
                    self.completed = Some(Box::new(session));
                    // The same Session keeps its actual writer, socket,
                    // transcript and live witnesses. Only completed control,
                    // poll and HELLO copies retire before the consuming token.
                    drop(self.capture.take());
                    disposal.complete_after_disposal_v4();
                    true
                }
            }
        };
        if completed {
            Ok(())
        } else {
            // The fallible disposal token and its Result have left scope.
            // Latch the actual lower failure before outer C/Root posts.
            self.native_primary = loan.original_failure_entered_v4();
            self.first = Some(First::Disposal);
            Err(StartResourceSessionClosedV4)
        }
    }

    /// Lends the actual completed Client only with its same native association.
    ///
    /// This mechanical borrow performs no IO or allocation. The later genuine
    /// IO loan separately pays/rejoins current Start, Source, Bank and Root.
    ///
    /// # Errors
    /// Refuses incomplete native/HELLO disposal, a prior failure, or another
    /// opening, Journal, socket or protected signed transcript.
    pub fn session_mut_v4<'held>(
        &'held mut self,
        opening: &'held aos_sandbox::StartResourceSessionOpeningOriginalV2,
    ) -> Result<StartResourceSessionBorrowV4<'held>, StartResourceSessionClosedV4> {
        if self.first.is_some() || self.capture.is_some() || self.disposal.is_some() {
            return Err(StartResourceSessionClosedV4);
        }
        let association = opening
            .completed_session_association_v4()
            .ok_or(StartResourceSessionClosedV4)?;
        let session = self
            .completed
            .as_deref_mut()
            .ok_or(StartResourceSessionClosedV4)?;
        if session.terminal_witness_failure
            || session.terminal_witness_debt.is_some()
            || !matches!(&session.client_witnesses, Ok(Some(witnesses)) if witnesses.first_failure.is_none())
        {
            return Err(StartResourceSessionClosedV4);
        }
        let journal = session
            .owner
            .start_resource_journal_v4()
            .map_err(|_| StartResourceSessionClosedV4)?;
        association
            .require_same_session_v4(journal, &session.socket, &session.transcript)
            .map_err(|_| StartResourceSessionClosedV4)?;
        Ok(StartResourceSessionBorrowV4 {
            inner: session,
            association,
        })
    }

    /// Rejoins the same completed Host Session after catalog publication and activation.
    ///
    /// This borrows the existing private authenticated Session. It performs no
    /// HELLO, endpoint loading, transcript replacement or new deadline. The
    /// genuine Domain owner pays and retains both independent native checks;
    /// the caller still finishes the actual Host1 C and Root posts.
    ///
    /// # Errors
    /// Refuses another fixed role, incomplete captured SDK context or changed
    /// native Start/Root/Session custody. The actual rejoin cause remains in
    /// the supplied genuine Domain original, including every reached prefix.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn rejoin_host_once_v2(
        &mut self,
        opening: &aos_sandbox::StartResourceSessionOpeningOriginalV2,
        original: &mut aos_sandbox::OriginalStartHostRootLoanV1<'_, '_>,
        root: &aos_sandbox::normal_root::RootStartResourceCurrentTurnV2<'_>,
        controller: &aos_sandbox::Journal,
        rejoin: &mut aos_sandbox::StartHostSessionRejoinOriginalV2,
    ) -> Result<(), StartResourceSessionClosedV4> {
        if opening.actual_role_v2() != aos_sandbox::ControllerInitialBrokerSessionRoleV1::Host {
            return Err(StartResourceSessionClosedV4);
        }
        let session = self.session_mut_v4(opening)?;
        let journal = session.inner.owner.start_resource_journal_v4()
            .map_err(|_| StartResourceSessionClosedV4)?;
        original.observe_host_session_rejoin_once_v2(root, opening, controller,
            journal, &session.inner.socket, &session.inner.transcript, rejoin)
            .map_err(|_| StartResourceSessionClosedV4)
    }

    /// Disposes this actual Network SDK interval after genuine Root completion.
    ///
    /// Exact packet/native comparison uses the completed originals already
    /// retained by both owners. All native and C/Root posts precede this call;
    /// no syscall, encoding, new horizon or financial refund occurs here.
    ///
    /// # Errors
    /// Refuses an incomplete or different Session/Root/Entry, unequal actual
    /// packets/native boundary, or any retained IO/native post failure.
    pub fn dispose_completed_network_once_v2(
        &mut self,
        flights: &mut super::output_registration_continuation::StartResourceProvisioningSessionIoOriginalV4,
        opening: &mut aos_sandbox::StartResourceSessionOpeningOriginalV2,
        prepared: &mut aos_sandbox::PreparedStartResourceRequestOriginalV2,
        completed: &aos_sandbox::normal_root::RootStartResourceCompletedOriginalV2,
        entry: &mut aos_sandbox::AcceptedStartEntryOriginalV1,
        controller: &aos_sandbox::Journal,
    ) -> Result<(), StartResourceSessionClosedV4> {
        if opening.actual_role_v2() != aos_sandbox::ControllerInitialBrokerSessionRoleV1::Network {
            return Err(StartResourceSessionClosedV4);
        }
        self.dispose_completed_resource_once_v2(flights, opening, prepared, completed, entry, controller)
    }

    /// Disposes the actual Mount SDK interval after its genuine Root completion.
    ///
    /// # Errors
    /// Refuses changed purpose, packets, native boundary, or incomplete posts.
    pub fn dispose_completed_mount_once_v2(
        &mut self,
        flights: &mut super::output_registration_continuation::StartResourceProvisioningSessionIoOriginalV4,
        opening: &mut aos_sandbox::StartResourceSessionOpeningOriginalV2,
        prepared: &mut aos_sandbox::PreparedStartResourceRequestOriginalV2,
        completed: &aos_sandbox::normal_root::RootStartResourceCompletedOriginalV2,
        entry: &mut aos_sandbox::AcceptedStartEntryOriginalV1,
        controller: &aos_sandbox::Journal,
    ) -> Result<(), StartResourceSessionClosedV4> {
        if opening.actual_role_v2() != aos_sandbox::ControllerInitialBrokerSessionRoleV1::Mount {
            return Err(StartResourceSessionClosedV4);
        }
        self.dispose_completed_resource_once_v2(flights, opening, prepared, completed, entry, controller)
    }

    /// Disposes the actual Host SDK interval after its genuine Root completion.
    ///
    /// # Errors
    /// Refuses changed purpose, packets, native boundary, or incomplete posts.
    pub fn dispose_completed_host_once_v2(
        &mut self,
        flights: &mut super::output_registration_continuation::StartResourceProvisioningSessionIoOriginalV4,
        opening: &mut aos_sandbox::StartResourceSessionOpeningOriginalV2,
        prepared: &mut aos_sandbox::PreparedStartResourceRequestOriginalV2,
        completed: &aos_sandbox::normal_root::RootStartResourceCompletedOriginalV2,
        entry: &mut aos_sandbox::AcceptedStartEntryOriginalV1,
        controller: &aos_sandbox::Journal,
    ) -> Result<(), StartResourceSessionClosedV4> {
        if opening.actual_role_v2() != aos_sandbox::ControllerInitialBrokerSessionRoleV1::Host {
            return Err(StartResourceSessionClosedV4);
        }
        self.dispose_completed_resource_once_v2(flights, opening, prepared, completed, entry, controller)
    }

    fn dispose_completed_resource_once_v2(
        &mut self,
        flights: &mut super::output_registration_continuation::StartResourceProvisioningSessionIoOriginalV4,
        opening: &mut aos_sandbox::StartResourceSessionOpeningOriginalV2,
        prepared: &mut aos_sandbox::PreparedStartResourceRequestOriginalV2,
        completed: &aos_sandbox::normal_root::RootStartResourceCompletedOriginalV2,
        entry: &mut aos_sandbox::AcceptedStartEntryOriginalV1,
        controller: &aos_sandbox::Journal,
    ) -> Result<(), StartResourceSessionClosedV4> {
        self.session_mut_v4(opening)?;
        let actual = flights.completed_exchange_data_v2().map_err(|_| StartResourceSessionClosedV4)?;
        let recorded = completed.comparison_data_v2();
        if actual.resource_request != recorded.resource_request
            || actual.resource_outcome != recorded.resource_outcome
            || actual.inventory_request != recorded.inventory_request
            || actual.inventory_outcome != recorded.inventory_outcome
            || actual.session_native != recorded.session_native {
            return Err(StartResourceSessionClosedV4);
        }
        let retained_model_bytes = if opening.actual_role_v2() == aos_sandbox::ControllerInitialBrokerSessionRoleV1::Host {
            // Host is the final resource. Its genuine Root completion owns the
            // exact fully verified packets; no later catalog consumes these
            // sole-decoded Host models after positive native disposal.
            completed.require_host_disposition_v2(entry, controller)
                .map_err(|_| StartResourceSessionClosedV4)?;
            0
        } else {
            flights.retain_completed_models_once_v2(completed)
                .map_err(|_| StartResourceSessionClosedV4)?
        };
        let disposition = match opening.actual_role_v2() {
            aos_sandbox::ControllerInitialBrokerSessionRoleV1::Network =>
                entry.prepare_completed_network_upper_disposal_v2(opening, prepared, completed, controller, retained_model_bytes),
            aos_sandbox::ControllerInitialBrokerSessionRoleV1::Mount =>
                entry.prepare_completed_mount_upper_disposal_v2(opening, prepared, completed, controller, retained_model_bytes),
            aos_sandbox::ControllerInitialBrokerSessionRoleV1::Host =>
                entry.prepare_completed_host_upper_disposal_v2(opening, prepared, completed, controller),
            _ => return Err(StartResourceSessionClosedV4),
        }.map_err(|_| StartResourceSessionClosedV4)?;
        // Drop actual successful flights first, then the actual Session/socket
        // and cold Journal control. The Domain token still owns the same Entry
        // and native endpoint until these upper borrowers are physically gone.
        flights.retire_completed_flights_v2();
        *self = Self::new();
        disposition.complete_after_sdk_disposal_v2().map_err(|_| StartResourceSessionClosedV4)
    }

    /// Prices a conservative retained upper bound for this same completed Client.
    ///
    /// This passive bound reuses its actual admitted compiled shape and the
    /// same initialization/native suppliers. It preserves prior native peaks
    /// conservatively; no physical disposal credit follows from a status bit.
    /// HELLO traffic, Output, disk and staging spending are not charged again.
    /// The genuine later IO loan separately joins current history growth.
    ///
    /// # Errors
    /// Refuses an incomplete/different native association or checked geometry.
    pub fn completed_receiving_demand_v4(
        &self,
        opening: &aos_sandbox::StartResourceSessionOpeningOriginalV2,
    ) -> Result<aos_sandbox_core::ResourceVector, StartResourceSessionClosedV4> {
        use aos_sandbox::journal::broker_session_receiving as geometry;
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
        if self.first.is_some() || self.capture.is_some() || self.disposal.is_some() {
            return Err(StartResourceSessionClosedV4);
        }
        let session = self
            .completed
            .as_deref()
            .ok_or(StartResourceSessionClosedV4)?;
        let association = opening
            .completed_session_association_v4()
            .ok_or(StartResourceSessionClosedV4)?;
        let journal = session
            .owner
            .start_resource_journal_v4()
            .map_err(|_| StartResourceSessionClosedV4)?;
        association
            .require_same_session_v4(journal, &session.socket, &session.transcript)
            .map_err(|_| StartResourceSessionClosedV4)?;
        let Some(Ok(shape)) = self.shape.as_ref() else {
            return Err(StartResourceSessionClosedV4);
        };
        let mut hello = shape.hello;
        // Runtime prices the enclosing Self header. The completed Session is
        // still a real Box body; only the physically dropped capture and the
        // enclosing inline Self are excluded from this dynamic survivor bound.
        hello.actual_inline_bytes = size_of::<DormantAuthenticatedBrokerSessionV1>()
            .checked_mul(2)
            .ok_or(StartResourceSessionClosedV4)?;
        let mut resident =
            geometry::fixed_start_network_client_handshake_receiving_demand_v2(hello)
                .map_err(|_| StartResourceSessionClosedV4)?
                .checked_add(
                    geometry::fixed_initialization_demand_v1()
                        .map_err(|_| StartResourceSessionClosedV4)?,
                )
                .map_err(|_| StartResourceSessionClosedV4)?;
        for plane in [
            shape.endpoint,
            shape.endpoint_revalidation,
            shape.floor,
            shape.floor_revalidation,
            shape.process,
        ] {
            let bytes = plane
                .inline_bytes
                .checked_add(plane.heap_bytes)
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(StartResourceSessionClosedV4)?;
            let files = u64::try_from(plane.open_files).map_err(|_| StartResourceSessionClosedV4)?;
            let names =
                u64::try_from(plane.metadata_cells).map_err(|_| StartResourceSessionClosedV4)?;
            resident = resident
                .checked_add(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, bytes)
                        .with(D::OpenFiles, files)
                        .with(D::MetadataEntries, names),
                )
                .map_err(|_| StartResourceSessionClosedV4)?;
        }
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, resident.get(D::MemoryBytes))
            .with(D::OpenFiles, resident.get(D::OpenFiles))
            .with(D::MetadataEntries, resident.get(D::MetadataEntries)))
    }

    /// Identifies an actual original native gate selected before later posts.
    #[must_use]
    pub fn native_original_failure_selected_v4(&self) -> bool {
        self.native_primary
    }

    /// Borrows the earliest actual refusal without preferring a later owed post.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let first = self.first?;
        match first {
            First::Reentry => Some(&StartResourceSessionClosedV4 as &dyn std::error::Error),
            First::Shape => self.shape.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Payment => self
                .payment
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Horizon => self
                .horizon
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.cutoff.as_ref()?.as_ref().err().map(|cause| cause as _)),
            First::Capture => {
                let cold = self
                    .capture
                    .as_ref()
                    .is_some_and(|capture| capture.cold_failure_selected_v4());
                let source = if cold {
                    self.current
                        .as_ref()
                        .and_then(|value| value.as_ref().err())
                        .map(|cause| cause as &dyn std::error::Error)
                        .or_else(|| {
                            self.prefix
                                .as_ref()
                                .and_then(|value| value.as_ref().err())
                                .map(|cause| cause as &dyn std::error::Error)
                        })
                        .or_else(|| {
                            if self.captured_native_selected {
                                self.captured_journal.failure()
                            } else {
                                None
                            }
                        })
                } else {
                    None
                };
                source.or_else(|| self.capture.as_ref().and_then(|capture| capture.failure()))
            }
            First::Disposal => self
                .disposal
                .as_ref()
                .map(|cause| cause as &dyn std::error::Error),
            First::NativeFinish => self
                .native_finish
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
        }
        .or(Some(&StartResourceSessionClosedV4))
    }
}

impl Default for StartResourceSessionOpenOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) struct StartResourceColdReceivingV4<'held, 'turn> {
    pub(super) loan: &'held mut StartResourceSessionOpeningLoanV2<'turn>,
    journal: &'held mut ControllerStartResourceSessionCapturedJournalOpenV4,
    current: &'held mut Option<Result<(), ResourceReservationErrorV1>>,
    prefix: &'held mut Option<Result<(), ResourceReservationErrorV1>>,
    captured_native_selected: &'held mut bool,
}

impl FixedServiceColdJournalReceivingV4 for StartResourceColdReceivingV4<'_, '_> {
    fn fixed_endpoint_v4(&self) -> ProtectedBrokerSessionFixedEndpointV1 {
        match self.loan.actual_role_v2() {
            aos_sandbox::ControllerInitialBrokerSessionRoleV1::Host => ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
            aos_sandbox::ControllerInitialBrokerSessionRoleV1::Mount => ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
            aos_sandbox::ControllerInitialBrokerSessionRoleV1::Storage => ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
            _ => ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
        }
    }

    fn durable_endpoint_v4(&self) -> BrokerSessionDurableEndpointV1 {
        BrokerSessionDurableEndpointV1::Client
    }

    fn require_current_v4(&mut self) -> Result<(), BrokerSessionSecurityError> {
        *self.current = Some(self.loan.require_fixed_capture_current_v2());
        if matches!(self.current, Some(Ok(()))) {
            Ok(())
        } else {
            Err(BrokerSessionSecurityError::Currentness)
        }
    }

    fn take_captured_journal_v4(
        &mut self,
    ) -> Result<aos_sandbox::Journal, BrokerSessionSecurityError> {
        self.require_current_v4()?;
        self.journal.prepare_once(
            aos_sandbox::journal::broker_session_receiving::protected_session_journal_limits_v1(),
            CapturedJournalOpenModeV1::CreateAndRepair,
            self.loan,
        );
        if self.journal.failure().is_some() {
            *self.captured_native_selected = true;
            return Err(BrokerSessionSecurityError::Currentness);
        }
        *self.prefix = Some(self.loan.admit_captured_prefix_once_v2(self.journal));
        if !matches!(self.prefix, Some(Ok(()))) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.journal.replay_once(self.loan);
        if self.journal.failure().is_some() {
            *self.captured_native_selected = true;
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let Some((journal, _)) = self.journal.take_opened(self.loan) else {
            *self.captured_native_selected = self.journal.failure().is_some();
            return Err(BrokerSessionSecurityError::Currentness);
        };
        // The writer is moved directly into BrokerMain's parked field by the
        // shared caller before its next fallible endpoint/schema/floor check.
        Ok(journal)
    }
}

/// Borrows only the same privately authenticated, natively completed Client.
///
/// No public constructor or raw Session/Journal/descriptor getter exists. The
/// shared finite Network reducer alone can access the actual co-owned Session.
#[must_use]
pub struct StartResourceSessionBorrowV4<'held> {
    pub(super) inner: &'held mut DormantAuthenticatedBrokerSessionV1,
    pub(super) association: &'held aos_sandbox::StartResourceSessionAssociationV4,
}
