//! Owns the actual initial Controller Client through the shared HELLO and cold engines.
//!
//! A genuine once-role B receiver is already fixed-paid and entered before
//! this inert owner is installed. It retains endpoint partials, connect/peer
//! outcomes, reducer failures, cold custody and the independent original post.

use super::*;
use super::selected_client_open::{SelectedClientCaptureV1, SelectedClientReceivingV1};
use std::path::Path;
use aos_sandbox_controller_domain::{
    ControllerInitialBrokerSessionCaptureShapeV1 as CaptureShape,
    ControllerInitialBrokerSessionClosedV1 as NativeClosed,
    ControllerInitialBrokerSessionReceivingLoanV1 as Loan,
    ControllerInitialBrokerSessionReceivingV1 as Receiving,
    ControllerInitialBrokerSessionRoleV1 as Role,
    ControllerInitialBrokerSessionShapeV1 as Shape,
};

#[derive(Debug, thiserror::Error)]
#[error("the original Controller initial Client remains closed with custody retained")]
pub(crate) struct ControllerInitialClientClosedV1;

pub(crate) struct ControllerInitialSessionOpenV1 {
    receiving: Receiving,
    capture: SelectedClientCaptureV1,
    result: Option<Result<(), ControllerInitialClientClosedV1>>,
    post: Option<Result<(), NativeClosed>>,
    native_disposition: Option<Result<(), BrokerSessionSecurityError>>,
    completed_transport: Option<std::num::NonZeroU64>,
    native_primary: bool,
    entered: bool,
    taken: bool,
}

impl ControllerInitialSessionOpenV1 {
    pub(crate) fn receiving_shape_v1(role: Role) -> Option<Shape> {
        let (failure_bytes, failure_cells) = storage_preparation_handshake_failure_obligations_v1()?;
        let hello_bytes = CLIENT_HELLO_MAXIMUM_BYTES.checked_add(SERVER_HELLO_MAXIMUM_BYTES)?;
        let checkpoint_heap = HistoricalSessionCheckpointConstructionCaptureV1::
            receiving_nonprojection_heap_bytes_v1(hello_bytes)?;
        let checkpoint_move = HistoricalSessionCheckpointConstructionCaptureV1::construction_bytes_v1();
        let failure_bytes = failure_bytes.checked_add(checkpoint_heap)?.checked_add(checkpoint_move)?;
        let failure_cells = failure_cells
            .checked_add(HistoricalSessionCheckpointConstructionCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(HistoricalSessionCheckpointConstructionCaptureV1::receiving_table_metadata_cells_v1(hello_bytes)?)?
            .checked_add(1)?;
        let process = storage_process_evidence_footprint_v1()?;
        let floor_revalidation = if role == Role::Storage {
            let floor = crate::recovery::floor_revalidation_footprint_v1()?;
            CaptureShape {
                inline_bytes: floor.inline_bytes,
                heap_bytes: floor.heap_bytes,
                open_files: floor.file_descriptors,
                metadata_cells: floor.metadata_cells,
            }
        } else {
            // These fixed protocols never enter the Storage mode/archive IO.
            // Their real inline cold interval is already in the capsule size.
            CaptureShape { inline_bytes: 0, heap_bytes: 0, open_files: 0, metadata_cells: 0 }
        };
        Some(Shape {
            hello: aos_sandbox_controller_domain::journal::broker_session_receiving::StorageHandshakePrivateFootprintV1 {
                // The concrete constructor temporary and boxed destination may
                // coexist; no optimizer placement is assumed.
                actual_inline_bytes: std::mem::size_of::<Self>().checked_mul(2)?,
                actual_failure_bytes: failure_bytes,
                // Capture, outer-result and main-stage control destinations
                // remain resident alongside the shared reducer failure owner.
                actual_failure_cells: failure_cells.checked_add(33)?,
            },
            endpoint: crate::endpoint::ProtectedBrokerSessionControllerClientOpeningV1::receiving_shape_v1()?,
            endpoint_revalidation: crate::endpoint::controller_initial_endpoint_revalidation_shape_v1()?,
            floor: crate::recovery::floor_initial_capture_shape_v1(role)?,
            floor_revalidation,
            process: CaptureShape {
                inline_bytes: process.inline_bytes,
                heap_bytes: process.heap_bytes,
                open_files: process.file_descriptors,
                metadata_cells: process.metadata_cells,
            },
        })
    }

    pub(crate) fn new(
        receiving: Receiving,
        launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
    ) -> Self {
        Self {
            receiving,
            capture: SelectedClientCaptureV1::controller(launch_image),
            result: None,
            post: None,
            native_disposition: None,
            completed_transport: None,
            native_primary: false,
            entered: false,
            taken: false,
        }
    }

    pub(crate) fn open_once(&mut self) -> Result<(), ControllerInitialClientClosedV1> {
        self.open_with_coverage_once_v1(None)
    }

    pub(crate) fn open_git_coverage_once_v1(
        &mut self,
        account: &mut aos_sandbox_controller_domain::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), ControllerInitialClientClosedV1> {
        self.open_with_coverage_once_v1(Some(account))
    }

    fn open_with_coverage_once_v1(
        &mut self,
        account: Option<&mut aos_sandbox_controller_domain::policy_compiler::GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(), ControllerInitialClientClosedV1> {
        if self.entered || self.taken {
            return Err(ControllerInitialClientClosedV1);
        }
        self.entered = true;
        self.result = Some(match self.receiving.borrow_once_v1() {
            Ok(mut loan) => match Self::receiving_shape_v1(loan.role_v1()) {
                Some(shape) if loan.admit_actual_capture_shape_once_v1(shape).is_ok() =>
                    self.capture.drive_once(SelectedClientReceivingV1::Controller { receiving: &mut loan, account }),
                _ => Err(ControllerInitialClientClosedV1),
            },
            Err(_) => Err(ControllerInitialClientClosedV1),
        });
        // Latch the actual prefix/loan cause before a later independent post
        // can fail. No borrowed cause or local native owner escapes this slot.
        self.native_primary = self.receiving.failure().is_some();
        self.post = Some(self.receiving.finish_capture_once_v1());
        if matches!(self.result, Some(Ok(()))) && matches!(self.post, Some(Ok(()))) {
            self.result = Some(self.capture.deadline_v1().map(|_| ()));
        }
        if matches!(self.result, Some(Ok(()))) && matches!(self.post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(ControllerInitialClientClosedV1)
        }
    }

    pub(crate) fn take_completed(&mut self) -> Option<DormantAuthenticatedBrokerSessionV1> {
        if self.taken || !matches!(self.result, Some(Ok(())))
            || !matches!(self.post, Some(Ok(())))
        {
            return None;
        }
        if self.native_disposition.is_none() {
            let Some(Ok(session)) = self.capture.completed.as_mut() else {
                std::process::abort()
            };
            self.native_disposition = Some(if session.terminal_witness_failure
                || session.terminal_witness_debt.is_some()
                || !matches!(&session.client_witnesses, Ok(Some(witnesses)) if witnesses.first_failure.is_none())
            {
                Err(BrokerSessionSecurityError::Currentness)
            } else {
                session.owner.retire_completed_initial_native_v1(&self.receiving)
            });
        }
        if !matches!(self.native_disposition, Some(Ok(()))) { return None; }
        let Some(Ok(session)) = self.capture.completed.as_mut() else { std::process::abort() };
        match self.receiving.retain_execution_cold_native_v2() {
            Ok(retention) => session.execution_cold_native = retention,
            Err(_) => {
                self.native_disposition = Some(Err(BrokerSessionSecurityError::Currentness));
                return None;
            }
        }
        match self.receiving.retain_recovery_session_native_v1() {
            Ok(retention) => session.recovery_session_native = retention,
            Err(_) => {
                self.native_disposition = Some(Err(BrokerSessionSecurityError::Currentness));
                return None;
            }
        }
        match self.receiving.retain_stop_cleanup_session_native_v1() {
            Ok(retention) => session.stop_cleanup_source_native = retention,
            Err(_) => {
                self.native_disposition = Some(Err(BrokerSessionSecurityError::Currentness));
                return None;
            }
        }
        let Some(Ok(session)) = self.capture.completed.take() else {
            std::process::abort()
        };
        self.completed_transport = Some(session.socket.peer().socket_cookie());
        self.taken = true;
        // Native replay, actual HELLO, cold retirement and the independent
        // original post all succeeded. Dispose only their completed temporary
        // capture, while the Session and original once-role B remain held.
        let completed_capture = std::mem::replace(&mut self.capture, SelectedClientCaptureV1::controller(None));
        drop(completed_capture);
        Some(session)
    }

    pub(crate) fn borrow_completed_session_v1<'held>(
        &'held self,
        session: &'held mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<ControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        if !self.taken || !matches!(self.result, Some(Ok(())))
            || !matches!(self.post, Some(Ok(())))
            || !matches!(self.native_disposition, Some(Ok(())))
            || self.failure().is_some()
            || self.completed_transport != Some(session.socket.peer().socket_cookie())
            || session.terminal_witness_failure || session.terminal_witness_debt.is_some()
            || !matches!(&session.client_witnesses, Ok(Some(witnesses)) if witnesses.first_failure.is_none())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // Rejoin the actual endpoint/main and, for Required, actual sidecar
        // and physical owner. This performs no IO. Any remaining unused native
        // destinations are disposed only by the same owning positive method.
        session.owner.retire_completed_initial_native_v1(&self.receiving)?;
        Ok(ControllerInitialSessionCompletedBorrowV1 { receiving: &self.receiving, session })
    }

    pub(crate) fn original_after_completed_preparation_v1<'capture>(
        &'capture self,
        rollover: &super::client_storage_continuation::CompletedStorageClientRolloverV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<&'capture Receiving, BrokerSessionSecurityError> {
        // The same private native join is complete before the pure ownership
        // move into the retained kernel. The capture and all original B native
        // owners remain borrowed for the entire new finite Client loan.
        let completed = self.borrow_completed_preparation_session_v1(rollover, session)?;
        drop(completed);
        Ok(&self.receiving)
    }

    pub(crate) fn borrow_completed_preparation_session_v1<'held>(
        &'held self,
        rollover: &super::client_storage_continuation::CompletedStorageClientRolloverV1,
        session: &'held mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<ControllerInitialSessionCompletedBorrowV1<'held>, BrokerSessionSecurityError> {
        if !self.taken || !matches!(self.result, Some(Ok(())))
            || !matches!(self.post, Some(Ok(())))
            || !matches!(self.native_disposition, Some(Ok(())))
            || self.failure().is_some()
            || !self.completed_transport.is_some_and(|cookie| rollover.matches_initial_v1(cookie))
            || !rollover.matches_session_v1(session)
            || session.terminal_witness_failure || session.terminal_witness_debt.is_some()
            || !matches!(&session.client_witnesses, Ok(Some(witnesses)) if witnesses.first_failure.is_none())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // The old cookie is never replaced. The completed rollover joins it
        // to this current transport before the SAME owning native association.
        session.owner.retire_completed_initial_native_v1(&self.receiving)?;
        Ok(ControllerInitialSessionCompletedBorrowV1 { receiving: &self.receiving, session })
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.native_primary {
            return self.receiving.failure();
        }
        self.capture.failure().or_else(|| self.receiving.failure())
            .or_else(|| self.native_disposition.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error))
    }
}

/// Borrows the complete real Session beside its original once-role receiver.
///
/// No survivor is replaced by an identity Arc: socket, authenticated witnesses,
/// main, floor/sidecar/helper, endpoint and native observer remain in Session.
/// The private transition may reborrow it mutably for its existing checks.
pub(crate) struct ControllerInitialSessionCompletedBorrowV1<'held> {
    receiving: &'held Receiving,
    session: &'held mut DormantAuthenticatedBrokerSessionV1,
}

impl<'held> ControllerInitialSessionCompletedBorrowV1<'held> {
    pub(crate) fn into_parts_v2(self) -> (&'held Receiving, &'held mut DormantAuthenticatedBrokerSessionV1) {
        (self.receiving, self.session)
    }

    pub(crate) fn require_recovered_ordinary_context_v2(
        &self,
        context: &aos_sandbox_broker::controller_receiving::bank_launch::ControllerRecoveredOrdinarySessionsOriginalV2,
        bank: &aos_sandbox_controller_domain::ControllerResourceBankOpeningV1,
        controller: &aos_sandbox_controller_domain::Journal,
        profile: &aos_sandbox_controller_domain::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.session.owner.require_completed_recovered_initial_native_v2(
            self.receiving, context, bank, controller, profile)
    }

    pub(crate) fn reborrow_v1(&mut self)
        -> (&Receiving, &mut DormantAuthenticatedBrokerSessionV1)
    {
        (self.receiving, self.session)
    }
}
