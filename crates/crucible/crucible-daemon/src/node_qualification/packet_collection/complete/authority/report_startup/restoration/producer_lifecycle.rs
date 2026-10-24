//! Forwards selected Producer actions through the same retained fresh owners.

use super::*;
use crucible_engine::node_contract::{OperationOutcome, RuntimePollFailure};
use crucible_node_format::{Id, U64};

impl PacketCompleteReportStartupHolder {
    /// Completes one genuinely admitted restored Producer operation durably.
    ///
    /// The same retained Runtime, Window, SDK group and concrete result store
    /// perform Begin, Poll, committed publication, scheduling ACK, native Retire
    /// and a fresh checkpoint. Every failed action owner remains retained. The
    /// callback borrows the actual completed outcome without cloning authority.
    ///
    /// # Errors
    /// Refuses foreign or incomplete fresh custody, absent independent publisher
    /// admission, operation/capacity/currentness refusal, native uncertainty,
    /// failed durable commitment, failed final proof or a callback error.
    pub fn execute_original_restored_producer(
        original: &Rc<RefCell<Self>>,
        node: &Id,
        operation: Id,
        horizon: U64,
        inspect: &mut dyn FnMut(&OperationOutcome) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimePollFailure> {
        let held = original
            .try_borrow()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        held.authenticate_native_origin_data()
            .map_err(RuntimePollFailure::Admission)?;
        held.authenticate_completed_fresh_runtime_data()
            .map_err(RuntimePollFailure::Admission)?;
        if held.original_scene_retired.get() || held.restored_result_publication.get().is_none() {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        let window = held
            .restoration_window
            .get()
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::OwnerUnavailable,
            ))?;
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        };
        let capsule = capsule
            .try_borrow()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        let outputs = held
            .host_sdk_outputs
            .try_borrow()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        let sdks = [
            outputs[0].as_ref().ok_or(RuntimePollFailure::Admission(
                RuntimeError::OwnerUnavailable,
            ))?,
            outputs[1].as_ref().ok_or(RuntimePollFailure::Admission(
                RuntimeError::OwnerUnavailable,
            ))?,
            outputs[2].as_ref().ok_or(RuntimePollFailure::Admission(
                RuntimeError::OwnerUnavailable,
            ))?,
        ];
        capsule.execute_original_producer_lifecycle_data(
            window,
            &held.plan,
            sdks,
            &held.authority.original_launches,
            held.authority
                .private_launches
                .each_ref()
                .map(Vec::as_slice),
            node,
            operation,
            horizon,
            inspect,
        )
    }
}

impl PacketCompleteReportStartupHolder {
    /// Reconciles the same retained completed operation without redispatching it.
    ///
    /// The global slot is routing DATA. The actual retained admission, token,
    /// outcome and Source fence authenticate the concrete publisher; no caller
    /// can supply replacement report bytes or a completion. Core alone decides
    /// whether the existing publication phase remains retryable.
    ///
    /// # Errors
    /// Refuses foreign/incomplete custody, absent or finished action, changed
    /// currentness, nonretryable phase, uncertain placement, native retirement
    /// or final observation failure, and a callback error.
    pub fn acknowledge_original_restored_producer_stored(
        original: &Rc<RefCell<Self>>,
        slot: usize,
        inspect: &mut dyn FnMut(&OperationOutcome) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimePollFailure> {
        let held = original
            .try_borrow()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        held.authenticate_native_origin_data()
            .map_err(RuntimePollFailure::Admission)?;
        held.authenticate_completed_fresh_runtime_data()
            .map_err(RuntimePollFailure::Admission)?;
        if held.original_scene_retired.get() || held.restored_result_publication.get().is_none() {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ));
        };
        let capsule = capsule
            .try_borrow()
            .map_err(|_| RuntimePollFailure::Admission(RuntimeError::OwnerBusy))?;
        capsule.acknowledge_original_producer_stored_data(
            &held.authority.original_launches,
            held.authority
                .private_launches
                .each_ref()
                .map(Vec::as_slice),
            slot,
            inspect,
        )
    }
}
