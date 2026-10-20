//! Borrows the same dispatch and a disjoint retained State-custody callback.

use super::*;
use crate::worker_protocol::NetworkPrepareWorkerDispatchV1;
use crate::worker_runtime::NetworkWorkerRuntimeError;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::pidfd::NamespaceFd;

pub(in crate::service_original) struct NetworkSourceCustodyReceivingV4<'held> {
    dispatch: &'held NetworkPrepareWorkerDispatchV1,
    effect: &'held aos_sandbox_broker::BrokerEffectIntentV1,
    receiving: &'held mut NetworkReceivingOriginalV4,
    check: &'held mut Option<Result<(), NetworkBrokerError>>,
    custody: &'held mut Option<Result<crate::NetworkNamespaceCustodyV1, NetworkBrokerError>>,
    entered: &'held mut bool,
    first: &'held mut Option<First>,
    original_selected: &'held mut bool,
}

impl NetworkPrepareSourcesOriginalV4 {
    /// Splits the same positive dispatch from its retained callback fields.
    pub(in crate::service_original) fn borrow_worker_dispatch_v4(
        &mut self,
    ) -> Result<
        (
            &NetworkPrepareWorkerDispatchV1,
            NetworkSourceCustodyReceivingV4<'_>,
        ),
        super::super::NetworkServiceClosedV4,
    > {
        if self.dispatch_v4().is_none() || self.custody_entered {
            return Err(super::super::NetworkServiceClosedV4);
        }
        let Some(Ok(NetworkPrepareExecutionOutcomeV1::Dispatch(dispatch))) = self.dispatch.as_ref()
        else {
            return Err(super::super::NetworkServiceClosedV4);
        };
        let verified = self
            .admission
            .verified_v4()
            .ok_or(super::super::NetworkServiceClosedV4)?;
        Ok((
            dispatch,
            NetworkSourceCustodyReceivingV4 {
                dispatch,
                effect: &verified.effect,
                receiving: &mut self.receiving,
                check: &mut self.custody_check,
                custody: &mut self.custody,
                entered: &mut self.custody_entered,
                first: &mut self.first,
                original_selected: &mut self.original_selected,
            },
        ))
    }
}

impl NetworkSourceCustodyReceivingV4<'_> {
    /// Executes only the same worker's actual guarded custody bind once.
    pub(in crate::service_original) fn bind_once_v4(
        &mut self,
        coordinator: &mut NetworkLifecycleAdmissionCoordinator,
        dispatch: &NetworkPrepareWorkerDispatchV1,
        namespace: &NamespaceFd,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        boot: &KernelBootId,
    ) -> Result<(), NetworkWorkerRuntimeError> {
        if *self.entered {
            self.first.get_or_insert(First::Custody);
            return Err(NetworkWorkerRuntimeError::Protocol(
                "Source custody cannot reenter",
            ));
        }
        *self.entered = true;
        *self.check = Some((|| {
            loan.require_network_prepare_current_v4().map_err(|_| {
                *self.original_selected = true;
                NetworkBrokerError::Authority
            })?;
            let (pair, _) = loan.retained_network_horizon_data_v4().map_err(|_| {
                *self.original_selected = true;
                NetworkBrokerError::Authority
            })?;
            if !std::ptr::eq(self.dispatch, dispatch) || pair.host_boot_id() != boot.into_bytes() {
                return Err(NetworkBrokerError::Request);
            }
            Ok(())
        })());
        if !matches!(self.check, Some(Ok(()))) {
            self.first.get_or_insert(First::Custody);
            return Err(NetworkWorkerRuntimeError::Protocol(
                "retained Source custody binding refused",
            ));
        }
        let identity = namespace.identity();
        let plan = dispatch.kernel_plan();
        let mut receiving = NetworkPrepareEffectReceivingV4 {
            original: &mut *self.receiving,
            loan,
        };
        *self.custody = Some(coordinator.bind_effect_namespace_custody_guarded_v4(
            dispatch.request_id(),
            dispatch.effect_digest(),
            *plan.network_handle(),
            boot.into_bytes(),
            identity.device,
            identity.inode,
            plan.digest(),
            &mut receiving,
            self.effect,
        ));
        if matches!(self.custody, Some(Ok(_))) {
            Ok(())
        } else {
            if self.receiving.original_failure_selected_v4() {
                *self.original_selected = true;
            }
            self.first.get_or_insert(First::Custody);
            Err(NetworkWorkerRuntimeError::Protocol(
                "retained Source custody append refused",
            ))
        }
    }
}
