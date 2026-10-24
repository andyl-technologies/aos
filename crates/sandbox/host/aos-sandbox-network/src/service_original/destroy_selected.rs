//! Keeps Destroy9's original signed sources on the actual enrolled Netd loan.
//!
//! The sole lifecycle admission and State engines produce its real dispatch.
//! A dispatch remains a pre-effect boundary: genuine child Source/F, P/O,
//! physical absence, pin removal and all enclosing posts remain required.

use super::callsite::NetworkServiceMethodV4;
use super::receiving::{
    NetworkPrepareEffectReceivingV4, NetworkReceivingErrorV4, NetworkReceivingOriginalV4,
};
use super::*;
use crate::broker::{
    NetworkBrokerError, NetworkLifecycleAdmissionOriginalV4, NetworkLifecycleAdmissionOutcome,
};
use crate::lifecycle_worker_protocol::NetworkLifecycleWorkerDispatchV1;
use aos_sandbox_broker::receiving::NetworkServiceReceivingLoanV4;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

#[derive(Clone, Copy)]
enum First {
    Order,
    Request,
    Receiving,
    Resolution,
    Admission,
    Dispatch,
    Fence,
    Ready,
}

/// Retains Destroy9's true signed admission, durable dispatch and source failures.
///
/// Construction is inert. This original supplies neither a kernel result nor
/// permission to use a legacy worker. The actual same-F P/O custody, effects
/// and complete absence/custody observations remain independent obligations.
#[must_use]
pub struct NetworkServiceDestroyOriginalV4 {
    admission: NetworkLifecycleAdmissionOriginalV4,
    receiving: NetworkReceivingOriginalV4,
    request: Option<std::result::Result<(), Closed>>,
    resolved: Option<
        std::result::Result<
            (
                crate::catalog::AuthenticatedNetworkPreparationV1,
                crate::NetworkKernelPlanV1,
            ),
            NetworkBrokerError,
        >,
    >,
    narrow: Option<std::result::Result<(), Closed>>,
    admitted: Option<std::result::Result<NetworkLifecycleAdmissionOutcome, NetworkBrokerError>>,
    dispatch: Option<std::result::Result<NetworkLifecycleWorkerDispatchV1, NetworkBrokerError>>,
    fence: Option<std::result::Result<Vec<u8>, NetworkBrokerError>>,
    ready: Option<std::result::Result<(), crate::state::NetworkStateError>>,
    first: Option<First>,
    original_selected: bool,
    entered: bool,
}

impl NetworkServiceDestroyOriginalV4 {
    /// Creates fixed empty destinations without allocation, admission or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            admission: NetworkLifecycleAdmissionOriginalV4::new(),
            receiving: NetworkReceivingOriginalV4::new(),
            request: None,
            resolved: None,
            narrow: None,
            admitted: None,
            dispatch: None,
            fence: None,
            ready: None,
            first: None,
            original_selected: false,
            entered: false,
        }
    }

    /// Identifies a refusal retained on this same actual enrolled parent loan.
    #[must_use]
    pub fn original_failure_selected_v4(&self) -> bool {
        self.original_selected || self.receiving.original_failure_selected_v4()
    }

    /// Borrows the first selected signed, receiving, catalog or State failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn cause<T, E: Error + 'static>(
            slot: &Option<std::result::Result<T, E>>,
        ) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            First::Order => None,
            First::Request => cause(&self.request),
            First::Receiving => self.receiving.failure(),
            First::Resolution => cause(&self.resolved),
            First::Admission => self
                .receiving
                .failure()
                .or_else(|| self.admission.failure())
                .or_else(|| cause(&self.narrow))
                .or_else(|| cause(&self.admitted)),
            First::Dispatch => self.receiving.failure().or_else(|| cause(&self.dispatch)),
            First::Fence => cause(&self.fence),
            First::Ready => self.receiving.failure().or_else(|| cause(&self.ready)),
        }
        .or(Some(&NetworkServiceClosedV4))
    }

    // Only the actual same-module worker continuation may borrow this positive
    // owner. No caller-provided dispatch/fence pair can replace its custody.
    pub(super) fn dispatch_v4(&self) -> Option<(&NetworkLifecycleWorkerDispatchV1, &[u8])> {
        if self.first.is_some() || !matches!(self.ready, Some(Ok(()))) {
            return None;
        }
        Some((
            self.dispatch.as_ref()?.as_ref().ok()?,
            self.fence.as_ref()?.as_ref().ok()?.as_slice(),
        ))
    }

    pub(super) fn observer_verified_original_v2(&self)
        -> Option<&aos_sandbox_broker::VerifiedBrokerAdmission>
    {
        self.dispatch_v4()?;
        self.admission.verified_v4()
    }
}

impl Default for NetworkServiceDestroyOriginalV4 {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkServiceDomainCallsiteV4<'_> {
    /// Runs Destroy9's sole signed admission and guarded durable dispatch issuer.
    ///
    /// All catalogs are the same protected startup owners. The same genuine
    /// Source/F loan prepays models and each actual State transaction before
    /// native entry. Its original D is narrowed to the verified signed effect.
    /// This method launches no worker and returns no successful client result.
    ///
    /// # Errors
    /// Retains wrong-purpose/request, original financial/native, signature,
    /// catalog, current-resource, durable State or dispatch refusal.
    pub fn destroy_sources_once_v4(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkServiceDestroyOriginalV4,
    ) -> Result<()> {
        if original.entered {
            original.first.get_or_insert(First::Order);
            return Err(NetworkServiceClosedV4);
        }
        original.entered = true;
        let result = self.destroy_sources_inner_v4(request, loan, original);
        if result.is_err() {
            // Select even an untagged early refusal before any enclosing
            // Session/F post can report a later, independent failure.
            original.first.get_or_insert(First::Request);
        }
        result
    }

    fn destroy_sources_inner_v4(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkServiceDestroyOriginalV4,
    ) -> Result<()> {
        original.request = Some((|| {
            if !matches!(self.method, NetworkServiceMethodV4::Destroy)
                || request.network_destroy_data_v4().is_none()
            {
                return Err(Closed);
            }
            loan.require_network_destroy_current_v4().map_err(|_| {
                original.original_selected = true;
                Closed
            })
        })());
        if !matches!(original.request, Some(Ok(()))) {
            original.first = Some(First::Request);
            return Err(NetworkServiceClosedV4);
        }
        let semantic = request
            .network_destroy_data_v4()
            .ok_or(NetworkServiceClosedV4)?;
        let artifacts = request.authorization().ok_or(NetworkServiceClosedV4)?;
        let demand = (|| {
            let overflow = AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            let bytes = std::mem::size_of::<NetworkServiceDestroyOriginalV4>()
                .checked_mul(2)
                .and_then(|bytes| {
                    bytes.checked_add(request.canonical_packet().len().checked_mul(4)?)
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<NetworkLifecycleWorkerDispatchV1>().checked_mul(2)?,
                    )
                })
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(overflow)?;
            self.coordinator
                .signed_preparation_receiving_demand_v4(artifacts)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?
                .checked_add(NetworkLifecycleAdmissionOriginalV4::receiving_demand_v4()?)?
                .checked_add(crate::lifecycle_state::lifecycle_record_receiving_demand_v4()?)?
                .checked_add(crate::kernel_plan::compilation_receiving_demand_v4()?)
        })()
        .map_err(NetworkReceivingErrorV4::from);
        if original
            .receiving
            .admit_additional_v4(loan, demand)
            .is_err()
        {
            original.first = Some(First::Receiving);
            return Err(NetworkServiceClosedV4);
        }
        let assignment = semantic
            .fence()
            .broker_assignment()
            .map_err(|_| NetworkServiceClosedV4)?;
        let handle = semantic
            .operation()
            .network_handle()
            .copied()
            .ok_or(NetworkServiceClosedV4)?;
        original.resolved = Some(self.coordinator.resolve_session_request_preparation(
            self.preparations,
            assignment,
            Some(handle),
        ));
        let Some(Ok((catalog, plan))) = original.resolved.as_ref() else {
            original.first = Some(First::Resolution);
            return Err(NetworkServiceClosedV4);
        };
        let (clock, _) = loan.retained_network_horizon_data_v4().map_err(|_| {
            original.original_selected = true;
            original.first = Some(First::Request);
            NetworkServiceClosedV4
        })?;
        let receiving = &mut original.receiving;
        let narrow = &mut original.narrow;
        let selected = &mut original.original_selected;
        original.admitted = Some(original.admission.run_selected_once_v4(
            self.coordinator,
            request,
            catalog,
            plan,
            self.namespaces,
            &clock,
            &mut |authority, admission, journal, transaction| {
                *narrow = Some(
                    loan.narrow_deadline_data_v4(
                        admission.effect.effect_deadline_boottime_nanoseconds(),
                        Some(
                            admission
                                .effect
                                .plan_expires_seconds()
                                .min(admission.effect.authority_expires_seconds()),
                        ),
                    ),
                );
                if !matches!(narrow, Some(Ok(()))) {
                    *selected = true;
                    return Err(crate::lifecycle_state::NetworkLifecycleStateError::Receiving);
                }
                receiving
                    .before_append_v4(loan, authority, &admission.effect, journal, transaction)
                    .map_err(|_| crate::lifecycle_state::NetworkLifecycleStateError::Receiving)
            },
        ));
        if !matches!(
            original.admitted,
            Some(Ok(NetworkLifecycleAdmissionOutcome::Prepared { .. }))
        ) {
            original.first = Some(First::Admission);
            return Err(NetworkServiceClosedV4);
        }
        if original.narrow.is_none() {
            // An exact existing Prepared row takes no begin-append frontier.
            // It still retains the same verified signed D before dispatch;
            // the absence of that append cannot leave a wider worker bound.
            let admission = original
                .admission
                .verified_v4()
                .ok_or(NetworkServiceClosedV4)?;
            original.narrow = Some(
                loan.narrow_deadline_data_v4(
                    admission.effect.effect_deadline_boottime_nanoseconds(),
                    Some(
                        admission
                            .effect
                            .plan_expires_seconds()
                            .min(admission.effect.authority_expires_seconds()),
                    ),
                ),
            );
            if !matches!(original.narrow, Some(Ok(()))) {
                original.original_selected = true;
                original.first = Some(First::Admission);
                return Err(NetworkServiceClosedV4);
            }
        }
        let (catalog, plan) = match original.resolved.take() {
            Some(Ok(resolved)) => resolved,
            _ => {
                original.first = Some(First::Resolution);
                return Err(NetworkServiceClosedV4);
            }
        };
        let mut receiving = NetworkPrepareEffectReceivingV4 {
            original: &mut original.receiving,
            loan,
        };
        original.dispatch = Some(self.coordinator.begin_destroy_effect_guarded_v4(
            request,
            catalog,
            plan,
            &original.admission,
            &mut receiving,
        ));
        let Some(Ok(dispatch)) = original.dispatch.as_ref() else {
            original.first = Some(First::Dispatch);
            return Err(NetworkServiceClosedV4);
        };
        original.fence = Some(self.coordinator.trusted_lifecycle_fence(dispatch));
        if !matches!(original.fence, Some(Ok(_))) {
            original.first = Some(First::Fence);
            return Err(NetworkServiceClosedV4);
        }
        let admission = original.admission.verified_v4().ok_or(NetworkServiceClosedV4)?;
        original.ready = Some(original.receiving.require_effect_current_v4(
            loan, self.coordinator.authority(), &admission.effect));
        if !matches!(original.ready, Some(Ok(()))) {
            original.first = Some(First::Ready);
            return Err(NetworkServiceClosedV4);
        }
        // This last actual clock/effect gate does not discharge native posts.
        // The same enclosing Source/Session owner still owes its independent
        // after, and the real worker caller must gate again before physical IO.
        Ok(())
    }
}
