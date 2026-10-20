//! Calls the sole retained parent P/O engine from actual completed sources.

use super::*;
use aos_sandbox_linux::boot::KernelBootId;

impl NetworkServiceDomainCallsiteV4<'_> {
    /// Executes Destroy9's distinct signed programme through the same P/O engine.
    ///
    /// The supplied namespace is checked against the genuine signed lifecycle
    /// dispatch by the parent engine. Its separately retained coordinator fence
    /// accompanies that dispatch. The resulting kernel absence is only one
    /// prerequisite: actual pin/store removal and the lifecycle commit remain
    /// owed to the enclosing Destroy owner after both terminal K records.
    ///
    /// # Errors
    /// Retains wrong purpose, signed source mismatch, profile/whole-pair fit,
    /// original payer, native birth, worker, absence or independent post failure.
    pub fn destroy_workers_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        sources: &super::super::destroy_selected::NetworkServiceDestroyOriginalV4,
        target: &NamespaceFd,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkServiceWorkersOriginalV2,
    ) -> Result<()> {
        if !matches!(
            self.method,
            super::super::callsite::NetworkServiceMethodV4::Destroy
        ) {
            return original.close(First::Request);
        }
        let (dispatch, trusted_current_fence) =
            sources.dispatch_v4().ok_or(NetworkServiceClosedV4)?;
        let verified = sources
            .observer_verified_original_v2()
            .ok_or(NetworkServiceClosedV4)?;
        let input = NetworkParentMutationInputV2::Destroy {
            dispatch,
            target,
            trusted_current_fence,
        };
        original.compile_once_v2(
            request,
            verified,
            dispatch.kernel_plan(),
            &input,
            BrokerVerb::NetworkDestroy,
            self.coordinator,
            self.namespace_store,
            self.namespaces,
            loan,
        )?;
        original.preflight_once_v2(loan)?;
        let quote = *original
            .quote
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(NetworkServiceClosedV4)?;
        original.funding[2] = Some(loan.require_additional_representation_v4(quote.transports[0]));
        if !matches!(original.funding[2], Some(Ok(()))) {
            return original.close(First::Funding(2));
        }
        let mut reservation = match loan.reserve_network_worker_birth_once_v2(
            &mut original.preparation_birth,
            Purpose::Preparation,
            Ok(quote.children[0]),
        ) {
            Ok(reservation) => reservation,
            Err(_) => {
                original.first = Some(First::Birth(0));
                return Err(NetworkServiceClosedV4);
            }
        };
        original.births[0] = Some((|| {
            reservation.prepare_prebirth_data_once_v2(
                request,
                dispatch.effect_digest(),
                quote.probes[0],
            )?;
            reservation.send_prebirth_once_v2()?;
            reservation.receive_prepared_once_v2()
        })());
        if !matches!(original.births[0], Some(Ok(()))) {
            original.first = Some(First::Birth(0));
            return Err(NetworkServiceClosedV4);
        }
        let Some(Ok(cleanup)) = original.cleanup.as_mut() else {
            return Err(NetworkServiceClosedV4);
        };
        original.mutation_result = Some(original.mutation.execute_once_v2(
            self.prepare_executor,
            &mut reservation,
            cleanup,
            input,
            |_, same_loan| same_loan.require_network_destroy_current_v4(),
        ));
        drop(reservation);
        if !matches!(original.mutation_result, Some(Ok(()))) {
            return original.close(First::Mutation);
        }
        let input = NetworkParentObservationInputV2::new(
            &original.mutation,
            target,
            dispatch.kernel_plan(),
        )
        .map_err(|_| NetworkServiceClosedV4)?;
        original.funding[3] = Some(loan.require_additional_representation_v4(quote.transports[1]));
        if !matches!(original.funding[3], Some(Ok(()))) {
            return original.close(First::Funding(3));
        }
        let mut reservation = match loan.reserve_network_worker_birth_once_v2(
            &mut original.observation_birth,
            Purpose::Observation,
            Ok(quote.children[1]),
        ) {
            Ok(reservation) => reservation,
            Err(_) => {
                original.first = Some(First::Birth(1));
                return Err(NetworkServiceClosedV4);
            }
        };
        original.births[1] = Some((|| {
            reservation.prepare_prebirth_data_once_v2(
                request,
                dispatch.effect_digest(),
                quote.probes[1],
            )?;
            reservation.send_prebirth_once_v2()?;
            reservation.receive_prepared_once_v2()
        })());
        if !matches!(original.births[1], Some(Ok(()))) {
            original.first = Some(First::Birth(1));
            return Err(NetworkServiceClosedV4);
        }
        let Some(Ok(cleanup)) = original.cleanup.as_mut() else {
            return Err(NetworkServiceClosedV4);
        };
        let sections = sections_v2(&original.payloads, request).ok_or(NetworkServiceClosedV4)?;
        original.observation_result = Some(original.observation.execute_once_v2(
            self.observation_executor,
            &mut reservation,
            cleanup,
            input,
            self.public_credentials,
            sections,
        ));
        drop(reservation);
        if !matches!(original.observation_result, Some(Ok(_))) {
            return original.close(First::Observation);
        }
        Ok(())
    }

    /// Executes and finalizes Prepare63 on its actual signed sources and payer.
    ///
    /// Both complete child quotes and parent transport/custody/suffix costs fit
    /// before P birth. The existing State binder and native FDStore run before
    /// any effect frame. P/O retain the same original operation and D; actual
    /// clean exit, death/Empty, K and all source/native posts precede finalization.
    ///
    /// # Errors
    /// Retains source, profile, same-F shortage, birth, native worker, custody,
    /// observation or guarded finalization refusal without a legacy fallback.
    pub fn execute_prepared_workers_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        sources: &mut super::super::prepare_selected::NetworkServicePrepareOriginalV4,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkServiceWorkersOriginalV2,
    ) -> Result<()> {
        if !matches!(
            self.method,
            super::super::callsite::NetworkServiceMethodV4::Prepare
        ) {
            return original.close(First::Request);
        }
        let dispatch = sources
            .sources
            .dispatch_v4()
            .ok_or(NetworkServiceClosedV4)?;
        let binding = (
            std::ptr::from_ref(&*sources).addr(),
            request.request_id(),
            request.signed_request_digest(),
            dispatch.kernel_plan().digest(),
        );
        if original.prepared_source != Some(binding)
            || original.verb != Some(BrokerVerb::NetworkPrepare)
            || original.response.prospective_body_data_v2().is_none()
        {
            return original.close(First::Request);
        }
        // The SDK prepays its actual terminal on this same ledger between
        // compilation and execution. Compare the entire P/O pair only now,
        // against that updated debt, before the first transport or PREBIRTH.
        original.preflight_once_v2(loan)?;
        let quote = *original
            .quote
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(NetworkServiceClosedV4)?;
        original.funding[2] = Some(loan.require_additional_representation_v4(quote.transports[0]));
        if !matches!(original.funding[2], Some(Ok(()))) {
            return original.close(First::Funding(2));
        }
        original.store_name = Some(NetworkNamespaceStoreName::from_network_handle(
            *dispatch.kernel_plan().network_handle(),
        ));
        if !matches!(original.store_name, Some(Ok(_))) {
            return original.close(First::Store);
        }
        let (pair, _) = loan
            .retained_network_horizon_data_v4()
            .map_err(|_| NetworkServiceClosedV4)?;
        original.boot = Some(KernelBootId::from_bytes(pair.host_boot_id()));
        let Some(Ok(boot)) = original.boot.as_ref() else {
            return original.close(First::Request);
        };
        let (dispatch, mut custody) = sources.sources.borrow_worker_dispatch_v4()?;
        let mut reservation = match loan.reserve_network_worker_birth_once_v2(
            &mut original.preparation_birth,
            Purpose::Preparation,
            Ok(quote.children[0]),
        ) {
            Ok(reservation) => reservation,
            Err(_) => {
                original.first = Some(First::Birth(0));
                return Err(NetworkServiceClosedV4);
            }
        };
        original.births[0] = Some((|| {
            reservation.prepare_prebirth_data_once_v2(
                request,
                dispatch.effect_digest(),
                quote.probes[0],
            )?;
            reservation.send_prebirth_once_v2()?;
            reservation.receive_prepared_once_v2()
        })());
        if !matches!(original.births[0], Some(Ok(()))) {
            original.first = Some(First::Birth(0));
            return Err(NetworkServiceClosedV4);
        }
        let Some(Ok(cleanup)) = original.cleanup.as_mut() else {
            return Err(NetworkServiceClosedV4);
        };
        let Some(Ok(name)) = original.store_name.as_ref() else {
            return Err(NetworkServiceClosedV4);
        };
        let coordinator = &mut *self.coordinator;
        let store = self.namespace_store;
        let store_original = &mut original.store;
        let store_result = &mut original.store_result;
        original.mutation_result = Some(original.mutation.execute_once_v2(
            self.prepare_executor,
            &mut reservation,
            cleanup,
            NetworkParentMutationInputV2::Prepare(dispatch),
            |namespace, same_loan| {
                custody
                    .bind_once_v4(coordinator, dispatch, namespace, same_loan, boot)
                    .map_err(|_| Closed)?;
                *store_result =
                    Some(store.store_retaining_once_v4(name, namespace, same_loan, store_original));
                match store_result {
                    Some(Ok(
                        NetworkNamespaceStoreOutcome::Stored | NetworkNamespaceStoreOutcome::Replay,
                    )) => Ok(()),
                    _ => Err(Closed),
                }
            },
        ));
        drop(reservation);
        if !matches!(original.mutation_result, Some(Ok(()))) {
            return original.close(
                if original
                    .store_result
                    .as_ref()
                    .is_some_and(|result| result.is_err())
                {
                    First::Store
                } else {
                    First::Mutation
                },
            );
        }
        let dispatch = sources
            .sources
            .dispatch_v4()
            .ok_or(NetworkServiceClosedV4)?;
        let target = original
            .mutation
            .completed_namespace_v2()
            .ok_or(NetworkServiceClosedV4)?;
        let plan = dispatch.kernel_plan();
        let input = NetworkParentObservationInputV2::new(&original.mutation, target, plan)
            .map_err(|_| NetworkServiceClosedV4)?;
        original.funding[3] = Some(loan.require_additional_representation_v4(quote.transports[1]));
        if !matches!(original.funding[3], Some(Ok(()))) {
            return original.close(First::Funding(3));
        }
        let mut reservation = match loan.reserve_network_worker_birth_once_v2(
            &mut original.observation_birth,
            Purpose::Observation,
            Ok(quote.children[1]),
        ) {
            Ok(reservation) => reservation,
            Err(_) => {
                original.first = Some(First::Birth(1));
                return Err(NetworkServiceClosedV4);
            }
        };
        original.births[1] = Some((|| {
            reservation.prepare_prebirth_data_once_v2(
                request,
                dispatch.effect_digest(),
                quote.probes[1],
            )?;
            reservation.send_prebirth_once_v2()?;
            reservation.receive_prepared_once_v2()
        })());
        if !matches!(original.births[1], Some(Ok(()))) {
            original.first = Some(First::Birth(1));
            return Err(NetworkServiceClosedV4);
        }
        let Some(Ok(cleanup)) = original.cleanup.as_mut() else {
            return Err(NetworkServiceClosedV4);
        };
        let sections = sections_v2(&original.payloads, request).ok_or(NetworkServiceClosedV4)?;
        original.observation_result = Some(original.observation.execute_once_v2(
            self.observation_executor,
            &mut reservation,
            cleanup,
            input,
            self.public_credentials,
            sections,
        ));
        drop(reservation);
        let Some(proof) = original
            .observation_result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
        else {
            return original.close(First::Observation);
        };
        original.output = original.mutation.take_prepared_output_once_v2();
        let Some(output) = original.output.as_ref() else {
            return original.close(First::Mutation);
        };
        original.finalization_result = Some(sources.sources.finalize_once_v4(
            self.coordinator,
            self.preparations,
            self.namespaces,
            request,
            output,
            proof,
            loan,
            &mut original.finalization,
        ));
        if !matches!(original.finalization_result, Some(Ok(()))) {
            return original.close(First::Finalization);
        }
        Ok(())
    }

    /// Compiles real Prepare63 and its prospective response before native birth.
    ///
    /// The unsigned response bytes are only cost/input DATA. The enclosing SDK
    /// must prepay its actual terminal on the same loan before calling
    /// `execute_prepared_workers_once_v2`, which then performs the full pair
    /// comparison against the updated ledger. Compilation issues no worker.
    ///
    /// # Errors
    /// Retains reentry, wrong purpose/source, profile, quote, original payer,
    /// canonical response construction or native protected-reader refusal.
    pub fn prepare_worker_programme_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        sources: &super::super::prepare_selected::NetworkServicePrepareOriginalV4,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkServiceWorkersOriginalV2,
    ) -> Result<()> {
        if !matches!(
            self.method,
            super::super::callsite::NetworkServiceMethodV4::Prepare
        ) || original.prepared_source.is_some()
        {
            return original.close(First::Order);
        }
        let dispatch = sources
            .sources
            .dispatch_v4()
            .ok_or(NetworkServiceClosedV4)?;
        let verified = sources
            .sources
            .observer_verified_original_v2()
            .ok_or(NetworkServiceClosedV4)?;
        original.compile_once_v2(
            request,
            verified,
            dispatch.kernel_plan(),
            &NetworkParentMutationInputV2::Prepare(dispatch),
            BrokerVerb::NetworkPrepare,
            self.coordinator,
            self.namespace_store,
            self.namespaces,
            loan,
        )?;
        if original
            .response
            .prepare_once_v2(request, *dispatch.kernel_plan().network_handle(), loan)
            .is_err()
        {
            return original.close(First::Response);
        }
        original.prepared_source = Some((
            std::ptr::from_ref(sources).addr(),
            request.request_id(),
            request.signed_request_digest(),
            dispatch.kernel_plan().digest(),
        ));
        Ok(())
    }
}
