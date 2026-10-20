//! Joins full worker proof comparison to retained State/publication frontiers.

use super::preissue::NetworkPrepareSourcesOriginalV4;
use super::receiving::NetworkReceivingOriginalV4;
use super::*;
use crate::PreparedNetworkObservationV1;
use crate::namespace_catalog::{
    NetworkNamespaceCatalogError, NetworkNamespaceCatalogOutcomeV1, NetworkNamespacePublicationV1,
    NetworkPinObservationOriginalV4,
};
use crate::preparation_runtime::{
    FinalizedNetworkPreparationCommitV1, NetworkPreparationFinalizationInput,
    NetworkPreparationFinalizationReceivingV4, NetworkPreparationRuntimeError,
    finalize_observation_worker_preparation_engine_v4,
};
use crate::state::{CommittedNetworkResultV1, VerifiedNetworkResultV1};
use crate::worker_runtime::PreparedNetworkWorkerOutput;
use aos_sandbox_broker::{BrokerEffectIntentV1, receiving::NetworkServiceReceivingLoanV4};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

pub(super) struct NetworkPreparationFinalizationOriginalV4 {
    pin: NetworkPinObservationOriginalV4,
    publication:
        Option<std::result::Result<NetworkNamespacePublicationV1, crate::NetworkBrokerError>>,
    result: Option<
        std::result::Result<FinalizedNetworkPreparationCommitV1, NetworkPreparationRuntimeError>,
    >,
    entered: bool,
    closed: bool,
}

impl NetworkPreparationFinalizationOriginalV4 {
    pub(super) fn new() -> Self {
        Self {
            pin: NetworkPinObservationOriginalV4::new(),
            publication: None,
            result: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn completed_v4(&self) -> Option<FinalizedNetworkPreparationCommitV1> {
        if self.closed {
            return None;
        }
        self.result.as_ref()?.as_ref().ok().copied()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.pin
            .failure()
            .or_else(|| {
                self.publication
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl NetworkPrepareSourcesOriginalV4 {
    pub(super) fn finalize_once_v4(
        &mut self,
        coordinator: &mut NetworkLifecycleAdmissionCoordinator,
        preparations: &NetworkPreparationCatalogV1,
        namespaces: &mut NetworkNamespaceCatalogV1,
        request: &AuthenticatedBrokerMethodRequestV1,
        output: &PreparedNetworkWorkerOutput,
        proof: PreparedNetworkObservationV1,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        original: &mut NetworkPreparationFinalizationOriginalV4,
    ) -> Result<()> {
        if original.entered {
            original.closed = true;
            return Err(NetworkServiceClosedV4);
        }
        original.entered = true;
        if self.dispatch_v4().is_none() {
            original.closed = true;
            return Err(NetworkServiceClosedV4);
        }
        // The same source's preconstruction debit already includes this
        // retained pin/codec/header plane before the first worker issue.
        // Each actual encoded append still enters its own existing gate.
        let Some(Ok(crate::NetworkPrepareExecutionOutcomeV1::Dispatch(dispatch))) =
            self.dispatch.as_ref()
        else {
            original.closed = true;
            return Err(NetworkServiceClosedV4);
        };
        let Some(Ok(reservation)) = self.reserved.as_ref() else {
            original.closed = true;
            return Err(NetworkServiceClosedV4);
        };
        let verified = self.admission.verified_v4().ok_or(NetworkServiceClosedV4)?;
        let input = NetworkPreparationFinalizationInput::new(
            request.exact_body(),
            reservation.preparation().resolution(),
            dispatch.kernel_plan(),
            output,
        );
        let mut receiving = RetainedPreparationFinalizationV4 {
            receiving: &mut self.receiving,
            loan,
            effect: &verified.effect,
            pin: &mut original.pin,
            publication: &mut original.publication,
        };
        original.result = Some(finalize_observation_worker_preparation_engine_v4(
            coordinator,
            preparations,
            namespaces,
            input,
            proof,
            &mut receiving,
        ));
        if matches!(original.result, Some(Ok(_))) {
            Ok(())
        } else {
            Err(NetworkServiceClosedV4)
        }
    }
}

struct RetainedPreparationFinalizationV4<'held, 'loan> {
    receiving: &'held mut NetworkReceivingOriginalV4,
    loan: &'held mut NetworkServiceReceivingLoanV4<'loan>,
    effect: &'held BrokerEffectIntentV1,
    pin: &'held mut NetworkPinObservationOriginalV4,
    publication: &'held mut Option<
        std::result::Result<NetworkNamespacePublicationV1, crate::NetworkBrokerError>,
    >,
}

impl NetworkPreparationFinalizationReceivingV4 for RetainedPreparationFinalizationV4<'_, '_> {
    fn commit_v4(
        &mut self,
        coordinator: &mut NetworkLifecycleAdmissionCoordinator,
        request_id: [u8; 16],
        effect_digest: aos_sandbox_core::ObjectDigest,
        verified: VerifiedNetworkResultV1,
    ) -> std::result::Result<CommittedNetworkResultV1, NetworkPreparationRuntimeError> {
        let mut receiving = super::receiving::NetworkPrepareEffectReceivingV4 {
            original: &mut *self.receiving,
            loan: &mut *self.loan,
        };
        coordinator
            .commit_verified_preparation_guarded_v4(
                request_id,
                effect_digest,
                verified,
                &mut receiving,
                self.effect,
            )
            .map_err(Into::into)
    }

    fn publish_v4(
        &mut self,
        coordinator: &NetworkLifecycleAdmissionCoordinator,
        preparations: &NetworkPreparationCatalogV1,
        namespaces: &mut NetworkNamespaceCatalogV1,
        result: CommittedNetworkResultV1,
    ) -> std::result::Result<NetworkNamespaceCatalogOutcomeV1, NetworkPreparationRuntimeError> {
        *self.publication = Some(coordinator.namespace_publication(result, preparations));
        let publication = self
            .publication
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(NetworkPreparationRuntimeError::ObservationProof)?;
        namespaces
            .publish_guarded_v4(publication, self.pin, &mut |journal, transaction| {
                self.receiving
                    .before_append_v4(
                        self.loan,
                        coordinator.authority(),
                        self.effect,
                        journal,
                        transaction,
                    )
                    .map_err(|_| NetworkNamespaceCatalogError::Receiving)
            })
            .map_err(Into::into)
    }
}
