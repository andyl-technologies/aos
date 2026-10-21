//! Composes the actual protected P/O programme before either physical birth.
//!
//! Only the retained signed source owners enter this private compiler. Real
//! protected profiles and the existing signed-verification supplier determine
//! both child invoices. The same original Source ledger checks the complete
//! pair, then pays each transport and child immediately before its own birth.

use super::*;
use crate::namespace_store::{
    NetworkNamespaceStoreMutationOriginalV4, NetworkNamespaceStoreName,
    NetworkNamespaceStoreOutcome,
};
use crate::observation_worker_runtime::{
    NetworkParentObservationInputV2, NetworkParentObservationOriginalV2,
};
use crate::worker_runtime::{NetworkParentMutationInputV2, NetworkParentMutationOriginalV2};
use aos_sandbox_broker::receiving::{
    NetworkServiceReceivingLoanV4, NetworkWorkerBirthOriginalV2,
    NetworkWorkerBirthPurposeV2 as Purpose, NetworkWorkerCleanupClockScopeV4,
};
use aos_sandbox_broker::{AuthorizationRecordError, VerifiedBrokerAdmission};
use aos_sandbox_model::{BrokerVerb, ObjectDigest};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use sha2::{Digest as _, Sha256};

mod driver;
pub(super) mod response;

#[derive(Clone, Copy)]
enum First {
    Order,
    Request,
    Header,
    Funding(usize),
    Profile,
    Width,
    Payload(usize),
    Crypto,
    Quote,
    Journal,
    Publication,
    Pair,
    Cleanup,
    Birth(usize),
    Mutation,
    Observation,
    Store,
    Finalization,
    Response,
}

#[derive(Debug, thiserror::Error)]
enum QuoteError {
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error("the actual protected worker programme or profile is unavailable")]
    Closed,
}

#[derive(Clone, Copy)]
struct PairQuote {
    children: [ResourceVector; 2],
    probes: [u64; 2],
    transports: [ResourceVector; 2],
}

/// Retains the actual signed service's entire physical P/O interval.
///
/// Construction performs no IO and grants no authority. Failed reservations,
/// native transport, original-D results and independent cleanup remain owned
/// here until the enclosing actual request and Source posts are complete.
#[must_use]
pub struct NetworkServiceWorkersOriginalV2 {
    entered: bool,
    verb: Option<BrokerVerb>,
    first: Option<First>,
    header: Option<std::result::Result<ResourceVector, AccountingError>>,
    payload_shape: Option<std::result::Result<ResourceVector, AccountingError>>,
    funding: [Option<std::result::Result<(), Closed>>; 4],
    request: Option<std::result::Result<(), QuoteError>>,
    profile: Option<std::result::Result<(), Closed>>,
    widths: Option<std::result::Result<[usize; 3], AuthorizationRecordError>>,
    payloads: [Option<std::result::Result<Vec<u8>, AuthorizationRecordError>>; 3],
    crypto: Option<std::result::Result<ResourceVector, AccountingError>>,
    quote: Option<std::result::Result<PairQuote, QuoteError>>,
    journal: Option<
        std::result::Result<
            ResourceVector,
            crate::journal::JournalAppendReceivingDemandErrorV1,
        >,
    >,
    publication: Option<
        std::result::Result<
            ResourceVector,
            crate::journal::JournalAppendReceivingDemandErrorV1,
        >,
    >,
    parent_future: Option<std::result::Result<ResourceVector, AccountingError>>,
    pair: Option<std::result::Result<(), Closed>>,
    cleanup: Option<std::result::Result<NetworkWorkerCleanupClockScopeV4, Closed>>,
    preparation_birth: NetworkWorkerBirthOriginalV2,
    observation_birth: NetworkWorkerBirthOriginalV2,
    births: [Option<std::result::Result<(), Closed>>; 2],
    mutation: NetworkParentMutationOriginalV2,
    mutation_result:
        Option<std::result::Result<(), crate::worker_runtime::NetworkWorkerRuntimeError>>,
    observation: NetworkParentObservationOriginalV2,
    observation_result: Option<
        std::result::Result<
            crate::PreparedNetworkObservationV1,
            crate::observation_worker_runtime::NetworkObservationWorkerError,
        >,
    >,
    store: NetworkNamespaceStoreMutationOriginalV4,
    store_name: Option<
        std::result::Result<
            NetworkNamespaceStoreName,
            crate::namespace_store::NetworkNamespaceStoreError,
        >,
    >,
    store_result: Option<
        std::result::Result<
            NetworkNamespaceStoreOutcome,
            crate::namespace_store::NetworkNamespaceStoreRefusalV4,
        >,
    >,
    finalization: super::finalization::NetworkPreparationFinalizationOriginalV4,
    finalization_result: Option<Result<()>>,
    output: Option<crate::worker_runtime::PreparedNetworkWorkerOutput>,
    boot: Option<
        std::result::Result<aos_linux_descriptors::boot::KernelBootId, aos_linux_descriptors::Error>,
    >,
    response: response::PreparationResponseOriginalV2,
    prepared_source: Option<(usize, [u8; 16], [u8; 32], ObjectDigest)>,
}

impl NetworkServiceWorkersOriginalV2 {
    /// Creates only empty retained destinations, without opening a source.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entered: false,
            verb: None,
            first: None,
            header: None,
            payload_shape: None,
            funding: std::array::from_fn(|_| None),
            request: None,
            profile: None,
            widths: None,
            payloads: std::array::from_fn(|_| None),
            crypto: None,
            quote: None,
            journal: None,
            publication: None,
            parent_future: None,
            pair: None,
            cleanup: None,
            preparation_birth: NetworkWorkerBirthOriginalV2::new(),
            observation_birth: NetworkWorkerBirthOriginalV2::new(),
            births: std::array::from_fn(|_| None),
            mutation: NetworkParentMutationOriginalV2::new(),
            mutation_result: None,
            observation: NetworkParentObservationOriginalV2::new(),
            observation_result: None,
            store: NetworkNamespaceStoreMutationOriginalV4::new(),
            store_name: None,
            store_result: None,
            finalization: super::finalization::NetworkPreparationFinalizationOriginalV4::new(),
            finalization_result: None,
            output: None,
            boot: None,
            response: response::PreparationResponseOriginalV2::new(),
            prepared_source: None,
        }
    }

    /// Borrows the first actual arithmetic, signed, native or domain refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        fn failed<T, E: Error + 'static>(
            slot: &Option<std::result::Result<T, E>>,
        ) -> Option<&(dyn Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        let cause = match self.first? {
            First::Request => failed(&self.request),
            First::Header => failed(&self.header).or_else(|| failed(&self.payload_shape)),
            First::Profile => self.preparation_birth.failure(),
            First::Width => failed(&self.widths),
            First::Payload(index) => failed(&self.payloads[index]),
            First::Crypto => failed(&self.crypto),
            First::Quote => failed(&self.quote),
            First::Journal => failed(&self.journal),
            First::Publication => failed(&self.publication),
            First::Pair => self
                .preparation_birth
                .failure()
                .or_else(|| failed(&self.parent_future)),
            First::Cleanup => failed(&self.cleanup),
            First::Birth(0) => self.preparation_birth.failure(),
            First::Birth(_) => self.observation_birth.failure(),
            First::Mutation => self
                .selected_mutation_failure_v5()
                .or_else(|| failed(&self.mutation_result)),
            First::Observation => self
                .selected_observation_failure_v5()
                .or_else(|| failed(&self.observation_result)),
            First::Finalization => self.finalization.failure(),
            First::Response => self.response.failure(),
            First::Store => failed(&self.store_name).or_else(|| failed(&self.store_result)),
            First::Funding(index) => failed(&self.funding[index]),
            First::Order => None,
        };
        cause.or(Some(&NetworkServiceClosedV4))
    }

    /// Borrows the rich original FDStore failure without erasing its SDK guard.
    #[must_use]
    pub fn store_failure_view_v2(&self) -> Option<NetworkNamespaceStoreFailureV4<'_>> {
        self.store.failure_view_v4()
    }

    /// Borrows actual completed P/O absence; pin/store disposal is still owed.
    #[must_use]
    pub fn completed_destroy_observation_v2(&self) -> Option<crate::PreparedNetworkObservationV1> {
        if self.first.is_some() || self.verb != Some(BrokerVerb::NetworkDestroy) {
            return None;
        }
        let quote = self.quote.as_ref()?.as_ref().ok()?;
        if quote.probes.into_iter().any(|count| count == 0) {
            return None;
        }
        self.observation_result.as_ref()?.as_ref().ok().copied()
    }

    /// Borrows the actual committed and published Prepare63 result.
    #[must_use]
    pub fn completed_preparation_v2(
        &self,
    ) -> Option<crate::preparation_runtime::FinalizedNetworkPreparationCommitV1> {
        if self.first.is_some()
            || self.verb != Some(BrokerVerb::NetworkPrepare)
            || !matches!(self.finalization_result, Some(Ok(())))
        {
            return None;
        }
        self.finalization.completed_v4()
    }

    fn compile_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        verified: &VerifiedBrokerAdmission,
        plan: &crate::NetworkKernelPlanV1,
        input: &NetworkParentMutationInputV2<'_>,
        verb: BrokerVerb,
        coordinator: &NetworkLifecycleAdmissionCoordinator,
        store: &SystemdNetworkNamespaceStore,
        namespaces: &NetworkNamespaceCatalogV1,
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
    ) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(NetworkServiceClosedV4);
        }
        self.entered = true;
        self.verb = Some(verb);
        self.request = Some(
            if verified.effect.request_id() == &request.request_id()
                && verified.effect.transport_request_digest().as_bytes()
                    == &<[u8; 32]>::from(Sha256::digest(request.exact_body()))
                && verified.effect.verb() == verb
            {
                Ok(())
            } else {
                Err(QuoteError::Closed)
            },
        );
        if !matches!(self.request, Some(Ok(()))) {
            return self.close(First::Request);
        }
        self.header = Some((|| {
            let bytes = std::mem::size_of::<Self>()
                .checked_mul(2)
                .ok_or_else(overflow)?;
            Ok(ResourceVector::ZERO.with(
                D::MemoryBytes,
                u64::try_from(bytes).map_err(|_| overflow())?,
            ))
        })());
        let Some(Ok(header)) = self.header.as_ref() else {
            return self.close(First::Header);
        };
        self.funding[0] = Some(loan.require_additional_representation_v4(*header));
        if !matches!(self.funding[0], Some(Ok(()))) {
            return self.close(First::Funding(0));
        }
        self.profile = Some(loan.read_network_worker_profile_once_v2(&mut self.preparation_birth));
        if !matches!(self.profile, Some(Ok(()))) {
            return self.close(First::Profile);
        }
        self.widths = Some((|| {
            let fence = verified.fence.network_handoff_length_data_v2()?;
            Ok([
                fence,
                fence,
                verified.effect.network_handoff_length_data_v2()?,
            ])
        })());
        let Some(Ok(widths)) = self.widths.as_ref() else {
            return self.close(First::Width);
        };
        // Both exact fence copies, effect and their temporary lease codec
        // buffers coexist. This debit precedes the first payload allocation.
        let payload_bytes = widths
            .iter()
            .try_fold(0usize, |sum, width| sum.checked_add(*width))
            .and_then(|bytes| bytes.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<Vec<u8>>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(overflow);
        let payload_demand =
            payload_bytes.map(|bytes| ResourceVector::ZERO.with(D::MemoryBytes, bytes));
        // Retain supplier failure in the same typed quote slot before refusal.
        self.payload_shape = Some(payload_demand);
        let Some(Ok(payload_demand)) = self.payload_shape.as_ref() else {
            return self.close(First::Header);
        };
        self.funding[1] = Some(loan.require_additional_representation_v4(*payload_demand));
        if !matches!(self.funding[1], Some(Ok(()))) {
            return self.close(First::Funding(1));
        }
        for index in 0..3 {
            self.payloads[index] = Some(if index == 2 {
                verified.effect.network_handoff_payload_data_v2()
            } else {
                verified.fence.network_handoff_payload_data_v2()
            });
            if !matches!(self.payloads[index], Some(Ok(_))) {
                return self.close(First::Payload(index));
            }
        }
        let artifacts = request.authorization().ok_or(NetworkServiceClosedV4)?;
        self.crypto = Some(coordinator.signed_preparation_receiving_demand_v4(artifacts));
        if !matches!(self.crypto, Some(Ok(_))) {
            return self.close(First::Crypto);
        }
        self.quote = Some((|| {
            let p = self
                .preparation_birth
                .selected_native_limits_data_v2(Purpose::Preparation)
                .ok_or(QuoteError::Closed)?;
            let o = self
                .preparation_birth
                .selected_native_limits_data_v2(Purpose::Observation)
                .ok_or(QuoteError::Closed)?;
            if self
                .preparation_birth
                .selected_argument_count_data_v2(Purpose::Preparation)
                != Some(8)
                || self
                    .preparation_birth
                    .selected_argument_count_data_v2(Purpose::Observation)
                    != Some(6)
            {
                return Err(QuoteError::Closed);
            }
            let width = input.encoded_length_data_v2().ok_or(QuoteError::Closed)?;
            let crypto = *self
                .crypto
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(QuoteError::Closed)?;
            let pquote =
                crate::worker_runtime::child_programme_v2::preparation_whole_programme_data_v2(
                    plan,
                    verb,
                    width,
                    request.exact_body().len(),
                    p,
                    crypto,
                )
                .ok_or(QuoteError::Closed)?;
            let sections = sections_v2(&self.payloads, request).ok_or(QuoteError::Closed)?;
            let lengths = std::array::from_fn(|index| {
                if index == 8 {
                    184 + plan.as_bytes().len()
                } else {
                    sections[index].len()
                }
            });
            let oquote = crate::observation_worker_runtime::child_programme_v2::observer_whole_programme_data_v2(
                plan, verb, lengths, o, crypto).ok_or(QuoteError::Closed)?;
            let children = [
                pquote.receiving_obligations_data_v2(),
                oquote.receiving_obligations_data_v2(),
            ];
            for (child, limits) in children.into_iter().zip([p, o]) {
                for (dimension, limit) in [(D::MemoryBytes, limits[0]), (D::Pids, limits[2])] {
                    if child.get(dimension) > limit {
                        return Err(AccountingError::LimitExceeded {
                            dimension,
                            limit,
                            attempted: child.get(dimension),
                        }
                        .into());
                    }
                }
            }
            let name = if verb == BrokerVerb::NetworkPrepare {
                ResourceVector::ZERO.with(
                    D::MemoryBytes,
                    u64::try_from(NetworkNamespaceStoreName::maximum_bytes_v4())
                        .map_err(|_| overflow())?,
                )
            } else {
                ResourceVector::ZERO
            };
            Ok(PairQuote {
                children,
                probes: [
                    pquote.source_queries_data_v2(),
                    oquote.source_queries_data_v2(),
                ],
                transports: [
                    NetworkParentMutationOriginalV2::receiving_demand_v2(input)?
                        .checked_add(name)?,
                    NetworkParentObservationOriginalV2::receiving_demand_v2(plan, sections)?,
                ],
            })
        })());
        if !matches!(self.quote, Some(Ok(_))) {
            return self.close(First::Quote);
        }
        self.journal = Some(if verb == BrokerVerb::NetworkPrepare {
            coordinator.preparation_suffix_receiving_demand_v2()
        } else {
            coordinator.destroy_suffix_receiving_demand_v2()
        });
        if !matches!(self.journal, Some(Ok(_))) {
            return self.close(First::Journal);
        }
        // Retirement writes the same canonical head+namespace row encoder.
        self.publication = Some(namespaces.publication_append_receiving_demand_v2());
        if !matches!(self.publication, Some(Ok(_))) {
            return self.close(First::Publication);
        }
        self.parent_future = Some((|| {
            let quote = self
                .quote
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or_else(overflow)?;
            let journal = *self
                .journal
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or_else(overflow)?;
            let publication = *self
                .publication
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or_else(overflow)?;
            let store = store.mutation_receiving_demand_data_v2().ok_or_else(overflow)?;
            quote.transports[0]
                .checked_add(quote.transports[1])?
                .checked_add(journal)?
                .checked_add(publication)?
                .checked_add(store)
        })());
        if !matches!(self.parent_future, Some(Ok(_))) {
            return self.close(First::Pair);
        }
        Ok(())
    }

    fn preflight_once_v2(&mut self, loan: &mut NetworkServiceReceivingLoanV4<'_>) -> Result<()> {
        if self.first.is_some() || self.pair.is_some() {
            return self.close(First::Order);
        }
        let Some(Ok(parent_future)) = self.parent_future.as_ref() else {
            return self.close(First::Pair);
        };
        let Some(Ok(quote)) = self.quote.as_ref() else {
            return self.close(First::Quote);
        };
        self.pair = Some(loan.preflight_network_worker_pair_once_v2(
            &mut self.preparation_birth,
            quote.children,
            *parent_future,
        ));
        if !matches!(self.pair, Some(Ok(()))) {
            return self.close(First::Pair);
        }
        self.cleanup = Some(loan.prearm_network_worker_cleanup_once_v4());
        if !matches!(self.cleanup, Some(Ok(_))) {
            return self.close(First::Cleanup);
        }
        Ok(())
    }

    fn close<T>(&mut self, first: First) -> Result<T> {
        self.first.get_or_insert(first);
        Err(NetworkServiceClosedV4)
    }
}

impl Default for NetworkServiceWorkersOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

fn overflow() -> AccountingError {
    AccountingError::ArithmeticOverflow {
        dimension: D::MemoryBytes,
    }
}

fn sections_v2<'held>(
    payloads: &'held [Option<std::result::Result<Vec<u8>, AuthorizationRecordError>>; 3],
    request: &'held AuthenticatedBrokerMethodRequestV1,
) -> Option<[&'held [u8]; 8]> {
    let artifacts = request.authorization()?;
    Some([
        request.exact_body(),
        artifacts.broker_plan(),
        artifacts.broker_plan_signature(),
        artifacts.ownership_lease(),
        artifacts.ownership_lease_signature(),
        payloads[0].as_ref()?.as_ref().ok()?.as_slice(),
        payloads[1].as_ref()?.as_ref().ok()?.as_slice(),
        payloads[2].as_ref()?.as_ref().ok()?.as_slice(),
    ])
}
