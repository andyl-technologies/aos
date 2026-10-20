//! Retains prospective response DATA and lends it only after actual finalization.
//!
//! The canonical protobuf model and byte vector are paid before construction.
//! Their pre-effect form is only a width/terminal input. The SDK observation
//! borrower additionally requires the same actual committed/published result;
//! neither a response body nor a matching header can supply that authority.

use super::*;
use aos_proto::aos::sandbox::local::v1::{NetworkResult, NetworkState};
use buffa::Message as _;

#[derive(Clone, Copy)]
enum ResponsePurpose {
    Preparation,
    Destroy,
}

pub(in crate::service_original) struct PreparationResponseOriginalV2 {
    entered: bool,
    binding: Option<([u8; 16], [u8; 32], [u8; 32])>,
    shapes: [Option<std::result::Result<ResourceVector, AccountingError>>; 2],
    funding: [Option<std::result::Result<(), Closed>>; 2],
    model: Option<NetworkResult>,
    cache: buffa::SizeCache,
    body: Option<Vec<u8>>,
    complete: bool,
    entry: Option<std::result::Result<(), Closed>>,
}

impl PreparationResponseOriginalV2 {
    pub(in crate::service_original) fn new() -> Self {
        Self {
            entered: false,
            binding: None,
            shapes: std::array::from_fn(|_| None),
            funding: std::array::from_fn(|_| None),
            model: None,
            cache: buffa::SizeCache::new(),
            body: None,
            complete: false,
            entry: None,
        }
    }

    pub(super) fn prepare_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        handle: [u8; 32],
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
    ) -> Result<()> {
        self.prepare_purpose_once_v2(request, handle, loan, ResponsePurpose::Preparation)
    }

    pub(in crate::service_original) fn prepare_destroy_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        handle: [u8; 32],
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
    ) -> Result<()> {
        self.prepare_purpose_once_v2(request, handle, loan, ResponsePurpose::Destroy)
    }

    fn prepare_purpose_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        handle: [u8; 32],
        loan: &mut NetworkServiceReceivingLoanV4<'_>,
        purpose: ResponsePurpose,
    ) -> Result<()> {
        if self.entered {
            return Err(NetworkServiceClosedV4);
        }
        self.entered = true;
        let (method, state) = match purpose {
            ResponsePurpose::Preparation => (63, NetworkState::NETWORK_STATE_DEFAULT_DROP),
            ResponsePurpose::Destroy => (9, NetworkState::NETWORK_STATE_ABSENT),
        };
        if request.method() as u32 != method {
            return Err(NetworkServiceClosedV4);
        }
        self.entry = Some(match purpose {
            ResponsePurpose::Preparation => loan.require_network_prepare_current_v4(),
            ResponsePurpose::Destroy => loan.require_network_destroy_current_v4(),
        });
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(NetworkServiceClosedV4);
        }
        self.binding = Some((
            request.request_id(),
            request.signed_request_digest(),
            handle,
        ));
        self.shapes[0] = Some((|| {
            let bytes = std::mem::size_of::<NetworkResult>()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(handle.len()))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(overflow)?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        let Some(Ok(shape)) = self.shapes[0].as_ref() else {
            return Err(NetworkServiceClosedV4);
        };
        self.funding[0] = Some(loan.require_additional_representation_v4(*shape));
        if !matches!(self.funding[0], Some(Ok(()))) {
            return Err(NetworkServiceClosedV4);
        }
        self.model = Some(NetworkResult {
            network_handle: handle.to_vec(),
            state: state.into(),
            ..Default::default()
        });
        let model = self.model.as_ref().ok_or(NetworkServiceClosedV4)?;
        // This exact model has no entered nested messages. The retained cache
        // owns its fixed header; the ordinary canonical protobuf engine sizes
        // and encodes the same model without a second wire implementation.
        let bytes = usize::try_from(model.compute_size(&mut self.cache)).ok();
        self.shapes[1] = Some(
            bytes
                .filter(|bytes| *bytes <= request.maximum_response_bytes() as usize)
                .and_then(|bytes| bytes.checked_mul(2))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .map(|bytes| ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                .ok_or_else(overflow),
        );
        let Some(Ok(shape)) = self.shapes[1].as_ref() else {
            return Err(NetworkServiceClosedV4);
        };
        self.funding[1] = Some(loan.require_additional_representation_v4(*shape));
        if !matches!(self.funding[1], Some(Ok(()))) {
            return Err(NetworkServiceClosedV4);
        }
        self.body = Some(model.encode_to_vec());
        self.complete = self
            .body
            .as_ref()
            .is_some_and(|body| Some(body.len()) == bytes);
        if self.complete {
            Ok(())
        } else {
            Err(NetworkServiceClosedV4)
        }
    }

    pub(in crate::service_original) fn prospective_body_data_v2(&self) -> Option<&[u8]> {
        if !self.complete {
            return None;
        }
        self.body.as_deref()
    }

    pub(in crate::service_original) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(Err(cause)) = self.entry.as_ref() {
            return Some(cause);
        }
        for index in 0..2 {
            if let Some(Err(cause)) = self.shapes[index].as_ref() {
                return Some(cause);
            }
            if let Some(Err(cause)) = self.funding[index].as_ref() {
                return Some(cause);
            }
        }
        None
    }

    pub(in crate::service_original) fn original_failure_selected(&self) -> bool {
        matches!(self.entry, Some(Err(_)))
            || self
                .funding
                .iter()
                .any(|result| matches!(result, Some(Err(_))))
    }

    pub(in crate::service_original) fn matches_binding_v2(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
        handle: [u8; 32],
    ) -> bool {
        self.complete
            && self.binding
                == Some((
                    request.request_id(),
                    request.signed_request_digest(),
                    handle,
                ))
    }
}

impl NetworkServiceWorkersOriginalV2 {
    /// Physically retires only the same wholly successful Prepare63 carriers.
    ///
    /// The SDK caller invokes this only after actual Sent and Session/F posts.
    /// Accepted ledger charges and PID1's old programme debt remain unchanged.
    ///
    /// # Errors
    /// Refuses unfinished/failed same-F posts, another request/source, missing
    /// committed publication or any failed physical P/O/response owner.
    pub fn dispose_completed_preparation_once_v5(
        &mut self,
        loan: &NetworkServiceReceivingLoanV4<'_>,
        request: &AuthenticatedBrokerMethodRequestV1,
        sources: &mut super::super::prepare_selected::NetworkServicePrepareOriginalV4,
    ) -> Result<()> {
        loan.require_completed_network_preparation_interval_v5()
            .map_err(|_| NetworkServiceClosedV4)?;
        let commit = self
            .completed_preparation_v2()
            .ok_or(NetworkServiceClosedV4)?;
        let source = std::ptr::from_ref(&*sources).addr();
        if self
            .prepared_source
            .map(|(address, id, digest, _)| (address, id, digest))
            != Some((
                source,
                request.request_id(),
                request.signed_request_digest(),
            ))
            || sources.failure().is_some()
            || !self
                .response
                .matches_binding_v2(request, commit.result().network_handle())
        {
            return Err(NetworkServiceClosedV4);
        }
        sources
            .sources
            .require_completed_preparation_sources_v5(request)?;
        drop(std::mem::replace(
            sources,
            super::super::prepare_selected::NetworkServicePrepareOriginalV4::new(),
        ));
        drop(std::mem::replace(self, Self::new()));
        Ok(())
    }

    /// Identifies the first refusal retained by the actual same parent payer.
    #[must_use]
    pub fn original_failure_selected_v2(&self) -> bool {
        match self.first {
            Some(First::Funding(index)) => matches!(self.funding[index], Some(Err(_))),
            Some(First::Profile | First::Pair | First::Birth(0)) => {
                self.preparation_birth.parent_failure_is_selected_v2()
            }
            Some(First::Birth(_)) => self.observation_birth.parent_failure_is_selected_v2(),
            Some(First::Mutation) => {
                self.mutation.parent_failure_selected_v2()
                    || self.mutation.birth_failure_selected_v2()
                        && self.preparation_birth.parent_failure_is_selected_v2()
            }
            Some(First::Observation) => {
                self.observation.parent_failure_selected_v2()
                    || self.observation.birth_failure_selected_v2()
                        && self.observation_birth.parent_failure_is_selected_v2()
            }
            Some(First::Store) => self.store.original_failure_selected_v4(),
            Some(First::Cleanup) => matches!(self.cleanup, Some(Err(_))),
            Some(First::Response) => self.response.original_failure_selected(),
            _ => false,
        }
    }

    pub(super) fn selected_mutation_failure_v5(&self) -> Option<&(dyn Error + 'static)> {
        if self.mutation.birth_failure_selected_v2() {
            self.preparation_birth.failure()
        } else {
            self.mutation.failure()
        }
    }

    pub(super) fn selected_observation_failure_v5(&self) -> Option<&(dyn Error + 'static)> {
        if self.observation.birth_failure_selected_v2() {
            self.observation_birth.failure()
        } else {
            self.observation.failure()
        }
    }

    /// Borrows the selected physical or late protected-source Prepare refusal.
    ///
    /// Custody and finalization borrow the actual source's retained receiving
    /// owner. A later independently owed failure cannot replace another stage.
    #[must_use]
    pub fn preparation_failure_v5<'held>(
        &'held self,
        sources: &'held super::super::prepare_selected::NetworkServicePrepareOriginalV4,
    ) -> Option<&'held (dyn Error + 'static)> {
        match self.first {
            Some(First::Mutation) if self.mutation.custody_failure_selected_v2() => {
                sources.sources.failure()
                    .or_else(|| self.preparation_birth.failure())
                    .or_else(|| self.failure())
            }
            Some(First::Finalization) => sources.sources.receiving.failure()
                .or_else(|| self.failure()),
            _ => self.failure(),
        }
    }

    /// Selects the same payer only when its late source gate is primary.
    #[must_use]
    pub fn preparation_original_failure_selected_v5(
        &self,
        sources: &super::super::prepare_selected::NetworkServicePrepareOriginalV4,
    ) -> bool {
        match self.first {
            Some(First::Mutation) if self.mutation.custody_failure_selected_v2() => {
                if sources.sources.failure().is_some() {
                    sources.sources.original_failure_selected_v4()
                } else {
                    self.preparation_birth.parent_failure_is_selected_v2()
                }
            }
            Some(First::Finalization) => {
                sources.sources.receiving.original_failure_selected_v4()
            }
            _ => self.original_failure_selected_v2(),
        }
    }

    /// Borrows unsigned canonical response DATA for before-P SDK terminal pricing.
    ///
    /// This exposes neither a domain observation nor a successful result.
    #[must_use]
    pub fn prospective_preparation_response_data_v2(&self) -> Option<&[u8]> {
        if self.first.is_some() || self.verb != Some(BrokerVerb::NetworkPrepare) {
            return None;
        }
        self.response.prospective_body_data_v2()
    }

    /// Borrows the genuine response only after actual committed/published P/O.
    ///
    /// # Errors
    /// Refuses failed/incomplete physical work, finalization, a changed original
    /// authenticated request, or disagreement with the committed network handle.
    pub fn preparation_response_v2<'held>(
        &'held self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<super::super::callsite::NetworkServiceObservationV4<'held>> {
        let result = self
            .completed_preparation_v2()
            .ok_or(NetworkServiceClosedV4)?
            .result();
        let binding = (
            request.request_id(),
            request.signed_request_digest(),
            result.network_handle(),
        );
        if self.response.binding != Some(binding) || request.method() as u32 != 63 {
            return Err(NetworkServiceClosedV4);
        }
        let body = self
            .response
            .prospective_body_data_v2()
            .ok_or(NetworkServiceClosedV4)?;
        Ok(super::super::callsite::NetworkServiceObservationV4 {
            body,
            request_id: request.request_id(),
            method: 63,
            signed_request_digest: request.signed_request_digest(),
        })
    }
}
