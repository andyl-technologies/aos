//! Dispatches one selected query with response-first, single-report receive.

use super::*;

impl ClientSession {
    pub(in crate::client) fn preflight_original_fresh_query_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.connection.preflight_original_fresh_query_data()
    }

    pub(in crate::client) fn fresh_query_raw_receive_storage_data(
        &self,
    ) -> Result<usize, ProviderError> {
        self.connection
            .original_fresh_query_raw_receive_storage_data()
    }

    pub(in crate::client) fn fresh_report_decode_storage_data(
        &self,
    ) -> Result<usize, ProviderError> {
        self.connection.original_fresh_report_decode_storage_data()
    }

    pub(in crate::client) fn fresh_restore_query_sequence(&self) -> Result<U64, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.original_response_loss.is_some() {
            return Err(refused());
        }
        Ok(self.sequence)
    }

    pub(in crate::client) fn fresh_restore_query_selection(
        &self,
    ) -> Result<&crate::reference_packet::control::PacketControlSelection, ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.original_native5_codec_owner()
            .ok_or_else(refused)?
            .fresh_restore_controller_selection_data(&self.authority)
    }

    pub(in crate::client) fn install_native5_source_fresh_restore_allocation_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: crate::connection::CanonicalAckCodecMetadataExtent,
    ) -> Result<(), ProviderError> {
        if self.sequence.get() != 2 || self.original_response_loss.is_some() {
            return Err(refused());
        }
        self.connection
            .install_native5_controller_fresh_restore_allocation_codec_with_metadata_extent(
                bank,
                selection,
                coordinator,
                profile,
                metadata_extent,
            )
    }

    pub(in crate::client) fn exchange_original_fresh_restore_query(
        &mut self,
        custody: &mut ClientCustody,
        original: &Envelope,
        budget: Duration,
    ) -> Result<Envelope, ProviderError> {
        self.fresh_restore_query_selection()?;
        if original.sequence != self.fresh_restore_query_sequence()? {
            return Err(refused());
        }
        self.connection
            .preflight_original_fresh_query_send(original)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        if custody.controller.contains_key(id) || custody.has_original_fresh_query_data() {
            return Err(refused());
        }
        self.deadline.reset(budget)?;
        let identity = original.request_hash(RequestOrigin::Controller)?;
        let original_bytes = envelope_bytes(original)?;
        custody.ensure_journal_room(
            original_bytes
                .checked_add(
                    usize::try_from(self.authority.limits().frame_bytes.get())
                        .map_err(|_| refused())?,
                )
                .ok_or_else(refused)?,
        )?;
        if custody.controller.len() >= custody.maximum_requests {
            return Err(refused());
        }
        custody.retain_journal_bytes(original_bytes)?;
        custody.controller.insert(
            id.clone(),
            ClientOriginal {
                request: original.clone(),
                identity,
                response: None,
            },
        );
        self.send(original.clone())?;
        let frame = self
            .connection
            .receive_original_fresh_query_response(original)?;
        // The actual reply reaches original custody before any decode/content
        // work or subsequent controller/source currentness check.
        custody.retain_journal_bytes(envelope_bytes(&frame.envelope)?)?;
        custody.controller.get_mut(id).ok_or_else(refused)?.response = Some(frame.envelope.clone());
        Ok(frame.envelope)
    }

    pub(in crate::client) fn receive_original_fresh_restore_report(
        &mut self,
        custody: &mut ClientCustody,
        original: &Envelope,
        reference: &ContentRef,
        budget: Duration,
    ) -> Result<(), ProviderError> {
        self.deadline.tighten(budget)?;
        let mut transfer = None;
        let mut offset = 0usize;
        let length = usize::try_from(reference.length.get()).map_err(|_| refused())?;
        loop {
            let frame = self.connection.receive_original_fresh_report_frame(
                original,
                reference,
                transfer.as_ref(),
                offset,
            )?;
            let ReceivedBody::Request(body) = frame.body else {
                return Err(refused());
            };
            let finished = match body.as_ref() {
                RequestBody::BlobBegin(body) if transfer.is_none() => {
                    transfer = Some(body.transfer_id.clone());
                    false
                }
                RequestBody::BlobChunk(body) if transfer.is_some() => {
                    offset = offset
                        .checked_add(body.bytes.as_slice().len())
                        .filter(|offset| *offset <= length)
                        .ok_or_else(refused)?;
                    false
                }
                RequestBody::BlobFinish(_) if offset == length => true,
                _ => return Err(refused()),
            };
            self.receive_transfer(custody, frame.envelope, *body)?;
            if finished {
                custody.content.get(reference)?;
                return Ok(());
            }
        }
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original fresh query session or report changed")
}

impl ClientCustody {
    pub(in crate::client) fn fresh_query_cache_requested_layout_data(
        &self,
        provider_requests: usize,
    ) -> Result<usize, ProviderError> {
        let entries = self
            .controller
            .len()
            .checked_add(self.provider.len())
            .and_then(|n| n.checked_add(provider_requests))
            .and_then(|n| n.checked_add(1))
            .ok_or_else(refused)?;
        // Count the full prospective tree layouts alongside existing trees so
        // a root split never borrows the current tree's allocation as credit.
        crate::retained_metadata::requested_storage::tree_storage_data(
            2,
            entries,
            std::mem::size_of::<Id>() + std::mem::size_of::<ClientOriginal>(),
            std::mem::align_of::<Id>().max(std::mem::align_of::<ClientOriginal>()),
        )
    }
}

impl ClientCustody {
    pub(in crate::client) fn has_original_fresh_query_data(&self) -> bool {
        self.controller.values().any(|cached| {
            cached.request.extensions.contains_key(crate::reference_packet::service::fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_QUERY)
        })
    }
}

#[cfg(test)]
mod tests {
    //! Checks immutable actual-cache replay data, without a native permission.
    // crucible-lint: panic-shortcut: assertions stop on namespace/replay mismatch.
    use super::*;
    use crate::{
        envelope::{Method, Nullable},
        reference_packet::service::fresh_restore_allocation::*,
    };
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn request() -> Result<Envelope, ProviderError> {
        let (_, authority, _, _) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let Value::Object(body) = serde_json::to_value(ObserveRequest {
            binding_hash: canonical::hash("cnp.owner-binding.v1", b"cache data control")?,
            owner_generation: U64::new(1),
            after_observation_sequence: U64::new(0),
            maximum_items: U64::new(1),
            extensions: Extensions::new(),
        })
        .map_err(crucible_node_format::ContractError::from)?
        else {
            return Err(refused());
        };
        Ok(Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(authority.session_id().clone())),
            incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            operation_id: Nullable(None),
            request_id: Nullable(Some(Id::new("query-cache-data")?)),
            sequence: U64::new(2),
            method: Method::Observe,
            body,
            extensions: Extensions::new(),
        })
    }

    #[test]
    fn actual_query_cache_is_permanent_in_controller_namespace_even_without_response() -> TestResult
    {
        let mut custody = ClientCustody::new(8, ClientContent::new(65536, 8, 4096)?)?;
        let mut original = request()?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?.clone();
        custody.controller.insert(
            id.clone(),
            ClientOriginal {
                identity: original.request_hash(RequestOrigin::Controller)?,
                request: original.clone(),
                response: None,
            },
        );
        assert!(!custody.has_original_fresh_query_data());
        original.extensions.insert(
            PACKET_FRESH_RESTORE_ALLOCATION_QUERY.into(),
            serde_json::to_value(PacketNativeFreshRestoreAllocationQuery {
                schema: PACKET_FRESH_RESTORE_ALLOCATION_QUERY.into(),
                nonce: crucible_node_format::Bytes::new(vec![1; 32]),
                completed_admit_request: crucible_node_format::Bytes::new(vec![2; 32]),
                completed_admit_response: crucible_node_format::Bytes::new(vec![3; 32]),
            })?,
        );
        custody.provider.insert(
            id.clone(),
            ClientOriginal {
                identity: original.request_hash(RequestOrigin::Provider)?,
                request: original.clone(),
                response: None,
            },
        );
        assert!(!custody.has_original_fresh_query_data());
        custody.controller.insert(
            id.clone(),
            ClientOriginal {
                identity: original.request_hash(RequestOrigin::Controller)?,
                request: original.clone(),
                response: None,
            },
        );
        assert!(custody.has_original_fresh_query_data());
        custody
            .controller
            .get_mut(&id)
            .ok_or_else(refused)?
            .response = Some(original);
        assert!(custody.has_original_fresh_query_data());
        Ok(())
    }
}
