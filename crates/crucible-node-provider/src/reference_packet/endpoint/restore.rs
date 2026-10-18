//! Drives selected authenticated restore preparation and exact input ACKs.
//!
//! A preparation receipt certifies owning input reservation only. It cannot
//! install a model or publish a restored-world gate; commit has its own issuer.

use super::*;
use crate::client::{DeadlineStream, ExchangeDeadline};
use crate::reference_packet::service::{
    OriginalNativeServiceCaptureContext,
    ack_emitter::NativeAckBoot,
    complete_restore::{PacketNative5CompleteRestoreSelection, transfer::*},
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use crucible_node_contract::U64;

pub(crate) struct PacketEndpointRestoreAllocation {
    creator: u32,
    thread: std::thread::ThreadId,
    policy: Rc<super::super::Native5Policy>,
    facts: RetainedProtocolMetadataFacts,
    startup_banks: Option<[crate::protocol_snapshot::ProtocolSnapshotAllocationFacts; 2]>,
}

impl PacketEndpointRestoreAllocation {
    pub(crate) fn authenticate_original(
        &self,
        policy: &Rc<super::super::Native5Policy>,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || !Rc::ptr_eq(&self.policy, policy)
        {
            return Err(refused());
        }
        Ok(())
    }
    pub(crate) fn facts(&self) -> RetainedProtocolMetadataFacts {
        self.facts
    }
    pub(crate) fn startup_reserved_bytes_data(&self) -> Result<usize, ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        let banks = self.startup_banks.as_ref().ok_or_else(refused)?;
        banks[0]
            .allocated_bytes
            .checked_add(banks[1].allocated_bytes)
            .ok_or_else(refused)
    }

    pub(crate) fn owner_header_bytes(&self) -> usize {
        std::mem::size_of::<PacketEndpoint<DeadlineStream>>()
    }
}

impl PacketEndpoint<DeadlineStream> {
    fn quote_original_restore_endpoint(
        &self,
        policy: &Rc<super::super::Native5Policy>,
    ) -> Result<PacketEndpointRestoreAllocation, ProviderError> {
        self.ensure_complete_origin()?;
        if !self.held
            || self.capture.is_some()
            || self.pending_capture.is_some()
            || self.after_confirmation.is_some()
        {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        // Pins share the receiver's ledger, but neither owner carries a process
        // origin. Authenticate the actual native actor before borrowing either.
        connection.original_native_owned11_admission()?;
        let mut observer = MetadataObserver::new();
        observer.vector::<ExchangeRecord>(self.records.capacity())?;
        for record in &self.records {
            record.observe_owned11_metadata(&mut observer)?;
        }
        observer.vector::<OperationContentPin>(self.pins.capacity())?;
        for pin in &self.pins {
            pin.observe_original_owned11_metadata(&self.uploads, &mut observer)?;
        }
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
            policy.as_ref(),
        )?;
        policy.observe_owned11_metadata(&mut observer)?;
        Ok(PacketEndpointRestoreAllocation {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            policy: Rc::clone(policy),
            facts: observer.finish(),
            startup_banks: None,
        })
    }

    fn quote_original_startup_restore_endpoint(
        &self,
        policy: &Rc<super::super::Native5Policy>,
    ) -> Result<PacketEndpointRestoreAllocation, ProviderError> {
        let facts = self.original_fresh_endpoint_retained_facts_data(policy)?;
        let banks = self
            .complete
            .as_ref()
            .ok_or_else(refused)?
            .original_fresh_report_bank_data()?;
        Ok(PacketEndpointRestoreAllocation {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            policy: Rc::clone(policy),
            facts,
            startup_banks: Some(banks),
        })
    }

    pub(super) fn restore_original_transfer(
        &mut self,
        request: &Envelope,
        body: &RequestBody,
        service: &OriginalNativeServiceCaptureContext<'_>,
        deadline: &ExchangeDeadline,
    ) -> Result<bool, ProviderError> {
        self.ensure_complete_origin()?;
        deadline.remaining()?;
        let prepare =
            matches!(body, RequestBody::Begin(begin) if begin.kind == BeginKind::PrepareRestore);
        // Discover/Realize and the once-only protocol Admit establish the very
        // token this route later requires. Ordinary initial traffic must reach
        // its existing handler before any selected restore-token lookup.
        if !prepare && !self.restore_protocol_attempted {
            return Ok(false);
        }
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let installed = connection.original_native_owned11_admission()?;
        installed.authenticate_current(connection)?;
        if installed.policy.complete_restore_selection()
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Ok(false);
        }
        if prepare {
            match connection.original_selected_restore_transfer_projection_data(request)? {
                CompleteRestoreTransferProjection::Request {
                    phase: PacketCompleteRestoreTransferPhase::Prepare,
                    ..
                } => {}
                CompleteRestoreTransferProjection::Request {
                    phase: PacketCompleteRestoreTransferPhase::Commit,
                    ..
                } => return self.restore_original_commit(request, deadline),
                _ => return Err(refused()),
            }
            if self.restore_protocol_attempted {
                return Err(refused());
            }
            self.restore_protocol_attempted = true;
            let policy = Rc::clone(&installed.policy);
            let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
            if let Some(original_owner) = self.fresh_restore_attempt.as_ref() {
                let original_loan = original_owner.try_borrow().map_err(|_| refused())?;
                let frame = original_loan.prepare_input.as_ref().ok_or_else(refused)?;
                if frame.envelope != *request {
                    return Err(refused());
                }
                original_loan.prepare.authenticate_active(connection)?;
                let record_index = self.records.len().checked_sub(1).ok_or_else(refused)?;
                let header = original_loan.borrow_completed_prepare_header(
                    connection,
                    &self.records[record_index],
                    record_index,
                )?;
                header.authenticate_header(connection, request)?;
                let endpoint_quote = self.quote_original_startup_restore_endpoint(&policy)?;
                let mut control_quote = Some(
                    self.native
                        .quote_original_startup_fresh_restore_control(&policy, endpoint_quote)?,
                );
                let roots = service.with_original_endpoint_roots(boot, &self.policy);
                // The mutable authority/containment walk precedes every service
                // registrar loan. The input frame remains in the endpoint Rc.
                let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
                    return Err(refused());
                };
                let mut service_quote =
                    Some(roots.quote_original_startup_restore_service_allocation(
                        connection,
                        &self.uploads,
                        &original_loan.prepare,
                    )?);
                let complete = self.complete.as_ref().ok_or_else(refused)?;
                NativeAckBoot::verify_complete_restore_prepare_with_startup_into(
                    boot,
                    &complete.hello,
                    request,
                    connection,
                    Some(&original_loan.prepare),
                    &mut self.restore_prepare_admission,
                    &mut service_quote,
                    &mut control_quote,
                )?;
            } else {
                // Ordinary boot5 keeps the original verifier and intrinsic
                // startupSome refusal, without constructing a replacement scope.
                NativeAckBoot::authenticate_legacy_prepare_startup_data(boot)?;
                let roots = service.with_original_endpoint_roots(boot, &self.policy);
                let mut service_quote = Some(
                    roots.quote_original_restore_service_allocation(connection, &self.uploads)?,
                );
                let endpoint_quote = self.quote_original_restore_endpoint(&policy)?;
                let mut control_quote = Some(
                    self.native
                        .quote_original_fresh_restore_control(&policy, endpoint_quote)?,
                );
                let complete = self.complete.as_ref().ok_or_else(refused)?;
                NativeAckBoot::verify_complete_restore_prepare_into(
                    boot,
                    &complete.hello,
                    request,
                    connection,
                    &mut self.restore_prepare_admission,
                    &mut service_quote,
                    &mut control_quote,
                )?;
            }
            let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
                return Err(refused());
            };
            let token = self
                .restore_prepare_admission
                .as_ref()
                .ok_or_else(refused)?;
            let prepared = token.request(connection)?;
            connection.preflight_original_complete_restore_input_suffix(
                &prepared,
                EXCHANGES
                    .checked_sub(self.records.len())
                    .ok_or_else(refused)?,
                self.transport_credit,
            )?;
            let quote = connection.quote_original_complete_restore_input_custody(&prepared)?;
            let result = token.original_prepare_result_data(connection, &self.native)?;
            drop(prepared);
            let reply = prefix::completed(result)?;
            let response = decode_response(body, &reply)?;
            let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
                return Err(refused());
            };
            connection.install_original_complete_restore_input_custody(
                &mut self.restore_prepare_admission,
                quote,
            )?;
            connection.acknowledge_original_complete_restore_input_custody()?;
            let mut assigned = connection.prepare_original_complete_restore_response(
                request,
                &response,
                PacketCompleteRestoreTransferPhase::Prepare,
            )?;
            let next = {
                let original = assigned.original()?;
                if original.sequence.get() != self.next_sequence {
                    return Err(refused());
                }
                original.sequence.get().checked_add(1).ok_or_else(refused)?
            };
            assigned.seal_original_prepare_receipt()?;
            assigned.publish()?;
            drop(assigned);
            deadline.remaining()?;
            if self.fresh_restore_attempt.is_some() {
                connection.authenticate_original_fresh_prepare_handoff_data(request)?;
                // The real verified issuer owns the full signed original and
                // input lease. Query/report proof originals remain in records
                // and literal banks. No callback or fallible operation follows
                // this successful handoff before eligibility is restored.
                self.fresh_restore_attempt = None;
            }
            self.next_sequence = next;
            self.held = false;
            return Ok(true);
        }
        if !self.restore_protocol_attempted {
            return Ok(false);
        }
        let Some(progress) = connection.receive_original_complete_restore_input(request, body)?
        else {
            return Err(refused());
        };
        let result = match (body, progress) {
            (
                RequestBody::BlobBegin(begin),
                OriginalCompleteRestoreInputProgress::Begin {
                    next_offset,
                    maximum_chunk_bytes,
                },
            ) => prefix::completed(BlobBeginResult {
                transfer_id: begin.transfer_id.clone(),
                next_offset: U64::new(u64::try_from(next_offset).map_err(|_| refused())?),
                maximum_chunk_bytes: U64::new(
                    u64::try_from(maximum_chunk_bytes).map_err(|_| refused())?,
                ),
            })?,
            (
                RequestBody::BlobChunk(chunk),
                OriginalCompleteRestoreInputProgress::Chunk { next_offset },
            ) => prefix::completed(BlobChunkResult {
                transfer_id: chunk.transfer_id.clone(),
                next_offset: U64::new(u64::try_from(next_offset).map_err(|_| refused())?),
            })?,
            (
                RequestBody::BlobFinish(finish),
                OriginalCompleteRestoreInputProgress::Finish { input },
            ) => prefix::completed(BlobFinishResult {
                transfer_id: finish.transfer_id.clone(),
                content: connection
                    .original_complete_restore_input_reference(input)?
                    .clone(),
            })?,
            _ => return Err(refused()),
        };
        self.prepare(
            request,
            &super::super::control::PacketControlReply {
                body: result,
                evidence: Vec::new(),
            },
        )?;
        let Some(Transport::Prepared(exchange, acknowledgements)) = self.transport.as_mut() else {
            return Err(refused());
        };
        exchange
            .publish(&mut |original, received| acknowledgements.validate(original, received))?;
        let Some(Transport::Prepared(exchange, _)) = self.transport.take() else {
            return Err(refused());
        };
        let (connection, record) = exchange.into_parts();
        self.records.push(record);
        self.transport = Some(Transport::Connected(connection));
        deadline.remaining()?;
        self.held = false;
        Ok(true)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native selected restore preparation held")
}

mod settled_quote17;
