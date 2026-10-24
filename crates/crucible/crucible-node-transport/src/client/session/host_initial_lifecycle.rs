//! Uses original initial slots and one nonrenewed cut for selected host calls.

use super::*;
use crate::client::OriginalPacketHostInitialResponse;
use crate::envelope::Method;

impl ClientSession {
    pub(in crate::client) fn original_host_initial_selection_data(
        &self,
    ) -> Result<&crate::reference_packet::control::PacketControlSelection, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.original_response_loss.is_some() {
            return Err(refused());
        }
        self.connection.original_host_initial_selection_data()
    }

    pub(in crate::client) fn original_host_initial_sequence_data(
        &self,
    ) -> Result<U64, ProviderError> {
        self.original_host_initial_selection_data()?;
        self.deadline.remaining()?;
        Ok(self.sequence)
    }

    pub(in crate::client) fn exchange_original_host_initial_into(
        &mut self,
        custody: &mut ClientCustody,
        owner: &mut OriginalPacketHostInitialResponse,
        budget: Duration,
    ) -> Result<(), ProviderError> {
        self.original_host_initial_selection_data()?;
        self.deadline.tighten(budget)?;
        let request = owner.original.as_ref().ok_or_else(refused)?;
        if request.sequence != self.sequence || custody.controller.contains_key(&owner.request_id) {
            return Err(refused());
        }
        let bytes = envelope_bytes(request)?;
        let response_room =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| refused())?;
        custody.ensure_journal_room(bytes.checked_add(response_room).ok_or_else(refused)?)?;
        if custody.controller.len() >= custody.maximum_requests {
            return Err(refused());
        }
        let identity = request.request_hash(RequestOrigin::Controller)?;
        custody.retain_journal_bytes(bytes)?;
        custody.controller.insert(
            owner.request_id.clone(),
            ClientOriginal {
                request: request.clone(),
                identity,
                response: None,
            },
        );
        self.send(request.clone())?;
        self.connection
            .receive_original_host_initial_into(request, &mut owner.received)?;
        let frame = owner.received.as_ref().ok_or_else(refused)?;
        let retained = custody
            .controller
            .get_mut(&owner.request_id)
            .ok_or_else(refused)?;
        retained.response = Some(frame.envelope.clone());
        custody.retain_journal_bytes(envelope_bytes(&frame.envelope)?)?;
        let receipt = match &frame.body {
            ReceivedBody::Response(body) => match &body.result {
                Some(MethodResult::Discover(_)) if owner.method == Method::Discover => None,
                Some(MethodResult::Realize(realized)) if owner.method == Method::Realize => {
                    Some(realized.closed_gate_receipt.clone())
                }
                _ => return Err(refused()),
            },
            _ => return Err(refused()),
        };
        if let Some(receipt) = receipt {
            while custody.content.get(&receipt).is_err() {
                self.connection.receive_original_host_initial_proof_into(
                    request,
                    owner.proof_transfer.as_ref(),
                    owner.proof_objects,
                    &mut owner.proof_received,
                )?;
                let proof = owner.proof_received.as_ref().ok_or_else(refused)?;
                let ReceivedBody::Request(body) = &proof.body else {
                    return Err(refused());
                };
                match body.as_ref() {
                    RequestBody::BlobBegin(begin) => {
                        owner.proof_objects =
                            owner.proof_objects.checked_add(1).ok_or_else(refused)?;
                        owner.proof_transfer =
                            Some((begin.transfer_id.clone(), begin.content.clone(), 0));
                    }
                    RequestBody::BlobChunk(chunk) => {
                        let (_, reference, offset) =
                            owner.proof_transfer.as_mut().ok_or_else(refused)?;
                        *offset = offset
                            .checked_add(chunk.bytes.as_slice().len())
                            .filter(|offset| {
                                u64::try_from(*offset)
                                    .is_ok_and(|offset| offset <= reference.length.get())
                            })
                            .ok_or_else(refused)?;
                    }
                    RequestBody::BlobFinish(_) => owner.proof_transfer = None,
                    _ => return Err(refused()),
                }
                // The original frame remains held while the ordinary content
                // owner validates, caches and acknowledges an independent clone.
                self.receive_transfer(custody, proof.envelope.clone(), body.as_ref().clone())?;
                owner.proof_received = None;
            }
            if owner.proof_transfer.is_some() {
                return Err(refused());
            }
        }
        self.original_host_initial_selection_data()?;
        self.deadline.remaining()?;
        owner.actor.ensure_current()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original host initial transport")
}

impl ClientCustody {
    pub(in crate::client) fn authenticate_original_host_initial_order(
        &self,
        method: Method,
    ) -> Result<(), ProviderError> {
        let previous = match method {
            Method::Discover => 0,
            Method::Realize => 1,
            _ => return Err(refused()),
        };
        if self.controller.len() != previous
            || !self.provider.is_empty()
            || self.controller.values().any(|original| {
                original.request.method != Method::Discover || original.response.is_none()
            })
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl ClientCustody {
    pub(in crate::client) fn prepare_original_host_initial_capacity_data(
        &mut self,
        journal_growth: usize,
    ) -> Result<(), ProviderError> {
        if !self.controller.is_empty() || !self.provider.is_empty() || self.retained_bytes != 0 {
            return Err(refused());
        }
        let maximum = self
            .maximum_bytes
            .checked_add(journal_growth)
            .filter(|value| *value <= 512 * 1024 * 1024)
            .ok_or_else(refused)?;
        // Compute every fallible scalar before changing either quota. No
        // allocating operation or external callback intervenes after this call.
        self.content.prepare_original_host_initial_capacity_data()?;
        self.maximum_bytes = maximum;
        Ok(())
    }
}

impl ClientSession {
    pub(in crate::client) fn begin_original_initial_ack_admit(
        &self,
        budget: Duration,
    ) -> Result<(U64, crate::operational_time::OperationalDeadline), ProviderError> {
        self.original_host_initial_selection_data()?;
        self.sequence.checked_add(U64::new(1))?;
        self.deadline.tighten(budget)?;
        Ok((self.sequence, self.deadline.original_cut()))
    }

    // The exact original, sealed bank and literal slot are separate custody
    // inputs. Output slots belong to the assigned owner and actual Source.
    pub(in crate::client) fn publish_original_initial_ack_admit_into(
        &mut self,
        custody: &mut ClientCustody,
        publication: OriginalAssignedPublicationData<'_>,
        retained: &mut Option<Envelope>,
        completed: &mut Option<ResponseBody>,
    ) -> Result<(), ProviderError> {
        let OriginalAssignedPublicationData {
            original,
            bytes,
            slot,
            cut,
        } = publication;

        if retained.is_some() || completed.is_some() || original.method != Method::Admit {
            return Err(refused());
        }
        self.authenticate_original_ack_admit_cut(original.sequence, cut)?;
        self.connection
            .publish_original_assigned_ack_admit(original, bytes, slot)?;
        self.sequence = self.sequence.checked_add(U64::new(1))?;
        self.connection
            .receive_original_host_initial_admit_into(original, retained, completed)?;
        let envelope = retained.as_ref().ok_or_else(refused)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        custody.controller.get_mut(id).ok_or_else(refused)?.response = Some(envelope.clone());
        custody.retain_journal_bytes(envelope_bytes(envelope)?)?;
        self.original_host_initial_selection_data()?;
        self.deadline.remaining()?;
        Ok(())
    }
}

impl ClientCustody {
    pub(in crate::client) fn authenticate_original_host_initial_admit_order(
        &self,
    ) -> Result<(), ProviderError> {
        if self.controller.len() != 2
            || self.provider.values().any(|value| value.response.is_none())
        {
            return Err(refused());
        }
        let discover = self
            .controller
            .values()
            .filter(|value| value.request.method == Method::Discover && value.response.is_some())
            .count();
        let realized = self
            .controller
            .values()
            .filter(|value| value.request.method == Method::Realize && value.response.is_some())
            .count();
        if discover != 1 || realized != 1 {
            return Err(refused());
        }
        let realize = self
            .controller
            .values()
            .find(|value| value.request.method == Method::Realize)
            .and_then(|value| value.response.as_ref())
            .ok_or_else(refused)?;
        let reference = realize
            .body
            .get("result")
            .and_then(Value::as_object)
            .and_then(|value| value.get("closed_gate_receipt"))
            .ok_or_else(refused)?;
        if !self.content.references().any(|actual| {
            crate::reference_packet::service::native_startup::data_equality::matches(
                reference, actual,
            )
        }) {
            return Err(refused());
        }
        Ok(())
    }
}
