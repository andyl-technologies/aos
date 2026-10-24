//! Encodes selected Observe records from the same stopped native inventory.
//!
//! Only the selected original Observe route consumes this producer. It avoids
//! temporary inventory/projection/definition clones while preserving raw2/4
//! canonical bytes. Generic Observe and all semantic grant paths remain on their
//! existing producers. Quoted layouts grant no Source or Capture authority.

use super::*;
use crate::reference_packet::serialization_storage::{
    NativeSerializationStorageData, actual_serialization_storage_data,
};
use crate::retained_metadata::MetadataObserver;

#[derive(Serialize)]
struct OriginalStoppedProducerInventory<'a> {
    reached: Position,
    gate_closed: bool,
    pending: &'a [super::super::PacketEvent],
    retained_outputs: &'a [super::super::PacketPublication],
    private_mutations: U64,
    packet_effects: U64,
}

impl super::super::PacketProgram {
    fn borrowed_original_stopped_inventory(
        &self,
    ) -> Result<OriginalStoppedProducerInventory<'_>, ProviderError> {
        if self.failed || self.next_event > self.events.len() {
            return Err(ProviderError::Correlation(
                "native stopped producer inventory",
            ));
        }
        Ok(OriginalStoppedProducerInventory {
            reached: self.reached,
            gate_closed: self.gate_closed,
            pending: &self.events[self.next_event..],
            retained_outputs: &self.outputs,
            private_mutations: U64::new(self.private_mutations),
            packet_effects: U64::new(self.packet_effects),
        })
    }
}

#[derive(Serialize)]
struct OriginalStoppedObserveRecord<'a, T: Serialize> {
    schema: &'static str,
    native_pid: U64,
    original: &'a Envelope,
    inventory: T,
    grant: Option<()>,
}

pub(crate) struct NativeStoppedObserveRecordStorageData<'a> {
    original: &'a Envelope,
    pub(crate) encoding: NativeSerializationStorageData,
}

impl<'a> NativeStoppedObserveRecordStorageData<'a> {
    /// Moves the already quoted layout without retaining its temporary borrow.
    pub(crate) fn into_encoding_data(self) -> NativeSerializationStorageData {
        self.encoding
    }

    /// Reborrows a moved original under its saved layout data.
    ///
    /// The actual stopped encoder independently recounts the same model and
    /// original before using the layout; this adapter creates no authority.
    pub(crate) fn borrow_original_encoding_data(
        original: &'a Envelope,
        encoding: NativeSerializationStorageData,
    ) -> Self {
        Self { original, encoding }
    }
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native stopped Observe raw record storage")
}

impl NativeProgram {
    fn quote_stopped_record<'a, T: Serialize>(
        &self,
        original: &'a Envelope,
        record: &OriginalStoppedObserveRecord<'_, T>,
        maximum: usize,
    ) -> Result<NativeStoppedObserveRecordStorageData<'a>, ProviderError> {
        let mut observer = MetadataObserver::new();
        observer.observe(original)?;
        match self {
            Self::OutputOnly(program) => {
                program.observe_original_live_capture_metadata(&mut observer)?;
            }
            Self::Connected(program) => {
                program.observe_original_live_capture_metadata(&mut observer)?;
            }
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict(
                    "native stopped Observe model incomplete",
                ));
            }
        }
        let fields = observer.finish();
        let encoding = actual_serialization_storage_data(record, fields, maximum)?;
        Ok(NativeStoppedObserveRecordStorageData { original, encoding })
    }

    pub(super) fn quote_original_stopped_observe_record<'a>(
        &self,
        original: &'a Envelope,
        maximum: usize,
    ) -> Result<NativeStoppedObserveRecordStorageData<'a>, ProviderError> {
        if original.message != crate::envelope::MessageKind::Request
            || original.method != Method::Observe
        {
            return Err(ProviderError::Correlation(
                "native stopped record requires original Observe",
            ));
        }
        match self {
            Self::OutputOnly(program) => self.quote_stopped_record(
                original,
                &OriginalStoppedObserveRecord {
                    schema: "source-owned.packet-native/2",
                    native_pid: U64::new(u64::from(std::process::id())),
                    original,
                    inventory: program.borrowed_original_stopped_inventory()?,
                    grant: None,
                },
                maximum,
            ),
            Self::Connected(program) => self.quote_stopped_record(
                original,
                &OriginalStoppedObserveRecord {
                    schema: "source-owned.packet-native/4",
                    native_pid: U64::new(u64::from(std::process::id())),
                    original,
                    inventory: program.borrowed_original_stopped_inventory()?,
                    grant: None,
                },
                maximum,
            ),
            Self::RestorationInProgress => Err(ProviderError::Conflict(
                "native stopped Observe model incomplete",
            )),
        }
    }

    fn encode_original_stopped_observe_record(
        &self,
        original: &Envelope,
        admitted: &NativeStoppedObserveRecordStorageData<'_>,
    ) -> Result<Vec<u8>, ProviderError> {
        // The original is a real immutable borrow held since the quote, not
        // a copied request identity or a decoder-controlled association.
        if admitted.original != original {
            return Err(ProviderError::Correlation(
                "native stopped Observe original changed",
            ));
        }
        let maximum = admitted.encoding.requested_total()?;
        let actual = self.quote_original_stopped_observe_record(original, maximum)?;
        if actual.encoding.maximum_encoded_bytes > admitted.encoding.maximum_encoded_bytes
            || actual.encoding.requested_total()? > maximum
        {
            return Err(exhausted());
        }
        match self {
            Self::OutputOnly(program) => crate::reference_packet::serialization_storage::encode_original_precharged_serialization(&OriginalStoppedObserveRecord {
                schema: "source-owned.packet-native/2",
                native_pid: U64::new(u64::from(std::process::id())),
                original,
                inventory: program.borrowed_original_stopped_inventory()?,
                grant: None,
            }, &admitted.encoding),
            Self::Connected(program) => crate::reference_packet::serialization_storage::encode_original_precharged_serialization(&OriginalStoppedObserveRecord {
                schema: "source-owned.packet-native/4",
                native_pid: U64::new(u64::from(std::process::id())),
                original,
                inventory: program.borrowed_original_stopped_inventory()?,
                grant: None,
            }, &admitted.encoding),
            Self::RestorationInProgress => Err(ProviderError::Conflict(
                "native stopped Observe model incomplete",
            )),
        }
    }

    pub(super) fn stopped_original_inventory_hash(&self) -> Result<HashRef, ProviderError> {
        Ok(match self {
            Self::OutputOnly(program) => canonical::json_hash(
                "source-owned.packet-inventory.v1",
                &program.borrowed_original_stopped_inventory()?,
            )?,
            Self::Connected(program) => canonical::json_hash(
                "source-owned.packet-connected-inventory/4",
                &program.borrowed_original_stopped_inventory()?,
            )?,
            Self::RestorationInProgress => {
                return Err(ProviderError::Conflict(
                    "native stopped Observe model incomplete",
                ));
            }
        })
    }
}

// Only this actual stopped producer constructs the witness. Its owned typed
// receipt and encoded evidence are produced together under the same Control
// currency, so the selected wrapper never reparses arbitrary supplied JSON.
pub(crate) struct ProducedOriginalObserveReceipt {
    creator: u32,
    identity: std::rc::Rc<()>,
    receipt: PacketNative5Record,
    activation: Id,
    world_generation: U64,
    model_cursor: Position,
    originals_before: usize,
}

pub(super) struct ProducedOriginalStoppedObserveEvidence {
    pub(super) evidence: Vec<(ContentRef, Vec<u8>)>,
    pub(super) receipt: ProducedOriginalObserveReceipt,
}

pub(super) fn original_stopped_observe_reply(
    result: ObserveResult,
    evidence: Vec<(ContentRef, Vec<u8>)>,
) -> Result<PacketControlReply, ProviderError> {
    let Value::Object(result) = serde_json::to_value(result).map_err(ContractError::from)? else {
        return Err(ProviderError::Frame("native Observe result must be object"));
    };
    let mut body = Map::new();
    body.insert("status".into(), Value::String("completed".into()));
    body.insert("operation_state".into(), Value::String("completed".into()));
    body.insert("result".into(), Value::Object(result));
    body.insert("extensions".into(), Value::Object(Map::new()));
    Ok(PacketControlReply { body, evidence })
}

impl ProducedOriginalObserveReceipt {
    pub(super) fn authenticate_dispatch_original_data(
        &self,
        original: &Envelope,
        currency: &restore_fresh::PacketLiveCaptureControlCurrency,
    ) -> Result<(), ProviderError> {
        currency.authenticate_produced_receipt_identity(self.creator, &self.identity)?;
        if &self.receipt.original != original
            || self.model_cursor != currency.cursor()
            || self.originals_before != currency.originals_before()
        {
            return Err(ProviderError::Correlation(
                "native Observe owned dispatch has another produced original",
            ));
        }
        Ok(())
    }

    pub(crate) fn original_allocation_scope(
        &self,
        currency: &restore_fresh::PacketLiveCaptureControlCurrency,
        observe_hash: HashRef,
        endpoint_records_before: usize,
        provider_next_sequence_before: u64,
    ) -> Result<
        super::super::service::capture_allocation::PacketNativeCaptureAllocationScope,
        ProviderError,
    > {
        use super::super::service::capture_allocation::{
            NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN, PacketNativeCaptureAllocationScope,
        };
        currency.authenticate_produced_receipt_identity(self.creator, &self.identity)?;
        observe_hash.validate()?;
        if observe_hash.domain != NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN
            || provider_next_sequence_before == 0
            || self.model_cursor != currency.cursor()
            || self.originals_before != currency.originals_before()
        {
            return Err(ProviderError::Correlation(
                "native Observe allocation scope differs",
            ));
        }
        let receipt = &self.receipt;
        let original = &receipt.original;
        let observe_request = original
            .request_id
            .0
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native Observe allocation original ID absent",
            ))?;
        // All owning copies are taken from the jointly produced receipt and
        // immutable stopped Control. No raw receipt is decoded or accepted as
        // an alternate producer. The caller admits these projected fields
        // before entering the selected dispatcher/transformer.
        Ok(PacketNativeCaptureAllocationScope {
            native_pid: receipt.native_pid,
            observe_request: observe_request.clone(),
            observe_sequence: original.sequence,
            observe_hash,
            session: receipt.session.clone(),
            incarnation: receipt.incarnation.clone(),
            node: receipt.node.clone(),
            owner: receipt.owner.clone(),
            binding_hash: receipt.binding_hash.clone(),
            world: receipt.world.clone(),
            activation: self.activation.clone(),
            world_generation: self.world_generation,
            owner_generation: receipt.owner_generation,
            model_cursor: currency.cursor(),
            control_originals_before: U64::new(
                u64::try_from(currency.originals_before()).map_err(|_| exhausted())?,
            ),
            endpoint_records_before: U64::new(
                u64::try_from(endpoint_records_before).map_err(|_| exhausted())?,
            ),
            provider_next_sequence_before: U64::new(provider_next_sequence_before),
        })
    }

    pub(crate) fn borrowed_allocation_record_view<'a>(
        &'a self,
        original: &Envelope,
        currency: &restore_fresh::PacketLiveCaptureControlCurrency,
        report: &'a ContentRef,
    ) -> Result<impl serde::Serialize + 'a, ProviderError> {
        currency.authenticate_produced_receipt_identity(self.creator, &self.identity)?;
        if &self.receipt.original != original
            || report.media_type != super::super::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA
            || report.length.get() == 0
            || report.length.get() > super::super::service::capture_allocation::MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES as u64
        {
            return Err(ProviderError::Correlation("native Observe produced receipt association differs"));
        }
        report.validate()?;
        #[derive(serde::Serialize)]
        struct BorrowedRecord<'a> {
            schema: &'static str,
            native: &'a PacketNative5Record,
            allocation: &'a ContentRef,
        }
        Ok(BorrowedRecord {
            schema:
                super::super::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_RECORD,
            native: &self.receipt,
            allocation: report,
        })
    }
}

impl PacketControl {
    pub(crate) fn quote_original_stopped_observe_record<'a>(
        &self,
        original: &'a Envelope,
        maximum: usize,
    ) -> Result<NativeStoppedObserveRecordStorageData<'a>, ProviderError> {
        if self.capture_creator != std::process::id()
            || !self.immediate
            || self.complete_capture_allocation_selection.is_none()
            || self.complete_coordinator.is_none()
            || self.fenced
        {
            return Err(ProviderError::Correlation(
                "native selected stopped Observe owner",
            ));
        }
        self.program
            .quote_original_stopped_observe_record(original, maximum)
    }

    pub(super) fn retain_original_stopped_observe_evidence(
        &mut self,
        original: &Envelope,
        currency: &restore_fresh::PacketLiveCaptureControlCurrency,
        admitted: &NativeStoppedObserveRecordStorageData<'_>,
    ) -> Result<ProducedOriginalStoppedObserveEvidence, ProviderError> {
        // Only the private Observe dispatcher supplies this borrowed original,
        // after its full route/body checks and sticky Unknown registration.
        // A portable selection or an arbitrary preencoded raw object cannot
        // enter this producer in place of the actual stopped model.
        currency.authenticate_completed_observe(self)?;

        if original.message != crate::envelope::MessageKind::Request
            || original.method != Method::Observe
        {
            return Err(ProviderError::Correlation(
                "native stopped producer requires original Observe",
            ));
        }
        let installed = self
            .complete_coordinator
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native stopped producer lacks coordinator",
            ))?;
        if installed.schema != "source-owned.packet-complete-coordinator-installation/5"
            || !installed.participants.contains(&self.selection)
        {
            return Err(ProviderError::Correlation(
                "native stopped producer foreign coordinator",
            ));
        }
        // The constructor fully validated this private coordinator. No method
        // mutates it; restoration creates a different Control identity. The
        // currency joins that same owner without regenerating its JSON here.
        let mut evidence = Vec::new();
        evidence.try_reserve_exact(2).map_err(|_| exhausted())?;
        let bytes = self
            .program
            .encode_original_stopped_observe_record(original, admitted)?;
        let raw = reference(&bytes)?;
        // The full reference was just constructed from these same immutable
        // producer bytes. Rehashing it would add no independent association.
        currency.authenticate_completed_observe(self)?;

        let receipt = self.original_complete_receipt_data(original, raw.clone())?;
        let receipt_bytes = encode(&receipt)?;
        let receipt_ref = reference(&receipt_bytes)?;
        self.install_content(raw.clone(), &bytes)?;
        self.install_content(receipt_ref.clone(), &receipt_bytes)?;
        currency.authenticate_completed_observe(self)?;

        let active = self.active.as_ref().ok_or(ProviderError::Correlation(
            "native stopped Observe active world absent",
        ))?;
        let activation = active.activation_id.clone();
        let world_generation = active.world_generation;

        // These are the actual two producer buffers. No decode or content-bank
        // clone is needed to rediscover their already checked association.
        evidence.push((raw, bytes));
        evidence.push((receipt_ref, receipt_bytes));
        Ok(ProducedOriginalStoppedObserveEvidence {
            evidence,
            receipt: ProducedOriginalObserveReceipt {
                creator: self.capture_creator,
                identity: std::rc::Rc::clone(&self.capture_identity),
                receipt,
                activation,
                world_generation,
                model_cursor: currency.cursor(),
                originals_before: currency.originals_before(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::connected::{
        PacketConnectedDefinition, PacketConnectedNativeRecord, PacketConnectedProgram,
        PacketInputConnection,
    };
    use crate::reference_packet::{Bytes, PacketEvent, PacketProgram};
    use std::os::unix::net::UnixDatagram;

    fn original() -> Result<Envelope, ProviderError> {
        Ok(Envelope {
            protocol: "CNP/1".into(),
            message: crate::envelope::MessageKind::Request,
            session_id: Nullable(Some(Id::new("session")?)),
            incarnation_id: Nullable(Some(Id::new("incarnation")?)),
            node_id: Nullable(Some(Id::new("node")?)),
            execution_owner_id: Nullable(Some(Id::new("owner")?)),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("original-observe")?)),
            operation_id: Nullable(None),
            sequence: U64::new(7),
            method: Method::Observe,
            body: Map::new(),
            extensions: Extensions::new(),
        })
    }

    // Real program constructors own actual sockets and precharged banks. These
    // controls compare only serializers; their inert original has no binding,
    // Source permission, common ticket or selected full-class authority.
    #[test]
    fn borrowed_producer_record_matches_real_owning_record_and_inventory_hash()
    -> Result<(), ProviderError> {
        let (socket, _peer) = UnixDatagram::pair()?;
        let mut payload = Vec::with_capacity(4096);
        payload.extend_from_slice(&[0, 255, 127]);
        let mut program = PacketProgram::new(
            vec![PacketEvent {
                id: Id::new("retained-binary-event")?,
                evaluation: Position::new(U64::new(2), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(2), U64::new(1), Phase::Publication),
                payload: Some(Bytes::new(payload)),
            }],
            socket,
        )?;
        program.open_gate()?;
        let original = original()?;
        let legacy = encode(&PacketNativeRecord {
            schema: "source-owned.packet-native/2".into(),
            native_pid: U64::new(u64::from(std::process::id())),
            original: original.clone(),
            inventory: program.inventory(),
            grant: None,
        })?;
        let program = NativeProgram::OutputOnly(program);
        let quoted = program.quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)?;
        let borrowed = program.encode_original_stopped_observe_record(&original, &quoted)?;
        assert_eq!(borrowed, legacy);
        assert_eq!(reference(&borrowed)?, reference(&legacy)?);
        assert_eq!(
            program.stopped_original_inventory_hash()?,
            program.inventory_hash()?
        );
        let decoded: PacketNativeRecord =
            serde_json::from_value(canonical::parse_json(&borrowed, FRAME)?)
                .map_err(ContractError::from)?;
        assert_eq!(decoded.original, original);
        assert!(decoded.grant.is_none());
        Ok(())
    }

    #[test]
    fn borrowed_reactive_record_matches_real_owning_record_and_inventory_hash()
    -> Result<(), ProviderError> {
        let endpoint = |node| -> Result<Endpoint, ProviderError> {
            Ok(Endpoint {
                node_id: Id::new(node)?,
                port_id: Id::new("port")?,
                lane_id: Id::new("lane")?,
            })
        };
        let (socket, _peer) = UnixDatagram::pair()?;
        let mut program = PacketConnectedProgram::new(
            PacketConnectedDefinition {
                schema: "source-owned.packet-connected-program/4".into(),
                connections: vec![PacketInputConnection {
                    id: Id::new("original-route")?,
                    policy: canonical::content_ref(b"original-policy", "application/octet-stream")?,
                    producer: endpoint("producer")?,
                    consumer: endpoint("consumer")?,
                    delay_ps: U64::new(1),
                }],
                output: None,
            },
            socket,
        )?;
        program.open_gate()?;
        let original = original()?;
        let legacy = encode(&PacketConnectedNativeRecord {
            schema: "source-owned.packet-native/4".into(),
            native_pid: U64::new(u64::from(std::process::id())),
            original: original.clone(),
            inventory: program.inventory()?,
            grant: None,
        })?;
        let program = NativeProgram::Connected(program);
        let quoted = program.quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)?;
        let borrowed = program.encode_original_stopped_observe_record(&original, &quoted)?;
        assert_eq!(borrowed, legacy);
        assert_eq!(reference(&borrowed)?, reference(&legacy)?);
        assert_eq!(
            program.stopped_original_inventory_hash()?,
            program.inventory_hash()?
        );
        let decoded: PacketConnectedNativeRecord =
            serde_json::from_value(canonical::parse_json(&borrowed, FRAME)?)
                .map_err(ContractError::from)?;
        assert_eq!(decoded.original, original);
        assert!(decoded.grant.is_none());
        Ok(())
    }

    #[test]
    fn borrowed_raw_record_refuses_changed_original_before_dom_or_model_mutation()
    -> Result<(), ProviderError> {
        let (socket, _peer) = UnixDatagram::pair()?;
        let mut program = PacketProgram::new(
            vec![PacketEvent {
                id: Id::new("private-event")?,
                evaluation: Position::new(U64::new(2), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(2), U64::new(0), Phase::Reaction),
                payload: None,
            }],
            socket,
        )?;
        program.open_gate()?;
        let original = original()?;
        let program = NativeProgram::OutputOnly(program);
        let admitted =
            program.quote_original_stopped_observe_record(&original, 16 * 1024 * 1024)?;
        let before = program.stopped_original_inventory_hash()?;
        let mut changed = original.clone();
        changed
            .body
            .insert("larger".into(), Value::String("changed".repeat(4096)));
        assert!(
            program
                .encode_original_stopped_observe_record(&changed, &admitted)
                .is_err()
        );
        assert_eq!(before, program.stopped_original_inventory_hash()?);
        changed.method = Method::Input;
        assert!(
            program
                .quote_original_stopped_observe_record(&changed, 16 * 1024 * 1024)
                .is_err()
        );
        Ok(())
    }
}
