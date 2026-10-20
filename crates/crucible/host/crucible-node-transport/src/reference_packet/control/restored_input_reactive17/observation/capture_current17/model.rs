//! Quotes and encodes the exact stopped Producer or Reactive Capture model.
//!
//! Both branches borrow the actual live inventory and retain its original
//! request. The Capture-specific caller has separately authenticated its cut,
//! Source/native owning checkpoint and full row. Generic Observe17 remains on
//! its existing Reactive-only branch; a matching model grants no action.

use super::*;
use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;

#[derive(Serialize)]
struct CaptureModel17<'a, I> {
    schema: &'static str,
    native_pid: U64,
    original: &'a Envelope,
    inventory: I,
    grant: Option<()>,
}

impl PacketControl {
    pub(super) fn capture17_model_storage_data(
        &self,
        previous: &Envelope,
        maximum: usize,
    ) -> Result<NativeSerializationStorageData, ProviderError> {
        let mut observed = MetadataObserver::new();
        let mut formatter = MetadataObserver::new();
        match &self.program {
            NativeProgram::OutputOnly(program) => {
                let inventory = program.borrow_original_capture_inventory(&mut observed)?;
                inventory.observe_serialized_formatter_fields(&mut formatter)?;
                actual_serialization_storage_data(
                    &CaptureModel17 {
                        schema: "source-owned.packet-native/2",
                        native_pid: U64::new(u64::from(self.capture_creator)),
                        original: previous,
                        inventory,
                        grant: None,
                    },
                    formatter.finish(),
                    maximum,
                )
            }
            NativeProgram::Connected(program) => {
                let inventory = program.borrow_original_capture_inventory(&mut observed)?;
                inventory.observe_serialized_formatter_fields(&mut formatter)?;
                actual_serialization_storage_data(
                    &CaptureModel17 {
                        schema: "source-owned.packet-native/4",
                        native_pid: U64::new(u64::from(self.capture_creator)),
                        original: previous,
                        inventory,
                        grant: None,
                    },
                    formatter.finish(),
                    maximum,
                )
            }
            NativeProgram::RestorationInProgress => Err(refused()),
        }
    }

    pub(super) fn encode_capture17_model_data(
        &self,
        previous: &Envelope,
        storage: &NativeSerializationStorageData,
        destination: &mut Vec<u8>,
    ) -> Result<(), ProviderError> {
        let mut observed = MetadataObserver::new();
        match &self.program {
            NativeProgram::OutputOnly(program) => {
                let inventory = program.borrow_original_capture_inventory(&mut observed)?;
                encode_original_precharged_serialization_into(
                    &CaptureModel17 {
                        schema: "source-owned.packet-native/2",
                        native_pid: U64::new(u64::from(self.capture_creator)),
                        original: previous,
                        inventory,
                        grant: None,
                    },
                    storage,
                    destination,
                )
            }
            NativeProgram::Connected(program) => {
                let inventory = program.borrow_original_capture_inventory(&mut observed)?;
                encode_original_precharged_serialization_into(
                    &CaptureModel17 {
                        schema: "source-owned.packet-native/4",
                        native_pid: U64::new(u64::from(self.capture_creator)),
                        original: previous,
                        inventory,
                        grant: None,
                    },
                    storage,
                    destination,
                )
            }
            NativeProgram::RestorationInProgress => Err(refused()),
        }
    }
}

pub(super) fn counter_scratch_data() -> usize {
    // The closures are never called: their real borrowed return types name
    // both inventory layouts without exposing the defining private modules.
    record_layout_data(|program: &'static crate::reference_packet::PacketProgram| {
        program.borrow_original_capture_inventory(&mut MetadataObserver::new())
    }) + record_layout_data(|program: &'static crate::reference_packet::connected::PacketConnectedProgram| {
        program.borrow_original_capture_inventory(&mut MetadataObserver::new())
    })
        + size_of::<MetadataObserver<'static>>() * 2
        + size_of::<NativeSerializationStorageData>()
        + size_of::<Result<NativeSerializationStorageData, ProviderError>>()
        + size_of::<&Envelope>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<&NativeSerializationStorageData>()
        + size_of::<Result<(), ProviderError>>()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
}

fn record_layout_data<P: 'static, I>(_: fn(&'static P) -> Result<I, ProviderError>) -> usize {
    size_of::<CaptureModel17<'static, I>>() + size_of::<Result<I, ProviderError>>()
}

// crucible-lint: allow panic-shortcut -- these controls compare actual DATA encoders, not action grants.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::{
        PacketEvent, PacketProgram,
        connected::{PacketConnectedDefinition, PacketConnectedProgram, PacketInputConnection},
    };
    use crate::retained_metadata::RetainedProtocolMetadataFacts;
    use crucible_node_format::{Bytes, Endpoint, Id, Phase, Position};
    use std::os::unix::net::UnixDatagram;

    fn matches_owning_record<I: Serialize>(
        view: &CaptureModel17<'_, I>,
        original: &impl Serialize,
        fields: RetainedProtocolMetadataFacts,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let maximum = 1_048_576;
        let shape = actual_serialization_storage_data(view, fields, maximum)?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(shape.maximum_encoded_bytes)?;
        encode_original_precharged_serialization_into(view, &shape, &mut encoded)?;
        let expected = canonical::canonical_json(&serde_json::to_value(original)?)?;
        assert_eq!(encoded, expected);
        assert_eq!(
            canonical::content_ref(&encoded, "application/json")?,
            canonical::content_ref(&expected, "application/json")?
        );
        assert!(shape.serializer_temporary_requested_bytes >= 20);
        Ok(())
    }

    #[test]
    fn producer_capture_encoder_matches_the_actual_owned_native2_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let (socket, _peer) = UnixDatagram::pair()?;
        let event = PacketEvent {
            id: Id::new("capture-model-event")?,
            evaluation: Position::new(U64::new(5), U64::new(0), Phase::Reaction),
            completion: Position::new(U64::new(5), U64::new(1), Phase::Publication),
            payload: Some(Bytes::new(b"actual pending modeled payload".to_vec())),
        };
        let mut program = PacketProgram::new(vec![event], socket)?;
        program.open_gate()?;
        let mut original = crate::envelope::tests::request();
        original.method = Method::Observe;
        let pid = U64::new(u64::from(std::process::id()));
        let owned = crate::reference_packet::control::PacketNativeRecord {
            schema: "source-owned.packet-native/2".into(),
            native_pid: pid,
            original: original.clone(),
            inventory: program.inventory(),
            grant: None,
        };
        let inventory = program.borrow_original_capture_inventory(&mut MetadataObserver::new())?;
        let mut formatter = MetadataObserver::new();
        inventory.observe_serialized_formatter_fields(&mut formatter)?;
        matches_owning_record(
            &CaptureModel17 {
                schema: "source-owned.packet-native/2",
                native_pid: pid,
                original: &original,
                inventory,
                grant: None,
            },
            &owned,
            formatter.finish(),
        )
    }

    #[test]
    fn reactive_capture_encoder_matches_the_actual_owned_native4_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let (socket, _peer) = UnixDatagram::pair()?;
        let endpoint = |node| -> Result<Endpoint, crucible_node_format::ContractError> {
            Ok(Endpoint {
                node_id: Id::new(node)?,
                port_id: Id::new("packet")?,
                lane_id: Id::new("lane")?,
            })
        };
        let definition = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![PacketInputConnection {
                id: Id::new("capture-model-route")?,
                policy: canonical::content_ref(b"actual policy", "application/json")?,
                producer: endpoint("source")?,
                consumer: endpoint("target")?,
                delay_ps: U64::new(3),
            }],
            output: None,
        };
        let mut program = PacketConnectedProgram::new(definition, socket)?;
        program.open_gate()?;
        let mut original = crate::envelope::tests::request();
        original.method = Method::Observe;
        let pid = U64::new(u64::from(std::process::id()));
        let owned = crate::reference_packet::connected::PacketConnectedNativeRecord {
            schema: "source-owned.packet-native/4".into(),
            native_pid: pid,
            original: original.clone(),
            inventory: program.inventory()?,
            grant: None,
        };
        let inventory = program.borrow_original_capture_inventory(&mut MetadataObserver::new())?;
        let mut formatter = MetadataObserver::new();
        inventory.observe_serialized_formatter_fields(&mut formatter)?;
        matches_owning_record(
            &CaptureModel17 {
                schema: "source-owned.packet-native/4",
                native_pid: pid,
                original: &original,
                inventory,
                grant: None,
            },
            &owned,
            formatter.finish(),
        )
    }
}
