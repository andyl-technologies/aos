//! Counts the closed stopped raw2/4 grammar before a native owner exists.
//!
//! Inventory populations use the real finite model constructor/transition
//! limits. Producer fields borrow the installed event definition. Reactive
//! fields account every independently retained inventory view, including each
//! repeated payload. The ordinary proof's 64 KiB encoded ceiling is enforced
//! separately; it never stands in for these DOM/canonical allocations.

use super::observe::original;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::report_shapes::{decimal, object, raw::{producer, initial_inventory, StoppedInventoryRowLimitsData}};
use super::*;
use crate::reference_packet::connected::PacketConnectedProgram;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection,
};

type Projection = OriginalSerializationStorageProjection;

fn reactive(projection: &mut Projection) -> Result<(), ProviderError> {
    let limits = PacketConnectedProgram::original_stopped_inventory_row_limits_data();
    let facts = StoppedInventoryRowLimitsData {
        events: limits.events,
        batches: limits.batches,
        payload_bytes: limits.payload_bytes,
    };
    crucible_source_birth_data::profile::reference_packet::service::native_startup::report_shapes::raw::reactive(projection, &facts)
}

pub(super) fn project(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut projection = Projection::new(maximum)?;
    object(
        &mut projection,
        &["schema", "native_pid", "original", "inventory", "grant"],
    )?;
    projection.add_string(match &launch.program {
        PacketConnectedSourceProgram::Producer { .. } => "source-owned.packet-native/2",
        PacketConnectedSourceProgram::Reactive { .. } => "source-owned.packet-native/4",
    })?;
    decimal(&mut projection)?;
    original(&mut projection, launch)?;
    match &launch.program {
        PacketConnectedSourceProgram::Producer { program } => {
            producer(&mut projection, program)?;
        }
        PacketConnectedSourceProgram::Reactive { .. } => reactive(&mut projection)?,
    }
    // The selected producer is an Observe: no semantic grant is serialized.
    projection.add_value(&())?;
    projection.finish(maximum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reactive_startup_projection_covers_distinct_maximum_inventory_populations()
    -> Result<(), ProviderError> {
        let limits = PacketConnectedProgram::original_stopped_inventory_row_limits_data();
        let maximum = 512 * 1024 * 1024;
        let mut projection = Projection::new(maximum)?;

        reactive(&mut projection)?;
        let actual = projection.finish(maximum)?;

        // Four independent event inventories coexist with both batch journals.
        // Actual native limits differ (32 events,16 batches). A positional swap
        // would project128 rows instead of the required160 and fails this check.
        assert_ne!(limits.events, limits.batches);
        assert_eq!(actual.sequence_elements, 160);
        assert_eq!(
            actual.sequence_elements,
            4 * limits.events + 2 * limits.batches
        );
        assert_eq!(actual.sequence_containers, 6);
        assert!(actual.maximum_encoded_bytes > limits.events * limits.payload_bytes);
        Ok(())
    }
}

/// Projects only the actual untouched Source14 model checked before live quote.
///
/// The original constructor owns all initial event payloads. No callback/input
/// has executed, and the actual activated model has no output or input history.
/// The complete old stopped-state projection remains available independently.
pub(super) fn project_initial(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut projection = Projection::new(maximum)?;
    object(
        &mut projection,
        &["schema", "native_pid", "original", "inventory", "grant"],
    )?;
    projection.add_string(match &launch.program {
        PacketConnectedSourceProgram::Producer { .. } => "source-owned.packet-native/2",
        PacketConnectedSourceProgram::Reactive { .. } => "source-owned.packet-native/4",
    })?;
    decimal(&mut projection)?;
    original(&mut projection, launch)?;
    initial_inventory(&mut projection, &launch.program)?;
    projection.add_value(&())?;
    projection.finish(maximum)
}

#[cfg(test)]
mod initial_geometry_tests {
    use super::*;
    use crate::reference_packet::connected::{PacketConnectedDefinition, PacketInputConnection};
    use crate::reference_packet::{PacketEvent, PacketProgram, PacketProgramDefinition};
    use crucible_node_format::{Bytes, Endpoint, Id, Phase, Position, U64, canonical};
    use std::os::unix::net::UnixDatagram;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn check(
        program: &PacketConnectedSourceProgram,
        inventory: impl serde::Serialize,
    ) -> TestResult {
        let maximum = 512 * 1024 * 1024;
        let mut counter = Projection::new(maximum)?;
        initial_inventory(&mut counter, program)?;
        let projected = counter.finish(maximum)?;
        let value = serde_json::to_value(inventory)?;
        let encoded = canonical::canonical_json(&value)?;
        let mut observer = MetadataObserver::new();
        observer.observe(&value)?;
        let actual_backing =
            crate::retained_metadata::requested_metadata_backing_storage_data(&observer.finish())?;

        assert!(encoded.len() <= projected.maximum_encoded_bytes);
        assert!(actual_backing <= projected.retained_value_backing_bytes);
        let exact = projected.requested_total()?;
        let mut counter = Projection::new(exact)?;
        initial_inventory(&mut counter, program)?;
        counter.finish(exact)?;
        let short = (|| {
            let mut counter = Projection::new(exact - 1)?;
            initial_inventory(&mut counter, program)?;
            counter.finish(exact - 1)
        })();
        assert!(short.is_err());
        Ok(())
    }

    #[test]
    fn actual_initial_producer_and_reactive_inventory_dom_and_encoding_fit_exact_projection()
    -> TestResult {
        let definition = PacketProgramDefinition {
            schema: "source-owned.packet-program.v1".into(),
            events: vec![PacketEvent {
                id: Id::new("actual-initial-event")?,
                evaluation: Position::new(U64::new(2), U64::new(0), Phase::Reaction),
                completion: Position::new(U64::new(2), U64::new(1), Phase::Publication),
                payload: Some(Bytes::new(vec![0, 255, 13, 10, 92, 34])),
            }],
        };
        let (socket, _peer) = UnixDatagram::pair()?;
        let mut producer = PacketProgram::new(definition.events.clone(), socket)?;
        producer.open_gate()?;
        check(
            &PacketConnectedSourceProgram::Producer {
                program: definition,
            },
            producer.inventory(),
        )?;

        let endpoint = |node| -> Result<Endpoint, ProviderError> {
            Ok(Endpoint {
                node_id: Id::new(node)?,
                port_id: Id::new("port")?,
                lane_id: Id::new("lane")?,
            })
        };
        let definition = PacketConnectedDefinition {
            schema: "source-owned.packet-connected-program/4".into(),
            connections: vec![PacketInputConnection {
                id: Id::new("actual-initial-route")?,
                policy: canonical::content_ref(b"policy", "application/octet-stream")?,
                producer: endpoint("producer")?,
                consumer: endpoint("consumer")?,
                delay_ps: U64::new(1),
            }],
            output: None,
        };
        let (socket, _peer) = UnixDatagram::pair()?;
        let mut reactive = PacketConnectedProgram::new(definition.clone(), socket)?;
        reactive.open_gate()?;
        check(
            &PacketConnectedSourceProgram::Reactive {
                program: definition,
            },
            reactive.inventory()?,
        )?;
        Ok(())
    }
}
