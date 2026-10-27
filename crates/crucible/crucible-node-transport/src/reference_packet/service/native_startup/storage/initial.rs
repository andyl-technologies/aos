//! Projects the constructor's closed Discover/Realize/once-Admit lifecycle.
//!
//! Field events describe the actual unopened constructor, not a fabricated native
//! owner. The selected receiver must restrict these three methods before typed
//! decoding. A raw/projection bound never grants permission to receive or act.

use super::*;
use crate::connection::{OriginalContinuationContentExtent, OriginalPacketPrefixProjectionInput};
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;

use crate::reference_packet::service::PacketNative5LaunchValidationFields as Fields;
use crucible_source_birth_data::profile::reference_packet::service::native_startup::initial_shapes as shapes;
use shapes::InitialShapeKindData as Kind;
pub(crate) use shapes::OriginalHostInitialLifecycleShapes;

pub(super) struct InitialLifecycleStorage {
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
}

pub(super) fn admit_projection(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    shapes::admit_projection(&Fields::from_launch_data(launch), maximum)
}

fn request(
    launch: &PacketNative5SourceLaunch,
    kind: Kind,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    shapes::request(&Fields::from_launch_data(launch), kind, maximum)
}

fn raw_record(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    shapes::raw_record(&Fields::from_launch_data(launch), maximum)
}

fn receipt(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    shapes::receipt(&Fields::from_launch_data(launch), maximum)
}

fn terminal(
    launch: &PacketNative5SourceLaunch,
    kind: Kind,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    shapes::terminal(&Fields::from_launch_data(launch), kind, maximum)
}

pub(super) fn project(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<InitialLifecycleStorage, ProviderError> {
    let discover = request(launch, Kind::Discover, maximum)?;
    let realize = request(launch, Kind::Realize, maximum)?;
    let admit = request(launch, Kind::Admit, maximum)?;
    let raw = raw_record(launch, maximum)?;
    let receipt = receipt(launch, maximum)?;
    let objects = [
        OriginalContinuationContentExtent {
            maximum_payload_bytes: raw.maximum_encoded_bytes.min(NATIVE_HELLO_BYTES),
            media_type: "application/json",
        },
        OriginalContinuationContentExtent {
            maximum_payload_bytes: receipt.maximum_encoded_bytes.min(NATIVE_HELLO_BYTES),
            media_type: "application/json",
        },
    ];
    let mut retained = 0usize;
    let mut transient = 0usize;
    let mut scratch = 0usize;
    for (kind, original) in [
        (Kind::Discover, &discover),
        (Kind::Realize, &realize),
        (Kind::Admit, &admit),
    ] {
        let terminal = terminal(launch, kind, maximum)?;
        let evidence = if matches!(kind, Kind::Realize) {
            &objects[..]
        } else {
            &[]
        };
        let prefix = crate::connection::quote_original_packet_baseline_prefix_startup_storage_data(
            launch,
            OriginalPacketPrefixProjectionInput {
                terminal: &terminal,
                original,
                objects: evidence,
                maximum_requested_bytes: maximum,
            },
        )?;
        retained = sum(
            &[
                retained,
                prefix
                    .exchange
                    .native_retained_backing_bytes
                    .ok_or_else(refused)?,
                prefix.native_source_backing_bytes.ok_or_else(refused)?,
                terminal.retained_value_backing_bytes,
                original.retained_value_backing_bytes,
            ],
            maximum,
        )?;
        transient = transient.max(sum(
            &[
                original.requested_total()?,
                terminal.requested_total()?,
                prefix.exchange.requested_bytes()?,
            ],
            maximum,
        )?);
        scratch = scratch.max(prefix.declared_counter_scratch_bytes);
    }
    let content = sum(
        &[
            objects[0].maximum_payload_bytes,
            objects[1].maximum_payload_bytes,
        ],
        maximum,
    )?;
    let mut trees = MetadataObserver::new();
    trees.tree::<crucible_node_format::Id, (
        crucible_node_format::HashRef,
        crate::reference_packet::control::PacketControlReply,
    )>(3)?;
    trees.tree::<crucible_node_format::ContentRef, Vec<u8>>(2)?;
    let tree_backing = requested_metadata_backing_storage_data(&trees.finish())?;
    let reference_children =
        "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len();
    retained = sum(
        &[
            retained,
            content,
            content,
            tree_backing,
            3 * (128 + "blake3-256".len() + "cnp.request.v1".len() + 64),
            6 * reference_children,
            2 * size_of::<(crucible_node_format::ContentRef, Vec<u8>)>(),
        ],
        maximum,
    )?;
    transient = transient.max(sum(
        &[
            raw.requested_total()?,
            receipt.requested_total()?,
            content,
            size_of::<crate::reference_packet::control::PacketNativeRecord>(),
            size_of::<crate::reference_packet::connected::PacketConnectedNativeRecord>(),
            size_of::<crate::reference_packet::control::PacketNative5Record>(),
        ],
        maximum,
    )?);
    Ok(InitialLifecycleStorage {
        retained,
        transient,
        scratch,
    })
}

pub(crate) fn original_host_initial_lifecycle_shapes_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<OriginalHostInitialLifecycleShapes, ProviderError> {
    shapes::original_host_initial_lifecycle_shapes_data(&Fields::from_launch_data(launch), maximum)
}

/// Names the actual defining Fields family and new direct adapter windows.
pub(crate) const fn original_initial_literal_shape_counter_scratch_data() -> usize {
    2 * size_of::<Fields<'static>>() // actual from_launch_data return
        + size_of::<&Fields<'static>>() // shared producer input loan
        + size_of::<&PacketNative5SourceLaunch>() // defining getter input loan
        + size_of::<usize>() // new lower maximum input; sequential calls share this window
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>() // direct returned shape
        + size_of::<Result<OriginalHostInitialLifecycleShapes, ProviderError>>() // direct returned host bank
}

#[cfg(test)]
#[path = "initial/original.rs"]
mod original;
#[cfg(test)]
#[path = "initial/shapes_tests.rs"]
mod shapes_tests;
