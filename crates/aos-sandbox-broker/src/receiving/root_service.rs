//! Runs the fixed Root PID1 recipe over its continuously owned native archive.
//!
//! Only the Root capture owns this private interval. It cannot be supplied by
//! a caller or used as payment; construction follows the genuine role's fixed
//! prepayment. The shared Systemd engine retains cancellation, native errors,
//! socket retirement and worker join exactly as for the upper adapter.

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_systemd::FixedPid1PropertyArchiveV1;

use crate::profile_data::{delivery, root_peer_data, schema};
use super::RootObservationErrorV1 as Error;

pub(super) use delivery::ServiceObservationV1;

const SERVICE_PROPERTIES: &[&str] = &[
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
];
const RESOURCE_SERVICE_PROPERTIES: &[&str] = &[
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "AOSResourceProducerEpoch",
];
pub(super) use super::ObservationLifetimeV1 as RootObserverLifetimeV1;
pub(super) use super::FixedPropertyArchiveV1 as FirstGlobalPropertyArchive;

pub(super) fn fixed_property_observer_demand_v1(bytes: usize) -> Option<ResourceVector> {
    let shape = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(bytes).ok()?;
    Some(ResourceVector::ZERO
        .with(D::MemoryBytes, shape.memory_bytes)
        .with(D::OpenFiles, shape.open_files)
        // Each actual retained row creates the exported one-worker thread.
        // The older kernel Pids reserve stays separate; no unnamed task credit
        // or positive-disposal assumption offsets this explicit supplier.
        .with(D::Pids, shape.worker_threads)
        .with(D::MetadataEntries, shape.metadata_entries)
        .with(D::NetworkBytes, shape.wire_io_bytes)
        .with(D::PublicationStagingBytes, shape.memory_bytes)
        .with(D::LogBytes, shape.maximum_log_bytes)
        .with(D::OutputBytes, shape.memory_bytes))
}

pub(super) fn observe_root_resource_with_archive(
    archive: &mut FirstGlobalPropertyArchive,
    profile_path: &str,
) -> Result<(ServiceObservationV1, [u8; 16]), Error> {
    observe_root_resource_with_archive_retaining_v1(archive, profile_path, &mut None)
}

pub(super) fn observe_root_resource_with_archive_retaining_v1(
    archive: &mut FirstGlobalPropertyArchive,
    profile_path: &str,
    canonical: &mut Option<std::io::Result<std::path::PathBuf>>,
) -> Result<(ServiceObservationV1, [u8; 16]), Error> {
    let (service, unit) = archive.read(
        schema::UNIT, std::process::id(), RESOURCE_SERVICE_PROPERTIES,
    )?;
    let (parent, producer) = root_peer_data::decode_root_resource(&service, &unit, profile_path)?;
    let parent = delivery::immutable_observation_into(parent, canonical)?;
    Ok((parent, producer))
}

/// Observes the fixed Root unit for the supplied comparison process DATA.
///
/// This is the existing ordinary recipe, not a receiving or role constructor.
/// Actual Root startup always supplies this process and its measured profile.
///
/// # Errors
/// Preserves the original native/property/decode and immutable comparisons.
pub fn observe_root_comparison_at_v1(
    profile_path: &str,
    pid: u32,
) -> Result<ServiceObservationV1, Error> {
    let (service, unit) = aos_systemd::read_pid1_startup_properties_v1(
        schema::UNIT, pid, SERVICE_PROPERTIES, aos_systemd::Pid1PropertyReadRecipeV1::Legacy,
    ).map_err(|_| Error::Service)?;
    let observed = root_peer_data::decode(&service, &unit, profile_path)?;
    delivery::immutable_observation_into(observed, &mut None).map_err(Into::into)
}

pub(super) fn observe(profile_path: &str) -> Result<ServiceObservationV1, Error> {
    observe_root_comparison_at_v1(profile_path, std::process::id())
}

pub(super) fn require_same(
    previous: &ServiceObservationV1, current: &ServiceObservationV1,
) -> Result<(), Error> {
    delivery::require_same(previous, current).map_err(Into::into)
}
