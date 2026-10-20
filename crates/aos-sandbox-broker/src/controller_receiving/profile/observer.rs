//! Shares fixed Controller query DATA and the actual readonly PID1 engine.
//!
//! The selected archive owns bounded flights only after its genuine C scope
//! admission. The ordinary helper retains the previous consuming thread recipe.

use aos_systemd::{OwnedValue, Value};
use super::ControllerProfileErrorV1 as NormalRootStartupErrorV1;
use super::delivery;

pub(super) use aos_systemd::FixedPid1PropertyArchiveV1 as FirstGlobalPropertyArchive;
pub(super) use super::property_values::PropertyPairV1;
use super::property_values::PropertyValuesV1;
pub(super) const CONTROLLER_UNIT: &str = delivery::CONTROLLER_UNIT;
pub(super) use delivery::SERVICE_PROPERTIES;

pub(super) const RESOURCE_SERVICE_PROPERTIES: &[&str] = &[
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

pub(super) const RUNTIME_TASK_PROPERTIES: &[&str] = &["TasksMax"];

pub(super) const PEER_PROPERTIES: &[&str] = &[
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
];

pub(super) use delivery::UNIT_PROPERTIES;

pub(super) fn read_controller_startup_with_archive(
    archive: &mut FirstGlobalPropertyArchive,
) -> Result<PropertyPairV1, NormalRootStartupErrorV1> {
    archive.read(CONTROLLER_UNIT, std::process::id(), SERVICE_PROPERTIES, UNIT_PROPERTIES)
        .map(|(service, unit)| (PropertyValuesV1::retained_owned(service), PropertyValuesV1::retained_owned(unit)))
        .map_err(|_| NormalRootStartupErrorV1::Service)
}

pub(super) fn read_controller_startup_under_slot_v1(
    archive: &mut FirstGlobalPropertyArchive,
    slot: &mut aos_systemd::FixedPid1PropertyWorkerSlotV1,
) -> Result<PropertyPairV1, NormalRootStartupErrorV1> {
    archive.read_under_slot(slot, CONTROLLER_UNIT, std::process::id(), SERVICE_PROPERTIES, UNIT_PROPERTIES)
        .map(|(service, unit)| (PropertyValuesV1::retained_owned(service), PropertyValuesV1::retained_owned(unit)))
        .map_err(|_| NormalRootStartupErrorV1::Service)
}

pub(super) fn read_controller_resource_with_archive(
    archive: &mut FirstGlobalPropertyArchive,
) -> Result<PropertyPairV1, NormalRootStartupErrorV1> {
    archive.read(CONTROLLER_UNIT, std::process::id(), RESOURCE_SERVICE_PROPERTIES, UNIT_PROPERTIES)
        .map(|(service, unit)| (PropertyValuesV1::retained_owned(service), PropertyValuesV1::retained_owned(unit)))
        .map_err(|_| NormalRootStartupErrorV1::Service)
}

pub(super) fn immutable_observation(
    observed: delivery::ServiceObservationV1,
) -> Result<delivery::ServiceObservationV1, NormalRootStartupErrorV1> {
    delivery::immutable_observation_into(observed, &mut None)
}

pub(super) fn decode_resource_producer(
    value: &OwnedValue,
) -> Result<[u8; 16], NormalRootStartupErrorV1> {
    super::delivery::decode_resource_producer(value)
}

#[derive(Clone, Copy)]
enum Pid1ConnectionRecipeV5 {
    Legacy,
    NixOfflineHardware,
}

/// Runs the unchanged ordinary fixed Nix hardware PID1 observation.
///
/// # Errors
/// Preserves connection, runtime, timeout, worker or property refusal.
pub fn read_nix_offline_hardware_properties(
    properties: &'static [&'static str],
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    read_properties_with_recipe(
        "aos-sandbox-nix-floor-provision.service",
        std::process::id(),
        properties,
        Pid1ConnectionRecipeV5::NixOfflineHardware,
    )
}


/// Runs the unchanged ordinary bounded-lifetime PID1 observation.
///
/// This consuming adapter grants no role or original receiving authority.
///
/// # Errors
/// Preserves connection, runtime, timeout, worker or property refusal.
pub fn read_properties(
    unit_name: &'static str,
    pid: u32,
    properties: &'static [&'static str],
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    read_properties_with_recipe(unit_name, pid, properties, Pid1ConnectionRecipeV5::Legacy)
}

fn read_properties_with_recipe(
    unit_name: &'static str,
    pid: u32,
    properties: &'static [&'static str],
    recipe: Pid1ConnectionRecipeV5,
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    let recipe = match recipe {
        Pid1ConnectionRecipeV5::Legacy => aos_systemd::Pid1PropertyReadRecipeV1::Legacy,
        Pid1ConnectionRecipeV5::NixOfflineHardware => {
            aos_systemd::Pid1PropertyReadRecipeV1::NixOfflineHardware
        }
    };
    aos_systemd::read_pid1_startup_properties_v1(unit_name, pid, properties, recipe)
        .map_err(|_| NormalRootStartupErrorV1::Service)
}

pub(super) fn observe_delivery(
    profile: &std::path::Path,
    tpm_image: bool,
    nix_profile: Option<&std::path::Path>,
    resource_delivery: bool,
    resource_launch: bool,
) -> Result<delivery::ServiceObservationV1, NormalRootStartupErrorV1> {
    let (properties, unit) = read_properties(CONTROLLER_UNIT, std::process::id(), SERVICE_PROPERTIES)?;
    immutable_observation(delivery::decode_delivery_with_resource_launch(
        &properties, &unit, profile, tpm_image, nix_profile, resource_delivery, resource_launch,
    )?)
}
