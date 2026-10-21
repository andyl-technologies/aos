//! Genuine PID1 fixed-unit observations shared by Root and its Controller client.
//!
//! Property equality is point-in-time, not a policy freeze. Trusted deployment
//! administration and PID1 remain within the RFC boot/system-manager boundary.

use std::path::PathBuf;

use aos_systemd_client::{OwnedValue, Value};

use crate::systemd_property_data;

mod property_values;
pub(crate) use property_values::{PropertyPairV1, PropertyValuesV1};

use super::{
    NormalRootStartupErrorV1, PID1_FD_NAME, PROFILE_FD_NAME,
    profile::{CONTEXT, UNIT},
};

pub(super) const SERVICE_PROPERTIES: &[&str] = &[
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
// Only the resource enrollment consumer reads original producer custody.
// Ordinary Root/Controller observers keep their literal property lists.
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

const UNIT_PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];
const NIX_BARRIER_PROPERTIES: &[&str] = &[
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
    "SELinuxContext",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "ExitType",
    "KillMode",
    "TimeoutStopUSec",
];
pub(super) const PEER_PROPERTIES: &[&str] =
    aos_sandbox_broker::receiving::ROOT_PEER_PROPERTIES_V1;

pub(super) const CONTROLLER_UNIT: &str = "aos-sandboxd.service";

const STORAGE_UNIT: &str = "aos-storaged.service";
const STORAGE_CGROUP: &str = "/aos.slice/aos-control.slice/aos-storaged.service";
const STORAGE_RECEIVING_CGROUP: &str = aos_sandbox_linux::cgroup::StorageCgroupLayoutV1::ReceivingAggregate
    .main_control_group_v1();
const STORAGE_CONTEXT: &str = "system_u:system_r:aos_sandbox_storage_t";
const STORAGE_PROPERTIES: &[&str] = &[
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
];
const STORAGE_RESOURCE_PROPERTIES: &[&str] = &[
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
    "AOSResourceProducerEpoch",
];

pub(super) use aos_sandbox_broker::profile_data::delivery::ServiceObservationV1;

pub(super) fn observe(
    profile_path: &str,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    observe_at(profile_path, std::process::id())
}

/// Observes only this process's fixed Storage unit through the same PID1 reader.
pub(super) fn observe_storage(
) -> Result<super::StorageWorkerParentDataV3, NormalRootStartupErrorV1> {
    let (service, unit) = read_properties(STORAGE_UNIT, std::process::id(), STORAGE_PROPERTIES)?;
    decode_storage(&service, &unit, false)
}

pub(super) fn observe_storage_resource(
) -> Result<(super::StorageWorkerParentDataV3, [u8; 16]), NormalRootStartupErrorV1> {
    let (service, unit) = read_properties(
        STORAGE_UNIT, std::process::id(), STORAGE_RESOURCE_PROPERTIES,
    )?;
    let (producer, common) = service.split_last()
        .ok_or(NormalRootStartupErrorV1::Service)?;
    let parent = decode_storage(common, &unit, true)?;
    Ok((parent, decode_resource_producer(producer)?))
}

// These fixed role recipes share the already-paid archive and existing
// semantic decoder. No caller-selected unit, PID or property list enters.
// The actual selected Controller profile supplies its separately paid
// archive. These fixed recipes return DATA and cannot select arbitrary units.
pub(super) fn read_controller_startup_with_archive(
    archive: &mut FirstGlobalPropertyArchive,
) -> Result<PropertyPairV1, NormalRootStartupErrorV1> {
    archive.read(CONTROLLER_UNIT, std::process::id(), SERVICE_PROPERTIES)
}

pub(super) fn read_controller_resource_with_archive(
    archive: &mut FirstGlobalPropertyArchive,
) -> Result<PropertyPairV1, NormalRootStartupErrorV1> {
    archive.read(CONTROLLER_UNIT, std::process::id(), RESOURCE_SERVICE_PROPERTIES)
}

pub(super) fn observe_storage_with_archive(
    archive: &mut FirstGlobalPropertyArchive,
) -> Result<super::StorageWorkerParentDataV3, NormalRootStartupErrorV1> {
    let (service, unit) = archive.read(
        STORAGE_UNIT, std::process::id(), STORAGE_PROPERTIES,
    )?;
    decode_storage(&service, &unit, false)
}

pub(super) fn observe_storage_resource_with_archive(
    archive: &mut FirstGlobalPropertyArchive,
) -> Result<(super::StorageWorkerParentDataV3, [u8; 16]), NormalRootStartupErrorV1> {
    let (service, unit) = archive.read(
        STORAGE_UNIT, std::process::id(), STORAGE_RESOURCE_PROPERTIES,
    )?;
    let (producer, common) = service.split_last()
        .ok_or(NormalRootStartupErrorV1::Service)?;
    let parent = decode_storage(common, &unit, true)?;
    Ok((parent, decode_resource_producer(producer)?))
}

pub(super) fn observe_root_resource_with_archive(
    archive: &mut FirstGlobalPropertyArchive,
    profile_path: &str,
) -> Result<(ServiceObservationV1, [u8; 16]), NormalRootStartupErrorV1> {
    let (service, unit) = archive.read(
        UNIT, std::process::id(), RESOURCE_SERVICE_PROPERTIES,
    )?;
    let (parent, producer) = decode_root_resource(&service, &unit, profile_path)?;
    Ok((immutable_observation(parent)?, producer))
}

fn decode_storage(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    resource_delivery: bool,
) -> Result<super::StorageWorkerParentDataV3, NormalRootStartupErrorV1> {
    let [cgroup, open_files, extras, maximum, stored, context, bounding, ambient, nnp, start] =
        service
    else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(open_files) = &**open_files else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let [Value::Structure(open_file)] = open_files.inner() else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let [Value::Str(path), Value::Str(name), Value::U64(1)] = open_file.fields() else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    let Value::Array(extras) = &**extras else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    if <&str>::try_from(cgroup).ok() != Some(if resource_delivery {
        STORAGE_RECEIVING_CGROUP
    } else {
        STORAGE_CGROUP
    })
        || path.as_str() != "/proc/1/exe"
        || name.as_str() != "aos-method46-pid1-image"
        || !super::client::valid_resource_delivery_names(extras.inner(), resource_delivery)
        || extras.element_signature() != Value::from("").value_signature()
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || systemd_property_data::explicit_context(context) != Some(STORAGE_CONTEXT)
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let command = systemd_property_data::single_exec_start(start)
        .ok_or(NormalRootStartupErrorV1::Service)?;
    if command.pid != std::process::id()
        || command.path.len() > 4096
        || !storage_main_argument_shape_v1(command.argv, resource_delivery)
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let executable = command.path.to_owned();
    let arguments = command
        .argv
        .iter()
        .map(|value| {
            let Value::Str(value) = value else {
                return Err(NormalRootStartupErrorV1::Service);
            };
            if value.len() > 4096 {
                return Err(NormalRootStartupErrorV1::Service);
            }
            Ok(value.as_str().to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let observed = immutable_observation(decode_unit(unit, STORAGE_UNIT)?)?;
    Ok(super::StorageWorkerParentDataV3 {
        fragment: observed.fragment,
        invocation: observed.invocation,
        executable,
        arguments,
    })
}

pub(super) fn observe_at(
    profile_path: &str,
    pid: u32,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    aos_sandbox_broker::receiving::observe_root_comparison_at_v1(profile_path, pid)
        .map_err(Into::into)
}

pub(super) fn observe_peer(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::profile::NormalRootProfileV1,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    let (values, unit) = read_properties(UNIT, pid, PEER_PROPERTIES)?;
    decode_peer_properties(profile_path, pid, profile, &values, &unit)
}

pub(super) fn decode_peer_properties(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::profile::NormalRootProfileV1,
    values: &[OwnedValue],
    unit: &[OwnedValue],
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::root_peer_data::decode_peer_properties(profile_path, pid, profile, values, unit).map_err(Into::into)
}

// Selected callers retain the actual canonicalization Result beside the same
// complete PID1 archive. Ordinary callers keep their original short sink.
pub(super) fn decode_peer_properties_into(
    profile_path: &std::path::Path,
    pid: u32,
    profile: &super::profile::NormalRootProfileV1,
    values: &[OwnedValue],
    unit: &[OwnedValue],
    canonical: &mut Option<std::io::Result<std::path::PathBuf>>,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::root_peer_data::decode_peer_properties_into(profile_path, pid, profile, values, unit, canonical).map_err(Into::into)
}

pub(super) fn require_peer_launch(
    launch: &[OwnedValue],
    pid: u32,
    profile: &super::profile::NormalRootProfileV1,
) -> Result<(), NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::root_peer_data::require_peer_launch(launch, pid, profile).map_err(Into::into)
}

pub(super) fn read_properties(
    unit_name: &'static str,
    pid: u32,
    properties: &'static [&'static str],
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    read_properties_with_recipe(unit_name, pid, properties, Pid1ConnectionRecipeV5::Legacy)
}

#[derive(Clone, Copy)]
pub(super) enum Pid1ConnectionRecipeV5 {
    Legacy,
    NixOfflineHardware,
}

pub(super) fn read_nix_offline_hardware_properties(
    properties: &'static [&'static str],
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    read_properties_with_recipe(
        "aos-sandbox-nix-floor-provision.service",
        std::process::id(),
        properties,
        Pid1ConnectionRecipeV5::NixOfflineHardware,
    )
}

// Resource Main supports the existing mutually exclusive measured selectors.
// Legacy observation keeps its original exact twelve-argument contract. This
// borrowed check precedes String collection and supplies comparison DATA only.
fn storage_main_argument_shape_v1(arguments: &[Value<'_>], resource_delivery: bool) -> bool {
    match arguments.len() {
        12 => true,
        13 if resource_delivery => matches!(arguments.last(), Some(Value::Str(flag))
            if matches!(flag.as_str(), "--git-upload-exclusive-cohort" | "--nix-storage-generation-prepare")),
        _ => false,
    }
}

fn read_properties_with_recipe(
    unit_name: &'static str,
    pid: u32,
    properties: &'static [&'static str],
    recipe: Pid1ConnectionRecipeV5,
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    let recipe = match recipe {
        Pid1ConnectionRecipeV5::Legacy => aos_systemd_client::Pid1PropertyReadRecipeV1::Legacy,
        Pid1ConnectionRecipeV5::NixOfflineHardware => {
            aos_systemd_client::Pid1PropertyReadRecipeV1::NixOfflineHardware
        }
    };
    aos_systemd_client::read_pid1_startup_properties_v1(unit_name, pid, properties, recipe)
        .map_err(|_| NormalRootStartupErrorV1::Service)
}

pub(crate) fn first_global_observer_demand_v1(
) -> Result<aos_sandbox_model::ResourceVector, NormalRootStartupErrorV1> {
    use aos_systemd_client::ControllerPropertyObserverAttemptV1 as Observer;

    let maximum = Observer::MESSAGE_BYTES.checked_mul(Observer::INCOMING_MESSAGES)
        .ok_or(NormalRootStartupErrorV1::Service)?;
    first_global_observer_demand_for_materialization_v1(maximum)
}

// This is representation DATA, never an admission or payer constructor. The
// lower receiver charges this exact cumulative encoded-byte ceiling before
// either its fixed header or dynamic body decoder can materialize a value.
// Strict wire/collection limits and the original service cgroup separately
// back allocator metadata, parser overhead and kernel residency (RFC-0006).
pub(crate) fn first_global_observer_demand_for_materialization_v1(
    materialized_bytes: usize,
) -> Result<aos_sandbox_model::ResourceVector, NormalRootStartupErrorV1> {
    observer_materialization_demand_v1(materialized_bytes)
}

// The selected receiver emits only Hello, GetNameOwner,
// GetConnectionUnixProcessID, GetUnit and Properties.Get. Their bodies contain
// at most two string arguments, with fixed tuple/header shape; no recursively
// decoded outbound OwnedValue is created. Returned destination/object paths
// come from already-admitted incoming frames and retain their own copy budget.
pub(crate) fn fixed_property_observer_demand_v1(
    materialized_bytes: usize,
) -> Result<aos_sandbox_model::ResourceVector, NormalRootStartupErrorV1> {
    aos_sandbox_broker::receiving::fixed_property_archive_demand_v1(materialized_bytes)
        .map_err(Into::into)
}

fn observer_materialization_demand_v1(
    materialized_bytes: usize,
) -> Result<aos_sandbox_model::ResourceVector, NormalRootStartupErrorV1> {
    aos_sandbox_broker::receiving::FixedPropertyArchiveV1::observer_materialization_demand_v1(materialized_bytes)
        .map_err(Into::into)
}

// Complete per-row data includes old/new entry Vec backing during a later
// funded increase of the SAME archive. Native row owners have their separate
// fixed-property bound; this does not describe an allocator's exact metadata.
pub(super) fn growing_fixed_property_observer_demand_v1(
    materialized_bytes: usize,
) -> Result<aos_sandbox_model::ResourceVector, NormalRootStartupErrorV1> {
    aos_sandbox_broker::receiving::growing_fixed_property_archive_demand_v1(materialized_bytes)
        .map_err(Into::into)
}

pub(crate) use aos_sandbox_broker::receiving::FixedPropertyArchiveGrowthErrorV1 as CreateIntakeObserverGrowthErrorV1;

// The one-field role projection keeps the same native archive/lifetime layout.
pub(crate) struct FirstGlobalPropertyArchive(
    aos_sandbox_broker::receiving::FixedPropertyArchiveV1,
);


impl FirstGlobalPropertyArchive {
    pub(super) fn new(
        maximum: usize,
        lifetime: crate::controller_resource_reservation::service_interval::ObserverLifetime,
    ) -> Self {
        Self(aos_sandbox_broker::receiving::FixedPropertyArchiveV1::new(maximum, lifetime))
    }

    pub(super) fn with_materialization_limit(
        maximum: usize,
        lifetime: crate::controller_resource_reservation::service_interval::ObserverLifetime,
        materialization_limit: usize,
    ) -> Self {
        Self(aos_sandbox_broker::receiving::FixedPropertyArchiveV1::with_materialization_limit(
            maximum, lifetime, materialization_limit,
        ))
    }

    pub(super) fn prepare(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.0.prepare().map_err(Into::into)
    }

    pub(super) fn failure_view(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.0.failure_view()
    }

    pub(super) fn grow_prepaid_create_intake_once(
        &mut self, maximum: usize,
    ) -> Result<(), CreateIntakeObserverGrowthErrorV1> {
        self.0.grow_rows(maximum)
    }

    pub(super) fn settle_positive_once(&mut self) -> Result<(), NormalRootStartupErrorV1> {
        self.0.settle_positive_once().map_err(Into::into)
    }

    pub(super) fn read(
        &mut self, unit_name: &'static str, pid: u32, properties: &'static [&'static str],
    ) -> Result<PropertyPairV1, NormalRootStartupErrorV1> {
        self.0.read(unit_name, pid, properties).map_err(Into::into)
    }
}

pub(super) fn immutable_observation(
    observed: ServiceObservationV1,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    immutable_observation_into(observed, &mut None)
}

// The selected owner supplies the result slot before this same native action.
// No name or observation is authority, and a repeated slot does no new IO.
pub(super) fn immutable_observation_into(
    mut observed: ServiceObservationV1,
    canonical: &mut Option<std::io::Result<PathBuf>>,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::delivery::immutable_observation_into(observed, canonical).map_err(Into::into)
}

// Only Nix floor-origin observations add the population crash-barrier fields.
// The ordinary Root/Controller flights retain their exact property list.
/// Reads the Nix barrier fields through the same authentic PID1 observer.
///
/// # Errors
///
/// Rejects failed original PID1 readback, wrong width or a barrier mismatch.
pub(super) fn read_nix_barrier_properties(
    unit_name: &'static str,
    pid: u32,
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), NormalRootStartupErrorV1> {
    let (mut properties, unit) = read_properties(unit_name, pid, NIX_BARRIER_PROPERTIES)?;
    if properties.len() != NIX_BARRIER_PROPERTIES.len() {
        return Err(NormalRootStartupErrorV1::Service);
    }
    let barrier = properties.split_off(SERVICE_PROPERTIES.len());
    require_nix_barrier(&barrier)?;
    Ok((properties, unit))
}

fn require_nix_barrier(values: &[OwnedValue]) -> Result<(), NormalRootStartupErrorV1> {
    let [exit_type, kill_mode, timeout] = values else {
        return Err(NormalRootStartupErrorV1::Service);
    };
    if <&str>::try_from(exit_type).ok() != Some("cgroup")
        || <&str>::try_from(kill_mode).ok() != Some("control-group")
        || u64::try_from(timeout).ok() != Some(u64::MAX)
    {
        return Err(NormalRootStartupErrorV1::Service);
    }
    Ok(())
}

pub(super) fn decode(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &str,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::root_peer_data::decode(service, unit, profile_path).map_err(Into::into)
}



pub(super) fn decode_unit(
    unit: &[OwnedValue],
    unit_name: &str,
) -> Result<ServiceObservationV1, NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::delivery::decode_unit(unit, unit_name).map_err(Into::into)
}





// This only compares already-retained property DATA. The original Root must
// supply a complete admission before any archive/read/runtime is constructed.
pub(super) fn decode_root_resource(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &str,
) -> Result<(ServiceObservationV1, [u8; 16]), NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::root_peer_data::decode_root_resource(service, unit, profile_path).map_err(Into::into)
}

pub(super) fn require_same(
    previous: &ServiceObservationV1,
    current: &ServiceObservationV1,
) -> Result<(), NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::delivery::require_same(previous, current).map_err(Into::into)
}

// A live property is merely an observation. The owning enrollment consumer
// compares it to its retained original pair under the same PID1 bookends.
pub(super) fn decode_resource_producer(
    value: &OwnedValue,
) -> Result<[u8; 16], NormalRootStartupErrorV1> {
    aos_sandbox_broker::profile_data::delivery::decode_resource_producer(value).map_err(Into::into)
}

#[cfg(test)]
mod nix_barrier_tests {
    use super::*;

    fn values(exit_type: &str, kill_mode: &str, timeout: u64) -> Vec<OwnedValue> {
        vec![
            OwnedValue::try_from(Value::from(exit_type.to_owned())).unwrap(),
            OwnedValue::try_from(Value::from(kill_mode.to_owned())).unwrap(),
            OwnedValue::from(timeout),
        ]
    }

    #[test]
    fn nix_barrier_appends_only_three_fields_to_the_ordinary_property_order() {
        assert_eq!(
            &NIX_BARRIER_PROPERTIES[..SERVICE_PROPERTIES.len()],
            SERVICE_PROPERTIES,
        );
        assert_eq!(
            &NIX_BARRIER_PROPERTIES[SERVICE_PROPERTIES.len()..],
            &["ExitType", "KillMode", "TimeoutStopUSec"],
        );
    }

    #[test]
    fn nix_barrier_requires_exact_population_and_unbounded_stop_properties() {
        assert!(require_nix_barrier(&values("cgroup", "control-group", u64::MAX)).is_ok());

        for candidate in [
            values("main", "control-group", u64::MAX),
            values("cgroup", "process", u64::MAX),
            values("cgroup", "control-group", u64::MAX - 1),
            values("cgroup", "control-group", 0),
        ] {
            assert!(require_nix_barrier(&candidate).is_err());
        }
        assert!(require_nix_barrier(&[]).is_err());
        let mut extra = values("cgroup", "control-group", u64::MAX);
        extra.push(OwnedValue::from(0_u64));
        assert!(require_nix_barrier(&extra).is_err());
    }
}

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod property_observer_received_descriptor_tests {
    use std::io::{IoSlice, IoSliceMut};
    use std::mem::MaybeUninit;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    use rustix::net::{
        RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
    };

    #[test]
    fn empty_controller_control_never_installs_rights_for_any_linux_rights_count() {
        let (sender, receiver) = UnixStream::pair().expect("fixture socket pair");
        let borrowed = vec![sender.as_fd(); 253];

        // Linux accepts at most SCM_MAX_FD=253 descriptors per rights message.
        // Exercise every accepted count, including no control. This matches
        // the actual Controller branch's zero-length slice, not the backing
        // LauncherRawRecord array's larger allocated capacity.
        for count in 0..=borrowed.len() {
            let mut outgoing = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253))];
            let mut outgoing = SendAncillaryBuffer::new(&mut outgoing);
            if count != 0 {
                assert!(outgoing.push(SendAncillaryMessage::ScmRights(&borrowed[..count])));
            }
            assert_eq!(sendmsg(&sender, &[IoSlice::new(b"x")], &mut outgoing,
                SendFlags::empty()).expect("fixture rights send"), 1);

            let mut bytes = [0_u8; 1];
            let mut no_control = [];
            let mut incoming = RecvAncillaryBuffer::new(&mut no_control);
            let message = recvmsg(&receiver, &mut [IoSliceMut::new(&mut bytes)],
                &mut incoming, RecvFlags::CMSG_CLOEXEC).expect("fixture rights receive");

            assert_eq!(message.bytes, 1);
            assert_eq!(bytes, *b"x");
            assert_eq!(incoming.drain().count(), 0, "sent rights: {count}");
            assert_eq!(message.flags.contains(ReturnFlags::CTRUNC), count != 0,
                "sent rights: {count}");
        }
    }

}


#[cfg(test)]
mod storage_main_argument_tests {
    use super::*;

    #[test]
    fn resource_main_accepts_only_one_existing_fixed_optional_mode() {
        let mut arguments: Vec<Value<'_>> = (0..12).map(|_| Value::from("fixed")).collect();
        assert!(storage_main_argument_shape_v1(&arguments, true));
        assert!(storage_main_argument_shape_v1(&arguments, false));

        arguments.push(Value::from("--git-upload-exclusive-cohort"));
        assert!(storage_main_argument_shape_v1(&arguments, true));
        assert!(!storage_main_argument_shape_v1(&arguments, false));
        arguments[12] = Value::from("--nix-storage-generation-prepare");
        assert!(storage_main_argument_shape_v1(&arguments, true));
        arguments[12] = Value::from("--unknown-mode");
        assert!(!storage_main_argument_shape_v1(&arguments, true));
        arguments[12] = Value::from("--git-upload-exclusive-cohort");
        arguments.push(Value::from("--nix-storage-generation-prepare"));
        assert!(!storage_main_argument_shape_v1(&arguments, true));
    }
}
