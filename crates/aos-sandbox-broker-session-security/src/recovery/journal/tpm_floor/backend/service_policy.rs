//! Actual fixed PID 1 service policy around every physical TPM operation.
//!
//! Required-mode image policy uses `ExitType=cgroup`, `KillMode=control-group`,
//! and infinite stop timeout. PID 1 observes `cgroup.events/populated`, whose
//! exit transition follows kernel file-release task work. A PID list does not
//! establish that ordering: Linux may hide `PF_EXITING` tasks before release.
//!
//! Readback pins effective properties, the exact nontransient image fragment,
//! invocation, actual PID 1 launch image, and retained process/cgroup objects. It is
//! NOT a policy freeze. Administrative reload or cgroup migration remains
//! within RFC-0021's trusted kernel/boot/system-manager deployment custody;
//! neither source readback nor unit-reference lifetime denies those changes.
//! Installed policy and crash ordering must qualify before method 46 can open.
//! No descriptor-number or shared-flock release ordering is assumed.
//! The launch FD is not a continuous measurement of a later manager reexec.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_systemd::{OwnedValue, SystemdClient, Value};
use rustix::fs::{Mode, OFlags, open};

use super::super::FloorErrorV1;
use super::super::format::FloorEndpointV1;
use super::image::MeasuredFileV1;

const PROPERTY_TIMEOUT: Duration = Duration::from_secs(5);
const SERVICE_PROPERTIES: &[&str] = &[
    "ExitType",
    "KillMode",
    "TimeoutStopUSec",
    "ControlGroup",
    "OpenFile",
    "ExtraFileDescriptorNames",
    "FileDescriptorStoreMax",
    "NFileDescriptorStore",
];
const UNIT_PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];

pub(super) struct RetainedFloorServicePolicyV1 {
    endpoint: FloorEndpointV1,
    parent: PidFd,
    parent_identity: PidFdProcessIdentity,
    cgroup: RetainedCgroupAnchor,
    invocation: Vec<u8>,
    fragment: MeasuredFileV1,
    manager: MeasuredFileV1,
}

struct PolicyObservationV1 {
    fragment: PathBuf,
    control_group: String,
    invocation: Vec<u8>,
}

impl RetainedFloorServicePolicyV1 {
    pub(super) fn open(
        endpoint: FloorEndpointV1,
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<Self, FloorErrorV1> {
        launch_image
            .require_endpoint(match endpoint {
                FloorEndpointV1::ControllerStorageClient => {
                    crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
                }
                FloorEndpointV1::StorageBroker => {
                    crate::ProtectedBrokerSessionFixedEndpointV1::StorageBroker
                }
            })
            .map_err(|_| FloorErrorV1::Provisioning)?;
        let manager = MeasuredFileV1::open_pid1(launch_image)?;
        let parent =
            PidFd::open(NonZeroU32::new(std::process::id()).ok_or(FloorErrorV1::Unavailable)?)
                .map_err(|_| FloorErrorV1::Unavailable)?;
        let info = parent.info().map_err(|_| FloorErrorV1::Unavailable)?;
        if info.parent_pid() != 1 || info.pid() != std::process::id() {
            return Err(FloorErrorV1::Provisioning);
        }
        let parent_identity = parent
            .process_identity()
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let observed = observe(endpoint)?;
        let root = CgroupV2Root::from_owned(
            open(
                "/sys/fs/cgroup",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| FloorErrorV1::Unavailable)?,
        )
        .map_err(|_| FloorErrorV1::Unavailable)?;
        let relative = observed
            .control_group
            .strip_prefix('/')
            .ok_or(FloorErrorV1::Provisioning)?;
        let cgroup = root
            .resolve(Path::new(relative))
            .map_err(|_| FloorErrorV1::Unavailable)?;
        cgroup
            .verify_exact_membership(&parent)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let mut retained = Self {
            endpoint,
            parent,
            parent_identity,
            cgroup,
            invocation: observed.invocation,
            fragment: MeasuredFileV1::observe_fragment(observed.fragment)?,
            manager,
        };
        retained.revalidate()?;
        Ok(retained)
    }

    pub(super) fn revalidate(&mut self) -> Result<(), FloorErrorV1> {
        self.manager.revalidate()?;
        self.fragment.revalidate()?;
        let observed = observe(self.endpoint)?;
        if observed.fragment != self.fragment.path()
            || observed.invocation != self.invocation
            || self
                .parent
                .process_identity()
                .map_err(|_| FloorErrorV1::Unavailable)?
                != self.parent_identity
            || self
                .parent
                .info()
                .map_err(|_| FloorErrorV1::Unavailable)?
                .parent_pid()
                != 1
        {
            return Err(FloorErrorV1::Provisioning);
        }
        self.cgroup
            .verify_exact_membership(&self.parent)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        self.fragment.revalidate()?;
        self.manager.revalidate()
    }

    pub(super) fn require_child(&self, child: &PidFd) -> Result<(), FloorErrorV1> {
        self.cgroup
            .verify_exact_membership(&self.parent)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        self.cgroup
            .verify_exact_membership(child)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        Ok(())
    }
}

/// Runs the shared async bus reader without nesting the daemon's Tokio runtime.
fn observe(endpoint: FloorEndpointV1) -> Result<PolicyObservationV1, FloorErrorV1> {
    std::thread::Builder::new()
        .name("method46-pid1-readback".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| FloorErrorV1::Unavailable)?;
            runtime.block_on(async {
                tokio::time::timeout(PROPERTY_TIMEOUT, async {
                    let systemd = SystemdClient::connect()
                        .await
                        .map_err(|_| FloorErrorV1::Unavailable)?;
                    let (service, unit) = systemd
                        .observe_pid1_service_startup_properties(
                            unit_name(endpoint),
                            std::process::id(),
                            SERVICE_PROPERTIES,
                            UNIT_PROPERTIES,
                        )
                        .await
                        .map_err(|_| FloorErrorV1::Unavailable)?;
                    decode_policy(&service, &unit, endpoint)
                })
                .await
                .map_err(|_| FloorErrorV1::Unavailable)?
            })
        })
        .map_err(|_| FloorErrorV1::Unavailable)?
        .join()
        .map_err(|_| FloorErrorV1::Unavailable)?
}

fn decode_policy(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    endpoint: FloorEndpointV1,
) -> Result<PolicyObservationV1, FloorErrorV1> {
    let mut observed = decode_policy_claims(service, unit, endpoint)?;
    observed.fragment =
        std::fs::canonicalize(observed.fragment).map_err(|_| FloorErrorV1::Provisioning)?;
    if !observed.fragment.starts_with("/nix/store")
        || observed
            .fragment
            .file_name()
            .is_none_or(|name| name != unit_name(endpoint))
    {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(observed)
}

/// Checks effective property shape; only the retained live observation is custody.
fn decode_policy_claims(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    endpoint: FloorEndpointV1,
) -> Result<PolicyObservationV1, FloorErrorV1> {
    let [
        exit_type,
        kill_mode,
        timeout,
        cgroup,
        open_files,
        extra_fds,
        store_maximum,
        stored_fds,
    ] = service
    else {
        return Err(FloorErrorV1::Provisioning);
    };
    let [fragment, drop_ins, transient, invocation] = unit else {
        return Err(FloorErrorV1::Provisioning);
    };
    let string_is = |value: &OwnedValue, expected: &str| {
        <&str>::try_from(value).is_ok_and(|value| value == expected)
    };
    let drop_ins = Vec::<String>::try_from(
        drop_ins
            .try_clone()
            .map_err(|_| FloorErrorV1::Provisioning)?,
    )
    .map_err(|_| FloorErrorV1::Provisioning)?;
    let invocation = Vec::<u8>::try_from(
        invocation
            .try_clone()
            .map_err(|_| FloorErrorV1::Provisioning)?,
    )
    .map_err(|_| FloorErrorV1::Provisioning)?;
    let cgroup = <&str>::try_from(cgroup).map_err(|_| FloorErrorV1::Provisioning)?;
    let expected_cgroup = format!("/aos.slice/aos-control.slice/{}", unit_name(endpoint));
    if !string_is(exit_type, "cgroup")
        || !string_is(kill_mode, "control-group")
        || u64::try_from(timeout).ok() != Some(u64::MAX)
        || bool::try_from(transient).ok() != Some(false)
        || !drop_ins.is_empty()
        || invocation.len() != 16
        || invocation.iter().all(|byte| *byte == 0)
        || cgroup != expected_cgroup
        || !has_exact_launch_fd_properties(open_files, extra_fds)
        || u32::try_from(store_maximum).ok() != Some(0)
        || u32::try_from(stored_fds).ok() != Some(0)
    {
        return Err(FloorErrorV1::Provisioning);
    }
    let fragment = <&str>::try_from(fragment).map_err(|_| FloorErrorV1::Provisioning)?;
    if fragment.len() > 4096 || !fragment.starts_with('/') {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(PolicyObservationV1 {
        fragment: PathBuf::from(fragment),
        control_group: cgroup.to_owned(),
        invocation,
    })
}

/// Checks the single fixed launch entry without copying caller-sized arrays.
fn has_exact_launch_fd_properties(open_files: &OwnedValue, extra_fds: &OwnedValue) -> bool {
    let Value::Array(open_files) = &**open_files else {
        return false;
    };
    let [Value::Structure(entry)] = open_files.inner() else {
        return false;
    };
    let [path, name, flags] = entry.fields() else {
        return false;
    };
    let Value::Array(extra_fds) = &**extra_fds else {
        return false;
    };

    // OpenFile's public read-only bit, with no append/truncate/graceful options.
    // The installed pinned 261.2 property encoding still requires qualification.
    <&str>::try_from(path).ok() == Some("/proc/1/exe")
        && <&str>::try_from(name).ok()
            == Some(aos_sandbox_storage::activation::PID1_LAUNCH_IMAGE_FD_NAME)
        && u64::try_from(flags).ok() == Some(1)
        && extra_fds.is_empty()
        && extra_fds.element_signature() == Value::from("").value_signature()
}

const fn unit_name(endpoint: FloorEndpointV1) -> &'static str {
    match endpoint {
        FloorEndpointV1::ControllerStorageClient => "aos-sandboxd.service",
        FloorEndpointV1::StorageBroker => "aos-storaged.service",
    }
}

#[cfg(test)]
mod tests {
    use aos_systemd::Value;

    use super::{FloorEndpointV1, OwnedValue, decode_policy_claims};

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn claims() -> (Vec<OwnedValue>, Vec<OwnedValue>) {
        let service = vec![
            value("cgroup"),
            value("control-group"),
            OwnedValue::from(u64::MAX),
            value("/aos.slice/aos-control.slice/aos-sandboxd.service"),
            value(vec![(
                "/proc/1/exe".to_owned(),
                aos_sandbox_storage::activation::PID1_LAUNCH_IMAGE_FD_NAME.to_owned(),
                1_u64,
            )]),
            value(Vec::<String>::new()),
            OwnedValue::from(0_u32),
            OwnedValue::from(0_u32),
        ];
        let unit = vec![
            // This test rejects policy claims before any filesystem lookup.
            value("/nix/store/fixture/aos-sandboxd.service"),
            value(Vec::<String>::new()),
            OwnedValue::from(false),
            value(vec![1_u8; 16]),
        ];
        (service, unit)
    }

    #[test]
    fn effective_floor_service_policy_rejects_weakened_claims() {
        let (service, unit) = claims();
        assert!(
            decode_policy_claims(&service, &unit, FloorEndpointV1::ControllerStorageClient).is_ok()
        );

        for (position, replacement) in [
            (0, value("main")),
            (1, value("process")),
            (2, OwnedValue::from(30_000_000_u64)),
            (3, value("/other.slice/aos-sandboxd.service")),
            (4, value(Vec::<(String, String, u64)>::new())),
            (
                4,
                value(vec![(
                    "/nix/store/asserted/systemd".to_owned(),
                    aos_sandbox_storage::activation::PID1_LAUNCH_IMAGE_FD_NAME.to_owned(),
                    1_u64,
                )]),
            ),
            (
                4,
                value(vec![(
                    "/proc/1/exe".to_owned(),
                    "wrong-name".to_owned(),
                    1_u64,
                )]),
            ),
            (
                4,
                value(vec![(
                    "/proc/1/exe".to_owned(),
                    aos_sandbox_storage::activation::PID1_LAUNCH_IMAGE_FD_NAME.to_owned(),
                    9_u64,
                )]),
            ),
            (
                4,
                value(vec![
                    (
                        "/proc/1/exe".to_owned(),
                        aos_sandbox_storage::activation::PID1_LAUNCH_IMAGE_FD_NAME.to_owned(),
                        1_u64,
                    );
                    2
                ]),
            ),
            (4, value(vec![("/proc/1/exe", "wrong-type", 1_u32)])),
            (5, value(vec!["unaccounted-fd".to_owned()])),
            (5, value(Vec::<u8>::new())),
            (6, OwnedValue::from(1_u32)),
            (7, OwnedValue::from(1_u32)),
        ] {
            let (mut service, unit) = claims();
            service[position] = replacement;
            assert!(
                decode_policy_claims(&service, &unit, FloorEndpointV1::ControllerStorageClient)
                    .is_err()
            );
        }
        for (position, replacement) in [
            (0, value("relative-fragment")),
            (
                1,
                value(vec![
                    "/etc/systemd/system/aos-sandboxd.service.d/override.conf".to_owned(),
                ]),
            ),
            (2, OwnedValue::from(true)),
            (3, value(vec![0_u8; 16])),
            (3, value(vec![1_u8; 15])),
        ] {
            let (service, mut unit) = claims();
            unit[position] = replacement;
            assert!(
                decode_policy_claims(&service, &unit, FloorEndpointV1::ControllerStorageClient)
                    .is_err()
            );
        }
        let (service, unit) = claims();
        assert!(
            decode_policy_claims(
                &service[..3],
                &unit,
                FloorEndpointV1::ControllerStorageClient
            )
            .is_err()
        );
        assert!(
            decode_policy_claims(
                &service,
                &unit[..3],
                FloorEndpointV1::ControllerStorageClient
            )
            .is_err()
        );
        assert!(decode_policy_claims(&service, &unit, FloorEndpointV1::StorageBroker).is_err());
    }
}
