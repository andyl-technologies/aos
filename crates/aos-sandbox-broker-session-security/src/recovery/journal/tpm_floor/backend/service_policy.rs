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

use std::ffi::OsStr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::{PidFd, PidFdProcessIdentity};
use aos_systemd::{OwnedValue, SystemdClient, Value};
use rustix::fs::{Mode, OFlags, open};

use super::super::FloorErrorV1;
use super::super::format::FloorEndpointV1;
use super::image::{MeasuredFileV1, open_original_pid1_image};

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
    "SELinuxContext",
];
const UNIT_PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];

pub(crate) struct RetainedFloorServicePolicyV1 {
    endpoint: FloorEndpointV1,
    parent: PidFd,
    parent_identity: PidFdProcessIdentity,
    cgroup: RetainedCgroupAnchor,
    invocation: Vec<u8>,
    fragment: MeasuredFileV1,
    manager: MeasuredFileV1,
    launch_image: crate::production_startup::Pid1LaunchImageV1,
}

struct PolicyObservationV1 {
    fragment: PathBuf,
    control_group: String,
    invocation: Vec<u8>,
}

impl RetainedFloorServicePolicyV1 {
    pub(crate) fn open(
        endpoint: FloorEndpointV1,
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<Self, FloorErrorV1> {
        launch_image
            .require_endpoint(fixed_endpoint(endpoint))
            .map_err(|_| FloorErrorV1::Provisioning)?;
        let manager = open_original_pid1_image(launch_image)?;
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
        let observed = observe(endpoint, launch_image)?;
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
            launch_image: launch_image.clone(),
        };
        retained.revalidate()?;
        Ok(retained)
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), FloorErrorV1> {
        self.manager.revalidate()?;
        self.fragment.revalidate()?;
        let observed = observe(self.endpoint, &self.launch_image)?;
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
        self.manager.revalidate().map_err(Into::into)
    }

    pub(crate) fn require_child(&self, child: &PidFd) -> Result<(), FloorErrorV1> {
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
fn observe(
    endpoint: FloorEndpointV1,
    launch_image: &crate::production_startup::Pid1LaunchImageV1,
) -> Result<PolicyObservationV1, FloorErrorV1> {
    let expected_profile = launch_image
        .recheck_profile_delivery(fixed_endpoint(endpoint))
        .map_err(|_| FloorErrorV1::Provisioning)?
        .map(Path::to_path_buf);
    let observed = std::thread::Builder::new()
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
                    decode_policy(&service, &unit, endpoint, expected_profile.as_deref())
                })
                .await
                .map_err(|_| FloorErrorV1::Unavailable)?
            })
        })
        .map_err(|_| FloorErrorV1::Unavailable)?
        .join()
        .map_err(|_| FloorErrorV1::Unavailable)?;
    launch_image
        .recheck_profile_delivery(fixed_endpoint(endpoint))
        .map_err(|_| FloorErrorV1::Provisioning)?;
    observed
}

fn decode_policy(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    endpoint: FloorEndpointV1,
    expected_profile: Option<&Path>,
) -> Result<PolicyObservationV1, FloorErrorV1> {
    let mut observed = decode_policy_claims(service, unit, endpoint, expected_profile)?;
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
    expected_profile: Option<&Path>,
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
        selinux_context,
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
        || !has_exact_launch_fd_properties(open_files, extra_fds, endpoint, expected_profile)
        || u32::try_from(store_maximum).ok() != Some(0)
        || u32::try_from(stored_fds).ok() != Some(0)
        || !has_exact_owner_context(selinux_context, endpoint)
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

fn has_exact_owner_context(value: &OwnedValue, endpoint: FloorEndpointV1) -> bool {
    let Value::Structure(value) = &**value else {
        return false;
    };
    let [ignore_failure, context] = value.fields() else {
        return false;
    };
    matches!(ignore_failure, Value::Bool(false))
        && matches!(context, Value::Str(context) if context.as_str() == super::confinement::owner_context(endpoint))
}

/// Checks only the fixed launch roles named by retained startup custody.
fn has_exact_launch_fd_properties(
    open_files: &OwnedValue,
    extra_fds: &OwnedValue,
    endpoint: FloorEndpointV1,
    expected_profile: Option<&Path>,
) -> bool {
    let Value::Array(open_files) = &**open_files else {
        return false;
    };
    let Value::Array(extra_fds) = &**extra_fds else {
        return false;
    };

    if (endpoint == FloorEndpointV1::StorageBroker && expected_profile.is_some())
        || open_files.len() != 1 + usize::from(expected_profile.is_some())
        || !extra_fds.is_empty()
        || extra_fds.element_signature() != Value::from("").value_signature()
    {
        return false;
    }

    // The installed pinned 261.2 encoding still requires qualification.
    // Flags must be the single public read-only bit, never other open options.
    let mut found = [false; 2];
    for entry in open_files.inner() {
        let Value::Structure(entry) = entry else {
            return false;
        };
        let [Value::Str(path), Value::Str(name), Value::U64(1)] = entry.fields() else {
            return false;
        };
        let index = match (path.as_str(), name.as_str()) {
            ("/proc/1/exe", aos_sandbox_storage::activation::PID1_LAUNCH_IMAGE_FD_NAME) => 0,
            (path, "aos-normal-root-client-profile")
                if expected_profile
                    .is_some_and(|expected| expected.as_os_str() == OsStr::new(path)) =>
            {
                1
            }
            _ => return false,
        };
        if found[index] {
            return false;
        }
        found[index] = true;
    }
    found == [true, expected_profile.is_some()]
}

const fn fixed_endpoint(endpoint: FloorEndpointV1) -> crate::ProtectedBrokerSessionFixedEndpointV1 {
    match endpoint {
        FloorEndpointV1::ControllerStorageClient => {
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
        }
        FloorEndpointV1::StorageBroker => {
            crate::ProtectedBrokerSessionFixedEndpointV1::StorageBroker
        }
    }
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

    use super::{FloorEndpointV1, OwnedValue, Path, decode_policy_claims};

    const PROFILE_PATH: &str = "/nix/store/selected-normal-root-profile/profile.json";
    const PROFILE_NAME: &str = "aos-normal-root-client-profile";
    const PID1_ENTRY: (&str, &str, u64) = (
        "/proc/1/exe",
        aos_sandbox_storage::activation::PID1_LAUNCH_IMAGE_FD_NAME,
        1,
    );
    const PROFILE_ENTRY: (&str, &str, u64) = (PROFILE_PATH, PROFILE_NAME, 1);

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
            value((false, "system_u:system_r:aos_sandbox_controller_t")),
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
            decode_policy_claims(
                &service,
                &unit,
                FloorEndpointV1::ControllerStorageClient,
                None
            )
            .is_ok()
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
            (
                8,
                value((true, "system_u:system_r:aos_sandbox_controller_t")),
            ),
            (8, value((false, "system_u:system_r:init_t"))),
            (8, value((false, "system_u:system_r:aos_sandbox_storage_t"))),
            (8, value("system_u:system_r:aos_sandbox_controller_t")),
        ] {
            let (mut service, unit) = claims();
            service[position] = replacement;
            assert!(
                decode_policy_claims(
                    &service,
                    &unit,
                    FloorEndpointV1::ControllerStorageClient,
                    None
                )
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
                decode_policy_claims(
                    &service,
                    &unit,
                    FloorEndpointV1::ControllerStorageClient,
                    None
                )
                .is_err()
            );
        }
        let (service, unit) = claims();
        assert!(
            decode_policy_claims(
                &service[..3],
                &unit,
                FloorEndpointV1::ControllerStorageClient,
                None,
            )
            .is_err()
        );
        assert!(
            decode_policy_claims(
                &service,
                &unit[..3],
                FloorEndpointV1::ControllerStorageClient,
                None,
            )
            .is_err()
        );
        assert!(
            decode_policy_claims(&service, &unit, FloorEndpointV1::StorageBroker, None).is_err()
        );
    }

    #[test]
    fn controller_profile_delivery_requires_exact_optional_roles() {
        let expected_profile = Some(Path::new(PROFILE_PATH));
        for entries in [
            vec![PID1_ENTRY, PROFILE_ENTRY],
            vec![PROFILE_ENTRY, PID1_ENTRY],
        ] {
            let (mut service, unit) = claims();
            service[4] = value(entries);

            assert!(
                decode_policy_claims(
                    &service,
                    &unit,
                    FloorEndpointV1::ControllerStorageClient,
                    expected_profile,
                )
                .is_ok()
            );
            assert!(
                decode_policy_claims(
                    &service,
                    &unit,
                    FloorEndpointV1::ControllerStorageClient,
                    None,
                )
                .is_err()
            );
        }

        for (case, entries) in [
            ("missing image", vec![PROFILE_ENTRY]),
            ("missing profile", vec![PID1_ENTRY]),
            ("missing both", vec![]),
            ("duplicate image", vec![PID1_ENTRY, PID1_ENTRY]),
            ("duplicate profile", vec![PROFILE_ENTRY, PROFILE_ENTRY]),
            (
                "foreign image path",
                vec![("/nix/store/other/systemd", PID1_ENTRY.1, 1), PROFILE_ENTRY],
            ),
            (
                "image duplicate separator alias",
                vec![("/proc//1/exe", PID1_ENTRY.1, 1), PROFILE_ENTRY],
            ),
            (
                "image dot alias",
                vec![("/proc/1/./exe", PID1_ENTRY.1, 1), PROFILE_ENTRY],
            ),
            (
                "foreign image role",
                vec![(PID1_ENTRY.0, "other-image", 1), PROFILE_ENTRY],
            ),
            (
                "image open flags",
                vec![(PID1_ENTRY.0, PID1_ENTRY.1, 9), PROFILE_ENTRY],
            ),
            (
                "foreign store profile",
                vec![
                    PID1_ENTRY,
                    ("/nix/store/other/profile.json", PROFILE_NAME, 1),
                ],
            ),
            (
                "profile duplicate separator alias",
                vec![
                    PID1_ENTRY,
                    (
                        "/nix/store//selected-normal-root-profile/profile.json",
                        PROFILE_NAME,
                        1,
                    ),
                ],
            ),
            (
                "profile dot alias",
                vec![
                    PID1_ENTRY,
                    (
                        "/nix/store/selected-normal-root-profile/./profile.json",
                        PROFILE_NAME,
                        1,
                    ),
                ],
            ),
            (
                "foreign profile role",
                vec![PID1_ENTRY, (PROFILE_PATH, "other-profile", 1)],
            ),
            (
                "profile open flags",
                vec![PID1_ENTRY, (PROFILE_PATH, PROFILE_NAME, 9)],
            ),
            ("extra image", vec![PID1_ENTRY, PROFILE_ENTRY, PID1_ENTRY]),
            (
                "extra profile",
                vec![PID1_ENTRY, PROFILE_ENTRY, PROFILE_ENTRY],
            ),
            (
                "extra role",
                vec![PID1_ENTRY, PROFILE_ENTRY, ("/other", "other", 1)],
            ),
        ] {
            let (mut service, unit) = claims();
            service[4] = value(entries);

            assert!(
                decode_policy_claims(
                    &service,
                    &unit,
                    FloorEndpointV1::ControllerStorageClient,
                    expected_profile,
                )
                .is_err(),
                "{case}",
            );
        }

        let (mut service, unit) = claims();
        service[4] = value(vec![
            (PID1_ENTRY.0, PID1_ENTRY.1, 1_u32),
            (PROFILE_PATH, PROFILE_NAME, 1_u32),
        ]);
        assert!(
            decode_policy_claims(
                &service,
                &unit,
                FloorEndpointV1::ControllerStorageClient,
                expected_profile,
            )
            .is_err()
        );

        for (position, replacement) in [
            (5, value(vec!["unaccounted-fd"])),
            (5, value(Vec::<u8>::new())),
            (6, OwnedValue::from(1_u32)),
            (7, OwnedValue::from(1_u32)),
        ] {
            let (mut service, unit) = claims();
            service[4] = value(vec![PID1_ENTRY, PROFILE_ENTRY]);
            service[position] = replacement;

            assert!(
                decode_policy_claims(
                    &service,
                    &unit,
                    FloorEndpointV1::ControllerStorageClient,
                    expected_profile,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn storage_delivery_never_accepts_controller_profile() {
        let (mut service, mut unit) = claims();
        service[3] = value("/aos.slice/aos-control.slice/aos-storaged.service");
        service[8] = value((false, "system_u:system_r:aos_sandbox_storage_t"));
        unit[0] = value("/nix/store/fixture/aos-storaged.service");

        assert!(
            decode_policy_claims(&service, &unit, FloorEndpointV1::StorageBroker, None).is_ok()
        );
        assert!(
            decode_policy_claims(
                &service,
                &unit,
                FloorEndpointV1::StorageBroker,
                Some(Path::new(PROFILE_PATH)),
            )
            .is_err()
        );

        service[4] = value(vec![PID1_ENTRY, PROFILE_ENTRY]);
        assert!(
            decode_policy_claims(&service, &unit, FloorEndpointV1::StorageBroker, None).is_err()
        );
    }
}
