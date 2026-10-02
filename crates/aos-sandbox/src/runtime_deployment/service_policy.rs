//! Rechecks the deployment publisher's fixed PID1 policy and original cgroup.
//!
//! Effective properties are observations, not an administrative policy freeze.
//! The exact immutable fragment is committed by the original image profile;
//! only its self-referencing profile OpenFile path is normalized. Cgroup exit
//! ordering retains the existing two-lock TPM helper crash contract.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_linux::cgroup::{CgroupPopulationMonitor, CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::PidFd;
use aos_systemd::{OwnedValue, SystemdClient, Value};
use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest as _, Sha256};

use crate::{immutable_image::RetainedImmutableFileV1, systemd_property_data};

use super::{
    CONTROL_GROUP, OWNER_CONTEXT, PID1_FD_NAME, PROFILE_FD_NAME, SOCKET_UNIT, UNIT,
    RuntimeDeploymentStartupErrorV1,
};

const PROPERTY_TIMEOUT: Duration = Duration::from_secs(5);
const PROFILE_PLACEHOLDER: &str = "@AOS_RUNTIME_DEPLOYMENT_PROFILE@";
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
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "User",
    "Group",
    "UMask",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
];
const UNIT_PROPERTIES: &[&str] = &[
    "FragmentPath",
    "DropInPaths",
    "Transient",
    "InvocationID",
    "TriggeredBy",
];

#[derive(Debug, Eq, PartialEq)]
struct PolicyObservationV1 {
    fragment: PathBuf,
    invocation: [u8; 16],
}

pub(super) struct RetainedDeploymentServicePolicyV1 {
    fragment: RetainedImmutableFileV1,
    cgroup: RetainedCgroupAnchor,
    observation: PolicyObservationV1,
}

impl RetainedDeploymentServicePolicyV1 {
    pub(super) fn retain(
        profile_path: &Path,
        executable: &str,
        unit_digest: [u8; 32],
        process: &PidFd,
    ) -> Result<Self, RuntimeDeploymentStartupErrorV1> {
        let observation = observe(profile_path, executable)?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observation.fragment.clone())
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        require_unit(&fragment, profile_path, unit_digest)?;

        let root = CgroupV2Root::from_owned(
            open(
                "/sys/fs/cgroup",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?,
        )
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        let cgroup = root
            .resolve(Path::new(
                CONTROL_GROUP
                    .strip_prefix('/')
                    .ok_or(RuntimeDeploymentStartupErrorV1::Service)?,
            ))
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        cgroup
            .verify_exact_membership(process)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;

        Ok(Self {
            fragment,
            cgroup,
            observation,
        })
    }

    pub(super) fn recheck(
        &self,
        profile_path: &Path,
        executable: &str,
        unit_digest: [u8; 32],
        process: &PidFd,
    ) -> Result<(), RuntimeDeploymentStartupErrorV1> {
        self.fragment
            .revalidate()
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        if observe(profile_path, executable)? != self.observation {
            return Err(RuntimeDeploymentStartupErrorV1::Service);
        }
        self.cgroup
            .verify_exact_membership(process)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        require_unit(&self.fragment, profile_path, unit_digest)
    }

    pub(super) fn require_child(
        &self,
        parent: &PidFd,
        child: &PidFd,
    ) -> Result<(), RuntimeDeploymentStartupErrorV1> {
        let parent_info = self
            .cgroup
            .verify_exact_membership(parent)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        let child_info = self
            .cgroup
            .verify_exact_membership(child)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        if parent_info.pid() != std::process::id() || child_info.parent_pid() != parent_info.pid() {
            return Err(RuntimeDeploymentStartupErrorV1::Service);
        }
        self.cgroup
            .verify_exact_membership(parent)
            .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
        Ok(())
    }

    pub(super) const fn invocation_id(&self) -> [u8; 16] {
        self.observation.invocation
    }

    // Only a held physical-invocation claim requests this original monitor.
    // The existing kernel reader owns identity, bounds and population parsing.
    pub(super) fn retain_host_invocation_population(
        &self,
    ) -> aos_sandbox_linux::Result<CgroupPopulationMonitor> {
        self.cgroup.population_monitor()
    }
}

fn observe(
    profile_path: &Path,
    executable: &str,
) -> Result<PolicyObservationV1, RuntimeDeploymentStartupErrorV1> {
    let profile_path = profile_path
        .to_str()
        .ok_or(RuntimeDeploymentStartupErrorV1::Profile)?
        .to_owned();
    let executable = executable.to_owned();

    // The shared systemd reader binds one unique PID1 bus owner and compares
    // unit ID, invocation, main PID and state around uncached property reads.
    // A separate bounded runtime also works when the publisher already serves
    // on Tokio; it supplies no generic unit or property selection API.
    let observed = std::thread::Builder::new()
        .name("deployment-publisher-pid1-readback".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
            runtime.block_on(async {
                tokio::time::timeout(PROPERTY_TIMEOUT, async {
                    let manager = SystemdClient::connect()
                        .await
                        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
                    let (service, unit) = manager
                        .observe_pid1_service_startup_properties(
                            UNIT,
                            std::process::id(),
                            SERVICE_PROPERTIES,
                            UNIT_PROPERTIES,
                        )
                        .await
                        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
                    decode(&service, &unit, &profile_path, &executable)
                })
                .await
                .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?
            })
        })
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?
        .join()
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
    let mut observed = observed?;
    observed.fragment = std::fs::canonicalize(&observed.fragment)
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
    if !observed.fragment.starts_with("/nix/store")
        || observed.fragment.file_name().is_none_or(|name| name != UNIT)
    {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    }
    Ok(observed)
}

fn decode(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &str,
    executable: &str,
) -> Result<PolicyObservationV1, RuntimeDeploymentStartupErrorV1> {
    let [
        exit_type,
        kill_mode,
        timeout,
        cgroup,
        open_files,
        extras,
        maximum,
        stored,
        context,
        bounding,
        ambient,
        nnp,
        user,
        group,
        umask,
        start,
        pre,
        post,
    ] = service
    else {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    };
    let [fragment, drop_ins, transient, invocation, triggered_by] = unit else {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    };
    let Value::Structure(context) = &**context else {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    };
    let [Value::Bool(false), Value::Str(context)] = context.fields() else {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    };
    let string_is = |value: &OwnedValue, expected: &str| <&str>::try_from(value).ok() == Some(expected);
    if !string_is(exit_type, "cgroup")
        || !string_is(kill_mode, "control-group")
        || u64::try_from(timeout).ok() != Some(u64::MAX)
        || !string_is(cgroup, CONTROL_GROUP)
        || !exact_open_files(open_files, extras, profile_path)
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || context.as_str() != OWNER_CONTEXT
        || u64::try_from(bounding).ok() != Some(0)
        || u64::try_from(ambient).ok() != Some(0)
        || bool::try_from(nnp).ok() != Some(true)
        || !string_is(user, "root")
        || !string_is(group, "root")
        || u32::try_from(umask).ok() != Some(0o077)
        || !exact_exec(start, executable)
        || !empty_commands(pre)
        || !empty_commands(post)
        || bool::try_from(transient).ok() != Some(false)
        || !exact_strings(drop_ins, &[])
        || !exact_strings(triggered_by, &[SOCKET_UNIT])
    {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    }

    let Value::Array(invocation) = &**invocation else {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    };
    if invocation.len() != 16 {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    }
    let mut id = [0; 16];
    for (slot, value) in id.iter_mut().zip(invocation.inner()) {
        *slot = u8::try_from(value).map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
    }
    if id == [0; 16] {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    }

    let fragment = <&str>::try_from(fragment)
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
    if fragment.len() > 1024
        || !fragment.starts_with('/')
        || !fragment.ends_with(&format!("/{UNIT}"))
    {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    }
    Ok(PolicyObservationV1 {
        fragment: fragment.into(),
        invocation: id,
    })
}

fn exact_open_files(open_files: &OwnedValue, extras: &OwnedValue, profile_path: &str) -> bool {
    systemd_property_data::exact_readonly_open_file_pair(
        open_files,
        extras,
        [("/proc/1/exe", PID1_FD_NAME), (profile_path, PROFILE_FD_NAME)],
    )
}

fn exact_exec(value: &OwnedValue, executable: &str) -> bool {
    let Value::Array(commands) = &**value else {
        return false;
    };
    let [Value::Structure(command)] = commands.inner() else {
        return false;
    };
    let [
        Value::Str(path),
        Value::Array(argv),
        Value::Bool(false),
        Value::U64(_),
        Value::U64(_),
        Value::U64(_),
        Value::U64(_),
        Value::U32(pid),
        Value::I32(_),
        Value::I32(_),
    ] = command.fields()
    else {
        return false;
    };
    path.as_str() == executable
        && *pid == std::process::id()
        && matches!(argv.inner(), [Value::Str(path)] if path.as_str() == executable)
}

fn empty_commands(value: &OwnedValue) -> bool {
    let Value::Array(commands) = &**value else {
        return false;
    };
    let shape = Value::from((
        "",
        Vec::<String>::new(),
        false,
        0_u64, 0_u64, 0_u64, 0_u64,
        0_u32,
        0_i32, 0_i32,
    ));
    commands.is_empty() && commands.element_signature() == shape.value_signature()
}

fn exact_strings(value: &OwnedValue, expected: &[&str]) -> bool {
    let Value::Array(values) = &**value else {
        return false;
    };
    values.element_signature() == Value::from("").value_signature()
        && values.len() == expected.len()
        && values.inner().iter().zip(expected).all(|(value, expected)| {
            matches!(value, Value::Str(value) if value.as_str() == *expected)
        })
}

fn require_unit(
    fragment: &RetainedImmutableFileV1,
    profile_path: &Path,
    expected: [u8; 32],
) -> Result<(), RuntimeDeploymentStartupErrorV1> {
    let bytes = fragment
        .read_bounded()
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
    let normalized = normalized_unit(
        &bytes,
        profile_path
            .to_str()
            .ok_or(RuntimeDeploymentStartupErrorV1::Profile)?,
    )?;
    if <[u8; 32]>::from(Sha256::digest(normalized)) != expected {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    }
    Ok(())
}

fn normalized_unit(
    bytes: &[u8],
    profile_path: &str,
) -> Result<Vec<u8>, RuntimeDeploymentStartupErrorV1> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| RuntimeDeploymentStartupErrorV1::Service)?;
    let actual = format!("OpenFile={profile_path}:{PROFILE_FD_NAME}:read-only\n");
    let placeholder = format!("OpenFile={PROFILE_PLACEHOLDER}:{PROFILE_FD_NAME}:read-only\n");
    if text
        .split_inclusive('\n')
        .filter(|line| *line == actual)
        .count()
        != 1
    {
        return Err(RuntimeDeploymentStartupErrorV1::Service);
    }
    Ok(text
        .split_inclusive('\n')
        .map(|line| {
            if line == actual {
                placeholder.as_str()
            } else {
                line
            }
        })
        .collect::<String>()
        .into_bytes())
}

#[cfg(test)]
mod tests {
    use super::{PROFILE_FD_NAME, decode, exact_open_files, normalized_unit};
    use aos_systemd::{OwnedValue, Value};

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).expect("inert property value")
    }

    type ExecCommand = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

    fn properties(profile: &str, executable: &str) -> (Vec<OwnedValue>, Vec<OwnedValue>) {
        let service = vec![
            value("cgroup"),
            value("control-group"),
            value(u64::MAX),
            value(super::CONTROL_GROUP),
            value(vec![
                (
                    "/proc/1/exe".to_owned(),
                    super::PID1_FD_NAME.to_owned(),
                    1_u64,
                ),
                (profile.to_owned(), PROFILE_FD_NAME.to_owned(), 1_u64),
            ]),
            value(Vec::<String>::new()),
            value(0_u32),
            value(0_u32),
            value((false, super::OWNER_CONTEXT)),
            value(0_u64),
            value(0_u64),
            value(true),
            value("root"),
            value("root"),
            value(0o077_u32),
            value(vec![(
                executable.to_owned(),
                vec![executable.to_owned()],
                false,
                0_u64, 0_u64, 0_u64, 0_u64,
                std::process::id(),
                0_i32, 0_i32,
            )]),
            value(Vec::<ExecCommand>::new()),
            value(Vec::<ExecCommand>::new()),
        ];
        let unit = vec![
            value(format!(
                "/nix/store/00000000000000000000000000000000-unit/{}",
                super::UNIT,
            )),
            value(Vec::<String>::new()),
            value(false),
            value(vec![1_u8; 16]),
            value(vec![super::SOCKET_UNIT.to_owned()]),
        ];
        (service, unit)
    }

    #[test]
    fn inert_property_claims_do_not_omit_crash_confinement_or_original_role_checks() {
        let profile = "/nix/store/00000000000000000000000000000000-profile/profile.json";
        let executable = "/nix/store/00000000000000000000000000000000-publisher/bin/aos-sandbox-runtime-publisher";
        let (service, unit) = properties(profile, executable);
        assert!(decode(&service, &unit, profile, executable).is_ok());

        for (slot, substitute) in [
            (0, value("main")),
            (1, value("process")),
            (2, value(30_000_000_u64)),
            (3, value("/system.slice/aos-sandbox-runtime-publisher.service")),
            (8, value(super::OWNER_CONTEXT)),
            (8, value((true, super::OWNER_CONTEXT))),
            (9, value(1_u64)),
            (10, value(1_u64)),
            (11, value(false)),
            (14, value(0_u32)),
            (16, value(Vec::<String>::new())),
        ] {
            let (mut service, unit) = properties(profile, executable);
            service[slot] = substitute;
            assert!(
                decode(&service, &unit, profile, executable).is_err(),
                "slot {slot}",
            );
        }
        let (service, mut unit) = properties(profile, executable);
        unit[4] = value(vec!["foreign.socket".to_owned()]);
        assert!(decode(&service, &unit, profile, executable).is_err());
    }

    #[test]
    fn deployment_profile_normalizes_only_its_one_exact_self_reference() {
        let profile = "/nix/store/00000000000000000000000000000000-profile/profile.json";
        let unit = format!(
            "[Service]\nOpenFile={profile}:{PROFILE_FD_NAME}:read-only\nCapabilityBoundingSet=\n"
        );
        let normalized = normalized_unit(unit.as_bytes(), profile).expect("closed unit");
        assert!(String::from_utf8(normalized).expect("UTF8").contains(
            "OpenFile=@AOS_RUNTIME_DEPLOYMENT_PROFILE@:aos-runtime-deployment-startup-profile:read-only\n"
        ));

        for invalid in [unit.repeat(2), unit.replace("read-only", "graceful")] {
            assert!(normalized_unit(invalid.as_bytes(), profile).is_err());
        }
    }

    #[test]
    fn original_open_files_refuse_wrong_roles_flags_and_duplicate_slots() {
        let profile = "/nix/store/00000000000000000000000000000000-profile/profile.json";
        let extras = value(Vec::<String>::new());
        let entries = vec![
            (
                "/proc/1/exe".to_owned(),
                super::super::PID1_FD_NAME.to_owned(),
                1_u64,
            ),
            (profile.to_owned(), PROFILE_FD_NAME.to_owned(), 1_u64),
        ];
        assert!(exact_open_files(&value(entries.clone()), &extras, profile));

        let mut duplicate = entries.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(!exact_open_files(&value(duplicate), &extras, profile));
        let mut wrong_flag = entries;
        wrong_flag[0].2 = 3;
        assert!(!exact_open_files(&value(wrong_flag), &extras, profile));
    }
}
