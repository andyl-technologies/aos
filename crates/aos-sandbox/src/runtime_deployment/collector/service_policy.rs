//! Original fixed collector unit, immutable fragment and kernel cgroup custody.
//!
//! The existing systemd reader binds the unique physical PID1 bus owner, unit,
//! main process and invocation around uncached readback. These point-in-time
//! observations do not freeze root administration or grant deployment effects.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::PidFd;
use aos_systemd::{OwnedValue, SystemdClient, Value};
use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest as _, Sha256};

use crate::{immutable_image::RetainedImmutableFileV1, systemd_property_data};

use super::{
    CAPABILITIES, CONTEXT, CONTROL_GROUP, InstalledCollectorStartupErrorV1 as Error,
    PID1_FD_NAME, PROFILE_FD_NAME, SOCKET_UNIT, UNIT,
};

const TIMEOUT: Duration = Duration::from_secs(5);
const PROFILE_PLACEHOLDER: &str = "@AOS_INSTALLED_FILTER_COLLECTOR_PROFILE@";
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

#[derive(Eq, PartialEq)]
struct ObservationV1 {
    fragment: PathBuf,
    invocation: [u8; 16],
}

pub(super) struct RetainedCollectorServicePolicyV1 {
    fragment: RetainedImmutableFileV1,
    cgroup: RetainedCgroupAnchor,
    original: ObservationV1,
}

impl RetainedCollectorServicePolicyV1 {
    pub(super) fn retain(
        profile: &Path,
        executable: &str,
        unit_digest: [u8; 32],
        process: &PidFd,
    ) -> Result<Self, Error> {
        let original = observe(profile, executable)?;
        let fragment = RetainedImmutableFileV1::observe_fragment(original.fragment.clone())
            .map_err(|_| Error::Service)?;
        require_unit(&fragment, profile, unit_digest)?;

        let root = CgroupV2Root::from_owned(
            open(
                "/sys/fs/cgroup",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::Service)?,
        )
        .map_err(|_| Error::Service)?;
        let relative = CONTROL_GROUP.strip_prefix('/').ok_or(Error::Service)?;
        let cgroup = root
            .resolve(Path::new(relative))
            .map_err(|_| Error::Service)?;
        cgroup.verify_exact_membership(process).map_err(|_| Error::Service)?;

        Ok(Self {
            fragment,
            cgroup,
            original,
        })
    }

    pub(super) fn recheck(
        &self,
        profile: &Path,
        executable: &str,
        unit_digest: [u8; 32],
        process: &PidFd,
    ) -> Result<(), Error> {
        self.fragment.revalidate().map_err(|_| Error::Service)?;
        if observe(profile, executable)? != self.original {
            return Err(Error::Service);
        }

        self.cgroup.verify_exact_membership(process).map_err(|_| Error::Service)?;
        require_unit(&self.fragment, profile, unit_digest)
    }

    pub(super) fn require_child(&self, parent: &PidFd, child: &PidFd) -> Result<(), Error> {
        let parent_info = self
            .cgroup
            .verify_exact_membership(parent)
            .map_err(|_| Error::Service)?;
        let child_info = self
            .cgroup
            .verify_exact_membership(child)
            .map_err(|_| Error::Service)?;
        if parent_info.pid() != std::process::id() || child_info.parent_pid() != parent_info.pid() {
            return Err(Error::Service);
        }

        self.cgroup.verify_exact_membership(parent).map_err(|_| Error::Service)?;
        Ok(())
    }
}

fn observe(profile: &Path, executable: &str) -> Result<ObservationV1, Error> {
    let profile = profile.to_str().ok_or(Error::Profile)?.to_owned();
    let executable = executable.to_owned();
    let observed = std::thread::Builder::new()
        .name("installed-collector-pid1-readback".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Error::Service)?;
            runtime.block_on(async {
                tokio::time::timeout(TIMEOUT, async {
                    let manager = SystemdClient::connect().await.map_err(|_| Error::Service)?;
                    let (service, unit) = manager
                        .observe_pid1_service_startup_properties(
                            UNIT,
                            std::process::id(),
                            SERVICE_PROPERTIES,
                            UNIT_PROPERTIES,
                        )
                        .await
                        .map_err(|_| Error::Service)?;
                    decode(&service, &unit, &profile, &executable)
                })
                .await
                .map_err(|_| Error::Service)?
            })
        })
        .map_err(|_| Error::Service)?
        .join()
        .map_err(|_| Error::Service)??;

    let fragment = std::fs::canonicalize(&observed.fragment).map_err(|_| Error::Service)?;
    if !fragment.starts_with("/nix/store") || fragment.file_name().is_none_or(|name| name != UNIT) {
        return Err(Error::Service);
    }

    Ok(ObservationV1 {
        fragment,
        invocation: observed.invocation,
    })
}

fn decode(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    profile: &str,
    executable: &str,
) -> Result<ObservationV1, Error> {
    let [exit, kill, timeout, cgroup, open_files, extra, maximum, stored, context,
        bounding, ambient, nnp, user, group, umask, start, pre, post] = service
    else {
        return Err(Error::Service);
    };
    let [fragment, drop_ins, transient, invocation, triggered_by] = unit else {
        return Err(Error::Service);
    };
    let Value::Structure(context) = &**context else {
        return Err(Error::Service);
    };
    let [Value::Bool(false), Value::Str(context)] = context.fields() else {
        return Err(Error::Service);
    };

    let string_is = |value: &OwnedValue, expected: &str| {
        <&str>::try_from(value).ok() == Some(expected)
    };
    if !string_is(exit, "cgroup")
        || !string_is(kill, "control-group")
        || u64::try_from(timeout).ok() != Some(u64::MAX)
        || !string_is(cgroup, CONTROL_GROUP)
        || !exact_open_files(open_files, extra, profile)
        || u32::try_from(maximum).ok() != Some(0)
        || u32::try_from(stored).ok() != Some(0)
        || context.as_str() != CONTEXT
        || u64::try_from(bounding).ok() != Some(CAPABILITIES)
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
        return Err(Error::Service);
    }

    let Value::Array(invocation) = &**invocation else {
        return Err(Error::Service);
    };
    if invocation.len() != 16 {
        return Err(Error::Service);
    }
    let mut identifier = [0; 16];
    for (slot, value) in identifier.iter_mut().zip(invocation.inner()) {
        *slot = u8::try_from(value).map_err(|_| Error::Service)?;
    }
    let fragment = <&str>::try_from(fragment).map_err(|_| Error::Service)?;
    if identifier == [0; 16]
        || fragment.len() > 1024
        || !fragment.starts_with('/')
        || !fragment.ends_with(&format!("/{UNIT}"))
    {
        return Err(Error::Service);
    }

    Ok(ObservationV1 {
        fragment: fragment.into(),
        invocation: identifier,
    })
}

fn exact_open_files(open_files: &OwnedValue, extra: &OwnedValue, profile: &str) -> bool {
    systemd_property_data::exact_readonly_open_file_pair(
        open_files,
        extra,
        [("/proc/1/exe", PID1_FD_NAME), (profile, PROFILE_FD_NAME)],
    )
}

fn exact_exec(value: &OwnedValue, executable: &str) -> bool {
    let Value::Array(commands) = &**value else {
        return false;
    };
    let [Value::Structure(command)] = commands.inner() else {
        return false;
    };
    let [Value::Str(path), Value::Array(argv), Value::Bool(false),
        Value::U64(_), Value::U64(_), Value::U64(_), Value::U64(_),
        Value::U32(pid), Value::I32(_), Value::I32(_)] = command.fields()
    else {
        return false;
    };
    path.as_str() == executable
        && *pid == std::process::id()
        && matches!(argv.inner(), [Value::Str(argument)] if argument.as_str() == executable)
}

fn empty_commands(value: &OwnedValue) -> bool {
    let Value::Array(commands) = &**value else {
        return false;
    };
    let schema = Value::from((
        "",
        Vec::<String>::new(),
        false,
        0_u64,
        0_u64,
        0_u64,
        0_u64,
        0_u32,
        0_i32,
        0_i32,
    ));
    commands.is_empty() && commands.element_signature() == schema.value_signature()
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
    profile: &Path,
    expected: [u8; 32],
) -> Result<(), Error> {
    let bytes = fragment.read_bounded().map_err(|_| Error::Service)?;
    let normalized = normalized_unit(&bytes, profile.to_str().ok_or(Error::Profile)?)?;
    if <[u8; 32]>::from(Sha256::digest(normalized)) != expected {
        return Err(Error::Service);
    }

    Ok(())
}

fn normalized_unit(bytes: &[u8], profile: &str) -> Result<Vec<u8>, Error> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(Error::Service);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Service)?;
    let actual = format!("OpenFile={profile}:{PROFILE_FD_NAME}:read-only\n");
    let replacement = format!("OpenFile={PROFILE_PLACEHOLDER}:{PROFILE_FD_NAME}:read-only\n");
    if text
        .split_inclusive('\n')
        .filter(|line| *line == actual)
        .count() != 1
    {
        return Err(Error::Service);
    }

    Ok(text
        .split_inclusive('\n')
        .map(|line| {
            if line == actual {
                replacement.as_str()
            } else {
                line
            }
        })
        .collect::<String>()
        .into_bytes())
}

#[cfg(test)]
mod tests;
