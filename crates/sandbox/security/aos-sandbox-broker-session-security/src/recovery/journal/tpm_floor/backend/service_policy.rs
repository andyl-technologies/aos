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
use aos_systemd_client::{OwnedValue, SystemdClient, Value};
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
    anchors: FloorServiceAnchorsV1,
    parent_identity: PidFdProcessIdentity,
    invocation: Vec<u8>,
    launch_image: crate::production_startup::Pid1LaunchImageV1,
}

// Ordinary and incomplete selected captures keep their original owned pins.
// Only a complete selected native comparison replaces those duplicates with
// the exact profile Arc already held by this service's launch image.
enum FloorServiceAnchorsV1 {
    Owned {
        parent: PidFd,
        cgroup: RetainedCgroupAnchor,
        fragment: MeasuredFileV1,
        manager: MeasuredFileV1,
    },
    Shared(aos_sandbox_controller_domain::normal_root::ControllerSharedStartupProfileV1),
}

struct FloorServiceAnchorBorrowV1<'held> {
    parent: &'held PidFd,
    cgroup: &'held RetainedCgroupAnchor,
    fragment: &'held MeasuredFileV1,
    manager: &'held MeasuredFileV1,
}

struct PolicyObservationV1 {
    fragment: PathBuf,
    control_group: String,
    invocation: Vec<u8>,
}

// One native opening schedule; dispositions change only where actual
// returned owners/results reside. Ordinary retains its exact lexical values.
macro_rules! service_open_step {
    (Ordinary, endpoint $original:ident, $endpoint:ident, $image:ident) => {
        $image.require_endpoint(fixed_endpoint($endpoint))
            .map_err(|_| FloorErrorV1::Provisioning)?;
    };
    (Retained, endpoint $original:ident, $endpoint:ident, $image:ident) => {
        $original.capture_endpoint($image)?;
    };
    (Ordinary, manager $original:ident, $manager:ident, $image:ident) => {
        let $manager = open_original_pid1_image($image)?;
    };
    (Retained, manager $original:ident, $manager:ident, $image:ident) => {
        $original.capture_manager($image)?;
    };
    (Ordinary, parent $original:ident, $parent:ident) => {
        let $parent = PidFd::open(NonZeroU32::new(std::process::id())
            .ok_or(FloorErrorV1::Unavailable)?)
            .map_err(|_| FloorErrorV1::Unavailable)?;
    };
    (Retained, parent $original:ident, $parent:ident) => {
        $original.capture_parent()?;
    };
    (Ordinary, info $original:ident, $parent:ident, $info:ident) => {
        let $info = $parent.info().map_err(|_| FloorErrorV1::Unavailable)?;
        require_original_manager_parent($info)?;
    };
    (Retained, info $original:ident, $parent:ident, $info:ident) => {
        $original.capture_info()?;
    };
    (Ordinary, identity $original:ident, $parent:ident, $identity:ident) => {
        let $identity = $parent.process_identity().map_err(|_| FloorErrorV1::Unavailable)?;
    };
    (Retained, identity $original:ident, $parent:ident, $identity:ident) => {
        $original.capture_identity()?;
    };
    (Ordinary, observed $original:ident, $observed:ident, $endpoint:ident, $image:ident) => {
        let $observed = observe($endpoint, $image)?;
    };
    (Retained, observed $original:ident, $observed:ident, $endpoint:ident, $image:ident) => {
        $original.capture_policy($image)?;
    };
    (Ordinary, cgroup $original:ident, $observed:ident, $root:ident, $relative:ident, $cgroup:ident) => {
        let $root = CgroupV2Root::from_owned(open(
            "/sys/fs/cgroup",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ).map_err(|_| FloorErrorV1::Unavailable)?)
            .map_err(|_| FloorErrorV1::Unavailable)?;
        let $relative = $observed.control_group.strip_prefix('/')
            .ok_or(FloorErrorV1::Provisioning)?;
        let $cgroup = $root.resolve(Path::new($relative))
            .map_err(|_| FloorErrorV1::Unavailable)?;
    };
    (Retained, cgroup $original:ident, $observed:ident, $root:ident, $relative:ident, $cgroup:ident) => {
        $original.capture_cgroup()?;
    };
    (Ordinary, membership $original:ident, $cgroup:ident, $parent:ident) => {
        $cgroup.verify_exact_membership(&$parent).map_err(|_| FloorErrorV1::Unavailable)?;
    };
    (Retained, membership $original:ident, $cgroup:ident, $parent:ident) => {
        $original.capture_membership()?;
    };
    (Ordinary, complete $original:ident, $endpoint:ident, $parent:ident, $identity:ident,
        $cgroup:ident, $observed:ident, $manager:ident, $image:ident) => {{
        let mut retained = Self {
            endpoint: $endpoint, parent_identity: $identity,
            anchors: FloorServiceAnchorsV1::Owned {
                parent: $parent, cgroup: $cgroup,
                fragment: MeasuredFileV1::observe_fragment($observed.fragment)?, manager: $manager,
            },
            invocation: $observed.invocation, launch_image: $image.clone(),
        };
        retained.revalidate()?;
        Ok(retained)
    }};
    (Retained, complete $original:ident, $endpoint:ident, $parent:ident, $identity:ident,
        $cgroup:ident, $observed:ident, $manager:ident, $image:ident) => {{
        $original.capture_fragment()?;
        $original.assemble($image)?;
        $original.capture_initial_currentness()?;
        $original.take_constructed_service()
    }};
}

macro_rules! service_open_recipe {
    ($mode:ident, $original:ident, $endpoint:ident, $image:ident) => {{
        service_open_step!($mode, endpoint $original, $endpoint, $image);
        service_open_step!($mode, manager $original, manager, $image);
        service_open_step!($mode, parent $original, parent);
        service_open_step!($mode, info $original, parent, info);
        service_open_step!($mode, identity $original, parent, parent_identity);
        service_open_step!($mode, observed $original, observed, $endpoint, $image);
        service_open_step!($mode, cgroup $original, observed, root, relative, cgroup);
        service_open_step!($mode, membership $original, cgroup, parent);
        service_open_step!($mode, complete $original, $endpoint, parent, parent_identity,
            cgroup, observed, manager, $image)
    }};
}

fn require_original_manager_parent(info: aos_sandbox_linux::pidfd::PidFdInfo)
    -> Result<(), FloorErrorV1>
{
    if info.parent_pid() != 1 || info.pid() != std::process::id() {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

impl RetainedFloorServicePolicyV1 {
    fn anchors(&self) -> Result<FloorServiceAnchorBorrowV1<'_>, FloorErrorV1> {
        match &self.anchors {
            FloorServiceAnchorsV1::Owned { parent, cgroup, fragment, manager } => {
                Ok(FloorServiceAnchorBorrowV1 { parent, cgroup, fragment, manager })
            }
            FloorServiceAnchorsV1::Shared(profile) => {
                let anchors = profile.floor_service_anchors_v1().ok_or(FloorErrorV1::Provisioning)?;
                Ok(FloorServiceAnchorBorrowV1 {
                    parent: anchors.process(), cgroup: anchors.cgroup(),
                    fragment: anchors.fragment(), manager: anchors.manager(),
                })
            }
        }
    }

    pub(crate) fn open(
        endpoint: FloorEndpointV1,
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
    ) -> Result<Self, FloorErrorV1> {
        Self::open_observed(endpoint, launch_image, None)
    }

    fn open_observed(
        endpoint: FloorEndpointV1,
        launch_image: &crate::production_startup::Pid1LaunchImageV1,
        original: Option<&mut FloorServiceAcquisitionOriginalV1>,
    ) -> Result<Self, FloorErrorV1> {
        match original {
            None => service_open_recipe!(Ordinary, original, endpoint, launch_image),
            Some(original) => service_open_recipe!(Retained, original, endpoint, launch_image),
        }
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), FloorErrorV1> {
        self.revalidate_observed(&mut None)
    }

    fn revalidate_observed(
        &mut self,
        original: &mut Option<&mut FloorServiceCurrentnessOriginalV1>,
    ) -> Result<(), FloorErrorV1> {
        let anchors = self.anchors()?;
        currentness::image(anchors.manager, original.as_deref_mut()
            .map(|original| (&mut original.manager[0], &mut original.manager_results[0])))?;
        currentness::image(anchors.fragment, original.as_deref_mut()
            .map(|original| (&mut original.fragment[0], &mut original.fragment_results[0])))?;

        // The ordinary observation keeps its old lexical owner through the
        // remaining native checks; selected DATA stays on its resident sink.
        let local_observed = match original.as_deref_mut() {
            None => Some(observe(self.endpoint, &self.launch_image)?),
            Some(original) => {
                original.policy_result = Some(original.policy.observe_with_deadline(
                    self.endpoint, &self.launch_image, original.deadline,
                ));
                match original.policy_result {
                    Some(Ok(())) => {}
                    Some(Err(cause)) => return Err(cause),
                    None => return Err(FloorErrorV1::Unavailable),
                }
                original.observed = original.policy.take_completed_once();
                None
            }
        };
        let observed = match original.as_deref() {
            Some(original) => original.observed.as_ref(),
            None => local_observed.as_ref(),
        }.ok_or(FloorErrorV1::Unavailable)?;
        let changed_names = observed.fragment != anchors.fragment.path()
            || observed.invocation != self.invocation;
        let binding = if changed_names
            || currentness::identity(anchors.parent, original.as_deref_mut())?
                != self.parent_identity
            || currentness::info(anchors.parent, original.as_deref_mut())?.parent_pid() != 1
        {
            Err(FloorErrorV1::Provisioning)
        } else {
            Ok(())
        };
        if let Some(original) = original.as_deref_mut() {
            original.binding = Some(binding);
        }
        binding?;
        currentness::membership(anchors.cgroup, anchors.parent, original.as_deref_mut()
            .map(|original| (&mut original.membership, &mut original.membership_result)))?;
        currentness::image(anchors.fragment, original.as_deref_mut()
            .map(|original| (&mut original.fragment[1], &mut original.fragment_results[1])))?;
        currentness::image(anchors.manager, original.as_deref_mut()
            .map(|original| (&mut original.manager[1], &mut original.manager_results[1])))
    }

    pub(crate) fn require_child(&self, child: &PidFd) -> Result<(), FloorErrorV1> {
        self.require_child_observed(child, &mut None)
    }

    fn require_child_observed(
        &self,
        child: &PidFd,
        original: &mut Option<&mut FloorServiceCurrentnessOriginalV1>,
    ) -> Result<(), FloorErrorV1> {
        let anchors = self.anchors()?;
        currentness::membership(anchors.cgroup, anchors.parent, original.as_deref_mut()
            .map(|original| (&mut original.child_membership[0], &mut original.child_results[0])))?;
        currentness::membership(anchors.cgroup, child, original.as_deref_mut()
            .map(|original| (&mut original.child_membership[1], &mut original.child_results[1])))
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
// Both dispositions use these exact shape predicates and conversion order.
// Ordinary keeps its original lexical owners. Selected parks actual clone and
// conversion failures before the next decoder or independent native post.
macro_rules! policy_claim_step {
    (Ordinary, strings $name:ident) => {
        let $name = |value: &OwnedValue, expected: &str| {
            <&str>::try_from(value).is_ok_and(|value| value == expected)
        };
    };
    (Retained, strings $name:ident) => {};
    (Ordinary, string_is $capture:ident, $function:ident, $value:ident, $index:literal, $expected:literal) => {
        $function($value, $expected)
    };
    (Retained, string_is $capture:ident, $function:ident, $value:ident, $index:literal, $expected:literal) => {
        $capture.string_is($value, $index, $expected)
    };
    (Ordinary, scalar $capture:ident, $value:ident, $slot:ident, $type:ident) => {
        $type::try_from($value).ok()
    };
    (Retained, scalar $capture:ident, $value:ident, $slot:ident, $type:ident) => {{
        $capture.$slot = Some($type::try_from($value));
        $capture.$slot.as_ref().and_then(|result| result.as_ref().ok()).copied()
    }};
    (Ordinary, string $capture:ident, $value:ident, $slot:ident) => {
        <&str>::try_from($value).map_err(|_| FloorErrorV1::Provisioning)?
    };
    (Retained, string $capture:ident, $value:ident, $slot:ident) => {
        $capture.$slot($value)?
    };

    (Ordinary, drop_ins $capture:ident, $value:ident) => {
        Vec::<String>::try_from($value.try_clone().map_err(|_| FloorErrorV1::Provisioning)?)
            .map_err(|_| FloorErrorV1::Provisioning)?
    };
    (Ordinary, invocation $capture:ident, $value:ident) => {
        Vec::<u8>::try_from($value.try_clone().map_err(|_| FloorErrorV1::Provisioning)?)
            .map_err(|_| FloorErrorV1::Provisioning)?
    };
    (Ordinary, finish_invocation $capture:ident, $value:ident) => { $value };
    (Ordinary, cgroup $capture:ident, $endpoint:ident) => {
        format!("/aos.slice/aos-control.slice/{}", unit_name($endpoint))
    };
    (Ordinary, drop_ins_empty $value:ident) => { $value.is_empty() };
    (Retained, drop_ins_empty $value:ident) => { $value };
    (Ordinary, invocation_invalid $capture:ident, $value:ident) => {
        $value.len() != 16 || $value.iter().all(|byte| *byte == 0)
    };
    (Retained, invocation_invalid $capture:ident, $value:ident) => {
        $value != 16 || $capture.invocation_is_zero()
    };
    (Retained, drop_ins $capture:ident, $value:ident) => {
        $capture.capture_drop_ins($value)?
    };
    (Retained, invocation $capture:ident, $value:ident) => {
        $capture.capture_invocation($value)?
    };
    (Retained, finish_invocation $capture:ident, $value:ident) => {
        $capture.take_invocation()?
    };
    (Retained, cgroup $capture:ident, $endpoint:ident) => {
        $capture.expected_cgroup($endpoint)?
    };
}

macro_rules! policy_claim_recipe {
    ($mode:ident, $capture:ident, $service:ident, $unit:ident,
        $endpoint:ident, $expected_profile:ident) => {{
        let service = $service;
        let unit = $unit;
        let endpoint = $endpoint;
        let expected_profile = $expected_profile;
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
    policy_claim_step!($mode, strings string_is);
    let drop_ins = policy_claim_step!($mode, drop_ins $capture, drop_ins);
    let invocation = policy_claim_step!($mode, invocation $capture, invocation);
    let cgroup = policy_claim_step!($mode, string $capture, cgroup, cgroup);
    let expected_cgroup = policy_claim_step!($mode, cgroup $capture, endpoint);
    if !policy_claim_step!($mode, string_is $capture, string_is, exit_type, 0, "cgroup")
        || !policy_claim_step!($mode, string_is $capture, string_is, kill_mode, 1, "control-group")
        || policy_claim_step!($mode, scalar $capture, timeout, timeout, u64) != Some(u64::MAX)
        || policy_claim_step!($mode, scalar $capture, transient, transient, bool) != Some(false)
        || !policy_claim_step!($mode, drop_ins_empty drop_ins)
        || policy_claim_step!($mode, invocation_invalid $capture, invocation)
        || cgroup != expected_cgroup
        || !has_exact_launch_fd_properties(open_files, extra_fds, endpoint, expected_profile)
        || policy_claim_step!($mode, scalar $capture, store_maximum, store_maximum, u32) != Some(0)
        || policy_claim_step!($mode, scalar $capture, stored_fds, stored_fds, u32) != Some(0)
        || !has_exact_owner_context(selinux_context, endpoint)
    {
        return Err(FloorErrorV1::Provisioning);
    }
    let fragment = policy_claim_step!($mode, string $capture, fragment, fragment);
    if fragment.len() > 4096 || !fragment.starts_with('/') {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(PolicyObservationV1 {
        fragment: PathBuf::from(fragment),
        control_group: cgroup.to_owned(),
        invocation: policy_claim_step!($mode, finish_invocation $capture, invocation),
    })
    }};
}

mod readback;
mod currentness;
mod acquisition;
pub(crate) use acquisition::FloorServiceAcquisitionOriginalV1;
pub(crate) use readback::FloorServicePolicyReadbackV1;
pub(crate) use currentness::FloorServiceCurrentnessOriginalV1;

fn decode_policy_claims(
    service: &[OwnedValue],
    unit: &[OwnedValue],
    endpoint: FloorEndpointV1,
    expected_profile: Option<&Path>,
) -> Result<PolicyObservationV1, FloorErrorV1> {
    policy_claim_recipe!(Ordinary, unused, service, unit, endpoint, expected_profile)

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
    use aos_systemd_client::Value;

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
