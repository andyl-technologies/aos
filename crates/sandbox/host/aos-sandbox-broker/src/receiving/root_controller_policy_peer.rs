//! Compares the original Controller on Root's PRE-ROOT metadata connection.
//!
//! Actual PID1 delivery, original process/cgroup and sending socket SID are
//! compared under Root's selected startup owner. They do not seal Controller's
//! executable or authenticate a Ready worker/kernel request. No caller path,
//! identity tuple, OpenFile flag or decoded record constructs this peer.

use std::num::NonZeroU32;
use std::path::Path;

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use aos_systemd_client::{OwnedValue, Value};

use super::root_service as service;
use super::root_startup_native::retain_fixed_cgroup;
use super::{RootObservationErrorV1 as Error, RootStartupNativeOriginalV1};
use crate::immutable_image::RetainedImmutableFileV1;
use crate::profile_data::delivery as client;

mod selected;
pub use selected::{RootSelectedControllerPeerOriginalV1, RootSelectedControllerCurrentSampleV1,
    RootSelectedControllerSubjectSampleV1};

const UNIT: &str = "aos-sandboxd.service";
const CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";

/// Retains the actual original Controller under the genuine Root startup.
///
/// No peer tuple, image DATA or financial handle constructs this owner.
pub struct RootControllerPolicyPeerV1<'startup> {
    startup: &'startup RootStartupNativeOriginalV1,
    pid: NonZeroU32,
    cgroup: RetainedCgroupAnchor,
    fragment: RetainedImmutableFileV1,
    nix_profile: Option<RetainedImmutableFileV1>,
    resource_producer: Option<[u8; 16]>,
    resource_launch: bool,
    observed: service::ServiceObservationV1,
}

impl RootStartupNativeOriginalV1 {
    /// Observes the actual Controller on the held original stream.
    ///
    /// # Errors
    /// Refuses changed startup, delivery, process, cgroup, images or stream.
    pub fn observe_controller_policy_peer(
        &self,
        stream: &RetainedUnixStream,
    ) -> Result<RootControllerPolicyPeerV1<'_>, Error> {
        self.recheck_actual_v1()?;
        stream.revalidate_original().map_err(|_| Error::Service)?;
        let pid = stream.peer().credentials().pid();
        let (observed, nix_profile, resource_producer, resource_launch) =
            observe_initial(self, pid)?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observed.fragment.clone())
            .map_err(|_| Error::Service)?;
        let peer = RootControllerPolicyPeerV1 {
            startup: self,
            pid,
            cgroup: retain_fixed_cgroup(Path::new(CGROUP))?,
            fragment,
            nix_profile,
            resource_producer,
            resource_launch,
            observed,
        };
        peer.recheck_stream(stream)?;
        Ok(peer)
    }
}

impl RootControllerPolicyPeerV1<'_> {
    /// Retains only an already-selected original startup failure for diagnostics.
    #[must_use]
    pub fn selected_currentness_failure_original_v1(
        &self,
    ) -> Option<super::RootSelectedCurrentnessFailureOriginalV1> {
        self.startup.selected_currentness_failure_original_v1()
    }

    /// Repeats the actual startup, Controller process and stream checks.
    ///
    /// # Errors
    /// Refuses changed selected/ordinary custody or any original peer binding.
    pub fn recheck_stream(&self, stream: &RetainedUnixStream) -> Result<(), Error> {
        self.startup.recheck_actual_v1()?;
        stream.revalidate_original().map_err(|_| Error::Service)?;
        let credentials = stream.peer().credentials();
        if credentials.pid() != self.pid
            || credentials.uid() != self.startup.fields().profile.identities[0]
            || credentials.gid() != self.startup.fields().profile.identities[1]
        {
            return Err(Error::Service);
        }
        self.require_process(stream.peer().pidfd())?;
        if let Some(profile) = &self.nix_profile {
            profile.revalidate().map_err(|_| Error::Profile)?;
        }
        let observed = observe(
            self.startup,
            self.pid,
            self.nix_profile.as_ref().map(|profile| profile.path()),
            self.resource_producer,
            self.resource_launch,
        )?;
        service::require_same(&self.observed, &observed)?;
        self.fragment.revalidate().map_err(|_| Error::Service)
    }

    /// Compares a received subject with the same actual original Controller.
    ///
    /// # Errors
    /// Refuses foreign socket context, credentials, process or original peer.
    pub fn require_chunk(
        &self,
        stream: &RetainedUnixStream,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), Error> {
        self.recheck_stream(stream)?;
        let actual = chunk.subject().credentials();
        let expected = stream.peer().credentials();
        if chunk.socket_context() != client::CONTEXT.as_bytes()
            || actual.pid() != expected.pid()
            || actual.uid() != expected.uid()
            || actual.gid() != expected.gid()
            || !chunk.subject().is_alive().map_err(|_| Error::Service)?
        {
            return Err(Error::Service);
        }
        self.require_process(chunk.subject().pidfd())
    }

    fn require_process(&self, process: &PidFd) -> Result<(), Error> {
        let info = self
            .cgroup
            .verify_exact_membership(process)
            .map_err(|_| Error::Service)?;
        require_controller_process_identity_data_v1(
            self.startup.fields().profile.identities,
            self.pid,
            &info,
        )
    }
}

/// Compares fixed Controller process identity DATA without adopting a peer.
///
/// # Errors
/// Rejects a foreign thread group, parent, user or group.
pub fn require_controller_process_identity_data_v1(
    identities: [u32; 4],
    pid: NonZeroU32,
    info: &aos_sandbox_linux::pidfd::PidFdInfo,
) -> Result<(), Error> {
    let credentials = info.credentials().ok_or(Error::Service)?;
    let [uid, gid, _, _] = identities;
    if info.thread_group_id() != pid.get()
        || info.parent_pid() != 1
        || [
            credentials.real_user_id(),
            credentials.effective_user_id(),
            credentials.saved_user_id(),
            credentials.filesystem_user_id(),
        ] != [uid; 4]
        || [
            credentials.real_group_id(),
            credentials.effective_group_id(),
            credentials.saved_group_id(),
            credentials.filesystem_group_id(),
        ] != [gid; 4]
    {
        return Err(Error::Service);
    }
    Ok(())
}

fn observe(
    startup: &RootStartupNativeOriginalV1,
    pid: NonZeroU32,
    nix_profile: Option<&Path>,
    resource_producer: Option<[u8; 16]>,
    resource_launch: bool,
) -> Result<service::ServiceObservationV1, Error> {
    let recipe = if resource_producer.is_some() {
        RESOURCE_SERVICE_PROPERTIES
    } else {
        client::SERVICE_PROPERTIES
    };
    let (properties, unit) = read_properties(UNIT, pid.get(), recipe)?;
    let common = if resource_producer.is_some() {
        properties
            .get(..client::SERVICE_PROPERTIES.len())
            .ok_or(Error::Service)?
    } else {
        &properties
    };
    let observed = immutable_observation(decode_controller_policy_delivery_data_v1(
        common,
        &unit,
        startup.fields().profile_file.path(),
        nix_profile,
        resource_producer.is_some(),
        resource_launch,
    )?)?;
    if let Some(expected) = resource_producer {
        let producer = properties.last().ok_or(Error::Service)?;
        if client::decode_resource_producer(producer)? != expected {
            return Err(Error::Service);
        }
    }
    Ok(observed)
}

fn observe_initial(
    startup: &RootStartupNativeOriginalV1,
    pid: NonZeroU32,
) -> Result<
    (
        service::ServiceObservationV1,
        Option<RetainedImmutableFileV1>,
        Option<[u8; 16]>,
        bool,
    ),
    Error,
> {
    let (properties, unit) = read_properties(UNIT, pid.get(), client::SERVICE_PROPERTIES)?;
    let nix_path = selected_controller_nix_profile_data_v1(&properties)?;
    let nix_profile = nix_path
        .map(|path| {
            let file = std::fs::File::open(path).map_err(|_| Error::Profile)?;
            crate::profile_data::images::retain_nix_controller_profile(file).map_err(Error::from)
        })
        .transpose()?;
    let (resource_delivery, resource_launch) =
        selected_controller_resource_pair_data_v1(&properties)?;
    let observed = immutable_observation(decode_controller_policy_delivery_data_v1(
        &properties,
        &unit,
        startup.fields().profile_file.path(),
        nix_profile.as_ref().map(|profile| profile.path()),
        resource_delivery,
        resource_launch,
    )?)?;
    let resource_producer = if resource_delivery {
        let (current, unit) = read_properties(UNIT, pid.get(), RESOURCE_SERVICE_PROPERTIES)?;
        let (producer, common) = current.split_last().ok_or(Error::Service)?;
        let current = immutable_observation(decode_controller_policy_delivery_data_v1(
            common,
            &unit,
            startup.fields().profile_file.path(),
            nix_profile.as_ref().map(|profile| profile.path()),
            true,
            resource_launch,
        )?)?;
        service::require_same(&observed, &current)?;
        Some(client::decode_resource_producer(producer)?)
    } else {
        None
    };
    Ok((observed, nix_profile, resource_producer, resource_launch))
}

// Only a complete, ordered original PID1 pair selects the additional recipe.
// Pair DATA grants no resource loan; the owning bank checks its own original FDs.
/// Selects only the exact original PID1 descriptor-role DATA.
///
/// # Errors
/// Refuses malformed or incomplete Controller role arrays.
pub fn selected_controller_resource_pair_data_v1(
    properties: &[OwnedValue],
) -> Result<(bool, bool), Error> {
    let Some(Value::Array(extras)) = properties.get(2).map(|value| &**value) else {
        return Err(Error::Service);
    };
    if extras.is_empty() {
        return Ok((false, false));
    }
    let launch = extras.len() == 3;
    if !client::valid_controller_launch_names(extras.inner(), true, launch) {
        return Err(Error::Service);
    }
    Ok((true, launch))
}

/// Selects only the exact original paired Nix profile pathname DATA.
///
/// # Errors
/// Refuses duplicate, foreign or incomplete immutable profile/PID1 names.
pub fn selected_controller_nix_profile_data_v1(
    properties: &[OwnedValue],
) -> Result<Option<std::path::PathBuf>, Error> {
    let Some(Value::Array(files)) = properties.get(1).map(|value| &**value) else {
        return Err(Error::Service);
    };
    let mut profile = None;
    let mut pid1 = false;
    for entry in files.inner() {
        let Value::Structure(entry) = entry else {
            return Err(Error::Service);
        };
        let [Value::Str(path), Value::Str(name), Value::U64(1)] = entry.fields() else {
            return Err(Error::Service);
        };
        match name.as_str() {
            client::NIX_PROFILE_NAME => {
                if profile.is_some() {
                    return Err(Error::Service);
                }
                crate::profile_data::schema::require_store_path(path.as_str())?;
                if !path
                    .as_str()
                    .ends_with("-aos-nix-startup-profile-2/controller.json")
                {
                    return Err(Error::Profile);
                }
                profile = Some(std::path::PathBuf::from(path.as_str()));
            }
            client::NIX_PID1_NAME => {
                if pid1 || Path::new(path.as_str()) != Path::new("/proc/1/exe") {
                    return Err(Error::Service);
                }
                pid1 = true;
            }
            // The complete closed parser below independently checks the old
            // Root/method46 roles. They do not establish Nix floor authority.
            _ => {}
        }
    }
    if profile.is_some() != pid1 {
        return Err(Error::Service);
    }
    Ok(profile)
}

/// Decodes canonical Controller delivery DATA without constructing custody.
///
/// # Errors
/// Refuses changed profile, native role table, unit or delivery grammar.
pub fn decode_controller_policy_delivery_data_v1(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile: &Path,
    nix_profile: Option<&Path>,
    resource_delivery: bool,
    resource_launch: bool,
) -> Result<service::ServiceObservationV1, Error> {
    let Some(Value::Array(files)) = properties.get(1).map(|value| &**value) else {
        return Err(Error::Service);
    };
    // Optionality comes only from PID1's actual table. The existing strict
    // Controller decoder still checks every exact name/path/flag and duplicate.
    let old_roles = files
        .len()
        .checked_sub(2 * usize::from(nix_profile.is_some()))
        .ok_or(Error::Service)?;
    let tpm_image = match old_roles {
        1 => false,
        2 => true,
        _ => return Err(Error::Service),
    };
    client::decode_delivery_with_resource_launch(
        properties,
        unit,
        profile,
        tpm_image,
        nix_profile,
        resource_delivery,
        resource_launch,
    )
    .map_err(Into::into)
}

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

fn read_properties(
    unit: &'static str,
    pid: u32,
    properties: &'static [&'static str],
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), Error> {
    aos_systemd_client::read_pid1_startup_properties_v1(
        unit,
        pid,
        properties,
        aos_systemd_client::Pid1PropertyReadRecipeV1::Legacy,
    )
    .map_err(|_| Error::Service)
}

fn immutable_observation(
    observed: service::ServiceObservationV1,
) -> Result<service::ServiceObservationV1, Error> {
    client::immutable_observation_into(observed, &mut None).map_err(Into::into)
}
