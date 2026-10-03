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
use aos_systemd::{OwnedValue, Value};

use super::{
    NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1, client, retain_fixed_cgroup,
    service,
};
use crate::immutable_image::RetainedImmutableFileV1;

const UNIT: &str = "aos-sandboxd.service";
const CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";

pub(crate) struct OriginalControllerPolicyPeerV1<'startup> {
    startup: &'startup ProductionNormalRootStartupV1,
    pid: NonZeroU32,
    cgroup: RetainedCgroupAnchor,
    fragment: RetainedImmutableFileV1,
    nix_profile: Option<RetainedImmutableFileV1>,
    observed: service::ServiceObservationV1,
}

impl ProductionNormalRootStartupV1 {
    pub(crate) fn observe_controller_policy_peer(
        &self,
        stream: &RetainedUnixStream,
    ) -> Result<OriginalControllerPolicyPeerV1<'_>, Error> {
        self.recheck()?;
        stream.revalidate_original().map_err(|_| Error::Service)?;
        let pid = stream.peer().credentials().pid();
        let (observed, nix_profile) = observe_initial(self, pid)?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observed.fragment.clone())
            .map_err(|_| Error::Service)?;
        let peer = OriginalControllerPolicyPeerV1 {
            startup: self,
            pid,
            cgroup: retain_fixed_cgroup(Path::new(CGROUP))?,
            fragment,
            nix_profile,
            observed,
        };
        peer.recheck_stream(stream)?;
        Ok(peer)
    }
}

impl OriginalControllerPolicyPeerV1<'_> {
    pub(crate) fn recheck_stream(&self, stream: &RetainedUnixStream) -> Result<(), Error> {
        self.startup.recheck()?;
        stream.revalidate_original().map_err(|_| Error::Service)?;
        let credentials = stream.peer().credentials();
        if credentials.pid() != self.pid
            || credentials.uid() != self.startup.profile.identities[0]
            || credentials.gid() != self.startup.profile.identities[1]
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
        )?;
        service::require_same(&self.observed, &observed)?;
        self.fragment.revalidate().map_err(|_| Error::Service)
    }

    pub(crate) fn require_chunk(
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
        let credentials = info.credentials().ok_or(Error::Service)?;
        let [uid, gid, _, _] = self.startup.profile.identities;
        if info.thread_group_id() != self.pid.get()
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
}

fn observe(
    startup: &ProductionNormalRootStartupV1,
    pid: NonZeroU32,
    nix_profile: Option<&Path>,
) -> Result<service::ServiceObservationV1, Error> {
    let (properties, unit) =
        service::read_properties(UNIT, pid.get(), service::SERVICE_PROPERTIES)?;
    service::immutable_observation(decode_delivery_with_backends(
        &properties,
        &unit,
        startup.profile_file.path(),
        nix_profile,
    )?)
}

fn observe_initial(
    startup: &ProductionNormalRootStartupV1,
    pid: NonZeroU32,
) -> Result<(service::ServiceObservationV1, Option<RetainedImmutableFileV1>), Error> {
    let (properties, unit) = service::read_properties(UNIT, pid.get(), service::SERVICE_PROPERTIES)?;
    let nix_path = selected_nix_profile(&properties)?;
    let nix_profile = nix_path.map(|path| {
        let file = std::fs::File::open(path).map_err(|_| Error::Profile)?;
        super::nix_startup::retain_controller_profile(file)
    }).transpose()?;
    let observed = service::immutable_observation(decode_delivery_with_backends(
        &properties,
        &unit,
        startup.profile_file.path(),
        nix_profile.as_ref().map(|profile| profile.path()),
    )?)?;
    Ok((observed, nix_profile))
}

fn selected_nix_profile(properties: &[OwnedValue]) -> Result<Option<std::path::PathBuf>, Error> {
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
            super::nix_startup::CONTROLLER_PROFILE_NAME => {
                if profile.is_some() {
                    return Err(Error::Service);
                }
                super::profile::require_store_path(path.as_str())?;
                if !path.as_str().ends_with("-aos-nix-startup-profile-2/controller.json") {
                    return Err(Error::Profile);
                }
                profile = Some(std::path::PathBuf::from(path.as_str()));
            }
            super::nix_startup::CONTROLLER_PID1_NAME => {
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

pub(super) fn decode_delivery(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile: &Path,
) -> Result<service::ServiceObservationV1, Error> {
    decode_delivery_with_backends(properties, unit, profile, None)
}

fn decode_delivery_with_backends(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile: &Path,
    nix_profile: Option<&Path>,
) -> Result<service::ServiceObservationV1, Error> {
    let Some(Value::Array(files)) = properties.get(1).map(|value| &**value) else {
        return Err(Error::Service);
    };
    // Optionality comes only from PID1's actual table. The existing strict
    // Controller decoder still checks every exact name/path/flag and duplicate.
    let old_roles = files.len().checked_sub(2 * usize::from(nix_profile.is_some()))
        .ok_or(Error::Service)?;
    let tpm_image = match old_roles {
        1 => false,
        2 => true,
        _ => return Err(Error::Service),
    };
    client::decode_delivery_with_backends(properties, unit, profile, tpm_image, nix_profile)
}

#[cfg(test)]
mod backend_tests {
    //! Pure original-Controller paired-delivery vectors, authored and UNRUN.
    //!
    //! Only inert PID1-shaped property DATA is decoded; no file, stream,
    //! startup owner, current floor or live process fixture is constructed.

    use super::*;

    const NIX_PROFILE: &str =
        "/nix/store/22222222222222222222222222222222-aos-nix-startup-profile-2/controller.json";

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn selected_properties(entries: Vec<(String, String, u64)>) -> Vec<OwnedValue> {
        vec![value(format!("/{CGROUP}")), value(entries)]
    }

    fn paired_files() -> Vec<(String, String, u64)> {
        vec![
            (NIX_PROFILE.to_owned(), super::super::nix_startup::CONTROLLER_PROFILE_NAME.to_owned(), 1),
            ("/proc/1/exe".to_owned(), super::super::nix_startup::CONTROLLER_PID1_NAME.to_owned(), 1),
        ]
    }

    #[test]
    fn selected_nix_profile_requires_the_exact_pair_before_retention() {
        let original = paired_files();
        let properties = selected_properties(original.clone());
        assert_eq!(selected_nix_profile(&properties).unwrap(), Some(NIX_PROFILE.into()));
        assert_eq!(selected_nix_profile(&selected_properties(Vec::new())).unwrap(), None);

        for index in 0..original.len() {
            let mut missing = original.clone();
            missing.remove(index);
            let mut duplicate = original.clone();
            duplicate.push(original[index].clone());
            let mut wrong_flags = original.clone();
            wrong_flags[index].2 = 0;

            for changed in [missing, duplicate, wrong_flags] {
                assert!(selected_nix_profile(&selected_properties(changed)).is_err());
            }
        }
        for (index, path) in [
            (0, "/tmp/controller.json"),
            (0, "/nix/store/22222222222222222222222222222222-aos-nix-startup-profile-2/owner.json"),
            (1, "/proc/self/exe"),
        ] {
            let mut changed = original.clone();
            changed[index].0 = path.to_owned();
            assert!(selected_nix_profile(&selected_properties(changed)).is_err());
        }
    }

    #[test]
    fn original_peer_legacy_decoder_keeps_its_no_nix_signature() {
        let _legacy: fn(&[OwnedValue], &[OwnedValue], &Path) -> Result<
            service::ServiceObservationV1, Error,
        > = decode_delivery;
        let properties = selected_properties(paired_files());
        let unit = Vec::new();

        assert!(decode_delivery(&properties, &unit, Path::new("/old/profile.json")).is_err());
        assert!(decode_delivery_with_backends(
            &properties, &unit, Path::new("/old/profile.json"), Some(Path::new(NIX_PROFILE)),
        ).is_err());
    }
}
