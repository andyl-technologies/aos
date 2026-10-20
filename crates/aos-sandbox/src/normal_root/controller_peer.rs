//! Adapts the actual lower Controller peer to the private Root role.
//!
//! Native startup, PID1, immutable-image, cgroup and stream ownership live in
//! Broker. These projections preserve the existing role errors and provide no
//! peer adopter, field constructor or alternate verification engine.

use std::num::NonZeroU32;
use std::path::Path;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use aos_systemd::OwnedValue;
#[cfg(test)]
use aos_systemd::Value;
use aos_sandbox_broker::receiving as native;
use super::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1, service};

pub(super) mod receiving;
pub(super) mod delete_receiving;

const CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";

pub(crate) struct OriginalControllerPolicyPeerV1<'startup> {
    native: native::RootControllerPolicyPeerV1<'startup>,
}

impl ProductionNormalRootStartupV1 {
    pub(crate) fn observe_controller_policy_peer(
        &self, stream: &RetainedUnixStream,
    ) -> Result<OriginalControllerPolicyPeerV1<'_>, Error> {
        self.native.observe_controller_policy_peer(stream)
            .map(|native| OriginalControllerPolicyPeerV1 { native })
            .map_err(|cause| match self.native.selected_currentness_failure_original_v1() {
                Some(original) => Error::SelectedCurrentness(original),
                None => cause.into(),
            })
    }
}

impl OriginalControllerPolicyPeerV1<'_> {
    pub(crate) fn recheck_stream(&self, stream: &RetainedUnixStream) -> Result<(), Error> {
        self.native.recheck_stream(stream).map_err(|cause| self.project_failure(cause))
    }

    pub(crate) fn require_chunk(
        &self, stream: &RetainedUnixStream, chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), Error> {
        self.native.require_chunk(stream, chunk).map_err(|cause| self.project_failure(cause))
    }

    fn project_failure(&self, cause: native::RootObservationErrorV1) -> Error {
        match self.native.selected_currentness_failure_original_v1() {
            Some(original) => Error::SelectedCurrentness(original),
            None => cause.into(),
        }
    }

    pub(crate) fn native_original_v1(&self) -> &native::RootControllerPolicyPeerV1<'_> {
        &self.native
    }
}

fn require_controller_process_identity(
    startup: &ProductionNormalRootStartupV1, pid: NonZeroU32,
    info: &aos_sandbox_linux::pidfd::PidFdInfo,
) -> Result<(), Error> {
    native::require_controller_process_identity_data_v1(startup.native.fields().profile.identities,
        pid, info).map_err(Into::into)
}

fn selected_resource_pair(properties: &[OwnedValue]) -> Result<(bool, bool), Error> {
    native::selected_controller_resource_pair_data_v1(properties).map_err(Into::into)
}

fn selected_nix_profile(properties: &[OwnedValue]) -> Result<Option<std::path::PathBuf>, Error> {
    native::selected_controller_nix_profile_data_v1(properties).map_err(Into::into)
}

pub(super) fn decode_delivery(
    properties: &[OwnedValue], unit: &[OwnedValue], profile: &Path,
) -> Result<service::ServiceObservationV1, Error> {
    decode_delivery_with_backends(properties, unit, profile, None)
}

fn decode_delivery_with_backends(
    properties: &[OwnedValue], unit: &[OwnedValue], profile: &Path, nix_profile: Option<&Path>,
) -> Result<service::ServiceObservationV1, Error> {
    decode_delivery_with_resource_pair(properties, unit, profile, nix_profile, false, false)
}

fn decode_delivery_with_resource_pair(
    properties: &[OwnedValue], unit: &[OwnedValue], profile: &Path, nix_profile: Option<&Path>,
    resource_delivery: bool, resource_launch: bool,
) -> Result<service::ServiceObservationV1, Error> {
    native::decode_controller_policy_delivery_data_v1(properties, unit, profile, nix_profile,
        resource_delivery, resource_launch).map_err(Into::into)
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
