//! Adapts the genuine lower Controller profile to upper operation owners.
//!
//! The first-table router, measured admission and private C receiver live in
//! Broker. Domain retains actual Root/P/I/Q/J scheduling, lifetime guards and
//! authority dispatch; none is completed by a lower comparison result.

mod admission;
mod capture;
mod environment;
mod peer_receiving;
mod profile_owner;
pub(super) mod source_successor_credential;
pub(crate) use environment::RootEnvironmentClientOriginalV1;
mod delete;
mod delete_planning;
pub(crate) use delete_planning::{
    RootDeletePlanningClientOriginalV1, RootDeletePlanningObservationLoanV1,
};
mod maintenance_storage;
mod provisioning;
mod resource_stream;
mod strict_chunk;
pub(crate) use maintenance_storage::RootMaintenanceStorageClientOriginalV3;
mod finality_recover;
#[doc(hidden)]
pub use finality_recover::{
    RootFinalityRecoverClientClosedV1, RootFinalityRecoverClientOriginalV1,
};
mod start_resource;
pub(crate) use delete::{DeleteSourceBindingDataV3, DeleteSourceClockBoundDataV3};
pub(crate) use delete::{RootDeleteChallengeLoanV1, RootDeleteClientOriginalV1};
#[doc(hidden)]
pub use provisioning::{
    RootStorageApplyAdmissionOriginalV1, RootStorageApplyClientClosedV1,
    RootStorageApplyClientOriginalV1, RootStorageApplyCompletionOriginalV1,
    RootStorageApplyConstructionTurnV1, RootStorageApplyCurrentTurnV1,
};
#[doc(hidden)]
pub use start_resource::{
    RootHostLaunchClientClosedV1, RootHostLaunchClientOriginalV1, RootHostPublicationTurnKindV2,
    RootStartAssignmentInputsClientOriginalV2, RootStartResourceCompletedOriginalV2,
    RootStartResourceConstructionTurnV2, RootStartResourceCurrentTurnV2,
    RootStartResourceExchangeDataV2, RootStartResourcePrepareAdmissionOriginalV2,
};
pub(crate) mod root_connection;
use super::{NormalRootStartupErrorV1, service};
pub use admission::{
    ControllerProfileAdmissionFailureV1, ProductionControllerSelectedProfileAdmissionV1,
};
use aos_sandbox_broker::profile_data::delivery as canonical_delivery;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use aos_systemd_client::{OwnedValue, Value};
pub use capture::{
    ControllerInitialCaptureFailureRefV1, ProductionControllerInitialCaptureAttemptV1,
    ProductionControllerNormalRootCaptureV1, ProductionControllerNormalRootStartupPartsV1,
};
pub(crate) use peer_receiving::CreateStorageRootPeerReceivingOriginalsV1;
pub use profile_owner::{
    ControllerProfileFailureViewV1, ControllerProfileLocalCurrentnessOriginalV1,
    ControllerProfileRequestedCountsV1, ProductionControllerNormalRootProfileV1,
};
use std::path::Path;
const UNIT: &str = canonical_delivery::CONTROLLER_UNIT;
pub(super) const CONTEXT: &str = canonical_delivery::CONTEXT;
pub(super) const PROFILE_NAME: &str = canonical_delivery::PROFILE_NAME;
const PUBLISHER_NAME: &str = canonical_delivery::PUBLISHER_NAME;
const TPM_IMAGE_NAME: &str = canonical_delivery::TPM_IMAGE_NAME;
const GIT_SOURCE_LISTENER_NAME: &str = canonical_delivery::GIT_SOURCE_LISTENER_NAME;
pub(crate) const RESOURCE_POLICY_NAME: &str = canonical_delivery::RESOURCE_POLICY_NAME;
pub(crate) const RESOURCE_ENROLLMENT_NAME: &str = canonical_delivery::RESOURCE_ENROLLMENT_NAME;
const RESOURCE_LAUNCH_NAME: &str = canonical_delivery::RESOURCE_LAUNCH_NAME;

impl ProductionControllerNormalRootProfileV1 {
    // These are comparison DATA from the original parsed/held image profile.
    // The actual Root loan retains all role, same-stream and native checks.
    pub(crate) fn cache_current_signer_identities_v1(&self) -> (u32, u32, u32) {
        let profile = self.original.schema();
        (
            profile.identities[2],
            profile.cache_signer_gid,
            profile.identities[1],
        )
    }

    pub(crate) fn attach_q04_intake_observers(
        &self,
        admission: &crate::controller_resource_reservation::service_interval::ObserverAdmission<'_>,
        origin: aos_sandbox_broker::controller_receiving::bank_launch::ControllerReservedObserverOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if !admission.belongs_to_q04_intake(self)
            || admission.capacity() != origin.capacity_data_v1()
            || !origin.lifetime_v1().same_original(&admission.lifetime())
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.original
            .attach_q04_intake_observers_v1(origin)
            .map_err(Into::into)
    }

    pub(crate) fn require_q04_intake_original(
        &self,
        lifetime: &crate::controller_resource_reservation::service_interval::ObserverLifetime,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .require_q04_intake_original_v1(lifetime)
            .map_err(Into::into)
    }

    pub(crate) fn recheck_q04_intake_profile(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .recheck_q04_intake_profile_v1()
            .map_err(Into::into)
    }

    pub(crate) fn attach_create_intake_observers(
        &self,
        admission: &crate::controller_resource_reservation::service_interval::ObserverAdmission<'_>,
        origin: aos_sandbox_broker::controller_receiving::bank_launch::ControllerReservedObserverOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if !admission.belongs_to_create_intake(self)
            || admission.capacity() != origin.capacity_data_v1()
            || !origin.lifetime_v1().same_original(&admission.lifetime())
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.original
            .attach_create_intake_observers_v1(origin)
            .map_err(Into::into)
    }

    pub(crate) fn require_create_intake_original(
        &self,
        lifetime: &crate::controller_resource_reservation::service_interval::ObserverLifetime,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .require_create_intake_original_v1(lifetime)
            .map_err(Into::into)
    }

    pub(crate) fn recheck_create_intake_profile(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .recheck_create_intake_profile_v1()
            .map_err(Into::into)
    }

    pub(crate) fn attach_nix_intake_observers(
        &self,
        admission: &crate::controller_resource_reservation::service_interval::ObserverAdmission<'_>,
        origin: aos_sandbox_broker::controller_receiving::bank_launch::ControllerReservedObserverOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if !admission.belongs_to_nix_intake(self)
            || admission.capacity() != origin.capacity_data_v1()
            || !origin.lifetime_v1().same_original(&admission.lifetime())
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.original
            .attach_nix_intake_observers_v1(origin)
            .map_err(Into::into)
    }

    pub(crate) fn require_nix_intake_original(
        &self,
        lifetime: &crate::controller_resource_reservation::service_interval::ObserverLifetime,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .require_nix_intake_original_v1(lifetime)
            .map_err(Into::into)
    }

    pub(crate) fn recheck_nix_intake_profile(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .recheck_nix_intake_profile_v1()
            .map_err(Into::into)
    }

    // Shares the genuinely bounded fixed-property decoder used by original
    // service receiving. Profile custody itself is part of the fixed J owner.
    pub(crate) fn create_intake_observer_demand()
    -> Result<aos_sandbox_model::ResourceVector, NormalRootStartupErrorV1> {
        service::growing_fixed_property_observer_demand_v1(64 * 1024)
    }

    pub(crate) fn first_global_observer_demand()
    -> Result<aos_sandbox_model::ResourceVector, NormalRootStartupErrorV1> {
        aos_sandbox_broker::receiving::FixedPropertyArchiveV1::controller_observer_row_demand_v1()
            .map_err(Into::into)
    }

    // Only the entered bank prefix can attach this original-funded recipe.
    // The profile owns every transport/result; no global or ambient switch
    // can turn ordinary observers into admission authority.
    pub(crate) fn attach_first_global_observers(
        &self,
        admission: &crate::controller_resource_reservation::service_interval::ObserverAdmission<'_>,
        origin: aos_sandbox_broker::controller_receiving::bank_launch::ControllerReservedObserverOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if !admission.belongs_to(self)
            || admission.capacity() != origin.capacity_data_v1()
            || !origin.lifetime_v1().same_original(&admission.lifetime())
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.original
            .attach_first_global_observers_v1(origin)
            .map_err(Into::into)
    }

    /// Closes a skipped FirstGlobal interval without releasing its charge.
    ///
    /// # Errors
    /// Refuses absent, contended or poisoned original archive custody. This
    /// denial-only operation cannot create, replace or rearm an admission.
    pub fn close_first_global_prefix_v1(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .close_first_global_prefix_v1()
            .map_err(Into::into)
    }

    pub(crate) fn require_first_global_original(
        &self,
        lifetime: &crate::controller_resource_reservation::service_interval::ObserverLifetime,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .require_first_global_original_v1(lifetime)
            .map_err(Into::into)
    }

    pub(crate) fn observe_first_global_cpu(
        &self,
        original: &mut aos_sandbox_linux::cgroup::FirstGlobalCpuReadbackV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .original_cgroup()
            .verify_exact_membership(self.original.original_process())
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        original
            .capture(self.original.original_cgroup())
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    pub(crate) fn recheck_first_global_cpu(
        &self,
        original: &mut aos_sandbox_linux::cgroup::FirstGlobalCpuReadbackV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .original_cgroup()
            .verify_exact_membership(self.original.original_process())
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        original
            .recheck(self.original.original_cgroup())
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    // A failed selected admission must not fall back to the unbounded legacy
    // observer merely to diagnose that failure. The unavailable borrower is
    // negative; independent writer names and raw clocks remain observable.
    pub(crate) fn recheck_first_global_profile(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.original
            .recheck_first_global_profile_v1()
            .map_err(Into::into)
    }

    pub(crate) fn require_resource_delivery(&self) -> Result<[u8; 16], NormalRootStartupErrorV1> {
        self.require_resource_producer()
            .map(|(invocation, _producer)| invocation)
    }

    // Only the actual Publisher flight calls this closed same-C/B route.
    // Its own scope never consumes, closes or replaces a retained P/I/Q/J
    // observer archive; the ordinary profile engine and comparisons are shared.
    pub(crate) fn require_publisher_resource_producer(
        &self,
        original: &std::sync::Arc<
            aos_sandbox_broker::controller_receiving::ControllerReceivingOriginalV1,
        >,
    ) -> Result<([u8; 16], [u8; 16]), NormalRootStartupErrorV1> {
        self.original
            .observe_publisher_resource_producer_v1(original)
            .map_err(Into::into)
    }

    // The actual J borrower is checked before scheduling; no failed P/I/Q/J
    // archive is consumed, closed or substituted by this independent B scope.
    pub(crate) fn require_create_storage_resource_producer(
        &self,
        original: &crate::controller_resource_reservation::CreateStorageOriginalLoanV1<'_>,
    ) -> Result<([u8; 16], [u8; 16]), NormalRootStartupErrorV1> {
        original
            .require_preparation_profile_original_v1(self)
            .map_err(|_| NormalRootStartupErrorV1::Service)?;
        self.read_create_storage_receiving_producer_v1()
    }

    // Fixed observational B receive only. The private actual operation's
    // resident currentness scope retains its own J entry and independent-post
    // obligation; this method supplies no J grant or operation authorization.
    pub(crate) fn read_create_storage_receiving_producer_v1(
        &self,
    ) -> Result<([u8; 16], [u8; 16]), NormalRootStartupErrorV1> {
        self.original
            .observe_create_storage_resource_producer_v1()
            .map_err(Into::into)
    }

    pub(crate) fn require_resource_producer(
        &self,
    ) -> Result<([u8; 16], [u8; 16]), NormalRootStartupErrorV1> {
        self.original
            .observe_controller_resource_producer_v1()
            .map_err(Into::into)
    }

    /// Rechecks selected bytes, policy and Controller's original unit delivery.
    ///
    /// # Errors
    /// Rejects changed inputs, original invocation/cgroup/process, subject,
    /// capabilities, identities or delivery roles.
    pub fn recheck(&self) -> Result<(), NormalRootStartupErrorV1> {
        self.original.recheck().map_err(Into::into)
    }

    // Only the original-flight coordinator can consume this real
    // stream join. No public digest/path/peer or readiness factory exists.
    pub(crate) fn observe_original_peer<'profile>(
        &'profile self,
        stream: &RetainedUnixStream,
    ) -> Result<OriginalNormalRootPeerV1<'profile>, NormalRootStartupErrorV1> {
        self.original
            .observe_original_peer(stream)
            .map(OriginalNormalRootPeerV1)
            .map_err(Into::into)
    }

}

// Only projects the existing native peer's fixed error categories.
// The actual stream/profile/cgroup/unit owner lives entirely in Broker.
pub(crate) struct OriginalNormalRootPeerV1<'profile>(
    aos_sandbox_broker::controller_receiving::profile::ControllerStartupRootPeerV1<'profile>,
);

impl OriginalNormalRootPeerV1<'_> {
    pub(crate) fn source_uid(&self) -> u32 {
        self.0.source_uid()
    }

    pub(crate) fn recheck_stream(
        &self,
        stream: &RetainedUnixStream,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.0.recheck_stream(stream).map_err(Into::into)
    }

    pub(crate) fn require_chunk(
        &self,
        stream: &RetainedUnixStream,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.0.require_chunk(stream, chunk).map_err(Into::into)
    }
}

pub(super) fn decode_delivery(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &Path,
    tpm_image: bool,
) -> Result<service::ServiceObservationV1, NormalRootStartupErrorV1> {
    decode_delivery_with_backends(properties, unit, profile_path, tpm_image, None)
}

pub(super) fn decode_delivery_with_backends(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &Path,
    tpm_image: bool,
    nix_profile: Option<&Path>,
) -> Result<service::ServiceObservationV1, NormalRootStartupErrorV1> {
    decode_delivery_with_resource_bank(
        properties,
        unit,
        profile_path,
        tpm_image,
        nix_profile,
        false,
    )
}

pub(super) fn decode_delivery_with_resource_bank(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &Path,
    tpm_image: bool,
    nix_profile: Option<&Path>,
    resource_delivery: bool,
) -> Result<service::ServiceObservationV1, NormalRootStartupErrorV1> {
    decode_delivery_with_resource_launch(
        properties,
        unit,
        profile_path,
        tpm_image,
        nix_profile,
        resource_delivery,
        false,
    )
}

pub(super) fn decode_delivery_with_resource_launch(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile_path: &Path,
    tpm_image: bool,
    nix_profile: Option<&Path>,
    resource_delivery: bool,
    resource_launch: bool,
) -> Result<service::ServiceObservationV1, NormalRootStartupErrorV1> {
    canonical_delivery::decode_delivery_with_resource_launch(
        properties,
        unit,
        profile_path,
        tpm_image,
        nix_profile,
        resource_delivery,
        resource_launch,
    )
    .map_err(Into::into)
}

pub(super) fn valid_names(names: &[String], publisher: bool) -> bool {
    valid_backend_names(names, publisher, false, false)
}

fn valid_backend_names(
    names: &[String],
    publisher: bool,
    nix_enabled: bool,
    git_source_cut: bool,
) -> bool {
    canonical_delivery::valid_backend_names(names, publisher, nix_enabled, git_source_cut)
}

pub(super) fn valid_controller_launch_names(
    names: &[Value<'_>],
    selected: bool,
    launch: bool,
) -> bool {
    canonical_delivery::valid_controller_launch_names(names, selected, launch)
}

pub(super) fn valid_resource_delivery_names(names: &[Value<'_>], selected: bool) -> bool {
    canonical_delivery::valid_resource_delivery_names(names, selected)
}

#[cfg(test)]
mod backend_tests {
    //! Pure closed-table/property vectors, authored and UNRUN.
    //!
    //! Literal names and PID1-shaped property DATA never create descriptors,
    //! admitted startup owners, launch images, floors or publication authority.

    use super::*;
    use aos_sandbox_linux::inherited_fd::ControllerInitialActivationTableV1;

    const ROOT_PROFILE: &str = "/nix/store/11111111111111111111111111111111-aos-normal-root-startup-profile-2/profile.json";
    const NIX_PROFILE: &str =
        "/nix/store/22222222222222222222222222222222-aos-nix-startup-profile-2/controller.json";

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn files(tpm_image: bool, nix_enabled: bool) -> Vec<(String, String, u64)> {
        let mut files = vec![(ROOT_PROFILE.to_owned(), PROFILE_NAME.to_owned(), 1)];
        if tpm_image {
            files.push(("/proc/1/exe".to_owned(), TPM_IMAGE_NAME.to_owned(), 1));
        }
        if nix_enabled {
            files.push((
                NIX_PROFILE.to_owned(),
                super::super::nix_startup::CONTROLLER_PROFILE_NAME.to_owned(),
                1,
            ));
            files.push((
                "/proc/1/exe".to_owned(),
                super::super::nix_startup::CONTROLLER_PID1_NAME.to_owned(),
                1,
            ));
        }
        files
    }

    fn properties(files: Vec<(String, String, u64)>) -> (Vec<OwnedValue>, Vec<OwnedValue>) {
        let properties = vec![
            value(format!("/{}", canonical_delivery::CGROUP)),
            value(files),
            value(Vec::<String>::new()),
            OwnedValue::from(0_u32),
            OwnedValue::from(0_u32),
            value((false, CONTEXT)),
            OwnedValue::from(0_u64),
            OwnedValue::from(0_u64),
            OwnedValue::from(true),
        ];
        let unit = vec![
            value(
                "/nix/store/33333333333333333333333333333333-aos-sandboxd-0.1.0/aos-sandboxd.service",
            ),
            value(Vec::<String>::new()),
            OwnedValue::from(false),
            value(vec![1_u8; 16]),
        ];
        (properties, unit)
    }

    #[test]
    fn declared_backend_table_preserves_every_legacy_role_combination() {
        for selection in 0..32 {
            let publisher = selection & 1 != 0;
            let nix_enabled = selection & 2 != 0;
            let git_source_cut = selection & 4 != 0;
            let root_profile = selection & 8 != 0;
            let method46_image = selection & 16 != 0;
            let mut names = Vec::new();
            for (selected, name) in [
                (publisher, PUBLISHER_NAME),
                (root_profile, PROFILE_NAME),
                (method46_image, TPM_IMAGE_NAME),
                (
                    nix_enabled,
                    super::super::nix_startup::CONTROLLER_PROFILE_NAME,
                ),
                (nix_enabled, super::super::nix_startup::CONTROLLER_PID1_NAME),
                (git_source_cut, GIT_SOURCE_LISTENER_NAME),
            ] {
                if selected {
                    names.push(name.to_owned());
                }
            }

            assert!(valid_backend_names(
                &names,
                publisher,
                nix_enabled,
                git_source_cut
            ));
            names.reverse();
            assert!(valid_backend_names(
                &names,
                publisher,
                nix_enabled,
                git_source_cut
            ));
            assert_eq!(
                valid_names(&names, publisher),
                !nix_enabled && !git_source_cut
            );
        }
    }

    #[test]
    fn backend_table_rejects_missing_duplicate_foreign_and_undeclared_roles() {
        let names: Vec<String> = [
            PROFILE_NAME,
            TPM_IMAGE_NAME,
            PUBLISHER_NAME,
            super::super::nix_startup::CONTROLLER_PROFILE_NAME,
            super::super::nix_startup::CONTROLLER_PID1_NAME,
            GIT_SOURCE_LISTENER_NAME,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();

        assert!(valid_backend_names(&names, true, true, true));
        for index in 0..names.len() {
            let mut duplicate = names.clone();
            duplicate.remove(if index == 0 { 1 } else { 0 });
            duplicate.push(names[index].clone());
            assert_eq!(duplicate.len(), 6);
            assert!(!valid_backend_names(&duplicate, true, true, true));
        }
        for index in 2..names.len() {
            let mut missing = names.clone();
            missing.remove(index);
            assert!(!valid_backend_names(&missing, true, true, true));
        }
        for foreign in [
            "unknown",
            "aos-normal-root-pid1-image",
            "aos-nix-owner-profile",
        ] {
            let mut changed = names.clone();
            changed[0] = foreign.to_owned();
            assert!(!valid_backend_names(&changed, true, true, true));
        }
        for flags in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert!(!valid_backend_names(&names, flags.0, flags.1, flags.2));
        }
    }

    #[test]
    fn legacy_capture_and_startup_parts_signature_is_preserved_without_capture() {
        let _legacy: fn(
            bool,
        ) -> Result<
            ProductionControllerNormalRootStartupPartsV1,
            NormalRootStartupErrorV1,
        > = ProductionControllerNormalRootCaptureV1::capture;
        let _combined: fn(
            bool,
            bool,
            bool,
        ) -> Result<
            ProductionControllerNormalRootStartupPartsV1,
            NormalRootStartupErrorV1,
        > = ProductionControllerNormalRootCaptureV1::capture_with_backends;
    }

    #[test]
    fn legacy_delivery_remains_no_nix_while_selected_delivery_requires_the_pair() {
        for tpm_image in [false, true] {
            let (legacy, unit) = properties(files(tpm_image, false));
            let decoded =
                decode_delivery(&legacy, &unit, Path::new(ROOT_PROFILE), tpm_image).unwrap();
            let combined = decode_delivery_with_backends(
                &legacy,
                &unit,
                Path::new(ROOT_PROFILE),
                tpm_image,
                None,
            )
            .unwrap();
            assert_eq!(decoded, combined);

            let (selected, unit) = properties(files(tpm_image, true));
            assert!(
                decode_delivery_with_backends(
                    &selected,
                    &unit,
                    Path::new(ROOT_PROFILE),
                    tpm_image,
                    Some(Path::new(NIX_PROFILE)),
                )
                .is_ok()
            );
            assert!(
                decode_delivery(&selected, &unit, Path::new(ROOT_PROFILE), tpm_image,).is_err()
            );
            assert!(
                decode_delivery_with_backends(
                    &selected,
                    &unit,
                    Path::new(ROOT_PROFILE),
                    tpm_image,
                    None,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn paired_delivery_rejects_missing_duplicate_substituted_and_git_openfile_roles() {
        let original = files(true, true);
        for index in [2, 3] {
            let mut missing = original.clone();
            missing.remove(index);
            let mut duplicate = original.clone();
            duplicate[if index == 2 { 3 } else { 2 }] = original[index].clone();
            let mut wrong_flags = original.clone();
            wrong_flags[index].2 = 0;
            let mut foreign_role = original.clone();
            foreign_role[index].1 = GIT_SOURCE_LISTENER_NAME.to_owned();

            for changed in [missing, duplicate, wrong_flags, foreign_role] {
                let (properties, unit) = properties(changed);
                assert!(
                    decode_delivery_with_backends(
                        &properties,
                        &unit,
                        Path::new(ROOT_PROFILE),
                        true,
                        Some(Path::new(NIX_PROFILE)),
                    )
                    .is_err()
                );
            }
        }
        for (index, path) in [(2, "/other/controller.json"), (3, "/proc/self/exe")] {
            let mut changed = original.clone();
            changed[index].0 = path.to_owned();
            let (properties, unit) = properties(changed);
            assert!(
                decode_delivery_with_backends(
                    &properties,
                    &unit,
                    Path::new(ROOT_PROFILE),
                    true,
                    Some(Path::new(NIX_PROFILE)),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn selected_delivery_keeps_exact_confinement_and_invocation_checks() {
        let (original, unit) = properties(files(true, true));
        let observed = decode_delivery_with_backends(
            &original,
            &unit,
            Path::new(ROOT_PROFILE),
            true,
            Some(Path::new(NIX_PROFILE)),
        )
        .unwrap();

        for (index, replacement) in [
            (0, value("/system.slice/aos-sandboxd.service")),
            (2, value(vec!["aos-git-source-cut".to_owned()])),
            (3, OwnedValue::from(1_u32)),
            (4, OwnedValue::from(1_u32)),
            (5, value((false, "system_u:system_r:aos_sandbox_nix_t"))),
            (6, OwnedValue::from(1_u64)),
            (7, OwnedValue::from(1_u64)),
            (8, OwnedValue::from(false)),
        ] {
            let (mut changed, unit) = properties(files(true, true));
            changed[index] = replacement;
            assert!(
                decode_delivery_with_backends(
                    &changed,
                    &unit,
                    Path::new(ROOT_PROFILE),
                    true,
                    Some(Path::new(NIX_PROFILE)),
                )
                .is_err(),
                "property {index}"
            );
        }

        let (properties, mut changed_unit) = properties(files(true, true));
        changed_unit[3] = value(vec![2_u8; 16]);
        let changed = decode_delivery_with_backends(
            &properties,
            &changed_unit,
            Path::new(ROOT_PROFILE),
            true,
            Some(Path::new(NIX_PROFILE)),
        )
        .unwrap();
        assert!(service::require_same(&observed, &changed).is_err());

        changed_unit[3] = value(vec![0_u8; 16]);
        assert!(
            decode_delivery_with_backends(
                &properties,
                &changed_unit,
                Path::new(ROOT_PROFILE),
                true,
                Some(Path::new(NIX_PROFILE)),
            )
            .is_err()
        );
    }

    #[test]
    fn launch_role_is_unique_paired_and_fits_the_complete_nine_role_table() {
        let mut names: Vec<String> = [
            PROFILE_NAME,
            PUBLISHER_NAME,
            TPM_IMAGE_NAME,
            super::super::nix_startup::CONTROLLER_PROFILE_NAME,
            super::super::nix_startup::CONTROLLER_PID1_NAME,
            GIT_SOURCE_LISTENER_NAME,
            RESOURCE_POLICY_NAME,
            RESOURCE_ENROLLMENT_NAME,
            RESOURCE_LAUNCH_NAME,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert!(valid_backend_names(&names, true, true, true));

        names.push(RESOURCE_LAUNCH_NAME.to_owned());
        assert!(!valid_backend_names(&names, true, true, true));
        names.pop();
        names.retain(|name| name != RESOURCE_POLICY_NAME && name != RESOURCE_ENROLLMENT_NAME);
        assert!(!valid_backend_names(&names, true, true, true));
    }

    #[test]
    fn controller_launch_property_is_exact_and_storage_pair_stays_closed() {
        let pair = [
            Value::from(RESOURCE_POLICY_NAME),
            Value::from(RESOURCE_ENROLLMENT_NAME),
        ];
        let launch = [
            Value::from(RESOURCE_POLICY_NAME),
            Value::from(RESOURCE_ENROLLMENT_NAME),
            Value::from(RESOURCE_LAUNCH_NAME),
        ];
        assert!(valid_controller_launch_names(&pair, true, false));
        assert!(!valid_controller_launch_names(&pair, true, true));
        assert!(valid_controller_launch_names(&launch, true, true));
        assert!(!valid_controller_launch_names(&launch, true, false));
        assert!(!valid_controller_launch_names(&launch, false, true));
        assert!(!valid_resource_delivery_names(&launch, true));

        let reordered = [
            Value::from(RESOURCE_POLICY_NAME),
            Value::from(RESOURCE_LAUNCH_NAME),
            Value::from(RESOURCE_ENROLLMENT_NAME),
        ];
        assert!(!valid_controller_launch_names(&reordered, true, true));
    }
}

mod execution_no_apply;
mod bookend;
mod stop_cleanup;
#[doc(hidden)]
pub use stop_cleanup::{RootStopCleanupClientOriginalV1, RootStopCleanupClientClosedV1,
    RootStopCleanupSigningLoanV1, RootStopCleanupChildLoanV1,
    RootStopCleanupClientCompletedBorrowV1};
#[doc(hidden)]
pub use execution_no_apply::{
    RootExecutionNoApplyClientAcquisitionBorrowV2, RootExecutionNoApplyClientClosedV2,
    RootExecutionNoApplyClientFloorBorrowV2, RootExecutionNoApplyClientOriginalV2,
};
