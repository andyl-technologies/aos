//! Restricted Broker entry to the single shared retained physical TPM owner.
//!
//! Only the existing floor composition opens this facade. Its opaque opening
//! capsule transfers the actual two lock loans and original PID1 reference;
//! neither scalar DATA nor an injected transport can construct the shared owner.
//! The facade keeps the original sealed backend API and owns only that owner.

use aos_sandbox_controller_domain::ProtectedJournalLockCustodyV1;

use crate::production_startup::Pid1LaunchImageV1;
use crate::tpm_nv_custody::physical::RetainedBrokerPhysicalTpmOwnerV1;

use super::super::{FloorErrorV1, FloorProfileV1};
use super::{AuthenticatedNvObservationV1, AuthenticatedTpmNvIoV1, sealed};

/// Transfers only the actual restricted Broker constructor's original inputs.
///
/// Fields and construction stay in this module. This is not a serializable
/// provisioning claim, a currentness witness, or an independently openable I/O
/// factory; the shared owner performs the same original admission itself.
pub(crate) struct BrokerPhysicalOpenV1<'open> {
    profile: FloorProfileV1,
    salt_name: [u8; 34],
    auth: &'open [u8; 32],
    locks: [ProtectedJournalLockCustodyV1; 2],
    launch_image: &'open Pid1LaunchImageV1,
}

impl<'open> BrokerPhysicalOpenV1<'open> {
    // Keep the purpose matcher below this already restricted physical seam;
    // neither this preamble nor matching DATA creates a measured helper phase.
    /// Checks the existing owner policy and fixed child-role sanity.
    ///
    /// # Errors
    /// Preserves owner enforcement and invalid child PID failures. It does not
    /// measure a helper, inspect its context or create a measured phase.
    pub(crate) fn require_helper_preamble(
        profile: FloorProfileV1,
        pid: u32,
    ) -> Result<(), FloorErrorV1> {
        super::confinement::require_helper_preamble(profile.endpoint(), pid)
    }

    /// Applies the original bounded Broker matcher to observed context DATA.
    ///
    /// # Errors
    /// Rejects excess bytes or a context other than this fixed helper role.
    /// Actual process/image/cgroup custody remains the physical owner's duty.
    pub(crate) fn require_helper_context(
        profile: FloorProfileV1,
        bytes: &[u8],
    ) -> Result<(), FloorErrorV1> {
        super::confinement::require_observed_helper_context(profile.endpoint(), bytes)
    }

    /// Moves the original inputs without allocation, validation or effects.
    pub(crate) fn into_parts(
        self,
    ) -> (
        FloorProfileV1,
        [u8; 34],
        &'open [u8; 32],
        [ProtectedJournalLockCustodyV1; 2],
        &'open Pid1LaunchImageV1,
    ) {
        (
            self.profile,
            self.salt_name,
            self.auth,
            self.locks,
            self.launch_image,
        )
    }
}

/// Keeps the original restricted sealed backend attached to the shared owner.
pub(in crate::recovery::journal::tpm_floor) struct PhysicalTpmNvIoV1 {
    owner: RetainedBrokerPhysicalTpmOwnerV1,
}

impl PhysicalTpmNvIoV1 {
    /// Forwards only negative custody observation to this SAME resident owner.
    #[cfg(feature = "online-nix")]
    pub(in crate::recovery::journal::tpm_floor) fn observe_online_postflight(
        &mut self,
    ) -> Result<(), FloorErrorV1> {
        self.owner.observe_online_postflight()
    }

    #[cfg(feature = "online-nix")]
    pub(in crate::recovery::journal::tpm_floor) fn retain_online(
        preparation: &crate::nix_service::floor::OnlinePhysicalInputPreparationV1<'_>,
        locks: [ProtectedJournalLockCustodyV1; 2],
        origin: crate::nix_service::floor::OnlineOriginV1,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Self {
        Self { owner: RetainedBrokerPhysicalTpmOwnerV1::retain_online(preparation, locks, origin, deadline) }
    }

    #[cfg(feature = "online-nix")]
    pub(in crate::recovery::journal::tpm_floor) fn admit_online(&mut self) -> Result<(), FloorErrorV1> {
        self.owner.admit_online()
    }

    pub(in crate::recovery::journal::tpm_floor) fn bind_cold_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        self.owner.bind_broker_cold_deadline(deadline)
    }

    pub(in crate::recovery::journal::tpm_floor) fn open(
        profile: FloorProfileV1,
        salt_name: [u8; 34],
        auth: &[u8; 32],
        locks: [ProtectedJournalLockCustodyV1; 2],
        launch_image: &Pid1LaunchImageV1,
    ) -> Result<Self, FloorErrorV1> {
        let binding = BrokerPhysicalOpenV1 {
            profile,
            salt_name,
            auth,
            locks,
            launch_image,
        };
        Ok(Self {
            owner: RetainedBrokerPhysicalTpmOwnerV1::open(binding)?,
        })
    }

    pub(in crate::recovery::journal::tpm_floor) fn retain(
        profile: FloorProfileV1,
        salt_name: [u8; 34],
        auth: &[u8; 32],
        locks: [ProtectedJournalLockCustodyV1; 2],
        launch_image: &Pid1LaunchImageV1,
    ) -> Self {
        let binding = BrokerPhysicalOpenV1 {
            profile,
            salt_name,
            auth,
            locks,
            launch_image,
        };
        Self {
            owner: RetainedBrokerPhysicalTpmOwnerV1::retain_broker(binding),
        }
    }

    pub(in crate::recovery::journal::tpm_floor) fn retain_funded_v2(
        profile: FloorProfileV1, salt_name: [u8; 34], auth: &[u8; 32],
        locks: [ProtectedJournalLockCustodyV1; 2], launch_image: &Pid1LaunchImageV1,
        payment: crate::tpm_nv_custody::physical::BrokerPhysicalPaymentOriginalV2,
    ) -> Self {
        let binding = BrokerPhysicalOpenV1 { profile, salt_name, auth, locks, launch_image };
        Self { owner: RetainedBrokerPhysicalTpmOwnerV1::retain_funded_broker_v2(binding, payment) }
    }

    pub(in crate::recovery::journal::tpm_floor) fn admit_funded_v2(
        &mut self, main: &aos_sandbox_controller_domain::Journal, sidecar: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), FloorErrorV1> {
        self.owner.admit_broker_with_controller_pair_v1(main, sidecar)
    }

    pub(in crate::recovery::journal::tpm_floor) fn finish_storage_initial_program_v2(
        &mut self, receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        main: &aos_sandbox_controller_domain::Journal, sidecar: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), FloorErrorV1> {
        self.owner.finish_storage_initial_program_v2(receiving, main, sidecar)
    }

    pub(in crate::recovery::journal::tpm_floor) fn controller_physical_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    { self.owner.controller_physical_failure_v1() }

    pub(in crate::recovery::journal::tpm_floor) fn controller_property_failure_view_v1(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>
    { self.owner.controller_property_failure_view_v1() }

    pub(in crate::recovery::journal::tpm_floor) fn observe_controller_floor_post_v1(&mut self)
        -> Result<(), FloorErrorV1>
    {
        self.owner.observe_controller_floor_post_v1()
    }

    pub(in crate::recovery::journal::tpm_floor) fn finish_controller_initial_once_v1(&mut self)
        -> Result<(), FloorErrorV1>
    {
        self.owner.finish_controller_initial_once_v1()
    }

    pub(in crate::recovery::journal::tpm_floor) fn admit(&mut self) -> Result<(), FloorErrorV1> {
        self.owner.admit_broker()
    }
}

impl sealed::Sealed for PhysicalTpmNvIoV1 {}

// Restricted concrete forwarding only; no new sealed transport or factory.
impl super::TpmNvExtendFloorBackendV1<PhysicalTpmNvIoV1> {
    pub(in crate::recovery::journal::tpm_floor) fn finish_storage_initial_program_v2(
        &mut self, receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        main: &aos_sandbox_controller_domain::Journal, sidecar: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), FloorErrorV1> {
        self.io.finish_storage_initial_program_v2(receiving, main, sidecar)
    }

    pub(in crate::recovery::journal::tpm_floor) fn controller_physical_failure_v1(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    { self.io.controller_physical_failure_v1() }

    pub(in crate::recovery::journal::tpm_floor) fn controller_property_failure_view_v1(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>
    { self.io.controller_property_failure_view_v1() }

    pub(in crate::recovery::journal::tpm_floor) fn observe_controller_floor_post_v1(&mut self)
        -> Result<(), FloorErrorV1>
    {
        self.io.observe_controller_floor_post_v1()
    }

    pub(in crate::recovery::journal::tpm_floor) fn finish_controller_initial_once_v1(&mut self)
        -> Result<(), FloorErrorV1>
    {
        self.io.finish_controller_initial_once_v1()
    }

    #[cfg(feature = "online-nix")]
    pub(in crate::recovery::journal::tpm_floor) fn observe_online_postflight(
        &mut self,
    ) -> Result<(), FloorErrorV1> {
        self.io.observe_online_postflight()
    }

    #[cfg(feature = "online-nix")]
    pub(in crate::recovery::journal::tpm_floor) fn bind_online_request_deadline(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        self.io.owner.bind_online_request_deadline(deadline)
    }

    pub(in crate::recovery::journal::tpm_floor) fn require_cold_retirement(
        &mut self,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), FloorErrorV1> {
        self.io.owner.require_broker_cold_retirement(deadline)
    }

    pub(in crate::recovery::journal::tpm_floor) fn clear_cold_deadline(&mut self) {
        self.io.owner.clear_broker_cold_deadline();
    }
}

impl AuthenticatedTpmNvIoV1 for PhysicalTpmNvIoV1 {
    fn begin_storage_primitive_v2(&mut self,
        receiving: &mut dyn super::super::storage_receiving::StorageFloorFinancialSourceV2,
        pair: &super::super::durable::controller_pair::HeldControllerFloorPairV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        self.owner.begin_storage_primitive_v2(receiving, pair.main(), pair.sidecar())
    }

    fn finish_storage_primitive_v2(&mut self,
        receiving: &mut dyn super::super::storage_receiving::StorageFloorFinancialSourceV2,
        pair: &super::super::durable::controller_pair::HeldControllerFloorPairV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        self.owner.finish_storage_primitive_v2(receiving, pair.main(), pair.sidecar())
    }

    fn read(&mut self, index: u32) -> Result<AuthenticatedNvObservationV1, FloorErrorV1> {
        self.owner.read(index)
    }

    fn extend(&mut self, index: u32, input: &[u8; 32]) -> Result<(), FloorErrorV1> {
        self.owner.extend(index, input)
    }
    fn read_with_pair_v1(
        &mut self,
        index: u32,
        pair: &super::super::durable::controller_pair::HeldControllerFloorPairV1<'_>,
    ) -> Result<AuthenticatedNvObservationV1, FloorErrorV1> {
        self.owner.read_with_controller_pair_v1(index, pair.main(), pair.sidecar())
    }

    fn extend_with_pair_v1(
        &mut self,
        index: u32,
        input: &[u8; 32],
        pair: &super::super::durable::controller_pair::HeldControllerFloorPairV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        self.owner.extend_with_controller_pair_v1(index, input, pair.main(), pair.sidecar())
    }

}

impl PhysicalTpmNvIoV1 {
    pub(in crate::recovery::journal::tpm_floor) fn retire_completed_initial_native_v1(
        &mut self,
        completed: &aos_sandbox_controller_domain::ControllerInitialSessionCompletedNativeBorrowV1<'_>,
        main: &aos_sandbox_controller_domain::Journal,
        sidecar: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), FloorErrorV1> {
        self.owner.retire_completed_initial_native_v1(completed, main, sidecar)
    }
}

impl super::TpmNvExtendFloorBackendV1<PhysicalTpmNvIoV1> {
    pub(in crate::recovery::journal::tpm_floor) fn retire_completed_initial_native_v1(
        &mut self,
        completed: &aos_sandbox_controller_domain::ControllerInitialSessionCompletedNativeBorrowV1<'_>,
        main: &aos_sandbox_controller_domain::Journal,
        sidecar: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), FloorErrorV1> {
        self.io.retire_completed_initial_native_v1(completed, main, sidecar)
    }
}
