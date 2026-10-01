//! Restricted Broker entry to the single shared retained physical TPM owner.
//!
//! Only the existing floor composition opens this facade. Its opaque opening
//! capsule transfers the actual two lock loans and original PID1 reference;
//! neither scalar DATA nor an injected transport can construct the shared owner.
//! The facade keeps the original sealed backend API and owns only that owner.

use aos_sandbox::ProtectedJournalLockCustodyV1;

use crate::production_startup::Pid1LaunchImageV1;
use crate::tpm_nv_custody::physical::RetainedPhysicalTpmOwnerV1;

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
    owner: RetainedPhysicalTpmOwnerV1<'static, 'static, 'static>,
}

impl PhysicalTpmNvIoV1 {
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
            owner: RetainedPhysicalTpmOwnerV1::open(binding)?,
        })
    }
}

impl sealed::Sealed for PhysicalTpmNvIoV1 {}

impl AuthenticatedTpmNvIoV1 for PhysicalTpmNvIoV1 {
    fn read(&mut self, index: u32) -> Result<AuthenticatedNvObservationV1, FloorErrorV1> {
        self.owner.read(index)
    }

    fn extend(&mut self, index: u32, input: &[u8; 32]) -> Result<(), FloorErrorV1> {
        self.owner.extend(index, input)
    }
}
