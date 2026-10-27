//! Retains the same manual Source's fixed initial TPM-helper measurement.
//!
//! The native authenticated Source selects the closed initial purpose and pays
//! the shared image engine before pin or ELF IO. No private auth, process launch,
//! channel, NV observation or TPM effect is issued by this passive capture. Both
//! reached image posts remain owed after any later startup failure.

use aos_sandbox_broker::fixed_tpm_helper_image::{
    FixedTpmHelperPurposeV1, HelperImageAcquisitionOriginalV1, HelperImageRevalidationOriginalV1,
    MeasuredHelperImageV1,
};

use aos_sandbox_protocol::method46_provisioning::{
    Method46EndpointDataV1, Method46ProfileDataV1, Method46ProvisionDataErrorV1,
};

use super::*;

mod birth;
use aos_sandbox_broker::fixed_initial_tpm_helper_birth::FixedInitialTpmHelperBirthOriginalV1;
pub use birth::{Method46InitialTpmHelperBirthLoanV1, Method46InitialTpmHelperDrivingLoanV1};

pub(super) struct InitialTpmHelperImageOriginalV1 {
    acquisition: HelperImageAcquisitionOriginalV1,
    image: Option<MeasuredHelperImageV1>,
    birth: Option<Box<FixedInitialTpmHelperBirthOriginalV1>>,
    capture: Option<Result<(), ImmutableImageErrorV1>>,
    provision: Option<Result<(Method46ProfileDataV1, [u8; 34]), Method46ProvisionDataErrorV1>>,
    node_matches: Option<bool>,
    post: HelperImageRevalidationOriginalV1,
    post_result: Option<Result<(), ImmutableImageErrorV1>>,
    entered: bool,
    posted: bool,
}

impl InitialTpmHelperImageOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            acquisition: HelperImageAcquisitionOriginalV1::new(),
            image: None,
            birth: None,
            capture: None,
            provision: None,
            node_matches: None,
            post: HelperImageRevalidationOriginalV1::new(),
            post_result: None,
            entered: false,
            posted: false,
        }
    }

    pub(super) fn finish_post(&mut self) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.entered {
            return Ok(());
        }
        if self.posted {
            return Err(Method46InitialStartupClosedV1);
        }
        self.posted = true;
        self.post_result = Some(
            match self
                .image
                .as_ref()
                .or_else(|| self.birth.as_ref().map(|birth| birth.image_original_v1()))
            {
                Some(image) => image.revalidate_owed_retaining_v1(&mut self.post),
                None => self
                    .acquisition
                    .observe_available_held_once_v1(&mut self.post),
            },
        );
        if matches!(self.post_result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Method46InitialStartupClosedV1)
        }
    }
}

fn purpose(role: Method46InitialServiceRoleV1) -> FixedTpmHelperPurposeV1 {
    match role {
        Method46InitialServiceRoleV1::ControllerStorageClient => {
            FixedTpmHelperPurposeV1::InitialController
        }
        Method46InitialServiceRoleV1::StorageBroker => FixedTpmHelperPurposeV1::InitialStorage,
    }
}

fn receiving_demand(purpose: FixedTpmHelperPurposeV1) -> Option<ResourceVector> {
    // Acquisition and its final comparison use the shared bound. The separately
    // owed terminal post may need both full bounded reads after any failure.
    let acquisition = HelperImageAcquisitionOriginalV1::receiving_with_input_demand_v1(purpose)?;
    let post = HelperImageRevalidationOriginalV1::maximum_with_input_receiving_demand_v1()?;
    acquisition
        .checked_add(post)
        .ok()?
        .checked_add(ResourceVector::ZERO.with(D::OutputBytes, 512))
        .ok()
}

impl Method46InitialStartupOriginalV1 {
    /// Measures this Source's compiled initial helper and loader once.
    ///
    /// The actual admitted initial unit and captured credential owner precede
    /// this step. The same still-current Source pays all retained pin reads,
    /// measurements and independent terminal posts before native IO. No caller
    /// supplies a path, purpose, descriptor, secret or resource amount.
    ///
    /// The same captured public provisioning credential is decoded by the
    /// shared canonical codec, with this role's fixed endpoint and the genuine
    /// Source node. Its salt Name remains resident for the eventual HELLO.
    ///
    /// This establishes passive file custody only. It launches no child and
    /// cannot release private auth or authorize an initial TPM operation.
    ///
    /// # Errors
    /// Refuses missing Source, unit or credential admission, prior failure,
    /// ended custody, absent compiled image pins, insufficient funding, native
    /// IO, changed immutable images, busy custody or repeated entry. All reached
    /// native prefixes and both owed image posts remain with this owner.
    pub fn capture_initial_tpm_helper_image_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let origin = self
            .origin
            .as_ref()
            .ok_or_else(|| self.fail(First::Order))?;
        let role = origin.role;
        let node = origin.node;
        let body = self.body.as_ref().ok_or_else(|| self.fail(First::Order))?;
        let ready = body.unit.initial_admitted()
            && body
                .credentials
                .try_borrow()
                .is_ok_and(|credentials| credentials.admitted_before_post())
            && body
                .tpm_helper_image
                .try_borrow()
                .is_ok_and(|helper| !helper.entered);
        if !ready {
            return Err(self.fail(First::Order));
        }
        if !self
            .source
            .try_borrow()
            .is_ok_and(|source| source.require_current_v1().is_ok())
        {
            return Err(self.fail(First::Source));
        }
        let purpose = purpose(role);
        self.fund_additional(receiving_demand(purpose))?;
        let body = self.body.as_mut().ok_or(self.closed)?;
        let helper = body.tpm_helper_image.get_mut();
        helper.entered = true;
        let endpoint = match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => {
                Method46EndpointDataV1::ControllerStorageClient
            }
            Method46InitialServiceRoleV1::StorageBroker => Method46EndpointDataV1::StorageBroker,
        };
        helper.provision = Some(
            body.credentials
                .get_mut()
                .decode_helper_provision_data(endpoint),
        );
        helper.node_matches = helper
            .provision
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map(|(profile, _)| profile.node() == node);
        if helper.node_matches != Some(true) {
            return Err(self.fail(First::TpmHelperImage));
        }
        helper.capture = Some(helper.acquisition.capture_once(purpose));
        if matches!(helper.capture, Some(Ok(()))) {
            helper.image = helper.acquisition.take_completed_once();
        }
        if helper.image.is_none() {
            return Err(self.fail(First::TpmHelperImage));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::ManuallyDrop;

    #[test]
    fn absent_genuine_source_cannot_measure_or_pay_for_an_initial_helper() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(startup.capture_initial_tpm_helper_image_once_v1().is_err());

            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
            assert!(matches!(startup.first.get(), Some(First::Order)));
        }
    }

    #[test]
    fn failed_helper_post_cannot_suppress_independent_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));
        startup
            .body
            .as_mut()
            .unwrap()
            .tpm_helper_image
            .get_mut()
            .entered = true;

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        let helper = startup.body.as_ref().unwrap().tpm_helper_image.borrow();
        assert!(helper.posted);
        assert!(matches!(helper.post_result, Some(Err(_))));
        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        assert!(matches!(startup.first.get(), Some(First::TpmHelperImage)));
    }

    #[test]
    fn busy_helper_post_cannot_suppress_independent_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));
        let held = startup.body.as_ref().unwrap().tpm_helper_image.borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        assert!(matches!(startup.first.get(), Some(First::Order)));
        drop(held);
    }
}
