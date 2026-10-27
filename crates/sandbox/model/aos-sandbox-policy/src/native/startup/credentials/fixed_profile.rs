//! Preserves the fixed profile driver's independent location and name stages.
//!
//! Location's successful temporary closes before plain basename revalidation.
//! Neither stage substitutes a health check, physical witness or supplied path.

use crate::journal_keys::SIGNER_PINS_KEY;
use crate::native::journal::names::{RootFixedNameRecipeV1, RootFixedNameRoleV1,
    RootPolicyNameObservationOriginalV1 as Names};
use crate::signed_inputs::{PolicyDeploymentHeadV1, PolicyDeploymentInputsV1,
    PolicyDeploymentInputProfileV2, verify_policy_deployment_profile_data_v2};
use ed25519_dalek::VerifyingKey;
use super::super::{RootStartupJournalOriginalV1, RootStartupJournalErrorV1,
    StartupJournalStorageV1, OrdinaryStartupPurposeV1};
use super::RootStartupCredentialErrorV1 as ErrorV1;

impl RootStartupJournalOriginalV1 {
    /// Admits the exact fixed deployment profile through its existing native driver.
    ///
    /// # Errors
    /// Preserves verification before opening, both named-location checks, pins,
    /// protected hold, head succession and actual native refusals.
    pub fn admit_fixed_deployment_profile_v2(
        packet: &[u8], inputs: &PolicyDeploymentInputsV1<'_>,
        profile: &PolicyDeploymentInputProfileV2,
        verifying_key: &VerifyingKey, now_unix_seconds: i64,
    ) -> Result<PolicyDeploymentHeadV1, ErrorV1> {
        let verified = verify_policy_deployment_profile_data_v2(
            packet, inputs, profile, verifying_key, now_unix_seconds,
        ).map_err(ErrorV1::from)?;
        let mut owner = Self::new_fixed_admission_v1();
        if let Err(returned) = owner.open_ordinary_once_v1() {
            return Err(ErrorV1::Opening { returned, original: Box::new(owner.into_failure_v1()) });
        }
        if let Err(returned) = owner.require_fixed_profile_named_location_v1() {
            return Err(ErrorV1::Opening { returned, original: Box::new(owner.into_failure_v1()) });
        }
        let (key, generation) = owner.read_fixed_deployment_role_v1()?;
        if key != *verifying_key || generation != profile.signer_generation() {
            return Err(ErrorV1::StaleHead);
        }
        let admitted = owner.admit_deployment_head_after_entry_v1(packet, verified, &key, None)?;
        if let Err(returned) = owner.require_fixed_profile_named_location_v1() {
            return Err(ErrorV1::Opening { returned, original: Box::new(owner.into_failure_v1()) });
        }
        Ok(admitted)
    }

    fn read_fixed_deployment_role_v1(&mut self) -> Result<(VerifyingKey, u64), ErrorV1> {
        let authority = self.credential_authority_after_entry_v1(None)?;
        let pins = authority.get(SIGNER_PINS_KEY)?.ok_or(ErrorV1::StaleHead)?;
        let (deployment_generation, deployment, _, _) =
            aos_sandbox_ledger_replay::replay::root_genesis_pins::decode_policy_signer_pins_v1(pins)
                .map_err(|error| match error {
                    aos_sandbox_ledger_replay::replay::root_genesis_pins::PolicySignerPinsDataErrorV1::InvalidHead => ErrorV1::InvalidHead,
                    aos_sandbox_ledger_replay::replay::root_genesis_pins::PolicySignerPinsDataErrorV1::StaleHead => ErrorV1::StaleHead,
                })?;
        Ok((deployment, deployment_generation))
    }

    fn require_fixed_profile_named_location_v1(&mut self) -> Result<(), RootStartupJournalErrorV1> {
        let StartupJournalStorageV1::Ordinary(ordinary) = &mut self.storage else {
            return Err(RootStartupJournalErrorV1::Closed);
        };
        if ordinary.purpose != OrdinaryStartupPurposeV1::FixedAdmission || ordinary.finished {
            return Err(RootStartupJournalErrorV1::Closed);
        }
        let journal = ordinary.opening.journal_v1().ok_or(RootStartupJournalErrorV1::Closed)?;
        if ordinary.names.as_ref().is_some_and(|names| names.failure().is_some()) {
            return Err(RootStartupJournalErrorV1::Names);
        }
        ordinary.names = Some(Names::new());
        let location = ordinary.names.as_mut().ok_or(RootStartupJournalErrorV1::Closed)?;
        location.observe_once(journal, RootFixedNameRoleV1::Authority, RootFixedNameRecipeV1::Location)
            .map_err(|()| RootStartupJournalErrorV1::Names)?;
        // The old directory temporary ended before require_names entered.
        location.settle_positive_once_v1();
        ordinary.names = Some(Names::new());
        let names = ordinary.names.as_mut().ok_or(RootStartupJournalErrorV1::Closed)?;
        names.observe_once(journal, RootFixedNameRoleV1::Authority, RootFixedNameRecipeV1::PlainNames)
            .map_err(|()| RootStartupJournalErrorV1::Names)?;
        names.settle_positive_once_v1();
        Ok(())
    }
}
