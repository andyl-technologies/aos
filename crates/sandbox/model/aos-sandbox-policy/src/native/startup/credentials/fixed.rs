//! Drives the existing one-off ordinary fixed credential entry points.
//!
//! This purpose differs from held startup: opening precedes each old semantic
//! body, without an added owned-name probe or admitted-pin field requirement.
//! Failed openings move their whole actual owner into the returned diagnostic.

use super::super::RootStartupJournalOriginalV1;
use super::RootStartupCredentialErrorV1 as ErrorV1;
use crate::signed_inputs::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, verify_policy_deployment_head_v1,
};
use ed25519_dalek::VerifyingKey;

impl RootStartupJournalOriginalV1 {
    /// Admits both signer pins using the existing one-off fixed ordinary opening.
    ///
    /// # Errors
    /// Preserves opening custody, pin, hold, state, append and readback refusals.
    pub fn admit_fixed_signer_pins_v1(
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), ErrorV1> {
        let mut owner = Self::new_fixed_admission_v1();
        if let Err(returned) = owner.open_ordinary_once_v1() {
            return Err(ErrorV1::Opening {
                returned,
                original: Box::new(owner.into_failure_v1()),
            });
        }
        owner.admit_signer_pins_after_entry_v1(
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            None,
        )
    }

    /// Verifies then admits the head through its original one-off ordinary route.
    ///
    /// # Errors
    /// Preserves verification before opening, then hold, succession and native refusals.
    pub fn admit_fixed_deployment_head_v1(
        packet: &[u8],
        inputs: &PolicyDeploymentInputsV1<'_>,
        verifying_key: &VerifyingKey,
        now_unix_seconds: i64,
    ) -> Result<PolicyDeploymentHeadV1, ErrorV1> {
        let verified =
            verify_policy_deployment_head_v1(packet, inputs, verifying_key, now_unix_seconds)
                .map_err(ErrorV1::from)?;
        let mut owner = Self::new_fixed_admission_v1();
        if let Err(returned) = owner.open_ordinary_once_v1() {
            return Err(ErrorV1::Opening {
                returned,
                original: Box::new(owner.into_failure_v1()),
            });
        }
        owner.admit_deployment_head_after_entry_v1(packet, verified, verifying_key, None)
    }

    /// Admits the optional Cache pin through its original fixed ordinary route.
    ///
    /// # Errors
    /// Preserves opening custody, signer separation, rotation and native refusals.
    pub fn admit_fixed_cache_pin_v1(
        credential: Option<&[u8]>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), ErrorV1> {
        let mut owner = Self::new_fixed_admission_v1();
        if let Err(returned) = owner.open_ordinary_once_v1() {
            return Err(ErrorV1::Opening {
                returned,
                original: Box::new(owner.into_failure_v1()),
            });
        }
        owner.admit_cache_pin_after_entry_v1(
            credential,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            None,
        )
    }

    /// Admits the optional Controller pin through its original fixed ordinary route.
    ///
    /// # Errors
    /// Preserves opening custody, signer separation, rotation and native refusals.
    pub fn admit_fixed_controller_pin_v1(
        credential: Option<&[u8]>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), ErrorV1> {
        let mut owner = Self::new_fixed_admission_v1();
        if let Err(returned) = owner.open_ordinary_once_v1() {
            return Err(ErrorV1::Opening {
                returned,
                original: Box::new(owner.into_failure_v1()),
            });
        }
        owner.admit_controller_pin_after_entry_v1(
            credential,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            None,
        )
    }

    /// Admits the optional Source pin through its original fixed ordinary route.
    ///
    /// # Errors
    /// Preserves opening custody, signer separation, rotation and native refusals.
    pub fn admit_fixed_source_pin_v1(
        credential: Option<&[u8]>,
        deployment_generation: u64,
        deployment_key: &VerifyingKey,
        project_generation: u64,
        project_key: &VerifyingKey,
    ) -> Result<(), ErrorV1> {
        let mut owner = Self::new_fixed_admission_v1();
        if let Err(returned) = owner.open_ordinary_once_v1() {
            return Err(ErrorV1::Opening {
                returned,
                original: Box::new(owner.into_failure_v1()),
            });
        }
        owner.admit_source_pin_after_entry_v1(
            credential,
            deployment_generation,
            deployment_key,
            project_generation,
            project_key,
            None,
        )
    }
}
