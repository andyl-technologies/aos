//! Owns fixed Controller attestation recipes beside the protected session key.
//!
//! Public completions accept existing sealed challenges and authenticated
//! outcomes, never a caller-selected endpoint or signing scalar. Controller
//! retains query, boot-before, currentness, and operation decisions at their
//! original frontiers. The original released-currentness signing interval
//! remains unchanged; these recipes establish no additional freshness proof.

use aos_sandbox::EffectFailure;
use aos_sandbox::lifecycle::{
    CurrentLifecycleBootInventoryV1, CurrentLifecycleEffectV1, CurrentLifecycleOperationV1,
    LifecycleAtomicDatasetSnapshotPlanV1, LifecycleAuthenticatedAtomicStorageSuccessorV1,
    LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1,
    LifecycleAuthenticatedBrokerDomainInventorySuccessorV1, LifecycleAuthenticatedBrokerEffectV1,
    LifecycleAuthenticatedRuntimeInventoryBootstrapV1,
    LifecycleAuthenticatedRuntimeInventorySuccessorV1,
    LifecycleAuthenticatedStorageInventoryBootstrapV1,
    LifecycleAuthenticatedStorageInventorySuccessorV1, LifecycleAuthenticatedStorageReadbackV1,
    LifecycleBootBootstrapEndpointV1, LifecycleBootInventoryBootstrapChallengeV1,
    LifecycleEffectObservationV1, LifecyclePhase6ErrorV1,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};

use crate::{DormantAuthenticatedBrokerSessionV1, ProtectedBrokerOutcomeCurrentnessOwnerV1};

impl DormantAuthenticatedBrokerSessionV1 {
    /// Completes the fixed Mount successor attestation from the original inventory pair.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_mount_inventory_successor(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &CurrentLifecycleBootInventoryV1<'_>,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_before: [u8; 16],
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventorySuccessorV1, LifecyclePhase6ErrorV1>
    {
        self.complete_domain_inventory_successor(
            challenge,
            boot,
            LifecycleBootBootstrapEndpointV1::Mount,
            initial,
            current,
            boot_before,
        )
    }

    /// Completes the fixed Mount bootstrap attestation from the original inventory pair.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_mount_inventory_bootstrap(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_before: [u8; 16],
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1, LifecyclePhase6ErrorV1>
    {
        self.complete_domain_inventory_bootstrap(
            challenge,
            LifecycleBootBootstrapEndpointV1::Mount,
            initial,
            current,
            boot_before,
        )
    }

    /// Completes the fixed Network successor attestation from the original inventory pair.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_network_inventory_successor(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &CurrentLifecycleBootInventoryV1<'_>,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_before: [u8; 16],
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventorySuccessorV1, LifecyclePhase6ErrorV1>
    {
        self.complete_domain_inventory_successor(
            challenge,
            boot,
            LifecycleBootBootstrapEndpointV1::Network,
            initial,
            current,
            boot_before,
        )
    }

    /// Completes the fixed Network bootstrap attestation from the original inventory pair.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_network_inventory_bootstrap(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_before: [u8; 16],
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1, LifecyclePhase6ErrorV1>
    {
        self.complete_domain_inventory_bootstrap(
            challenge,
            LifecycleBootBootstrapEndpointV1::Network,
            initial,
            current,
            boot_before,
        )
    }

    /// Completes the fixed Host successor after the original upper boot comparison.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_host_inventory_successor(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &CurrentLifecycleBootInventoryV1<'_>,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_after: [u8; 16],
    ) -> Result<LifecycleAuthenticatedRuntimeInventorySuccessorV1, LifecyclePhase6ErrorV1> {
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            initial,
            current,
        )?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        LifecycleAuthenticatedRuntimeInventorySuccessorV1::from_fixed_endpoint_attestation(
            challenge, boot, initial, current, boot_after, signature,
        )
    }

    /// Completes the fixed Host bootstrap with its original post-sign boot comparison.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_host_inventory_bootstrap(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_before: [u8; 16],
    ) -> Result<LifecycleAuthenticatedRuntimeInventoryBootstrapV1, LifecyclePhase6ErrorV1> {
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            initial,
            current,
        )?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let boot_after = KernelBootId::current()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        LifecycleAuthenticatedRuntimeInventoryBootstrapV1::from_fixed_endpoint_attestation(
            challenge, initial, current, signature,
        )
    }

    /// Completes the fixed Storage successor from the original complete inventory pair.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_storage_inventory_successor(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &CurrentLifecycleBootInventoryV1<'_>,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleAuthenticatedStorageInventorySuccessorV1, LifecyclePhase6ErrorV1> {
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Storage,
            initial,
            current,
        )?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        LifecycleAuthenticatedStorageInventorySuccessorV1::from_fixed_endpoint_attestation(
            challenge, boot, initial, current, signature,
        )
    }

    /// Completes the fixed Storage bootstrap from the original complete inventory pair.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_storage_inventory_bootstrap(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleAuthenticatedStorageInventoryBootstrapV1, LifecyclePhase6ErrorV1> {
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Storage,
            initial,
            current,
        )?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        LifecycleAuthenticatedStorageInventoryBootstrapV1::from_fixed_endpoint_attestation(
            challenge, initial, current, signature,
        )
    }

    /// Completes the fixed Storage readback for the original authenticated effect.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_storage_effect_readback(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        effect: &LifecycleAuthenticatedBrokerEffectV1,
        apply: &AuthenticatedBrokerMethodOutcomeV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleAuthenticatedStorageReadbackV1, LifecyclePhase6ErrorV1> {
        let message = challenge.storage_effect_signing_message(apply, outcome)?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        LifecycleAuthenticatedStorageReadbackV1::from_fixed_endpoint_attestation(
            challenge, effect, apply, outcome, signature,
        )
    }

    /// Completes the fixed adjacent Storage group and successor attestation.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_controller_atomic_storage_adjacent(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        program: ObjectDigest,
        observation: ObjectDigest,
        predecessor: &AuthenticatedBrokerMethodOutcomeV1,
        group: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleAuthenticatedAtomicStorageSuccessorV1, LifecyclePhase6ErrorV1> {
        let message =
            challenge.storage_atomic_snapshot_signing_message(predecessor, group, current)?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let successor =
            LifecycleAuthenticatedAtomicStorageSuccessorV1::from_fixed_endpoint_attestation(
                challenge,
                operation,
                plan,
                program,
                observation,
                predecessor,
                group,
                current,
                signature,
            )?;
        Ok(successor)
    }

    /// Completes only the original historical Storage trio attestation.
    ///
    /// # Errors
    /// Returns the original unsuccessful-group, receipt, adjacency, protected signing, or successor failure.
    pub fn complete_controller_historical_atomic_storage_adjacent(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        predecessor: &AuthenticatedBrokerMethodOutcomeV1,
        group: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleAuthenticatedAtomicStorageSuccessorV1, EffectFailure> {
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = group.result() else {
            return Err(EffectFailure::Permanent(
                "historical Storage group was not successful".to_owned(),
            ));
        };
        let receipt = aos_sandbox_protocol::decode_atomic_storage_snapshot_response(exact_body)
            .map_err(|_| {
                EffectFailure::Permanent("historical Storage receipt is invalid".to_owned())
            })?;
        let program = aos_sandbox_core::ObjectDigest::from_bytes(receipt.program());
        let observation = aos_sandbox_core::ObjectDigest::from_bytes(receipt.observation());
        let message = challenge
            .storage_atomic_snapshot_signing_message(predecessor, group, current)
            .map_err(|_| {
                EffectFailure::Permanent("historical Storage trio is not adjacent".to_owned())
            })?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| {
                EffectFailure::Retryable(
                    "Storage fixed endpoint attestation is unavailable".to_owned(),
                )
            })?;
        let successor =
            LifecycleAuthenticatedAtomicStorageSuccessorV1::from_fixed_endpoint_attestation(
                challenge,
                operation,
                plan,
                program,
                observation,
                predecessor,
                group,
                current,
                signature,
            )
            .map_err(|_| {
                EffectFailure::Permanent("historical Storage successor is invalid".to_owned())
            })?;
        Ok(successor)
    }

    /// Completes only the fixed historical Storage group status attestation.
    ///
    /// # Errors
    /// Returns the original unsuccessful-group, receipt, status, protected signing, or successor failure.
    pub fn complete_controller_historical_atomic_storage_status(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        operation: &CurrentLifecycleOperationV1<'_>,
        plan: &LifecycleAtomicDatasetSnapshotPlanV1,
        predecessor: &AuthenticatedBrokerMethodOutcomeV1,
        group: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<LifecycleAuthenticatedAtomicStorageSuccessorV1, EffectFailure> {
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = group.result() else {
            return Err(EffectFailure::Permanent(
                "historical Storage group was not successful".to_owned(),
            ));
        };
        let receipt = aos_sandbox_protocol::decode_atomic_storage_snapshot_response(exact_body)
            .map_err(|_| {
                EffectFailure::Permanent("historical Storage receipt is invalid".to_owned())
            })?;
        let program = aos_sandbox_core::ObjectDigest::from_bytes(receipt.program());
        let observation = aos_sandbox_core::ObjectDigest::from_bytes(receipt.observation());
        let message = challenge
            .storage_atomic_snapshot_status_signing_message(predecessor, group, current)
            .map_err(|_| {
                EffectFailure::Permanent("Storage status cannot attest the group".to_owned())
            })?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| {
                EffectFailure::Retryable(
                    "Storage fixed endpoint status attestation is unavailable".to_owned(),
                )
            })?;
        let successor =
            LifecycleAuthenticatedAtomicStorageSuccessorV1::from_fixed_endpoint_status_attestation(
                challenge,
                operation,
                plan,
                program,
                observation,
                predecessor,
                group,
                current,
                signature,
            )
            .map_err(|_| {
                EffectFailure::Permanent("Storage status does not prove the group".to_owned())
            })?;
        Ok(successor)
    }

    /// Completes the original owned Host effect and inventory frame after its exact recheck.
    ///
    /// # Errors
    /// Returns the original challenge, protected attestation, or lifecycle binding failure.
    pub fn complete_controller_host_effect<'lifecycle>(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        effect: CurrentLifecycleEffectV1<'lifecycle>,
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        inventory: AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1> {
        let mut current = self
            .revalidate_broker_outcome(currentness)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        current
            .revalidate()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        drop(current);

        let message = challenge.broker_effect_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            &effect,
            &outcome,
            &inventory,
        )?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;

        effect.observe_fixed_broker_effect(
            &challenge,
            LifecycleBootBootstrapEndpointV1::Host,
            &outcome,
            &inventory,
            signature,
        )
    }

    fn complete_domain_inventory_successor(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &CurrentLifecycleBootInventoryV1<'_>,
        endpoint: LifecycleBootBootstrapEndpointV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_before: [u8; 16],
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventorySuccessorV1, LifecyclePhase6ErrorV1>
    {
        let message = challenge.endpoint_signing_message(endpoint, initial, current)?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let boot_after = KernelBootId::current()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        LifecycleAuthenticatedBrokerDomainInventorySuccessorV1::from_fixed_endpoint_attestation(
            challenge, boot, endpoint, initial, current, signature,
        )
    }

    fn complete_domain_inventory_bootstrap(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        endpoint: LifecycleBootBootstrapEndpointV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_before: [u8; 16],
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1, LifecyclePhase6ErrorV1>
    {
        let message = challenge.endpoint_signing_message(endpoint, initial, current)?;
        let signature = self
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let boot_after = KernelBootId::current()
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
            .into_bytes();
        if boot_before != boot_after {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1::from_fixed_endpoint_attestation(
            challenge, endpoint, initial, current, signature,
        )
    }
}
