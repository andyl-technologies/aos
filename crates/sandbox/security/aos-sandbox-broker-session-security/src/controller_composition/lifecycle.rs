//! Owns fixed Controller attestation recipes beside the protected session key.
//!
//! Public completions accept existing sealed challenges and authenticated
//! outcomes, never a caller-selected endpoint or signing scalar. Controller
//! retains query, boot-before, currentness, and operation decisions at their
//! original frontiers. Inventory-pair and Host-effect completions retain the
//! exact protected terminal loan through signing and typed construction. Other
//! recipes retain their existing currentness requirements.

use aos_sandbox_controller_domain::EffectFailure;
use aos_sandbox_controller_domain::lifecycle::{
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
use aos_sandbox_model::ObjectDigest;
use aos_linux_descriptors::boot::KernelBootId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
};

use crate::{
    DormantAuthenticatedBrokerSessionV1, ProtectedBrokerOutcomeCurrentV1,
    ProtectedBrokerOutcomeCurrentnessOwnerV1,
};

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
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventorySuccessorV1, LifecyclePhase6ErrorV1>
    {
        self.complete_domain_inventory_successor(
            challenge,
            boot,
            LifecycleBootBootstrapEndpointV1::Mount,
            initial,
            current,
            boot_before,
            currentness,
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
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1, LifecyclePhase6ErrorV1>
    {
        self.complete_domain_inventory_bootstrap(
            challenge,
            LifecycleBootBootstrapEndpointV1::Mount,
            initial,
            current,
            boot_before,
            currentness,
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
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventorySuccessorV1, LifecyclePhase6ErrorV1>
    {
        self.complete_domain_inventory_successor(
            challenge,
            boot,
            LifecycleBootBootstrapEndpointV1::Network,
            initial,
            current,
            boot_before,
            currentness,
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
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1, LifecyclePhase6ErrorV1>
    {
        self.complete_domain_inventory_bootstrap(
            challenge,
            LifecycleBootBootstrapEndpointV1::Network,
            initial,
            current,
            boot_before,
            currentness,
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
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedRuntimeInventorySuccessorV1, LifecyclePhase6ErrorV1> {
        let mut held = retain_current_inventory(self, current, currentness)?;
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            initial,
            current,
        )?;
        let signature = held
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let completed =
            LifecycleAuthenticatedRuntimeInventorySuccessorV1::from_fixed_endpoint_attestation(
                challenge, boot, initial, current, boot_after, signature,
            );
        finish_current_attestation(&mut held, completed)
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
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedRuntimeInventoryBootstrapV1, LifecyclePhase6ErrorV1> {
        let mut held = retain_current_inventory(self, current, currentness)?;
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            initial,
            current,
        )?;
        let signature = held
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let completed = (|| {
            let boot_after = KernelBootId::current()
                .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
                .into_bytes();
            if boot_before != boot_after {
                return Err(LifecyclePhase6ErrorV1::StaleAuthority);
            }
            LifecycleAuthenticatedRuntimeInventoryBootstrapV1::from_fixed_endpoint_attestation(
                challenge, initial, current, signature,
            )
        })();
        finish_current_attestation(&mut held, completed)
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
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedStorageInventorySuccessorV1, LifecyclePhase6ErrorV1> {
        let mut held = retain_current_inventory(self, current, currentness)?;
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Storage,
            initial,
            current,
        )?;
        let signature = held
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let completed =
            LifecycleAuthenticatedStorageInventorySuccessorV1::from_fixed_endpoint_attestation(
                challenge, boot, initial, current, signature,
            );
        finish_current_attestation(&mut held, completed)
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
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedStorageInventoryBootstrapV1, LifecyclePhase6ErrorV1> {
        let mut held = retain_current_inventory(self, current, currentness)?;
        let message = challenge.endpoint_signing_message(
            LifecycleBootBootstrapEndpointV1::Storage,
            initial,
            current,
        )?;
        let signature = held
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let completed =
            LifecycleAuthenticatedStorageInventoryBootstrapV1::from_fixed_endpoint_attestation(
                challenge, initial, current, signature,
            );
        finish_current_attestation(&mut held, completed)
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
        let program = aos_sandbox_model::ObjectDigest::from_bytes(receipt.program());
        let observation = aos_sandbox_model::ObjectDigest::from_bytes(receipt.observation());
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
        let program = aos_sandbox_model::ObjectDigest::from_bytes(receipt.program());
        let observation = aos_sandbox_model::ObjectDigest::from_bytes(receipt.observation());
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
        let mut held = retain_current_inventory(self, &inventory, currentness)?;

        let message = challenge.broker_effect_signing_message(
            LifecycleBootBootstrapEndpointV1::Host,
            &effect,
            &outcome,
            &inventory,
        )?;
        let signature = held
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;

        let completed = effect.observe_fixed_broker_effect(
            &challenge,
            LifecycleBootBootstrapEndpointV1::Host,
            &outcome,
            &inventory,
            signature,
        );
        finish_current_attestation(&mut held, completed)
    }

    /// Retains the exact adjacent Host Inventory attestation for genuine Stop.
    ///
    /// # Errors
    /// Returns the original currentness owner and retained failure if the
    /// canonical pair, protected writer, signer, native checks or posts refuse.
    pub fn complete_host_stop_inventory_retaining_v5(
        &mut self,
        challenge: LifecycleBootInventoryBootstrapChallengeV1,
        effect: CurrentLifecycleEffectV1<'_>,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
        inventory: &AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
        post: &mut crate::ExecutionClientPostOriginalV1,
        original: &mut crate::HostStopInventoryAttestationOriginalV5,
    ) -> (ProtectedBrokerOutcomeCurrentnessOwnerV1,
        Result<LifecycleEffectObservationV1, LifecyclePhase6ErrorV1>) {
        if original.entered || original.closed.is_some() {
            original.closed.get_or_insert(crate::BrokerSessionSecurityError::Currentness);
            return (currentness, Err(LifecyclePhase6ErrorV1::StaleAuthority));
        }
        original.entered = true;
        let mut held = match self.retain_execution_outcome_current_with_post_v1(currentness, post) {
            Ok(held) => { original.current = Some(Ok(())); held }
            Err((owner, cause)) => {
                original.current = Some(Err(cause));
                return (owner, Err(LifecyclePhase6ErrorV1::StaleAuthority));
            }
        };
        let primary = (|| {
            if held.authenticated_outcome() != inventory {
                return Err(LifecyclePhase6ErrorV1::StaleAuthority);
            }
            original.message = Some(challenge.broker_effect_signing_message(
                LifecycleBootBootstrapEndpointV1::Host, &effect, outcome, inventory));
            let message = original.message.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(LifecyclePhase6ErrorV1::StaleAuthority)?;
            held.revalidate_stop_inventory_attestation_v5(post, &mut original.before, false)
                .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
            let signature = held.sign_stop_inventory_attestation_v5(message, &mut original.signature)
                .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
            original.observation = Some(effect.observe_fixed_broker_effect(&challenge,
                LifecycleBootBootstrapEndpointV1::Host, outcome, inventory, signature));
            original.observation.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(LifecyclePhase6ErrorV1::StaleAuthority)
        })();
        // Once currentness entry succeeded its distinct after is owed even if
        // message formation, pre-sign checks, signing or canonical fold refused.
        let after = held.revalidate_stop_inventory_attestation_v5(post, &mut original.after, true);
        let owner = held.into_currentness_owner();
        let returned = match primary {
            Err(cause) => Err(cause),
            Ok(observation) if after.is_ok() => Ok(observation),
            Ok(_) => Err(LifecyclePhase6ErrorV1::StaleAuthority),
        };
        (owner, returned)
    }

    fn complete_domain_inventory_successor(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        boot: &CurrentLifecycleBootInventoryV1<'_>,
        endpoint: LifecycleBootBootstrapEndpointV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_before: [u8; 16],
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventorySuccessorV1, LifecyclePhase6ErrorV1>
    {
        let mut held = retain_current_inventory(self, current, currentness)?;
        let message = challenge.endpoint_signing_message(endpoint, initial, current)?;
        let signature = held
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let completed = (|| {
            let boot_after = KernelBootId::current()
                .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
                .into_bytes();
            if boot_before != boot_after {
                return Err(LifecyclePhase6ErrorV1::StaleAuthority);
            }
            LifecycleAuthenticatedBrokerDomainInventorySuccessorV1::from_fixed_endpoint_attestation(
                challenge, boot, endpoint, initial, current, signature,
            )
        })();
        finish_current_attestation(&mut held, completed)
    }

    fn complete_domain_inventory_bootstrap(
        &mut self,
        challenge: &LifecycleBootInventoryBootstrapChallengeV1,
        endpoint: LifecycleBootBootstrapEndpointV1,
        initial: &AuthenticatedBrokerMethodOutcomeV1,
        current: &AuthenticatedBrokerMethodOutcomeV1,
        boot_before: [u8; 16],
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1, LifecyclePhase6ErrorV1>
    {
        let mut held = retain_current_inventory(self, current, currentness)?;
        let message = challenge.endpoint_signing_message(endpoint, initial, current)?;
        let signature = held
            .sign_lifecycle_bootstrap_attestation(&message)
            .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
        let completed = (|| {
            let boot_after = KernelBootId::current()
                .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?
                .into_bytes();
            if boot_before != boot_after {
                return Err(LifecyclePhase6ErrorV1::StaleAuthority);
            }
            LifecycleAuthenticatedBrokerDomainInventoryBootstrapV1::from_fixed_endpoint_attestation(
                challenge, endpoint, initial, current, signature,
            )
        })();
        finish_current_attestation(&mut held, completed)
    }
}

// The authenticated inventory must be the exact terminal whose original
// writer and socket peer remain borrowed, rather than detached signed DATA.
fn retain_current_inventory<'session>(
    session: &'session mut DormantAuthenticatedBrokerSessionV1,
    inventory: &AuthenticatedBrokerMethodOutcomeV1,
    currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
) -> Result<ProtectedBrokerOutcomeCurrentV1<'session>, LifecyclePhase6ErrorV1> {
    let mut held = session
        .revalidate_broker_outcome(currentness)
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    require_current_inventory(&held, inventory)?;
    held.revalidate_lifecycle_attestation()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority)?;
    Ok(held)
}

// A failed typed construction still owes its final native check. Preserve its
// original error if both fail; a successful value escapes only after the post.
fn finish_current_attestation<T>(
    held: &mut ProtectedBrokerOutcomeCurrentV1<'_>,
    completed: Result<T, LifecyclePhase6ErrorV1>,
) -> Result<T, LifecyclePhase6ErrorV1> {
    let post = held
        .revalidate_lifecycle_attestation()
        .map_err(|_| LifecyclePhase6ErrorV1::StaleAuthority);
    let completed = completed?;
    post?;
    Ok(completed)
}

fn require_current_inventory(
    held: &ProtectedBrokerOutcomeCurrentV1<'_>,
    inventory: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<(), LifecyclePhase6ErrorV1> {
    if held.authenticated_outcome() != inventory {
        return Err(LifecyclePhase6ErrorV1::StaleAuthority);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
