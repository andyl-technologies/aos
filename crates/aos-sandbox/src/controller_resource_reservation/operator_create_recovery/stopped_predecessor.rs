//! Lends the actual first-local stopped predecessor to new residual enrollment.
//!
//! This historical custody is earned by the genuine newly authorized Recover,
//! full independent Root/Source comparison, joint4 and all original posts. It
//! never restores old C23 or claims and never grants Ready, a normal intake or
//! a Session. Fresh physical inventories, residual financing, new enrollment
//! and its own native disposal remain mandatory downstream conjunctions.

use super::*;

const CLOSED: OperatorCreateRecoveryClosedV1 = OperatorCreateRecoveryClosedV1;
use crate::journal::RecordNamespace;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox_core::{OperationId, ProjectId, SandboxId};
use aos_sandbox_protocol::domain_ledger::operation::{decode_operation, effect_key};
use aos_sandbox_protocol::domain_ledger::public_operation::OperationState;
use aos_sandbox_protocol::public_api::projection::PROJECTION_KEY_PREFIX;

/// Borrows genuine completed custody, without minting current service authority.
///
/// The private constructor is available only on the actual retained Recover
/// owner. The old signed Source/C/Root/Inventory observations remain resident
/// with that owner. Its original authorization bounds are never renewed.
#[doc(hidden)]
pub struct OperatorRecoveredStoppedCreateSeedV1<'completed> {
    pub(super) owner: &'completed OperatorCreateRecoveryOriginalV1,
    target: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
    source_terminal: [u8; 32],
}

pub(super) fn carrier_receiving_bytes_v1() -> Option<usize> {
    std::mem::size_of::<OperatorRecoveredStoppedCreateSeedV1<'_>>()
        .checked_mul(3)?
        .checked_add(
            std::mem::size_of::<super::finality::FirstLocalCompletedFieldsV1<'_>>()
                .checked_mul(3)?,
        )?
        .checked_add(
            std::mem::size_of::<aos_sandbox_protocol::domain_ledger::operation::OperationRecord>()
                .checked_mul(2)?,
        )?
        .checked_add(
            std::mem::size_of::<
                aos_sandbox_ledger_replay::source_policy_hold::SourceDomainPolicyHoldStateV1,
            >()
            .checked_mul(3)?,
        )?
        .checked_add(std::mem::size_of::<[u8; 20]>().checked_mul(2)?)
}

impl OperatorCreateRecoveryOriginalV1 {
    /// Lends a first-local stopped predecessor after exact positive recovery.
    ///
    /// This performs only allocation-free checks against the already paid,
    /// retained complete models and the same C/Source instance and cut. It
    /// cannot substitute a raw completed row for genuine native custody.
    ///
    /// # Errors
    /// Refuses failed/missing finality, another Source/C original, any later
    /// Source cut, additional operations/resources, active execution/attachment
    /// families, or more than the sole first-local stopped Sandbox projection.
    #[doc(hidden)]
    pub fn borrow_first_local_stopped_predecessor_v1<'completed>(
        &'completed self,
        controller: &Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        inventory_journal: &'completed Journal,
        inventory_outcome: &'completed aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        inventory: &'completed aos_sandbox_protocol::ValidatedStorageInventory,
    ) -> Result<OperatorRecoveredStoppedCreateSeedV1<'completed>, OperatorCreateRecoveryClosedV1>
    {
        let completed = self.first_local_completed_fields_v1(controller)?;
        let fields = completed.resources.fields_v1();
        if fields.mode != aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningModeDataV1::CreateStopped {
            return Err(CLOSED);
        }
        let (nonce, binding) = self
            .storage
            .require_root_inventory_data_v1(inventory_journal, inventory_outcome)
            .map_err(|_| CLOSED)?;
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } =
            inventory_outcome.result()
        else {
            return Err(CLOSED);
        };
        use sha2::Digest as _;
        let [workspace] = inventory.workspaces() else {
            return Err(CLOSED);
        };
        if nonce != completed.query.nonce || binding != completed.query.inventory_session
            || aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::
                finality_inventory_commitment_v1(inventory_outcome.canonical_packet()) != completed.query.inventory
            || inventory.encoded_response_digest_v1() != <[u8; 32]>::from(sha2::Sha256::digest(exact_body))
            || workspace.creation_operation_id() != fields.parent.as_bytes()
            || !inventory.operator_repair_commits().is_empty() {
            return Err(CLOSED);
        }
        self.source.require_first_local_source_v1(
            fields.parent,
            completed.source_terminal,
            source,
        )?;
        require_first_local_controller_family_data_v2(controller, fields.parent,
            fields.publication_operation, completed.operation, &completed.projection_key)?;
        Ok(OperatorRecoveredStoppedCreateSeedV1 {
            owner: self,
            target: fields.parent,
            project: fields.project,
            sandbox: fields.sandbox,
            source_terminal: completed.source_terminal,
        })
    }
}

impl OperatorRecoveredStoppedCreateSeedV1<'_> {
    /// Returns the historical Create identity, without granting its old scope.
    #[must_use]
    pub const fn target_v1(&self) -> OperationId {
        self.target
    }

    /// Returns the exact recovered project comparison identity.
    #[must_use]
    pub const fn project_v1(&self) -> ProjectId {
        self.project
    }

    /// Returns the sole recovered stopped Sandbox comparison identity.
    #[must_use]
    pub const fn sandbox_v1(&self) -> SandboxId {
        self.sandbox
    }

    pub(crate) fn native_original_v1(
        &self,
    ) -> Result<&ControllerOperatorRecoverReceivingV1, ResourceReservationErrorV1> {
        self.owner.completed_native_for_resumption_v1()
    }

    pub(crate) fn profile_original_v1(&self) -> &ProductionControllerNormalRootProfileV1 {
        &self.owner.profile
    }

    pub(crate) fn completed_resident_demand_v1(
        &self,
        controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.owner.completed_read_resident_demand_v1(controller)
    }

    pub(crate) fn require_same_current_source_v1(
        &self,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        self.owner
            .source
            .require_first_local_source_v1(self.target, self.source_terminal, source)
    }

    pub(crate) fn require_same_completed_v1(
        &self,
        bank: &ControllerResourceBankOpeningV1,
        controller: &Journal,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.owner
            .completed_metadata_operation_v1(controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        bank.require_operator_recover_disposed_v1(self.native_original_v1()?, controller, profile)
    }

    pub(crate) fn original_horizon_v1(
        &self,
    ) -> Result<(RawPairedClockSample, u64, i64), OperatorCreateRecoveryClosedV1> {
        let original = self
            .owner
            .horizon
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(CLOSED)?;
        Ok((
            original.original,
            original.cutoff,
            original.expires_wall_seconds,
        ))
    }
}

fn require_first_local_controller_family_data_v2(
    controller: &Journal,
    parent: OperationId,
    publication: OperationId,
    recovery: OperationId,
    projection_key: &[u8],
) -> Result<(), OperatorCreateRecoveryClosedV1> {
        let mut operations = 0usize;
        let mut effects = 0usize;
        let mut projections = 0usize;
        let parent_effect = effect_key(parent, 0);
        let child_effect = effect_key(publication, 0);
        for (namespace, key, value) in controller.all_records() {
            match namespace {
                RecordNamespace::Operation => {
                    if key != parent.as_bytes()
                        && key != publication.as_bytes()
                        && key != recovery.as_bytes()
                    {
                        return Err(CLOSED);
                    }
                    if decode_operation(value).map_err(|_| CLOSED)?.state()
                        != OperationState::Succeeded
                    {
                        return Err(CLOSED);
                    }
                    operations = operations.checked_add(1).ok_or(CLOSED)?;
                }
                RecordNamespace::Effect => {
                    if key != parent_effect.as_slice() && key != child_effect.as_slice() {
                        return Err(CLOSED);
                    }
                    effects = effects.checked_add(1).ok_or(CLOSED)?;
                }
                RecordNamespace::DesiredState => {
                    if key.starts_with(PROJECTION_KEY_PREFIX) {
                        if key != projection_key {
                            return Err(CLOSED);
                        }
                        projections = projections.checked_add(1).ok_or(CLOSED)?;
                    }
                }
                // These are retained administrative/authority/account and
                // comparison families already covered by full Root C replay.
                // Historical inventory rows are never fresh physical proof.
                RecordNamespace::Idempotency
                | RecordNamespace::OwnershipGate
                | RecordNamespace::AuthorityPublication
                | RecordNamespace::PublisherAuthority
                | RecordNamespace::PublisherPolicy
                | RecordNamespace::PublisherIngress
                | RecordNamespace::RuntimeAuthority
                | RecordNamespace::SandboxSpec
                | RecordNamespace::ControllerIdentity
                | RecordNamespace::GlobalCapacityReservation
                | RecordNamespace::BrokerSessionTraffic
                | RecordNamespace::CliAuthorizationTime
                | RecordNamespace::OperatorRecovery
                | RecordNamespace::PublicOperationAuthorization
                | RecordNamespace::PublicCapabilityBootstrap
                | RecordNamespace::ControllerResourceReservation
                | RecordNamespace::CreateStorageHistory
                | RecordNamespace::ControllerPolicyHold
                | RecordNamespace::SourceDomainPolicyHold
                | RecordNamespace::StorageResourceInventory
                | RecordNamespace::NetworkResourceInventory
                | RecordNamespace::HostCatalogReconciliation => {}
                // The initial supported subset has no active or historical
                // execution, attachment, view, snapshot, Nix or worker flight.
                _ => return Err(CLOSED),
            }
        }
        if operations != 3 || effects != 2 || projections != 1 {
            return Err(CLOSED);
        }
    Ok(())
}

impl OperatorCreateRecoveryOriginalV1 {
    // The new maintenance has already paid full C/Source schema replay. This
    // consumes historical fields of the actual same-C completed Recover only;
    // it never invokes that owner's expired R clock or native read interval.
    pub(crate) fn require_cold_controller_family_for_maintenance_data_v2(
        &self,
        controller: &Journal,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        let completed = self.first_local_completed_fields_v1(controller)?;
        let fields = completed.resources.fields_v1();
        if fields.mode != aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningModeDataV1::CreateStopped {
            return Err(CLOSED);
        }
        require_first_local_controller_family_data_v2(controller, fields.parent,
            fields.publication_operation, completed.operation, &completed.projection_key)
    }

    pub(crate) fn require_cold_storage_for_maintenance_data_v2(
        &self,
        controller: &Journal,
        inventory: &aos_sandbox_protocol::ValidatedStorageInventory,
    ) -> Result<(), OperatorCreateRecoveryClosedV1> {
        let completed = self.first_local_completed_fields_v1(controller)?;
        let fields = completed.resources.fields_v1();
        let [workspace] = inventory.workspaces() else { return Err(CLOSED); };
        if workspace.creation_operation_id() != fields.parent.as_bytes()
            || !inventory.operator_repair_commits().is_empty() {
            return Err(CLOSED);
        }
        Ok(())
    }
}
