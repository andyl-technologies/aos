//! Rechecks committed native custody against exact archived common journals.
//!
//! Source keeps its native read fence armed while the concrete archive validator
//! compares Runtime7 input/operation ancestry and the actual Control model.
//! Fixed identities retain correspondence only; they create no final context,
//! fresh ACK, readiness, activation or another transaction.

use super::*;
use crucible_node_transport::client::CnpController;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OriginalRestorationNativeContinuationIdentity {
    pub(super) held_reference: [u8; 32],
    pub(super) inventory: [u8; 32],
    pub(super) cursor: crucible_node_format::Position,
}

/// Lends a completed target to its same actual native node for inspection.
///
/// The installed window alone creates this nonconstructible borrowed argument.
/// It never renews Query, a phase claim or a completed transport operation.
#[must_use = "inspect the same runtime-owned node without extracting its controller"]
pub struct OriginalRestorationNodeContinuationInspection<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    plan: &'a InstalledConformancePlan,
    activation: &'a ActivationRecord,
    selected: usize,
    installed_scope: Option<&'a crate::node_contract::OriginalLineageNativeScope>,
    continuation: Option<super::installed_context::OriginalCompleteNativeFenceStep<'a>>,
}

impl OriginalRestorationNodeContinuationInspection<'_> {
    pub(crate) fn ticket_data(&self) -> Result<&CompleteOriginalNativeTicket, RuntimeError> {
        self.target()?.ticket_data()
    }

    pub(crate) fn source_data(&self) -> Result<&Rc<PacketCompleteSemanticSource>, RuntimeError> {
        self.window
            .sources
            .get(self.selected)
            .ok_or(RuntimeError::ForeignAuthority)
    }

    pub(crate) fn authenticate_runtime_data(
        &self,
        runtime: &ConformanceRuntime,
    ) -> Result<(), RuntimeError> {
        self.target()?.authenticate_original_target_data(
            self.plan,
            self.source_data()?,
            runtime,
            &self.window.archive,
            self.activation,
        )?;
        self.authenticate_current()
    }

    fn target(&self) -> Result<&CompleteOriginalRestorationTransactionTarget, RuntimeError> {
        self.window
            .targets
            .get(self.selected)
            .and_then(OnceCell::get)
            .ok_or(RuntimeError::OwnerUnavailable)
    }

    fn authenticate_current(&self) -> Result<(), RuntimeError> {
        if let Some(scope) = self.installed_scope {
            return self
                .window
                .authenticate_original_complete_identity_data(self.plan, scope);
        }
        self.window.authenticate_original_completed_member_data(
            self.target()?,
            self.source_data()?,
            self.plan,
            self.activation,
        )?;
        self.window
            .authenticate_original_runtime_member_current_data(&self.activation.world_binding_hash)
    }

    pub(crate) fn inspect_original_controller_data(
        self,
        controller: &CnpController,
        read_owner: *const (),
    ) -> Result<(), RuntimeError> {
        self.authenticate_current()?;
        let target = self.target()?;
        let source = self.source_data()?;
        if let Some(scope) = self.installed_scope {
            if let Some(phase) =
                self.window.activation_phases[self.selected].verified_phase_data()?
            {
                return self.window.with_original_activated_node_custody_data(
                    self.selected,
                    source.as_ref(),
                    controller,
                    read_owner,
                    phase,
                    |_, _, _| match self.continuation {
                        Some(next) => next.inspect_next(),
                        None => Err(RuntimeError::OwnerUnavailable),
                    },
                    || {
                        self.window
                            .authenticate_original_complete_identity_data(self.plan, scope)
                    },
                );
            }
        }
        let node = self
            .window
            .node_rows
            .get()
            .and_then(|rows| rows.get(self.selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        node.authenticate_original_owner_data(source, read_owner)?;
        let signer = node.signer.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let validation = target
            .ticket_data()?
            .native_restoration_construction_data()?
            .original_archived_validation_construction_data()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let inspection = OriginalRestorationTransactionInspection {
            window: self.window,
            target,
            source,
            plan: self.plan,
            activation: self.activation,
            installed_scope: self.installed_scope,
        };
        let inputs = inspection.original_inputs_data()?;
        let uploaded = target.completed_upload_data()?;
        let uploaded = uploaded.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let evidence = source.original_verified_restore_transfer_commit_data(
            controller,
            uploaded,
            signer,
            &inspection,
        )?;
        self.window.archive.original_runtime_record_data()?;
        let maximum_record = self
            .window
            .archive
            .original_archive_limits_data()?
            .state
            .maximum_record_bytes;
        let other = self
            .window
            .observed_other_retained
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let mut observed = None;
        evidence.authenticate_held_continuation_data(
            &inputs,
            signer,
            uploaded,
            |held, reference| {
                self.window.authenticate_original_import_boundary_data(
                    self.selected,
                    source,
                    held,
                    validation,
                    maximum_record,
                    other,
                )?;
                // Every later inspection repeats the actual receipt/MAC chain and
                // model predicates before comparing these correspondence identities.
                observed = Some(OriginalRestorationNativeContinuationIdentity {
                    held_reference: reference_identity(reference),
                    inventory: hash_identity(&held.inventory_hash),
                    cursor: held.local_cursor,
                });
                if let Some(continuation) = self.continuation {
                    continuation.inspect_next()?;
                }
                Ok(())
            },
            || self.authenticate_current(),
        )?;
        let observed = observed.ok_or(RuntimeError::InvalidReceipt)?;
        let slot = self
            .window
            .native_continuations
            .get(self.selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if slot.get().is_some_and(|prior| prior != observed) {
            return Err(RuntimeError::InvalidReceipt);
        }
        // SourceRead rechecked the actual native kernel/registrar after the
        // member callback. No callback or allocation follows its return here.
        slot.set(Some(observed));
        Ok(())
    }
}

impl CompleteOriginalRestorationWindow {
    /// Repeats each committed native journal/model check on its original node.
    ///
    /// This read-only inspection cannot issue final context or activate a world.
    /// Four-owner scope and common-custody installation remain separate gates.
    ///
    /// # Errors
    /// Refuses changed membership, missing real receipts, different histories or
    /// model state, an unsupported actual node or exhausted original precredit.
    pub fn inspect_original_native_continuations(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &ConformanceRuntime,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        let attempt = super::dispatch::RestorationDispatchAttempt::begin(self)?;
        self.inspect_original_native_group_data(plan, runtime, activation)?;
        attempt.complete()?;
        Ok(())
    }

    pub(super) fn inspect_original_native_group_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &ConformanceRuntime,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        for selected in 0..3 {
            let inspection = OriginalRestorationNodeContinuationInspection {
                window: self,
                plan,
                activation,
                selected,
                installed_scope: None,
                continuation: None,
            };
            inspection.authenticate_runtime_data(runtime)?;
            runtime.inspect_original_restoration_continuation(inspection)?;
        }
        self.authenticate_original_runtime_member_current_data(&activation.world_binding_hash)?;
        Ok(())
    }

    pub(super) fn continuation_counter_scratch_data() -> usize {
        size_of::<OriginalRestorationNodeContinuationInspection<'static>>()
            + 3 * size_of::<super::installed_context::OriginalCompleteNativeFenceStep<'static>>()
            + size_of::<Result<OriginalRestorationNodeContinuationInspection<'static>, RuntimeError>>(
            )
            + size_of::<OriginalRestorationTransactionInspection<'static>>()
            + size_of::<Option<OriginalRestorationNativeContinuationIdentity>>()
            + size_of::<OriginalRestorationNativeContinuationIdentity>()
            + size_of::<
                std::cell::Ref<
                    'static,
                    Option<crucible_node_transport::client::OriginalCompleteRestoreInputUpload>,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        Option<crucible_node_transport::client::OriginalCompleteRestoreInputUpload>,
                    >,
                    RuntimeError,
                >,
            >()
            + size_of::<
                Result<
                    &crate::node_state::CompleteOriginalArchivedValidationConstructionData,
                    RuntimeError,
                >,
            >()
            + size_of::<
                Option<&crate::node_state::CompleteOriginalArchivedValidationConstructionData>,
            >()
            + 2 * size_of::<blake3::Hasher>()
            + 2 * size_of::<blake3::Hash>()
            + size_of::<[&str; 4]>()
            + size_of::<std::array::IntoIter<&'static str, 4>>()
            + size_of::<[&str; 3]>()
            + size_of::<std::array::IntoIter<&'static str, 3>>()
            + 2 * size_of::<[u8; 8]>()
            + size_of::<[u8; 32]>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

pub(super) fn hash_identity(hash: &crucible_node_format::HashRef) -> [u8; 32] {
    let mut state =
        blake3::Hasher::new_derive_key("core.original-restoration-inventory-correspondence/1");
    for text in [&hash.algorithm, &hash.domain, &hash.digest].map(String::as_str) {
        state.update(&(text.len() as u64).to_le_bytes());
        state.update(text.as_bytes());
    }
    *state.finalize().as_bytes()
}

pub(super) fn reference_identity(reference: &ContentRef) -> [u8; 32] {
    let mut state =
        blake3::Hasher::new_derive_key("core.original-restoration-held-reference-correspondence/1");
    for text in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ]
    .map(String::as_str)
    {
        state.update(&(text.len() as u64).to_le_bytes());
        state.update(text.as_bytes());
    }
    state.update(&reference.length.get().to_le_bytes());
    *state.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::{ContentRef, canonical};

    #[test]
    fn native_correspondence_keeps_domain_media_length_and_inventory_separate() {
        let reference =
            canonical::content_ref(b"actual retained hold", "application/json").unwrap();
        let original = reference_identity(&reference);
        for mutation in 0..5 {
            let mut changed: ContentRef = reference.clone();
            match mutation {
                0 => changed.hash.algorithm.push('x'),
                1 => changed.hash.domain.push('x'),
                2 => changed.hash.digest.push('0'),
                3 => changed.media_type.push('x'),
                _ => changed.length = crucible_node_format::U64::new(changed.length.get() + 1),
            }
            assert_ne!(reference_identity(&changed), original);
        }
        assert_ne!(hash_identity(&reference.hash), original);
    }
}

impl<'a> OriginalRestorationNodeContinuationInspection<'a> {
    pub(super) fn for_original_installed_window(
        window: &'a CompleteOriginalRestorationWindow,
        plan: &'a InstalledConformancePlan,
        scope: &'a crate::node_contract::OriginalLineageNativeScope,
        selected: usize,
        continuation: super::installed_context::OriginalCompleteNativeFenceStep<'a>,
    ) -> Self {
        Self {
            window,
            plan,
            activation: &scope.target,
            selected,
            installed_scope: Some(scope),
            continuation: Some(continuation),
        }
    }
}
