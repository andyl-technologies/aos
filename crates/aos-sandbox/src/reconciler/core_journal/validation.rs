//! Shares the sole canonical validation body for borrowed Controller Journal work.
//!
//! Ordinary entry points delegate immediately; scoped Host entry retains the
//! genuine Start native owner through this same validation and commit engine.

use super::*;

impl CoreJournalMutationV2<'_, '_> {
    pub(in crate::reconciler) fn ensure_ledger_validated(&mut self) -> Result<(), ReconcilerError> {
        self.ensure_ledger_validated_for(true)
    }

    pub(in crate::reconciler) fn ensure_ledger_validated_for(
        &mut self,
        validate_current_boot: bool,
    ) -> Result<(), ReconcilerError> {
        // Cached structural validity says nothing about a later failed commit.
        // Check on every entry before replay or any executor/session interaction.
        self.journal.ensure_healthy()?;
        if !self.ledger_validated {
            // Scan the publication namespace once after recovery or an exposed
            // raw journal mutation. Individual gated operations still verify
            // their direct prepared/current references on every selection.
            validate_publication_namespace(&self.journal).map_err(|_| {
                ReconcilerError::CorruptLedger("authority publication namespace is corrupt")
            })?;
            observe_reservation::validate_all(&self.journal)?;
            project_admission::validate_all(&self.journal)?;
            self.validate_all_ownership_gates(validate_current_boot)?;
            self.validate_public_operation_authorizations()?;
            accepted_start::validate_all_v1(&self.journal)?;
            validate_runtime_authority_operations(&self.journal)?;
            aos_sandbox_protocol::domain_ledger::provisioning_resources::
                validate_provisioning_resource_links_v1(
                    self.journal.historical_read_view_v1().materialized_state_v1(),
                )?;
            create_failure::validate_all_prepare_floors(&self.journal)?;
            crate::controller_no_apply_settlement_cursor::validate_all_controller_no_apply_cursors_v1(
                &self.journal,
            )
            .map_err(|_| ReconcilerError::CorruptLedger("Controller no-Apply settlement cursor is corrupt"))?;
            if self
                .journal
                .records(RecordNamespace::SandboxSpec)
                .next()
                .is_some()
            {
                crate::sandbox_spec_state::validate_namespace(&self.journal)
                    .map_err(|error| ReconcilerError::SandboxSpec(Box::new(error)))?;
            }
            if self
                .journal
                .records(RecordNamespace::FilesystemViewRevision)
                .next()
                .is_some()
            {
                crate::filesystem_view_state::validate_namespace(&self.journal)
                    .map_err(|error| ReconcilerError::FilesystemViewRevision(Box::new(error)))?;
            }
            if self
                .journal
                .records(RecordNamespace::AttachmentSlot)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::attachment_slot_state::validate_namespace(&self.journal)
                    .map_err(|error| ReconcilerError::AttachmentSlot(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "attachment slots require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::RuntimeAuthority)
                .next()
                .is_some()
            {
                RuntimeAuthorityStore::load(&mut self.journal, RuntimeAuthorityLimits::default())?;
            }
            if self
                .journal
                .records(RecordNamespace::RuntimeGeneration)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::runtime_scope::validate_generation_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::RuntimeGeneration(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "runtime generations require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::NamespaceTarget)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::runtime_scope::validate_namespace_target_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::NamespaceTarget(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "namespace targets require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::AttachmentDesired)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::attachment_state::validate_namespace(&self.journal)
                    .map_err(|error| ReconcilerError::AttachmentDesired(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "attachment desired state requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::MountAttempt)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::mount_attempt::validate_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::MountAttempt(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "mount attempts require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::MountCompletion)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::mount_attempt::validate_completion_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::MountAttempt(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "mount completions require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::MountInventory)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::mount_attempt::validate_inventory_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::MountAttempt(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "mount inventory requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::MountSourceAcquisitionInventory)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::mount_source_acquisition_inventory::validate_namespace(&mut self.journal)
                    .map_err(|error| {
                        ReconcilerError::MountSourceAcquisitionInventory(Box::new(error))
                    })?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "Mount source-acquisition inventory requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::AttachmentSourceAttempt)
                .next()
                .is_some()
                || self
                    .journal
                    .records(RecordNamespace::AttachmentSourceCompletion)
                    .next()
                    .is_some()
                || self
                    .journal
                    .records(RecordNamespace::AttachmentSourceDispatch)
                    .next()
                    .is_some()
            {
                #[cfg(target_os = "linux")]
                {
                    crate::attachment_source::validate_attempt_namespace(&mut self.journal)
                        .map_err(|error| ReconcilerError::AttachmentSource(Box::new(error)))?;
                    crate::attachment_source::validate_completion_namespace(&mut self.journal)
                        .map_err(|error| ReconcilerError::AttachmentSource(Box::new(error)))?;
                    crate::attachment_source::validate_dispatch_namespace(&mut self.journal)
                        .map_err(|error| ReconcilerError::AttachmentSource(Box::new(error)))?;
                }
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "attachment source custody requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::DestinationSlotAttempt)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::destination_slot_effect::validate_attempt_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::DestinationSlotEffect(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "destination-slot attempts require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::DestinationSlotCompletion)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::destination_slot_effect::validate_completion_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::DestinationSlotEffect(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "destination-slot completions require Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::DestinationSlotInventory)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::destination_slot_inventory::validate_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::DestinationSlotInventory(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "destination-slot inventory requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::StorageResourceInventory)
                .next()
                .is_some()
                || self
                    .journal
                    .records(RecordNamespace::NetworkResourceInventory)
                    .next()
                    .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::resource_inventory::validate_namespaces(&mut self.journal)
                    .map_err(|error| ReconcilerError::ResourceInventory(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "broker resource inventory requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::AttachmentVerification)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::attachment_verification::validate_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::AttachmentVerification(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "attachment verification requires Linux validation",
                ));
            }
            if self
                .journal
                .records(RecordNamespace::HostCatalogReconciliation)
                .next()
                .is_some()
            {
                #[cfg(target_os = "linux")]
                crate::host_catalog_reconciliation::validate_namespace(&mut self.journal)
                    .map_err(|error| ReconcilerError::HostCatalogReconciliation(Box::new(error)))?;
                #[cfg(not(target_os = "linux"))]
                return Err(ReconcilerError::CorruptLedger(
                    "Host catalog reconciliation requires Linux validation",
                ));
            }
            // Executor-free validation must not satisfy the stronger cache
            // used immediately before effect recovery and dispatch.
            self.ledger_validated = validate_current_boot;
        }
        Ok(())
    }

    pub(in crate::reconciler) fn load_and_validate_ownership_gate(
        &mut self,
        operation_id: OperationId,
        operation: OperationRecord,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
        self.load_and_validate_ownership_gate_for(operation_id, operation, true)
    }

    pub(in crate::reconciler) fn load_and_validate_ownership_gate_for(
        &mut self,
        operation_id: OperationId,
        operation: OperationRecord,
        validate_current_boot: bool,
    ) -> Result<Option<OwnershipGateStatusV1>, ReconcilerError> {
        self.validate_canceled_operation(operation_id, operation)?;
        create_failure::validate_failed_create_operation(&self.journal, operation_id, operation)?;
        operator_repair_failure::validate_operation(&self.journal, operation_id, operation)?;
        let gate = self
            .journal
            .get(RecordNamespace::OwnershipGate, operation_id.as_bytes())
            .map(|bytes| decode_ownership_gate(bytes).map_err(ReconcilerError::from))
            .transpose()?;
        let Some(gate) = gate else {
            return if operation.ownership_gated() {
                Err(ReconcilerError::CorruptLedger(
                    "ownership-gated operation has no gate",
                ))
            } else {
                self.validate_effect_authority_bindings(
                    operation_id,
                    operation.effect_count(),
                    None,
                    None,
                    validate_current_boot,
                )?;
                Ok(None)
            };
        };
        let plan = match &gate {
            OwnershipGateStatusV1::Pending(plan)
            | OwnershipGateStatusV1::Activated { plan, .. } => plan,
        };
        if plan.operation_id() != operation_id
            || self
                .journal
                .check_idempotency(plan.idempotency_key(), plan.request_digest())
                != IdempotencyOutcome::Replay(operation_id)
        {
            return Err(ReconcilerError::CorruptLedger(
                "ownership gate does not match its operation",
            ));
        }
        if !operation.ownership_gated() {
            return Err(ReconcilerError::CorruptLedger(
                "ungated operation has an ownership gate",
            ));
        }
        self.validate_effect_authority_bindings(
            operation_id,
            operation.effect_count(),
            Some(plan.publication_draft()),
            match &gate {
                OwnershipGateStatusV1::Activated {
                    publication_digest, ..
                } => Some(*publication_digest),
                OwnershipGateStatusV1::Pending(_) => None,
            },
            validate_current_boot,
        )?;
        match (&gate, operation.state()) {
            (OwnershipGateStatusV1::Pending(_), OperationState::OwnershipPending) => Ok(Some(gate)),
            (
                OwnershipGateStatusV1::Activated {
                    plan,
                    publication_digest,
                    lease_generation,
                    lease_digest,
                },
                OperationState::Accepted
                | OperationState::Applying
                | OperationState::Succeeded
                | OperationState::PermanentlyBlocked,
            ) => {
                validate_durable_gate_publication(
                    &self.journal,
                    *publication_digest,
                    plan.publication_draft(),
                    plan.claim(),
                    *lease_generation,
                    *lease_digest,
                )
                .map_err(|_| {
                    ReconcilerError::CorruptLedger(
                        "activated ownership gate publication is missing or corrupt",
                    )
                })?;
                Ok(Some(gate))
            }
            _ => Err(ReconcilerError::CorruptLedger(
                "ownership gate state does not match its operation",
            )),
        }
    }

    pub(in crate::reconciler) fn load_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationRecord, ReconcilerError> {
        readonly::load_operation(&self.journal, operation_id)
    }

    pub(in crate::reconciler) fn pending_operation_count(&self) -> Result<usize, ReconcilerError> {
        readonly::pending_operation_count(&self.journal)
    }

    pub(in crate::reconciler) fn validate_all_ownership_gates(
        &mut self,
        validate_current_boot: bool,
    ) -> Result<(), ReconcilerError> {
        let gated_operations = self
            .journal
            .records(RecordNamespace::OwnershipGate)
            .map(|(key, _)| decode_operation_key(key))
            .collect::<Result<Vec<_>, _>>()?;
        for operation_id in gated_operations {
            let operation = self.load_operation(operation_id).map_err(|error| {
                if matches!(error, ReconcilerError::OperationNotFound) {
                    ReconcilerError::CorruptLedger("orphan ownership gate")
                } else {
                    error
                }
            })?;
            self.load_and_validate_ownership_gate_for(
                operation_id,
                operation,
                validate_current_boot,
            )?;
        }

        let operations = self
            .journal
            .records(RecordNamespace::Operation)
            .map(|(key, _)| decode_operation_key(key))
            .collect::<Result<Vec<_>, _>>()?;
        for operation_id in operations {
            let operation = self.load_operation(operation_id)?;
            self.load_and_validate_ownership_gate_for(
                operation_id,
                operation,
                validate_current_boot,
            )?;
        }
        Ok(())
    }

    pub(in crate::reconciler) fn validate_canceled_operation(
        &self,
        operation_id: OperationId,
        operation: OperationRecord,
    ) -> Result<(), ReconcilerError> {
        readonly::validate_canceled_operation(&self.journal, operation_id, operation)
    }

    pub(in crate::reconciler) fn validate_effect_authority_bindings(
        &mut self,
        operation_id: OperationId,
        effect_count: u32,
        draft: Option<&AuthorityPublicationDraftV1>,
        activated_publication: Option<ObjectDigest>,
        validate_current_boot: bool,
    ) -> Result<(), ReconcilerError> {
        for step in 0..effect_count {
            let bytes = self
                .journal
                .get(RecordNamespace::Effect, &effect_key(operation_id, step))
                .ok_or(ReconcilerError::CorruptLedger("missing effect record"))?;
            let effect = decode_effect(bytes).map_err(ReconcilerError::from)?;
            match (draft, effect.plan().authority()) {
                (None, None) => {}
                (Some(draft), Some(binding)) => {
                    let template = draft
                        .templates()
                        .iter()
                        .find(|template| template.digest() == binding.template_digest())
                        .ok_or(ReconcilerError::CorruptLedger(
                            "authority effect template is absent from gate draft",
                        ))?;
                    if binding.source_draft_digest() != draft.digest()
                        || binding.operation_id() != operation_id
                        || binding.step() != step
                        || binding.audience() != template.audience()
                        || binding.method() != template.method()
                        || binding.body_digest()
                            != effect_body_digest(template.body_without_deadline())
                        || binding.semantic_digest()
                            != crate::dispatch::semantic_identity_digest(template.semantics())
                        || !binding.descriptor_free()
                        || !template.descriptor_roles().is_empty()
                        || effect.plan().request() != template.body_without_deadline()
                    {
                        return Err(ReconcilerError::CorruptLedger(
                            "authority effect does not match gate draft template",
                        ));
                    }
                    if let Some(dispatch) = effect.dispatch() {
                        let current_host_boot_id = if validate_current_boot
                            && matches!(effect.state(), EffectState::Applying { .. })
                        {
                            Some(
                                self.current_effect_boot_v2(operation_id, step)?,
                            )
                        } else {
                            None
                        };
                        validate_durable_effect_attempt(
                            &self.journal,
                            draft.manifest().manifest().sandbox(),
                            activated_publication.ok_or(ReconcilerError::CorruptLedger(
                                "authority dispatch exists before gate activation",
                            ))?,
                            binding.digest(),
                            binding.source_draft_digest(),
                            binding.audience(),
                            binding.template_digest(),
                            effect.plan().request(),
                            dispatch,
                            current_host_boot_id,
                        )
                        .map_err(|_| {
                            ReconcilerError::CorruptLedger(
                                "authority effect dispatch is missing or corrupt",
                            )
                        })?;
                        if let EffectState::Applied { receipt, .. } = effect.state() {
                            effect::validate_durable_receipt_history(dispatch, receipt.as_bytes())
                                .map_err(|_| {
                                    ReconcilerError::CorruptLedger(
                                        "authority effect receipt is malformed or substituted",
                                    )
                                })?;
                        }
                    }
                }
                (Some(_), None) => {
                    return Err(ReconcilerError::CorruptLedger(
                        "effect record authority flag does not match operation provenance",
                    ));
                }
                (None, Some(_)) => {
                    return Err(ReconcilerError::CorruptLedger(
                        "effect record authority flag does not match operation provenance",
                    ));
                }
            }
        }
        for (key, _) in self.journal.records(RecordNamespace::Effect) {
            if key.len() >= OPERATION_KEY_BYTES
                && &key[..OPERATION_KEY_BYTES] == operation_id.as_bytes()
            {
                let step: [u8; 4] = key
                    .get(OPERATION_KEY_BYTES..)
                    .ok_or(ReconcilerError::CorruptLedger("invalid effect key"))?
                    .try_into()
                    .map_err(|_| ReconcilerError::CorruptLedger("invalid effect key"))?;
                if u32::from_be_bytes(step) >= effect_count {
                    return Err(ReconcilerError::CorruptLedger(
                        "operation has an extra effect",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(in crate::reconciler) fn validate_gated_effects_for_activation(
        &self,
        operation_id: OperationId,
        effect_count: u32,
    ) -> Result<(), ReconcilerError> {
        readonly::validate_gated_effects_for_activation(&self.journal, operation_id, effect_count)
    }

    pub(in crate::reconciler) fn validate_operation_gate_relation(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), ReconcilerError> {
        let operation = self.load_operation(operation_id)?;
        self.load_and_validate_ownership_gate(operation_id, operation)?;
        Ok(())
    }

    pub(in crate::reconciler) fn validate_public_operation_authorizations(&self) -> Result<(), ReconcilerError> {
        readonly::validate_public_operation_authorizations(&self.journal)
    }
}
