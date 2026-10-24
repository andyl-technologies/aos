//! Sealed native and public-provider control for the same bounded checksum model.

use super::*;
use crucible_node_transport::ProviderError;

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Defines source-installed control of a retained checksum application process.
///
/// This interface is sealed to in-process adapters that own authenticated
/// native resources. Implementing a wire DTO or supplying a receipt reference
/// cannot implement this contract or issue host execution authority.
pub trait ControlledReference: sealed::Sealed {
    /// Borrows the original collection plan when this control is fixture-only.
    ///
    /// Ordinary controls return None. The marker remains in the owning native
    /// capsule and cannot be erased by selecting an ordinary runtime.
    fn collection_scope(&self) -> Option<&crate::node_admission::InstalledConformancePlan> {
        None
    }

    /// Reauthenticates native custody against the same opaque collection plan.
    ///
    /// # Errors
    /// Defaults to refusal. Selected controls must check original source/kernel
    /// custody and independently installed fixture authority on every call.
    fn validate_collection_scope(
        &self,
        _plan: &crate::node_admission::InstalledConformancePlan,
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "controlled collection custody is unsupported",
        ))
    }

    /// Returns the exact source-installed quantized facet interpretation.
    ///
    /// The graph's independent installation authenticator still checks this
    /// selection. Returning a name does not qualify a source implementation.
    fn quantized_facet(&self) -> &str {
        "reference-device/quantized-v1"
    }

    /// Returns the original controlled application's custody state.
    fn status(&self) -> DeviceStatus;
    /// Returns the actual controlled application process ID.
    fn child_pid(&self) -> u32;
    /// Returns the original finite native supervision slot identity.
    fn supervision_id(&self) -> U64;
    /// Returns the original host-bound execution owner.
    fn owner_id(&self) -> &Id;
    /// Returns the original surviving provider incarnation.
    fn incarnation_id(&self) -> &Id;
    /// Returns the original host-bound owner generation.
    fn generation(&self) -> U64;

    /// Returns the installed media type of the unchanged checksum output bytes.
    fn output_media_type(&self) -> &str {
        "application/json"
    }

    /// Returns genuine public event identity and FIFO, or the native adapter mapping.
    ///
    /// # Errors
    /// Refuses foreign receipts or unavailable original publication custody.
    fn publication_identity(
        &self,
        _receipt: &DeviceReceipt,
    ) -> Result<Option<(Id, U64)>, OperationFailure> {
        Ok(None)
    }

    /// Returns selected source publication causes, or the legacy native mapping.
    ///
    /// Cumulative input/checksum ancestry is distinct from same-time Event causes.
    /// The selected source must authenticate original publication custody first.
    ///
    /// # Errors
    /// Refuses foreign receipts or unrepresentable original public causes.
    fn publication_causal_parents(
        &self,
        _receipt: &DeviceReceipt,
    ) -> Result<Option<Vec<Position>>, OperationFailure> {
        Ok(None)
    }

    /// Returns the actual selected source proof for the original closed window.
    ///
    /// The legacy native checksum path returns `None` and retains its unchanged
    /// DeviceReceipt leaf codec. A selected source returns the original body
    /// beneath its authenticated owning window; a reconstructed label or matching
    /// digest cannot substitute for that custody.
    ///
    /// # Errors
    /// Refuses foreign receipts, missing original proof bytes or exhausted
    /// predeclared evidence credits after original native effects.
    fn completion_proof(
        &self,
        _receipt: &DeviceReceipt,
    ) -> Result<Option<InputPayload>, OperationFailure> {
        Ok(None)
    }

    /// Stages exact immutable bytes without executing an application reaction.
    ///
    /// # Errors
    /// Refuses changed grants, unknown input custody or exhausted finite limits.
    fn stage(&mut self, grant: DeviceGrant, bytes: &[u8]) -> Result<(), ProviderError>;
    /// Executes only the retained original admitted window.
    ///
    /// # Errors
    /// Retains original custody on failure or uncertain native effects.
    fn activate(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError>;
    /// Closes an original window while retaining its exact output evidence.
    ///
    /// # Errors
    /// Refuses mismatched original identity or unresolved native closure.
    fn close(&mut self, grant: &DeviceGrant) -> Result<DeviceReceipt, ProviderError>;
    /// Authenticates an immutable receipt against retained original native custody.
    ///
    /// # Errors
    /// Refuses changed receipt bytes, foreign owners or lost native custody.
    fn validate_receipt(&self, receipt: &DeviceReceipt) -> Result<(), ProviderError>;
    /// Acknowledges genuine consumption separately from byte transfer custody.
    ///
    /// # Errors
    /// Refuses foreign windows or unverified original output consumption.
    fn acknowledge_publication(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError>;
    /// Requests native containment and reports only positively reaped resources.
    ///
    /// # Errors
    /// Retains actual resources and originals when native reclamation is unknown.
    fn quarantine(&mut self) -> Result<bool, ProviderError>;

    /// Reports whether this original backend supports same-owner graceful cleanup.
    fn graceful_retirement_available(&self) -> bool {
        false
    }

    /// Executes original native Shutdown without a signaling fallback.
    ///
    /// # Errors
    /// Refuses unsupported cleanup or retains the first uncertain native result.
    fn shutdown_retirement(&mut self) -> Result<(), OperationFailure> {
        Err(super::native_failure(
            "controlled graceful retirement is unsupported",
        ))
    }

    /// Polls actual resources after successful original graceful Shutdown.
    ///
    /// # Errors
    /// Refuses unsupported cleanup or unresolved original Shutdown custody.
    fn poll_retirement(&mut self) -> Result<bool, ProviderError> {
        Err(ProviderError::Correlation(
            "controlled graceful reclamation is unsupported",
        ))
    }

    /// Moves the same reclaimed native capsule into its original supervisor slot.
    ///
    /// # Errors
    /// Refuses unsupported transfer, live resources or incomplete semantic cleanup.
    fn transfer_retirement(&mut self) -> Result<(), OperationFailure> {
        Err(super::native_failure(
            "controlled retirement transfer is unsupported",
        ))
    }

    /// Declares the finite original backend history allowance before reading it.
    fn retirement_history_credit(&self) -> Option<usize> {
        None
    }

    /// Reads private original backend bodies without issuing native work.
    ///
    /// # Errors
    /// Refuses unsupported history, lost original custody or exhausted credit.
    fn retirement_history(
        &self,
        _maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        Err(super::no_effect(
            "controlled original retirement history is unsupported",
        ))
    }

    /// Returns authenticated public readiness, or delegates to native readiness.
    ///
    /// # Errors
    /// Refuses changed world scope or unresolved original preparation.
    fn prepare_activation(
        &mut self,
        _record: &ActivationRecord,
    ) -> Result<Option<ReadyAttestation>, OperationFailure> {
        Ok(None)
    }

    /// Checks retained public readiness in addition to common runtime scope.
    ///
    /// # Errors
    /// Refuses stale native resources or changed original readiness records.
    fn validate_activation(
        &self,
        _record: &ActivationRecord,
        _ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        Ok(())
    }

    /// Returns original public owner preparation, or explicit unsupported mapping.
    ///
    /// # Errors
    /// Refuses changed readiness or unavailable original native preparation.
    fn prepared_owners(
        &self,
        _record: &ActivationRecord,
        _ready: &ReadyAttestation,
    ) -> Result<Option<Vec<crucible_node_format::PreparedOwner>>, OperationFailure> {
        Ok(None)
    }

    /// Checks actual public owner records against retained original readiness.
    ///
    /// # Errors
    /// Refuses unsupported mapping or changed original owner preparation.
    fn validate_prepared_owners(
        &self,
        _record: &ActivationRecord,
        _ready: &ReadyAttestation,
        _owners: &[crucible_node_format::PreparedOwner],
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "public owner preparation mapping is unsupported",
        ))
    }

    /// Authenticates freshly realized native initial state before coordinator extraction.
    ///
    /// # Errors
    /// Refuses unsupported proof, restored state or any retained execution/input work.
    fn validate_initial_preparation(
        &self,
        _world: &ActivationRecord,
        _ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "fresh native initial-state proof is unsupported",
        ))
    }

    /// Reads original retained native boundary proof bytes under world custody.
    ///
    /// # Errors
    /// Refuses unsupported evidence, foreign scope or finite byte exhaustion.
    fn read_boundary_evidence(
        &self,
        _activation: &WorldActivation,
        _references: &[ContentRef],
        _maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        Err(super::no_effect(
            "controlled boundary evidence is unsupported",
        ))
    }

    /// Checks original proof bodies against the same native world custody.
    ///
    /// # Errors
    /// Refuses unsupported evidence or any changed original object or scope.
    fn validate_boundary_evidence(
        &self,
        _activation: &WorldActivation,
        _references: &[ContentRef],
        _objects: &[InputPayload],
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "controlled boundary evidence validation is unsupported",
        ))
    }

    /// Reads complete original Stage ACK bodies through retained native custody.
    ///
    /// # Errors
    /// Refuses unsupported codecs, changed original staging or exhausted credits.
    fn read_original_input_evidence(
        &self,
        _original: &OperationAdmission,
        _staged: &crate::node_contract::OriginalStagedInput<'_>,
        _limits: crate::node_contract::OriginalInputLineageLimits,
    ) -> Result<crate::node_contract::OriginalInputEvidence, OperationFailure> {
        Err(super::no_effect(
            "controlled original input evidence is unsupported",
        ))
    }

    /// Authenticates exact original Stage ACK bodies and direct codec rows.
    ///
    /// # Errors
    /// Refuses unsupported validation or changed original native custody.
    fn validate_original_input_evidence(
        &self,
        _original: &OperationAdmission,
        _staged: &crate::node_contract::OriginalStagedInput<'_>,
        _evidence: &crate::node_contract::OriginalInputEvidence,
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "controlled original input evidence validation is unsupported",
        ))
    }

    /// Selects runtime-owned provenance for nonempty original public input.
    fn requires_input_provenance(&self, _batch: &RuntimeInputBatch) -> bool {
        false
    }

    /// Stages the same opaque original together with authenticated producer proofs.
    ///
    /// # Errors
    /// Refuses unsupported proof custody, changed inputs or uncertain effects.
    fn stage_runtime_inputs_with_provenance(
        &mut self,
        _batch: &RuntimeInputBatch,
        _provenance: &crate::node_contract::InputProvenanceClosure,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        Err(super::no_effect(
            "controlled input provenance staging is unsupported",
        ))
    }

    /// Lists codec-declared dependencies of an authenticated original proof.
    ///
    /// # Errors
    /// Refuses unsupported provenance, foreign roots or exhausted finite limits.
    fn input_provenance_dependencies(
        &self,
        _activation: &WorldActivation,
        _root: &ContentRef,
        _limits: crate::node_contract::InputProvenanceLimits,
    ) -> Result<Vec<ContentRef>, OperationFailure> {
        Err(super::no_effect(
            "controlled provenance dependencies are unsupported",
        ))
    }

    /// Authenticates the complete original dependency roster.
    ///
    /// # Errors
    /// Refuses unsupported provenance, omitted dependencies or changed scope.
    fn validate_input_provenance_dependencies(
        &self,
        _activation: &WorldActivation,
        _root: &ContentRef,
        _dependencies: &[ContentRef],
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "controlled provenance dependency validation is unsupported",
        ))
    }

    /// Stages the coordinator's opaque committed-world input authority.
    ///
    /// # Errors
    /// Retains originals on uncertain remote activation or input custody.
    fn stage_runtime_inputs(
        &mut self,
        _batch: &RuntimeInputBatch,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        Ok(None)
    }

    /// Selects the explicitly supported host-owned immutable input transfer.
    ///
    /// Socket-backed implementations keep the default. Returning `None` from
    /// input staging does not by itself select host-owned custody.
    fn uses_host_owned_input_custody(&self) -> bool {
        false
    }

    /// Authenticates the exact original host-owned immutable transfer.
    ///
    /// # Errors
    /// Refuses unsupported custody, foreign commits or changed native ownership.
    fn validate_host_owned_input_custody(
        &self,
        _original: &RuntimeInputBatch,
        _commit: &crate::node_scheduling::InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "controlled host-owned input custody is unsupported",
        ))
    }

    /// Consumes the same opaque coordinator commit in the actual external child.
    ///
    /// # Errors
    /// Refuses unsupported source journals or unresolved original consumption.
    fn commit_runtime_input_custody(
        &mut self,
        _original: &RuntimeInputBatch,
        _commit: &crate::node_scheduling::InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "controlled external input commit is unsupported",
        ))
    }

    /// Authenticates the actual child's consumed original coordinator commit.
    ///
    /// # Errors
    /// Refuses unsupported validation, foreign commits or uncertain consumption.
    fn validate_runtime_input_custody_commit(
        &self,
        _original: &RuntimeInputBatch,
        _commit: &crate::node_scheduling::InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "controlled external input commit validation is unsupported",
        ))
    }

    /// Reports whether the selected input needs an opaque original producer view.
    fn requires_original_input_lineage(&self, _batch: &RuntimeInputBatch) -> bool {
        false
    }

    /// Reads original publication claims under retained native custody and credits.
    ///
    /// # Errors
    /// Refuses unsupported selection, foreign scope, missing rows or exhausted credits.
    fn original_publication_lineage(
        &self,
        _original: &OperationAdmission,
        _outcome: &OperationOutcome,
        _publication: &crate::node_scheduling::NativePublication,
        _limits: crate::node_contract::OriginalInputLineageLimits,
    ) -> Result<crate::node_contract::OriginalPublicationClaim, OperationFailure> {
        Err(super::no_effect(
            "controlled original publication lineage is unsupported",
        ))
    }

    /// Authenticates the same original publication and every selected row/body.
    ///
    /// # Errors
    /// Refuses unsupported validation, changed source or incomplete dependencies.
    fn validate_original_publication_lineage(
        &self,
        _original: &OperationAdmission,
        _outcome: &OperationOutcome,
        _publication: &crate::node_scheduling::NativePublication,
        _claim: &crate::node_contract::OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        Err(super::no_effect(
            "controlled original publication validation is unsupported",
        ))
    }

    /// Stages an exact original runtime-sealed producer association.
    ///
    /// # Errors
    /// Refuses unsupported or changed inputs and retains uncertain native effects.
    fn stage_runtime_inputs_with_original_lineage(
        &mut self,
        _batch: &RuntimeInputBatch,
        _provenance: &crate::node_contract::InputProvenanceClosure,
        _lineage: &crate::node_contract::OriginalInputLineage,
    ) -> Result<Option<NativeInputAcknowledgement>, OperationFailure> {
        Err(super::no_effect(
            "controlled original input lineage is unsupported",
        ))
    }

    /// Retains the original opaque operation before issuing remote native work.
    ///
    /// # Errors
    /// Refuses a changed token, scope or admission; no replacement is allocated.
    fn retain_operation(&mut self, _original: &OperationAdmission) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl sealed::Sealed for ReferenceDevice {}

impl ControlledReference for ReferenceDevice {
    fn uses_host_owned_input_custody(&self) -> bool {
        true
    }

    fn validate_host_owned_input_custody(
        &self,
        original: &RuntimeInputBatch,
        commit: &crate::node_scheduling::InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        let identity = original
            .owners()
            .iter()
            .find(|owner| owner.owner == *self.owner_id());
        if self.status() != DeviceStatus::Parked
            || identity.is_none_or(|owner| {
                owner.incarnation != *self.incarnation_id() || owner.generation != self.generation()
            })
            || !original.activation().same_authority(commit.activation())
            || original.node() != commit.node()
            || original.stage_operation() != commit.stage_operation()
            || original.batch() != commit.batch()
            || original.inventory() != commit.inventory()
            || original.cutoff() != commit.cutoff()
        {
            return Err(super::no_effect(
                "reference host-owned transfer changed original custody",
            ));
        }
        Ok(())
    }

    fn status(&self) -> DeviceStatus {
        ReferenceDevice::status(self)
    }
    fn child_pid(&self) -> u32 {
        ReferenceDevice::child_pid(self)
    }
    fn supervision_id(&self) -> U64 {
        ReferenceDevice::supervision_id(self)
    }
    fn owner_id(&self) -> &Id {
        ReferenceDevice::owner_id(self)
    }
    fn incarnation_id(&self) -> &Id {
        ReferenceDevice::incarnation_id(self)
    }
    fn generation(&self) -> U64 {
        ReferenceDevice::generation(self)
    }
    fn stage(&mut self, grant: DeviceGrant, bytes: &[u8]) -> Result<(), ProviderError> {
        ReferenceDevice::stage(self, grant, bytes)
    }
    fn activate(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        ReferenceDevice::activate(self, grant)
    }
    fn close(&mut self, grant: &DeviceGrant) -> Result<DeviceReceipt, ProviderError> {
        ReferenceDevice::close(self, grant)
    }
    fn validate_receipt(&self, receipt: &DeviceReceipt) -> Result<(), ProviderError> {
        ReferenceDevice::validate_receipt(self, receipt)
    }
    fn acknowledge_publication(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        ReferenceDevice::acknowledge_publication(self, grant)
    }
    fn quarantine(&mut self) -> Result<bool, ProviderError> {
        ReferenceDevice::quarantine(self)
    }
}
