//! Original opaque input commitments consumed by the actual public source journal.

use crucible_node_format::*;
use crucible_node_transport::{
    ProviderError, bodies::*, input_commit::*, reference_service::ReferenceServiceBootstrap,
};
use serde::de::DeserializeOwned;

use crate::{
    node_contract::OperationFailure,
    node_scheduling::{InputCustodyCommit, RuntimeInputBatch},
};

use super::{
    control::{InputCommitAttempt, StagedInput, original_id},
    readiness::{after_native_effect, refused, unknown},
};

mod peer;

// Only the two owning reference adapters implement this private transport seam.
// Their original controllers and source guards retain every native exchange.
pub(super) trait InputCommitPeer {
    fn staged_input(&self) -> Option<&StagedInput>;
    fn staged_input_mut(&mut self) -> Option<&mut StagedInput>;
    fn commit_owner_binding(&self) -> &OwnerBinding;
    fn commit_bootstrap(&self) -> Result<ReferenceServiceBootstrap, ProviderError>;
    fn commit_features(&self) -> Result<IdSet, ProviderError>;
    fn commit_request_hash(
        &self,
        request: Id,
        body: &InputRequest,
        extensions: Extensions,
    ) -> Result<HashRef, ProviderError>;
    fn commit_upload(&mut self, reference: &ContentRef, bytes: &[u8]) -> Result<(), ProviderError>;
    fn commit_call(
        &mut self,
        request: Id,
        body: InputRequest,
        extensions: Extensions,
    ) -> Result<ResponseBody, ProviderError>;
    fn commit_record<T: DeserializeOwned + Validate>(
        &self,
        reference: &ContentRef,
    ) -> Result<T, ProviderError>;
    fn commit_content(&self, reference: &ContentRef) -> Result<&[u8], ProviderError>;
    fn commit_verify_native(&self) -> Result<(), ProviderError>;
    fn commit_retain_boundary(
        &mut self,
        reference: &ContentRef,
        dependencies: Vec<ContentRef>,
    ) -> Result<(), OperationFailure>;

    fn check_original_input_commit(
        &self,
        original: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        let staged = self
            .staged_input()
            .ok_or_else(|| refused("original public input staging is absent"))?;
        if !std::rc::Rc::ptr_eq(
            &original.activation().authority,
            &commit.activation().authority,
        ) || !std::rc::Rc::ptr_eq(
            &staged.original.activation().authority,
            &commit.activation().authority,
        ) || original.activation().record() != commit.activation().record()
            || original.node() != commit.node()
            || original.stage_operation() != commit.stage_operation()
            || original.batch() != commit.batch()
            || original.inventory() != commit.inventory()
            || original.cutoff() != commit.cutoff()
            || staged.original.activation().record() != original.activation().record()
            || staged.original.node() != original.node()
            || staged.original.stage_operation() != original.stage_operation()
            || staged.original.batch() != original.batch()
            || staged.original.inventory() != original.inventory()
            || staged.original.cutoff() != original.cutoff()
            || staged.original.deliveries() != original.deliveries()
            || staged.original.payloads() != original.payloads()
            || staged.acknowledgement.is_none()
        {
            return Err(refused(
                "later commitment changed original opaque public input authority",
            ));
        }
        if let Some(attempt) = &staged.commitment {
            let retained = &attempt.original;
            if !std::rc::Rc::ptr_eq(
                &retained.activation().authority,
                &commit.activation().authority,
            ) || retained.activation().record() != commit.activation().record()
                || retained.node() != commit.node()
                || retained.stage_operation() != commit.stage_operation()
                || retained.batch() != commit.batch()
                || retained.inventory() != commit.inventory()
                || retained.cutoff() != commit.cutoff()
            {
                return Err(refused(
                    "public commitment retry changed original authority",
                ));
            }
        }
        Ok(())
    }

    fn consume_input_commit(
        &mut self,
        original: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        self.check_original_input_commit(original, commit)?;
        if self
            .staged_input()
            .is_some_and(|staged| staged.commitment.is_some())
        {
            // Every effect attempt owns one original request. Uncertain transfer,
            // receipt allocation or transport cannot be retried as new work.
            return self.validate_consumed_input_commit(original, commit);
        }
        if !self
            .commit_features()
            .map_err(unknown)?
            .iter()
            .any(|feature| feature.as_str() == INPUT_COMMIT_FEATURE)
        {
            return Err(refused(
                "original public source did not negotiate consumed input commitments",
            ));
        }
        let bootstrap = self.commit_bootstrap().map_err(unknown)?;
        let staged = self
            .staged_input()
            .ok_or_else(|| refused("original public input disappeared"))?;
        let staging_receipt = staged
            .acknowledgement
            .as_ref()
            .ok_or_else(|| refused("original Input receipt unavailable"))?
            .proof_ref
            .clone();
        let inventory_value = serde_json::to_value(original.deliveries())
            .map_err(|error| unknown(ContractError::from(error).into()))?;
        let inventory_bytes =
            canonical::canonical_json(&inventory_value).map_err(|error| unknown(error.into()))?;
        original
            .inventory()
            .verify(&inventory_bytes)
            .map_err(|error| unknown(error.into()))?;
        let intent = InputCommitIntentV1 {
            schema_version: 1,
            session_id: bootstrap.authority.session_id.clone(),
            incarnation_id: bootstrap.authority.incarnation_id.clone(),
            node_id: original.node().clone(),
            execution_owner_id: bootstrap.owner_id.clone(),
            owner_generation: bootstrap.authority.owner_generation,
            activation_id: commit.activation().record().activation_id.clone(),
            world_generation: commit.activation().record().generation,
            world_binding_hash: commit.activation().record().world_binding_hash.clone(),
            stage_operation_id: original.stage_operation().clone(),
            input_request_id: original_id("input", original.stage_operation()).map_err(unknown)?,
            batch_id: original.batch().clone(),
            batch_hash: staged
                .public
                .identity()
                .map_err(|error| unknown(error.into()))?,
            staging_receipt,
            delivery_inventory: original.inventory().clone(),
            cutoff: original.cutoff(),
        };
        intent.validate().map_err(|error| unknown(error.into()))?;
        let public = staged.public.clone();
        let binding_hash = self
            .commit_owner_binding()
            .identity()
            .map_err(|error| unknown(error.into()))?;
        let request = original_id("input-commit", original.stage_operation()).map_err(unknown)?;
        let extensions = Extensions::from([(
            INPUT_COMMIT_FEATURE.into(),
            serde_json::to_value(&intent)
                .map_err(|error| unknown(ContractError::from(error).into()))?,
        )]);
        let public_request = InputRequest {
            binding_hash,
            owner_generation: bootstrap.authority.owner_generation,
            batch_id: public.batch_id.clone(),
            batch_sequence: public.batch_sequence,
            input_epoch: public.input_epoch.clone(),
            events: public.events.clone(),
            batch_hash: intent.batch_hash.clone(),
            extensions: public.extensions.clone(),
        };
        let request_hash = self
            .commit_request_hash(request.clone(), &public_request, extensions.clone())
            .map_err(unknown)?;
        self.staged_input_mut()
            .ok_or_else(|| refused("original public input disappeared"))?
            .commitment = Some(InputCommitAttempt {
            original: commit.retained_copy(),
            intent: intent.clone(),
            request: request.clone(),
            request_hash: request_hash.clone(),
            inventory_bytes: inventory_bytes.clone(),
            receipt: None,
            record: None,
        });
        self.commit_upload(original.inventory(), &inventory_bytes)
            .map_err(unknown)?;
        let response = self
            .commit_call(request.clone(), public_request, extensions)
            .map_err(unknown)?;
        let Some(MethodResult::Input(result)) = response.result else {
            return Err(unknown(ProviderError::Correlation(
                "original source input commitment did not complete",
            )));
        };
        let receipt: ControlReceipt = self
            .commit_record(&result.custody_receipt)
            .map_err(unknown)?;
        let custody: InputCustodyRecord =
            self.commit_record(&receipt.record_ref).map_err(unknown)?;
        if custody.execution_owner_id != bootstrap.owner_id
            || custody.owner_generation != bootstrap.authority.owner_generation
            || custody.input_epoch != public.input_epoch
            || custody.input_watermark != public.batch_sequence
            || custody.batch_hashes != [intent.batch_hash.clone()]
            || custody.pending_inventory.hash != result.inventory_hash
            || custody.evidence_refs.len() != 1
            || !custody.extensions.is_empty()
        {
            return Err(unknown(ProviderError::Correlation(
                "later receipt changed baseline original input custody",
            )));
        }
        let commit_record_ref = custody.evidence_refs[0].clone();
        let record: InputCommitRecordV1 =
            self.commit_record(&commit_record_ref).map_err(unknown)?;
        let expected_ids = public
            .events
            .iter()
            .map(|event| event.id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let staged_bytes = self
            .staged_input()
            .ok_or_else(|| {
                unknown(ProviderError::Correlation(
                    "original staged input disappeared",
                ))
            })?
            .bytes
            .clone();
        record
            .staged_bytes
            .verify(&staged_bytes)
            .map_err(|error| unknown(error.into()))?;
        if receipt.kind != ControlReceiptKind::InputCustody
            || receipt.issuer != ReceiptIssuer::Provider
            || receipt.session_id != bootstrap.authority.session_id
            || receipt.incarnation_id != bootstrap.authority.incarnation_id
            || receipt.request_id != request
            || receipt.operation_id.is_some()
            || receipt.owner_ids != [bootstrap.owner_id.clone()]
            || receipt.world_generation != bootstrap.world_generation
            || !receipt.extensions.is_empty()
            || record.intent != intent
            || record.request_hash != request_hash
            || record.request_id != request
            || result.accepted_event_ids != expected_ids
            || result.input_watermark != public.batch_sequence
            || self.commit_content(&record.staged_bytes).map_err(unknown)? != staged_bytes
        {
            return Err(unknown(ProviderError::Correlation(
                "source commitment receipt changed original retained input",
            )));
        }
        self.commit_verify_native().map_err(unknown)?;
        self.commit_retain_boundary(&intent.delivery_inventory, Vec::new())
            .map_err(after_native_effect)?;
        // The native octet stream is a byte leaf, and a single delivery can
        // reuse its original payload reference. Causality belongs to the
        // commitment record below, through the inventory and staging receipt.
        self.commit_retain_boundary(&record.staged_bytes, Vec::new())
            .map_err(after_native_effect)?;
        self.commit_retain_boundary(
            &commit_record_ref,
            vec![
                intent.delivery_inventory.clone(),
                intent.staging_receipt.clone(),
                record.staged_bytes.clone(),
            ],
        )
        .map_err(after_native_effect)?;
        self.commit_retain_boundary(
            &receipt.record_ref,
            vec![custody.pending_inventory, commit_record_ref],
        )
        .map_err(after_native_effect)?;
        self.commit_retain_boundary(&result.custody_receipt, vec![receipt.record_ref])
            .map_err(after_native_effect)?;
        let attempt = self
            .staged_input_mut()
            .and_then(|staged| staged.commitment.as_mut())
            .ok_or_else(|| {
                unknown(ProviderError::Correlation(
                    "original commitment attempt disappeared",
                ))
            })?;
        attempt.record = Some(record);
        attempt.receipt = Some(result.custody_receipt);
        self.validate_consumed_input_commit(original, commit)
    }

    fn validate_consumed_input_commit(
        &self,
        original: &RuntimeInputBatch,
        commit: &InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        self.check_original_input_commit(original, commit)?;
        let staged = self
            .staged_input()
            .ok_or_else(|| refused("original public input absent"))?;
        let attempt = staged
            .commitment
            .as_ref()
            .ok_or_else(|| refused("actual source commitment has not been attempted"))?;
        let (Some(receipt), Some(record)) = (&attempt.receipt, &attempt.record) else {
            return Err(unknown(ProviderError::Correlation(
                "original source commitment remains unresolved",
            )));
        };
        attempt
            .intent
            .delivery_inventory
            .verify(&attempt.inventory_bytes)
            .map_err(|error| unknown(error.into()))?;
        record
            .staged_bytes
            .verify(&staged.bytes)
            .map_err(|error| unknown(error.into()))?;
        let retained: ControlReceipt = self.commit_record(receipt).map_err(unknown)?;
        let custody: InputCustodyRecord =
            self.commit_record(&retained.record_ref).map_err(unknown)?;
        if custody.evidence_refs.len() != 1
            || !custody.extensions.is_empty()
            || custody.execution_owner_id != attempt.intent.execution_owner_id
            || custody.owner_generation != attempt.intent.owner_generation
            || custody.input_epoch != staged.public.input_epoch
            || custody.input_watermark != staged.public.batch_sequence
            || custody.batch_hashes != [attempt.intent.batch_hash.clone()]
        {
            return Err(unknown(ProviderError::Correlation(
                "retained baseline input commitment custody changed",
            )));
        }
        let actual: InputCommitRecordV1 = self
            .commit_record(&custody.evidence_refs[0])
            .map_err(unknown)?;
        if actual != *record
            || record.intent != attempt.intent
            || record.request_hash != attempt.request_hash
            || record.request_id != attempt.request
            || retained.request_id != attempt.request
        {
            return Err(unknown(ProviderError::Correlation(
                "retained source commitment changed original custody",
            )));
        }
        self.commit_verify_native().map_err(unknown)
    }
}
