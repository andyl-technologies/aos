//! Owns bounded original common grants and exact model-aware native wire bodies.
//!
//! A subordinate refusal remains separate from successful Serial progress.
//! Original private token authority, grant scope and native raw response are
//! retained before any administrative ACK or public outcome becomes visible.

use std::rc::Rc;

use crucible_node_contract::{ContentRef, canonical};
use crucible_node_provider::gem5::{ArmRootRunOutcome, GEM5_NATIVE_FRAME_BYTES};

use crate::{
    node_contract::{OperationAdmission, OperationFailure, OperationOutcome, OperationToken},
    node_scheduling::InputPayload,
};

use super::refusal;

// Both the original response and its one-byte Serial payload fit this reserved
// envelope. No canonical regeneration of the native packet changes its bytes.
pub(super) const PREFIX_CREDIT: usize = GEM5_NATIVE_FRAME_BYTES + 1;

pub(super) struct NativePrefix {
    pub outcome: ArmRootRunOutcome,
    pub proof: ContentRef,
    pub activation: crate::node_contract::SavedRuntimeActivation,
    pub route: crate::node_contract::NodeRoute,
}

pub(super) struct OriginalOperation {
    pub admission: OperationAdmission,
    pub prefixes: Vec<NativePrefix>,
    pub outcome: Option<OperationOutcome>,
    pub evidence: Vec<InputPayload>,
    pub acknowledged: bool,
    pub failure: Option<OperationFailure>,
}

pub(super) struct RootLedger {
    pub operations: Vec<OriginalOperation>,
    pub standalone: Vec<InputPayload>,
    maximum_operations: usize,
    maximum_prefixes: usize,
    maximum_bytes: usize,
    retained_prefixes: usize,
    retained_bytes: usize,
}

impl RootLedger {
    pub(super) fn remaining_bytes(&self) -> usize {
        self.maximum_bytes - self.retained_bytes
    }

    pub(super) fn new(
        maximum_operations: usize,
        maximum_prefixes: usize,
        maximum_bytes: usize,
    ) -> Result<Self, OperationFailure> {
        if maximum_operations == 0
            || maximum_operations > 4096
            || maximum_prefixes == 0
            || maximum_prefixes > 512
            || !(PREFIX_CREDIT..=256 * 1024 * 1024).contains(&maximum_bytes)
        {
            return Err(refusal("ARM original ledger resource policy is invalid"));
        }
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(maximum_operations)
            .map_err(|_| refusal("ARM original operation reservation is unavailable"))?;
        let mut standalone = Vec::new();
        standalone
            .try_reserve_exact(4096)
            .map_err(|_| refusal("ARM administrative evidence reservation is unavailable"))?;

        Ok(Self {
            operations,
            standalone,
            maximum_operations,
            maximum_prefixes,
            maximum_bytes,
            retained_prefixes: 0,
            retained_bytes: 0,
        })
    }

    pub(super) fn reserve(
        &mut self,
        admission: &OperationAdmission,
    ) -> Result<(), OperationFailure> {
        if self.operations.len() >= self.maximum_operations
            || self
                .operations
                .iter()
                .any(|old| old.admission.token().operation() == admission.token().operation())
        {
            return Err(refusal(
                "ARM original operation identity or credit is occupied",
            ));
        }
        self.operations.push(OriginalOperation {
            admission: admission.clone(),
            prefixes: Vec::new(),
            outcome: None,
            evidence: Vec::new(),
            acknowledged: false,
            failure: None,
        });
        Ok(())
    }

    fn index(&self, token: &OperationToken) -> Result<usize, OperationFailure> {
        let index = self
            .operations
            .iter()
            .position(|old| old.admission.token().operation() == token.operation())
            .ok_or_else(|| refusal("ARM original operation custody is absent"))?;
        let original = self.operations[index].admission.token();
        if !Rc::ptr_eq(&original.authority, &token.authority) || original.route() != token.route() {
            return Err(refusal(
                "ARM original operation token has foreign live authority",
            ));
        }
        Ok(index)
    }

    pub(super) fn original(
        &self,
        token: &OperationToken,
    ) -> Result<&OriginalOperation, OperationFailure> {
        Ok(&self.operations[self.index(token)?])
    }

    pub(super) fn original_mut(
        &mut self,
        token: &OperationToken,
    ) -> Result<&mut OriginalOperation, OperationFailure> {
        let index = self.index(token)?;
        Ok(&mut self.operations[index])
    }

    pub(super) fn prepare_prefix(
        &mut self,
        token: &OperationToken,
    ) -> Result<(), OperationFailure> {
        if self.retained_prefixes >= self.maximum_prefixes
            || self
                .retained_bytes
                .checked_add(PREFIX_CREDIT)
                .is_none_or(|bytes| bytes > self.maximum_bytes)
        {
            return Err(refusal(
                "ARM original prefix byte or object credit is exhausted",
            ));
        }
        let original = self.original_mut(token)?;
        original
            .prefixes
            .try_reserve_exact(1)
            .map_err(|_| refusal("ARM original prefix slot is unavailable"))?;
        original
            .evidence
            .try_reserve_exact(2)
            .map_err(|_| refusal("ARM original prefix evidence slots are unavailable"))?;
        Ok(())
    }

    pub(super) fn retain_prefix(
        &mut self,
        token: &OperationToken,
        outcome: ArmRootRunOutcome,
    ) -> Result<ContentRef, OperationFailure> {
        let bytes = outcome.bytes();
        if bytes.len() > GEM5_NATIVE_FRAME_BYTES || self.retained_prefixes >= self.maximum_prefixes
        {
            return Err(refusal(
                "ARM original native response exceeds reserved frame credit",
            ));
        }
        let total = self.charge(bytes.len())?;
        let reference = canonical::content_ref(bytes, "application/json")
            .map_err(|error| refusal(&error.to_string()))?;
        let object = copy_object(&reference, bytes)?;
        let original = self.original_mut(token)?;
        original.prefixes.push(NativePrefix {
            outcome,
            proof: reference.clone(),
            activation: crate::node_contract::SavedRuntimeActivation::from(
                original.admission.activation.record(),
            ),
            route: original.admission.token().route().clone(),
        });
        original.evidence.push(object);
        self.retained_bytes = total;
        self.retained_prefixes += 1;
        Ok(reference)
    }

    pub(super) fn retain_payload(
        &mut self,
        token: &OperationToken,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), OperationFailure> {
        reference
            .verify(bytes)
            .map_err(|error| refusal(&error.to_string()))?;
        if let Some(old) = self
            .original(token)?
            .evidence
            .iter()
            .find(|old| &old.reference == reference)
        {
            return if old.bytes == bytes {
                Ok(())
            } else {
                Err(refusal("ARM original payload reference changed bytes"))
            };
        }
        let total = self.charge(bytes.len())?;
        let object = copy_object(reference, bytes)?;
        self.original_mut(token)?.evidence.push(object);
        self.retained_bytes = total;
        Ok(())
    }

    pub(super) fn retain_standalone(
        &mut self,
        objects: &[(&ContentRef, &[u8])],
    ) -> Result<(), OperationFailure> {
        let mut total = self.retained_bytes;
        let mut count = self.standalone.len();
        for (index, (reference, bytes)) in objects.iter().enumerate() {
            reference
                .verify(bytes)
                .map_err(|error| refusal(&error.to_string()))?;
            let existing = self
                .standalone
                .iter()
                .find(|old| &old.reference == *reference);
            if let Some(old) = existing {
                if old.bytes != *bytes {
                    return Err(refusal("ARM original stopped evidence changed"));
                }
            } else if let Some((_, old)) = objects[..index].iter().find(|(old, _)| old == reference)
            {
                if old != bytes {
                    return Err(refusal("ARM stopped evidence repeats changed bytes"));
                }
            } else {
                total = total
                    .checked_add(bytes.len())
                    .filter(|total| *total <= self.maximum_bytes)
                    .ok_or_else(|| {
                        refusal("ARM stopped evidence aggregate byte credit is exhausted")
                    })?;
                count += 1;
            }
        }
        if count > 4096 {
            return Err(refusal("ARM stopped evidence object credit is exhausted"));
        }
        for (reference, bytes) in objects {
            if !self
                .standalone
                .iter()
                .any(|old| &old.reference == *reference)
            {
                self.standalone.push(copy_object(reference, bytes)?);
                // Each successful retention remains charged if a later copy is
                // refused. A retry cannot consume unaccounted administrative bytes.
                self.retained_bytes = self.charge(bytes.len())?;
            }
        }
        Ok(())
    }

    pub(super) fn evidence(
        &self,
        token: &OperationToken,
        references: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        let original = self.original(token)?;
        read_objects(&original.evidence, references, self.maximum_bytes)
    }

    pub(super) fn boundary_evidence(
        &self,
        references: &[ContentRef],
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        read_objects(&self.standalone, references, self.maximum_bytes)
    }

    fn charge(&self, bytes: usize) -> Result<usize, OperationFailure> {
        self.retained_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum_bytes)
            .ok_or_else(|| refusal("ARM original evidence byte credit is exhausted"))
    }
}

fn copy_object(reference: &ContentRef, bytes: &[u8]) -> Result<InputPayload, OperationFailure> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(bytes.len())
        .map_err(|_| refusal("ARM original evidence body allocation is unavailable"))?;
    retained.extend_from_slice(bytes);
    Ok(InputPayload {
        reference: reference.clone(),
        bytes: retained,
    })
}

fn read_objects(
    original: &[InputPayload],
    references: &[ContentRef],
    maximum_bytes: usize,
) -> Result<Vec<InputPayload>, OperationFailure> {
    if references.len() > original.len() {
        return Err(refusal(
            "ARM requested evidence exceeds original object custody",
        ));
    }
    let mut total = 0u64;
    for (index, reference) in references.iter().enumerate() {
        if references[..index].contains(reference) {
            return Err(refusal("ARM evidence request repeats an original object"));
        }
        total = total
            .checked_add(reference.length.get())
            .filter(|total| *total <= maximum_bytes as u64)
            .ok_or_else(|| refusal("ARM evidence response exceeds aggregate byte credit"))?;
        if !original.iter().any(|old| &old.reference == reference) {
            return Err(refusal(
                "ARM requested evidence is foreign to retained custody",
            ));
        }
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(references.len())
        .map_err(|_| refusal("ARM evidence response slots are unavailable"))?;
    for reference in references {
        let object = original
            .iter()
            .find(|old| &old.reference == reference)
            .ok_or_else(|| refusal("ARM original evidence object disappeared"))?;
        result.push(copy_object(reference, &object.bytes)?);
    }
    Ok(result)
}
