//! Derives the complete portless Clock result from the source programme.
//!
//! Expected state and scheduling bodies are constructed before dispatch. No
//! observed outcome, decoded passed report or native proof supplies these values.

use super::*;
use crucible_engine::node_scheduling::{
    NativeOutputBound, NativeProducerBound, NativeSchedulingObservation,
};
use serde::Serialize;

#[derive(Serialize)]
struct ExpectedReceipt<'a> {
    schema_version: u16,
    profile: &'static str,
    node: &'a Id,
    owners: &'a [OwnerIdentity],
    boundary: Position,
    native: ContentRef,
    native_sequence: U64,
    input: Option<(&'a Id, &'a ContentRef, U64)>,
    pending_causes: ContentRef,
}

pub(super) struct ExpectedClockCase {
    pub(super) request: OperationRequest,
    pub(super) outcome: OperationOutcome,
    pub(super) objects: [InputPayload; 3],
}

impl ExpectedClockCase {
    pub(super) fn new(
        node: &Id,
        owners: &[OwnerIdentity],
        operation: &Id,
        start: Position,
        limit: Position,
        settle: bool,
    ) -> Result<Self, NodeObservedError> {
        // The closed model's documented codec is prefix plus one LE u64.
        // Derive the expected cursor from the programme, never from native readback.
        let mut native_bytes = b"crucible.host-clock.v1\0".to_vec();
        native_bytes.extend_from_slice(&limit.time_ps.get().to_le_bytes());
        let native = InputPayload {
            reference: canonical::content_ref(&native_bytes, "application/octet-stream")?,
            bytes: native_bytes,
        };
        let causes_bytes = br#"{"schema":"crucible.host-pending-causes.v1","causes":[]}"#.to_vec();
        let causes = InputPayload {
            reference: canonical::content_ref(&causes_bytes, "application/json")?,
            bytes: causes_bytes,
        };
        let receipt_bytes = serde_json::to_vec(&ExpectedReceipt {
            schema_version: 1,
            profile: crucible_engine::node_adapters::HOST_EXACT_PROFILE,
            node,
            owners,
            boundary: limit,
            native: native.reference.clone(),
            native_sequence: U64::new(0),
            input: None,
            pending_causes: causes.reference.clone(),
        })?;
        let receipt = InputPayload {
            reference: canonical::content_ref(&receipt_bytes, "application/octet-stream")?,
            bytes: receipt_bytes,
        };
        let observation = NativeSchedulingObservation {
            node: node.clone(),
            owners: owners.to_vec(),
            reached: limit,
            closed_prefix: limit,
            bounds: vec![NativeProducerBound {
                producer: node.clone(),
                bound: NativeOutputBound::AfterInstant(U64::new(u64::MAX)),
                proof_ref: receipt.reference.clone(),
            }],
            publications: Vec::new(),
            input_progress: None,
            external_inputs: Vec::new(),
            proof_ref: receipt.reference.clone(),
        };
        let request = if settle {
            OperationRequest::BoundarySettle { start, limit }
        } else {
            OperationRequest::ExactRun {
                start,
                limit,
                boundary_policy: ExactBoundaryPolicy::HorizonPark,
            }
        };
        Ok(Self {
            request,
            outcome: OperationOutcome {
                operation: operation.clone(),
                node: node.clone(),
                owners: owners.to_vec(),
                progress: ProgressEvidence::Exact {
                    reached: limit,
                    stop: StopReason::HorizonPark,
                },
                retained_outputs: Vec::new(),
                scheduling: Some(observation),
            },
            objects: [receipt, native, causes],
        })
    }

    pub(super) fn authenticate_objects(
        &self,
        actual: &[InputPayload],
    ) -> Result<(), NodeObservedError> {
        if actual.len() != self.objects.len()
            || self.objects.iter().any(|expected| {
                actual
                    .iter()
                    .filter(|row| {
                        row.reference == expected.reference && row.bytes == expected.bytes
                    })
                    .count()
                    != 1
            })
        {
            return Err(refused(
                "original Clock native state, causes or receipt differs from source oracle",
            ));
        }
        Ok(())
    }
}

impl crate::node_qualification::RetainedMetadataOwned for ExpectedClockCase {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self {
            request,
            outcome,
            objects,
        } = self;
        counter.charge(request)?;
        counter.charge(outcome)?;
        counter.charge(objects)
    }
}
