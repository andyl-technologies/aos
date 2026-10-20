//! Source-owned later input commitments and the native execution gate.

use crucible_node_format::*;
use serde_json::{Map, Value};

use crate::ProviderError;
use crate::bodies::{InputRequest, InputResult, OperationState};
use crate::envelope::{Envelope, RequestOrigin};
use crate::handshake::ConnectionAuthority;
use crate::input_commit::{
    CommittedDeliveryV1, INPUT_COMMIT_FEATURE, InputCommitIntentV1, InputCommitRecordV1,
};
use crate::native_journal::{NativeJournal, NativeRequestRegistration};

use super::resources::Resources;
use super::{completed, object, refusal, unknown};

pub(super) struct NativeInputCommit {
    pub(super) intent: InputCommitIntentV1,
    pub(super) request_id: Id,
    pub(super) request_hash: HashRef,
    pub(super) bytes: Vec<u8>,
    pub(super) receipt: Option<ContentRef>,
    pub(super) record: Option<InputCommitRecordV1>,
}

pub(super) fn commit(
    journal: &mut NativeJournal<Resources>,
    authority: &ConnectionAuthority,
    envelope: &Envelope,
    request: &InputRequest,
) -> Result<Map<String, Value>, ProviderError> {
    let registration = journal.register_request(authority, envelope, RequestOrigin::Controller)?;
    let NativeRequestRegistration::New(permit) = registration else {
        let NativeRequestRegistration::Original(original) = registration else {
            return Err(ProviderError::Conflict(
                "original input commitment registration unavailable",
            ));
        };
        return original.outcome.map_or_else(unknown, |bytes| {
            object(canonical::parse_json(&bytes, 16 * 1024 * 1024)?)
        });
    };
    let checked = (|| {
        let value = envelope
            .extensions
            .get(INPUT_COMMIT_FEATURE)
            .ok_or(ProviderError::Frame("input commitment absent"))?;
        let intent: InputCommitIntentV1 =
            serde_json::from_value(value.clone()).map_err(ContractError::from)?;
        intent.validate()?;
        let original = journal
            .snapshot()
            .inputs
            .values()
            .find(|original| {
                original.request_key.id == intent.input_request_id
                    && original.request_key.origin == RequestOrigin::Controller
            })
            .ok_or(ProviderError::Correlation(
                "original accepted Input snapshot unavailable",
            ))?;
        let result = original.result.clone().ok_or(ProviderError::Conflict(
            "original Input staging is unresolved",
        ))?;
        if original.state != OperationState::Completed
            || original.batch_hash != intent.batch_hash
            || result.custody_receipt != intent.staging_receipt
            || original.batch != request.verified_batch(&intent.execution_owner_id)?
        {
            return Err(ProviderError::Correlation(
                "commitment changed original accepted Input snapshot",
            ));
        }
        journal
            .resources()
            .verify_intent(envelope, request, &intent)?;
        Ok((intent, result))
    })();
    let (intent, staged_result) = match checked {
        Ok(checked) => checked,
        Err(error) => {
            let response = refusal(&error)?;
            journal.record_request_refusal(&permit, &response)?;
            return Ok(response);
        }
    };
    // The journal holds the original envelope before resource access. The native
    // attempt additionally takes the actual bytes before storing any receipt.
    let outcome =
        journal.with_request_resources(&permit, |resources| {
            let request_id = permit.request_key().id.clone();
            let request_hash = envelope.request_hash(RequestOrigin::Controller)?;
            resources.input_commits.insert(
                intent.batch_id.clone(),
                NativeInputCommit {
                    intent: intent.clone(),
                    request_id: request_id.clone(),
                    request_hash: request_hash.clone(),
                    bytes: resources.input_bytes.clone(),
                    receipt: None,
                    record: None,
                },
            );
            let staged_bytes =
                resources.store(resources.input_bytes.clone(), "application/octet-stream")?;
            let record = InputCommitRecordV1 {
                schema_version: 1,
                intent: intent.clone(),
                request_id: request_id.clone(),
                request_hash,
                staged_bytes,
            };
            record.validate()?;
            let record_ref = resources.store_json(&record)?;
            let original_receipt: ControlReceipt = resources.resolve(&intent.staging_receipt)?;
            let mut custody: InputCustodyRecord =
                resources.resolve(&original_receipt.record_ref)?;
            // The negotiated evidence augments the baseline custody grammar;
            // it cannot replace a standard record with a private receipt shape.
            custody.evidence_refs = vec![record_ref];
            custody.validate()?;
            let record_ref = resources.store_json(custody)?;
            let receipt = resources.control_receipt(
                ControlReceiptKind::InputCustody,
                record_ref,
                &request_id,
                None,
            )?;
            let retained = resources.input_commits.get_mut(&intent.batch_id).ok_or(
                ProviderError::Correlation("original input commitment disappeared"),
            )?;
            retained.record = Some(record);
            retained.receipt = Some(receipt.clone());
            completed(InputResult {
                custody_receipt: receipt,
                ..staged_result
            })
        });
    let response = match outcome {
        Ok(response) => response,
        Err(_) => unknown()?,
    };
    // Failure after entering resources is sticky Unknown, including receipt
    // allocation failure; reconnect cannot create another attempt or deadline.
    journal.record_request_terminal(&permit, &response)?;
    Ok(response)
}

pub(super) fn original_commit_completed(journal: &NativeJournal<Resources>) -> bool {
    let Some(batch) = &journal.resources().input else {
        return false;
    };
    let Some(commit) = journal.resources().input_commits.get(&batch.batch_id) else {
        return false;
    };
    let key = crate::journal::RequestKey {
        origin: RequestOrigin::Controller,
        id: commit.request_id.clone(),
    };
    journal.resources().has_input_commit()
        && journal
            .snapshot()
            .requests
            .get(&key)
            .is_some_and(|request| {
                request.request_hash() == &commit.request_hash
                    && request.outcome().is_some_and(|bytes| {
                        canonical::parse_json(bytes, 16 * 1024 * 1024).is_ok_and(|value| {
                            value
                                .get("status")
                                .is_some_and(|status| status == "completed")
                        })
                    })
            })
}

impl Resources {
    fn verify_intent(
        &self,
        envelope: &Envelope,
        request: &InputRequest,
        intent: &InputCommitIntentV1,
    ) -> Result<(), ProviderError> {
        self.check_owner(envelope, request.owner_generation, &request.binding_hash)?;
        let batch = self.input.as_ref().ok_or(ProviderError::Correlation(
            "actual original staged bytes unavailable",
        ))?;
        let retained_bytes = self
            .input_commits
            .values()
            .try_fold(self.input_bytes.len(), |total, commit| {
                total.checked_add(commit.bytes.len())
            });
        if retained_bytes
            .is_none_or(|total| total as u64 > self.bootstrap.resource_limits.content_bytes.get())
        {
            return Err(ProviderError::ResourceExhausted(
                "original source input commitment bytes",
            ));
        }
        if !self.active
            || self
                .window
                .as_ref()
                .is_some_and(|window| !window.publication_acknowledged)
            || self.input_commits.contains_key(&intent.batch_id)
            || self.input_commits.len() >= self.bootstrap.limits.journal_entries.get() as usize
            || batch != &request.verified_batch(&intent.execution_owner_id)?
            || intent.session_id != self.bootstrap.authority.session_id
            || intent.incarnation_id != self.bootstrap.authority.incarnation_id
            || intent.node_id != self.bootstrap.node_id
            || intent.execution_owner_id != self.bootstrap.owner_id
            || intent.owner_generation != self.bootstrap.authority.owner_generation
            || intent.activation_id != self.bootstrap.activation_id
            || intent.world_generation != self.bootstrap.world_generation
            || intent.world_binding_hash != self.bootstrap.world_binding_hash
            || intent.cutoff
                != Position::new(
                    self.bootstrap
                        .quantum_ps
                        .checked_mul(self.next_quantum)?
                        .checked_add(U64::new(1))?,
                    U64::new(0),
                    Phase::BoundaryControl,
                )
            || intent.batch_id != batch.batch_id
            || intent.batch_hash != batch.identity()?
            || self.input_custody.as_ref() != Some(&intent.staging_receipt)
        {
            return Err(ProviderError::Correlation(
                "later input commitment changed actual native authority",
            ));
        }
        let inventory = self.content(&intent.delivery_inventory)?;
        let value = canonical::parse_json_with_depth(inventory, 16 * 1024 * 1024, 64)?;
        if canonical::canonical_json(&value)? != inventory {
            return Err(ProviderError::Frame("input inventory is not canonical"));
        }
        let deliveries: Vec<CommittedDeliveryV1> =
            serde_json::from_value(value).map_err(ContractError::from)?;
        if deliveries.len() != batch.events.len() || deliveries.len() > MAX_ARRAY_ELEMENTS {
            return Err(ProviderError::Correlation(
                "complete input inventory changed native event population",
            ));
        }
        let mut offset = 0usize;
        for (delivery, event) in deliveries.iter().zip(&batch.events) {
            delivery.verify_event(event, &intent.node_id, intent.cutoff)?;
            let length = usize::try_from(event.payload.length.get())
                .map_err(|_| ProviderError::ResourceExhausted("input payload length"))?;
            let end = offset
                .checked_add(length)
                .ok_or(ProviderError::ResourceExhausted("input payload offset"))?;
            let bytes = self
                .input_bytes
                .get(offset..end)
                .ok_or(ProviderError::Correlation(
                    "original staged payload bytes incomplete",
                ))?;
            event.payload.verify(bytes)?;
            offset = end;
        }
        if offset != self.input_bytes.len() {
            return Err(ProviderError::Correlation(
                "staged bytes contain undeclared input",
            ));
        }
        Ok(())
    }

    pub(super) fn has_input_commit(&self) -> bool {
        self.input.as_ref().is_some_and(|batch| {
            self.input_commits
                .get(&batch.batch_id)
                .is_some_and(|commit| {
                    commit.receipt.is_some()
                        && commit.record.is_some()
                        && commit.bytes == self.input_bytes
                        && batch
                            .identity()
                            .is_ok_and(|identity| identity == commit.intent.batch_hash)
                })
        })
    }

    pub(super) fn require_input_commit(&self, start: Position) -> Result<(), ProviderError> {
        let cutoff = Position::new(
            start.time_ps.checked_add(U64::new(1))?,
            U64::new(0),
            Phase::BoundaryControl,
        );
        let batch = self
            .input
            .as_ref()
            .ok_or(ProviderError::Correlation("original native input absent"))?;
        let commitment =
            self.input_commits
                .get(&batch.batch_id)
                .ok_or(ProviderError::Correlation(
                    "later native input commitment absent",
                ))?;
        if !self.has_input_commit() || commitment.intent.cutoff != cutoff {
            return Err(ProviderError::Correlation(
                "native execution requires the original committed input cut",
            ));
        }
        Ok(())
    }
}
