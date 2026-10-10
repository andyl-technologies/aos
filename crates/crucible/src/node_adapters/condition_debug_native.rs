//! Original native condition-control journal without process-local authority decoding.

use super::*;
use crate::node_contract::{ConditionControlRequest, ConditionStopRecord, OperationAdmission};
use crate::node_scheduling::InputPayload;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeControlJournal {
    pub(super) stop: Box<ConditionStopRecord>,
    pub(super) barrier: crucible_node_contract::ContentRef,
    pub(super) report: InputPayload,
    pub(super) resume: Option<NativeResumeRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeResumeRecord {
    format: String,
    version: u16,
    operation: Id,
    stop_operation: Id,
    barrier: crucible_node_contract::ContentRef,
    report: crucible_node_contract::ContentRef,
    source: crate::node_contract::SavedRuntimeActivation,
    owners: Vec<crate::node_contract::OwnerIdentity>,
    cut: Position,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalIndex {
    format: String,
    version: u16,
    stop: ContentRef,
    report: ContentRef,
    resume: Option<ContentRef>,
}

impl NativeControlJournal {
    pub(super) fn preflight_restore(
        store: &dag::EvidenceDag,
        reference: &ContentRef,
        expanded: &mut ExpansionCredit,
    ) -> Result<(), OperationFailure> {
        let index: JournalIndex = serde_json::from_slice(store.body(reference)?)
            .map_err(|error| refuse(&error.to_string()))?;
        if index.format != "crucible.host-condition-journal-index" || index.version != 1 {
            return Err(refuse("condition original journal index changed"));
        }
        let stop: ConditionStopRecord = serde_json::from_slice(store.body(&index.stop)?)
            .map_err(|error| refuse(&error.to_string()))?;
        expanded.record_index(&stop, store.body(&index.stop)?.len())?;
        for inventory in &stop.native {
            let objects = store
                .closure_with_limit(&inventory.receipt.reference, expanded.remaining_entries())?;
            for object in objects {
                expanded.charge(1, object.bytes.as_slice().len())?;
            }
        }
        expanded.charge(1, store.body(&index.report)?.len())?;
        if let Some(reference) = &index.resume {
            expanded.charge(1, store.body(reference)?.len())?;
        }
        Ok(())
    }

    pub(super) fn store(
        &self,
        store: &mut dag::EvidenceDag,
    ) -> Result<ContentRef, OperationFailure> {
        for inventory in &self.stop.native {
            for object in inventory
                .proof_objects
                .iter()
                .chain(std::iter::once(&inventory.receipt))
            {
                store.insert(
                    object.reference.clone(),
                    &object.bytes,
                    ConditionDebugModel::original_dependencies(&object.bytes)?,
                )?;
            }
        }
        let stop_bytes = canonical_bytes(self.stop.as_ref())?;
        store.insert(
            self.barrier.clone(),
            &stop_bytes,
            self.stop
                .native
                .iter()
                .map(|inventory| inventory.receipt.reference.clone())
                .collect(),
        )?;
        store.insert(
            self.report.reference.clone(),
            &self.report.bytes,
            Vec::new(),
        )?;
        let resume = self
            .resume
            .as_ref()
            .map(|resume| store.add(&canonical_bytes(resume)?, "application/json", Vec::new()))
            .transpose()?;
        let index = JournalIndex {
            format: "crucible.host-condition-journal-index".into(),
            version: 1,
            stop: self.barrier.clone(),
            report: self.report.reference.clone(),
            resume: resume.clone(),
        };
        let mut dependencies = vec![index.stop.clone(), index.report.clone()];
        dependencies.extend(resume);
        store.add(&canonical_bytes(&index)?, "application/json", dependencies)
    }

    pub(super) fn restore(
        store: &dag::EvidenceDag,
        reference: &ContentRef,
    ) -> Result<Self, OperationFailure> {
        let index: JournalIndex = serde_json::from_slice(store.body(reference)?)
            .map_err(|error| refuse(&error.to_string()))?;
        if index.format != "crucible.host-condition-journal-index" || index.version != 1 {
            return Err(refuse("condition original journal index changed"));
        }
        let mut stop: ConditionStopRecord = serde_json::from_slice(store.body(&index.stop)?)
            .map_err(|error| refuse(&error.to_string()))?;
        for inventory in &mut stop.native {
            inventory.receipt.bytes = store.body(&inventory.receipt.reference)?.to_vec();
            inventory.proof_objects = store
                .closure(&inventory.receipt.reference)?
                .into_iter()
                .filter(|object| object.reference != inventory.receipt.reference)
                .map(|object| InputPayload {
                    reference: object.reference.clone(),
                    bytes: object.bytes.as_slice().to_vec(),
                })
                .collect();
        }
        let report = InputPayload {
            bytes: store.body(&index.report)?.to_vec(),
            reference: index.report,
        };
        let resume = index
            .resume
            .map(|reference| {
                serde_json::from_slice(store.body(&reference)?)
                    .map_err(|error| refuse(&error.to_string()))
            })
            .transpose()?;
        Ok(Self {
            stop: Box::new(stop),
            barrier: index.stop,
            report,
            resume,
        })
    }

    pub(super) fn index_dependencies(bytes: &[u8]) -> Result<Vec<ContentRef>, OperationFailure> {
        let index: JournalIndex =
            serde_json::from_slice(bytes).map_err(|error| refuse(&error.to_string()))?;
        if index.version != 1 || index.format != "crucible.host-condition-journal-index" {
            return Err(refuse(
                "condition original journal selected grammar changed",
            ));
        }
        let mut dependencies = vec![index.stop, index.report];
        dependencies.extend(index.resume);
        dependencies.sort();
        dependencies.dedup();
        Ok(dependencies)
    }
}

impl ConditionDebugModel {
    pub(in crate::node_adapters) fn retain_provenance(
        &mut self,
        provenance: &crate::node_contract::InputProvenanceClosure,
    ) -> Result<(), OperationFailure> {
        if self
            .provenance
            .iter()
            .any(|saved| saved.stage_operation == *provenance.stage_operation())
            || self.provenance.len() >= self.maximum_events
        {
            return Err(refuse(
                "condition original producer proof history exhausted or reused",
            ));
        }
        let mut expanded = self.expansion_credit()?;
        expanded.provenance(provenance.saved())?;
        let mut staged = self.clone();
        staged.provenance.push(provenance.saved().clone());
        staged.validate_provenance()?;
        staged.capture()?;
        *self = staged;
        Ok(())
    }

    pub(super) fn validate_provenance(&self) -> Result<(), OperationFailure> {
        let mut stages = std::collections::BTreeSet::new();
        for saved in &self.provenance {
            if saved.schema_version != 1
                || !stages.insert(&saved.stage_operation)
                || saved.roots.windows(2).any(|pair| pair[0] >= pair[1])
                || saved
                    .objects
                    .windows(2)
                    .any(|pair| pair[0].reference >= pair[1].reference)
            {
                return Err(refuse("condition original producer proof grammar changed"));
            }
            for object in &saved.objects {
                object
                    .reference
                    .verify(&object.bytes)
                    .map_err(|error| refuse(&error.to_string()))?;
            }
            if saved
                .roots
                .iter()
                .any(|root| !saved.objects.iter().any(|object| &object.reference == root))
            {
                return Err(refuse("condition original producer proof root omitted"));
            }
        }
        Ok(())
    }

    pub(in crate::node_adapters) fn native_control(
        &mut self,
        admission: &OperationAdmission,
    ) -> Result<InputPayload, OperationFailure> {
        let crate::node_contract::OperationRequest::DebugConditionV1(request) = admission.request()
        else {
            return Err(refuse("condition original control grammar differs"));
        };
        let mut expanded = self.expansion_credit()?;
        if let ConditionControlRequest::Stop { barrier, receipt } = request.as_ref() {
            expanded.record(
                barrier,
                usize::try_from(receipt.length.get())
                    .map_err(|_| refuse("condition expanded index length overflow"))?,
            )?;
            // The prospective original report also becomes retained ownership.
            expanded.charge(1, original_report(barrier, receipt)?.bytes.len())?;
        }
        let mut staged = self.clone();
        let result = match request.as_ref() {
            ConditionControlRequest::Stop { barrier, receipt } => {
                if staged.journal.is_some()
                    || staged.resumed
                    || staged.candidate.as_ref() != Some(&barrier.hit)
                    || staged.position() != barrier.cut
                    || barrier.version != 1
                    || barrier.operation != *admission.token().operation()
                    || barrier.node != admission.token().route().node
                    || barrier.source
                        != crate::node_contract::SavedRuntimeActivation::from(
                            admission.activation().record(),
                        )
                {
                    return Err(refuse(
                        "condition native stop differs from its original live context",
                    ));
                }
                let bytes = canonical_bytes(barrier.as_ref())?;
                receipt
                    .verify(&bytes)
                    .map_err(|error| refuse(&error.to_string()))?;
                let report = original_report(barrier, receipt)?;
                staged.journal = Some(NativeControlJournal {
                    stop: barrier.clone(),
                    barrier: receipt.clone(),
                    report: report.clone(),
                    resume: None,
                });
                report
            }
            ConditionControlRequest::Resume {
                stop_operation,
                barrier,
                report,
            } => {
                let journal = staged
                    .journal
                    .as_mut()
                    .ok_or_else(|| refuse("condition has no original stop journal"))?;
                if staged.resumed
                    || journal.resume.is_some()
                    || journal.stop.operation != *stop_operation
                    || journal.barrier != *barrier
                    || journal.report.reference != *report
                    || journal.stop.node != admission.token().route().node
                    || journal.stop.cut != staged.evaluation.position()
                {
                    return Err(refuse(
                        "condition resume differs from original stopped custody",
                    ));
                }
                let resume = NativeResumeRecord {
                    format: "crucible.host-condition-resume".into(),
                    version: 1,
                    operation: admission.token().operation().clone(),
                    stop_operation: stop_operation.clone(),
                    barrier: barrier.clone(),
                    report: report.clone(),
                    source: admission.activation().record().into(),
                    owners: admission.token().route().owners.clone(),
                    cut: journal.stop.cut,
                };
                let receipt = payload(canonical_bytes(&resume)?)?;
                journal.resume = Some(resume);
                staged.resumed = true;
                receipt
            }
        };
        // Reserve the entire replaced native journal/checkpoint before the
        // first live control transition. A refusal changes neither cursor nor hit.
        staged.capture()?;
        *self = staged;
        Ok(result)
    }

    pub(super) fn validate_native_journal(&self) -> Result<(), OperationFailure> {
        let Some(journal) = &self.journal else {
            if self.resumed {
                return Err(refuse("condition omitted original resume journal"));
            }
            return Ok(());
        };
        if journal.stop.version != 1
            || self.candidate.as_ref() != Some(&journal.stop.hit)
            || journal.stop.cut > self.position()
            || journal.stop.node != journal.stop.hit.input.consumer
            || self.resumed != journal.resume.is_some()
            || !self.resumed && journal.stop.cut != self.position()
        {
            return Err(refuse(
                "condition original native control association changed",
            ));
        }
        journal
            .barrier
            .verify(&canonical_bytes(journal.stop.as_ref())?)
            .map_err(|error| refuse(&error.to_string()))?;
        if original_report(&journal.stop, &journal.barrier)? != journal.report {
            return Err(refuse("condition original native report changed"));
        }
        if let Some(resume) = &journal.resume
            && (resume.format != "crucible.host-condition-resume"
                || resume.version != 1
                || resume.stop_operation != journal.stop.operation
                || resume.barrier != journal.barrier
                || resume.report != journal.report.reference
                || resume.cut != journal.stop.cut
                || resume.operation == journal.stop.operation
                || resume.owners.is_empty())
        {
            return Err(refuse("condition original native resume history changed"));
        }
        Ok(())
    }
}

fn original_report(
    stop: &ConditionStopRecord,
    receipt: &crucible_node_contract::ContentRef,
) -> Result<InputPayload, OperationFailure> {
    let bytes = canonical::canonical_json(&serde_json::json!({
        "format": "crucible.host-condition-stop-report",
        "version": 1,
        "stop_operation": stop.operation,
        "node": stop.node,
        "condition": stop.hit.condition,
        "source": stop.source,
        "triggering_evaluation": stop.hit.evaluation,
        "actual_stopped_cut": stop.cut,
        "original_input": stop.hit.input,
        "original_outcome": stop.hit.outcome,
        "barrier": receipt,
        "canonical": true,
        "mutates_guest_memory": false,
    }))
    .map_err(|error| refuse(&error.to_string()))?;
    payload(bytes)
}

pub(in crate::node_adapters) fn canonical_bytes(
    value: &impl Serialize,
) -> Result<Vec<u8>, OperationFailure> {
    canonical::canonical_json(
        &serde_json::to_value(value).map_err(|error| refuse(&error.to_string()))?,
    )
    .map_err(|error| refuse(&error.to_string()))
}

fn payload(bytes: Vec<u8>) -> Result<InputPayload, OperationFailure> {
    let reference = canonical::content_ref(&bytes, "application/json")
        .map_err(|error| refuse(&error.to_string()))?;
    Ok(InputPayload { reference, bytes })
}

// Expanded ownership is separate from deduplicated encoded-DAG credit. The
// fixed ceilings match the selected Runtime6 closure and preserve smaller
// encoded-model budgets without multiplying their repeated association bytes.
pub(super) struct ExpansionCredit {
    entries: usize,
    bytes: usize,
}

impl ExpansionCredit {
    pub(super) fn new() -> Self {
        Self {
            entries: 0,
            bytes: 0,
        }
    }

    pub(super) fn remaining_entries(&self) -> usize {
        65_536 - self.entries
    }

    pub(super) fn charge(&mut self, entries: usize, bytes: usize) -> Result<(), OperationFailure> {
        let next_entries = self
            .entries
            .checked_add(entries)
            .ok_or_else(|| refuse("condition expanded association count overflow"))?;
        let next_bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| refuse("condition expanded association bytes overflow"))?;
        if next_entries > 65_536 || next_bytes > 64 << 20 {
            return Err(refuse("condition expanded association credit exhausted"));
        }
        self.entries = next_entries;
        self.bytes = next_bytes;
        Ok(())
    }

    pub(super) fn provenance(
        &mut self,
        saved: &crate::node_contract::SavedInputProvenance,
    ) -> Result<(), OperationFailure> {
        self.charge(1 + saved.roots.len(), 0)?;
        for body in &saved.objects {
            self.charge(1, body.bytes.len())?;
        }
        Ok(())
    }

    pub(super) fn record_index(
        &mut self,
        record: &ConditionStopRecord,
        index_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.charge(1, index_bytes)?;
        self.charge(
            1 + record.source.owners.len(),
            record.scheduler.as_slice().len(),
        )?;
        self.charge(
            1 + record.hit.outcome.parents.len(),
            record.hit.outcome.bytes.as_slice().len(),
        )?;
        for inventory in &record.native {
            self.charge(1 + inventory.owners.len(), 0)?;
        }
        Ok(())
    }

    pub(super) fn record(
        &mut self,
        record: &ConditionStopRecord,
        index_bytes: usize,
    ) -> Result<(), OperationFailure> {
        self.record_index(record, index_bytes)?;
        for body in record.dependency_objects() {
            self.charge(1, body.bytes.len())?;
        }
        Ok(())
    }
}
