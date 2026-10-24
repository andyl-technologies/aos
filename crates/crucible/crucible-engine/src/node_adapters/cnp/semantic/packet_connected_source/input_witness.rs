//! Borrows source-authenticated original Stage or Commit journals without decoding authority.

use super::*;

/// Borrows one complete original staged or consumed input record.
///
/// Only the concrete source constructs this witness after joining the same
/// controller's original requests, responses, input context and full custody
/// journals. Caller bytes, matching references and decoded records cannot
/// construct it. A staging witness alone never means delivery or consumption.
pub struct PacketConnectedInputWitness<'a> {
    reference: ContentRef,
    bytes: &'a [u8],
    record: OriginalInputRecord,
}

enum OriginalInputRecord {
    Stage(PacketStageRecord),
    Commit(PacketCommitRecord),
}

impl PacketConnectedInputWitness<'_> {
    /// Borrows the source-checked original content identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the complete verified bytes retained by the original controller.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Borrows the original Stage record when this witness retains staged bytes.
    pub fn stage(&self) -> Option<&PacketStageRecord> {
        match &self.record {
            OriginalInputRecord::Stage(record) => Some(record),
            OriginalInputRecord::Commit(_) => None,
        }
    }

    /// Borrows the original Commit record when this witness retains consumed input.
    pub fn commit(&self) -> Option<&PacketCommitRecord> {
        match &self.record {
            OriginalInputRecord::Commit(record) => Some(record),
            OriginalInputRecord::Stage(_) => None,
        }
    }
}

impl PacketConnectedSemanticSource {
    /// Borrows a complete source-authenticated original input custody journal.
    ///
    /// It accepts only content already retained by this same controller, then
    /// authenticates the full original Stage or Commit lineage. Success supplies
    /// no grant, delivery, Ready or class acceptance.
    ///
    /// # Errors
    /// Refuses foreign or stale source/native custody, unrelated content, unknown
    /// record kinds or changed original requests, receipts, cuts and payloads.
    pub fn original_input_witness<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
        reference: &ContentRef,
    ) -> Result<PacketConnectedInputWitness<'a>, OperationFailure> {
        self.guard(scope)?;
        let result = (|| {
            let value: serde_json::Value = self.object(scope, reference)?;
            let record = match value.get("schema").and_then(serde_json::Value::as_str) {
                Some("source-owned.packet-staged-bytes/4") => {
                    OriginalInputRecord::Stage(self.stage_record(scope, reference)?)
                }
                Some("source-owned.packet-consumed-input/4") => {
                    OriginalInputRecord::Commit(self.commit_record(scope, reference)?)
                }
                _ => return Err(refused("connected original input witness kind changed")),
            };
            let bytes = scope.controller.content(reference).map_err(unknown)?;
            Ok(PacketConnectedInputWitness {
                reference: reference.clone(),
                bytes,
                record,
            })
        })();
        self.guard(scope)?;
        result
    }
}
