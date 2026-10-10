//! Reads a complete source-selected native Stage receipt beneath completion custody.
//!
//! Direct rows are inert codec data. Native source validation remains mandatory
//! before and after generic closure checks; this reader issues no permission.

use super::*;
use crate::node_scheduling::InputPayload;
use crucible_node_contract::ContentRef;

/// Retains original native input receipt bytes with complete direct codec rows.
#[derive(serde::Serialize)]
pub struct OriginalInputEvidence {
    /// Names exactly the ACK root retained by the owning runtime.
    pub root: ContentRef,
    /// Retains every typed body once in strict full-reference order.
    pub objects: Vec<InputPayload>,
    /// Retains one complete authenticated direct row for every body.
    pub rows: Vec<OriginalLineageRow>,
}

impl NodeRuntime {
    /// Reads original native staging receipt closure through an actual completed token.
    ///
    /// The source hook is default-refusing and must reserve the full supplied
    /// limits before copying. Generic body integrity cannot authenticate a
    /// source codec, native custody or readiness. Empty input permission returns
    /// explicit absence without invoking a native hook.
    ///
    /// # Errors
    /// Refuses foreign or pending completions, missing staged custody, retained
    /// failure, unsupported source readers, incomplete closure or byte limits.
    /// Native uncertainty and corrupt readback preserve containment obligations.
    pub fn original_input_evidence(
        &mut self,
        token: &OperationToken,
        limits: OriginalInputLineageLimits,
    ) -> Result<Option<OriginalInputEvidence>, RuntimePollFailure> {
        self.validate_token(token)
            .map_err(RuntimePollFailure::Admission)?;
        self.checked_route(&token.route.node)
            .map_err(RuntimePollFailure::Admission)?;
        let entry = self
            .operations
            .get(token.operation())
            .ok_or(RuntimePollFailure::Admission(
                RuntimeError::ForeignAuthority,
            ))?;
        if !matches!(
            entry.result,
            RetainedResult::Complete(_) | RetainedResult::Acknowledged(_)
        ) {
            return Err(RuntimePollFailure::Admission(
                RuntimeError::OutstandingObligations,
            ));
        }
        let Some(staged) = self
            .observe_original_staged_input(&entry.admission)
            .map_err(RuntimePollFailure::Admission)?
        else {
            return Ok(None);
        };
        let defaults = OriginalInputLineageLimits::default();
        if limits.maximum_objects == 0
            || limits.maximum_objects > defaults.maximum_objects
            || limits.maximum_bytes == 0
            || limits.maximum_bytes > defaults.maximum_bytes
            || limits.maximum_edges > defaults.maximum_edges
            || staged.acknowledgement().proof_ref.length.get() > limits.maximum_bytes as u64
        {
            return Err(RuntimePollFailure::Admission(RuntimeError::ResourceLimit));
        }
        let source = self
            .nodes
            .get(&token.route.node)
            .ok_or(RuntimePollFailure::Admission(RuntimeError::UnknownNode))?;
        let read = (|| {
            let evidence =
                source.read_original_input_evidence(&entry.admission, &staged, limits)?;
            source.validate_original_input_evidence(&entry.admission, &staged, &evidence)?;
            Ok::<_, OperationFailure>(evidence)
        })();
        let evidence = match read {
            Ok(evidence) => evidence,
            Err(failure) => {
                if failure.effects != EffectKnowledge::None {
                    self.contain_roster(token.route());
                }
                return Err(RuntimePollFailure::Native(failure));
            }
        };
        let valid = evidence.root == staged.acknowledgement().proof_ref
            && valid_geometry(&evidence, limits).is_ok()
            && source
                .validate_original_input_evidence(&entry.admission, &staged, &evidence)
                .is_ok()
            && self
                .snapshots
                .get(&token.route.node)
                .is_some_and(|snapshot| snapshot.validate_current(source.as_ref()).is_ok());
        if !valid {
            self.contain_roster(token.route());
            return Err(RuntimePollFailure::Admission(RuntimeError::InvalidReceipt));
        }
        Ok(Some(evidence))
    }
}

fn valid_geometry(
    evidence: &OriginalInputEvidence,
    limits: OriginalInputLineageLimits,
) -> Result<(), RuntimeError> {
    if evidence.objects.len() > limits.maximum_objects
        || evidence.rows.len() != evidence.objects.len()
        || evidence
            .objects
            .windows(2)
            .any(|pair| pair[0].reference >= pair[1].reference)
    {
        return Err(RuntimeError::ResourceLimit);
    }
    let mut bytes = 0usize;
    for (object, row) in evidence.objects.iter().zip(&evidence.rows) {
        bytes = bytes
            .checked_add(object.bytes.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        if bytes > limits.maximum_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        if object.reference != row.object
            || object.reference.verify(&object.bytes).is_err()
            || evidence.objects.iter().any(|other| {
                other.reference.hash == object.reference.hash
                    && other.reference.length != object.reference.length
            })
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    original_input_lineage::validate_original_input_evidence_rows(
        &evidence.rows,
        &evidence.root,
        limits,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "runtime_original_input_evidence_tests.rs"]
mod tests;
