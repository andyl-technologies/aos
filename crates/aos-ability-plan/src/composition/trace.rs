//! Independent bounds for retained successful-pass explanations.

use aos_ability_model::DesiredStateDocument;
use aos_contract::Sha256Digest;
use serde::Serialize;

use crate::resolution::{CandidateRejection, ResolutionDecision, ResolutionPolicyDocument};
use aos_contract::limits::BoundedWriter;

use super::{CompositionError, CompositionLimits};

#[derive(Default)]
pub(super) struct TraceBudget {
    entries: u32,
    bytes: u64,
}

impl TraceBudget {
    pub(super) fn retain(
        &mut self,
        pass: BorrowedCompositionPass<'_>,
        limits: CompositionLimits,
    ) -> Result<(), CompositionError> {
        let BorrowedCompositionPass {
            round,
            desired_state,
            desired_state_digest,
            policy,
            policy_digest,
            decisions,
            rejections,
        } = pass;
        let additional_entries = decisions.len().saturating_add(rejections.len()) as u32;
        let entries =
            self.entries
                .checked_add(additional_entries)
                .ok_or(CompositionError::Limit {
                    limit: "trace entry count",
                })?;
        if entries > limits.max_trace_entries {
            return Err(CompositionError::Limit {
                limit: "trace entry count",
            });
        }
        let remaining = limits.max_trace_bytes.saturating_sub(self.bytes);
        let mut writer = BoundedWriter::new(remaining, "bounded composition trace exceeded");
        serde_json::to_writer(
            &mut writer,
            &BorrowedCompositionPass {
                round,
                desired_state,
                desired_state_digest,
                policy,
                policy_digest,
                decisions,
                rejections,
            },
        )
        .map_err(|error| {
            if writer.exceeded() {
                CompositionError::Limit {
                    limit: "trace byte",
                }
            } else {
                CompositionError::Encoding(error.to_string())
            }
        })?;
        let retained_bytes =
            self.bytes
                .checked_add(writer.written())
                .ok_or(CompositionError::Limit {
                    limit: "trace byte",
                })?;
        if retained_bytes > limits.max_trace_bytes {
            return Err(CompositionError::Limit {
                limit: "trace byte",
            });
        }
        self.entries = entries;
        self.bytes = retained_bytes;
        Ok(())
    }
}

#[derive(Serialize)]
pub(super) struct BorrowedCompositionPass<'a> {
    pub(super) round: u32,
    pub(super) desired_state: &'a DesiredStateDocument,
    pub(super) desired_state_digest: Sha256Digest,
    pub(super) policy: &'a ResolutionPolicyDocument,
    pub(super) policy_digest: Sha256Digest,
    pub(super) decisions: &'a [ResolutionDecision],
    pub(super) rejections: &'a [CandidateRejection],
}
