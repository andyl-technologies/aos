//! Validates complete original command, prefix and consumed-ACK archival bodies.
//!
//! Native proposal bytes are retained unchanged and grant no retirement authority.
//! The owning adapter must authenticate the proposal through the native source
//! operation before requesting slot release.

// SPDX-License-Identifier: Apache-2.0

use crucible_protocol::node_control::{
    NativeEffectCompute, NativeEffectProgress, NativeEffectProgressStatus,
    NativePrefixAcknowledgement, NativePrefixProgress,
};

use super::ArchiveError;
use super::codec::{Cursor, put_blob};

/// Retains one immutable native result and both sides of its exact ACK exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixEvidence {
    /// Retains complete canonical Result256 or Result320 bytes.
    pub result: Vec<u8>,
    /// Retains the exact original ACK192 offered to the native source.
    pub offered_acknowledgement: Vec<u8>,
    /// Retains the actual native-consumed ACK192 returned by the source getter.
    pub consumed_acknowledgement: Vec<u8>,
}

/// Retains every original prefix before a terminal native retirement request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalEvidence {
    /// Retains all prefixes in their original order, including the initial256.
    pub prefixes: Vec<PrefixEvidence>,
    /// Retains the complete original native terminal-retirement proposal.
    pub native_proposal: Vec<u8>,
}

impl TerminalEvidence {
    /// Validates complete history and a consumed final ACK without granting release.
    ///
    /// # Errors
    /// Rejects foreign history, dropped prefixes, changed ACKs, nonterminal results,
    /// unknown effects or an exhausted declared prefix/evidence bound.
    pub fn validate(
        &self,
        original: &NativeEffectCompute,
        maximum_prefixes: u32,
    ) -> Result<(), ArchiveError> {
        if self.prefixes.is_empty()
            || self.prefixes.len() > maximum_prefixes as usize
            || self.native_proposal.is_empty()
            || self.native_proposal.len() > 4096
        {
            return Err(ArchiveError::Budget);
        }
        let first = NativeEffectProgress::decode(&self.prefixes[0].result)?;
        first.validate_against(original)?;
        validate_ack(
            &self.prefixes[0],
            NativePrefixAcknowledgement::from_initial(&first)?,
        )?;
        let mut previous = None;
        let mut final_status = first.status;
        let mut final_end = first.end_result;
        for evidence in &self.prefixes[1..] {
            let result = NativePrefixProgress::decode(&evidence.result)?;
            if let Some(previous) = &previous {
                result.validate_after_progress(original, previous)?;
            } else {
                result.validate_after_initial(original, &first)?;
            }
            validate_ack(
                evidence,
                NativePrefixAcknowledgement::from_progress(&result)?,
            )?;
            final_status = result.status;
            final_end = result.end_result;
            previous = Some(result);
        }
        if final_status != NativeEffectProgressStatus::Completed || final_end != 0 {
            return Err(ArchiveError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ArchiveError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.prefixes.len() as u32).to_be_bytes());
        for prefix in &self.prefixes {
            put_blob(&mut bytes, &prefix.result)?;
            put_blob(&mut bytes, &prefix.offered_acknowledgement)?;
            put_blob(&mut bytes, &prefix.consumed_acknowledgement)?;
        }
        put_blob(&mut bytes, &self.native_proposal)?;
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8], maximum_prefixes: u32) -> Result<Self, ArchiveError> {
        let mut cursor = Cursor(bytes);
        let count = cursor.u32()?;
        if count == 0 || count > maximum_prefixes {
            return Err(ArchiveError::Corrupt);
        }
        let mut prefixes = Vec::new();
        prefixes
            .try_reserve_exact(count as usize)
            .map_err(|_| ArchiveError::Budget)?;
        for _ in 0..count {
            prefixes.push(PrefixEvidence {
                result: cursor.blob(320)?.to_vec(),
                offered_acknowledgement: cursor.blob(192)?.to_vec(),
                consumed_acknowledgement: cursor.blob(192)?.to_vec(),
            });
        }
        let native_proposal = cursor.blob(4096)?.to_vec();
        cursor.finish()?;
        Ok(Self {
            prefixes,
            native_proposal,
        })
    }
}

fn validate_ack(
    evidence: &PrefixEvidence,
    expected: NativePrefixAcknowledgement,
) -> Result<(), ArchiveError> {
    if evidence.offered_acknowledgement != expected.encode()?
        || evidence.consumed_acknowledgement != evidence.offered_acknowledgement
    {
        return Err(ArchiveError::Conflict);
    }
    Ok(())
}
