//! Validates the selected native held-proof prefix before Host cache/content effects.
//!
//! Prepare has no prefix; Commit carries exactly one canonical native object.
//! This fixed view does not authenticate Source proofs or issue a receive grant.

use super::*;
use crate::reference_packet::service::complete_restore::{
    maximum_complete_restore_held_evidence_bytes, transfer::PacketCompleteRestoreTransferPhase,
};

pub(in crate::client) struct HeldPrefix {
    phase: PacketCompleteRestoreTransferPhase,
    chunk: usize,
    maximum: usize,
    first: Option<u64>,
    next: Option<u64>,
    length: usize,
    received: usize,
    digest: [u8; 64],
    finished: bool,
}

impl HeldPrefix {
    pub(in crate::client) fn new(
        phase: PacketCompleteRestoreTransferPhase,
        authority: &ConnectionAuthority,
    ) -> Result<Self, ProviderError> {
        authority.ensure_live()?;
        let chunk = usize::try_from(authority.limits().blob_chunk_bytes.get())
            .map_err(|_| refused())?
            .min(4096);
        if chunk == 0 {
            return Err(refused());
        }
        Ok(Self {
            phase,
            chunk,
            maximum: maximum_complete_restore_held_evidence_bytes()?,
            first: None,
            next: None,
            length: 0,
            received: 0,
            digest: [0; 64],
            finished: false,
        })
    }

    pub(in crate::client) fn phase_data(&self) -> PacketCompleteRestoreTransferPhase {
        self.phase
    }

    pub(in crate::client) fn requires_content(&self) -> bool {
        self.phase == PacketCompleteRestoreTransferPhase::Commit
    }

    pub(in crate::client) fn authenticate_request(
        &mut self,
        original: &Envelope,
        request: &Envelope,
        body: &RequestBody,
    ) -> Result<(), ProviderError> {
        if !self.requires_content()
            || self.finished
            || request.protocol != original.protocol
            || request.message != MessageKind::Request
            || request.session_id != original.session_id
            || request.incarnation_id != original.incarnation_id
            || request.node_id.0.is_some()
            || request.execution_owner_id.0.is_some()
            || request.capture_owner_id.0.is_some()
            || request.operation_id.0.is_some()
            || !request.extensions.is_empty()
            || self.next.is_some_and(|next| request.sequence.get() != next)
            || sequence_id(
                request.request_id.0.as_ref().ok_or_else(refused)?.as_str(),
                "packet-restore-held-proof-",
            )? != request.sequence.get()
        {
            return Err(refused());
        }
        let next = request.sequence.get().checked_add(1).ok_or_else(refused)?;
        match body {
            RequestBody::BlobBegin(begin)
                if request.method == crate::envelope::Method::BlobBegin
                    && self.first.is_none()
                    && begin.extensions.is_empty() =>
            {
                if sequence_id(begin.transfer_id.as_str(), "packet-restore-held-transfer-")?
                    != request.sequence.get()
                {
                    return Err(refused());
                }
                let length = usize::try_from(begin.content.length.get()).map_err(|_| refused())?;
                authenticate_reference(&begin.content)?;
                if length == 0 || length > self.maximum {
                    return Err(refused());
                }
                self.digest
                    .copy_from_slice(begin.content.hash.digest.as_bytes());
                self.length = length;
                self.first = Some(request.sequence.get());
            }
            RequestBody::BlobChunk(chunk)
                if request.method == crate::envelope::Method::BlobChunk
                    && self.first.is_some()
                    && chunk.extensions.is_empty() =>
            {
                self.authenticate_transfer(&chunk.transfer_id)?;
                let expected = self
                    .length
                    .checked_sub(self.received)
                    .ok_or_else(refused)?
                    .min(self.chunk);
                if expected == 0
                    || chunk.bytes.as_slice().len() != expected
                    || usize::try_from(chunk.offset.get()).ok() != Some(self.received)
                {
                    return Err(refused());
                }
                self.received = self.received.checked_add(expected).ok_or_else(refused)?;
            }
            RequestBody::BlobFinish(finish)
                if request.method == crate::envelope::Method::BlobFinish
                    && self.first.is_some()
                    && finish.extensions.is_empty()
                    && self.received == self.length =>
            {
                self.authenticate_transfer(&finish.transfer_id)?;
                self.finished = true;
            }
            _ => return Err(refused()),
        }
        self.next = Some(next);
        Ok(())
    }

    fn authenticate_transfer(&self, id: &Id) -> Result<(), ProviderError> {
        if Some(sequence_id(id.as_str(), "packet-restore-held-transfer-")?) != self.first {
            return Err(refused());
        }
        Ok(())
    }

    pub(in crate::client) fn authenticate_terminal(
        &self,
        response: &ResponseBody,
    ) -> Result<(), ProviderError> {
        // Real errors retain their ordinary full-R storage and remain available
        // to the Source. They never complete its verified phase.
        if matches!(&response.shape, ResponseShape::Error { .. }) {
            return Ok(());
        }
        if !matches!(
            &response.shape,
            ResponseShape::Completed {
                operation_state: OperationState::Completed,
                ..
            }
        ) {
            return Err(refused());
        }
        let Some(MethodResult::PrepareRestore(result)) = &response.result else {
            return Err(refused());
        };
        if self.requires_content() {
            authenticate_reference(&result.closed_gate_receipt)?;
            if !self.finished
                || result.closed_gate_receipt.length.get() != self.length as u64
                || result.closed_gate_receipt.hash.digest.as_bytes() != self.digest
            {
                return Err(refused());
            }
        } else if self.first.is_some() {
            return Err(refused());
        }
        Ok(())
    }
}

fn authenticate_reference(reference: &ContentRef) -> Result<(), ProviderError> {
    if reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
        || reference.hash.digest.len() != 64
        || !reference
            .hash
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || reference.media_type != "application/json"
    {
        return Err(refused());
    }
    Ok(())
}

fn sequence_id(value: &str, prefix: &str) -> Result<u64, ProviderError> {
    let digits = value.strip_prefix(prefix).ok_or_else(refused)?;
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(refused());
    }
    digits.parse().map_err(|_| refused())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("selected restore held-proof prefix changed")
}

#[cfg(test)]
#[path = "restore_transfer_prefix/tests.rs"]
mod tests;
