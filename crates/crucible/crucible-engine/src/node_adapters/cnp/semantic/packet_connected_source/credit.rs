//! Complete source-fixed packet original prefixes before any consuming dispatch.
//!
//! This counts immutable outgoing uploads and incoming native proof transfers,
//! not only the final semantic reply. Capacity checks are data guards beneath
//! the same exclusively owned controller; they grant no native/common authority.

use crucible_node_transport::client::CnpController;

use super::{OperationFailure, refused};

const FRAME_BYTES: usize = 65_536;
const CHUNK_BYTES: usize = 4096;
const AUTHORIZATION_BYTES: usize = 8192;

pub(super) enum Prefix {
    Preparation,
    Stage,
    InputStage,
    InputCommit,
    WorldActivation,
    Operation,
    Observation,
    Query,
    Retirement,
}

struct Allowance {
    controller_requests: usize,
    provider_requests: usize,
    journal_bytes: usize,
    content_objects: usize,
    content_bytes: usize,
}

impl Prefix {
    fn allowance(self) -> Result<Allowance, OperationFailure> {
        let (uploads, ordinary_requests, native_proofs): (&[usize], usize, usize) = match self {
            Self::Preparation => (&[], 2, 1),
            Self::Stage => (&[], 1, 1),
            Self::InputStage => (&[FRAME_BYTES, 32, 32, 32, 32], 1, 3),
            Self::InputCommit => (&[], 1, 3),
            Self::WorldActivation => (&[FRAME_BYTES, FRAME_BYTES], 1, 1),
            Self::Operation => (&[FRAME_BYTES, FRAME_BYTES, AUTHORIZATION_BYTES], 2, 2),
            Self::Observation => (&[FRAME_BYTES, FRAME_BYTES], 2, 2),
            Self::Query => (&[], 1, 0),
            Self::Retirement => (&[AUTHORIZATION_BYTES], 1, 0),
        };
        let mut controller_requests = ordinary_requests;
        let mut content_bytes = native_proofs * FRAME_BYTES;
        for bytes in uploads {
            controller_requests = controller_requests
                .checked_add(bytes.div_ceil(CHUNK_BYTES) + 2)
                .ok_or_else(|| refused("packet complete upload request credit overflows"))?;
            content_bytes = content_bytes
                .checked_add(*bytes)
                .ok_or_else(|| refused("packet complete upload byte credit overflows"))?;
        }
        // Each complete incoming proof owns BlobBegin, up to sixteen chunks,
        // BlobFinish, and both original request/response envelopes per row.
        let provider_requests = native_proofs * (FRAME_BYTES / CHUNK_BYTES + 2);
        let journal_bytes = controller_requests
            .checked_add(provider_requests)
            .and_then(|rows| rows.checked_mul(2 * FRAME_BYTES))
            .ok_or_else(|| refused("packet complete prefix journal credit overflows"))?;
        Ok(Allowance {
            controller_requests,
            provider_requests,
            journal_bytes,
            content_objects: uploads.len() + native_proofs,
            content_bytes,
        })
    }

    pub(super) fn preflight(self, controller: &CnpController) -> Result<(), OperationFailure> {
        let limits = controller.authority().limits();
        if limits.frame_bytes.get() < FRAME_BYTES as u64
            || limits.blob_chunk_bytes.get() < CHUNK_BYTES as u64
        {
            return Err(refused("packet complete source prefix dialect limits"));
        }
        let allowance = self.allowance()?;
        controller
            .preflight_source_reply(
                allowance.controller_requests,
                allowance.provider_requests,
                allowance.journal_bytes,
                allowance.content_objects,
                allowance.content_bytes,
            )
            .map_err(|error| refused(error.to_string()))
    }
}
