//! Complete source-fixed packet original prefixes before any consuming dispatch.
//!
//! This counts immutable outgoing uploads and incoming native proof transfers,
//! not only the final semantic reply. Capacity checks are data guards beneath
//! the same exclusively owned controller; they grant no native/common authority.

use crucible_node_transport::client::CnpController;

use super::{OperationFailure, PacketConnectedSemanticSource, refused};
use crucible_node_transport::reference_packet::service::capture_allocation::MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES;

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
    fn allowance(self, complete: bool, allocation: bool) -> Result<Allowance, OperationFailure> {
        if allocation && !complete {
            return Err(refused(
                "packet allocation reply requires complete native evidence",
            ));
        }
        let report_bytes = if allocation && matches!(self, Self::Observation) {
            MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES
        } else {
            0
        };
        // Complete Control::record_evidence retains both the underlying record
        // and its receipt. Begin/Poll and World/Observe each produce two proofs.
        // Input stages/commits instead publish their three distinct native,
        // custody and receipt objects, independently of the Complete wrapper.
        let (uploads, ordinary_requests, proof_objects): (&[usize], usize, usize) = match self {
            Self::Preparation => (&[], 2, if complete { 2 } else { 1 }),
            Self::Stage => (&[], 1, if complete { 2 } else { 1 }),
            Self::InputStage => (&[FRAME_BYTES, 32, 32, 32, 32], 1, 3),
            Self::InputCommit => (&[], 1, 3),
            Self::WorldActivation => (&[FRAME_BYTES, FRAME_BYTES], 1, if complete { 2 } else { 1 }),
            Self::Operation => (
                &[FRAME_BYTES, FRAME_BYTES, AUTHORIZATION_BYTES],
                2,
                if complete { 4 } else { 2 },
            ),
            Self::Observation => (&[FRAME_BYTES, FRAME_BYTES], 2, if complete { 4 } else { 2 }),
            Self::Query => (&[], 1, 0),
            Self::Retirement => (&[AUTHORIZATION_BYTES], 1, 0),
        };
        let mut controller_requests = ordinary_requests;
        let mut content_bytes = proof_objects * FRAME_BYTES + report_bytes;
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
        // Selected Observe12 embeds the receipt in its outer record, retaining
        // one additional report object rather than another receipt copy.
        let provider_requests = proof_objects * (FRAME_BYTES / CHUNK_BYTES + 2)
            + if report_bytes == 0 {
                0
            } else {
                report_bytes.div_ceil(CHUNK_BYTES) + 2
            };
        let journal_bytes = controller_requests
            .checked_add(provider_requests)
            .and_then(|rows| rows.checked_mul(2 * FRAME_BYTES))
            .ok_or_else(|| refused("packet complete prefix journal credit overflows"))?;
        Ok(Allowance {
            controller_requests,
            provider_requests,
            journal_bytes,
            content_objects: uploads.len() + proof_objects + usize::from(report_bytes != 0),
            content_bytes,
        })
    }

    fn preflight(
        self,
        controller: &CnpController,
        complete: bool,
        allocation: bool,
    ) -> Result<(), OperationFailure> {
        let limits = controller.authority().limits();
        if limits.frame_bytes.get() < FRAME_BYTES as u64
            || limits.blob_chunk_bytes.get() < CHUNK_BYTES as u64
        {
            return Err(refused("packet complete source prefix dialect limits"));
        }
        let allowance = self.allowance(complete, allocation)?;
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

impl PacketConnectedSemanticSource {
    /// Counts additional immutable evidence-selection and wrapper call controls.
    pub(in crate::node_adapters::cnp::semantic) fn reply_credit_selection_counter_scratch_data()
    -> usize {
        use std::mem::size_of;

        // Each call boundary retains its own Complete/allocation arguments.
        3 * size_of::<[bool; 2]>()
            + size_of::<usize>()
            + size_of::<&Self>()
            + size_of::<Prefix>()
            + size_of::<&CnpController>()
    }

    pub(super) fn preflight_reply(
        &self,
        prefix: Prefix,
        controller: &CnpController,
    ) -> Result<(), OperationFailure> {
        prefix.preflight(
            controller,
            self.complete_storage.is_some(),
            self.complete_capture_allocation_selection.is_some(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_prefixes_reserve_underlying_records_and_receipts() {
        // Control::record_evidence publishes two distinct objects per ordinary
        // Complete proof. Begin/Poll and World/Observe each produce two proofs.
        for (prefix, objects, transfers, bytes) in [
            (Prefix::Preparation, 2, 36, 2 * FRAME_BYTES),
            (Prefix::Stage, 2, 36, 2 * FRAME_BYTES),
            (Prefix::WorldActivation, 4, 36, 4 * FRAME_BYTES),
            (
                Prefix::Operation,
                7,
                72,
                6 * FRAME_BYTES + AUTHORIZATION_BYTES,
            ),
            (Prefix::Observation, 6, 72, 6 * FRAME_BYTES),
        ] {
            let allowance = prefix.allowance(true, false).unwrap();

            assert_eq!(allowance.content_objects, objects);
            assert_eq!(allowance.provider_requests, transfers);
            assert_eq!(allowance.content_bytes, bytes);
            assert_eq!(
                allowance.journal_bytes,
                (allowance.controller_requests + transfers) * 2 * FRAME_BYTES,
            );
        }
    }

    #[test]
    fn allocation_observe_reserves_its_separate_original_report() {
        // capture_publication replaces the receipt with its outer record and
        // appends the independently transferred report. It does not transfer
        // the superseded receipt as a fourth object for this Observe.
        let allowance = Prefix::Observation.allowance(true, true).unwrap();

        assert_eq!(allowance.content_objects, 7);
        assert_eq!(allowance.provider_requests, 78);
        assert_eq!(
            allowance.content_bytes,
            6 * FRAME_BYTES + MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES,
        );
        assert_eq!(allowance.journal_bytes, 232 * FRAME_BYTES);

        let ordinary = Prefix::Stage.allowance(true, false).unwrap();
        let selected = Prefix::Stage.allowance(true, true).unwrap();
        assert_eq!(ordinary.content_objects, selected.content_objects);
        assert_eq!(ordinary.content_bytes, selected.content_bytes);
        assert_eq!(ordinary.provider_requests, selected.provider_requests);
    }

    #[test]
    fn allocation_reply_without_complete_evidence_is_refused() {
        assert!(Prefix::Stage.allowance(false, true).is_err());
    }

    #[test]
    fn input_prefixes_keep_their_three_distinct_original_proof_objects() {
        let stage = Prefix::InputStage.allowance(true, true).unwrap();
        let commit = Prefix::InputCommit.allowance(true, true).unwrap();

        assert_eq!(stage.content_objects, 8);
        assert_eq!(stage.provider_requests, 54);
        assert_eq!(stage.content_bytes, 4 * FRAME_BYTES + 4 * 32);
        assert_eq!(commit.content_objects, 3);
        assert_eq!(commit.provider_requests, 54);
        assert_eq!(commit.content_bytes, 3 * FRAME_BYTES);
    }
}
