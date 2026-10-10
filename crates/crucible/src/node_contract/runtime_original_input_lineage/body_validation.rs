//! Checks exact historical typed bodies without issuing native lineage authority.

use super::*;
use crate::node_state::VerifiedStateContent;
use crucible_node_contract::{Event, EventStage, canonical};

impl OriginalLineageRuntimeRecord {
    /// Checks original bodies against an independently authenticated typed archive.
    ///
    /// This validates reference integrity and ordered Event facts only. The
    /// installed native continuation verifier must separately authenticate source
    /// windows, exact consumed inputs, predecessor/ACK journals and fresh owners.
    /// A matching archive body never constructs a live input association.
    ///
    /// # Errors
    /// Refuses metadata credit exhaustion, missing or changed full-reference roles,
    /// unsupported publication codecs or altered original delivery/Event tuples.
    pub fn validate_original_bodies(
        &self,
        content: &VerifiedStateContent,
        limits: OriginalInputLineageLimits,
        maximum_record_bytes: usize,
    ) -> Result<(), RuntimeError> {
        self.validate_metadata(limits, maximum_record_bytes)?;
        self.check_original_bodies(|reference| content.get(reference))
    }

    pub(in crate::node_contract::runtime) fn check_original_bodies<'a>(
        &self,
        mut body: impl FnMut(&ContentRef) -> Option<&'a [u8]>,
    ) -> Result<(), RuntimeError> {
        for input in &self.inputs {
            for reference in &input.payloads {
                verify_body(reference, &mut body)?;
            }
            if let Some(provenance) = &input.provenance {
                for reference in &provenance.objects {
                    verify_body(reference, &mut body)?;
                }
            }
            let Some(lineage) = &input.lineage else {
                continue;
            };
            for (publication, delivery) in lineage.publications.iter().zip(&input.deliveries) {
                for reference in &publication.objects {
                    verify_body(reference, &mut body)?;
                }
                if publication.published.media_type != "application/json" {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                let bytes = body(&publication.published).ok_or(RuntimeError::InvalidReceipt)?;
                let event: Event = canonical::decode(bytes, bytes.len())
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                if event.id != delivery.publication_id
                    || event.source != delivery.producer_endpoint
                    || event.source_sequence != delivery.native_sequence
                    || event.payload != delivery.payload
                    || event.provenance_ref != delivery.provenance_ref
                    || event.publication_position != delivery.publication
                    || event.position != delivery.publication
                    || event.stage != EventStage::Publication
                    || event.delivery_position.is_some()
                    || !event.extensions.is_empty()
                    || !event.causal_parent_ids.is_empty()
                    || !delivery.causal_parents.is_empty()
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
            }
        }
        Ok(())
    }
}

fn verify_body<'a>(
    reference: &ContentRef,
    body: &mut impl FnMut(&ContentRef) -> Option<&'a [u8]>,
) -> Result<(), RuntimeError> {
    let bytes = body(reference).ok_or(RuntimeError::InvalidReceipt)?;
    reference
        .verify(bytes)
        .map_err(|_| RuntimeError::InvalidReceipt)
}
