//! Lends the actual sole incoming canonical report-query literal without copies.
//!
//! This is a local immutable data loan. The selected source writer's canonical
//! correspondence is checked against the original retained frame; generic wire
//! spelling tolerance does not acquire this source-class correspondence.

use super::*;
use crate::transport::original_frames::{FrameDirection, OriginalFrame};
use std::cell::Ref;

fn authenticate_literal(
    original: &Envelope,
    frame: OriginalFrame<'_>,
) -> Result<(), ProviderError> {
    if frame.direction != FrameDirection::Incoming
        || !frame.complete
        || frame.transferred != frame.bytes.len()
        || frame.bytes.len() < 4
    {
        return Err(ProviderError::Correlation(
            "report query literal progress differs",
        ));
    }
    let header: [u8; 4] = frame.bytes[..4]
        .try_into()
        .map_err(|_| ProviderError::Correlation("report query literal header absent"))?;
    if usize::try_from(u32::from_be_bytes(header)).ok() != Some(frame.bytes.len() - 4) {
        return Err(ProviderError::Correlation(
            "report query literal extent differs",
        ));
    }
    crate::protocol_snapshot::owned11::correspondence::envelope(original, &frame.bytes[4..])
}

impl<S: ProviderStream> Connection<S> {
    /// Lends the exact retained canonical body of the sole original Observe query.
    ///
    /// The loan holds the actual frame-bank borrow through hashing. The caller
    /// drops it before publication or transport work. No canonical bytes are
    /// generated, no correlation advances, and no allocation right is issued.
    pub(crate) fn original_report_query_body_data(
        &self,
        original: &Envelope,
        first_response: u64,
    ) -> Result<Ref<'_, [u8]>, ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.original_native_owned11_admission()?;
        if self.role != EndpointRole::Provider || original.method != Method::Observe {
            return Err(ProviderError::Correlation(
                "report query requires native Observe",
            ));
        }
        self.guard
            .preflight_original_packet_prefix_data(original, first_response, 1, 0)?;
        let slot = self
            .reader
            .original_slot()
            .ok_or(ProviderError::Correlation(
                "report query reader original absent",
            ))?;
        let frames = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "report query literal bank absent",
            ))?;
        let bank = frames
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("report query literal bank borrowed"))?;
        authenticate_literal(
            original,
            bank.frame(slot).ok_or(ProviderError::Correlation(
                "report query original slot absent",
            ))?,
        )?;
        self.authority.ensure_live()?;
        Ref::filter_map(bank, |bank| {
            bank.frame(slot).and_then(|frame| frame.bytes.get(4..))
        })
        .map_err(|_| ProviderError::Correlation("report query literal body absent"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Nullable;
    use crucible_node_format::{Extensions, U64, canonical};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn original() -> Result<Envelope, ProviderError> {
        Ok(Envelope {
            protocol: "CNP/1".to_owned(),
            message: MessageKind::Request,
            session_id: Nullable(Some(Id::new("session")?)),
            incarnation_id: Nullable(Some(Id::new("incarnation")?)),
            node_id: Nullable(Some(Id::new("node")?)),
            execution_owner_id: Nullable(Some(Id::new("owner")?)),
            capture_owner_id: Nullable(None),
            request_id: Nullable(Some(Id::new("query")?)),
            operation_id: Nullable(None),
            sequence: U64::new(8),
            method: Method::Observe,
            body: serde_json::Map::new(),
            extensions: Extensions::new(),
        })
    }

    #[test]
    fn full_original_literal_matches_without_reencoding_or_accepting_changed_sequence() -> TestResult
    {
        let original = original()?;
        let body = canonical::canonical_json(&serde_json::to_value(&original)?)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
        bytes.extend_from_slice(&body);
        let frame = || OriginalFrame {
            direction: FrameDirection::Incoming,
            bytes: &bytes,
            transferred: bytes.len(),
            complete: true,
        };
        authenticate_literal(&original, frame())?;
        let mut changed = original.clone();
        changed.sequence = U64::new(9);
        assert!(authenticate_literal(&changed, frame()).is_err());
        assert_eq!(&bytes[4..], body);
        Ok(())
    }

    #[test]
    fn partial_wrong_direction_and_changed_header_refuse_before_body_loan() -> TestResult {
        let original = original()?;
        let body = canonical::canonical_json(&serde_json::to_value(&original)?)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::try_from(body.len())?.to_be_bytes());
        bytes.extend_from_slice(&body);
        assert!(
            authenticate_literal(
                &original,
                OriginalFrame {
                    direction: FrameDirection::Incoming,
                    bytes: &bytes,
                    transferred: bytes.len() - 1,
                    complete: false,
                }
            )
            .is_err()
        );
        assert!(
            authenticate_literal(
                &original,
                OriginalFrame {
                    direction: FrameDirection::Outgoing,
                    bytes: &bytes,
                    transferred: bytes.len(),
                    complete: true,
                }
            )
            .is_err()
        );
        bytes[0] = 1;
        assert!(
            authenticate_literal(
                &original,
                OriginalFrame {
                    direction: FrameDirection::Incoming,
                    bytes: &bytes,
                    transferred: bytes.len(),
                    complete: true,
                }
            )
            .is_err()
        );
        Ok(())
    }
}
