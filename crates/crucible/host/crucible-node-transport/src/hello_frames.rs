//! Computes role-normalized digests of complete original literal Hello frames.
//!
//! ```text
//! frame_digest = BLAKE3_DERIVE_KEY("source-owned.cnp-original-hello-frame/5",
//!                                 uint32_be(body_length) || original_body)
//! ```
//!
//! Request and response are named by protocol role, independently of local stream
//! direction. These fixed-size data values preserve raw correspondence only;
//! source-owned kernel, registrar and installed policy associations remain
//! separate. Partial originals cannot supply a complete frame digest.

use crate::{
    ProviderError,
    connection::EndpointRole,
    transport::original_frames::{FrameDirection, OriginalFrameReservation},
};

/// Reports complete raw Hello request and response digests without source rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalHelloFrameDigests {
    /// Commits to the original controller request, including its literal header.
    pub request_frame_digest: [u8; 32],
    /// Commits to the original native response, including its literal header.
    pub response_frame_digest: [u8; 32],
}

pub(crate) fn original_hello_frame_digests(
    bank: &OriginalFrameReservation,
    role: EndpointRole,
) -> Result<OriginalHelloFrameDigests, ProviderError> {
    let mut request = None;
    let mut response = None;
    for frame in bank.frames() {
        if !frame.complete || frame.transferred != frame.bytes.len() || frame.bytes.len() < 5 {
            return Err(ProviderError::Frame("original Hello frame incomplete"));
        }
        let header: [u8; 4] = frame.bytes[..4]
            .try_into()
            .map_err(|_| ProviderError::Frame("original Hello header missing"))?;
        if usize::try_from(u32::from_be_bytes(header)).ok() != Some(frame.bytes.len() - 4) {
            return Err(ProviderError::Frame("original Hello raw extent changed"));
        }
        let mut hash = blake3::Hasher::new_derive_key("source-owned.cnp-original-hello-frame/5");
        hash.update(frame.bytes);
        let digest = *hash.finalize().as_bytes();
        let controller_request = matches!(
            (role, frame.direction),
            (EndpointRole::Controller, FrameDirection::Outgoing)
                | (EndpointRole::Provider, FrameDirection::Incoming)
        );
        let slot = if controller_request {
            &mut request
        } else {
            &mut response
        };
        if slot.replace(digest).is_some() {
            return Err(ProviderError::Frame("original Hello direction repeated"));
        }
    }
    Ok(OriginalHelloFrameDigests {
        request_frame_digest: request
            .ok_or(ProviderError::Frame("original Hello request absent"))?,
        response_frame_digest: response
            .ok_or(ProviderError::Frame("original Hello response absent"))?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn append(
        bank: &mut OriginalFrameReservation,
        direction: FrameDirection,
        body: &[u8],
        complete: bool,
    ) {
        let framed = body.len() + 4;
        let slot = bank.begin(direction, framed).unwrap();
        bank.append(slot, &(body.len() as u32).to_be_bytes())
            .unwrap();
        bank.append(slot, body).unwrap();
        if direction == FrameDirection::Outgoing {
            bank.advance(slot, framed).unwrap();
        }
        if complete {
            bank.finish(slot).unwrap();
        }
    }

    #[test]
    fn hello_digests_normalize_roles_and_preserve_literal_whitespace() {
        let mut host = OriginalFrameReservation::reserve(128, 1).unwrap();
        let mut native = OriginalFrameReservation::reserve(128, 1).unwrap();
        append(
            &mut host,
            FrameDirection::Outgoing,
            b"{ \"kind\" : \"request\" }",
            true,
        );
        append(
            &mut host,
            FrameDirection::Incoming,
            b"{\"kind\":\"response\"}",
            true,
        );
        append(
            &mut native,
            FrameDirection::Incoming,
            b"{ \"kind\" : \"request\" }",
            true,
        );
        append(
            &mut native,
            FrameDirection::Outgoing,
            b"{\"kind\":\"response\"}",
            true,
        );
        let expected = original_hello_frame_digests(&host, EndpointRole::Controller).unwrap();
        assert_eq!(
            expected,
            original_hello_frame_digests(&native, EndpointRole::Provider).unwrap()
        );
        let reversed = original_hello_frame_digests(&host, EndpointRole::Provider).unwrap();
        assert_eq!(
            expected.request_frame_digest,
            reversed.response_frame_digest
        );
        assert_ne!(expected.request_frame_digest, reversed.request_frame_digest);

        let mut normalized = OriginalFrameReservation::reserve(128, 1).unwrap();
        append(
            &mut normalized,
            FrameDirection::Outgoing,
            b"{\"kind\":\"request\"}",
            true,
        );
        append(
            &mut normalized,
            FrameDirection::Incoming,
            b"{\"kind\":\"response\"}",
            true,
        );
        assert_ne!(
            expected.request_frame_digest,
            original_hello_frame_digests(&normalized, EndpointRole::Controller)
                .unwrap()
                .request_frame_digest
        );
    }

    #[test]
    fn hello_digests_refuse_missing_partial_or_repeated_directions_without_mutation() {
        let mut bank = OriginalFrameReservation::reserve(128, 2).unwrap();
        assert!(original_hello_frame_digests(&bank, EndpointRole::Controller).is_err());
        append(&mut bank, FrameDirection::Outgoing, b"{}", true);
        assert!(original_hello_frame_digests(&bank, EndpointRole::Controller).is_err());
        append(&mut bank, FrameDirection::Incoming, b"{}", false);
        let before = serde_json::to_vec(&bank.protocol_view()).unwrap();
        assert!(original_hello_frame_digests(&bank, EndpointRole::Controller).is_err());
        assert_eq!(serde_json::to_vec(&bank.protocol_view()).unwrap(), before);
        bank.finish(1).unwrap();
        assert!(original_hello_frame_digests(&bank, EndpointRole::Controller).is_ok());
        append(&mut bank, FrameDirection::Incoming, b"{}", true);
        let before = serde_json::to_vec(&bank.protocol_view()).unwrap();
        assert!(original_hello_frame_digests(&bank, EndpointRole::Controller).is_err());
        assert_eq!(serde_json::to_vec(&bank.protocol_view()).unwrap(), before);
    }
}
