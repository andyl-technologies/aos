//! Retains historical policy-source transfer bytes after the original clearance.
//!
//! The exact received buffer is moved, not copied. Its original Q04 framing is
//! comparison DATA only: no Root peer, currentness, signing or resource loan is
//! carried here. Later decoding and verification belong to their new paid cut.

use super::super::{CreateQ04ErrorV1, Q04PreviewV1};

pub(crate) struct RetainedCreatePolicySourcesDataV1 {
    bytes: Vec<u8>,
    framing: Result<[u8; 16], CreateQ04ErrorV1>,
}

impl RetainedCreatePolicySourcesDataV1 {
    pub(super) fn capture(
        bytes: Vec<u8>,
        nonce: Result<[u8; 16], CreateQ04ErrorV1>,
    ) -> Self {
        let framing = nonce.and_then(|nonce| {
            Q04PreviewV1::decode(&bytes, nonce)?;
            Ok(nonce)
        });
        Self { bytes, framing }
    }

    pub(crate) fn preview(&self) -> Result<Q04PreviewV1<'_>, CreateQ04ErrorV1> {
        let nonce = self.framing.as_ref().map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
        Q04PreviewV1::decode(&self.bytes, *nonce).map_err(CreateQ04ErrorV1::from)
    }

    pub(crate) fn failure(&self) -> Option<&CreateQ04ErrorV1> {
        self.framing.as_ref().err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_framing_retains_the_exact_received_buffer_and_native_cause() {
        let bytes = vec![7; 100];
        let address = bytes.as_ptr();
        let owner = RetainedCreatePolicySourcesDataV1::capture(
            bytes, Err(CreateQ04ErrorV1::ChangedCut),
        );

        assert_eq!(owner.bytes.as_ptr(), address);
        assert_eq!(owner.bytes, vec![7; 100]);
        assert!(matches!(owner.failure(), Some(CreateQ04ErrorV1::ChangedCut)));
        assert!(owner.preview().is_err());
        assert_eq!(owner.bytes.as_ptr(), address);
    }
}
