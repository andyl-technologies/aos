//! Checks actual admission identities against complete borrowed original slots.

use super::{BorrowedAuthority17Lineage, bytes::*};
use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{Fields, invalid, plain_string};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BorrowedAdmission17Kind {
    Ack,
    Prepare,
    Commit,
}

#[derive(Clone, Copy)]
pub(crate) struct BorrowedAdmission17Lineage<'a> {
    pub(crate) encoded: &'a [u8],
    pub(crate) kind: BorrowedAdmission17Kind,
    pub(crate) authority: BorrowedAuthority17Lineage<'a>,
    pub(crate) request_id: &'a [u8],
    pub(crate) sequence: u64,
    pub(crate) literal_slot: usize,
    pub(crate) literal_length: usize,
    pub(crate) literal_digest: [u8; 32],
    pub(crate) original: Option<&'a [u8]>,
}

impl<'a> BorrowedAdmission17Lineage<'a> {
    pub(crate) fn authenticate_original(
        self,
        original: &[u8],
        frames: Frames17<'_>,
    ) -> Result<(), ProviderError> {
        if original == b"null"
            || field(original, "request_id")? != self.request_id
            || quoted(field(original, "sequence")?)? != self.sequence
            || field(original, "session_id")? != self.authority.session
            || field(original, "incarnation_id")? != self.authority.incarnation
        {
            return Err(invalid());
        }
        let frame = frames.frame(self.literal_slot)?;
        frame
            .bytes
            .range(4, frame.bytes.len().checked_sub(4).ok_or_else(invalid)?)?
            .canonical(original)
    }

    pub(crate) fn read(
        input: &'a [u8],
        authority: BorrowedAuthority17Lineage<'a>,
        frames: Frames17<'a>,
    ) -> Result<Self, ProviderError> {
        let kind = match plain_string(field(input, "schema")?)? {
            "source-private.native-verified-admit-history/17" => BorrowedAdmission17Kind::Ack,
            "source-private.native-verified-prepare-history/17" => BorrowedAdmission17Kind::Prepare,
            "source-private.native-verified-commit-history/17" => BorrowedAdmission17Kind::Commit,
            _ => return Err(invalid()),
        };
        let identity = field(input, "identity")?;
        let identity_authority = BorrowedAuthority17Lineage::read(field(identity, "authority")?)?;
        let token_authority = BorrowedAuthority17Lineage::read(field(input, "authority")?)?;
        identity_authority.same_registration(authority)?;
        token_authority.same_registration(authority)?;
        let ack = kind == BorrowedAdmission17Kind::Ack;
        let request_id = field(identity, if ack { "admit_id" } else { "request_id" })?;
        let sequence = quoted(field(
            identity,
            if ack { "admit_sequence" } else { "sequence" },
        )?)?;
        let literal_slot = quantity(field(
            identity,
            if ack { "literal_index" } else { "literal_slot" },
        )?)?;
        let literal_length = quantity(field(identity, "literal_length")?)?;
        let literal_digest = digest(field(identity, "literal_digest")?)?;
        let frame = frames.frame(literal_slot)?;
        if !frame.incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() != literal_length
            || frame.bytes.hash()? != literal_digest
        {
            return Err(invalid());
        }
        let original = if ack {
            Some(field(input, "original")?)
        } else {
            None
        };
        if let Some(original) = original {
            if field(original, "request_id")? != request_id
                || quoted(field(original, "sequence")?)? != sequence
                || field(original, "session_id")? != authority.session
                || field(original, "incarnation_id")? != authority.incarnation
            {
                return Err(invalid());
            }
            frame
                .bytes
                .range(4, frame.bytes.len().checked_sub(4).ok_or_else(invalid)?)?
                .canonical(original)?;
        }
        Ok(Self {
            encoded: input,
            kind,
            authority,
            request_id,
            sequence,
            literal_slot,
            literal_length,
            literal_digest,
            original,
        })
    }
}
