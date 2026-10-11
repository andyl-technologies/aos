//! Owns the immutable no-extension packet transport verifier.
//!
//! Baseline framing and method decoding run in the ordinary Connection decoder.
//! This extra source verifier reads only that decoded envelope; it retains no
//! callback, policy object, mutable state or native authority. The connection
//! records this choice only when its own private installation method runs.

use super::{BodySchemaVerifier, ConnectionAuthority, Envelope, ProviderError, ReceivedBody};

pub(super) struct PacketSchema;

impl BodySchemaVerifier for PacketSchema {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        envelope: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        if !envelope.extensions.is_empty()
            || envelope.body.get("extensions").is_some_and(|extensions| {
                extensions
                    .as_object()
                    .is_none_or(|values| !values.is_empty())
            })
        {
            return Err(ProviderError::Correlation(
                "immutable packet transport extensions unsupported",
            ));
        }
        Ok(())
    }
}
