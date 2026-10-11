//! Exclusively retained canonical sends prepared before source-native effects.
//!
//! Preparation owns the complete frame and original correlation before a
//! callback. Publication discharges transport correlation only, never an
//! execution operation, output body or native owner. Abandoned preparations
//! fence their original connection and transfer unresolved originals.

use std::io;

use serde::Serialize;

use super::*;

/// Retains one exact prepared frame under the same exclusively borrowed stream.
///
/// Its fields are private and its lifetime excludes intervening receives or
/// sends on this connection. It grants no native operation authority. The
/// source owner must retain complete native custody outside this transport
/// capsule until authentic reconciliation or reclamation.
#[must_use = "publish the original prepared frame or retain its fenced custody"]
pub struct PreparedSend<'a, S: ProviderStream> {
    connection: &'a mut Connection<S>,
    original: Envelope,
    bytes: Vec<u8>,
    completed: bool,
}

impl<S: ProviderStream> Connection<S> {
    /// Prepares exact canonical bytes and original correlation before effects.
    ///
    /// The complete borrowed envelope is sized before JSON value allocation.
    /// All closed body/schema, scope, sequence and original correlation checks
    /// precede reservation. No bytes are sent by preparation, and a dropped
    /// capsule fences the same connection instead of releasing retry authority.
    /// Existing [`Self::send`] behavior and wire bytes remain unchanged.
    ///
    /// # Errors
    /// Refuses revoked/fenced authority, malformed or oversized envelopes,
    /// changed originals, wrong sequence and exhausted original correlations.
    pub fn prepare_send(
        &mut self,
        original: Envelope,
    ) -> Result<PreparedSend<'_, S>, ProviderError> {
        self.check_authority()?;
        let limits = self.authority.limits();
        let maximum_bytes = allowance(limits.frame_bytes.get())?;
        let maximum_nesting = allowance(limits.nesting.get())?;
        serialized_credit(&original, maximum_bytes)?;
        self.validate_body(&original, false)?;

        let value =
            serde_json::to_value(&original).map_err(crucible_node_contract::ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        canonical::parse_json_with_depth(&bytes, maximum_bytes, maximum_nesting)?;
        self.authority
            .with_live(|| self.guard.register_outgoing(original.clone()))?;
        Ok(PreparedSend {
            connection: self,
            original,
            bytes,
            completed: false,
        })
    }
}

impl<S: ProviderStream> PreparedSend<'_, S> {
    /// Publishes only the previously prepared original canonical frame bytes.
    ///
    /// Encoding and original response/request copies already precede the source
    /// callback. Success confirms transport response correlation only. Failure
    /// fences the same stream while its supervisor retains unresolved originals;
    /// neither case proves native completion, publication ACK or cleanup.
    ///
    /// # Errors
    /// Refuses revoked authority, incomplete transport writes or changed retained
    /// correlation. Native effects must remain owned independently on error.
    pub fn publish(mut self) -> Result<(), ProviderError> {
        self.connection.check_authority()?;
        let length = u32::try_from(self.bytes.len())
            .map_err(|_| ProviderError::Frame("prepared frame length is unrepresentable"))?;
        let stream = self.connection.reader.stream_mut();
        if let Err(error) = stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| stream.write_all(&self.bytes))
        {
            self.connection.contain(ConnectionFailure::Write);
            return Err(error.into());
        }
        if self.original.message == MessageKind::Response
            && let Err(error) = self.connection.guard.confirm_response_sent(&self.original)
        {
            self.connection.contain(ConnectionFailure::Protocol);
            return Err(error);
        }
        self.completed = true;
        Ok(())
    }
}

impl<S: ProviderStream> Drop for PreparedSend<'_, S> {
    fn drop(&mut self) {
        if !self.completed {
            self.connection.contain(ConnectionFailure::Closed);
        }
    }
}

pub(crate) fn serialized_credit(
    value: &impl Serialize,
    maximum: usize,
) -> Result<usize, ProviderError> {
    struct Counter {
        used: usize,
        maximum: usize,
    }

    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let next = self
                .used
                .checked_add(bytes.len())
                .filter(|next| *next <= self.maximum)
                .ok_or_else(|| io::Error::other("prepared frame exceeds complete byte credit"))?;
            self.used = next;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter { used: 0, maximum };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| ProviderError::ResourceExhausted("prepared whole frame bytes"))?;
    Ok(counter.used)
}
