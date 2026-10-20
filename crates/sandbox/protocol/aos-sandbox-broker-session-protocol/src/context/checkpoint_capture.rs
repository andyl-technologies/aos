//! Retains the reached fixed historical context parser and canonical comparison.
//!
//! The same decoder serves the ordinary consuming adapter. This passive
//! destination grants no protected origin, currentness or financial authority.

use super::*;

pub(super) enum Disposition {
    Ordinary,
    Retained,
}

/// Retains partial historical context keys and exact decode causes.
#[doc(hidden)]
pub struct BrokerSessionContextCheckpointDecodeCaptureV1 {
    keys: Option<Vec<ProtectedBrokerSessionKeyV1>>,
    context: Option<Result<Option<ProtectedBrokerSessionVerificationContextV1>, BrokerSessionValidationError>>,
    canonical_bytes: Option<Vec<u8>>,
    canonical: Option<Result<(), BrokerSessionValidationError>>,
    completion: Option<Result<(), BrokerSessionValidationError>>,
    closed: Option<BrokerSessionValidationError>,
    entered: bool,
    taken: bool,
}

impl Default for BrokerSessionContextCheckpointDecodeCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerSessionContextCheckpointDecodeCaptureV1 {
    /// Prearms fixed empty parsing slots without allocating or observing IO.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keys: None,
            context: None,
            canonical_bytes: None,
            canonical: None,
            completion: None,
            closed: None,
            entered: false,
            taken: false,
        }
    }

    /// Borrows the first actual parsing or canonical comparison refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&BrokerSessionValidationError> {
        self.context.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.canonical.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err()))
            .or(self.closed.as_ref())
    }

    /// Borrows the reached context model, which is never protected provenance.
    #[must_use]
    pub fn context(&self) -> Option<&ProtectedBrokerSessionVerificationContextV1> {
        self.context.as_ref()?.as_ref().ok()?.as_ref()
    }

    /// Moves a complete canonical model once while retaining its outcome.
    ///
    /// # Errors
    /// Refuses incomplete, failed, repeated or already-consumed parsing.
    pub fn take_context_once(&mut self)
        -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionValidationError>
    {
        if self.failure().is_some() || self.taken || !matches!(self.completion, Some(Ok(()))) {
            self.closed.get_or_insert(BrokerSessionValidationError::InvalidEncoding);
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        let context = self.context.as_mut().and_then(|result| result.as_mut().ok())
            .and_then(Option::take);
        match context {
            Some(context) => {
                self.taken = true;
                Ok(context)
            }
            None => {
                self.closed.get_or_insert(BrokerSessionValidationError::InvalidEncoding);
                Err(BrokerSessionValidationError::InvalidEncoding)
            }
        }
    }

    /// Reports actual fixed parser layout, including its owned context slots.
    #[must_use]
    pub const fn inline_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Reports the four reached key carriers and one canonical context buffer.
    #[must_use]
    pub const fn receiving_heap_bytes_v1() -> usize {
        4 * std::mem::size_of::<ProtectedBrokerSessionKeyV1>() + CHECKPOINT_BYTES
    }

    /// Counts all eight destination fields and four reached fixed key carriers.
    #[must_use]
    pub const fn metadata_cells_v1() -> usize {
        8 + 4
    }

    /// Reports the same fixed key, backing and outcome cells with checked DATA ABI.
    #[must_use]
    pub const fn receiving_metadata_cells_v1() -> Option<usize> {
        Some(Self::metadata_cells_v1())
    }

    pub(super) fn capture_once(
        &mut self,
        bytes: &[u8],
        disposition: Disposition,
    ) -> Result<(), BrokerSessionValidationError> {
        if self.entered {
            self.closed.get_or_insert(BrokerSessionValidationError::InvalidEncoding);
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        self.entered = true;
        self.completion = Some(self.decode_inner(bytes, disposition));
        if matches!(self.completion, Some(Ok(()))) {
            Ok(())
        } else {
            Err(BrokerSessionValidationError::InvalidEncoding)
        }
    }

    pub(super) fn into_ordinary_result(mut self)
        -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionValidationError>
    {
        let error = self.context.as_mut().and_then(|result| result.as_mut().err())
            .map(|cause| cause.clone())
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err()).cloned());
        if let Some(error) = error {
            // The old context/canonical temporary precedes the reached key Vec
            // in reverse local cleanup; neither ordinary buffer escapes.
            drop(self.canonical_bytes.take());
            drop(self.context.take());
            drop(self.keys.take());
            return Err(error);
        }
        self.take_context_once()
    }

    fn decode_inner(
        &mut self,
        bytes: &[u8],
        disposition: Disposition,
    ) -> Result<(), BrokerSessionValidationError> {
        if bytes.len() != CHECKPOINT_BYTES {
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        let mut input = bytes;
        if checkpoint_field::<8>(&mut input)? != *CHECKPOINT_MAGIC
            || checkpoint_field::<2>(&mut input)? != 1_u16.to_be_bytes()
        {
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        let domain_id = checkpoint_field(&mut input)?;
        let route_id = checkpoint_field(&mut input)?;
        let route_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
        let route_digest = checkpoint_field(&mut input)?;
        let trust_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
        let trust_digest = checkpoint_field(&mut input)?;
        let revocation_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
        let revocation_digest = checkpoint_field(&mut input)?;
        let node_id = checkpoint_field(&mut input)?;
        let boot_id = checkpoint_field(&mut input)?;
        let protocol = BrokerSessionProtocolV1::from_code(checkpoint_field::<1>(&mut input)?[0])?;
        let major = u16::from_be_bytes(checkpoint_field(&mut input)?);
        let minor = u16::from_be_bytes(checkpoint_field(&mut input)?);
        let audience = audience_from_code(checkpoint_field::<1>(&mut input)?[0])?;
        let client_process = checkpoint_field(&mut input)?;
        let broker_process = checkpoint_field(&mut input)?;
        self.keys = Some(Vec::with_capacity(4));
        for _ in 0..4 {
            let signer =
                BrokerSessionSignerReferenceV1::decode(checkpoint_slice(&mut input, 120)?)?;
            let public_key = checkpoint_field(&mut input)?;
            let minimum_authority_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
            let minimum_key_generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
            let revoked = checkpoint_field::<1>(&mut input)?[0];
            let superseded = checkpoint_field::<1>(&mut input)?[0];
            let generation = u64::from_be_bytes(checkpoint_field(&mut input)?);
            if revoked > 1 || superseded > 1 || (superseded == 0 && generation != 0) {
                return Err(BrokerSessionValidationError::InvalidEncoding);
            }
            let key = ProtectedBrokerSessionKeyV1::new(
                signer,
                public_key,
                minimum_authority_generation,
                minimum_key_generation,
                revoked == 1,
                (superseded == 1).then_some(generation),
            )?;
            self.keys.as_mut().ok_or(BrokerSessionValidationError::InvalidEncoding)?.push(key);
        }
        let keys = match disposition {
            Disposition::Ordinary => self.keys.take()
                .ok_or(BrokerSessionValidationError::InvalidEncoding)?
                .try_into().map_err(|_| BrokerSessionValidationError::InvalidEncoding)?,
            Disposition::Retained => {
                let keys: &[ProtectedBrokerSessionKeyV1; 4] = self.keys.as_deref()
                    .ok_or(BrokerSessionValidationError::InvalidEncoding)?
                    .try_into().map_err(|_| BrokerSessionValidationError::InvalidEncoding)?;
                // These four fixed wire carriers contain no heap ownership.
                // Their original reached Vec stays parked on validation Err.
                keys.clone()
            }
        };
        self.context = Some(ProtectedBrokerSessionVerificationContextV1::new(
            domain_id,
            route_id,
            route_generation,
            route_digest,
            trust_generation,
            trust_digest,
            revocation_generation,
            revocation_digest,
            node_id,
            boot_id,
            protocol,
            major,
            minor,
            audience,
            client_process,
            broker_process,
            keys,
        ).map(Some));
        let context = self.context.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(Option::as_ref).ok_or(BrokerSessionValidationError::InvalidEncoding)?;
        // Successful fixed key construction has no later borrower of this Vec.
        // Retire its backing only after the full context constructor succeeds.
        drop(self.keys.take());
        if !input.is_empty() {
            self.canonical = Some(Err(BrokerSessionValidationError::InvalidEncoding));
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        self.canonical_bytes = Some(context.checkpoint_bytes());
        self.canonical = Some(if self.canonical_bytes.as_deref() == Some(bytes) {
            Ok(())
        } else {
            Err(BrokerSessionValidationError::InvalidEncoding)
        });
        if !matches!(self.canonical, Some(Ok(()))) {
            return Err(BrokerSessionValidationError::InvalidEncoding);
        }
        // The exact canonical comparison is complete; this temporary has
        // reached its original final borrower before returning the model.
        drop(self.canonical_bytes.take());
        Ok(())
    }
}
