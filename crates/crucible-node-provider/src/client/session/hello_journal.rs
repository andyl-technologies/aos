//! Retains one original pre-connection Hello exchange under pre-reserved credit.
//!
//! The complete request is prepared before Child. Complete incoming wire JSON is
//! retained before envelope or handshake authentication, including a refused
//! response. This private journal is data, not lease or native authority; it is
//! preserves complete validated response body bytes and secret Hello material.

use std::io::{self, Write};

use serde_json::Value;

use crate::{ProviderError, envelope::Envelope};

const MAXIMUM_BYTES: usize = 1024 * 1024;

/// Owns bounded original Hello bodies without registration or command authority.
///
/// The host reserves this journal before launching the original peer. Accessors
/// borrow private data only; callers must not publish its admission token. A
/// failed or incomplete frame leaves the original attempt fenced and does not
/// imply that a complete response was received or authenticated.
pub struct OriginalHelloJournal {
    request: Envelope,
    request_value: Value,
    response: Vec<u8>,
    maximum_bytes: usize,
    maximum_nesting: usize,
    attempted: bool,
    received: bool,
}

impl OriginalHelloJournal {
    /// Reserves the complete original request and one full incoming frame.
    ///
    /// # Errors
    /// Refuses zero or over-one-MiB frame credit, invalid nesting, an oversized
    /// original request or unavailable incoming storage. No I/O occurs here.
    pub fn reserve(
        request: &Envelope,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, ProviderError> {
        if maximum_bytes == 0
            || maximum_bytes > MAXIMUM_BYTES
            || maximum_nesting == 0
            || maximum_nesting > 64
        {
            return Err(ProviderError::ResourceExhausted(
                "original Hello journal limits",
            ));
        }
        serde_json::to_writer(
            Counter {
                bytes: 0,
                limit: maximum_bytes,
            },
            request,
        )
        .map_err(crucible_node_contract::ContractError::from)?;
        let request_value =
            serde_json::to_value(request).map_err(crucible_node_contract::ContractError::from)?;
        let mut response = Vec::new();
        response
            .try_reserve_exact(maximum_bytes)
            .map_err(|_| ProviderError::ResourceExhausted("original Hello response reservation"))?;
        Ok(Self {
            request: request.clone(),
            request_value,
            response,
            maximum_bytes,
            maximum_nesting,
            attempted: false,
            received: false,
        })
    }

    /// Borrows the complete private original request, including secret material.
    pub fn request(&self) -> &Envelope {
        &self.request
    }

    /// Borrows a complete received JSON body before interpreting its authority.
    ///
    /// The body preserves the actual validated JSON bytes, including whitespace
    /// and a rejected envelope. The framing length is not included. No body is
    /// exposed for malformed JSON, an incomplete frame or an unattempted exchange.
    pub fn response(&self) -> Option<&[u8]> {
        self.received.then_some(self.response.as_slice())
    }

    /// Reports that the original exchange was reserved for its one attempt.
    pub fn attempted(&self) -> bool {
        self.attempted
    }

    pub(super) fn begin(
        &mut self,
        request: &Envelope,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<(), ProviderError> {
        if self.attempted
            || &self.request != request
            || self.maximum_bytes != maximum_bytes
            || self.maximum_nesting != maximum_nesting
        {
            return Err(ProviderError::Correlation(
                "original Hello journal changed or used",
            ));
        }
        self.attempted = true;
        Ok(())
    }

    pub(super) fn request_value(&self) -> &Value {
        &self.request_value
    }

    pub(super) fn retain_response(&mut self, bytes: &[u8]) -> Result<(), ProviderError> {
        if !self.attempted || self.received || !self.response.is_empty() {
            return Err(ProviderError::Correlation(
                "original Hello response already retained",
            ));
        }
        if bytes.is_empty()
            || bytes.len() > self.maximum_bytes
            || bytes.len() > self.response.capacity()
        {
            return Err(ProviderError::ResourceExhausted(
                "original Hello response credit",
            ));
        }
        // The frame decoder has already bounded and validated these original
        // bytes. All complete retention capacity was reserved before Child;
        // copying here neither canonicalizes the body nor allocates another Vec.
        self.response.extend_from_slice(bytes);
        self.received = true;
        Ok(())
    }
}

struct Counter {
    bytes: usize,
    limit: usize,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= self.limit)
            .ok_or_else(|| io::Error::other("original Hello request credit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "hello_journal/tests.rs"]
mod tests;
