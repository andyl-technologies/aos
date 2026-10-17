//! Original-authority loans for application-owned RPC receive storage.
//!
//! Reallocation reserves the new capacity while the old bytes and loan remain
//! live. Replaced storage drops before its loan, so long streams retain current
//! capacity instead of accumulating a history of allocations.

use super::*;
use crucible::owned_decode::{DecodeBudget, DecodeScratch};

pub(super) struct WireBytes {
    bytes: Vec<u8>,
    loan: Option<DecodeScratch>,
    budget: DecodeBudget,
}

impl std::ops::Deref for WireBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl WireBytes {
    pub(super) fn new(budget: DecodeBudget) -> Self {
        Self {
            bytes: Vec::new(),
            loan: None,
            budget,
        }
    }

    pub(super) fn copy_from(
        bytes: &[u8],
        budget: DecodeBudget,
    ) -> Result<Self, ControlClientError> {
        let mut storage = Self::new(budget);
        storage.append(bytes)?;
        Ok(storage)
    }

    pub(super) fn append(&mut self, bytes: &[u8]) -> Result<(), ControlClientError> {
        self.budget.check().map_err(admission)?;
        let required = self.bytes.len().checked_add(bytes.len()).ok_or_else(|| {
            admission(crucible::owned_decode::DecodeAdmissionError::new(
                std::fmt::Error,
            ))
        })?;
        if required <= self.bytes.capacity() {
            self.bytes.extend_from_slice(bytes);
            return Ok(());
        }

        let capacity = required.checked_next_power_of_two().ok_or_else(|| {
            admission(crucible::owned_decode::DecodeAdmissionError::new(
                std::fmt::Error,
            ))
        })?;
        let loan = self
            .budget
            .reserve_scratch_bytes(capacity as u64)
            .map_err(admission)?;
        let mut replacement = Vec::new();
        replacement.try_reserve_exact(capacity).map_err(|source| {
            admission(crucible::owned_decode::DecodeAdmissionError::new(source))
        })?;
        replacement.extend_from_slice(&self.bytes);
        replacement.extend_from_slice(bytes);

        let old_bytes = std::mem::replace(&mut self.bytes, replacement);
        drop(old_bytes);
        let old_loan = self.loan.replace(loan);
        drop(old_loan);
        Ok(())
    }

    pub(super) fn take_prefix(&mut self, length: usize) -> Result<Self, ControlClientError> {
        let message = Self::copy_from(&self.bytes[..length], self.budget.clone())?;
        self.bytes.drain(..length + 2);
        Ok(message)
    }

    pub(super) fn take_tail(&mut self) -> Self {
        let replacement = Self::new(self.budget.clone());
        std::mem::replace(self, replacement)
    }
}

fn admission(source: crucible::owned_decode::DecodeAdmissionError) -> ControlClientError {
    client_output_admission(crate::admitted_output::admission(source))
}

pub(super) async fn read_response(
    response: reqwest::Response,
    budget: DecodeBudget,
    maximum: Option<usize>,
) -> Result<WireBytes, ControlClientError> {
    let mut storage = WireBytes::new(budget);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| ControlClientError::HttpRequest {
            message: error.to_string(),
        })?;
        let length = storage.len().checked_add(chunk.len()).ok_or_else(|| {
            admission(crucible::owned_decode::DecodeAdmissionError::new(
                std::fmt::Error,
            ))
        })?;
        if maximum.is_some_and(|maximum| length > maximum) {
            return Err(rpc_decode("RPC response exceeds its wire limit"));
        }
        storage.append(&chunk)?;
    }
    Ok(storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_capacity_and_extracted_bytes_hold_independent_loans()
    -> Result<(), Box<dyn std::error::Error>> {
        let (budget, used) = crate::admitted_output::tests::fixture_budget_with_counter()?;
        let baseline = used.load(std::sync::atomic::Ordering::SeqCst);
        let mut wire = WireBytes::new(budget.clone());
        wire.append(b"hello\n\ntail")?;
        let capacity = wire.bytes.capacity() as u64;
        assert_eq!(
            used.load(std::sync::atomic::Ordering::SeqCst),
            baseline + capacity
        );

        let message = wire.take_prefix(5)?;
        assert_eq!(&*message, b"hello");
        assert_eq!(&*wire, b"tail");
        assert_eq!(
            used.load(std::sync::atomic::Ordering::SeqCst),
            baseline + capacity + message.bytes.capacity() as u64
        );
        drop(message);
        assert_eq!(
            used.load(std::sync::atomic::Ordering::SeqCst),
            baseline + capacity
        );

        for _ in 0..20 {
            wire.bytes.clear();
            wire.append(b"hello\n\n")?;
            drop(wire.take_prefix(5)?);
            assert_eq!(
                used.load(std::sync::atomic::Ordering::SeqCst),
                baseline + capacity
            );
        }
        drop(wire);
        assert_eq!(used.load(std::sync::atomic::Ordering::SeqCst), baseline);
        Ok(())
    }

    #[test]
    fn growth_admits_old_and_new_overlap_then_releases_old_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (budget, used) = crate::admitted_output::tests::fixture_budget_with_counter()?;
        let baseline = used.load(std::sync::atomic::Ordering::SeqCst);
        let mut wire = WireBytes::new(budget.clone());
        wire.append(b"abc")?;
        wire.append(b"defgh")?;
        assert_eq!(&*wire, b"abcdefgh");
        assert_eq!(
            used.load(std::sync::atomic::Ordering::SeqCst),
            baseline + wire.bytes.capacity() as u64
        );
        drop(wire);
        assert_eq!(used.load(std::sync::atomic::Ordering::SeqCst), baseline);
        Ok(())
    }

    #[test]
    fn original_credit_refusal_preserves_existing_wire_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (budget, used) = crate::admitted_output::tests::fixture_budget_with_counter()?;
        let baseline = used.load(std::sync::atomic::Ordering::SeqCst);
        let mut wire = WireBytes::new(budget.clone());
        wire.append(b"abc")?;
        let held = budget.reserve_scratch_bytes(
            1024 * 1024 - used.load(std::sync::atomic::Ordering::SeqCst) - 1,
        )?;
        assert!(matches!(
            wire.append(b"defgh"),
            Err(ControlClientError::Streaming {
                source: StreamingApiError::OutputAdmission { .. }
            })
        ));
        assert_eq!(&*wire, b"abc");
        drop(held);
        drop(wire);
        assert_eq!(used.load(std::sync::atomic::Ordering::SeqCst), baseline);
        Ok(())
    }
}
