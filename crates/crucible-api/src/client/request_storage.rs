//! Counted borrowed RPC request rendering and retained HTTP body credit.
//!
//! The two formatting passes borrow the same immutable fields. The output
//! capacity is reserved before allocation, and the HTTP byte owner retains
//! that loan through every framework clone of the request body.

use super::*;
use crucible::owned_decode::{DecodeBudget, DecodeScratch};
use std::fmt::{self, Display, Write};

pub(super) struct Hex<'a>(pub(super) &'a [u8]);

impl Display for Hex<'_> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(output, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub(super) fn line(output: &mut dyn Write, key: &str, value: impl Display) -> fmt::Result {
    writeln!(output, "{key}={value}")
}

pub(super) fn session(output: &mut dyn Write, session: SessionRef) -> fmt::Result {
    line(output, "session-id", session.id.value)?;
    line(output, "epoch", session.epoch)?;
    line(output, "seed", Hex(&session.seed.bytes()))
}

struct Count(usize);

impl Write for Count {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0 = self.0.checked_add(text.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}

struct Output {
    bytes: Vec<u8>,
    capacity: usize,
}

impl Write for Output {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let length = self.bytes.len().checked_add(text.len()).ok_or(fmt::Error)?;
        if length > self.capacity {
            return Err(fmt::Error);
        }
        self.bytes.extend_from_slice(text.as_bytes());
        Ok(())
    }
}

struct BodyOwner {
    output: Output,
    _buffer_loan: DecodeScratch,
    _owner_loan: DecodeScratch,
    _budget: DecodeBudget,
}

impl AsRef<[u8]> for BodyOwner {
    fn as_ref(&self) -> &[u8] {
        &self.output.bytes
    }
}

pub(super) fn from_admitted(
    body: crate::AdmittedOutput<Vec<u8>>,
) -> Result<Bytes, ControlClientError> {
    body.into_wire_bytes().map_err(admission)
}

pub(super) fn encode(
    render: impl Fn(&mut dyn Write) -> fmt::Result,
) -> Result<Bytes, ControlClientError> {
    let budget = authority()?;

    let mut count = Count(0);
    render(&mut count)
        .map_err(|source| admission(crucible::owned_decode::DecodeAdmissionError::new(source)))?;
    let buffer_loan = budget
        .reserve_scratch_bytes(count.0 as u64)
        .map_err(admission)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(count.0)
        .map_err(|source| admission(crucible::owned_decode::DecodeAdmissionError::new(source)))?;
    let mut output = Output {
        bytes,
        capacity: count.0,
    };
    render(&mut output)
        .map_err(|source| admission(crucible::owned_decode::DecodeAdmissionError::new(source)))?;
    if output.bytes.len() != count.0 {
        return Err(admission(
            crucible::owned_decode::DecodeAdmissionError::new(fmt::Error),
        ));
    }

    let owner_loan =
        crate::admitted_output::wire::reserve_owner::<BodyOwner>(&budget).map_err(admission)?;
    Ok(Bytes::from_owner(BodyOwner {
        output,
        _buffer_loan: buffer_loan,
        _owner_loan: owner_loan,
        _budget: budget,
    }))
}

pub(super) fn authority() -> Result<DecodeBudget, ControlClientError> {
    let budget = crucible::owned_decode::current_budget().ok_or_else(|| {
        client_output_admission(crate::admitted_output::admission(
            crucible::owned_decode::DecodeAdmissionError::new(MissingRequestAuthority),
        ))
    })?;
    budget.check().map_err(admission)?;

    Ok(budget)
}

fn admission(source: crucible::owned_decode::DecodeAdmissionError) -> ControlClientError {
    client_output_admission(crate::admitted_output::admission(source))
}

#[derive(Debug, thiserror::Error)]
#[error("RPC request rendering requires its retained original resource authority")]
struct MissingRequestAuthority;

#[cfg(test)]
mod tests;
