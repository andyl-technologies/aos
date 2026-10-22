//! Retains closed Source-side Bootstrap18 response decoding as transport DATA.
//!
//! The actual Source separately retains the strict raw frame and original SDK,
//! admits this component's R/T/S beside its whole holder, and brackets decoding
//! with its original Hello cut and current authority. These fields do not prove
//! raw-frame origin, settle correlation, verify a MAC or complete a Source phase.
//!
//! ```text
//! empty output -> installed failed prefix -> envelope -> request -> body -> result -> receipt
//! ```

use super::*;
use crate::bodies::{OperationState, ResponseShape};
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use crucible_node_format::Extensions;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::mem::size_of;

mod preflight;
mod raw_preflight;
pub use raw_preflight::{
    native_import18_bootstrap_raw_preflight_counter_scratch_data,
    native_import18_bootstrap_raw_preflight_data,
};
mod storage;

type BorrowedFieldMapper = for<'a> fn((&'a String, &'a Value)) -> (&'a str, &'a Value);
type RequestMapDecoder<'a> = serde::de::value::MapDeserializer<
    'a,
    std::iter::Map<serde_json::map::Iter<'a>, BorrowedFieldMapper>,
    serde_json::Error,
>;

fn borrowed_field<'a>((key, value): (&'a String, &'a Value)) -> (&'a str, &'a Value) {
    (key.as_str(), value)
}

pub use storage::{
    PacketNativeImport18BootstrapResponseDecodeRowData,
    native_import18_bootstrap_response_decode_counter_scratch_data,
    native_import18_bootstrap_response_decode_quote_data,
};

/// Identifies the last spent construction step without granting transport credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketNativeImport18BootstrapResponseDecodeStep {
    /// Constructs the response Envelope from the unchanged borrowed strict tree.
    Envelope,
    /// Retains the typed body of the actual original assignment.
    Request,
    /// Retains the completed common body and its independent result map.
    Body,
    /// Retains the bootstrap-only typed result before original correspondence.
    Result,
    /// Retains the sole receipt before validating its grammar.
    Receipt,
}

/// Preserves serde coordinates without retaining an unbounded diagnostic string.
#[derive(Clone, Copy, Debug)]
pub struct PacketNativeImport18BootstrapResponseDecodeFailureData {
    /// Names the actual decoder that failed.
    pub step: PacketNativeImport18BootstrapResponseDecodeStep,
    /// Preserves the original serde classification.
    pub category: serde_json::error::Category,
    /// Preserves the original line coordinate.
    pub line: usize,
    /// Preserves the original column coordinate.
    pub column: usize,
}

/// Retains all initialized response outputs after either decoding outcome.
///
/// An occupied destination refuses reuse. Decoded receipt DATA still requires
/// the Source's independently reconstructed context, assigned-response digest
/// and distinct-domain receipt MAC under its same actual private key.
pub struct PacketNativeImport18BootstrapResponseDecodeData {
    row: PacketNativeImport18BootstrapResponseDecodeRowData,
    step: Option<PacketNativeImport18BootstrapResponseDecodeStep>,
    envelope: Option<Envelope>,
    request: Option<PacketNativeImport18BootstrapRequest>,
    body: Option<ResponseShape>,
    result: Option<PacketNativeImport18BootstrapResult>,
    receipt: Option<PacketNativeImport18BootstrapAckReceipt>,
    failure: Option<PacketNativeImport18BootstrapResponseDecodeFailureData>,
    decoded: bool,
    failed: bool,
}

/// Borrows every saved field without reconstructing a live Source occurrence.
pub struct PacketNativeImport18BootstrapResponseDecodeHistoryData<'a> {
    /// Preserves the independently derived component quote.
    pub requested_storage: [usize; 3],
    /// Preserves the last spent construction step.
    pub step: Option<PacketNativeImport18BootstrapResponseDecodeStep>,
    /// Borrows the actual decoded response even after later refusal.
    pub envelope: Option<&'a Envelope>,
    /// Borrows the actual original's typed body before response correspondence.
    pub request: Option<&'a PacketNativeImport18BootstrapRequest>,
    /// Borrows the common body and its separately allocated result map.
    pub body: Option<&'a ResponseShape>,
    /// Borrows the typed result, including a failed original correspondence.
    pub result: Option<&'a PacketNativeImport18BootstrapResult>,
    /// Borrows the typed receipt without asserting MAC verification.
    pub receipt: Option<&'a PacketNativeImport18BootstrapAckReceipt>,
    /// Preserves the actual serde failure coordinates.
    pub failure: Option<PacketNativeImport18BootstrapResponseDecodeFailureData>,
    /// Reports structural decoding only, never Source/bootstrap completion.
    pub decoded: bool,
    /// Preserves any failed preflight, decoder, correspondence or census.
    pub failed: bool,
}

/// Retains a closed bootstrap-only response before every later semantic check.
///
/// The caller first admits the quoted component beside its actual raw frame,
/// original assignment and whole Source/SDK. This function does
/// not authenticate those owners. Allocation-free preflight rejects arbitrary
/// result/error trees before any DTO construction. Refused/error traffic stays
/// in the caller's raw-frame slot and never becomes a bootstrap-only result.
///
/// # Errors
/// Refuses occupied output, insufficient restriction, changed header or closed
/// grammar, malformed DTO, changed original recipe/row or retained-byte excess.
/// Every installed prefix remains in `output`; an installed owner has no reset.
pub fn native_import18_bootstrap_response_decode_into_data(
    original: &Envelope,
    raw: &Value,
    row: &PacketNativeImport18BootstrapResponseDecodeRowData,
    maximum: usize,
    output: &mut Option<PacketNativeImport18BootstrapResponseDecodeData>,
) -> Result<(), ProviderError> {
    if output.is_some() {
        return Err(refused());
    }
    *output = Some(PacketNativeImport18BootstrapResponseDecodeData {
        row: *row,
        step: None,
        envelope: None,
        request: None,
        body: None,
        result: None,
        receipt: None,
        failure: None,
        decoded: false,
        failed: true,
    });
    let attempt = output.as_mut().ok_or_else(refused)?;
    let result = attempt.construct_data(original, raw, maximum);
    // Check actual surviving capacities on both outcomes. The caller's whole
    // census runs after its SDK/Source loans end, including the raw failed input.
    let retained = attempt.retained_requested_bytes_data()?;
    if retained > row.axes[0] {
        return Err(exhausted());
    }
    result?;
    attempt.decoded = true;
    attempt.failed = false;
    Ok(())
}

impl PacketNativeImport18BootstrapResponseDecodeData {
    fn construct_data(
        &mut self,
        original: &Envelope,
        raw: &Value,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        storage::sum(&self.row.axes).and_then(|peak| {
            if peak > maximum {
                Err(exhausted())
            } else {
                Ok(())
            }
        })?;
        let closed = preflight::inspect_data(original, raw)?;
        self.step = Some(PacketNativeImport18BootstrapResponseDecodeStep::Envelope);
        self.envelope = Some(self.decode::<Envelope>(raw)?);
        let envelope = self.envelope.as_ref().ok_or_else(refused)?;
        envelope.validate()?;
        original.matches_response(envelope)?;

        self.step = Some(PacketNativeImport18BootstrapResponseDecodeStep::Request);
        let fields = original
            .body
            .iter()
            .map(borrowed_field as BorrowedFieldMapper);
        let decoded =
            PacketNativeImport18BootstrapRequest::deserialize(RequestMapDecoder::new(fields));
        self.request = Some(decoded.map_err(|error| self.retain_failure(error))?);
        self.request.as_ref().ok_or_else(refused)?.validate_data()?;

        self.step = Some(PacketNativeImport18BootstrapResponseDecodeStep::Body);
        self.body = Some(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result: closed.result.as_object().ok_or_else(refused)?.clone(),
            extensions: Extensions::new(),
        });

        self.step = Some(PacketNativeImport18BootstrapResponseDecodeStep::Result);
        self.result = Some(self.decode::<PacketNativeImport18BootstrapResult>(closed.result)?);
        self.result
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_request_data(self.request.as_ref().ok_or_else(refused)?)?;

        self.step = Some(PacketNativeImport18BootstrapResponseDecodeStep::Receipt);
        self.receipt =
            Some(self.decode::<PacketNativeImport18BootstrapAckReceipt>(closed.receipt)?);
        self.receipt.as_ref().ok_or_else(refused)?.validate_data()
    }

    fn decode<'de, T: Deserialize<'de>>(&mut self, value: &'de Value) -> Result<T, ProviderError> {
        T::deserialize(value).map_err(|error| self.retain_failure(error))
    }

    fn retain_failure(&mut self, error: serde_json::Error) -> ProviderError {
        self.failure =
            self.step.map(
                |step| PacketNativeImport18BootstrapResponseDecodeFailureData {
                    step,
                    category: error.classify(),
                    line: error.line(),
                    column: error.column(),
                },
            );
        ProviderError::Correlation("closed bootstrap response DTO decode")
    }

    /// Borrows the same retained prefix without serialization or authority checks.
    pub fn borrowed_history_data(
        &self,
    ) -> PacketNativeImport18BootstrapResponseDecodeHistoryData<'_> {
        PacketNativeImport18BootstrapResponseDecodeHistoryData {
            requested_storage: self.row.axes,
            step: self.step,
            envelope: self.envelope.as_ref(),
            request: self.request.as_ref(),
            body: self.body.as_ref(),
            result: self.result.as_ref(),
            receipt: self.receipt.as_ref(),
            failure: self.failure,
            decoded: self.decoded,
            failed: self.failed,
        }
    }

    /// Counts all actual decoded backing, including failed typed outputs.
    ///
    /// The inline owner header is included. The caller separately counts its raw
    /// tree/bytes, original assignment, SDK maps and any received/cached clones.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic or bounded metadata traversal exhaustion.
    pub fn retained_requested_bytes_data(&self) -> Result<usize, ProviderError> {
        storage::retained_data(self)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("closed Source bootstrap response decode")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("closed Source bootstrap response decode")
}

#[cfg(test)]
mod tests;
