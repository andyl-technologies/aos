//! Reads every retained decoded frame variant as inert historical DATA.
//!
//! ```text
//! [raw_envelope,["Request",["Observe",typed_request]]]
//! [raw_envelope,["Response",raw_shape,null_or_typed_result]]
//! ```
//!
//! The raw map and the independent typed cache remain distinct even when they
//! disagree. No body validation, request assignment or transport enrollment runs.
//! All capacity records append to the enclosing caller's one Ledger.

use crate::handshake::{HelloRequest, HelloResult};
use crate::protocol_snapshot::compact_bytes::{BorrowedCompactBytes, ValidatedCompactBytes};
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string, unsigned,
};
use crate::retained_metadata::{MetadataObserver, records::MetadataRecordKind};
use crate::{
    ProviderError,
    bodies::*,
    connection::{ReceivedBody, ReceivedFrame},
};
use serde::{Serialize, Serializer};
use std::mem::{align_of, size_of};

#[path = "settled17/vocabulary.rs"]
mod vocabulary;

/// Retains raw and typed DATA without a live received-frame custody owner.
pub(crate) struct HistoricalReceivedFrame17 {
    pub(crate) envelope: crate::envelope::Envelope,
    pub(crate) body: ReceivedBody,
}

impl HistoricalType for HistoricalReceivedFrame17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let envelope = ledger.read::<crate::envelope::Envelope>(next(&mut fields)?, build)?;
        let body = read_body(next(&mut fields)?, ledger, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            envelope: envelope.ok_or_else(invalid)?,
            body: body.ok_or_else(invalid)?,
        }))
    }
}

fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next_value()?.ok_or_else(invalid)
}

fn read_body(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<ReceivedBody>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let body = match plain_string(next(&mut fields)?)? {
        "Request" => {
            boxed::<RequestBody>(ledger)?;
            read_request(next(&mut fields)?, ledger, build)?
                .map(|body| ReceivedBody::Request(Box::new(body)))
        }
        "Response" => {
            boxed::<ResponseBody>(ledger)?;
            let shape = ledger.read::<ResponseShape>(next(&mut fields)?, build)?;
            let raw = next(&mut fields)?;
            let result = if raw == b"null" {
                Some(None)
            } else {
                read_result(raw, ledger, build)?.map(Some)
            };
            if build {
                Some(ReceivedBody::Response(Box::new(ResponseBody {
                    shape: shape.ok_or_else(invalid)?,
                    result: result.ok_or_else(invalid)?,
                })))
            } else {
                None
            }
        }
        "Notification" => {
            boxed::<NotificationBody>(ledger)?;
            ledger
                .read::<NotificationBody>(next(&mut fields)?, build)?
                .map(|body| ReceivedBody::Notification(Box::new(body)))
        }
        _ => return Err(invalid()),
    };
    fields.finish()?;
    Ok(body)
}

fn boxed<T>(ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Boxed, 1, align_of::<T>())? != size_of::<T>() {
        return Err(invalid());
    }
    ledger.native17_target_box_data::<T>()
}

/// Borrows one raw bank without expanding bytes into JSON integers.
pub(crate) struct BorrowedByteBank17<'a>(pub(crate) &'a Vec<u8>);

impl Serialize for BorrowedByteBank17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (self.0.capacity(), BorrowedCompactBytes::new(self.0)).serialize(serializer)
    }
}

/// Retains one raw bank at its recorded requested capacity.
pub(crate) struct HistoricalByteBank17(pub(crate) Vec<u8>);

impl HistoricalType for HistoricalByteBank17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_byte_bank(input, ledger, build, false).map(|bytes| bytes.map(Self))
    }
}

/// Borrows the existing17 Commit/Prepare byte-bank field order.
pub(crate) struct BorrowedReversedByteBank17<'a>(pub(crate) &'a Vec<u8>);

impl Serialize for BorrowedReversedByteBank17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (BorrowedCompactBytes::new(self.0), self.0.capacity()).serialize(serializer)
    }
}

/// Retains the compact-first17 bank without changing its native requested row.
pub(crate) struct HistoricalReversedByteBank17(pub(crate) Vec<u8>);

impl HistoricalType for HistoricalReversedByteBank17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_byte_bank(input, ledger, build, true).map(|bytes| bytes.map(Self))
    }
}

fn read_byte_bank(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    compact_first: bool,
) -> Result<Option<Vec<u8>>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let first = next(&mut fields)?;
    let second = next(&mut fields)?;
    fields.finish()?;
    let (capacity, body) = if compact_first {
        (second, first)
    } else {
        (first, second)
    };
    let capacity = usize::try_from(unsigned(capacity)?).map_err(|_| invalid())?;
    read_byte_bank_parts17(body, capacity, ledger, build)
}

/// Reads split compact bytes and capacity through the caller's native row.
///
/// # Errors
/// Refuses a changed capacity, malformed compact encoding or unavailable backing.
pub(crate) fn read_byte_bank_parts17(
    body: &[u8],
    capacity: usize,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<Vec<u8>>, ProviderError> {
    if ledger.row_aligned(
        MetadataRecordKind::Vector,
        size_of::<u8>(),
        align_of::<u8>(),
    )? != capacity
        || capacity > ledger.limits.maximum_owned_backing_bytes
    {
        return Err(invalid());
    }
    let plan = ValidatedCompactBytes::validate(body, ledger.limits.maximum_input_bytes, capacity)?;
    ledger.native17_target_vector_data::<u8>(capacity)?;
    ledger.native17_target_vector_data::<u8>(capacity)?;
    if !build {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| exhausted())?;
    if bytes.capacity() != capacity {
        return Err(exhausted());
    }
    plan.fill_preowned(&mut bytes)?;
    Ok(Some(bytes))
}

/// Borrows an inline digest; it has no independent byte allocation.
pub(crate) struct BorrowedDigest17<'a>(pub(crate) &'a [u8; 32]);

impl Serialize for BorrowedDigest17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        BorrowedCompactBytes::new(self.0).serialize(serializer)
    }
}

/// Stores an inline digest without creating a byte-vector capacity record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalDigest17(pub(crate) [u8; 32]);

impl HistoricalType for HistoricalDigest17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let plan = ValidatedCompactBytes::validate(input, ledger.limits.maximum_input_bytes, 32)?;
        if plan.decoded_length() != 32 {
            return Err(invalid());
        }
        let mut bytes = [0; 32];
        plan.copy_range(0, &mut bytes)?;
        Ok(build.then_some(Self(bytes)))
    }
}

/// Borrows actual pinned ThreadId text using fixed stack storage.
pub(crate) struct BorrowedThread17<'a>(pub(crate) &'a std::thread::ThreadId);

impl Serialize for BorrowedThread17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use std::fmt::Write;
        struct Text {
            bytes: [u8; 64],
            length: usize,
        }
        impl std::fmt::Write for Text {
            fn write_str(&mut self, text: &str) -> std::fmt::Result {
                let end = self
                    .length
                    .checked_add(text.len())
                    .filter(|end| *end <= 64)
                    .ok_or(std::fmt::Error)?;
                self.bytes[self.length..end].copy_from_slice(text.as_bytes());
                self.length = end;
                Ok(())
            }
        }
        let mut text = Text {
            bytes: [0; 64],
            length: 0,
        };
        write!(&mut text, "{:?}", self.0).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(
            std::str::from_utf8(&text.bytes[..text.length]).map_err(serde::ser::Error::custom)?,
        )
    }
}

/// Stores a historical thread label without constructing a ThreadId.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HistoricalThread17 {
    pub(crate) bytes: [u8; 64],
    pub(crate) length: usize,
}

impl HistoricalType for HistoricalThread17 {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let text = plain_string(input)?.as_bytes();
        let number = text
            .strip_prefix(b"ThreadId(")
            .and_then(|text| text.strip_suffix(b")"))
            .ok_or_else(invalid)?;
        if text.len() > 64 || unsigned(number)? == 0 {
            return Err(invalid());
        }
        let mut bytes = [0; 64];
        bytes[..text.len()].copy_from_slice(text);
        Ok(build.then_some(Self {
            bytes,
            length: text.len(),
        }))
    }
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native17 retained historical backing")
}

fn read_request(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<RequestBody>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let kind = plain_string(next(&mut fields)?)?;
    let body = next(&mut fields)?;
    fields.finish()?;
    match kind {
        "Hello" => Ok(ledger
            .read::<HelloRequest>(body, build)?
            .map(RequestBody::Hello)),
        "Discover" => Ok(ledger
            .read::<DiscoverRequest>(body, build)?
            .map(RequestBody::Discover)),
        "Realize" => Ok(ledger
            .read::<RealizeRequest>(body, build)?
            .map(RequestBody::Realize)),
        "Admit" => Ok(ledger
            .read::<AdmitRequest>(body, build)?
            .map(RequestBody::Admit)),
        "Activate" => Ok(ledger
            .read::<ActivateRequest>(body, build)?
            .map(RequestBody::Activate)),
        "Input" => Ok(ledger
            .read::<InputRequest>(body, build)?
            .map(RequestBody::Input)),
        "Observe" => Ok(ledger
            .read::<ObserveRequest>(body, build)?
            .map(RequestBody::Observe)),
        "Begin" => Ok(ledger
            .read::<BeginRequest>(body, build)?
            .map(RequestBody::Begin)),
        "Poll" => Ok(ledger
            .read::<PollRequest>(body, build)?
            .map(RequestBody::Poll)),
        "Cancel" => Ok(ledger
            .read::<CancelRequest>(body, build)?
            .map(RequestBody::Cancel)),
        "QuantumClose" => Ok(ledger
            .read::<QuantumCloseRequest>(body, build)?
            .map(RequestBody::QuantumClose)),
        "WorldActivate" => Ok(ledger
            .read::<WorldActivateRequest>(body, build)?
            .map(RequestBody::WorldActivate)),
        "Abort" => Ok(ledger
            .read::<AbortRequest>(body, build)?
            .map(RequestBody::Abort)),
        "Retire" => Ok(ledger
            .read::<RetireRequest>(body, build)?
            .map(RequestBody::Retire)),
        "BlobBegin" => Ok(ledger
            .read::<BlobBeginRequest>(body, build)?
            .map(RequestBody::BlobBegin)),
        "BlobChunk" => Ok(ledger
            .read::<BlobChunkRequest>(body, build)?
            .map(RequestBody::BlobChunk)),
        "BlobFinish" => Ok(ledger
            .read::<BlobFinishRequest>(body, build)?
            .map(RequestBody::BlobFinish)),
        "Release" => Ok(ledger
            .read::<ReleaseRequest>(body, build)?
            .map(RequestBody::Release)),
        _ => Err(invalid()),
    }
}

fn observe_request(
    value: &RequestBody,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    match value {
        RequestBody::Hello(body) => observer.observe(body),
        RequestBody::Discover(body) => observer.observe(body),
        RequestBody::Realize(body) => observer.observe(body),
        RequestBody::Admit(body) => observer.observe(body),
        RequestBody::Activate(body) => observer.observe(body),
        RequestBody::Input(body) => observer.observe(body),
        RequestBody::Observe(body) => observer.observe(body),
        RequestBody::Begin(body) => observer.observe(body),
        RequestBody::Poll(body) => observer.observe(body),
        RequestBody::Cancel(body) => observer.observe(body),
        RequestBody::QuantumClose(body) => observer.observe(body),
        RequestBody::WorldActivate(body) => observer.observe(body),
        RequestBody::Abort(body) => observer.observe(body),
        RequestBody::Retire(body) => observer.observe(body),
        RequestBody::BlobBegin(body) => observer.observe(body),
        RequestBody::BlobChunk(body) => observer.observe(body),
        RequestBody::BlobFinish(body) => observer.observe(body),
        RequestBody::Release(body) => observer.observe(body),
    }
}

fn read_result(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<MethodResult>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let kind = plain_string(next(&mut fields)?)?;
    let body = next(&mut fields)?;
    fields.finish()?;
    match kind {
        "Hello" => Ok(ledger
            .read::<HelloResult>(body, build)?
            .map(MethodResult::Hello)),
        "Discover" => Ok(ledger
            .read::<DiscoverResult>(body, build)?
            .map(MethodResult::Discover)),
        "Realize" => Ok(ledger
            .read::<RealizeResult>(body, build)?
            .map(MethodResult::Realize)),
        "Admit" => Ok(ledger
            .read::<AdmitResult>(body, build)?
            .map(MethodResult::Admit)),
        "Activate" => Ok(ledger
            .read::<ActivateResult>(body, build)?
            .map(MethodResult::Activate)),
        "Input" => Ok(ledger
            .read::<InputResult>(body, build)?
            .map(MethodResult::Input)),
        "Observe" => Ok(ledger
            .read::<ObserveResult>(body, build)?
            .map(MethodResult::Observe)),
        "Poll" => Ok(ledger
            .read::<PollResult>(body, build)?
            .map(MethodResult::Poll)),
        "Cancel" => Ok(ledger
            .read::<CancelResult>(body, build)?
            .map(MethodResult::Cancel)),
        "QuantumClose" => Ok(ledger
            .read::<QuantumCloseResult>(body, build)?
            .map(MethodResult::QuantumClose)),
        "WorldActivate" => Ok(ledger
            .read::<WorldActivateResult>(body, build)?
            .map(MethodResult::WorldActivate)),
        "Abort" => Ok(ledger
            .read::<AbortResult>(body, build)?
            .map(MethodResult::Abort)),
        "Retire" => Ok(ledger
            .read::<RetireResult>(body, build)?
            .map(MethodResult::Retire)),
        "BlobBegin" => Ok(ledger
            .read::<BlobBeginResult>(body, build)?
            .map(MethodResult::BlobBegin)),
        "BlobChunk" => Ok(ledger
            .read::<BlobChunkResult>(body, build)?
            .map(MethodResult::BlobChunk)),
        "BlobFinish" => Ok(ledger
            .read::<BlobFinishResult>(body, build)?
            .map(MethodResult::BlobFinish)),
        "Release" => Ok(ledger
            .read::<ReleaseResult>(body, build)?
            .map(MethodResult::Release)),
        "BeginAccepted" => Ok(ledger
            .read::<BeginAccepted>(body, build)?
            .map(MethodResult::BeginAccepted)),
        "ExactRun" => Ok(ledger
            .read::<ExactRunResult>(body, build)?
            .map(MethodResult::ExactRun)),
        "BoundarySettle" => Ok(ledger
            .read::<ExactRunResult>(body, build)?
            .map(MethodResult::BoundarySettle)),
        "QuantumBegin" => Ok(ledger
            .read::<QuantumBeginResult>(body, build)?
            .map(MethodResult::QuantumBegin)),
        "Pause" => Ok(ledger
            .read::<PauseResult>(body, build)?
            .map(MethodResult::Pause)),
        "Capture" => Ok(ledger
            .read::<CaptureResult>(body, build)?
            .map(MethodResult::Capture)),
        "PrepareRestore" => Ok(ledger
            .read::<PrepareRestoreResult>(body, build)?
            .map(MethodResult::PrepareRestore)),
        "Shutdown" => Ok(ledger
            .read::<ShutdownResult>(body, build)?
            .map(MethodResult::Shutdown)),
        _ => Err(invalid()),
    }
}

fn observe_result(
    value: &MethodResult,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    match value {
        MethodResult::Hello(body) => observer.observe(body),
        MethodResult::Discover(body) => observer.observe(body),
        MethodResult::Realize(body) => observer.observe(body),
        MethodResult::Admit(body) => observer.observe(body),
        MethodResult::Activate(body) => observer.observe(body),
        MethodResult::Input(body) => observer.observe(body),
        MethodResult::Observe(body) => observer.observe(body),
        MethodResult::Poll(body) => observer.observe(body),
        MethodResult::Cancel(body) => observer.observe(body),
        MethodResult::QuantumClose(body) => observer.observe(body),
        MethodResult::WorldActivate(body) => observer.observe(body),
        MethodResult::Abort(body) => observer.observe(body),
        MethodResult::Retire(body) => observer.observe(body),
        MethodResult::BlobBegin(body) => observer.observe(body),
        MethodResult::BlobChunk(body) => observer.observe(body),
        MethodResult::BlobFinish(body) => observer.observe(body),
        MethodResult::Release(body) => observer.observe(body),
        MethodResult::BeginAccepted(body) => observer.observe(body),
        MethodResult::ExactRun(body) => observer.observe(body),
        MethodResult::BoundarySettle(body) => observer.observe(body),
        MethodResult::QuantumBegin(body) => observer.observe(body),
        MethodResult::Pause(body) => observer.observe(body),
        MethodResult::Capture(body) => observer.observe(body),
        MethodResult::PrepareRestore(body) => observer.observe(body),
        MethodResult::Shutdown(body) => observer.observe(body),
    }
}

impl ReceivedFrame {
    /// Appends complete raw and independent typed-cache backing in source order.
    ///
    /// # Errors
    /// Refuses finite metadata exhaustion or checked requested-storage overflow.
    pub(crate) fn observe_settled17_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.envelope)?;
        match &self.body {
            ReceivedBody::Request(body) => {
                observer.boxed_value(body.as_ref())?;
                observe_request(body, observer)
            }
            ReceivedBody::Response(body) => {
                observer.boxed_value(body.as_ref())?;
                observer.observe(&body.shape)?;
                if let Some(result) = &body.result {
                    observe_result(result, observer)?;
                }
                Ok(())
            }
            ReceivedBody::NativeImport18Bootstrap(_) => {
                return Err(crate::ProviderError::Conflict(
                    "bootstrap18 requires its distinct current owner",
                ));
            }
            ReceivedBody::Notification(body) => {
                observer.boxed_value(body.as_ref())?;
                observer.observe(body.as_ref())
            }
        }
    }
}

#[cfg(test)]
#[path = "settled17/tests.rs"]
mod tests;

#[path = "settled17/retained17.rs"]
mod retained17;
pub(crate) use retained17::{
    ByteBank17ReadAttempt, current_settled17_builder_counter_scratch_data,
    preflight_byte_bank_parts17, read_byte_bank_parts_into17,
};
