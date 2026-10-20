//! Retains each compact byte-bank allocation before any later decoding failure.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;

/// Owns the final byte vector from its first reservation through publication.
pub(crate) struct ByteBank17ReadAttempt<T> {
    pub(crate) buffer: Vec<u8>,
    pub(crate) capacity: Option<usize>,
    pub(crate) failed: bool,
    completed: Option<T>,
}
impl<T> Default for ByteBank17ReadAttempt<T> {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            capacity: None,
            failed: false,
            completed: None,
        }
    }
}

fn parts17(input: &[u8], reversed: bool) -> Result<(&[u8], usize), ProviderError> {
    let mut f = Fields::array(input)?;
    let first = next(&mut f)?;
    let second = next(&mut f)?;
    f.finish()?;
    let (capacity, bytes) = if reversed {
        (second, first)
    } else {
        (first, second)
    };
    Ok((
        bytes,
        usize::try_from(unsigned(capacity)?).map_err(|_| invalid())?,
    ))
}

fn preflight_parts17(
    bytes: &[u8],
    capacity: usize,
    l: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    if l.row_aligned(
        MetadataRecordKind::Vector,
        size_of::<u8>(),
        align_of::<u8>(),
    )? != capacity
        || capacity > l.limits.maximum_owned_backing_bytes
    {
        return Err(invalid());
    }
    let plan = ValidatedCompactBytes::validate(bytes, l.limits.maximum_input_bytes, capacity)?;
    if plan.decoded_length() > capacity {
        return Err(invalid());
    }
    l.native17_target_vector_data::<u8>(capacity)
}
fn build_parts17<T>(
    bytes: &[u8],
    capacity: usize,
    l: &mut Ledger<'_, '_, '_>,
    a: &mut ByteBank17ReadAttempt<T>,
) -> Result<(), ProviderError> {
    if a.failed || a.capacity.is_some() || a.completed.is_some() {
        return Err(invalid());
    }
    let result = (|| {
        if l.row_aligned(
            MetadataRecordKind::Vector,
            size_of::<u8>(),
            align_of::<u8>(),
        )? != capacity
            || capacity > l.limits.maximum_owned_backing_bytes
        {
            return Err(invalid());
        }
        a.capacity = Some(capacity);
        let plan = ValidatedCompactBytes::validate(bytes, l.limits.maximum_input_bytes, capacity)?;
        if plan.decoded_length() > capacity {
            return Err(invalid());
        }
        l.native17_target_vector_data::<u8>(capacity)?;
        a.buffer
            .try_reserve_exact(capacity)
            .map_err(|_| invalid())?;
        if a.buffer.capacity() != capacity {
            return Err(invalid());
        }
        plan.fill_preowned(&mut a.buffer)?;
        Ok(())
    })();
    if result.is_err() {
        a.failed = true;
    }
    result
}

macro_rules! bank_build17 {
    ($ty:ident,$reversed:literal) => {
        impl Native17Build for $ty {
            type Attempt = ByteBank17ReadAttempt<Self>;
            fn preflight_data(
                input: &[u8],
                l: &mut Ledger<'_, '_, '_>,
            ) -> Result<(), ProviderError> {
                let (bytes, capacity) = parts17(input, $reversed)?;
                preflight_parts17(bytes, capacity, l)
            }
            fn read_into_data(
                input: &[u8],
                l: &mut Ledger<'_, '_, '_>,
                a: &mut Self::Attempt,
            ) -> Result<(), ProviderError> {
                let result = (|| {
                    let (bytes, capacity) = parts17(input, $reversed)?;
                    build_parts17(bytes, capacity, l, a)?;
                    a.completed = Some(Self(std::mem::take(&mut a.buffer)));
                    Ok(())
                })();
                if result.is_err() {
                    a.failed = true;
                }
                result
            }
            fn output_data(a: &Self::Attempt) -> Option<&Self> {
                a.completed.as_ref()
            }
            fn take_output_data(a: &mut Self::Attempt) -> Option<Self> {
                a.completed.take()
            }
            fn observe_attempt_data(
                a: &Self::Attempt,
                o: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                o.vector::<u8>(a.buffer.capacity())?;
                if let Some(v) = &a.completed {
                    Self::observe_output_data(v, o)?;
                }
                Ok(())
            }
            fn observe_output_data(
                v: &Self,
                o: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                o.vector::<u8>(v.0.capacity())
            }
        }
    };
}
bank_build17!(HistoricalByteBank17, false);
bank_build17!(HistoricalReversedByteBank17, true);

/// Retains the split compact-bank owner used by native stage and receipt views.
pub(crate) fn read_byte_bank_parts_into17(
    bytes: &[u8],
    capacity: usize,
    l: &mut Ledger<'_, '_, '_>,
    a: &mut ByteBank17ReadAttempt<HistoricalByteBank17>,
) -> Result<(), ProviderError> {
    build_parts17(bytes, capacity, l, a)?;
    a.completed = Some(HistoricalByteBank17(std::mem::take(&mut a.buffer)));
    Ok(())
}
pub(crate) fn preflight_byte_bank_parts17(
    bytes: &[u8],
    capacity: usize,
    l: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    preflight_parts17(bytes, capacity, l)
}

pub(crate) struct Inline17ReadAttempt<T> {
    pub(crate) value: Option<T>,
    pub(crate) failed: bool,
}
impl<T> Default for Inline17ReadAttempt<T> {
    fn default() -> Self {
        Self {
            value: None,
            failed: false,
        }
    }
}
macro_rules! fixed_build17 {
    ($ty:ty,$check:expr) => {
        impl Native17Build for $ty {
            type Attempt = Inline17ReadAttempt<Self>;
            fn preflight_data(
                input: &[u8],
                l: &mut Ledger<'_, '_, '_>,
            ) -> Result<(), ProviderError> {
                let _ = <Self as HistoricalType>::read(input, l, false)?;
                Ok(())
            }
            fn read_into_data(
                input: &[u8],
                l: &mut Ledger<'_, '_, '_>,
                a: &mut Self::Attempt,
            ) -> Result<(), ProviderError> {
                if a.failed || a.value.is_some() {
                    return Err(invalid());
                }
                match <Self as HistoricalType>::read(input, l, true) {
                    Ok(Some(v)) => {
                        ($check)(&v);
                        a.value = Some(v);
                        Ok(())
                    }
                    Ok(None) => {
                        a.failed = true;
                        Err(invalid())
                    }
                    Err(e) => {
                        a.failed = true;
                        Err(e)
                    }
                }
            }
            fn output_data(a: &Self::Attempt) -> Option<&Self> {
                a.value.as_ref()
            }
            fn take_output_data(a: &mut Self::Attempt) -> Option<Self> {
                a.value.take()
            }
            fn observe_attempt_data(
                _: &Self::Attempt,
                _: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                Ok(())
            }
            fn observe_output_data(
                _: &Self,
                _: &mut MetadataObserver<'_>,
            ) -> Result<(), ProviderError> {
                Ok(())
            }
        }
    };
}
fixed_build17!(HistoricalDigest17, |v: &HistoricalDigest17| {
    let HistoricalDigest17(bytes) = v;
    fn copy<T: Copy>(_: &T) {}
    copy(bytes);
});
fixed_build17!(HistoricalThread17, |v: &HistoricalThread17| {
    let HistoricalThread17 { bytes, length } = v;
    fn copy<T: Copy>(_: &T) {}
    copy(bytes);
    copy(length);
});

#[path = "retained17/request.rs"]
mod request;
#[path = "retained17/result.rs"]
mod result;
use request::{HistoricalRequestCache17, RequestCache17ReadAttempt};
use result::{HistoricalResultCache17, ResultCache17ReadAttempt};

struct HistoricalReceivedBody17(ReceivedBody);
impl HistoricalType for HistoricalReceivedBody17 {
    fn read(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_body(input, l, build).map(|v| v.map(Self))
    }
}

/// Retains raw response shape and its independently decoded result cache.
pub(crate) struct ReceivedBody17ReadAttempt {
    request: RequestCache17ReadAttempt,
    shape: <ResponseShape as Native17Build>::Attempt,
    result: ResultCache17ReadAttempt,
    notification: <NotificationBody as Native17Build>::Attempt,
    pub(crate) kind: Option<&'static str>,
    pub(crate) phase: usize,
    pub(crate) failed: bool,
    completed: Option<HistoricalReceivedBody17>,
}
impl Default for ReceivedBody17ReadAttempt {
    fn default() -> Self {
        Self {
            request: Default::default(),
            shape: Default::default(),
            result: Default::default(),
            notification: Default::default(),
            kind: None,
            phase: 0,
            failed: false,
            completed: None,
        }
    }
}
fn body_fields17(input: &[u8]) -> Result<(&str, &[u8], Option<&[u8]>), ProviderError> {
    let mut f = Fields::array(input)?;
    let kind = plain_string(next(&mut f)?)?;
    let first = next(&mut f)?;
    let second = if kind == "Response" {
        Some(next(&mut f)?)
    } else {
        None
    };
    f.finish()?;
    if !matches!(kind, "Request" | "Response" | "Notification") {
        return Err(invalid());
    }
    Ok((kind, first, second))
}
impl Native17Build for HistoricalReceivedBody17 {
    type Attempt = ReceivedBody17ReadAttempt;
    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let (kind, first, second) = body_fields17(input)?;
        match kind {
            "Request" => {
                boxed::<RequestBody>(l)?;
                HistoricalRequestCache17::preflight_data(first, l)
            }
            "Response" => {
                boxed::<ResponseBody>(l)?;
                ResponseShape::preflight_data(first, l)?;
                let raw = second.ok_or_else(invalid)?;
                if raw != b"null" {
                    HistoricalResultCache17::preflight_data(raw, l)?;
                }
                Ok(())
            }
            "Notification" => {
                boxed::<NotificationBody>(l)?;
                NotificationBody::preflight_data(first, l)
            }
            _ => Err(invalid()),
        }
    }
    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if a.failed || a.kind.is_some() || a.completed.is_some() {
            return Err(invalid());
        }
        let result = (|| {
            let (kind, first, second) = body_fields17(input)?;
            let value = match kind {
                "Request" => {
                    a.kind = Some("Request");
                    boxed::<RequestBody>(l)?;
                    HistoricalRequestCache17::read_into_data(first, l, &mut a.request)?;
                    a.phase = 1;
                    ReceivedBody::Request(Box::new(
                        HistoricalRequestCache17::take_output_data(&mut a.request)
                            .ok_or_else(invalid)?
                            .0,
                    ))
                }
                "Response" => {
                    a.kind = Some("Response");
                    boxed::<ResponseBody>(l)?;
                    ResponseShape::read_into_data(first, l, &mut a.shape)?;
                    a.phase = 1;
                    let raw = second.ok_or_else(invalid)?;
                    if raw != b"null" {
                        HistoricalResultCache17::read_into_data(raw, l, &mut a.result)?;
                        a.phase = 2;
                    }
                    if ResponseShape::output_data(&a.shape).is_none()
                        || (raw != b"null"
                            && HistoricalResultCache17::output_data(&a.result).is_none())
                    {
                        return Err(invalid());
                    }
                    let result = if raw == b"null" {
                        None
                    } else {
                        Some(
                            HistoricalResultCache17::take_output_data(&mut a.result)
                                .ok_or_else(invalid)?
                                .0,
                        )
                    };
                    ReceivedBody::Response(Box::new(ResponseBody {
                        shape: ResponseShape::take_output_data(&mut a.shape).ok_or_else(invalid)?,
                        result,
                    }))
                }
                "Notification" => {
                    a.kind = Some("Notification");
                    boxed::<NotificationBody>(l)?;
                    NotificationBody::read_into_data(first, l, &mut a.notification)?;
                    a.phase = 1;
                    ReceivedBody::Notification(Box::new(
                        NotificationBody::take_output_data(&mut a.notification)
                            .ok_or_else(invalid)?,
                    ))
                }
                _ => return Err(invalid()),
            };
            a.completed = Some(Self(value));
            Ok(())
        })();
        if result.is_err() {
            a.failed = true;
        }
        result
    }
    fn output_data(a: &Self::Attempt) -> Option<&Self> {
        a.completed.as_ref()
    }
    fn take_output_data(a: &mut Self::Attempt) -> Option<Self> {
        a.completed.take()
    }
    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        HistoricalRequestCache17::observe_attempt_data(&a.request, o)?;
        ResponseShape::observe_attempt_data(&a.shape, o)?;
        HistoricalResultCache17::observe_attempt_data(&a.result, o)?;
        NotificationBody::observe_attempt_data(&a.notification, o)?;
        if let Some(v) = &a.completed {
            Self::observe_output_data(v, o)?;
        }
        Ok(())
    }
    fn observe_output_data(v: &Self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match &v.0 {
            ReceivedBody::Request(v) => {
                o.boxed_value(v.as_ref())?;
                observe_request(v, o)
            }
            ReceivedBody::Response(v) => {
                o.boxed_value(v.as_ref())?;
                ResponseShape::observe_output_data(&v.shape, o)?;
                if let Some(v) = &v.result {
                    observe_result(v, o)?;
                }
                Ok(())
            }
            ReceivedBody::NativeImport18Bootstrap(_) => {
                return Err(crate::ProviderError::Conflict(
                    "bootstrap18 requires its distinct current owner",
                ));
            }
            ReceivedBody::Notification(v) => {
                o.boxed_value(v.as_ref())?;
                NotificationBody::observe_output_data(v, o)
            }
        }
    }
}

/// Retains each completed raw frame field and the current typed cache attempt.
pub(crate) struct ReceivedFrame17ReadAttempt {
    pub(crate) envelope: <crate::envelope::Envelope as Native17Build>::Attempt,
    pub(crate) body: ReceivedBody17ReadAttempt,
    pub(crate) phase: usize,
    pub(crate) failed: bool,
    completed: Option<HistoricalReceivedFrame17>,
}
impl Default for ReceivedFrame17ReadAttempt {
    fn default() -> Self {
        Self {
            envelope: Default::default(),
            body: Default::default(),
            phase: 0,
            failed: false,
            completed: None,
        }
    }
}
impl Native17Build for HistoricalReceivedFrame17 {
    type Attempt = ReceivedFrame17ReadAttempt;
    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut f = Fields::array(input)?;
        let envelope = next(&mut f)?;
        let body = next(&mut f)?;
        f.finish()?;
        crate::envelope::Envelope::preflight_data(envelope, l)?;
        HistoricalReceivedBody17::preflight_data(body, l)
    }
    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if a.failed || a.phase != 0 || a.completed.is_some() {
            return Err(invalid());
        }
        let result = (|| {
            let mut f = Fields::array(input)?;
            let envelope = next(&mut f)?;
            let body = next(&mut f)?;
            f.finish()?;
            crate::envelope::Envelope::read_into_data(envelope, l, &mut a.envelope)?;
            a.phase = 1;
            HistoricalReceivedBody17::read_into_data(body, l, &mut a.body)?;
            a.phase = 2;
            if crate::envelope::Envelope::output_data(&a.envelope).is_none()
                || HistoricalReceivedBody17::output_data(&a.body).is_none()
            {
                return Err(invalid());
            }
            a.completed = Some(Self {
                envelope: crate::envelope::Envelope::take_output_data(&mut a.envelope)
                    .ok_or_else(invalid)?,
                body: HistoricalReceivedBody17::take_output_data(&mut a.body)
                    .ok_or_else(invalid)?
                    .0,
            });
            Ok(())
        })();
        if result.is_err() {
            a.failed = true;
        }
        result
    }
    fn output_data(a: &Self::Attempt) -> Option<&Self> {
        a.completed.as_ref()
    }
    fn take_output_data(a: &mut Self::Attempt) -> Option<Self> {
        a.completed.take()
    }
    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        crate::envelope::Envelope::observe_attempt_data(&a.envelope, o)?;
        HistoricalReceivedBody17::observe_attempt_data(&a.body, o)?;
        if let Some(v) = &a.completed {
            Self::observe_output_data(v, o)?;
        }
        Ok(())
    }
    fn observe_output_data(v: &Self, o: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        crate::envelope::Envelope::observe_output_data(&v.envelope, o)?;
        match &v.body {
            ReceivedBody::Request(v) => {
                o.boxed_value(v.as_ref())?;
                observe_request(v, o)
            }
            ReceivedBody::Response(v) => {
                o.boxed_value(v.as_ref())?;
                ResponseShape::observe_output_data(&v.shape, o)?;
                if let Some(v) = &v.result {
                    observe_result(v, o)?;
                }
                Ok(())
            }
            ReceivedBody::NativeImport18Bootstrap(_) => {
                return Err(crate::ProviderError::Conflict(
                    "bootstrap18 requires its distinct current owner",
                ));
            }
            ReceivedBody::Notification(v) => {
                o.boxed_value(v.as_ref())?;
                NotificationBody::observe_output_data(v, o)
            }
        }
    }
}

/// Names the actual complete cache, raw-bank and fixed primitive build headers.
pub(crate) fn current_settled17_builder_counter_scratch_data() -> usize {
    size_of::<ReceivedFrame17ReadAttempt>()
        + size_of::<ReceivedBody17ReadAttempt>()
        + size_of::<ByteBank17ReadAttempt<HistoricalByteBank17>>()
        + size_of::<ByteBank17ReadAttempt<HistoricalReversedByteBank17>>()
        + size_of::<Inline17ReadAttempt<HistoricalDigest17>>()
        + size_of::<Inline17ReadAttempt<HistoricalThread17>>()
}

#[path = "retained17/native_import18_response.rs"]
mod native_import18_response;

impl ReceivedFrame {
    /// Observes the actual raw envelope and every retained typed terminal cache.
    ///
    /// This shared DATA visitor also counts refused Request/Notification frames.
    /// It neither decodes nor certifies a successful upload or connection phase.
    ///
    /// # Errors
    /// Refuses exhausted metadata bookkeeping or checked layout arithmetic.
    pub(crate) fn observe_native_import17_upload_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        crate::envelope::Envelope::observe_output_data(&self.envelope, observer)?;
        match &self.body {
            ReceivedBody::NativeImport18Bootstrap(_) => {
                return Err(crate::ProviderError::Conflict(
                    "bootstrap18 requires its distinct current owner",
                ));
            }
            ReceivedBody::Request(body) => {
                observer.boxed_value(body.as_ref())?;
                observe_request(body, observer)
            }
            ReceivedBody::Response(body) => {
                observer.boxed_value(body.as_ref())?;
                ResponseShape::observe_output_data(&body.shape, observer)?;
                if let Some(result) = &body.result {
                    observe_result(result, observer)?;
                }
                Ok(())
            }
            ReceivedBody::Notification(body) => {
                observer.boxed_value(body.as_ref())?;
                NotificationBody::observe_output_data(body, observer)
            }
        }
    }

    /// Names the direct borrowed controls of the shared retained-cache observer.
    pub(crate) fn native_import17_upload_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<(&crate::envelope::Envelope, &ReceivedBody)>()
            + size_of::<&RequestBody>()
            + size_of::<&ResponseBody>()
            + size_of::<&NotificationBody>()
            + size_of::<Option<&MethodResult>>()
            + size_of::<&MethodResult>()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

#[cfg(test)]
mod native_import17_upload_tests {
    use super::*;
    use crucible_node_contract::{Id, U64};
    use serde_json::Value;

    #[test]
    fn unexpected_notification_keeps_independent_raw_and_typed_backing() {
        let id = || crate::envelope::Nullable(Some(Id::new("history/scope").unwrap()));
        let mut raw = String::with_capacity(211);
        raw.push_str("raw envelope history");
        let raw_capacity = raw.capacity();
        let mut typed = String::with_capacity(137);
        typed.push_str("independent typed notification cache");
        let typed_capacity = typed.capacity();
        let mut body = serde_json::Map::new();
        body.insert("raw".into(), Value::String(raw));
        let mut details = serde_json::Map::new();
        details.insert("cache".into(), Value::String(typed));
        let frame = ReceivedFrame {
            envelope: crate::envelope::Envelope {
                protocol: "CNP/1".into(),
                message: crate::envelope::MessageKind::Event,
                session_id: id(),
                incarnation_id: id(),
                node_id: crate::envelope::Nullable(None),
                execution_owner_id: crate::envelope::Nullable(None),
                capture_owner_id: crate::envelope::Nullable(None),
                operation_id: crate::envelope::Nullable(None),
                request_id: crate::envelope::Nullable(None),
                sequence: U64::new(9),
                method: crate::envelope::Method::Poll,
                body,
                extensions: Default::default(),
            },
            body: ReceivedBody::Notification(Box::new(NotificationBody {
                operation_state: OperationState::Completed,
                last_observation_sequence: U64::new(8),
                details,
                extensions: Default::default(),
            })),
        };
        let mut observer = MetadataObserver::new();

        frame
            .observe_native_import17_upload_data(&mut observer)
            .unwrap();
        let facts = observer.finish();

        assert!(facts.string_capacity_bytes >= raw_capacity + typed_capacity);
        assert_eq!(facts.boxed_value_bytes, size_of::<NotificationBody>());
        assert!(matches!(frame.body, ReceivedBody::Notification(_)));
    }
}
