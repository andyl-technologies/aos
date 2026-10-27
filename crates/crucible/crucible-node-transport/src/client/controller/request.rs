//! Constructs the same bounded scoped original for both journal representations.
//!
//! The sizing pass precedes JSON and typed-body construction. This helper owns
//! no stream effect, journal insertion, deadline or Source assignment.

use super::*;
use std::mem::size_of;

struct RequestSizingCounter {
    used: usize,
    maximum: usize,
}

impl Write for RequestSizingCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.used.checked_add(bytes.len()) else {
            return Err(io::Error::other("generic body length overflow"));
        };
        if next > self.maximum {
            return Err(io::Error::other("generic frame exceeds original credit"));
        }
        self.used = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) enum RequestExtensions<'a> {
    Owned(Extensions),
    Borrowed(&'a Extensions),
}

impl RequestExtensions<'_> {
    fn as_extensions(&self) -> &Extensions {
        match self {
            Self::Owned(extensions) => extensions,
            Self::Borrowed(extensions) => extensions,
        }
    }

    fn into_owned(self) -> Extensions {
        match self {
            Self::Owned(extensions) => extensions,
            Self::Borrowed(extensions) => extensions.clone(),
        }
    }
}

impl CnpController {
    /// Names the shared request constructor's fixed views and return controls.
    ///
    /// The closed packet body's field graph bounds nested serializer controls.
    /// Arbitrary serializer callbacks, backing and physical stack remain separate.
    /// This counts the borrowed envelope, typed result, JSON result and returned
    /// tuple without granting allocation rights.
    pub const fn scoped_request_construction_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<RequestSizingCounter>()
            + size_of::<serde_json::Serializer<&mut RequestSizingCounter>>()
            + size_of::<serde_json::value::Serializer>()
            + closed_serializer_counter_scratch_data()
            + size_of::<Result<(), serde_json::Error>>()
            + size_of::<CallScope>()
            + size_of::<BorrowedEnvelope<'static, ()>>()
            + size_of::<(RequestBody, Envelope)>()
            + size_of::<Result<(RequestBody, Envelope), ProviderError>>()
            + size_of::<Result<RequestBody, ProviderError>>()
            + size_of::<Result<Value, serde_json::Error>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Value>()
            + size_of::<serde_json::Map<String, Value>>()
            + size_of::<[&Id; 3]>()
            + size_of::<RequestExtensions<'static>>()
            + size_of::<&Extensions>()
            + size_of::<Extensions>()
            + crucible_node_format::literal_json::deserialization_counter_scratch_data()
    }

    pub(super) fn prepare_scoped_request(
        &self,
        request_id: Id,
        scope: CallScope,
        body: impl Serialize,
        extensions: Extensions,
    ) -> Result<(RequestBody, Envelope), ProviderError> {
        self.prepare_scoped_request_with_extensions(
            request_id,
            scope,
            body,
            RequestExtensions::Owned(extensions),
        )
    }

    pub(super) fn prepare_scoped_request_with_extensions(
        &self,
        request_id: Id,
        scope: CallScope,
        body: impl Serialize,
        extensions: RequestExtensions<'_>,
    ) -> Result<(RequestBody, Envelope), ProviderError> {
        let CallScope {
            operation_id,
            method,
            owner_scoped,
            capture_owner,
        } = scope;
        if self.fenced {
            return Err(ProviderError::Correlation(
                "generic original controller is fenced",
            ));
        }
        let session_id = self.session.authority().session_id().clone();
        let incarnation_id = self.session.authority().incarnation_id().clone();
        let node_id = owner_scoped.then(|| self.route.node.clone());
        let execution_owner_id =
            (owner_scoped && capture_owner.is_none()).then(|| self.route.execution_owner.clone());
        let wire = BorrowedEnvelope {
            protocol: "CNP/1",
            message: MessageKind::Request,
            session_id: &session_id,
            incarnation_id: &incarnation_id,
            node_id: &node_id,
            execution_owner_id: &execution_owner_id,
            capture_owner_id: capture_owner.as_ref(),
            request_id: &request_id,
            operation_id: &operation_id,
            sequence: U64::new(u64::MAX),
            method,
            body: &body,
            extensions: extensions.as_extensions(),
        };
        count_serialized(&wire, self.maximum_frame()?)?;

        let body = serde_json::to_value(body).map_err(crucible_node_format::ContractError::from)?;
        let Value::Object(body) = body else {
            return Err(ProviderError::Frame("generic method body is not an object"));
        };
        let original = decode_request(method, &body)?;
        // The packet entry point still lends its caller's original here. Its
        // closed preflight bounded recursion, and complete sizing has now
        // bounded live contents before any independently owned clone exists.
        let extensions = extensions.into_owned();
        let request = Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Request,
            session_id: Nullable(Some(session_id)),
            incarnation_id: Nullable(Some(incarnation_id)),
            node_id: Nullable(node_id),
            execution_owner_id: Nullable(execution_owner_id),
            capture_owner_id: Nullable(capture_owner),
            request_id: Nullable(Some(request_id)),
            operation_id: Nullable(operation_id),
            sequence: U64::new(2),
            method,
            body,
            extensions,
        };
        Ok((original, request))
    }
}

/// Names the actual associated serializer controls without copying their fields.
const fn closed_serializer_counter_scratch_data() -> usize {
    type Text = &'static mut serde_json::Serializer<&'static mut RequestSizingCounter>;
    type Value = serde_json::value::Serializer;

    // Sum every compound variant even though one recursive activation selects
    // only one. The depth comes from the same exhaustive DTO field graph used
    // by preflight, with an independent allowance for literal JSON recursion.
    let per_level = size_of::<<Text as serde::Serializer>::SerializeSeq>()
        + size_of::<<Text as serde::Serializer>::SerializeTuple>()
        + size_of::<<Text as serde::Serializer>::SerializeTupleStruct>()
        + size_of::<<Text as serde::Serializer>::SerializeTupleVariant>()
        + size_of::<<Text as serde::Serializer>::SerializeMap>()
        + size_of::<<Text as serde::Serializer>::SerializeStruct>()
        + size_of::<<Text as serde::Serializer>::SerializeStructVariant>()
        + size_of::<<Value as serde::Serializer>::SerializeSeq>()
        + size_of::<<Value as serde::Serializer>::SerializeTuple>()
        + size_of::<<Value as serde::Serializer>::SerializeTupleStruct>()
        + size_of::<<Value as serde::Serializer>::SerializeTupleVariant>()
        + size_of::<<Value as serde::Serializer>::SerializeMap>()
        + size_of::<<Value as serde::Serializer>::SerializeStruct>()
        + size_of::<<Value as serde::Serializer>::SerializeStructVariant>()
        + size_of::<serde_json::Value>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<&serde_json::Value>()
        + size_of::<&str>();
    crate::bodies::packet_runtime_serialization_depth() * per_level
}

pub(super) fn count_serialized(
    value: &impl Serialize,
    maximum: usize,
) -> Result<(), ProviderError> {
    serde_json::to_writer(&mut RequestSizingCounter { used: 0, maximum }, value)
        .map_err(|_| ProviderError::ResourceExhausted("generic whole-frame precredit"))
}
