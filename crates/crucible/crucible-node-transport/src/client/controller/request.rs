//! Constructs the same bounded scoped original for both journal representations.
//!
//! The sizing pass precedes JSON and typed-body construction. This helper owns
//! no stream effect, journal insertion, deadline or Source assignment.

use super::*;

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
    /// The actual caller's body header, backing, serializer effects and physical
    /// stack remain separate. This counts the borrowed envelope, typed result,
    /// JSON result and the new returned tuple without granting allocation rights.
    pub const fn scoped_request_construction_counter_scratch_data() -> usize {
        use std::mem::size_of;

        size_of::<&Self>()
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
