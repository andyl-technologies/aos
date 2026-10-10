//! Connect error codes and public failure messages for Hub service methods.
/// A registry-hub method failure, tagged with a Connect error code.
///
/// Mirrors the subset of `connectrpc::ErrorCode` the hub uses. The transport
/// renders it as the Connect-JSON error envelope plus an HTTP status. The
/// [`RpcError::Internal`] variant carries no public detail — the underlying
/// error is logged at construction (see [`RpcError::internal`]) and the wire
/// message is the generic `"internal error"`, so a database error never leaks
/// its internals to a caller.
#[derive(Debug)]
pub enum RpcError {
    /// An unexpected server-side failure; detail already logged, not exposed.
    Internal,
    /// The request was malformed (bad argument, bad page token, …).
    InvalidArgument(String),
    /// The addressed resource does not exist (or is hidden from the caller).
    NotFound(String),
    /// The caller is authenticated but lacks the required permission.
    PermissionDenied(String),
    /// The caller presented no, or an invalid, credential.
    Unauthenticated(String),
    /// The resource already exists (unique-constraint conflict).
    AlreadyExists(String),
    /// A precondition on system state was not met.
    FailedPrecondition(String),
    /// The caller exceeded a rate limit or quota.
    ResourceExhausted(String),
    /// Every eligible backend was temporarily unavailable.
    Unavailable(String),
    /// The requested protocol feature is not implemented by this server.
    Unimplemented(String),
}

impl RpcError {
    /// Build an [`RpcError::Internal`], logging `err` for operators.
    ///
    /// The returned error exposes only `"internal error"` on the wire; the full
    /// chain is written to the `tracing` log so the detail is recoverable
    /// server-side without leaking to the caller.
    #[must_use]
    pub fn internal<E>(err: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        let err = err.into();
        tracing::error!(error = %format!("{err:#}"), "rpc failed");
        RpcError::Internal
    }

    /// Build a [`RpcError::NotFound`] reading `"{what} not found"`.
    #[must_use]
    pub fn not_found(what: &str) -> Self {
        RpcError::NotFound(format!("{what} not found"))
    }

    /// Build a [`RpcError::InvalidArgument`] from any message.
    #[must_use]
    pub fn invalid(msg: impl Into<String>) -> Self {
        RpcError::InvalidArgument(msg.into())
    }

    /// The Connect error code string (e.g. `"not_found"`) for the wire envelope.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            RpcError::Internal => "internal",
            RpcError::InvalidArgument(_) => "invalid_argument",
            RpcError::NotFound(_) => "not_found",
            RpcError::PermissionDenied(_) => "permission_denied",
            RpcError::Unauthenticated(_) => "unauthenticated",
            RpcError::AlreadyExists(_) => "already_exists",
            RpcError::FailedPrecondition(_) => "failed_precondition",
            RpcError::ResourceExhausted(_) => "resource_exhausted",
            RpcError::Unavailable(_) => "unavailable",
            RpcError::Unimplemented(_) => "unimplemented",
        }
    }

    /// The human-readable message for the wire envelope.
    ///
    /// [`RpcError::Internal`] returns the generic `"internal error"`; all other
    /// variants return their carried message.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            RpcError::Internal => "internal error",
            RpcError::InvalidArgument(m)
            | RpcError::NotFound(m)
            | RpcError::PermissionDenied(m)
            | RpcError::Unauthenticated(m)
            | RpcError::AlreadyExists(m)
            | RpcError::FailedPrecondition(m)
            | RpcError::ResourceExhausted(m)
            | RpcError::Unavailable(m)
            | RpcError::Unimplemented(m) => m,
        }
    }

    /// The HTTP status the Connect protocol maps this code to.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            RpcError::Internal => 500,
            RpcError::InvalidArgument(_) => 400,
            RpcError::NotFound(_) => 404,
            RpcError::PermissionDenied(_) => 403,
            RpcError::Unauthenticated(_) => 401,
            RpcError::AlreadyExists(_) => 409,
            RpcError::FailedPrecondition(_) => 400,
            RpcError::ResourceExhausted(_) => 429,
            RpcError::Unavailable(_) => 503,
            RpcError::Unimplemented(_) => 501,
        }
    }

    /// Maps a topology read failure without turning temporary exhaustion into 500.
    pub(in crate::service) fn surface_read(error: anyhow::Error) -> Self {
        if crate::placement_read::classify_read_error(&error)
            == crate::placement_read::ReadFailureClass::Retryable
        {
            tracing::warn!(error = %format!("{error:#}"), "all eligible surface backends unavailable");
            RpcError::Unavailable(
                "all eligible storage backends are temporarily unavailable".into(),
            )
        } else {
            RpcError::internal(error)
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for RpcError {}
