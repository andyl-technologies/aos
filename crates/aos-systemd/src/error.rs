//! Crate-local error type.
//!
//! `aos-systemd` is deliberately apm-agnostic — it does NOT depend on
//! `aos-core`. The apm-side mapping to `AosError` / exit codes happens at the
//! call site (via `anyhow` context). `Error` is `Send + Sync + 'static`, so it
//! threads through `anyhow` cleanly.

/// Errors surfaced by [`crate::SystemdClient`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The system bus could not be reached (e.g. `/run/dbus/system_bus_socket`
    /// is absent). This is the replacement for the old `which systemctl`
    /// smoke check — a clearer, more actionable signal than "command not
    /// found".
    #[error("cannot reach systemd: no system bus (is /run/dbus/system_bus_socket present?): {0}")]
    SystemdUnavailable(#[source] zbus::Error),

    /// Any other zbus transport / protocol error.
    #[error("systemd D-Bus error: {0}")]
    Zbus(#[from] zbus::Error),

    /// A `org.freedesktop.DBus.Properties` call error (distinct error type in
    /// zbus from the general transport error).
    #[error("systemd D-Bus properties error: {0}")]
    Fdo(#[from] zbus::fdo::Error),

    /// A job was submitted and we began awaiting its `JobRemoved`, but the
    /// signal-listener task dropped the result sender before delivering it —
    /// which only happens if the bus connection died mid-flight.
    #[error("systemd job result channel closed before completion (unit {0})")]
    JobSenderDropped(String),

    /// Pinned lifecycle calls, early completions, or waiter identities
    /// exhausted the bounded job registry capacity.
    #[error("systemd pinned job registry capacity was exhausted")]
    JobCompletionOverflow,

    /// The caller's pinned bus/manager incarnation is no longer current.
    #[error("systemd manager incarnation changed before the pinned operation")]
    ManagerIncarnationChanged,

    /// A configured unit name is an alias rather than its stable canonical ID.
    #[error("systemd unit {requested} resolves to canonical unit {canonical}")]
    UnitAlias {
        /// Names the configured alias rejected by exact native admission.
        requested: String,
        /// Names the canonical unit reported by the resolved object.
        canonical: String,
    },

    /// A canonical unit no longer resolves to its admission-qualified object.
    #[error("systemd unit {unit} changed identity before the pinned operation")]
    UnitIdentityChanged {
        /// Names the exact canonical unit requested by the caller.
        unit: String,
        /// Carries the object identity established during admission.
        expected: String,
        /// Carries the object identity observed immediately before dispatch.
        actual: String,
    },
}

impl Error {
    /// Returns `true` when the error is systemd's `NoSuchUnit` method error.
    ///
    /// This lets callers treat stop/remove operations on already-unloaded
    /// units as idempotent without swallowing unrelated D-Bus failures.
    pub fn is_no_such_unit(&self) -> bool {
        match self {
            Self::Zbus(err) => is_no_such_unit(err),
            Self::SystemdUnavailable(_)
            | Self::Fdo(_)
            | Self::JobSenderDropped(_)
            | Self::JobCompletionOverflow
            | Self::ManagerIncarnationChanged
            | Self::UnitAlias { .. }
            | Self::UnitIdentityChanged { .. } => false,
        }
    }
}

pub(crate) fn is_no_such_unit(err: &zbus::Error) -> bool {
    matches!(err, zbus::Error::MethodError(name, _, _) if name.as_str().contains("NoSuchUnit"))
}

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, Error>;
