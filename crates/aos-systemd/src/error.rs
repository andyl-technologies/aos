//! Crate-local error type.
//!
//! `aos-systemd` is deliberately apm-agnostic — it does NOT depend on
//! `aos-core`. The apm-side mapping to `AosError` / exit codes happens at the
//! call site (via `anyhow` context). `Error` is `Send + Sync + 'static`, so it
//! threads through `anyhow` cleanly.

/// Errors surfaced by [`crate::SystemdClient`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A caller attempted to construct an invalid typed sandbox unit, or
    /// systemd returned an observation that violates the typed contract.
    #[error("invalid sandbox unit contract: {0}")]
    InvalidSandboxUnit(String),

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
            | Self::InvalidSandboxUnit(_) => false,
        }
    }
}

pub(crate) fn is_no_such_unit(err: &zbus::Error) -> bool {
    matches!(err, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit")
}

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_unit_error_requires_the_exact_systemd_name() {
        for (name, expected) in [
            ("org.freedesktop.systemd1.NoSuchUnit", true),
            ("org.freedesktop.systemd1.NoSuchUnitExtra", false),
            ("org.freedesktop.systemd1.NotNoSuchUnit", false),
            ("org.example.NoSuchUnit", false),
            ("org.freedesktop.systemd1.AccessDenied", false),
        ] {
            let message = zbus::Message::signal("/", "org.aos.Test", "Error")
                .unwrap()
                .build(&())
                .unwrap();
            let error = Error::Zbus(zbus::Error::MethodError(
                name.try_into().unwrap(),
                None,
                message,
            ));
            assert_eq!(error.is_no_such_unit(), expected, "{name}");
        }
    }
}
