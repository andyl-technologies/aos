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
}

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, Error>;
