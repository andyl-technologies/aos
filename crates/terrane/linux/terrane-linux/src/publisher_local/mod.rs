//! Implements the registered host-local publisher descriptor transport.
//!
//! `wire` mirrors the registered protobuf schema; `validation` rejects the
//! closed vocabulary before effects. `socket` owns authenticated Linux
//! sequenced-packet connections and descriptor custody. Native publication and
//! lifecycle authority remain in `publisher_io`.

#[cfg(feature = "native-test-fixtures")]
mod native_fixture;
#[cfg(feature = "native-test-fixtures")]
pub use native_fixture::{native_fixture_selectors, run_native_fixture, supervise_native_fixture};

#[cfg(feature = "tokio")]
pub mod server;

pub mod client;
pub mod socket;
pub mod validation;
pub mod wire;

use std::{fmt, io};

/// A rejected local publisher exchange or failed kernel operation.
#[derive(Debug)]
pub enum Error {
    /// A packet violates the registered closed protocol.
    Invalid(&'static str),
    /// The connected kernel identity does not match the configured role.
    Denied,
    /// The authenticated publisher returned a registered failure outcome.
    Remote(wire::ResultCode),
    /// A kernel operation failed.
    Io(io::Error),
    /// A protobuf value could not be decoded.
    Protobuf(prost::DecodeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid publisher-local packet: {reason}"),
            Self::Remote(code) => write!(f, "publisher-local outcome: {code:?}"),
            Self::Denied => f.write_str("publisher-local peer identity denied"),
            Self::Io(error) => write!(f, "publisher-local I/O: {error}"),
            Self::Protobuf(error) => write!(f, "publisher-local protobuf: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protobuf(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rustix::io::Errno> for Error {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}
