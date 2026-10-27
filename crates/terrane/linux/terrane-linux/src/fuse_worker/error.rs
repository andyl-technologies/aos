//! Preserves the failing boundary when a read-only worker faults its connection.

use crate::{fuse_backing, fuse_dispatch, fuse_lifetime, fuse_open, fuse_protocol, fuse_read};
use std::{fmt, io};

/// Reports an invalid startup policy, failed exchange or lost worker invariant.
#[derive(Debug)]
pub enum Error {
    /// A native exchange, allocation or authenticated index request failed.
    Io(io::Error),
    /// The worker cannot preserve the named request or ownership invariant.
    State(&'static str),
    /// The original request or reply has invalid framing.
    Protocol(fuse_protocol::Error),
    /// The kernel and configured policy cannot negotiate initialization.
    Initialization(fuse_protocol::init::Error),
    /// The bounded metadata dispatcher cannot complete a request.
    Metadata(fuse_dispatch::Error),
    /// Kernel lookup, handle or pending-work accounting failed.
    Lifetime(fuse_lifetime::Error),
    /// An original pending open cannot be retained or completed.
    Open(fuse_open::Error),
    /// An original backing reservation cannot be retained or installed.
    Backing(fuse_backing::Error),
    /// A received backing or requested range cannot serve a read.
    Read(fuse_read::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::State(message) => formatter.write_str(message),
            Self::Protocol(error) => error.fmt(formatter),
            Self::Initialization(error) => error.fmt(formatter),
            Self::Metadata(error) => error.fmt(formatter),
            Self::Lifetime(error) => error.fmt(formatter),
            Self::Open(error) => error.fmt(formatter),
            Self::Backing(error) => error.fmt(formatter),
            Self::Read(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::State(_) => None,
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Initialization(error) => Some(error),
            Self::Metadata(error) => Some(error),
            Self::Lifetime(error) => Some(error),
            Self::Open(error) => Some(error),
            Self::Backing(error) => Some(error),
            Self::Read(error) => Some(error),
        }
    }
}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for Error {
            fn from(error: $source) -> Self {
                Self::$variant(error)
            }
        }
    };
}

from_error!(io::Error, Io);
from_error!(&'static str, State);
from_error!(fuse_protocol::Error, Protocol);
from_error!(fuse_protocol::init::Error, Initialization);
from_error!(fuse_dispatch::Error, Metadata);
from_error!(fuse_lifetime::Error, Lifetime);
from_error!(fuse_open::Error, Open);
from_error!(fuse_backing::Error, Backing);
from_error!(fuse_read::Error, Read);
