//! Preserves typed failures of GPL-side RAM ownership and observation.

// SPDX-License-Identifier: GPL-2.0-or-later

use std::collections::TryReserveError;
use std::io;
use std::num::ParseIntError;
use std::str::Utf8Error;
use std::sync::Arc;

/// A rejected operational RAM action; none of these failures model guest faults.
#[derive(Clone, Debug, thiserror::Error)]
pub enum RamError {
    /// Canonical identity, proof, geometry or admitted metadata failed.
    #[error(transparent)]
    Core(#[from] crucible_ram::RamError),
    /// A private native operation returned its original status or errno.
    #[error("native RAM operation {operation} failed ({status})")]
    Native {
        operation: &'static str,
        status: i32,
    },
    /// Fallible Rust allocation failed before publication or mutation.
    #[error("RAM allocation failed: {0}")]
    Allocation(#[source] Arc<TryReserveError>),
    /// Operational transport, backing, kernel or source I/O failed.
    #[error("RAM I/O failed: {0}")]
    Io(#[source] Arc<io::Error>),
    /// The public control codec, authority or transport rejected an exchange.
    #[error("RAM control failed: {0}")]
    Control(#[source] Arc<crucible_protocol::ram_control::RamControlError>),
    /// The bounded immutable page-source protocol failed validation.
    #[error("RAM page protocol failed: {0}")]
    PageProtocol(#[source] Arc<crucible_protocol::ram_page::RamPageProtocolError>),
    /// The authenticated child handoff plan failed decoding or validation.
    #[error("RAM fork plan failed: {0}")]
    ForkPlan(#[source] Arc<crucible_protocol::ram_fork::RamForkPlanError>),
    /// QEMU's borrowed installation boundary failed validation.
    #[error(transparent)]
    Abi(#[from] crate::QemuPluginAbiError),
    /// A canonical native identifier was not UTF-8.
    #[error(transparent)]
    Utf8(#[from] Utf8Error),
    /// An explicit operational integer was malformed or out of range.
    #[error(transparent)]
    Integer(#[from] ParseIntError),
    /// A specifically identified ownership, ordering or encoding invariant failed.
    #[error("RAM invariant failed: {0}")]
    Invariant(&'static str),
    /// A mandatory private symbol was absent from this QEMU incarnation.
    #[error("required native RAM export is absent: {0:?}")]
    MissingSymbol(&'static [u8]),
    /// The authenticated owner did not admit the complete metadata requirement.
    #[error("RAM metadata requires {required} bytes; owner admits {admitted}")]
    MetadataAdmission { required: u64, admitted: u64 },
    /// Live original-start supervision refused an operational action.
    #[error("RAM supervision refused {operation}: {failure}")]
    Supervision {
        operation: &'static str,
        failure: SupervisionFailure,
    },
}

/// A finite operational supervision disposition, independent of modeled time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SupervisionFailure {
    /// The original-start or progress allowance expired.
    #[error("deadline expired")]
    Expired,
    /// The retained operation was explicitly canceled.
    #[error("operation canceled")]
    Canceled,
    /// A complete finite class policy was not available.
    #[error("finite policy unavailable")]
    MissingPolicy,
    /// Admission or operation capacity was exhausted.
    #[error("operation capacity exhausted")]
    Capacity,
    /// Cleanup or execution authority could not be established.
    #[error("operational authority uncertain")]
    Uncertain,
}

// Operational source errors compare by retained failure identity. Cloning an
// installation result preserves its cause without flattening errno or type.
impl PartialEq for RamError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Core(left), Self::Core(right)) => left == right,
            (
                Self::Native {
                    operation: left,
                    status: left_status,
                },
                Self::Native {
                    operation: right,
                    status: right_status,
                },
            ) => left == right && left_status == right_status,
            (Self::Allocation(left), Self::Allocation(right)) => Arc::ptr_eq(left, right),
            (Self::Io(left), Self::Io(right)) => Arc::ptr_eq(left, right),
            (Self::Control(left), Self::Control(right)) => Arc::ptr_eq(left, right),
            (Self::PageProtocol(left), Self::PageProtocol(right)) => Arc::ptr_eq(left, right),
            (Self::ForkPlan(left), Self::ForkPlan(right)) => Arc::ptr_eq(left, right),
            (Self::Abi(left), Self::Abi(right)) => left == right,
            (Self::Utf8(left), Self::Utf8(right)) => left == right,
            (Self::Integer(left), Self::Integer(right)) => left == right,
            (Self::Invariant(left), Self::Invariant(right)) => left == right,
            (Self::MissingSymbol(left), Self::MissingSymbol(right)) => left == right,
            (
                Self::MetadataAdmission {
                    required: left,
                    admitted: left_admitted,
                },
                Self::MetadataAdmission {
                    required: right,
                    admitted: right_admitted,
                },
            ) => left == right && left_admitted == right_admitted,
            (
                Self::Supervision {
                    operation: left,
                    failure: left_failure,
                },
                Self::Supervision {
                    operation: right,
                    failure: right_failure,
                },
            ) => left == right && left_failure == right_failure,
            _ => false,
        }
    }
}

impl Eq for RamError {}

impl From<&'static str> for RamError {
    fn from(reason: &'static str) -> Self {
        Self::Invariant(reason)
    }
}

impl From<TryReserveError> for RamError {
    fn from(error: TryReserveError) -> Self {
        Self::Allocation(Arc::new(error))
    }
}

impl From<io::Error> for RamError {
    fn from(error: io::Error) -> Self {
        Self::Io(Arc::new(error))
    }
}

impl From<crucible_protocol::ram_control::RamControlError> for RamError {
    fn from(error: crucible_protocol::ram_control::RamControlError) -> Self {
        Self::Control(Arc::new(error))
    }
}

impl From<crucible_protocol::ram_page::RamPageProtocolError> for RamError {
    fn from(error: crucible_protocol::ram_page::RamPageProtocolError) -> Self {
        Self::PageProtocol(Arc::new(error))
    }
}

impl From<crucible_protocol::ram_fork::RamForkPlanError> for RamError {
    fn from(error: crucible_protocol::ram_fork::RamForkPlanError) -> Self {
        Self::ForkPlan(Arc::new(error))
    }
}
