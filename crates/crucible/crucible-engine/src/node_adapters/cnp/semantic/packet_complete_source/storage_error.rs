//! Shares the same owner walk between legacy diagnostics and typed precredit.
//!
//! The typed instantiation never formats a diagnostic or constructs an owned
//! error String. Legacy wrappers retain their original refused/unknown mapping.

use std::fmt::Display;

use crate::node_contract::{OperationFailure, RuntimeError};

pub(in crate::node_adapters::cnp::semantic) trait StorageError:
    Sized
{
    fn refused(reason: &'static str) -> Self;
    fn limit(reason: &'static str) -> Self;
    fn origin(reason: &'static str) -> Self;
    fn runtime(error: RuntimeError) -> Self;
    fn unknown(error: impl Display) -> Self;
    fn member_headers(
        member: &crate::node_admission::OriginalReportStartupMember,
    ) -> Result<usize, Self>;
    fn reservation_metadata(
        reservation: &crate::node_adapters::cnp::CnpSemanticSnapshotReservation,
    ) -> Result<usize, Self>;
    fn snapshot_metadata(
        snapshot: &crate::node_adapters::cnp::CnpOriginalSemanticSnapshot,
        maximum: usize,
    ) -> Result<usize, Self>;
    fn read(
        read: &crate::node_adapters::cnp::semantic::CnpSemanticSourceRead,
        maximum: usize,
    ) -> Result<crate::node_adapters::cnp::semantic::CnpRetainedStorageReport, Self>;
}

impl StorageError for OperationFailure {
    fn refused(reason: &'static str) -> Self {
        super::refused(reason)
    }
    fn limit(reason: &'static str) -> Self {
        super::refused(reason)
    }
    fn origin(reason: &'static str) -> Self {
        super::refused(reason)
    }
    fn runtime(error: RuntimeError) -> Self {
        super::unknown(error)
    }
    fn unknown(error: impl Display) -> Self {
        super::unknown(error)
    }
    fn member_headers(
        member: &crate::node_admission::OriginalReportStartupMember,
    ) -> Result<usize, Self> {
        member
            .retained_shared_storage_data()
            .map_err(super::unknown)
    }
    fn reservation_metadata(
        reservation: &crate::node_adapters::cnp::CnpSemanticSnapshotReservation,
    ) -> Result<usize, Self> {
        reservation.retained_metadata_requested_storage_data()
    }
    fn snapshot_metadata(
        snapshot: &crate::node_adapters::cnp::CnpOriginalSemanticSnapshot,
        maximum: usize,
    ) -> Result<usize, Self> {
        snapshot
            .retained_metadata_requested_storage_data(maximum)?
            .complete_requested_bytes()
    }
    fn read(
        read: &crate::node_adapters::cnp::semantic::CnpSemanticSourceRead,
        maximum: usize,
    ) -> Result<crate::node_adapters::cnp::semantic::CnpRetainedStorageReport, Self> {
        read.retained_requested_storage_data(maximum)
    }
}

impl StorageError for RuntimeError {
    fn refused(_: &'static str) -> Self {
        Self::UnsupportedFacet
    }
    fn limit(_: &'static str) -> Self {
        Self::ResourceLimit
    }
    fn origin(_: &'static str) -> Self {
        Self::ForeignAuthority
    }
    fn runtime(error: RuntimeError) -> Self {
        error
    }
    fn unknown(_: impl Display) -> Self {
        Self::UnsupportedFacet
    }
    fn member_headers(
        member: &crate::node_admission::OriginalReportStartupMember,
    ) -> Result<usize, Self> {
        member.retained_shared_storage_precredit_data()
    }
    fn reservation_metadata(
        reservation: &crate::node_adapters::cnp::CnpSemanticSnapshotReservation,
    ) -> Result<usize, Self> {
        reservation.retained_metadata_requested_storage_precredit_data()
    }
    fn snapshot_metadata(
        snapshot: &crate::node_adapters::cnp::CnpOriginalSemanticSnapshot,
        maximum: usize,
    ) -> Result<usize, Self> {
        snapshot
            .retained_metadata_requested_storage_precredit_data(maximum)?
            .complete_requested_bytes_precredit_data()
    }
    fn read(
        read: &crate::node_adapters::cnp::semantic::CnpSemanticSourceRead,
        maximum: usize,
    ) -> Result<crate::node_adapters::cnp::semantic::CnpRetainedStorageReport, Self> {
        read.retained_requested_storage_precredit_data(maximum)
    }
}

#[cfg(test)]
#[path = "storage_error/tests.rs"]
mod tests;
