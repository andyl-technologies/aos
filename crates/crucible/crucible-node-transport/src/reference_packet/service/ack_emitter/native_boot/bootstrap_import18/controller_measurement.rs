//! Measures the real original controller image under the admitted initial cut.
//!
//! The full reference is a temporary DATA comparison. No file, measurement,
//! Source purpose or native authority is retained or issued by this check.

use super::super::{
    measure_original_restore_controller_executable,
    original_prepare_executable_measurement_construction_data,
};
use super::*;
use crate::reference_packet::service::{
    PacketNative5SourceLaunch, complete_restore::import18::OriginalImport18DecodedBodyLoans,
};
use crucible_node_format::{ContentRef, HashRef, U64};

impl OriginalImport18RawBootstrap {
    /// Joins the running controller image to its authenticated declaration.
    ///
    /// # Errors
    ///
    /// Returns an error when the original typed bodies are unavailable, the
    /// bounded kernel image measurement fails, or its full reference differs.
    pub(super) fn authenticate_controller_executable_data(&self) -> Result<(), ProviderError> {
        let bodies = self.typed_bodies_data()?;
        let launch = bodies.launch.launch_data();
        // The preceding kernel join authenticates this PID against the same
        // original socket. The measurement reads /proc/<pid>/exe directly and
        // checks the same descriptor's length/metadata before and after reading.
        let actual = measure_original_restore_controller_executable(launch.controller_pid)?;
        if actual != launch.controller_executable {
            return Err(ProviderError::Correlation(
                "original import18 controller executable DATA",
            ));
        }
        Ok(())
    }
}

/// Prices the real sequential measurement, full reference and comparison work.
pub(in crate::reference_packet::service) fn construction_data() -> [usize; 3] {
    let mut row = original_prepare_executable_measurement_construction_data();
    row[2] += size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<OriginalImport18DecodedBodyLoans<'static>>()
        + size_of::<Result<OriginalImport18DecodedBodyLoans<'static>, ProviderError>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&ContentRef>() * 2
        + size_of::<&HashRef>() * 2
        + size_of::<&String>() * 6
        + size_of::<&U64>() * 2
        + size_of::<u64>() * 2
        + size_of::<bool>()
        + size_of::<Result<(), ProviderError>>();
    row
}
