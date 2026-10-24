//! Keeps successful probe captures under their original Main control loan.
//!
//! Moving a received value transfers the actual buffers and their payer together.
//! Borrowed output access cannot detach either allocation from its funding.

use crucible_host_resources::host_services::process_birth::SourceHostControlLease;
use std::process::Output;

/// Retains both probe buffers before returning their original funding.
#[derive(Debug)]
pub(crate) struct FundedProbeOutput<Funding> {
    // Field destruction order is intentional: both Vec allocations close first.
    output: Output,
    _funding: Funding,
}

/// Owns successful Source-issued captures and their existing Main loan.
pub(crate) type GuardedProbeOutput = FundedProbeOutput<SourceHostControlLease>;

impl<Funding> FundedProbeOutput<Funding> {
    pub(super) fn new(output: Output, funding: Funding) -> Self {
        Self {
            output,
            _funding: funding,
        }
    }

    /// Borrows captured status and bytes while retaining their original funding.
    pub(crate) fn output(&self) -> &Output {
        &self.output
    }
}

#[cfg(test)]
mod tests;
