//! Backend-neutral accounting for admitted attempt execution quanta.
//!
//! The counter charges common [`AttemptResourceLimits`] before modeled progress.
//! It does not authorize an execution grant, install native resource controls,
//! observe elapsed time, or acquire process ownership. Each actual backend guard
//! must still enforce its independently admitted operational contract.

use crucible_campaign::AttemptResourceLimits;
use std::fmt;

/// Tracks the exact admitted execution-quantum ceiling for one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptExecutionQuantumCounter {
    ceiling: u64,
    charged: u64,
}

impl AttemptExecutionQuantumCounter {
    /// Creates an unspent counter from the admitted resource limits.
    #[must_use]
    pub const fn new(resources: AttemptResourceLimits) -> Self {
        Self {
            ceiling: resources.maximum_execution_quanta(),
            charged: 0,
        }
    }

    /// Returns the exact admitted quantum ceiling.
    #[must_use]
    pub const fn ceiling(self) -> u64 {
        self.ceiling
    }

    /// Returns the number of quanta charged so far.
    #[must_use]
    pub const fn charged(self) -> u64 {
        self.charged
    }

    /// Charges one quantum before modeled progress.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionQuantumExhausted`] without changing the counter when
    /// the admitted ceiling has already been spent.
    pub fn charge(&mut self) -> Result<(), ExecutionQuantumExhausted> {
        if self.charged >= self.ceiling {
            return Err(ExecutionQuantumExhausted {
                ceiling: self.ceiling,
            });
        }

        // The admitted ceiling also bounds the increment at u64::MAX.
        self.charged += 1;
        Ok(())
    }
}

/// Reports that an attempt's admitted execution-quantum ceiling is exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionQuantumExhausted {
    ceiling: u64,
}

impl ExecutionQuantumExhausted {
    /// Returns the exact ceiling that prevented another charge.
    #[must_use]
    pub const fn ceiling(self) -> u64 {
        self.ceiling
    }
}

impl fmt::Display for ExecutionQuantumExhausted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("execution quantum ceiling is exhausted")
    }
}

impl std::error::Error for ExecutionQuantumExhausted {}

#[cfg(test)]
mod tests;
