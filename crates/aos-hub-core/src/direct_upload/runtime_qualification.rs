//! Closed configured runtime bounds and their original foreground eligibility.
//!
//! A reference names independently reviewed evidence; its fields cannot prove
//! measurement, cancellation, provider privacy, settlement or readiness.
//!
//! ```text
//! version=1, qualificationDigest=<sha256>, maximumObjectBytes=<decimal string>,
//! maximumVerificationSeconds=<decimal string>, maximumParallelObjects=<decimal string>,
//! settlementReserveSeconds=<decimal string>,
//! maximumParallelProviderRequests=<decimal string>,
//! cacheDestinationPolicy=retained_original_baseline
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{valid_direct_digest, WireInteger, MAX_DIRECT_OBJECT_BYTES};

/// Mandatory original-baseline policy for every new cache destination mutation.
///
/// Naming this policy proves no retained reservation or Native permission.
/// Actual dispatch enforces the original baseline and fixed foreground cutoff;
/// exact historical terminal receipts remain free of provider I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectCacheDestinationPolicy {
    /// Requires the original retained baseline and permission before new mutation.
    RetainedOriginalBaseline,
}

/// Independently reviewed runtime reference with explicit configured ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectRuntimeQualification {
    /// Closed foreground reference version, currently one.
    pub version: u32,
    /// Exact independently reviewed artifact/API/capacity evidence commitment.
    pub qualification_digest: String,
    /// Maximum source size; the protocol ceiling alone cannot qualify this limit.
    pub maximum_object_bytes: WireInteger,
    /// Maximum verification duration within the actual remaining invocation budget.
    pub maximum_verification_seconds: WireInteger,
    /// Positive protected control/settlement reserve, never a guessed default.
    pub settlement_reserve_seconds: WireInteger,
    /// Maximum simultaneous objects in the participating Worker isolate.
    pub maximum_parallel_objects: WireInteger,
    /// Maximum simultaneous provider requests in the participating Worker isolate.
    pub maximum_parallel_provider_requests: WireInteger,
    /// Required cache destination dispatch policy, with no bypass or default.
    pub cache_destination_policy: DirectCacheDestinationPolicy,
}

impl DirectRuntimeQualification {
    /// Checks closed version, commitment, protocol size and configured concurrency.
    ///
    /// This structural check does not establish actual runtime qualification.
    ///
    /// # Errors
    /// Returns a value-free error for an unknown version or malformed bounds.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && valid_direct_digest(&self.qualification_digest)
                && (1..=MAX_DIRECT_OBJECT_BYTES).contains(&self.maximum_object_bytes.get())
                && self.maximum_verification_seconds.get() > 0
                && self.settlement_reserve_seconds.get() > 0
                && (1..=32).contains(&self.maximum_parallel_objects.get())
                && (1..=32).contains(&self.maximum_parallel_provider_requests.get())
                && self.cache_destination_policy
                    == DirectCacheDestinationPolicy::RetainedOriginalBaseline,
            "invalid direct runtime qualification reference"
        );
        Ok(())
    }

    /// Checks verification against the actual remaining original foreground window.
    ///
    /// The adapter supplies qualified uncertainty; the reserve comes from this
    /// exact retained protected reference. No default reserve or larger read
    /// window is inferred. New private authorization cannot extend the invocation.
    ///
    /// # Errors
    /// Returns a value-free error for invalid inputs, subtraction underflow or
    /// a verification ceiling that exceeds the conservative remainder.
    pub fn validate_foreground_window(
        &self,
        actual_remaining_seconds: u64,
        qualified_uncertainty: u64,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            (1..=30).contains(&actual_remaining_seconds)
                && (1..30).contains(&qualified_uncertainty),
            "invalid direct runtime foreground policy"
        );
        let available = actual_remaining_seconds
            .checked_sub(qualified_uncertainty)
            .and_then(|remaining| remaining.checked_sub(self.settlement_reserve_seconds.get()));
        ensure!(
            available.is_some_and(|seconds| self.maximum_verification_seconds.get() <= seconds),
            "direct runtime verification exceeds foreground budget"
        );
        Ok(())
    }
}
