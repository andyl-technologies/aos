//! Shares the single fixed ESYS helper runtime resource calculation.
//!
//! Normal Security and initial Source custody quote the same source-built
//! code, TCTI, crypto and scratch geometry. Callers authenticate and debit
//! their own genuine Source before constructing or driving a native owner.

// Published helper source fixes the160/48/80/84/128 byte protocol, explicit
// device TCTI<=64KiB, salt/session/index resources and bounded TPM public data.
const MAPPED_CODE_BYTES: u64 = 16 * 1024 * 1024;
const TCTI_BYTES: u64 = 65536;
const FIXED_TPM_CRYPTO_WORK_BYTES: u64 = 4 * 1024 * 1024;
const NATIVE_SCRATCH_BYTES: usize = 4 * 65536 + 4096 * 4;

/// Quotes the fixed shared ESYS helper code, TCTI, crypto, scratch and stack.
///
/// The actual service cgroup backs residual native allocator bookkeeping.
/// An unbounded inherited stack overflows and refuses. This passive supplier
/// grants no receiving, process, TPM or successful physical-operation authority.
#[must_use]
pub fn helper_runtime_bytes_v1(stack: rustix::process::Rlimit) -> Option<u64> {
    u64::try_from(NATIVE_SCRATCH_BYTES)
        .ok()?
        .checked_add(MAPPED_CODE_BYTES)?
        .checked_add(TCTI_BYTES)?
        .checked_add(FIXED_TPM_CRYPTO_WORK_BYTES)?
        // Unlimited requests overflow and refuse, rather than inventing a
        // narrower process limit in a representation supplier.
        .checked_add(stack.current.unwrap_or(u64::MAX))
}
