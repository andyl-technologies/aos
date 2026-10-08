//! Shared bounds for structurally checked public requests and their client state.
//!
//! These ceilings constrain untrusted DATA; meeting them does not authenticate
//! a caller, reserve resources, or grant Controller admission or effect authority.

/// Maximum decoded bytes in an opaque resource version or cursor.
pub const MAXIMUM_CLI_OPAQUE_BYTES: usize = 4 * 1024;

/// Maximum bytes in an idempotency key.
pub const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Maximum pages consumed by one CLI invocation.
pub const MAXIMUM_CLI_PAGES: u16 = 4_096;

/// Maximum events retained by one command invocation.
pub const MAXIMUM_CLI_EVENTS: u32 = 65_536;

/// Maximum client-side wait duration in nanoseconds.
pub const MAXIMUM_CLI_WAIT_NANOSECONDS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

/// Maximum arguments accepted by one execution.
pub const MAXIMUM_EXEC_ARGUMENTS: usize = aos_sandbox_core::MAX_EXECUTION_ARGUMENTS;

/// Maximum bytes in one execution argument.
pub const MAXIMUM_EXEC_ARGUMENT_BYTES: usize =
    aos_sandbox_core::MAX_EXECUTION_ARGUMENT_STRING_BYTES;

/// Maximum aggregate bytes in an execution argument vector.
pub const MAXIMUM_EXEC_ARGUMENT_VECTOR_BYTES: usize =
    aos_sandbox_core::MAX_EXECUTION_ARGUMENT_BYTES;

/// Maximum environment rows supplied to one execution.
pub const MAXIMUM_EXEC_ENVIRONMENT: usize = aos_sandbox_core::MAX_EXECUTION_ENVIRONMENT_ENTRIES;

/// Maximum bytes in one environment name.
pub const MAXIMUM_EXEC_ENVIRONMENT_NAME_BYTES: usize =
    aos_sandbox_core::MAX_EXECUTION_ENVIRONMENT_NAME_BYTES;

/// Maximum bytes in one environment value.
pub const MAXIMUM_EXEC_ENVIRONMENT_VALUE_BYTES: usize =
    aos_sandbox_core::MAX_EXECUTION_ENVIRONMENT_VALUE_BYTES;

/// Maximum aggregate environment bytes.
pub const MAXIMUM_EXEC_ENVIRONMENT_BYTES: usize = aos_sandbox_core::MAX_EXECUTION_ENVIRONMENT_BYTES;

/// Maximum public-key or proof bytes used for endpoint admission.
pub const MAXIMUM_ENDPOINT_PROOF_BYTES: usize = 64 * 1024;
