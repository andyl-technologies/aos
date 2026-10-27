//! Proves explicit workspace lint levels reach the compiler.

/// Unwraps a caller-supplied optional value.
pub fn unwrap_value(value: Option<u32>) -> u32 {
    value.unwrap()
}
