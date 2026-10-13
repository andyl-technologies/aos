//! Owns canonical history reads within one authorization's held operation.
//!
//! Each invocation preserves its actual input purpose and completes its own
//! physical and Original checks before the enclosing Guard decides permission.

#[cfg(test)]
mod tests;
