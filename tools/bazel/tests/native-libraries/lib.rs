//! Exercises native-library linkage from a compiled Rust documentation example.

// SAFETY: The C helper accepts no arguments and owns its database and buffers.
unsafe extern "C" {
    safe fn native_library_probe() -> i32;
}

/// Returns the answer obtained through the selected SQLite and zstd libraries.
///
/// # Examples
///
/// ```
/// assert_eq!(native_library_fixture::answer(), 42);
/// ```
pub fn answer() -> i32 {
    native_library_probe()
}
