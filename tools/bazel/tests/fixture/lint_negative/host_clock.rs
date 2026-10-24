//! Proves deterministic-state lint configuration reaches the compiler.

/// Reads the forbidden ambient host clock.
pub fn read_clock() -> std::time::Instant {
    std::time::Instant::now()
}
