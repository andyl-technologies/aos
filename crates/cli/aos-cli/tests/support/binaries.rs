//! Resolves declared CLI binaries before a subprocess changes its directory.

// Cargo supplies absolute binary paths. Bazel supplies paths in the test's
// runfiles directory; resolve those once while preserving the same callers.
macro_rules! cli_binary {
    ($variable:literal) => {{
        static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PATH.get_or_init(|| {
            std::path::absolute(env!($variable))
                .expect("resolve declared CLI test executable")
                .into_os_string()
                .into_string()
                .expect("CLI test executable path is UTF-8")
        })
        .as_str()
    }};
}
