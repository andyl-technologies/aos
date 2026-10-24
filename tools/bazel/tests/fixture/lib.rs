//! Supplies a deterministic value for cross-derivation cache qualification.

/// Returns the fixture's shared library value.
///
/// # Examples
///
/// ```rust
/// assert_eq!(fixture_library::answer(), 42);
/// assert_eq!(env!("CARGO_PKG_NAME"), "aos-bazel-fixture");
/// assert_eq!(env!("CARGO_PKG_VERSION"), "1.2.3-rc.4+local.5");
/// ```
pub fn answer() -> u32 {
    fixture_generated::answer() + u32::from(cfg!(feature = "extra"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    static PROCESS_USED: AtomicBool = AtomicBool::new(false);

    #[test]
    fn returns_expected_answer() {
        assert_eq!(super::answer(), 42);
    }

    #[test]
    fn package_metadata_matches_the_declared_identity() {
        assert_eq!(env!("CARGO_PKG_NAME"), "aos-bazel-fixture");
        assert_eq!(env!("CARGO_PKG_VERSION"), "1.2.3-rc.4+local.5");
        assert_eq!(env!("CARGO_PKG_VERSION_MAJOR"), "1");
        assert_eq!(env!("CARGO_PKG_VERSION_MINOR"), "2");
        assert_eq!(env!("CARGO_PKG_VERSION_PATCH"), "3");
        assert_eq!(env!("CARGO_PKG_VERSION_PRE"), "rc.4");
        assert_eq!(env!("CARGO_PKG_AUTHORS"), "Fixture One:Fixture Two");
        assert_eq!(
            env!("CARGO_PKG_DESCRIPTION"),
            "Hermetic Bazel qualification fixture"
        );
        assert_eq!(
            env!("CARGO_PKG_HOMEPAGE"),
            "https://example.invalid/fixture"
        );
        assert_eq!(
            env!("CARGO_PKG_REPOSITORY"),
            "https://example.invalid/fixture/source"
        );
        assert_eq!(env!("CARGO_PKG_LICENSE"), "Apache-2.0");
        assert_eq!(env!("CARGO_PKG_LICENSE_FILE"), "");
        assert_eq!(env!("CARGO_PKG_README"), "");
        assert_eq!(env!("CARGO_PKG_RUST_VERSION"), "");
    }

    #[test]
    fn first_case_owns_a_fresh_process() {
        assert!(!PROCESS_USED.swap(true, Ordering::SeqCst));
    }

    #[test]
    fn second_case_owns_a_fresh_process() {
        assert!(!PROCESS_USED.swap(true, Ordering::SeqCst));
    }

    #[test]
    #[ignore = "validates the runner's default ignored-test selection"]
    fn ignored_case_is_not_selected() {
        panic!("an ignored case ran without an explicit request");
    }
}
