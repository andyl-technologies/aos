//! Supplies a deterministic value for cross-derivation cache qualification.

/// Returns the fixture's shared library value.
pub fn answer() -> u32 {
    42
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
