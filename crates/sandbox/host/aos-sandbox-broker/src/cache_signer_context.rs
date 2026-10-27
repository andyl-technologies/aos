//! Shares the installed Cache task context across initial F and reply checks.
//!
//! The selected Cache unit uses the exact three-part non-MLS context. A task
//! observation and a socket SID remain distinct native facts; matching these
//! bytes cannot authenticate a process or substitute for its original pidfd.

/// Names the exact non-MLS task context installed for the Cache signer.
pub const CACHE_SIGNER_TASK_CONTEXT_V1: &[u8] = b"system_u:system_r:aos_sandbox_cache_signer_t";

/// Compares the exact Cache task context and an optional native terminator.
///
/// Only one trailing newline or NUL is accepted. An MLS field, arbitrary
/// suffix, another domain or multiple terminators is refused.
#[must_use]
pub fn cache_signer_task_context_matches_v1(actual: &[u8]) -> bool {
    exact_task_context_matches_v1(actual, CACHE_SIGNER_TASK_CONTEXT_V1, true)
}

// This is the existing shared F sampler's literal comparison. Its ordinary
// Source expectation and caller-selected terminal handling remain unchanged.
pub(crate) fn exact_task_context_matches_v1(
    actual: &[u8],
    expected: &[u8],
    allow_terminal: bool,
) -> bool {
    actual == expected || allow_terminal &&
        (actual.strip_suffix(b"\n") == Some(expected)
            || actual.strip_suffix(&[0]) == Some(expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_f_and_reply_match_the_same_installed_non_mls_cache_context() {
        for actual in [
            CACHE_SIGNER_TASK_CONTEXT_V1.to_vec(),
            [CACHE_SIGNER_TASK_CONTEXT_V1, b"\n"].concat(),
            [CACHE_SIGNER_TASK_CONTEXT_V1, &[0]].concat(),
        ] {
            assert!(cache_signer_task_context_matches_v1(&actual));
            assert!(exact_task_context_matches_v1(&actual, CACHE_SIGNER_TASK_CONTEXT_V1, true));
        }
        for suffix in [b":s0".as_slice(), b":s0\n", b":foreign", b"\n\0", b"\0\n"] {
            let actual = [CACHE_SIGNER_TASK_CONTEXT_V1, suffix].concat();
            assert!(!cache_signer_task_context_matches_v1(&actual));
            assert!(!exact_task_context_matches_v1(&actual, CACHE_SIGNER_TASK_CONTEXT_V1, true));
        }
        assert!(!cache_signer_task_context_matches_v1(b"system_u:system_r:aos_sandbox_source_signer_t"));
        assert!(!cache_signer_task_context_matches_v1(b""));
    }

    #[test]
    fn source_sampler_keeps_its_existing_exact_context_and_terminal_policy() {
        let expected = b"system_u:system_r:aos_sandbox_source_signer_t";
        let newline = [expected.as_slice(), b"\n"].concat();
        assert!(exact_task_context_matches_v1(expected, expected, false));
        assert!(!exact_task_context_matches_v1(&newline, expected, false));
        assert!(exact_task_context_matches_v1(&newline, expected, true));
        assert!(!exact_task_context_matches_v1(CACHE_SIGNER_TASK_CONTEXT_V1, expected, true));
    }
}
