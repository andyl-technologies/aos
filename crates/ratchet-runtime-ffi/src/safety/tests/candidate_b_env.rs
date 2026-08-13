//! Candidate-B environment-wrapper entries in the unsafe review manifest.

use super::{
    EXTERN_TOKEN, UNSAFE_TOKEN, assert_has_safety_comment_before, assert_has_safety_doc_before,
    trimmed_line_occurrences,
};

const FN_TYPE_LINE: &str = concat!(
    "pub type RuntimeCandidateBEnvGetNativeFn = ",
    "uns",
    "afe ",
    "ext",
    "ern \"C\" fn(*mut c_void, u32) -> u64;"
);
const FN_LINE: &str = concat!(
    "pub ",
    "uns",
    "afe ",
    "ext",
    "ern \"C\" fn aos_candidate_b_env_get(env: *mut c_void, slot: u32) -> u64 {"
);
const DECODER_CALL_LINE: &str = concat!(
    "uns",
    "afe { // aos_candidate_b_env_get runtime-environment decode"
);
const TEST_CALL_LINE: &str = concat!(
    "let raw = ",
    "uns",
    "afe { aos_candidate_b_env_get(env_ptr, 0) };"
);

pub(super) fn is_allowed_token(line: &str, token: &str) -> bool {
    let trimmed = line.trim_start();
    match token {
        UNSAFE_TOKEN => matches!(
            trimmed,
            FN_TYPE_LINE | FN_LINE | DECODER_CALL_LINE | TEST_CALL_LINE
        ),
        EXTERN_TOKEN => matches!(trimmed, FN_TYPE_LINE | FN_LINE),
        _ => false,
    }
}

pub(super) fn assert_reviewed_counts(source: &str) {
    for (line, label) in [
        (FN_TYPE_LINE, "function-pointer type"),
        (FN_LINE, "wrapper"),
        (DECODER_CALL_LINE, "decoder call"),
        (TEST_CALL_LINE, "direct test call"),
    ] {
        assert_eq!(
            trimmed_line_occurrences(source, line),
            1,
            "Candidate-B env {label} must stay singly reviewed"
        );
    }
}

pub(super) fn assert_reviewed_safety_comments(lines: &[&str]) {
    assert_has_safety_comment_before(
        lines,
        DECODER_CALL_LINE,
        "Candidate-B aos_env_get decoder call must keep a SAFETY comment",
    );
    assert_has_safety_comment_before(
        lines,
        TEST_CALL_LINE,
        "Candidate-B aos_env_get direct test call must keep a SAFETY comment",
    );
}

pub(super) fn assert_public_unsafe_docs(lines: &[&str]) {
    assert_has_safety_doc_before(
        lines,
        FN_TYPE_LINE,
        "public Candidate-B env function-pointer type must document # Safety",
    );
    assert_has_safety_doc_before(
        lines,
        FN_LINE,
        "public Candidate-B env wrapper must document # Safety",
    );
}
