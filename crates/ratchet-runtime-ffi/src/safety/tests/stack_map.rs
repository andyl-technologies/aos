//! Exact unsafe-boundary audit for compiled stack-map bindings.

use super::*;

const JIT_CONTEXT_DECODER: &str = concat!(
    "pub(crate) ", "uns", "afe fn with_native_jit_context<R>("
);
const JIT_CONTEXT_CAST: &str = concat!(
    "call(", "uns", "afe { rt.cast::<RuntimeJitContext<'static>>().as_mut() })"
);
const JIT_EVALUATOR_CONTEXT_DECODER: &str = concat!(
    "pub(crate) ", "uns", "afe fn with_native_jit_evaluator_context<R>("
);
const JIT_EVALUATOR_CONTEXT_CAST: &str = concat!(
    "let jit_context = ", "uns", "afe { rt.cast::<RuntimeJitContext<'static>>().as_mut() };"
);
const JIT_EVALUATOR_CAST: &str = concat!(
    "let eval = ", "uns", "afe { jit_context.eval.as_mut() };"
);
const ENTER_TYPE: &str = concat!(
    "uns", "afe ", "ext", "ern \"C\" fn(*mut c_void, *mut c_void, u32, u32);"
);
const EXIT_TYPE: &str = concat!(
    "pub type RuntimeJitStackMapExitNativeFn = ", "uns", "afe ", "ext",
    "ern \"C\" fn(*mut c_void, *mut c_void);"
);
const EXPORT_ATTR: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
const ENTER_FN: &str = concat!(
    "pub ", "uns", "afe ", "ext", "ern \"C\" fn aos_jit_stack_map_enter("
);
const EXIT_FN: &str = concat!(
    "pub ", "uns", "afe ", "ext",
    "ern \"C\" fn aos_jit_stack_map_exit(rt: *mut c_void, binding: *mut c_void) {"
);
const HEADER_READ: &str = concat!("let header = ", "uns", "afe { binding.as_ref() };");
const BOUND_HEADER_READ: &str = concat!(
    "let bound_header = ", "uns", "afe { binding.as_ref() };"
);
const VALUES_ADDRESS: &str = concat!("let values = ", "uns", "afe {");
const VALUE_READ: &str = concat!(
    "let value = ", "uns", "afe { values.add(index as usize).read() };"
);
const BOUND_VALUE_READ: &str = concat!(
    "let value = ", "uns", "afe { pointer.as_ptr().read() };"
);
const BOUND_VALUE_WRITE: &str = concat!(
    "uns", "afe { pointer.as_ptr().write(slot.value()) };"
);
const BOUND_VALUE_ADDRESS: &str = concat!("let pointer = ", "uns", "afe {");
const ENTER_DECODE: &str = concat!(
    "uns", "afe { // aos_jit_stack_map_enter runtime-context decode"
);
const EXIT_DECODE: &str = concat!(
    "uns", "afe { // aos_jit_stack_map_exit runtime-context decode"
);
const TEST_CALL: &str = concat!("uns", "afe { // balanced stack-map binding exercise");

pub(super) fn is_allowed_token(
    source_root: &Path,
    source_path: &Path,
    line: &str,
    token: &str,
) -> bool {
    if !is_unsafe_boundary_token(token) {
        return false;
    }
    let trimmed = line.trim_start();
    if source_path == source_root.join("context.rs") {
        return token == UNSAFE_TOKEN
            && matches!(trimmed, JIT_CONTEXT_DECODER | JIT_CONTEXT_CAST
                | JIT_EVALUATOR_CONTEXT_DECODER | JIT_EVALUATOR_CONTEXT_CAST
                | JIT_EVALUATOR_CAST);
    }
    if source_path != source_root.join("stack_map.rs") {
        return false;
    }
    match token {
        UNSAFE_TOKEN => [ENTER_TYPE, EXIT_TYPE, EXPORT_ATTR, ENTER_FN, EXIT_FN, HEADER_READ,
            BOUND_HEADER_READ,
            VALUES_ADDRESS, VALUE_READ, BOUND_VALUE_READ, BOUND_VALUE_WRITE,
            BOUND_VALUE_ADDRESS, ENTER_DECODE, EXIT_DECODE, TEST_CALL].contains(&trimmed),
        EXTERN_TOKEN => [ENTER_TYPE, EXIT_TYPE, ENTER_FN, EXIT_FN].contains(&trimmed),
        NO_MANGLE_TOKEN => trimmed == EXPORT_ATTR,
        _ => false,
    }
}

pub(super) fn assert_reviewed(source_root: &Path) {
    let context = fs::read_to_string(source_root.join("context.rs"))
        .expect("shared runtime context FFI source file is readable");
    let source = fs::read_to_string(source_root.join("stack_map.rs"))
        .expect("stack-map FFI source file is readable");
    for (text, expected, message) in [
        (JIT_CONTEXT_DECODER, 1, "JIT context decoder"),
        (JIT_CONTEXT_CAST, 1, "JIT context cast"),
        (JIT_EVALUATOR_CONTEXT_DECODER, 1, "JIT evaluator-context decoder"),
        (JIT_EVALUATOR_CONTEXT_CAST, 1, "JIT evaluator-context cast"),
        (JIT_EVALUATOR_CAST, 1, "JIT evaluator cast"),
        (ENTER_TYPE, 1, "enter function-pointer type"),
        (EXIT_TYPE, 1, "exit function-pointer type"),
        (EXPORT_ATTR, 2, "export attributes"),
    ] {
        let input = if matches!(text, JIT_CONTEXT_DECODER | JIT_CONTEXT_CAST
            | JIT_EVALUATOR_CONTEXT_DECODER | JIT_EVALUATOR_CONTEXT_CAST
            | JIT_EVALUATOR_CAST) {
            &context
        } else {
            &source
        };
        assert_eq!(trimmed_line_occurrences(input, text), expected, "{message} changed");
    }
    for line in [ENTER_FN, EXIT_FN, HEADER_READ, BOUND_HEADER_READ, VALUES_ADDRESS, VALUE_READ, BOUND_VALUE_READ,
        BOUND_VALUE_WRITE, BOUND_VALUE_ADDRESS, ENTER_DECODE, EXIT_DECODE, TEST_CALL] {
        assert_eq!(trimmed_line_occurrences(&source, line), 1, "reviewed line changed");
    }
    let lines = source.lines().collect::<Vec<_>>();
    for line in [HEADER_READ, BOUND_HEADER_READ, VALUES_ADDRESS, VALUE_READ, BOUND_VALUE_READ, BOUND_VALUE_WRITE,
        BOUND_VALUE_ADDRESS, ENTER_DECODE, EXIT_DECODE, TEST_CALL] {
        assert_has_safety_comment_before(&lines, line, "stack-map operation needs SAFETY comment");
    }
    let context_lines = context.lines().collect::<Vec<_>>();
    for line in [JIT_CONTEXT_DECODER, JIT_CONTEXT_CAST, JIT_EVALUATOR_CONTEXT_DECODER,
        JIT_EVALUATOR_CONTEXT_CAST, JIT_EVALUATOR_CAST] {
        assert_has_safety_comment_before(
            &context_lines,
            line,
            "JIT context operation needs SAFETY comment",
        );
    }
    for line in [ENTER_TYPE, EXIT_TYPE, ENTER_FN, EXIT_FN] {
        assert_has_safety_doc_before(&lines, line, "public stack-map ABI needs # Safety");
    }
}

#[test]
fn source_filter_does_not_accept_lint_inside_block_comments() {
    let filtered = code_lines_without_comments_or_ordinary_strings(
        "/*\n#![deny(unsafe_op_in_unsafe_fn)]\n*/\npub mod env;",
    );
    assert!(
        !filtered
            .iter()
            .any(|line| line.trim() == RUNTIME_FFI_UNSAFE_CRATE_LINT)
    );
}
