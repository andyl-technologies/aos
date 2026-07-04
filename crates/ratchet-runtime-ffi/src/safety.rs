//! Unsafe-discipline manifest for runtime FFI wrappers.
//!
//! `ratchet-runtime-ffi` is intentionally unsafe-capable because native runtime
//! helper wrappers must decode raw ABI pointers supplied by compiled code. This
//! module records the standing controls for that boundary and tests that current
//! source files keep every unsafe token on a reviewed allowlist.

/// Crate-level lint required for the runtime FFI unsafe boundary.
pub const RUNTIME_FFI_UNSAFE_CRATE_LINT: &str = "#![deny(unsafe_op_in_unsafe_fn)]";

/// Comment prefix required beside each runtime FFI unsafe operation.
pub const RUNTIME_FFI_SAFETY_COMMENT_PREFIX: &str = "// SAFETY:";

/// The runtime FFI operation that remains innately unsafe after validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFfiInnateUnsafeOperation {
    /// Decodes a caller-supplied raw runtime pointer inside a native ABI wrapper.
    NativeWrapperPointerDecode,
}

/// Standing controls required before unsafe runtime FFI code can land.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFfiUnsafeDiscipline {
    crate_lint: &'static str,
    safety_comment_prefix: &'static str,
    second_reviewer_required: bool,
    sanitizer_ci_required: bool,
    innate_unsafe_operation: RuntimeFfiInnateUnsafeOperation,
}

impl RuntimeFfiUnsafeDiscipline {
    /// Creates the standing runtime FFI unsafe-discipline manifest.
    pub const fn new(
        crate_lint: &'static str,
        safety_comment_prefix: &'static str,
        second_reviewer_required: bool,
        sanitizer_ci_required: bool,
        innate_unsafe_operation: RuntimeFfiInnateUnsafeOperation,
    ) -> Self {
        Self {
            crate_lint,
            safety_comment_prefix,
            second_reviewer_required,
            sanitizer_ci_required,
            innate_unsafe_operation,
        }
    }

    /// Returns the crate-level lint required by the unsafe boundary.
    pub const fn crate_lint(self) -> &'static str {
        self.crate_lint
    }

    /// Returns the required local invariant-comment prefix.
    pub const fn safety_comment_prefix(self) -> &'static str {
        self.safety_comment_prefix
    }

    /// Returns whether a second reviewer is required for new unsafe blocks.
    pub const fn second_reviewer_required(self) -> bool {
        self.second_reviewer_required
    }

    /// Returns whether sanitizer CI must cover unsafe runtime FFI paths.
    pub const fn sanitizer_ci_required(self) -> bool {
        self.sanitizer_ci_required
    }

    /// Returns the innate unsafe operation isolated by this crate.
    pub const fn innate_unsafe_operation(self) -> RuntimeFfiInnateUnsafeOperation {
        self.innate_unsafe_operation
    }
}

/// Returns the standing unsafe-discipline manifest for `ratchet-runtime-ffi`.
pub const fn runtime_ffi_unsafe_discipline() -> RuntimeFfiUnsafeDiscipline {
    RuntimeFfiUnsafeDiscipline::new(
        RUNTIME_FFI_UNSAFE_CRATE_LINT,
        RUNTIME_FFI_SAFETY_COMMENT_PREFIX,
        true,
        true,
        RuntimeFfiInnateUnsafeOperation::NativeWrapperPointerDecode,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use super::*;

    const UNSAFE_TOKEN: &str = concat!("uns", "afe");
    const EXTERN_TOKEN: &str = concat!("ext", "ern");
    const NO_MANGLE_TOKEN: &str = concat!("no_", "mangle");
    const ENV_GET_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeEnvGetNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, u32) -> Value;"
    );
    const ENV_GET_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const ENV_GET_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_env_get(env: *mut c_void, slot: u32) -> Value {"
    );
    const ENV_GET_DECODER_CALL_LINE: &str = concat!("uns", "afe {");
    const ENV_FRAME_DECODER_LINE: &str = concat!(
        "uns",
        "afe fn with_native_env_frame<R>(env: *mut c_void, call: impl FnOnce(&EvalFrame) -> R) -> R {"
    );
    const ENV_FRAME_CAST_LINE: &str =
        concat!("call(", "uns", "afe { env.cast::<EvalFrame>().as_ref() })");
    const DIRECT_TEST_CALL_LINE: &str =
        concat!("let actual = ", "uns", "afe { aos_env_get(env, 1) };");
    const BINDING_TEST_CALL_LINE: &str = concat!(
        "let actual = ",
        "uns",
        "afe { (binding.function())(env, 0) };"
    );
    const FORCE_FN_TYPE_LINE: &str = concat!(
        "pub type RuntimeForceNativeFn = ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn(*mut c_void, Value) -> Value;"
    );
    const FORCE_EXPORT_ATTR_LINE: &str = concat!("#[", "uns", "afe(", "no_", "mangle)]");
    const FORCE_FN_LINE: &str = concat!(
        "pub ",
        "uns",
        "afe ",
        "ext",
        "ern \"C\" fn aos_force(_rt: *mut c_void, value: Value) -> Value {"
    );
    const DIRECT_FORCE_TEST_CALL_LINE: &str =
        concat!("let actual = ", "uns", "afe { aos_force(rt, expected) };");
    const FORCE_BINDING_TEST_CALL_LINE: &str = concat!(
        "let actual = ",
        "uns",
        "afe { (binding.function())(rt, expected) };"
    );
    const FORCE_MALFORMED_VALUE_TRANSMUTE_LINE: &str = concat!(
        "let malformed = ",
        "uns",
        "afe { std::mem::transmute::<RawValueForTest, Value>(raw) };"
    );
    const FORCE_MALFORMED_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_force(rt, malformed) };");
    const FORCE_THUNK_ABORT_TEST_CALL_LINE: &str =
        concat!("let _ = ", "uns", "afe { aos_force(rt, thunk) };");

    #[test]
    fn discipline_manifest_names_required_controls() {
        let discipline = runtime_ffi_unsafe_discipline();

        assert_eq!(discipline.crate_lint(), RUNTIME_FFI_UNSAFE_CRATE_LINT);
        assert_eq!(
            discipline.safety_comment_prefix(),
            RUNTIME_FFI_SAFETY_COMMENT_PREFIX
        );
        assert!(discipline.second_reviewer_required());
        assert!(discipline.sanitizer_ci_required());
        assert_eq!(
            discipline.innate_unsafe_operation(),
            RuntimeFfiInnateUnsafeOperation::NativeWrapperPointerDecode
        );
    }

    #[test]
    fn crate_root_declares_unsafe_operation_lint() {
        let crate_root = include_str!("lib.rs");
        let mut saw_item = false;

        for code in code_lines_without_comments_or_ordinary_strings(crate_root) {
            let trimmed = code.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == RUNTIME_FFI_UNSAFE_CRATE_LINT {
                assert!(
                    !saw_item,
                    "runtime FFI unsafe lint must appear before crate items"
                );
                return;
            }
            if trimmed.starts_with("pub ") {
                saw_item = true;
            }
        }

        panic!("crate root does not declare {RUNTIME_FFI_UNSAFE_CRATE_LINT}");
    }

    #[test]
    fn current_runtime_ffi_sources_keep_unsafe_boundaries_allowlisted() {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut findings = Vec::new();

        assert_sources_compile_only_from_scanned_tree(&source_root);

        for source_path in rust_sources(&source_root) {
            let source = fs::read_to_string(&source_path).expect("source file is readable");
            let raw_lines = source.lines().collect::<Vec<_>>();
            let code_lines = code_lines_without_comments_or_ordinary_strings(&source);
            assert_eq!(
                raw_lines.len(),
                code_lines.len(),
                "source filter must preserve line count for {}",
                source_path.display()
            );

            for (line_number, code) in code_lines.iter().enumerate() {
                let line = raw_lines[line_number];
                for token in code_tokens(code) {
                    if is_allowed_env_wrapper_token(&source_root, &source_path, line, token)
                        || is_allowed_force_wrapper_token(&source_root, &source_path, line, token)
                    {
                        continue;
                    }

                    if is_unsafe_boundary_token(token) {
                        findings.push(format!(
                            "{}:{} contains `{token}`",
                            source_path.display(),
                            line_number + 1
                        ));
                    }
                }
            }
        }

        assert!(
            findings.is_empty(),
            "ratchet-runtime-ffi contains unreviewed unsafe-boundary tokens:\n{}",
            findings.join("\n")
        );

        assert_reviewed_unsafe_boundary_counts(&source_root);
        assert_reviewed_safety_comments(&source_root);
        assert_public_unsafe_docs(&source_root);
    }

    fn is_allowed_env_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("env.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == ENV_GET_FN_TYPE_LINE
                || trimmed == ENV_GET_EXPORT_ATTR_LINE
                || trimmed == ENV_GET_FN_LINE
                || trimmed == ENV_GET_DECODER_CALL_LINE
                || trimmed == ENV_FRAME_DECODER_LINE
                || trimmed == ENV_FRAME_CAST_LINE
                || trimmed == DIRECT_TEST_CALL_LINE
                || trimmed == BINDING_TEST_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == ENV_GET_FN_TYPE_LINE || trimmed == ENV_GET_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == ENV_GET_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_allowed_force_wrapper_token(
        source_root: &Path,
        source_path: &Path,
        line: &str,
        token: &str,
    ) -> bool {
        if !is_unsafe_boundary_token(token) {
            return false;
        }

        if source_path != source_root.join("force.rs") {
            return false;
        }

        let trimmed = line.trim_start();
        if token == UNSAFE_TOKEN {
            trimmed == FORCE_FN_TYPE_LINE
                || trimmed == FORCE_EXPORT_ATTR_LINE
                || trimmed == FORCE_FN_LINE
                || trimmed == DIRECT_FORCE_TEST_CALL_LINE
                || trimmed == FORCE_BINDING_TEST_CALL_LINE
                || trimmed == FORCE_MALFORMED_VALUE_TRANSMUTE_LINE
                || trimmed == FORCE_MALFORMED_ABORT_TEST_CALL_LINE
                || trimmed == FORCE_THUNK_ABORT_TEST_CALL_LINE
        } else if token == EXTERN_TOKEN {
            trimmed == FORCE_FN_TYPE_LINE || trimmed == FORCE_FN_LINE
        } else if token == NO_MANGLE_TOKEN {
            trimmed == FORCE_EXPORT_ATTR_LINE
        } else {
            false
        }
    }

    fn is_unsafe_boundary_token(token: &str) -> bool {
        [UNSAFE_TOKEN, EXTERN_TOKEN, NO_MANGLE_TOKEN].contains(&token)
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

    #[test]
    fn source_retargeting_detection_rejects_unscanned_rust_inputs() {
        let findings = source_retargeting_findings(
            Path::new("synthetic.rs"),
            r#"
include!("../unchecked.rs");
#[path = "../unchecked.rs"]
mod unchecked;
#[cfg_attr(feature = "ffi", path = "../unchecked_cfg.rs")]
mod unchecked_cfg;
"#,
        );

        assert_eq!(findings.len(), 3);
        assert!(
            findings
                .iter()
                .any(|finding| finding.contains(INCLUDE_MACRO_LABEL))
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.contains(PATH_ATTRIBUTE_LABEL))
                .count(),
            2
        );
    }

    fn rust_sources(root: &Path) -> Vec<PathBuf> {
        let mut sources = Vec::new();
        collect_rust_sources(root, &mut sources);
        sources.sort();
        sources
    }

    fn collect_rust_sources(path: &Path, sources: &mut Vec<PathBuf>) {
        if path.is_dir() {
            for entry in fs::read_dir(path).expect("source directory is readable") {
                collect_rust_sources(&entry.expect("source entry is readable").path(), sources);
            }
            return;
        }

        if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path.to_path_buf());
        }
    }

    fn code_lines_without_comments_or_ordinary_strings(source: &str) -> Vec<String> {
        let mut lines = Vec::new();
        let mut in_string = false;
        let mut raw_string_hashes = None;
        let mut escaped = false;
        let mut block_comment_depth = 0usize;

        for line in source.lines() {
            let mut code = String::with_capacity(line.len());
            let chars = line.chars().collect::<Vec<_>>();
            let mut index = 0;

            while index < chars.len() {
                if let Some(hashes) = raw_string_hashes {
                    if chars[index] == '"' && raw_string_terminator_matches(&chars, index, hashes) {
                        for _ in 0..=hashes {
                            code.push(' ');
                        }
                        index += hashes + 1;
                        raw_string_hashes = None;
                    } else {
                        code.push(' ');
                        index += 1;
                    }
                    continue;
                }

                let ch = chars[index];
                if block_comment_depth > 0 {
                    if ch == '/' && chars.get(index + 1) == Some(&'*') {
                        block_comment_depth += 1;
                        code.push(' ');
                        code.push(' ');
                        index += 2;
                    } else if ch == '*' && chars.get(index + 1) == Some(&'/') {
                        block_comment_depth -= 1;
                        code.push(' ');
                        code.push(' ');
                        index += 2;
                    } else {
                        code.push(' ');
                        index += 1;
                    }
                    continue;
                }

                if !in_string && ch == '/' && chars.get(index + 1) == Some(&'/') {
                    break;
                }

                if !in_string && ch == '/' && chars.get(index + 1) == Some(&'*') {
                    block_comment_depth += 1;
                    code.push(' ');
                    code.push(' ');
                    index += 2;
                    continue;
                }

                if !in_string && let Some((delimiter_len, hashes)) = raw_string_start(&chars, index)
                {
                    for _ in 0..delimiter_len {
                        code.push(' ');
                    }
                    index += delimiter_len;
                    raw_string_hashes = Some(hashes);
                    continue;
                }

                if ch == '"' && !escaped {
                    in_string = !in_string;
                    code.push(' ');
                } else if in_string {
                    code.push(' ');
                } else {
                    code.push(ch);
                }

                escaped = ch == '\\' && !escaped;
                if ch != '\\' {
                    escaped = false;
                }

                index += 1;
            }

            lines.push(code);
        }

        lines
    }

    fn raw_string_start(chars: &[char], index: usize) -> Option<(usize, usize)> {
        let raw_prefix_index = if chars.get(index) == Some(&'r') {
            index
        } else if chars.get(index) == Some(&'b') && chars.get(index + 1) == Some(&'r') {
            index + 1
        } else {
            return None;
        };

        let mut cursor = raw_prefix_index + 1;
        while chars.get(cursor) == Some(&'#') {
            cursor += 1;
        }

        if chars.get(cursor) == Some(&'"') {
            Some((cursor - index + 1, cursor - raw_prefix_index - 1))
        } else {
            None
        }
    }

    fn raw_string_terminator_matches(chars: &[char], quote_index: usize, hashes: usize) -> bool {
        (0..hashes).all(|offset| chars.get(quote_index + 1 + offset) == Some(&'#'))
    }

    fn code_tokens(code: &str) -> impl Iterator<Item = &str> {
        code.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .filter(|token| !token.is_empty())
    }

    fn assert_sources_compile_only_from_scanned_tree(source_root: &Path) {
        let mut findings = Vec::new();

        for source_path in rust_sources(source_root) {
            let source = fs::read_to_string(&source_path).expect("source file is readable");
            findings.extend(source_retargeting_findings(&source_path, &source));
        }

        assert!(
            findings.is_empty(),
            "ratchet-runtime-ffi may not retarget compiled Rust outside scanned src files:\n{}",
            findings.join("\n")
        );
    }

    fn source_retargeting_findings(source_path: &Path, source: &str) -> Vec<String> {
        let mut findings = Vec::new();
        let mut inside_attribute = false;

        for (line_number, code) in code_lines_without_comments_or_ordinary_strings(source)
            .iter()
            .enumerate()
        {
            let tokens = code_tokens(code).collect::<Vec<_>>();
            let trimmed = code.trim_start();
            if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
                inside_attribute = true;
            }

            if tokens.contains(&INCLUDE_TOKEN) {
                findings.push(format!(
                    "{}:{} contains `{INCLUDE_MACRO_LABEL}`",
                    source_path.display(),
                    line_number + 1
                ));
            }

            if inside_attribute && tokens.contains(&PATH_TOKEN) {
                findings.push(format!(
                    "{}:{} contains `{PATH_ATTRIBUTE_LABEL}`",
                    source_path.display(),
                    line_number + 1
                ));
            }

            if inside_attribute && code.contains(']') {
                inside_attribute = false;
            }
        }

        findings
    }

    const INCLUDE_TOKEN: &str = concat!("incl", "ude");
    const INCLUDE_MACRO_LABEL: &str = concat!("incl", "ude!");
    const PATH_TOKEN: &str = concat!("pa", "th");
    const PATH_ATTRIBUTE_LABEL: &str = concat!("#[", "pa", "th]");

    fn assert_reviewed_unsafe_boundary_counts(source_root: &Path) {
        let env = fs::read_to_string(source_root.join("env.rs"))
            .expect("environment FFI source file is readable");
        let force =
            fs::read_to_string(source_root.join("force.rs")).expect("force FFI source is readable");

        assert_eq!(
            trimmed_line_occurrences(&env, ENV_GET_FN_TYPE_LINE),
            1,
            "env native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, ENV_GET_EXPORT_ATTR_LINE),
            1,
            "env native wrapper export attribute must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, ENV_GET_FN_LINE),
            1,
            "aos_env_get native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, ENV_GET_DECODER_CALL_LINE),
            1,
            "aos_env_get wrapper call to the decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, ENV_FRAME_DECODER_LINE),
            1,
            "raw EvalFrame pointer decoder must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, ENV_FRAME_CAST_LINE),
            1,
            "raw EvalFrame pointer cast must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, DIRECT_TEST_CALL_LINE),
            1,
            "direct test call of aos_env_get must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&env, BINDING_TEST_CALL_LINE),
            1,
            "metadata function-pointer test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_FN_TYPE_LINE),
            1,
            "force native function-pointer type must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_EXPORT_ATTR_LINE),
            1,
            "force native wrapper export attribute must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_FN_LINE),
            1,
            "aos_force native wrapper must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, DIRECT_FORCE_TEST_CALL_LINE),
            1,
            "direct test call of aos_force must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_BINDING_TEST_CALL_LINE),
            1,
            "force metadata function-pointer test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_MALFORMED_VALUE_TRANSMUTE_LINE),
            1,
            "malformed Value construction test must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_MALFORMED_ABORT_TEST_CALL_LINE),
            1,
            "malformed payload abort test call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&force, FORCE_THUNK_ABORT_TEST_CALL_LINE),
            1,
            "thunk abort test call must stay singly reviewed"
        );
    }

    fn assert_reviewed_safety_comments(source_root: &Path) {
        let env = fs::read_to_string(source_root.join("env.rs"))
            .expect("environment FFI source file is readable");
        let force =
            fs::read_to_string(source_root.join("force.rs")).expect("force FFI source is readable");
        let lines = env.lines().collect::<Vec<_>>();
        let force_lines = force.lines().collect::<Vec<_>>();

        assert_has_safety_comment_before(
            &lines,
            ENV_GET_DECODER_CALL_LINE,
            "aos_env_get decoder call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &lines,
            ENV_FRAME_CAST_LINE,
            "raw EvalFrame pointer cast must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &lines,
            DIRECT_TEST_CALL_LINE,
            "direct wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &lines,
            BINDING_TEST_CALL_LINE,
            "metadata function-pointer test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            DIRECT_FORCE_TEST_CALL_LINE,
            "direct force wrapper test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_BINDING_TEST_CALL_LINE,
            "force metadata function-pointer test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_MALFORMED_VALUE_TRANSMUTE_LINE,
            "malformed Value construction test must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_MALFORMED_ABORT_TEST_CALL_LINE,
            "malformed payload abort test call must keep a SAFETY comment",
        );
        assert_has_safety_comment_before(
            &force_lines,
            FORCE_THUNK_ABORT_TEST_CALL_LINE,
            "thunk abort test call must keep a SAFETY comment",
        );
    }

    fn assert_public_unsafe_docs(source_root: &Path) {
        let env = fs::read_to_string(source_root.join("env.rs"))
            .expect("environment FFI source file is readable");
        let force =
            fs::read_to_string(source_root.join("force.rs")).expect("force FFI source is readable");
        let lines = env.lines().collect::<Vec<_>>();
        let force_lines = force.lines().collect::<Vec<_>>();

        assert_has_safety_doc_before(
            &lines,
            ENV_GET_FN_TYPE_LINE,
            "public native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &lines,
            ENV_GET_FN_LINE,
            "public native wrapper must document # Safety",
        );
        assert_has_safety_doc_before(
            &force_lines,
            FORCE_FN_TYPE_LINE,
            "public force native function-pointer type must document # Safety",
        );
        assert_has_safety_doc_before(
            &force_lines,
            FORCE_FN_LINE,
            "public force native wrapper must document # Safety",
        );
    }

    fn assert_has_safety_comment_before(lines: &[&str], expected: &str, message: &str) {
        let index = unique_line_index(lines, expected);
        let start = index.saturating_sub(3);
        assert!(
            lines[start..index].iter().any(|line| line
                .trim_start()
                .starts_with(RUNTIME_FFI_SAFETY_COMMENT_PREFIX)),
            "{message}"
        );
    }

    fn assert_has_safety_doc_before(lines: &[&str], expected: &str, message: &str) {
        let index = unique_line_index(lines, expected);
        let start = index.saturating_sub(10);
        assert!(
            lines[start..index]
                .iter()
                .any(|line| line.trim_start() == "/// # Safety"),
            "{message}"
        );
    }

    fn unique_line_index(lines: &[&str], expected: &str) -> usize {
        let matches = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| (line.trim_start() == expected).then_some(index))
            .collect::<Vec<_>>();

        assert_eq!(
            matches.len(),
            1,
            "expected exactly one reviewed line `{expected}`, found {}",
            matches.len()
        );
        matches[0]
    }

    fn trimmed_line_occurrences(source: &str, expected: &str) -> usize {
        source
            .lines()
            .filter(|line| line.trim_start() == expected)
            .count()
    }
}
