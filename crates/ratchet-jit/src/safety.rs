//! Unsafe-discipline manifest for future JIT code.
//!
//! `ratchet-jit` is intentionally an unsafe-capable crate because executable
//! machine-code entry requires raw function-pointer calls that Rust cannot
//! validate. This module records the standing review controls for that future
//! boundary while the current crate contains mostly safe metadata, inert
//! native-entry type aliases, bounded native thunk-call boundaries, and policy
//! adapters.

/// Crate-level lint required for the JIT unsafe boundary.
pub const JIT_UNSAFE_CRATE_LINT: &str = "#![deny(unsafe_op_in_unsafe_fn)]";

/// Comment prefix required beside each future unsafe operation.
pub const JIT_SAFETY_COMMENT_PREFIX: &str = "// SAFETY:";

/// The JIT operation that remains innately unsafe even after validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitInnateUnsafeOperation {
    /// Transmutes a raw code pointer into the frozen runtime-call ABI and calls it.
    CodePointerTransmuteCall,
}

/// Standing controls required before unsafe JIT code can land.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JitUnsafeDiscipline {
    crate_lint: &'static str,
    safety_comment_prefix: &'static str,
    second_reviewer_required: bool,
    sanitizer_ci_required: bool,
    innate_unsafe_operation: JitInnateUnsafeOperation,
}

impl JitUnsafeDiscipline {
    /// Creates the standing JIT unsafe-discipline manifest.
    pub const fn new(
        crate_lint: &'static str,
        safety_comment_prefix: &'static str,
        second_reviewer_required: bool,
        sanitizer_ci_required: bool,
        innate_unsafe_operation: JitInnateUnsafeOperation,
    ) -> Self {
        Self {
            crate_lint,
            safety_comment_prefix,
            second_reviewer_required,
            sanitizer_ci_required,
            innate_unsafe_operation,
        }
    }

    /// Returns the crate-level lint required by the unsafe fence.
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

    /// Returns whether sanitizer CI must cover unsafe JIT paths once they exist.
    pub const fn sanitizer_ci_required(self) -> bool {
        self.sanitizer_ci_required
    }

    /// Returns the innate unsafe operation that the JIT boundary must isolate.
    pub const fn innate_unsafe_operation(self) -> JitInnateUnsafeOperation {
        self.innate_unsafe_operation
    }
}

/// Returns the standing unsafe-discipline manifest for `ratchet-jit`.
pub const fn jit_unsafe_discipline() -> JitUnsafeDiscipline {
    JitUnsafeDiscipline::new(
        JIT_UNSAFE_CRATE_LINT,
        JIT_SAFETY_COMMENT_PREFIX,
        true,
        true,
        JitInnateUnsafeOperation::CodePointerTransmuteCall,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use super::*;

    #[test]
    fn discipline_manifest_names_required_controls() {
        let discipline = jit_unsafe_discipline();

        assert_eq!(discipline.crate_lint(), JIT_UNSAFE_CRATE_LINT);
        assert_eq!(
            discipline.safety_comment_prefix(),
            JIT_SAFETY_COMMENT_PREFIX
        );
        assert!(discipline.second_reviewer_required());
        assert!(discipline.sanitizer_ci_required());
        assert_eq!(
            discipline.innate_unsafe_operation(),
            JitInnateUnsafeOperation::CodePointerTransmuteCall
        );
    }

    #[test]
    fn crate_root_declares_unsafe_operation_lint() {
        let crate_root = include_str!("lib.rs");

        assert!(crate_root.contains(JIT_UNSAFE_CRATE_LINT));
    }

    #[test]
    fn current_jit_sources_keep_unsafe_boundaries_allowlisted() {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut findings = Vec::new();

        for source_path in rust_sources(&source_root) {
            let source = fs::read_to_string(&source_path).expect("source file is readable");
            for (line_number, line) in source.lines().enumerate() {
                let code = code_without_line_comments_or_ordinary_strings(line);
                for token in code_tokens(&code) {
                    if is_allowed_native_entry_alias_token(&source_path, &code, token) {
                        continue;
                    }
                    if is_allowed_native_thunk_call_token(&source_path, &code, token) {
                        continue;
                    }
                    if is_allowed_native_lambda_call_token(&source_path, &code, token) {
                        continue;
                    }
                    if is_allowed_mixed_superblock_token(&source_path, &code, token) {
                        continue;
                    }

                    if matches!(token, "unsafe" | "extern" | "transmute") {
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
            "ratchet-jit contains unreviewed unsafe-boundary tokens:\n{}",
            findings.join("\n")
        );

        assert_reviewed_unsafe_boundary_counts(&source_root);
    }

    fn is_allowed_native_entry_alias_token(source_path: &Path, code: &str, token: &str) -> bool {
        if !matches!(token, "unsafe" | "extern") {
            return false;
        }

        if source_path.file_name().and_then(|name| name.to_str()) != Some("abi.rs") {
            return false;
        }

        let trimmed = code.trim_start();
        trimmed.starts_with("pub type JitThunkFn = unsafe extern")
            || (trimmed.starts_with("unsafe extern")
                && trimmed.contains("JitRuntimeContextPtr")
                && trimmed.ends_with("-> u64;"))
            || trimmed.starts_with("pub type JitLambdaFn = unsafe extern")
            || trimmed.starts_with("pub type JitLambdaArgvFn = unsafe extern")
            || trimmed.starts_with("pub type JitFoldStepI64AccFn = unsafe extern")
    }

    fn is_allowed_mixed_superblock_token(source_path: &Path, code: &str, token: &str) -> bool {
        if source_path.file_name().and_then(|name| name.to_str()) != Some("mixed_superblock.rs") {
            return false;
        }

        let trimmed = code.trim_start();
        match token {
            "unsafe" | "extern"
                if trimmed == "type Entry = unsafe extern \"C\" fn(*mut RawActivation) -> u32;" =>
            {
                true
            }
            "unsafe"
                if trimmed
                    == "let entry = unsafe { mem::transmute::<*mut u8, Entry>(self.code.as_ptr()) };" =>
            {
                true
            }
            "transmute" => {
                trimmed
                    == "let entry = unsafe { mem::transmute::<*mut u8, Entry>(self.code.as_ptr()) };"
            }
            "unsafe" if trimmed == "let status = unsafe { entry(&mut activation.raw) };" => true,
            _ => false,
        }
    }

    fn is_allowed_native_thunk_call_token(source_path: &Path, code: &str, token: &str) -> bool {
        let file_name = source_path.file_name().and_then(|name| name.to_str());
        if file_name == Some("candidate_b.rs") {
            let trimmed = code.trim_start();
            return match token {
                "unsafe" => trimmed.starts_with(
                    "pub unsafe fn jit_cranelift_call_context_finalized_candidate_b_thunk_entry(",
                ) || trimmed
                    == "let entry = unsafe { mem::transmute::<*mut u8, JitCandidateBThunkFn>(code_ptr.as_ptr()) };"
                    || trimmed == "let word = unsafe { entry(rt, env) };"
                    || trimmed == "let word = unsafe {"
                    || trimmed == "let active_error = unsafe {"
                    || trimmed == "let candidate_error = unsafe {",
                "transmute" => {
                    trimmed
                        == "let entry = unsafe { mem::transmute::<*mut u8, JitCandidateBThunkFn>(code_ptr.as_ptr()) };"
                }
                _ => false,
            };
        }
        if file_name == Some("candidate_c.rs") {
            let trimmed = code.trim_start();
            return match token {
                "unsafe" => trimmed.starts_with(
                    "pub unsafe fn jit_cranelift_call_context_finalized_candidate_c_thunk_entry(",
                ) || trimmed
                    == "let entry = unsafe { mem::transmute::<*mut u8, JitCandidateCThunkFn>(code_ptr.as_ptr()) };"
                    || trimmed == "let word = unsafe { entry(rt, env) };"
                    || trimmed == "let word = unsafe {"
                    || trimmed == "let active_error = unsafe {"
                    || trimmed == "let candidate_error = unsafe {",
                "transmute" => {
                    trimmed
                        == "let entry = unsafe { mem::transmute::<*mut u8, JitCandidateCThunkFn>(code_ptr.as_ptr()) };"
                }
                _ => false,
            };
        }
        // The former single `cranelift.rs` native thunk-call boundary was split
        // (§2 cap) across three `cranelift/` submodules; each reviewed line is
        // pinned to exactly the submodule that now owns it.
        if file_name == Some("context.rs") {
            let trimmed = code.trim_start();
            return match token {
                "unsafe" => {
                    trimmed.starts_with(
                        "pub unsafe fn jit_cranelift_call_context_finalized_thunk_entry(",
                    ) || trimmed == "let context_dispatched = unsafe { thunk_entry(rt, env) };"
                }
                _ => false,
            };
        }
        if file_name == Some("preflight_fns.rs") {
            let trimmed = code.trim_start();
            return match token {
                "unsafe" => {
                    trimmed.starts_with(
                        "pub unsafe fn jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(",
                    ) || trimmed.starts_with(
                        "pub unsafe fn jit_cranelift_call_finalized_thunk_entry(",
                    ) || trimmed
                        == "let value = unsafe { thunk_entry(ptr::null_mut(), ptr::null_mut()) };"
                        || trimmed == "let value = unsafe { thunk_entry(rt, env) };"
                        || trimmed == "let dispatched = unsafe { thunk_entry(rt, env) };"
                }
                _ => false,
            };
        }
        if file_name == Some("tier1.rs") {
            let trimmed = code.trim_start();
            return match token {
                "unsafe" => {
                    trimmed.starts_with(
                        "pub unsafe fn jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(",
                    ) || trimmed.starts_with(
                        "pub unsafe fn jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(",
                    ) || trimmed
                        == "let promotion_gated_registered_native_thunk_invocation = unsafe {"
                        || trimmed
                            == "let entry = unsafe { mem::transmute::<*mut u8, JitThunkFn>(code_ptr.as_ptr()) };"
                }
                "transmute" => {
                    trimmed
                        == "let entry = unsafe { mem::transmute::<*mut u8, JitThunkFn>(code_ptr.as_ptr()) };"
                }
                _ => false,
            };
        }
        false
    }

    /// The tier-2 lambda-entry boundary lives in `cranelift/tier2.rs`: one
    /// dispatch entrypoint, one native call, and one code-pointer transmute,
    /// each pinned to a single reviewed line. The decoded-`i64`-accumulator
    /// fold-step entry adds one further reviewed triple of the same shape.
    fn is_allowed_native_lambda_call_token(source_path: &Path, code: &str, token: &str) -> bool {
        if source_path.file_name().and_then(|name| name.to_str()) != Some("tier2.rs") {
            return false;
        }

        let trimmed = code.trim_start();
        match token {
            "unsafe" => trimmed
                .starts_with("pub unsafe fn jit_cranelift_call_context_finalized_lambda_entry(")
                || trimmed.starts_with(
                    "pub unsafe fn jit_cranelift_call_context_finalized_lambda_argv_entry(",
                )
                || trimmed.starts_with(
                    "pub unsafe fn jit_cranelift_call_context_finalized_fold_step_i64acc_entry(",
                )
                || trimmed == "let lambda_dispatched = unsafe { lambda_entry(rt, env, argument) };"
                || trimmed
                    == "let chain_dispatched = unsafe { argv_entry(rt, env, argv.as_ptr()) };"
                || trimmed == "let acc_next = unsafe { fold_step_entry(rt, env, acc, elem) };"
                || trimmed
                    == "let entry = unsafe { mem::transmute::<*mut u8, JitLambdaFn>(code_ptr.as_ptr()) };"
                || trimmed
                    == "let entry = unsafe { mem::transmute::<*mut u8, JitLambdaArgvFn>(code_ptr.as_ptr()) };"
                || trimmed
                    == "let entry = unsafe { mem::transmute::<*mut u8, JitFoldStepI64AccFn>(code_ptr.as_ptr()) };",
            "transmute" => {
                trimmed
                    == "let entry = unsafe { mem::transmute::<*mut u8, JitLambdaFn>(code_ptr.as_ptr()) };"
                    || trimmed
                        == "let entry = unsafe { mem::transmute::<*mut u8, JitLambdaArgvFn>(code_ptr.as_ptr()) };"
                    || trimmed
                        == "let entry = unsafe { mem::transmute::<*mut u8, JitFoldStepI64AccFn>(code_ptr.as_ptr()) };"
            }
            _ => false,
        }
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

    fn code_without_line_comments_or_ordinary_strings(line: &str) -> String {
        let mut code = String::with_capacity(line.len());
        let mut chars = line.chars().peekable();
        let mut in_string = false;
        let mut escaped = false;

        while let Some(ch) = chars.next() {
            if !in_string && ch == '/' && chars.peek() == Some(&'/') {
                break;
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
        }

        code
    }

    fn code_tokens(code: &str) -> impl Iterator<Item = &str> {
        code.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .filter(|token| !token.is_empty())
    }

    fn assert_reviewed_unsafe_boundary_counts(source_root: &Path) {
        // The former `cranelift.rs` native thunk-call boundary was split (§2 cap)
        // across three `cranelift/` submodules; each reviewed line is now pinned to
        // the submodule that owns it. The total pin count is preserved.
        let context = fs::read_to_string(source_root.join("cranelift").join("context.rs"))
            .expect("Cranelift context source file is readable");
        let preflight_fns =
            fs::read_to_string(source_root.join("cranelift").join("preflight_fns.rs"))
                .expect("Cranelift preflight-fns source file is readable");
        let tier1 = fs::read_to_string(source_root.join("cranelift").join("tier1.rs"))
            .expect("Cranelift tier1 source file is readable");
        let mixed_superblock =
            fs::read_to_string(source_root.join("cranelift").join("mixed_superblock.rs"))
                .expect("mixed-superblock Cranelift source file is readable");

        assert_eq!(
            trimmed_line_occurrences(
                &mixed_superblock,
                "type Entry = unsafe extern \"C\" fn(*mut RawActivation) -> u32;",
            ),
            1,
            "mixed-superblock native entry signature must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &mixed_superblock,
                "let entry = unsafe { mem::transmute::<*mut u8, Entry>(self.code.as_ptr()) };",
            ),
            1,
            "mixed-superblock code-pointer transmute must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &mixed_superblock,
                "let status = unsafe { entry(&mut activation.raw) };",
            ),
            1,
            "mixed-superblock native call must stay singly reviewed"
        );

        assert_eq!(
            trimmed_line_occurrences(
                &preflight_fns,
                "pub unsafe fn jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(",
            ),
            1,
            "registered native thunk-call entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier1,
                "pub unsafe fn jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(",
            ),
            1,
            "promotion-gated registered native thunk-call entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier1,
                "pub unsafe fn jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(",
            ),
            1,
            "full-IR promotion-gated registered native thunk-call entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &preflight_fns,
                "let value = unsafe { thunk_entry(ptr::null_mut(), ptr::null_mut()) };",
            ),
            1,
            "no-import native thunk call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &preflight_fns,
                "let value = unsafe { thunk_entry(rt, env) };"
            ),
            1,
            "registered native thunk call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &preflight_fns,
                "pub unsafe fn jit_cranelift_call_finalized_thunk_entry(",
            ),
            1,
            "finalized thunk-entry dispatch entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &preflight_fns,
                "let dispatched = unsafe { thunk_entry(rt, env) };",
            ),
            1,
            "finalized thunk-entry native call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &context,
                "pub unsafe fn jit_cranelift_call_context_finalized_thunk_entry(",
            ),
            1,
            "shared-context finalized thunk-entry dispatch entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &context,
                "let context_dispatched = unsafe { thunk_entry(rt, env) };",
            ),
            1,
            "shared-context finalized thunk-entry native call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier1,
                "let promotion_gated_registered_native_thunk_invocation = unsafe {",
            ),
            2,
            "promotion-gated registered native thunk calls must stay explicitly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier1,
                "let entry = unsafe { mem::transmute::<*mut u8, JitThunkFn>(code_ptr.as_ptr()) };",
            ),
            1,
            "native thunk code-pointer transmute must stay singly reviewed"
        );

        let candidate_b = fs::read_to_string(source_root.join("cranelift").join("candidate_b.rs"))
            .expect("Candidate-B Cranelift source file is readable");
        assert_eq!(
            trimmed_line_occurrences(
                &candidate_b,
                "pub unsafe fn jit_cranelift_call_context_finalized_candidate_b_thunk_entry(",
            ),
            1,
            "Candidate-B thunk dispatch entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&candidate_b, "let word = unsafe { entry(rt, env) };"),
            1,
            "Candidate-B native thunk call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &candidate_b,
                "let entry = unsafe { mem::transmute::<*mut u8, JitCandidateBThunkFn>(code_ptr.as_ptr()) };",
            ),
            1,
            "Candidate-B code-pointer transmute must stay singly reviewed"
        );

        let candidate_c = fs::read_to_string(source_root.join("cranelift").join("candidate_c.rs"))
            .expect("Candidate-C Cranelift source file is readable");
        assert_eq!(
            trimmed_line_occurrences(
                &candidate_c,
                "pub unsafe fn jit_cranelift_call_context_finalized_candidate_c_thunk_entry(",
            ),
            1,
            "Candidate-C thunk dispatch entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(&candidate_c, "let word = unsafe { entry(rt, env) };"),
            1,
            "Candidate-C native thunk call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &candidate_c,
                "let entry = unsafe { mem::transmute::<*mut u8, JitCandidateCThunkFn>(code_ptr.as_ptr()) };",
            ),
            1,
            "Candidate-C code-pointer transmute must stay singly reviewed"
        );

        let tier2 = fs::read_to_string(source_root.join("cranelift").join("tier2.rs"))
            .expect("tier-2 Cranelift source file is readable");
        assert_eq!(
            trimmed_line_occurrences(
                &tier2,
                "pub unsafe fn jit_cranelift_call_context_finalized_lambda_entry(",
            ),
            1,
            "tier-2 lambda-entry dispatch entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier2,
                "let lambda_dispatched = unsafe { lambda_entry(rt, env, argument) };",
            ),
            1,
            "tier-2 lambda-entry native call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier2,
                "let entry = unsafe { mem::transmute::<*mut u8, JitLambdaFn>(code_ptr.as_ptr()) };",
            ),
            1,
            "tier-2 lambda code-pointer transmute must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier2,
                "pub unsafe fn jit_cranelift_call_context_finalized_lambda_argv_entry(",
            ),
            1,
            "tier-2 chain-entry dispatch entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier2,
                "let chain_dispatched = unsafe { argv_entry(rt, env, argv.as_ptr()) };",
            ),
            1,
            "tier-2 chain-entry native call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier2,
                "let entry = unsafe { mem::transmute::<*mut u8, JitLambdaArgvFn>(code_ptr.as_ptr()) };",
            ),
            1,
            "tier-2 chain code-pointer transmute must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier2,
                "pub unsafe fn jit_cranelift_call_context_finalized_fold_step_i64acc_entry(",
            ),
            1,
            "tier-2 fold-step dispatch entrypoint must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier2,
                "let acc_next = unsafe { fold_step_entry(rt, env, acc, elem) };",
            ),
            1,
            "tier-2 fold-step native call must stay singly reviewed"
        );
        assert_eq!(
            trimmed_line_occurrences(
                &tier2,
                "let entry = unsafe { mem::transmute::<*mut u8, JitFoldStepI64AccFn>(code_ptr.as_ptr()) };",
            ),
            1,
            "tier-2 fold-step code-pointer transmute must stay singly reviewed"
        );
    }

    fn trimmed_line_occurrences(source: &str, expected: &str) -> usize {
        source
            .lines()
            .filter(|line| line.trim_start() == expected)
            .count()
    }
}
