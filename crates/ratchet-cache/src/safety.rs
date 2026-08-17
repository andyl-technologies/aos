//! Unsafe-discipline manifest for cache storage primitives.
//!
//! `ratchet-cache` is intentionally unsafe-capable because read-only memory
//! mappings and Unix advisory locks cross interfaces whose invariants Rust
//! cannot verify. This module records the allowed operation classes and tests
//! that every unsafe operation remains confined to the reviewed source files.

/// Crate-level lint required for the cache unsafe boundary.
pub const CACHE_UNSAFE_CRATE_LINT: &str = "#![deny(unsafe_op_in_unsafe_fn)]";

/// Comment prefix required beside each cache unsafe operation.
pub const CACHE_SAFETY_COMMENT_PREFIX: &str = "// SAFETY:";

/// Cache operations that remain innately unsafe after validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheInnateUnsafeOperation {
    /// Creates and exposes a read-only mapping of caller-frozen file bytes.
    ReadOnlyFileMapping,
    /// Acquires or releases an advisory lock through a raw file descriptor.
    AdvisoryFileLock,
    /// Implements the lease proof that keeps mapped blob-pack bytes immutable.
    ImmutableBlobPackLease,
}

/// Standing controls required for unsafe cache storage code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheUnsafeDiscipline {
    crate_lint: &'static str,
    safety_comment_prefix: &'static str,
    second_reviewer_required: bool,
    sanitizer_ci_required: bool,
    innate_unsafe_operations: &'static [CacheInnateUnsafeOperation],
}

impl CacheUnsafeDiscipline {
    /// Creates the standing cache unsafe-discipline manifest.
    pub const fn new(
        crate_lint: &'static str,
        safety_comment_prefix: &'static str,
        second_reviewer_required: bool,
        sanitizer_ci_required: bool,
        innate_unsafe_operations: &'static [CacheInnateUnsafeOperation],
    ) -> Self {
        Self {
            crate_lint,
            safety_comment_prefix,
            second_reviewer_required,
            sanitizer_ci_required,
            innate_unsafe_operations,
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

    /// Returns whether a second reviewer is required for new unsafe operations.
    pub const fn second_reviewer_required(self) -> bool {
        self.second_reviewer_required
    }

    /// Returns whether sanitizer CI must cover unsafe cache paths.
    pub const fn sanitizer_ci_required(self) -> bool {
        self.sanitizer_ci_required
    }

    /// Returns the unsafe operation classes isolated by this crate.
    pub const fn innate_unsafe_operations(self) -> &'static [CacheInnateUnsafeOperation] {
        self.innate_unsafe_operations
    }
}

const CACHE_INNATE_UNSAFE_OPERATIONS: &[CacheInnateUnsafeOperation] = &[
    CacheInnateUnsafeOperation::ReadOnlyFileMapping,
    CacheInnateUnsafeOperation::AdvisoryFileLock,
    CacheInnateUnsafeOperation::ImmutableBlobPackLease,
];

/// Returns the standing unsafe-discipline manifest for `ratchet-cache`.
pub const fn cache_unsafe_discipline() -> CacheUnsafeDiscipline {
    CacheUnsafeDiscipline::new(
        CACHE_UNSAFE_CRATE_LINT,
        CACHE_SAFETY_COMMENT_PREFIX,
        true,
        true,
        CACHE_INNATE_UNSAFE_OPERATIONS,
    )
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::*;

    const REVIEWED_UNSAFE_COUNTS: &[(&str, usize)] = &[
        ("store.rs", 7),
        ("file_lock.rs", 2),
        ("blob_pack/locking.rs", 2),
        ("blob_pack/mapped.rs", 5),
        ("blob_pack/tests.rs", 3),
        ("blob_pack/tests/mapped.rs", 1),
    ];

    #[test]
    fn discipline_manifest_names_required_controls() {
        let discipline = cache_unsafe_discipline();

        assert_eq!(discipline.crate_lint(), CACHE_UNSAFE_CRATE_LINT);
        assert_eq!(
            discipline.safety_comment_prefix(),
            CACHE_SAFETY_COMMENT_PREFIX
        );
        assert!(discipline.second_reviewer_required());
        assert!(discipline.sanitizer_ci_required());
        assert_eq!(
            discipline.innate_unsafe_operations(),
            CACHE_INNATE_UNSAFE_OPERATIONS
        );
    }

    #[test]
    fn crate_root_declares_unsafe_operation_lint() {
        let crate_root = include_str!("lib.rs");

        assert!(crate_root.contains(CACHE_UNSAFE_CRATE_LINT));
    }

    #[test]
    fn current_cache_sources_keep_unsafe_operations_allowlisted() {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut actual = Vec::new();

        collect_unsafe_counts(&source_root, &source_root, &mut actual);
        actual.sort_unstable_by(|left, right| left.0.cmp(&right.0));

        let mut expected: Vec<_> = REVIEWED_UNSAFE_COUNTS
            .iter()
            .map(|(path, count)| ((*path).to_owned(), *count))
            .collect();
        expected.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(actual, expected, "cache unsafe inventory changed");

        for (relative_path, _) in REVIEWED_UNSAFE_COUNTS {
            let source = fs::read_to_string(source_root.join(relative_path))
                .expect("reviewed cache source is readable");
            assert_local_safety_contracts(relative_path, &source);
        }
    }

    fn collect_unsafe_counts(root: &Path, path: &Path, counts: &mut Vec<(String, usize)>) {
        if path.is_dir() {
            for entry in fs::read_dir(path).expect("cache source directory is readable") {
                collect_unsafe_counts(
                    root,
                    &entry.expect("cache source entry is readable").path(),
                    counts,
                );
            }
            return;
        }

        if path.extension().is_none()
            || path.extension().is_some_and(|extension| extension != "rs")
            || path.file_name().is_some_and(|name| name == "safety.rs")
        {
            return;
        }

        let source = fs::read_to_string(path).expect("cache source file is readable");
        let count = source
            .lines()
            .map(code_without_line_comments_or_ordinary_strings)
            .map(|line| {
                line.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                    .filter(|token| *token == "unsafe")
                    .count()
            })
            .sum();
        if count != 0 {
            let relative = path
                .strip_prefix(root)
                .expect("cache source is below source root")
                .to_string_lossy()
                .replace('\\', "/");
            counts.push((relative, count));
        }
    }

    fn assert_local_safety_contracts(relative_path: &str, source: &str) {
        let lines: Vec<_> = source.lines().collect();
        for (line_index, line) in lines.iter().enumerate() {
            let code = code_without_line_comments_or_ordinary_strings(line);
            let trimmed = code.trim_start();
            if !code
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .any(|token| token == "unsafe")
            {
                continue;
            }

            if trimmed.starts_with("pub unsafe fn") || trimmed.starts_with("pub unsafe trait") {
                assert_nearby_contract(relative_path, &lines, line_index, "# Safety", 40);
            } else if trimmed.starts_with("unsafe impl") {
                assert_nearby_contract(relative_path, &lines, line_index, "SAFETY:", 8);
            } else {
                assert_nearby_contract(relative_path, &lines, line_index, "SAFETY:", 8);
            }
        }
    }

    fn assert_nearby_contract(
        relative_path: &str,
        lines: &[&str],
        line_index: usize,
        contract: &str,
        radius: usize,
    ) {
        let start = line_index.saturating_sub(radius);
        let end = (line_index + radius + 1).min(lines.len());
        assert!(
            lines[start..end].iter().any(|line| line.contains(contract)),
            "{relative_path}:{} lacks nearby `{contract}` contract",
            line_index + 1
        );
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
}
