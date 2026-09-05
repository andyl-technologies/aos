//! Tests for validation of transparency statements and their bound package metadata.

use super::ensure_safe_package_provenance_statement_path;

#[test]
fn package_provenance_statement_path_rejects_git_revspec_punctuation() {
    assert!(ensure_safe_package_provenance_statement_path("0:foo.intoto.jsonl").is_err());
    assert!(
        ensure_safe_package_provenance_statement_path(
            "provenance/w/web/x86_64-linux/bad:path.intoto.jsonl"
        )
        .is_err()
    );
    assert!(
        ensure_safe_package_provenance_statement_path(
            "provenance/w/web/x86_64-linux/good.intoto.jsonl"
        )
        .is_ok()
    );
}
