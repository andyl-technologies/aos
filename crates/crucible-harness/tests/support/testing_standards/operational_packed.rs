//! Binds Packed lock polling and single-shot idempotent publication observations.
//!
//! These source contracts retain the existing original account and callback.
//! They classify exact operations without granting waits or test reruns.

use super::{Companion, Contract};

const LOCK_CHECK: &str = r#"pub(super) fn check(
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    original
        .verify_live()
        .map_err(|error| batch::admission_under(original, error))?;
    boundary()?;
    original
        .verify_live()
        .map_err(|error| batch::admission_under(original, error))
}"#;

const REOPENED_PUBLICATION: &str = r#"let retry = restarted
    .put_many_if_absent_with_boundary(&fixture.original, &[(id, source)], &mut || Ok(()))
    .unwrap();"#;

const RECOVERED_PUBLICATION: &str = r#"let retry = fixture
    .backend
    .put_many_if_absent_with_boundary(&fixture.original, &[(id, input)], &mut || Ok(()))
    .unwrap();"#;

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-cas",
        target: "src/content_store/packed/checked_io",
        required: &[
            r#"pub(super) fn lock(
                backend: &PackedBlobBackend,
                name: &str,
                shared: bool,
                original: &DecodeBudget,
                boundary: &mut dyn FnMut() -> Result<(), StoreError>,
            ) -> Result<OwnedFile, StoreError> {
                lock_file(backend, name, shared, false, original, boundary)
            }"#,
            r#"pub(super) fn create_lock(
                backend: &PackedBlobBackend,
                name: &str,
                shared: bool,
                original: &DecodeBudget,
                boundary: &mut dyn FnMut() -> Result<(), StoreError>,
            ) -> Result<OwnedFile, StoreError> {
                lock_file(backend, name, shared, true, original, boundary)
            }"#,
            r#"fn lock_file(
                backend: &PackedBlobBackend,
                name: &str,
                shared: bool,
                create: bool,
                original: &DecodeBudget,
                boundary: &mut dyn FnMut() -> Result<(), StoreError>,
            ) -> Result<OwnedFile, StoreError>"#,
            "let path = path(&backend.admin, name, original)?;",
            r#"let file = open_file(
                path.as_path(),
                if create { OFlags::RDWR | OFlags::CREATE } else { OFlags::RDWR },
                "open-packed-checked-lock", original, boundary,
            )?;
            length(&file, original, boundary)?;"#,
            r#"loop {
                checked_reader::check(original, boundary)?;
                match flock(file.file(), operation) {"#,
            "FlockOperation::NonBlockingLockShared",
            "FlockOperation::NonBlockingLockExclusive",
            "Ok(()) => break,",
            "Err(rustix::io::Errno::INTR) => continue,",
            "Err(rustix::io::Errno::WOULDBLOCK) => {",
            r#"return Err(StoreError::StreamIo {
                operation: "lock-packed-checked-backend",
                source: source.into(),
            });"#,
            "} checked_reader::check(original, boundary)?; Ok(file)",
        ],
        expressions: &[(
            "std::thread::sleep(std::time::Duration::from_millis(1));",
            1,
        )],
        companions: &[Companion {
            path: "crates/crucible-cas/src/content_store/checked_reader.rs",
            required: &[LOCK_CHECK],
            counts: &[],
        }],
    },
    Contract {
        package: "crucible-cas",
        target: "src/content_store/packed/checked/tests",
        required: &[
            "fn checked_publication_restarts_retries_and_keeps_exact_v1_index_bytes()",
            "ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes)",
            r#"let restarted = PackedBlobBackend::open(
                "checked-packed", fixture._root.path(), MIN_TARGET_PACK_BYTES,
            ).unwrap();"#,
            "let generation = restarted.load_index().unwrap().generation;",
            "assert_eq!(restarted.load_index().unwrap().generation, generation);",
            "fn checked_publication_retains_pack_visibility_and_exact_callback_refusal_before_index()",
            "Some(StoreError::Unauthorized)",
            "assert_eq!(source.outcome().published_packs, 1);",
            "assert!(source.outcome().pack_visibility_uncertain);",
            "assert!(!source.outcome().index_visibility_uncertain);",
            "assert_eq!(fs::read(fixture.backend.index_path()).unwrap(), old_index);",
            "drop(error); fixture.original.verify_live().unwrap();",
            "assert_eq!(fixture.backend.load_index().unwrap().entries.len(), 2);",
        ],
        // Only these two concrete observations and their length assertions are
        // classified. Any additional retry call, macro, or declaration remains.
        expressions: &[
            (REOPENED_PUBLICATION, 1),
            (RECOVERED_PUBLICATION, 1),
            ("assert_eq!(retry.len(), 1);", 2),
        ],
        companions: &[],
    },
];

#[cfg(test)]
mod tests {
    use super::super::{mask_with_companions, pattern, read_companions};
    use super::*;

    fn scrub(source: &str) -> String {
        super::super::super::super::scrub_comments_and_strings(source)
    }

    fn findings(contract: &Contract, source: &str, companions: &[String]) -> Vec<String> {
        let masked = mask_with_companions(contract, &scrub(source), companions);
        super::super::super::super::flaky_escape_failures("unreviewed", "unreviewed", &masked)
    }

    // Preserve original whitespace and scrub the inserted source too. A mutation
    // must reach the same executable token scanner as the positive source.
    fn replace_fragment(source: &str, fragment: &str, replacement: &str) -> String {
        let code = scrub(source);
        let compact = pattern(fragment);
        let offsets = code
            .char_indices()
            .filter(|(_, character)| !character.is_whitespace())
            .flat_map(|(offset, character)| std::iter::repeat_n(offset, character.len_utf8()))
            .collect::<Vec<_>>();
        let matches = super::super::super::expression_offsets(&code, &compact);
        assert!(
            !matches.is_empty(),
            "mutation fragment not found: {fragment}"
        );
        let mut changed = source.to_owned();
        for offset in matches.into_iter().rev() {
            let start = offsets[offset];
            let end = offsets[offset + compact.len() - 1] + 1;
            changed.replace_range(start..end, replacement);
        }
        changed
    }

    #[test]
    fn packed_contracts_require_exact_original_checks_and_single_shot_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::super::super::workspace_root();
        for contract in CONTRACTS {
            let source = std::fs::read_to_string(
                root.join("crates")
                    .join(contract.package)
                    .join(format!("{}.rs", contract.target)),
            )?;
            let companions = read_companions(contract)?;
            assert!(findings(contract, &source, &companions).is_empty());
            for requirement in contract.required {
                let identical = replace_fragment(&source, requirement, requirement);
                assert!(findings(contract, &identical, &companions).is_empty());
                let changed =
                    replace_fragment(&source, requirement, "removed_original_obligation();");
                assert!(
                    !findings(contract, &changed, &companions).is_empty(),
                    "{requirement}"
                );
            }
            for (expression, _) in contract.expressions {
                let identical = replace_fragment(&source, expression, expression);
                assert!(findings(contract, &identical, &companions).is_empty());
                let duplicate = format!("{source}\n{expression}");
                assert!(!findings(contract, &duplicate, &companions).is_empty());
                let altered = expression
                    .replace("from_millis(1)", "from_millis(2)")
                    .replace("fixture.original", "other.original")
                    .replace("retry.len()", "retry.is_empty()");
                assert_ne!(altered, *expression);
                let changed = replace_fragment(&source, expression, &altered);
                assert!(!findings(contract, &changed, &companions).is_empty());
            }
            for added in [
                "fn conceal() { retry(); }",
                "fn conceal() { retry!(); }",
                "fn retry() {}",
                "fn conceal() { std::thread::sleep(std::time::Duration::from_millis(1)); }",
            ] {
                assert!(!findings(contract, &format!("{source}\n{added}"), &companions).is_empty());
            }
            for (index, companion) in contract.companions.iter().enumerate() {
                for requirement in companion.required {
                    let mut changed = companions.clone();
                    changed[index] =
                        replace_fragment(&changed[index], requirement, "removed_original_check();");
                    assert!(!findings(contract, &source, &changed).is_empty());
                }
                assert!(!findings(contract, &source, &[]).is_empty());
            }
            if contract.target.ends_with("checked_io") {
                for (before, after) in [
                    (
                        "lock_file(backend, name, shared, false, original, boundary)",
                        "lock_file(backend, name, shared, false, other_original, boundary)",
                    ),
                    (
                        "lock_file(backend, name, shared, true, original, boundary)",
                        "lock_file(backend, name, shared, true, original, other_boundary)",
                    ),
                    (
                        "if create { OFlags::RDWR | OFlags::CREATE } else { OFlags::RDWR }",
                        "if create { OFlags::RDWR } else { OFlags::RDWR | OFlags::CREATE }",
                    ),
                    (
                        "loop { checked_reader::check(original, boundary)?; match flock",
                        "loop { match flock",
                    ),
                    (
                        "} checked_reader::check(original, boundary)?; Ok(file)",
                        "} Ok(file)",
                    ),
                ] {
                    let changed = replace_fragment(&source, before, after);
                    assert!(!findings(contract, &changed, &companions).is_empty());
                }
                let mut changed = companions.clone();
                changed[0] =
                    replace_fragment(&changed[0], "original.verify_live()", "other.verify_live()");
                assert!(!findings(contract, &source, &changed).is_empty());
            }
        }
        Ok(())
    }
}
