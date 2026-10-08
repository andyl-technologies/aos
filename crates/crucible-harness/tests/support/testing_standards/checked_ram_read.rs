//! Requires the checked RAM read's original accounts, bounded body and EOF.
//!
//! These source obligations replace the removed raw RAM read helper. They
//! grant no flaky-token masking, test repetition or operational allowance.

use std::fs;
use std::path::Path;

struct Input {
    path: &'static str,
    required: &'static [&'static str],
    counts: &'static [(&'static str, usize)],
}

const INPUTS: &[Input] = &[
    Input {
        path: "crates/crucible-cas/src/ram/codec.rs",
        required: &[
            "fn read_envelope_with_partition(",
            "let account = work.original().child().map_err(admission)?;",
            "let (maximum_bytes, maximum_children) = object_limits(id)?;",
            "self.backend.read_with_boundary(original, id, None, boundary)",
            "if source.logical_length() > maximum_bytes",
            "source.read_all_with_boundary(original, maximum_bytes, boundary)",
            "let _terminal_scope = record.original.enter();",
            "if let Err(error) = (work.boundary)()",
            "if !id.authenticates(bytes)",
            "ContentEnvelope::from_canonical_bytes_with_child_limit(bytes, maximum_children)?",
        ],
        counts: &[(
            "source.read_all_with_boundary(original, maximum_bytes, boundary)",
            2,
        )],
    },
    Input {
        path: "crates/crucible-cas/src/content_store/checked_reader.rs",
        required: &[
            "let mut reader = source.open_with_boundary(caller, boundary)?;",
            "let source = reader.original_account().clone();",
            "batch::read_reader_under(&source, caller, length, maximum, boundary,",
            "&mut |output, boundary| reader.read_with_boundary(output, boundary)",
            "if caller.same_account(source) { return check(caller, boundary); }",
            "caller.verify_live().map_err(|error| batch::admission_under(caller, error))?;",
            "source.verify_live().map_err(|error| batch::admission_under(source, error))?;",
            "boundary()?;",
        ],
        counts: &[],
    },
    Input {
        path: "crates/crucible-cas/src/content_store/batch.rs",
        required: &[
            "pub(crate) fn read_reader_under<F>(",
            "super::checked_reader::check_pair(caller, account, boundary)?;",
            "if length > maximum",
            "let credit = account.reserve_scratch_array::<u8>(capacity)",
            "while observed < capacity",
            "let end = capacity.min(observed.saturating_add(64 * 1024));",
            "let count = read(&mut bytes[observed..end], boundary)?;",
            "if count > end - observed",
            "let mut extra = [0_u8; 1];",
            "let count = read(&mut extra, boundary)?;",
            "if observed != capacity || count != 0",
            "observed: (observed as u64).saturating_add(count as u64)",
            "account.verify_live().map_err(|error| admission_under(account, error))?;",
            "Ok(OwnedBlobBytes { bytes, _credit: credit, })",
        ],
        counts: &[
            (
                "super::checked_reader::check_pair(caller, account, boundary)?;",
                6,
            ),
            ("let count = read(&mut extra, boundary)?;", 1),
        ],
    },
    Input {
        path: "crates/crucible-cas/src/ram/store_boundary.rs",
        required: &[
            "let original = self.account.original;",
            "let mut first = None;",
            "let result = operation(original, &mut ||",
            "first = Some(error);",
            "(Some(first), Ok(value)) => { drop(value); Err(first) }",
            "(Some(first), Err(StoreError::RamBoundary { .. })) => Err(first)",
            "let cause = slot.retain(Some(first), storage.into());",
        ],
        counts: &[],
    },
];

fn compact(source: &str) -> String {
    super::scrub_comments_and_strings(source)
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn input_failures(input: &Input, source: &str) -> Vec<String> {
    let source = compact(source);
    let mut failures = input
        .required
        .iter()
        .filter(|required| !source.contains(&compact(required)))
        .map(|required| {
            format!(
                "{} is missing checked RAM read obligation: {required}",
                input.path
            )
        })
        .collect::<Vec<_>>();
    for (expression, expected) in input.counts {
        let actual = source.match_indices(&compact(expression)).count();
        if actual != *expected {
            failures.push(format!(
                "{} requires {expected} checked RAM read sites, observed {actual}: {expression}",
                input.path,
            ));
        }
    }
    failures
}

pub(crate) fn failures(root: &Path) -> std::io::Result<Vec<String>> {
    let mut failures = Vec::new();
    for input in INPUTS {
        failures.extend(input_failures(
            input,
            &fs::read_to_string(root.join(input.path))?,
        ));
    }
    Ok(failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_ram_read_obligations_reject_each_removed_original_body_and_eof_proof()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::super::workspace_root();
        assert!(failures(&root)?.is_empty());

        for input in INPUTS {
            let source = fs::read_to_string(root.join(input.path))?;
            let source = compact(&source);
            for required in input.required {
                let required = compact(required);
                assert!(source.contains(&required));
                let removed = source.replace(&required, "removed_original_read_proof()");
                assert!(!input_failures(input, &removed).is_empty());
            }
            for (expression, count) in input.counts {
                let expression = compact(expression);
                assert_eq!(source.match_indices(&expression).count(), *count);
                let removed = source.replacen(&expression, "removed_original_read_site()", 1);
                assert!(!input_failures(input, &removed).is_empty());
                let added = format!("{source}{expression}");
                assert!(!input_failures(input, &added).is_empty());
            }
        }
        Ok(())
    }
}
