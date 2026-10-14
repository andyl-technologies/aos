//! Tests the bounded retained-source shutdown diagnostics.

use super::{SHUTDOWN_LEAF_PART_CHARACTERS, SHUTDOWN_LEAF_PARTS, report_shutdown_leaf};

#[derive(Debug, thiserror::Error)]
#[error("wrapping shutdown failure")]
struct WrappingFailure(#[source] std::io::Error);

/// Builds a leaf cause whose parts are distinguishable by their letter.
fn lettered_cause(parts: usize) -> String {
    (0..parts)
        .map(|index| {
            let letter = char::from(b'a' + u8::try_from(index % 26).unwrap_or(0));
            letter.to_string().repeat(SHUTDOWN_LEAF_PART_CHARACTERS)
        })
        .collect()
}

fn leaf_rows(cause: String) -> Vec<String> {
    let failure = WrappingFailure(std::io::Error::other(cause));
    let mut output = Vec::new();
    report_shutdown_leaf(&mut output, &"source", &failure);
    String::from_utf8(output)
        .unwrap_or_else(|error| panic!("diagnostic rows should be UTF-8: {error}"))
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn short_leaf_cause_is_written_whole_in_one_part() {
    let rows = leaf_rows(String::from("released project still in use"));

    assert_eq!(
        rows,
        [
            "CRUCIBLE-HOT-FORK-SHUTDOWN-V1 source_key=\"source\" leaf_depth=1 part=1/1 cause=\"released project still in use\""
        ]
    );
}

#[test]
fn long_leaf_cause_keeps_its_first_and_last_parts() {
    let total = SHUTDOWN_LEAF_PARTS + 4;

    let rows = leaf_rows(lettered_cause(total));

    assert_eq!(rows.len(), SHUTDOWN_LEAF_PARTS);
    let numbered = rows
        .iter()
        .map(|row| {
            row.split_once(" part=")
                .and_then(|(_, rest)| rest.split_once('/'))
                .map(|(index, _)| index.to_owned())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    let expected = (1..=SHUTDOWN_LEAF_PARTS / 2)
        .chain(total - SHUTDOWN_LEAF_PARTS / 2 + 1..=total)
        .map(|index| index.to_string())
        .collect::<Vec<_>>();
    assert_eq!(numbered, expected);
    assert!(rows[0].ends_with(&format!("cause=\"{}\"", "a".repeat(512))));
    assert!(rows[SHUTDOWN_LEAF_PARTS - 1].contains(&format!("part={total}/{total} ")));
}
