//! Tests streaming console automata against a brute-force reference.

use super::*;

/// Compiles a pattern the test expects to be streamable.
fn automaton(pattern: &str) -> ConsoleAutomaton {
    ConsoleAutomaton::compile(pattern)
        .unwrap_or_else(|error| panic!("pattern `{pattern}` should compile: {error}"))
}

/// Returns every end offset of a substring that fully matches `pattern`.
fn reference_match_ends(pattern: &str, stream: &[u8], anchored_start: bool) -> Vec<usize> {
    let full = regex::bytes::Regex::new(&format!("^(?:{pattern})$"))
        .unwrap_or_else(|error| panic!("reference pattern should compile: {error}"));
    (1..=stream.len())
        .filter(|end| {
            let starts = if anchored_start { 0..1 } else { 0..*end };
            starts
                .into_iter()
                .any(|start| full.is_match(&stream[start..*end]))
        })
        .collect()
}

/// Returns every end offset the automaton reports when fed one byte at a time.
fn streamed_match_ends(automaton: &ConsoleAutomaton, stream: &[u8]) -> Vec<usize> {
    let mut state = automaton.start();
    let mut ends = Vec::new();
    for (index, byte) in stream.iter().enumerate() {
        let advance = automaton.advance(state, std::slice::from_ref(byte));
        if advance.matched {
            ends.push(index + 1);
        }
        state = advance.state;
    }
    ends
}

#[test]
fn reports_every_match_end_including_overlaps() {
    let cases: [(&str, &[u8]); 5] = [
        ("aa", b"aaaa"),
        ("ab|b", b"xabab"),
        ("ready+", b"readyyy ready"),
        ("[0-9]{2}", b"a123b45"),
        ("(?-u:\\xff)x", b"\xffx\xff\xffx"),
    ];

    for (pattern, stream) in cases {
        let automaton = automaton(pattern);

        assert_eq!(
            streamed_match_ends(&automaton, stream),
            reference_match_ends(pattern, stream, false),
            "pattern `{pattern}`"
        );
    }
}

#[test]
fn batch_reports_do_not_depend_on_how_the_stream_is_split() {
    let automaton = automaton("needle");
    let stream = b"hay needle hayneedleneedle";
    let ends = streamed_match_ends(&automaton, stream);

    for split in 0..=stream.len() {
        let first = automaton.advance(automaton.start(), &stream[..split]);
        let second = automaton.advance(first.state, &stream[split..]);

        assert_eq!(first.matched, ends.iter().any(|end| *end <= split));
        assert_eq!(second.matched, ends.iter().any(|end| *end > split));
        assert_eq!(
            second.state,
            automaton.advance(automaton.start(), stream).state
        );
    }
}

#[test]
fn start_anchors_bind_to_the_stream_and_to_lines() {
    let stream_start = automaton("^ok");
    let line_start = automaton("(?m:^)ok");
    let stream = b"ok\nok xok";

    assert_eq!(streamed_match_ends(&stream_start, stream), vec![2]);
    assert_eq!(streamed_match_ends(&line_start, stream), vec![2, 5]);
    assert_eq!(
        reference_match_ends("ok", stream, true),
        streamed_match_ends(&stream_start, stream)
    );
}

#[test]
fn rejects_constructs_decided_after_the_match_ends() {
    for pattern in [
        "done$",
        "(?m:done$)",
        "done\\z",
        "\\bdone",
        "done\\B",
        "(?mR:^)done",
    ] {
        let Err(error) = ConsoleAutomaton::compile(pattern) else {
            panic!("pattern `{pattern}` should be rejected");
        };

        assert!(
            matches!(error, ConsolePatternError::UndecidableConstruct { .. }),
            "pattern `{pattern}` produced {error:?}"
        );
    }
}

#[test]
fn rejects_empty_and_impossible_matches() {
    assert!(matches!(
        ConsoleAutomaton::compile("a*"),
        Err(ConsolePatternError::MatchesEmpty { .. })
    ));
    assert!(matches!(
        ConsoleAutomaton::compile("(?-u:[^\\x00-\\xff])"),
        Err(ConsolePatternError::NeverMatches { .. })
    ));
    assert!(matches!(
        ConsoleAutomaton::compile("("),
        Err(ConsolePatternError::Syntax { .. })
    ));
}

#[test]
fn rejects_patterns_beyond_the_construction_bounds() {
    let Err(error) = ConsoleAutomaton::compile("(?-u:[ab]*a[ab]{24})") else {
        panic!("exponential determinization should be rejected");
    };

    assert!(
        matches!(
            error,
            ConsolePatternError::Construction { .. } | ConsolePatternError::TooLarge { .. }
        ),
        "{error:?}"
    );
}

#[test]
fn identity_depends_on_the_language_not_the_spelling() {
    let plain = automaton("ab");

    assert_eq!(plain.content_hash(), automaton("a(?:b)").content_hash());
    assert_eq!(plain.content_hash(), automaton("ab|ab").content_hash());
    assert_ne!(plain.content_hash(), automaton("abc").content_hash());
}

#[test]
fn restore_accepts_only_canonical_state_indexes() {
    let automaton = automaton("abc");
    let after_prefix = automaton.advance(automaton.start(), b"ab").state;
    let count = u32::try_from(automaton.state_count())
        .unwrap_or_else(|error| panic!("small automaton state count: {error}"));

    assert_eq!(
        automaton.restore_state(after_prefix.index()),
        Some(after_prefix)
    );
    assert_eq!(automaton.restore_state(count), None);
    assert!(automaton.table_bytes() <= MAX_CONSOLE_AUTOMATON_BYTES);
}
