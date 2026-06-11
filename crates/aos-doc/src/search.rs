//! Fuzzy subsequence search over documentation entries.
//!
//! Implements a small fzf-style matcher: a query matches an entry when its
//! characters appear in order (not necessarily contiguously) in the entry's
//! path, summary, or body. Matches are scored with bonuses for consecutive
//! characters, word-boundary hits, prefix matches, and exact path-component
//! matches, with a small penalty per skipped character. Path matches carry
//! double weight so `head` ranks `functions.lists.head` above an entry that
//! merely mentions "head" in prose.
//!
//! All matching is ASCII case-insensitive; [`fuzzy_search`] is the public
//! entry point used by both the CLI and the TUI search overlay.

use crate::model::DocEntry;

/// Performs fuzzy subsequence search against all entries.
///
/// Returns a list of `(entry_index, score)` pairs sorted by score
/// descending. Only entries with a positive score are included; an empty
/// query yields no results.
pub fn fuzzy_search(entries: &[DocEntry], query: &str) -> Vec<(usize, i64)> {
    if query.is_empty() {
        return Vec::new();
    }

    let query_lower = query.to_ascii_lowercase();

    let mut results: Vec<(usize, i64)> = entries
        .iter()
        .enumerate()
        .filter_map(|(idx, entry)| {
            let score = score_entry(entry, &query_lower);
            if score > 0 { Some((idx, score)) } else { None }
        })
        .collect();

    results.sort_by(|a, b| b.1.cmp(&a.1));
    results
}

/// Scores a single entry against a lowercased query.
/// Searches path (2x weight), summary, and body, taking the best field.
fn score_entry(entry: &DocEntry, query_lower: &str) -> i64 {
    let path_score = score_path(&entry.path.to_ascii_lowercase(), query_lower) * 2;
    let summary_score = fuzzy_score(&entry.summary.to_ascii_lowercase(), query_lower);
    let body_score = fuzzy_score(&entry.body.to_ascii_lowercase(), query_lower);

    // Take the best field match.
    path_score.max(summary_score).max(body_score)
}

/// Scores a query against a dotted path.
/// Scores against both the full path and each individual component,
/// returning the best score. Adds a +10 bonus for exact component matches.
fn score_path(path: &str, query: &str) -> i64 {
    let full_score = fuzzy_score(path, query);

    let component_score = path
        .split('.')
        .map(|component| {
            let s = fuzzy_score(component, query);
            if s > 0 && component == query {
                s + 10 // exact component match bonus
            } else {
                s
            }
        })
        .max()
        .unwrap_or(0);

    full_score.max(component_score)
}

/// Computes a fuzzy subsequence match score.
///
/// Scoring rules:
/// - Consecutive character matches: +3 per consecutive char
/// - Word boundary match (after `.`, `_`, `-`, or first char): +5
/// - Prefix match (query matches from position 0): +10
/// - Gap penalty: -1 per skipped char
///
/// Returns 0 if the query is not a subsequence of the text. The alignment
/// is found by a greedy left-to-right scan (earliest match positions), so
/// the score is a fast approximation rather than a globally optimal one.
fn fuzzy_score(text: &str, query: &str) -> i64 {
    let text_bytes = text.as_bytes();
    let query_bytes = query.as_bytes();

    if query_bytes.is_empty() {
        return 0;
    }

    if query_bytes.len() > text_bytes.len() {
        return 0;
    }

    // Find the best scoring alignment using a greedy approach with
    // two passes: left-to-right finds earliest match positions,
    // then we score from those positions.
    let positions = match find_match_positions(text_bytes, query_bytes) {
        Some(p) => p,
        None => return 0,
    };

    compute_score(text_bytes, &positions)
}

/// Finds match positions for the query as a subsequence of text.
/// Uses a greedy left-to-right scan; returns `None` if no alignment exists.
fn find_match_positions(text: &[u8], query: &[u8]) -> Option<Vec<usize>> {
    let mut positions = Vec::with_capacity(query.len());
    let mut text_idx = 0;

    for &qch in query {
        let mut found = false;
        while text_idx < text.len() {
            if text[text_idx] == qch {
                positions.push(text_idx);
                text_idx += 1;
                found = true;
                break;
            }
            text_idx += 1;
        }
        if !found {
            return None;
        }
    }

    Some(positions)
}

/// Computes the score for a fixed set of matched positions.
fn compute_score(text: &[u8], positions: &[usize]) -> i64 {
    if positions.is_empty() {
        return 0;
    }

    let mut score: i64 = 0;

    // Prefix bonus: first query char matches first text char.
    if positions[0] == 0 {
        score += 10;
    }

    // Gap penalty for characters before the first match.
    score -= positions[0] as i64;

    for (i, &pos) in positions.iter().enumerate() {
        // Word boundary bonus.
        if is_word_boundary(text, pos) {
            score += 5;
        }

        // Consecutive bonus.
        if i > 0 {
            let prev_pos = positions[i - 1];
            if pos == prev_pos + 1 {
                score += 3;
            } else {
                // Gap penalty for skipped characters.
                score -= (pos - prev_pos - 1) as i64;
            }
        }
    }

    score
}

/// Checks if a position is a word boundary (first char, or preceded by `.`, `_`, `-`, or a space).
fn is_word_boundary(text: &[u8], pos: usize) -> bool {
    if pos == 0 {
        return true;
    }
    matches!(text[pos - 1], b'.' | b'_' | b'-' | b' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_entry(path: &str, summary: &str) -> DocEntry {
        DocEntry {
            path: path.to_string(),
            category: crate::model::DocCategory::Function,
            summary: summary.to_string(),
            body: String::new(),
            type_sig: None,
            default: None,
            examples: Vec::new(),
            see_also: Vec::new(),
            parameters: Vec::new(),
            source_file: None,
            source_line: None,
            section: None,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn test_exact_match() {
        let score = fuzzy_score("head", "head");
        assert!(score > 0, "exact match should have positive score");
    }

    #[test]
    fn test_prefix_bonus() {
        let prefix = fuzzy_score("head", "he");
        let middle = fuzzy_score("ahead", "he");
        assert!(
            prefix > middle,
            "prefix match ({prefix}) should score higher than middle match ({middle})"
        );
    }

    #[test]
    fn test_word_boundary_bonus() {
        let boundary = fuzzy_score("lists.head", "head");
        let no_boundary = fuzzy_score("listsxhead", "head");
        assert!(
            boundary > no_boundary,
            "word boundary ({boundary}) should score higher than no boundary ({no_boundary})"
        );
    }

    #[test]
    fn test_no_match() {
        let score = fuzzy_score("hello", "xyz");
        assert_eq!(score, 0, "non-subsequence should score 0");
    }

    #[test]
    fn test_empty_query() {
        let results = fuzzy_search(&[], "");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_ranking() {
        let entries = vec![
            make_entry("functions.strings.concat", "Concatenate strings"),
            make_entry("functions.lists.head", "Return the first element"),
            make_entry("functions.lists.headOrDefault", "Head with default"),
        ];

        let results = fuzzy_search(&entries, "head");
        assert!(!results.is_empty());
        // "head" should rank higher than "headOrDefault" due to exact match properties.
        assert_eq!(
            results[0].0, 1,
            "exact path component match should rank first"
        );
    }

    #[test]
    fn test_path_weight() {
        let entries = vec![
            make_entry("foo", "the head of a list"),
            make_entry("head", "some function"),
        ];

        let results = fuzzy_search(&entries, "head");
        assert_eq!(results[0].0, 1, "path match (2x weight) should rank first");
    }

    #[test]
    fn test_consecutive_bonus() {
        let consecutive = fuzzy_score("abcdef", "abcd");
        let spread = fuzzy_score("axbxcxd", "abcd");
        assert!(
            consecutive > spread,
            "consecutive ({consecutive}) should score higher than spread ({spread})"
        );
    }
}
