//! Streaming console-pattern automata for `console_match` conditions.
//!
//! A console pattern is compiled once, at scenario validation, into a
//! deterministic byte automaton that Crucible owns. Evaluation feeds each
//! node's console bytes through the automaton as they arrive and carries one
//! state per declared pattern, so no console history is retained and no byte
//! is scanned twice.
//!
//! # Semantics
//!
//! The automaton reports every offset at which some match of the pattern ends,
//! including overlapping matches and matches that began arbitrarily far back
//! in the stream. Whether a match ends at an offset depends only on the bytes
//! up to that offset, so a report never depends on how the stream is divided
//! into batches. Constructs that need bytes after the match end to decide it
//! (end anchors and word boundaries) are rejected, as are patterns that can
//! match the empty string or can never match.
//!
//! # Construction
//!
//! `regex-automata` determinizes and minimizes the pattern. The minimized
//! automaton is then re-indexed breadth-first from the stream start state in
//! byte order and compressed into byte classes. That canonical table is the
//! only representation retained; its content hash identifies the pattern's
//! language independently of the library's internal state layout, and a
//! checkpointed state is a dense index into it.
//!
//! The canonical table hashed by [`ConsoleAutomaton::content_hash`] is:
//!
//! ```text
//! u16 LE  byte-class count k
//! [u8;256] byte -> class
//! u32 LE  state count n
//! n bytes accepting flag per state (0 or 1)
//! n*k u32 LE  next-state index, row-major by state then class
//! ```

use std::collections::{BTreeMap, VecDeque};

use regex_automata::dfa::{Automaton as _, StartKind, dense};
use regex_automata::nfa::thompson;
use regex_automata::util::{start, syntax};
use regex_automata::{Anchored, MatchKind};
use regex_syntax::hir::Look;

use crate::ContentHash;

/// Largest canonical transition table, in bytes, one console pattern may use.
pub const MAX_CONSOLE_AUTOMATON_BYTES: usize = 1024 * 1024;

/// Largest intermediate NFA, in bytes, built while compiling one pattern.
const MAX_CONSOLE_NFA_BYTES: usize = 8 * 1024 * 1024;

/// Largest determinization working set, in bytes, for one pattern.
const MAX_CONSOLE_DETERMINIZATION_BYTES: usize = 16 * 1024 * 1024;

/// Domain separating console automaton identities from other content.
const CONSOLE_AUTOMATON_DOMAIN: &str = "crucible.console-automaton.v1";

/// Reasons a console pattern cannot become a streaming automaton.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConsolePatternError {
    /// The pattern is not valid regular-expression syntax.
    #[error("console pattern `{pattern}` is invalid: {reason}")]
    Syntax {
        /// Rejected pattern.
        pattern: String,
        /// Parser diagnostic.
        reason: String,
    },
    /// The pattern uses a construct decided by bytes after a match ends.
    #[error(
        "console pattern `{pattern}` uses {construct}, which a streaming matcher cannot decide when the match ends"
    )]
    UndecidableConstruct {
        /// Rejected pattern.
        pattern: String,
        /// Human-readable name of the rejected construct.
        construct: &'static str,
    },
    /// The pattern matches the empty string, so it would match at every offset.
    #[error("console pattern `{pattern}` can match the empty string")]
    MatchesEmpty {
        /// Rejected pattern.
        pattern: String,
    },
    /// The pattern can never match any byte sequence.
    #[error("console pattern `{pattern}` can never match")]
    NeverMatches {
        /// Rejected pattern.
        pattern: String,
    },
    /// Determinization exceeded a fixed construction bound.
    #[error("console pattern `{pattern}` exceeds the automaton construction bound: {reason}")]
    Construction {
        /// Rejected pattern.
        pattern: String,
        /// Builder diagnostic.
        reason: String,
    },
    /// The canonical transition table exceeds [`MAX_CONSOLE_AUTOMATON_BYTES`].
    #[error(
        "console pattern `{pattern}` needs a {bytes}-byte automaton, above the {limit}-byte bound"
    )]
    TooLarge {
        /// Rejected pattern.
        pattern: String,
        /// Canonical table size.
        bytes: usize,
        /// Applicable bound.
        limit: usize,
    },
}

/// One state of a [`ConsoleAutomaton`], as a dense canonical index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsoleAutomatonState(u32);

impl ConsoleAutomatonState {
    /// Returns the canonical state index stored in checkpoints.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

/// Result of feeding one batch of console bytes to an automaton.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleAdvance {
    /// State after the last byte of the batch.
    pub state: ConsoleAutomatonState,
    /// Whether some match ends at an offset within the batch.
    pub matched: bool,
}

/// Canonical deterministic byte automaton for one console pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleAutomaton {
    classes: [u8; 256],
    class_count: usize,
    accepting: Vec<bool>,
    transitions: Vec<u32>,
    content_hash: ContentHash,
}

impl ConsoleAutomaton {
    /// Compiles `pattern` into a canonical streaming automaton.
    ///
    /// Patterns follow `regex::bytes` syntax: Unicode-aware classes, with
    /// `(?-u)` permitting arbitrary bytes. `^` and `\A` denote the start of the
    /// node's console stream and `(?m:^)` the start of a line.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crucible_engine::ConsoleAutomaton;
    ///
    /// let automaton = ConsoleAutomaton::compile("ready").expect("streamable pattern");
    /// let first = automaton.advance(automaton.start(), b"rea");
    /// let second = automaton.advance(first.state, b"dy\n");
    /// assert!(!first.matched);
    /// assert!(second.matched);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ConsolePatternError`] when the pattern is invalid, uses an
    /// end anchor or word boundary, matches the empty string, never matches,
    /// or exceeds a construction or table-size bound.
    pub fn compile(pattern: &str) -> Result<Self, ConsolePatternError> {
        validate_streamable_syntax(pattern)?;
        let dfa = build_minimal_dfa(pattern)?;
        Self::from_dfa(pattern, &dfa)
    }

    /// Returns the state before any console byte has been consumed.
    #[must_use]
    pub const fn start(&self) -> ConsoleAutomatonState {
        ConsoleAutomatonState(0)
    }

    /// Feeds `bytes` from `state` and reports whether any match ends in them.
    ///
    /// # Panics
    ///
    /// Does not panic for states produced by this automaton or accepted by
    /// [`Self::restore_state`].
    #[must_use]
    pub fn advance(&self, state: ConsoleAutomatonState, bytes: &[u8]) -> ConsoleAdvance {
        let mut current = state.0 as usize;
        let mut matched = false;
        for &byte in bytes {
            let class = usize::from(self.classes[usize::from(byte)]);
            current = self.transitions[current * self.class_count + class] as usize;
            matched |= self.accepting[current];
        }
        ConsoleAdvance {
            state: ConsoleAutomatonState(current as u32),
            matched,
        }
    }

    /// Validates a checkpointed state index against this automaton.
    #[must_use]
    pub fn restore_state(&self, index: u32) -> Option<ConsoleAutomatonState> {
        ((index as usize) < self.accepting.len()).then_some(ConsoleAutomatonState(index))
    }

    /// Returns the number of canonical states.
    #[must_use]
    pub fn state_count(&self) -> usize {
        self.accepting.len()
    }

    /// Returns the canonical transition table size in bytes.
    #[must_use]
    pub fn table_bytes(&self) -> usize {
        canonical_table_bytes(self.accepting.len(), self.class_count)
    }

    /// Returns the content hash of the canonical table.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Re-indexes a minimized DFA breadth-first and compresses byte classes.
    fn from_dfa(pattern: &str, dfa: &dense::DFA<Vec<u32>>) -> Result<Self, ConsolePatternError> {
        let start_config = start::Config::new()
            .anchored(Anchored::No)
            .look_behind(None);
        let start_id =
            dfa.start_state(&start_config)
                .map_err(|source| ConsolePatternError::Construction {
                    pattern: pattern.to_owned(),
                    reason: source.to_string(),
                })?;

        // Breadth-first discovery in byte order gives every equivalent
        // minimal automaton the same state numbering.
        let mut indexes = BTreeMap::new();
        let mut order = Vec::new();
        let mut queue = VecDeque::from([start_id]);
        indexes.insert(start_id, 0_u32);
        let mut rows = Vec::<[u32; 256]>::new();
        while let Some(id) = queue.pop_front() {
            order.push(id);
            let mut row = [0_u32; 256];
            for (byte, slot) in (0..=u8::MAX).zip(row.iter_mut()) {
                let next = dfa.next_state(id, byte);
                let next_index = match indexes.get(&next) {
                    Some(index) => *index,
                    None => {
                        let index = u32::try_from(indexes.len()).map_err(|_| too_large(pattern))?;
                        indexes.insert(next, index);
                        queue.push_back(next);
                        index
                    }
                };
                *slot = next_index;
            }
            rows.push(row);
            if canonical_table_bytes(rows.len(), 1) > MAX_CONSOLE_AUTOMATON_BYTES {
                return Err(too_large(pattern));
            }
        }

        // Without end anchors, the end-of-input transition only settles the
        // DFA's one-byte match delay, so it reports exactly whether a match
        // ends after the last consumed byte.
        let accepting = order
            .iter()
            .map(|id| dfa.is_match_state(dfa.next_eoi_state(*id)))
            .collect::<Vec<_>>();
        if accepting[0] {
            return Err(ConsolePatternError::MatchesEmpty {
                pattern: pattern.to_owned(),
            });
        }
        if !accepting.iter().any(|accepting| *accepting) {
            return Err(ConsolePatternError::NeverMatches {
                pattern: pattern.to_owned(),
            });
        }

        let (classes, class_count) = byte_classes(&rows);
        let bytes = canonical_table_bytes(rows.len(), class_count);
        if bytes > MAX_CONSOLE_AUTOMATON_BYTES {
            return Err(ConsolePatternError::TooLarge {
                pattern: pattern.to_owned(),
                bytes,
                limit: MAX_CONSOLE_AUTOMATON_BYTES,
            });
        }
        let representatives = class_representatives(&classes, class_count);
        let transitions = rows
            .iter()
            .flat_map(|row| representatives.iter().map(|byte| row[usize::from(*byte)]))
            .collect::<Vec<_>>();

        let content_hash = canonical_hash(&classes, class_count, &accepting, &transitions);
        Ok(Self {
            classes,
            class_count,
            accepting,
            transitions,
            content_hash,
        })
    }
}

/// Rejects syntax a streaming matcher cannot decide at the match end.
fn validate_streamable_syntax(pattern: &str) -> Result<(), ConsolePatternError> {
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pattern)
        .map_err(|source| ConsolePatternError::Syntax {
            pattern: pattern.to_owned(),
            reason: source.to_string(),
        })?;

    for look in hir.properties().look_set().iter() {
        let construct = match look {
            // Start assertions are decided by bytes already consumed.
            Look::Start | Look::StartLF => continue,
            Look::End | Look::EndLF | Look::EndCRLF => "an end anchor",
            Look::StartCRLF => "a CRLF-aware line anchor",
            _ => "a word boundary",
        };
        return Err(ConsolePatternError::UndecidableConstruct {
            pattern: pattern.to_owned(),
            construct,
        });
    }
    match hir.properties().minimum_len() {
        Some(0) => Err(ConsolePatternError::MatchesEmpty {
            pattern: pattern.to_owned(),
        }),
        None => Err(ConsolePatternError::NeverMatches {
            pattern: pattern.to_owned(),
        }),
        Some(_) => Ok(()),
    }
}

/// Determinizes and minimizes `pattern` under the fixed construction bounds.
fn build_minimal_dfa(pattern: &str) -> Result<dense::DFA<Vec<u32>>, ConsolePatternError> {
    dense::Builder::new()
        .configure(
            dense::Config::new()
                .match_kind(MatchKind::All)
                .start_kind(StartKind::Unanchored)
                .minimize(true)
                .byte_classes(true)
                .determinize_size_limit(Some(MAX_CONSOLE_DETERMINIZATION_BYTES))
                .dfa_size_limit(Some(MAX_CONSOLE_DETERMINIZATION_BYTES)),
        )
        .syntax(syntax::Config::new().utf8(false))
        .thompson(
            thompson::Config::new()
                .utf8(false)
                .nfa_size_limit(Some(MAX_CONSOLE_NFA_BYTES)),
        )
        .build(pattern)
        .map_err(|source| ConsolePatternError::Construction {
            pattern: pattern.to_owned(),
            reason: source.to_string(),
        })
}

/// Groups bytes whose transition columns are identical in every state.
///
/// Classes are numbered by the first byte, in byte order, that belongs to
/// them, so equal tables always produce equal class maps.
fn byte_classes(rows: &[[u32; 256]]) -> ([u8; 256], usize) {
    let mut classes = [0_u8; 256];
    let mut class_of_column = BTreeMap::<Vec<u32>, u8>::new();
    for byte in 0..=u8::MAX {
        let column = rows
            .iter()
            .map(|row| row[usize::from(byte)])
            .collect::<Vec<_>>();
        // At most 256 classes exist, so every class number fits in a byte.
        let next_class = u8::try_from(class_of_column.len()).unwrap_or(u8::MAX);
        classes[usize::from(byte)] = *class_of_column.entry(column).or_insert(next_class);
    }
    (classes, class_of_column.len())
}

/// Returns the first byte of each class, in class order.
fn class_representatives(classes: &[u8; 256], class_count: usize) -> Vec<u8> {
    let mut representatives = Vec::with_capacity(class_count);
    for byte in 0..=u8::MAX {
        if usize::from(classes[usize::from(byte)]) == representatives.len() {
            representatives.push(byte);
        }
    }
    representatives
}

/// Size of the canonical table encoding for `states` states and `classes` classes.
fn canonical_table_bytes(states: usize, classes: usize) -> usize {
    2 + 256 + 4 + states + states.saturating_mul(classes).saturating_mul(4)
}

/// Hashes the canonical table encoding documented in the module header.
fn canonical_hash(
    classes: &[u8; 256],
    class_count: usize,
    accepting: &[bool],
    transitions: &[u32],
) -> ContentHash {
    let mut material = Vec::with_capacity(canonical_table_bytes(accepting.len(), class_count));
    material.extend_from_slice(&(class_count as u16).to_le_bytes());
    material.extend_from_slice(classes);
    material.extend_from_slice(&(accepting.len() as u32).to_le_bytes());
    material.extend(accepting.iter().map(|accepting| u8::from(*accepting)));
    for next in transitions {
        material.extend_from_slice(&next.to_le_bytes());
    }
    ContentHash::from_canonical_material_bytes(CONSOLE_AUTOMATON_DOMAIN, &material)
}

fn too_large(pattern: &str) -> ConsolePatternError {
    ConsolePatternError::TooLarge {
        pattern: pattern.to_owned(),
        bytes: MAX_CONSOLE_AUTOMATON_BYTES.saturating_add(1),
        limit: MAX_CONSOLE_AUTOMATON_BYTES,
    }
}

#[cfg(test)]
#[path = "console_automaton_tests.rs"]
mod tests;
