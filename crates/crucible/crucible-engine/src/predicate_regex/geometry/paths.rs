//! Checked emitted-path census for the pinned Thompson compiler.

use super::{PredicateRegexError, add, mul};
use regex_syntax::hir::{Class, Hir, HirKind};
use regex_syntax::utf8::Utf8Sequences;

#[derive(Default)]
pub(super) struct Paths {
    pub(super) states: u64,
    pub(super) edges: u64,
    pub(super) unicode: bool,
    pub(super) trie_nodes: u64,
    pub(super) trie_edges: u64,
    pub(super) trie_chunks: u64,
}

pub(super) fn count(hir: &Hir) -> Result<Paths, PredicateRegexError> {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Ok(Paths::simple(1, 1)),
        HirKind::Literal(literal) => {
            let bytes = literal.0.len() as u64;
            Ok(Paths::simple(bytes.max(1), bytes.max(1)))
        }
        HirKind::Class(Class::Bytes(class)) => Ok(Paths::simple(2, class.ranges().len() as u64)),
        HirKind::Class(Class::Unicode(class)) => {
            if class.is_ascii() {
                return Ok(Paths::simple(2, class.ranges().len() as u64));
            }
            // Every UTF-8 range path can add at most one state per byte.
            // Prefix/suffix sharing only reduces this bound. Iterating the
            // concrete normalized ranges uses Utf8Sequences' fixed stack.
            let mut bytes = 0;
            for range in class.iter() {
                for sequence in Utf8Sequences::new(range.start(), range.end()) {
                    bytes = add(bytes, sequence.as_slice().len() as u64)?;
                }
            }
            Ok(Paths {
                states: add(bytes, 2)?,
                edges: add(bytes, 1)?,
                unicode: true,
                ..Paths::default()
            })
        }
        // WhichCaptures::Implicit returns the child directly for explicit
        // capture groups. The root's implicit start/end are counted outside.
        HirKind::Capture(capture) => count(&capture.sub),
        HirKind::Concat(children) => {
            let mut paths = Paths::default();
            for child in children {
                paths.append(count(child)?)?;
            }
            paths.states = paths.states.max(1);
            Ok(paths)
        }
        HirKind::Alternation(children) => {
            if children.len() > 1
                && children
                    .iter()
                    .all(|child| matches!(child.kind(), HirKind::Literal(_)))
            {
                let mut bytes = 0;
                for child in children {
                    if let HirKind::Literal(literal) = child.kind() {
                        bytes = add(bytes, literal.0.len() as u64)?;
                    }
                }
                let nodes = add(bytes, 1)?;
                let chunks = add(nodes, children.len() as u64)?;
                // Each trie state creates a union and at most one sparse
                // state per chunk; the trie also creates its final target.
                // Every sparse edge corresponds to a trie byte edge.
                Ok(Paths {
                    states: add(add(nodes, chunks)?, 1)?,
                    edges: add(add(bytes, chunks)?, nodes)?,
                    trie_nodes: nodes,
                    trie_edges: bytes,
                    trie_chunks: chunks,
                    ..Paths::default()
                })
            } else {
                let mut paths = Paths::simple(2, children.len() as u64);
                for child in children {
                    paths.append(count(child)?)?;
                }
                Ok(paths)
            }
        }
        HirKind::Repetition(repetition) => {
            let mut paths = count(&repetition.sub)?;
            let copies = match repetition.max {
                Some(maximum) => u64::from(maximum),
                None => u64::from(repetition.min).max(1),
            };
            paths.states = mul(paths.states, copies)?;
            paths.edges = mul(paths.edges, copies)?;
            // Bounded repeats add one two-edge union per optional copy,
            // plus the zero-copy prefix and final empty. Unbounded repeats
            // need at most two unions and one empty (nullable x*).
            let unions = match repetition.max {
                Some(maximum) => u64::from(maximum - repetition.min),
                None => 2,
            };
            paths.states = add(paths.states, add(unions, 2)?)?;
            paths.edges = add(paths.edges, add(mul(unions, 2)?, 2)?)?;
            // Literal tries are constructed one copy at a time. Their own
            // temporary peak does not multiply with the repeat count;
            // retained emitted NFA states/edges above do multiply.
            Ok(paths)
        }
    }
}

impl Paths {
    fn simple(states: u64, edges: u64) -> Self {
        Self {
            states,
            edges,
            ..Self::default()
        }
    }

    fn append(&mut self, other: Self) -> Result<(), PredicateRegexError> {
        self.states = add(self.states, other.states)?;
        self.edges = add(self.edges, other.edges)?;
        self.unicode |= other.unicode;
        // Nested nonliteral expressions cannot keep two LiteralTrie
        // instances live: a trie is used only when all children are literal.
        self.trie_nodes = self.trie_nodes.max(other.trie_nodes);
        self.trie_edges = self.trie_edges.max(other.trie_edges);
        self.trie_chunks = self.trie_chunks.max(other.trie_chunks);
        Ok(())
    }
}
