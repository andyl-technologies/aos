//! Concrete Thompson construction and PikeVM workspace admission.
//!
//! This audit is coupled to the exact `regex-automata = 0.4.14` manifest pin.
//! It covers its forward, unshrunk compiler with implicit captures. Reverse
//! tries, explicit group names, meta-engine optimizers and DFA construction
//! are unreachable in this configuration. HIR geometry counts emitted paths,
//! not encoded pattern bytes; counted repetitions expand those paths before
//! any compiler allocation occurs.

use super::{CompiledPredicate, PredicateRegexError};
use crate::owned_decode::DecodeAdmissionError;
use regex_automata::nfa::thompson::{NFA, State, Transition};
use regex_automata::util::primitives::StateID;
use regex_automata::util::{
    alphabet::ByteClasses,
    look::{LookMatcher, LookSet},
};
use regex_syntax::hir::Hir;
use std::mem::{align_of, size_of};

mod paths;

pub(super) struct CompilerGeometry {
    pub(super) temporary_bytes: u64,
    pub(super) logical_limit: usize,
}

/// Computes the live allocation envelope before Thompson construction.
pub(super) fn compiler_geometry(hir: &Hir) -> Result<CompilerGeometry, PredicateRegexError> {
    let paths = paths::count(hir)?;
    let states = add(paths.states, 8)?;
    let edges = add(paths.edges, 8)?;
    let mut bytes = 0;

    // builder::State's largest payload is a three-word Vec. Its other
    // payloads fit three words, and a discriminant plus maximum alignment
    // fits two further words. This tuple bounds that private enum on both
    // 32-bit and 64-bit targets without assuming its optimized layout.
    accumulate(
        &mut bytes,
        growing::<(Vec<Transition>, [usize; 2])>(states)?,
    )?;
    accumulate(&mut bytes, buffers::<Transition>(edges, states)?)?;

    // Builder::build retains the builder while allocating final states,
    // transition boxes, the remap and removed-empty lists, and visited bits.
    accumulate(&mut bytes, growing::<State>(states)?)?;
    accumulate(&mut bytes, array::<Transition>(mul(edges, 2)?)?)?;
    accumulate(&mut bytes, growing::<StateID>(states)?)?;
    accumulate(&mut bytes, growing::<(StateID, StateID)>(states)?)?;
    accumulate(&mut bytes, array::<bool>(states)?)?;

    // Final NFA property discovery owns a second sparse-set pair and an
    // epsilon traversal stack. Each visited state contributes each outgoing
    // edge at most once; duplicate pending edges are included in `edges`.
    accumulate(&mut bytes, array::<StateID>(mul(states, 2)?)?)?;
    accumulate(&mut bytes, growing::<StateID>(add(states, edges)?)?)?;
    accumulate(&mut bytes, implicit_metadata()?)?;
    // The compiler manufactures an AnyByte HIR for unanchored searching,
    // independently of the admitted input HIR's own source custody.
    accumulate(&mut bytes, super::syntax::unanchored_prefix_peak()?)?;
    // Compiler::new initializes the unused reverse RangeTrie with its
    // root and final nodes; each node contains one empty transition Vec.
    accumulate(&mut bytes, growing::<Vec<Transition>>(2)?)?;

    if paths.unicode {
        // Utf8BoundedMap::clear allocates 10,000 entries. Version wrap can
        // replace the table while the old one is still live. Entry payloads
        // are u16 + Vec<Transition> + StateID, all aligned at most usize.
        accumulate(&mut bytes, array::<(Vec<Transition>, [usize; 2])>(20_000)?)?;
        // Cached transition keys are copies of newly emitted builder
        // transitions. Even stale versions retain keys from those states,
        // so the total is bounded by all emitted paths, including repeats.
        accumulate(&mut bytes, buffers::<Transition>(edges, states)?)?;

        // A UTF-8 sequence has at most four bytes. Its unfinished prefix
        // stack therefore has five nodes, each with at most 256 outgoing
        // byte ranges. Two words cover Option<Utf8LastTransition> padding.
        accumulate(&mut bytes, growing::<(Vec<Transition>, [usize; 2])>(5)?)?;
        accumulate(&mut bytes, buffers::<Transition>(5 * 256, 5)?)?;
    }

    if paths.trie_nodes != 0 {
        // LiteralTrie owns two Vecs per state. Frame owns a chunk iterator,
        // slice iterator and two Vecs; eight words bound the two iterators
        // (three slices in StateChunksIter, one in the frame).
        accumulate(
            &mut bytes,
            growing::<(Vec<Transition>, Vec<(usize, usize)>)>(paths.trie_nodes)?,
        )?;
        accumulate(
            &mut bytes,
            buffers::<(u8, StateID)>(paths.trie_edges, paths.trie_nodes)?,
        )?;
        accumulate(
            &mut bytes,
            buffers::<(usize, usize)>(paths.trie_chunks, paths.trie_nodes)?,
        )?;
        accumulate(
            &mut bytes,
            growing::<([usize; 8], Vec<StateID>, Vec<Transition>)>(paths.trie_nodes)?,
        )?;
        accumulate(
            &mut bytes,
            buffers::<Transition>(paths.trie_edges, paths.trie_nodes)?,
        )?;
        accumulate(
            &mut bytes,
            buffers::<StateID>(paths.trie_chunks, paths.trie_nodes)?,
        )?;
    }

    // The logical size safeguard is independent of the allocation envelope:
    // upstream's size_limit checks lengths after insertion, whereas the
    // original loan above covers capacity and old/new allocation overlap.
    let logical = add(
        add(
            array::<(Vec<Transition>, [usize; 2])>(states)?,
            array::<Transition>(edges)?,
        )?,
        implicit_metadata()?,
    )?;
    Ok(CompilerGeometry {
        temporary_bytes: bytes,
        logical_limit: usize::try_from(logical).map_err(|_| overflow())?,
    })
}

pub(super) fn retained_bytes(nfa: &NFA) -> Result<u64, PredicateRegexError> {
    // memory_usage includes Inner, transition boxes and GroupInfo contents,
    // but uses state length rather than capacity and excludes Arc headers.
    // Add a full capacity envelope rather than subtracting that logical size.
    let mut bytes = u64::try_from(nfa.memory_usage()).map_err(|_| overflow())?;
    accumulate(&mut bytes, growing::<State>(nfa.states().len() as u64)?)?;
    accumulate(&mut bytes, implicit_metadata()?)?;
    accumulate(&mut bytes, array::<usize>(6)?)?;
    accumulate(&mut bytes, array::<CompiledPredicate>(1)?)?;
    Ok(bytes)
}

pub(super) fn search_bytes(nfa: &NFA) -> Result<u64, PredicateRegexError> {
    let states = nfa.states().len() as u64;
    let slots = nfa.group_info().slot_len() as u64;
    if nfa.pattern_len() != 1 || slots != 2 {
        return Err(overflow());
    }
    let mut pending = 1;
    for state in nfa.states() {
        let successors = match state {
            State::Union { alternates } => alternates.len() as u64,
            State::BinaryUnion { .. } => 2,
            State::Capture { .. } => 1,
            _ => 0,
        };
        pending = add(pending, successors)?;
    }

    // Cache has two active sets, each containing dense/sparse StateID
    // arrays and a 2*states+2 slot table. resize starts from empty, so the
    // capacity is its requested length (or the four-element Vec minimum).
    let mut bytes = array::<StateID>(mul(states.max(4), 4)?)?;
    accumulate(
        &mut bytes,
        array::<Option<usize>>(mul(add(mul(states, slots)?, slots)?.max(4), 2)?)?,
    )?;
    // find_iter owns Captures::matches in addition to Cache. One pattern
    // allocates its two overall-match offsets; cloning GroupInfo adds only
    // an Arc reference, whose retained allocation is already program-owned.
    accumulate(&mut bytes, array::<Option<usize>>(slots)?)?;
    // FollowEpsilon's two variants contain StateID or SmallIndex+offset.
    // Option<usize> deliberately exceeds the private niche-optimized offset;
    // the extra word covers its enum discriminant and alignment. Each state
    // is explored once per closure, so every union edge and capture restore
    // can be pending only once, plus the initial root exploration.
    accumulate(
        &mut bytes,
        growing::<(usize, Option<usize>, usize)>(pending)?,
    )?;
    Ok(bytes)
}

fn implicit_metadata() -> Result<u64, PredicateRegexError> {
    // One pattern and only unnamed group zero: no map entries or names.
    // Builder and final GroupInfo can coexist. Both outer vectors and their
    // one inner vector are included with their minimum/growth overlap.
    let mut bytes = 0;
    accumulate(&mut bytes, growing::<Vec<Option<std::sync::Arc<str>>>>(1)?)?;
    accumulate(&mut bytes, growing::<Option<std::sync::Arc<str>>>(1)?)?;
    accumulate(&mut bytes, growing::<StateID>(1)?)?;
    accumulate(&mut bytes, growing::<(usize, usize)>(1)?)?;
    accumulate(
        &mut bytes,
        growing::<std::collections::HashMap<std::sync::Arc<str>, usize>>(1)?,
    )?;
    accumulate(&mut bytes, growing::<Vec<Option<std::sync::Arc<str>>>>(1)?)?;
    accumulate(&mut bytes, growing::<Option<std::sync::Arc<str>>>(1)?)?;
    // Inner owns precisely these fields in nfa.rs. ByteClassSet privately
    // wraps two u128s; every other extent is a public dependency/std type.
    // Sum every field plus a full alignment gap per field, independent of
    // Rust's private field ordering. GroupInfoInner is audited the same way.
    accumulate(
        &mut bytes,
        private_record(&[
            extent::<Vec<State>>(),
            extent::<StateID>(),
            extent::<StateID>(),
            extent::<Vec<StateID>>(),
            extent::<std::sync::Arc<()>>(),
            extent::<[u128; 2]>(),
            extent::<ByteClasses>(),
            extent::<bool>(),
            extent::<bool>(),
            extent::<bool>(),
            extent::<bool>(),
            extent::<LookMatcher>(),
            extent::<LookSet>(),
            extent::<LookSet>(),
            extent::<usize>(),
        ])?,
    )?;
    accumulate(
        &mut bytes,
        private_record(&[
            extent::<Vec<(usize, usize)>>(),
            extent::<Vec<std::collections::HashMap<std::sync::Arc<str>, usize>>>(),
            extent::<Vec<Vec<Option<std::sync::Arc<str>>>>>(),
            extent::<usize>(),
        ])?,
    )?;
    // ArcInner has two atomic word counters before its payload. Include
    // possible padding to the NFA's u128 alignment and both other owners.
    accumulate(
        &mut bytes,
        add(
            array::<usize>(6)?,
            (align_of::<u128>() - 1 + 2 * (align_of::<usize>() - 1)) as u64,
        )?,
    )?;
    Ok(bytes)
}

fn extent<T>() -> (u64, u64) {
    (size_of::<T>() as u64, align_of::<T>() as u64)
}

fn private_record(fields: &[(u64, u64)]) -> Result<u64, PredicateRegexError> {
    let alignment = fields
        .iter()
        .map(|(_, alignment)| *alignment)
        .max()
        .unwrap_or(1);
    let mut bytes = 0;
    for &(width, _) in fields {
        bytes = add(bytes, add(width, alignment - 1)?)?;
    }
    Ok(bytes)
}

fn growing<T>(count: u64) -> Result<u64, PredicateRegexError> {
    // Pinned Vec growth doubles its previous capacity, with a four-element
    // minimum for these non-byte types. Charge both old and new allocations
    // at their separate 2*max(count,4) upper capacities before a realloc.
    array::<T>(mul(count.max(4), 4)?)
}

fn buffers<T>(elements: u64, buffers: u64) -> Result<u64, PredicateRegexError> {
    // Apply the same old/new capacity bound across separate transition
    // vectors, including a minimum allocation for every possible vector.
    array::<T>(add(mul(elements, 4)?, mul(buffers, 16)?)?)
}

fn array<T>(count: u64) -> Result<u64, PredicateRegexError> {
    mul(count, size_of::<T>() as u64)
}

fn accumulate(total: &mut u64, value: u64) -> Result<(), PredicateRegexError> {
    *total = add(*total, value)?;
    Ok(())
}

fn add(left: u64, right: u64) -> Result<u64, PredicateRegexError> {
    left.checked_add(right).ok_or_else(overflow)
}

fn mul(left: u64, right: u64) -> Result<u64, PredicateRegexError> {
    left.checked_mul(right).ok_or_else(overflow)
}

fn overflow() -> PredicateRegexError {
    PredicateRegexError::Admission(DecodeAdmissionError::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "predicate regex allocation geometry exceeds the original addressable resource bound",
    )))
}
