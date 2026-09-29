//! Matches canonical byte globs and proves grant-language containment.
//!
//! Each glob becomes a small nondeterministic automaton. Containment explores
//! pairs of determinized states and rejects a child accepting a word the
//! parent union rejects. A fixed exploration budget fails closed on expensive
//! inputs; it never approximates a widening pattern as narrower (AUTH-14/20).

use alloc::{collections::BTreeSet, vec, vec::Vec};

use super::{Grant, Unauthorized};

const MAX_STATES: usize = 16_384;

#[derive(Clone, Copy, Debug)]
enum Atom {
    Literal(u8),
    Star,
    Deep,
}

fn atoms(pattern: &str) -> Vec<Atom> {
    let mut result = Vec::new();
    let mut bytes = pattern.bytes().peekable();
    while let Some(byte) = bytes.next() {
        if byte == b'*' {
            if bytes.peek() == Some(&b'*') {
                bytes.next();
                result.push(Atom::Deep);
            } else {
                result.push(Atom::Star);
            }
        } else {
            result.push(Atom::Literal(byte));
        }
    }
    result
}

fn grant_atoms(pattern: &str) -> Vec<Atom> {
    let (reference, root) = pattern.split_once(':').unwrap_or((pattern, "**"));
    let mut result = atoms(reference);
    result.push(Atom::Literal(0));
    result.extend(atoms(root));
    result
}

fn closure(machine: &[Atom], state: &mut Vec<usize>) {
    let mut cursor = 0;
    while cursor < state.len() {
        let position = state[cursor];
        if matches!(machine.get(position), Some(Atom::Star | Atom::Deep))
            && !state.contains(&(position + 1))
        {
            state.push(position + 1);
        }
        cursor += 1;
    }
    state.sort_unstable();
}

fn start(machine: &[Atom]) -> Vec<usize> {
    let mut state = vec![0];
    closure(machine, &mut state);
    state
}

fn step(machine: &[Atom], state: &[usize], byte: u8) -> Vec<usize> {
    let mut next = Vec::new();
    for &position in state {
        let target = match machine.get(position) {
            Some(Atom::Literal(literal)) if *literal == byte => Some(position + 1),
            Some(Atom::Star) if byte != b'/' && byte != 0 => Some(position),
            Some(Atom::Deep) if byte != 0 => Some(position),
            _ => None,
        };
        if let Some(target) = target {
            if !next.contains(&target) {
                next.push(target);
            }
        }
    }
    closure(machine, &mut next);
    next
}

pub(super) fn matches(pattern: &str, bytes: &[u8]) -> bool {
    let machine = atoms(pattern);
    let state = bytes.iter().fold(start(&machine), |state, &byte| {
        step(&machine, &state, byte)
    });
    state.contains(&machine.len())
}

pub(super) fn grant_matches(pattern: &str, reference: &[u8], root: &[u8]) -> bool {
    let (reference_pattern, root_pattern) = pattern.split_once(':').unwrap_or((pattern, "**"));
    matches(reference_pattern, reference) && matches(root_pattern, root)
}

pub(super) fn contained(child: &Grant, parents: &[Grant], verb: u8) -> Result<bool, Unauthorized> {
    let child_machine = grant_atoms(&child.pattern);
    let parent_machines: Vec<_> = parents
        .iter()
        .filter(|grant| grant.verbs.effective() & verb != 0)
        .map(|grant| grant_atoms(&grant.pattern))
        .collect();

    // Literal bytes and one representative of each wildcard class suffice:
    // transitions distinguish only literal equality, slash, and the separator.
    let mut alphabet = BTreeSet::from([0, b'/']);
    for atom in child_machine.iter().chain(parent_machines.iter().flatten()) {
        if let Atom::Literal(byte) = atom {
            alphabet.insert(*byte);
        }
    }
    if let Some(other) = (1..=255).find(|byte| !alphabet.contains(byte)) {
        alphabet.insert(other);
    }

    let initial = (
        start(&child_machine),
        parent_machines.iter().map(|machine| start(machine)).collect::<Vec<_>>(),
    );
    let mut seen = BTreeSet::from([initial.clone()]);
    let mut pending = vec![initial];
    while let Some((child_state, parent_states)) = pending.pop() {
        if child_state.contains(&child_machine.len())
            && !parent_machines.iter().zip(&parent_states).any(|(machine, state)| state.contains(&machine.len()))
        {
            return Ok(false);
        }
        for &byte in &alphabet {
            let next_child = step(&child_machine, &child_state, byte);
            if next_child.is_empty() {
                continue;
            }
            let next_parents = parent_machines.iter().zip(&parent_states)
                .map(|(machine, state)| step(machine, state, byte)).collect();
            let next = (next_child, next_parents);
            if seen.insert(next.clone()) {
                if seen.len() > MAX_STATES {
                    return Err(Unauthorized);
                }
                pending.push(next);
            }
        }
    }
    Ok(true)
}

pub(super) fn canonical_reference(bytes: &[u8]) -> bool {
    bytes.starts_with(b"refs/") && canonical_components(bytes, false)
}

pub(super) fn canonical_root(bytes: &[u8]) -> bool {
    bytes == b"/" || bytes.strip_prefix(b"/").is_some_and(|path| canonical_components(path, false))
}

fn canonical_components(bytes: &[u8], pattern: bool) -> bool {
    !bytes.is_empty() && bytes.len() <= 4096 && bytes.split(|byte| *byte == b'/').all(|component| {
        !component.is_empty() && component.len() <= 255 && component != b"." && component != b".."
            && component.iter().all(|byte| *byte != 0 && *byte != b':' && (pattern || *byte != b'*'))
    })
}

pub(super) fn valid_grant(pattern: &str) -> bool {
    let (reference, root) = pattern.split_once(':').unwrap_or((pattern, "/"));
    reference.starts_with("refs/") && canonical_components(reference.as_bytes(), true)
        && (root == "/" || root.strip_prefix('/').is_some_and(|path| canonical_components(path.as_bytes(), true)))
}
