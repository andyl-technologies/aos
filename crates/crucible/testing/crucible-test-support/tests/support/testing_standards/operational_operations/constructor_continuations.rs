//! Binds constructor continuation to saved loans and physical last use.
//!
//! These contracts distinguish one bounded pass of an existing owner from
//! reissuing construction. They attest source structure only; entered-native
//! Source/rearm qualification remains required and is not supplied here.

use super::{Companion, Contract};

#[path = "constructor_continuations/facts.rs"]
mod facts;
#[path = "constructor_continuations/node.rs"]
mod node;
#[path = "constructor_continuations/installation.rs"]
mod installation;
#[path = "constructor_continuations/runtime.rs"]
mod runtime;
#[path = "constructor_continuations/target.rs"]
mod target;
#[path = "constructor_continuations/pending.rs"]
mod pending;
#[path = "constructor_continuations/cleanup.rs"]
mod cleanup;
#[path = "constructor_continuations/members.rs"]
mod members;
#[path = "constructor_continuations/native.rs"]
mod native;
#[path = "constructor_continuations/retained.rs"]
mod retained;

pub(super) const CONTRACTS: &[Contract] = &[
    node::CONTRACT,
    installation::CONTRACT,
    runtime::CONTRACT,
    target::CONTRACT,
    pending::CONTRACT,
    cleanup::CONTRACT,
    members::CONTRACT,
    native::CONTRACT,
    retained::CONTRACT,
];

/// Mutates only an owned continuation's actual receiver or argument.
#[cfg(test)]
pub(super) fn altered_expression(expression: &str) -> String {
    if !CONTRACTS.iter().any(|contract| {
        contract
            .expressions
            .iter()
            .any(|(actual, _)| *actual == expression)
    }) {
        return expression.to_owned();
    }
    let Some(offset) = expression.find('(') else {
        return expression.to_owned();
    };
    let mut altered = expression.to_owned();
    altered.insert_str(offset + 1, "foreign_owner, ");
    altered
}

#[cfg(test)]
#[path = "constructor_continuations/tests.rs"]
mod tests;
