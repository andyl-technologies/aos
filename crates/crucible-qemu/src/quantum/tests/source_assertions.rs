//! Source-order assertions for the quantum implementation contract.

use super::QUANTUM_SOURCE;

pub(super) fn assert_source_order(source: &str, needles: &[&str], context: &str) {
    let mut offset = 0;
    for needle in needles {
        let remaining = &source[offset..];
        let Some(relative) = remaining.find(needle) else {
            panic!("{context}: missing `{needle}` after byte offset {offset}");
        };
        offset += relative + needle.len();
    }
}

pub(super) fn function_source(signature: &str) -> &str {
    let Some(start) = QUANTUM_SOURCE.find(signature) else {
        panic!("missing source signature `{signature}`");
    };
    let after_signature = &QUANTUM_SOURCE[start..];
    let Some(open_relative) = after_signature.find('{') else {
        panic!("missing body for source signature `{signature}`");
    };
    let open = start + open_relative;
    let mut depth = 0_i32;
    for (relative, ch) in QUANTUM_SOURCE[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &QUANTUM_SOURCE[start..open + relative + ch.len_utf8()];
                }
            }
            _ => {}
        }
    }

    panic!("unterminated source body for `{signature}`");
}
