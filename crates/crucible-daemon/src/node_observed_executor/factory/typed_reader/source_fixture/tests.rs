//! Checks pre-allocation encoding credit without source or native authority.

use crucible_node_provider::ProviderError;
use serde::{Serialize, Serializer};
use std::cell::Cell;

struct ObservedSerialization<'a> {
    calls: &'a Cell<usize>,
    body: &'a str,
}

impl Serialize for ObservedSerialization<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.calls.set(self.calls.get() + 1);
        serializer.serialize_str(self.body)
    }
}

#[test]
fn original_borrowed_credit_refuses_before_value_reconstruction() -> Result<(), ProviderError> {
    let calls = Cell::new(0);
    let original = ObservedSerialization {
        calls: &calls,
        body: "\u{0}\u{0}\u{0}",
    };
    // Escaped controls each require six bytes, plus both string delimiters.
    assert!(super::launch::encode(&original, 19).is_err());
    assert_eq!(calls.get(), 1);

    calls.set(0);
    let exact = super::launch::encode(&original, 20)?;
    assert_eq!(exact.len(), 20);
    assert_eq!(calls.get(), 2);
    Ok(())
}
