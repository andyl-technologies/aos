//! Checks that generic property nesting uses input-proportional bounds.

use super::{Error, Value, validate_preserved_map, validate_property};
use crate::cbor;
use crate::tree_format::Property;
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn resolution_preserves_deep_registered_generic_values() {
    let mut encoded = vec![0x81; 4096];
    encoded.push(0xf5);
    let properties = [Property {
        name: "future",
        value: &encoded,
    }];
    validate_preserved_map(&properties, &["future"])
        .expect("generic values have no graft-depth cap");
}

#[test]
fn resolution_accepts_deep_selectors_and_inheritance_wrappers() {
    let mut selector = Vec::new();
    for _ in 0..512 {
        selector.extend_from_slice(&[0x82, 0x63, b'n', b'o', b't']);
    }
    cbor::write_array(&mut selector, 2);
    cbor::write_text(&mut selector, "preset");
    cbor::write_text(&mut selector, "any");

    let property = Property {
        name: "trust",
        value: &selector,
    };
    assert_eq!(
        validate_property(&property).expect("deep selector").1,
        Value::Selector(&selector)
    );

    let mut wrapped = Vec::new();
    cbor::write_map(&mut wrapped, 2);
    cbor::write_text(&mut wrapped, "value");
    wrapped.extend_from_slice(&selector);
    cbor::write_text(&mut wrapped, "inherit");
    wrapped.push(0xf4);
    let property = Property {
        name: "trust",
        value: &wrapped,
    };
    assert_eq!(
        validate_property(&property)
            .expect("wrapped deep selector")
            .1,
        Value::Selector(&selector)
    );
}

#[test]
fn resolution_rejects_truncated_nesting_and_noncanonical_maps() {
    let encoded = vec![0x81; 4096];
    assert!(
        validate_preserved_map(
            &[Property {
                name: "future",
                value: &encoded
            }],
            &["future"]
        )
        .is_err()
    );

    let unsorted = [0xa2, 0x61, b'b', 0xf5, 0x61, b'a', 0xf4];
    assert_eq!(
        validate_preserved_map(
            &[Property {
                name: "future",
                value: &unsorted
            }],
            &["future"]
        ),
        Err(Error::InvalidValue)
    );
}

#[test]
fn resolution_source_selector_uses_closed_commit_sources() {
    for source in [
        "built", "uploaded", "imported", "merged", "derived", "migrated", "unknown",
    ] {
        let mut encoded = Vec::new();
        cbor::write_array(&mut encoded, 2);
        cbor::write_text(&mut encoded, "source");
        cbor::write_text(&mut encoded, source);
        let result = validate_property(&Property {
            name: "trust",
            value: &encoded,
        });
        assert_eq!(result.is_ok(), source != "unknown");
    }
}
