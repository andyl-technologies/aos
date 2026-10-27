//! Literal independent controls models; no owning codec derives these fields.

use super::super::support::{Value, hex};
use super::Case;

/// Returns the complete literal contextual carrier refusals models.
///
/// # Panics
/// Panics if a literal fixture contains malformed hexadecimal data.
pub(super) fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "carrier-bad-primary-P-substituted-for-O",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "b7d1ca00e335addee41001ae75767b73068426bd8bd687499d424a143827cf05",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "b7d1ca00e335addee41001ae75767b73068426bd8bd687499d424a143827cf05",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-primary-extra-attribute",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![
                                    (Value::Text("uid"), Value::UInt(24)),
                                    (
                                        Value::Text("index.occurrences"),
                                        Value::Bytes(hex(
                                            "b7d1ca00e335addee41001ae75767b73068426bd8bd687499d424a143827cf05",
                                        )),
                                    ),
                                ]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-primary-extra-provenance",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "b7d1ca00e335addee41001ae75767b73068426bd8bd687499d424a143827cf05",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(11),
                                Value::Bytes(hex(
                                    "0000000000000000000000000000000000000000000000000000000000000000",
                                )),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-primary-multiple-targets",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "b7d1ca00e335addee41001ae75767b73068426bd8bd687499d424a143827cf05",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![
                                    Value::Bytes(hex(
                                        "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                    )),
                                    Value::Bytes(hex(
                                        "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                    )),
                                ]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "format",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-primary-wrong-entry-kind",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "b7d1ca00e335addee41001ae75767b73068426bd8bd687499d424a143827cf05",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "format",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-primary-wrong-pointer-width",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "00000000000000000000000000000000000000000000000000000000000000",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-primary-empty-continuation",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "source-relationship",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-route-omitted-repeated-graft",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("6c656674")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "8c0f2c819445d0f712774d5494b74386be6467e12db588b24466fc9630a1b2d6",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "source-relationship",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-route-extra-source-key",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("616273656e74")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "8c0f2c819445d0f712774d5494b74386be6467e12db588b24466fc9630a1b2d6",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "source-relationship",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-route-dot-component",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("2e2e")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "8c0f2c819445d0f712774d5494b74386be6467e12db588b24466fc9630a1b2d6",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-route-component-256",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "8c0f2c819445d0f712774d5494b74386be6467e12db588b24466fc9630a1b2d6",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-route-forbidden-gap-properties",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("6c656674")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "8c0f2c819445d0f712774d5494b74386be6467e12db588b24466fc9630a1b2d6",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-route-terminal-at-graft",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("6c656674")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "source-relationship",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-terminal-explicit-empty-attrs",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("70726573656e74")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (Value::UInt(9), Value::Map(vec![])),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "carrier-role",
            identity: "",
            source: "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-terminal-forward-pointer-at-file",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("70726573656e74")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "source-relationship",
            identity: "",
            source: "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-missing-route-actually-present",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("70726573656e74")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "missing-route",
            scope: "source-relationship",
            identity: "",
            source: "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-terminal-wrong-O",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("70726573656e74")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "source-relationship",
            identity: "",
            source: "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-primary-omitted-gap-binding",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "b7d1ca00e335addee41001ae75767b73068426bd8bd687499d424a143827cf05",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "source-relationship",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-primary-bound-empty-G",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "b7d1ca00e335addee41001ae75767b73068426bd8bd687499d424a143827cf05",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "source-relationship",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-target-not-key-O",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "085ef9cbabadf115cc5c43f8563d3a2809311905996c7523c8401cf39461a937",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "gap",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-terminal-instead-of-forward",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "gap",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-extra-object",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![
                        Value::Array(vec![
                            Value::Bytes(hex(
                                "0000000000000000000000000000000000000000000000000000000000000000",
                            )),
                            Value::UInt(0),
                            Value::Map(vec![
                                (Value::UInt(1), Value::UInt(7)),
                                (
                                    Value::UInt(9),
                                    Value::Map(vec![(
                                        Value::Text("index.occurrences"),
                                        Value::Bytes(hex(
                                            "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
                                        )),
                                    )]),
                                ),
                                (
                                    Value::UInt(14),
                                    Value::Array(vec![Value::Bytes(hex(
                                        "0000000000000000000000000000000000000000000000000000000000000000",
                                    ))]),
                                ),
                            ]),
                        ]),
                        Value::Array(vec![
                            Value::Bytes(hex(
                                "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                            )),
                            Value::UInt(0),
                            Value::Map(vec![
                                (Value::UInt(1), Value::UInt(7)),
                                (
                                    Value::UInt(9),
                                    Value::Map(vec![(
                                        Value::Text("index.occurrences"),
                                        Value::Bytes(hex(
                                            "085ef9cbabadf115cc5c43f8563d3a2809311905996c7523c8401cf39461a937",
                                        )),
                                    )]),
                                ),
                                (
                                    Value::UInt(14),
                                    Value::Array(vec![Value::Bytes(hex(
                                        "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                    ))]),
                                ),
                            ]),
                        ]),
                    ]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "gap",
            scope: "source-relationship",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-binding-bare",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Text(
                            "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                        ),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-binding-inherits",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(true)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-binding-uppercase",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-binding-extra-property",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![
                        (Value::Text("domain"), Value::Text("public")),
                        (
                            Value::Text("index-gaps"),
                            Value::Map(vec![
                                (
                                    Value::Text("value"),
                                    Value::Text(
                                        "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                    ),
                                ),
                                (Value::Text("inherit"), Value::Bool(false)),
                            ]),
                        ),
                    ]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-binding-on-namespace-owner",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "ordinary-namespace",
            scope: "property-placement",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-binding-on-route-root",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "present-route",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-binding-on-G-root",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "gap",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-gap-binding-on-nonroot",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-gaps"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Text(
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: false,
            role: "primary",
            scope: "format-context",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-primary-explicit-empty-properties",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (Value::UInt(3), Value::Map(vec![])),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-bad-local-route-reused-as-primary",
            family: "carrier-negative",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("6c6f63616c2d726f7574652d6b6579")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(
                                    Value::Text("index.occurrences"),
                                    Value::Bytes(hex(
                                        "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
                                    )),
                                )]),
                            ),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "primary",
            scope: "carrier-role",
            identity: "",
            source: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            lower: "",
            upper: "",
        },
    ]
}
