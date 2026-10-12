//! Literal independent roots models; no owning codec derives these fields.

use super::super::support::{Value, hex};
use super::Case;

/// Returns the complete literal primary and missing-object roots models.
///
/// # Panics
/// Panics if a literal fixture contains malformed hexadecimal data.
pub(super) fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "carrier-empty-index",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "empty primary with no gaps",
            scope: "",
            identity: "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-child-gaps",
            family: "carrier-node",
            positive: true,
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
                                        "31217cd40b98481be82f8042fafed9781520e5c430dfcb8057e77684c3eba3de",
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
            full_entries: vec![(
                hex("030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "31217cd40b98481be82f8042fafed9781520e5c430dfcb8057e77684c3eba3de",
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
            )],
            usage: "index",
            is_root: true,
            role: "missing objects uid",
            scope: "",
            identity: "f833f28b631e28a851d9ec4d0bd8fe3e376f42dae07577393b11f48a34407473",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-child-primary",
            family: "carrier-node",
            positive: true,
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
                                    "f833f28b631e28a851d9ec4d0bd8fe3e376f42dae07577393b11f48a34407473",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![(
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
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
            )],
            usage: "index",
            is_root: true,
            role: "primary uid",
            scope: "",
            identity: "cc9cad20b00e7a8f49bfb4292c04f243cb6ff25232d87c0fb2529dee54b410ed",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-parent-gaps",
            family: "carrier-node",
            positive: true,
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
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex("030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
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
            )],
            usage: "index",
            is_root: true,
            role: "missing objects uid",
            scope: "",
            identity: "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-parent-primary",
            family: "carrier-node",
            positive: true,
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
                                    "b9d582827fb3dfe663103cddd043271e4878fd3c2850d470463be9a7401f0d27",
                                ),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![(
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
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
            )],
            usage: "index",
            is_root: true,
            role: "primary uid",
            scope: "",
            identity: "f517690891d770e2db6eff09009caa2a37eb98be658bd8ee19749c27adbf56e1",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-zero-gaps",
            family: "carrier-node",
            positive: true,
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
                                        "31217cd40b98481be82f8042fafed9781520e5c430dfcb8057e77684c3eba3de",
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
            full_entries: vec![(
                hex("030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "31217cd40b98481be82f8042fafed9781520e5c430dfcb8057e77684c3eba3de",
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
            )],
            usage: "index",
            is_root: true,
            role: "missing objects uid",
            scope: "",
            identity: "f833f28b631e28a851d9ec4d0bd8fe3e376f42dae07577393b11f48a34407473",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-zero-primary",
            family: "carrier-node",
            positive: true,
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
                                    "f833f28b631e28a851d9ec4d0bd8fe3e376f42dae07577393b11f48a34407473",
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
            role: "primary uid with zero candidates and nonempty G",
            scope: "",
            identity: "f215b67da8a292e4e25d3d4f022f907564ddf9df456f53971840850074f25429",
            source: "",
            lower: "",
            upper: "",
        },
    ]
}
