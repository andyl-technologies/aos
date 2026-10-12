//! Literal independent routes models; no owning codec derives these fields.

use super::super::support::{Value, hex};
use super::Case;

/// Returns the complete literal present and missing local routes models.
///
/// # Panics
/// Panics if a literal fixture contains malformed hexadecimal data.
pub(super) fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "carrier-child-present-route",
            family: "carrier-node",
            positive: true,
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
            full_entries: vec![(
                hex("70726573656e74"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
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
            role: "present route uid/24/O",
            scope: "",
            identity: "8c0f2c819445d0f712774d5494b74386be6467e12db588b24466fc9630a1b2d6",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-child-missing-route",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("6d697373696e67")),
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
            full_entries: vec![(
                hex("6d697373696e67"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
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
            role: "missing route uid/O",
            scope: "",
            identity: "31217cd40b98481be82f8042fafed9781520e5c430dfcb8057e77684c3eba3de",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-parent-present-route",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![
                        Value::Array(vec![
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
                        ]),
                        Value::Array(vec![
                            Value::Bytes(hex("7269676874")),
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
                        ]),
                    ]),
                ),
            ]),
            full_entries: vec![
                (
                    hex("6c656674"),
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
                ),
                (
                    hex("7269676874"),
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
                ),
            ],
            usage: "index",
            is_root: true,
            role: "present route uid/24/O",
            scope: "",
            identity: "b7d1ca00e335addee41001ae75767b73068426bd8bd687499d424a143827cf05",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-parent-missing-route",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![
                        Value::Array(vec![
                            Value::Bytes(hex("6c656674")),
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
                        ]),
                        Value::Array(vec![
                            Value::Bytes(hex("7269676874")),
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
                        ]),
                    ]),
                ),
            ]),
            full_entries: vec![
                (
                    hex("6c656674"),
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
                ),
                (
                    hex("7269676874"),
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
                ),
            ],
            usage: "index",
            is_root: true,
            role: "missing route uid/O",
            scope: "",
            identity: "085ef9cbabadf115cc5c43f8563d3a2809311905996c7523c8401cf39461a937",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-zero-missing-route",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("6d697373696e67")),
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
            full_entries: vec![(
                hex("6d697373696e67"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
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
            role: "missing route uid/O",
            scope: "",
            identity: "31217cd40b98481be82f8042fafed9781520e5c430dfcb8057e77684c3eba3de",
            source: "",
            lower: "",
            upper: "",
        },
    ]
}
