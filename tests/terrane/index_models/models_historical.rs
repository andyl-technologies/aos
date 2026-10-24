//! Literal independent historical models; no owning codec derives these fields.

use super::super::support::{Value, hex};
use super::Case;

/// Returns the complete literal historical and enclosing field witnesses models.
///
/// # Panics
/// Panics if a literal fixture contains malformed hexadecimal data.
pub(super) fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "index-root-one-matching-object",
            family: "historical-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex("1818abababababababababababababababababababababababababababababababab"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(14),
                        Value::Array(vec![Value::Bytes(hex(
                            "abababababababababababababababababababababababababababababababab",
                        ))]),
                    ),
                ]),
            )],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "54a403b34202a7d94b4b95e0ec584d2aa6c8a15b471d4092e083eaf69d69ede1",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "ordinary-owner-with-index-binding",
            family: "historical-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("66696c65")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(1)),
                            (Value::UInt(2), Value::UInt(420)),
                            (Value::UInt(3), Value::UInt(1)),
                            (
                                Value::UInt(4),
                                Value::Array(vec![
                                    Value::UInt(0),
                                    Value::Bytes(hex(
                                        "abababababababababababababababababababababababababababababababab",
                                    )),
                                ]),
                            ),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(Value::Text("uid"), Value::UInt(24))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-roots"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Map(vec![(
                                    Value::Text("uid"),
                                    Value::Text(
                                        "54a403b34202a7d94b4b95e0ec584d2aa6c8a15b471d4092e083eaf69d69ede1",
                                    ),
                                )]),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![(
                hex("66696c65"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(1)),
                    (Value::UInt(2), Value::UInt(420)),
                    (Value::UInt(3), Value::UInt(1)),
                    (
                        Value::UInt(4),
                        Value::Array(vec![
                            Value::UInt(0),
                            Value::Bytes(hex(
                                "abababababababababababababababababababababababababababababababab",
                            )),
                        ]),
                    ),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(Value::Text("uid"), Value::UInt(24))]),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "",
            identity: "7c2eff97aa81d83999f89cb55ebdb4c8f5e7a8ac0f39a9a26f641d3810d13704",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "ordinary-root-explicit-empty-properties",
            family: "historical-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (Value::UInt(3), Value::Map(vec![])),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "",
            identity: "cc955cb92cf9f968bad7071b18d4e2a1abb1e302e6cd2d7958c1629cbacbab37",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "ordinary-root-absent-properties",
            family: "historical-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "",
            identity: "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "ordinary-owner-explicit-empty-binding",
            family: "historical-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-roots"),
                        Value::Map(vec![
                            (Value::Text("value"), Value::Map(vec![])),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "",
            identity: "eb5fc2ee4d90bed9a0b39313b2741d48c4acde4f0333b1196b3a6b03a149ed3f",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "ordinary-owner-binding-on-nonroot",
            family: "historical-node",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("66696c65")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(1)),
                            (Value::UInt(2), Value::UInt(420)),
                            (Value::UInt(3), Value::UInt(1)),
                            (
                                Value::UInt(4),
                                Value::Array(vec![
                                    Value::UInt(0),
                                    Value::Bytes(hex(
                                        "abababababababababababababababababababababababababababababababab",
                                    )),
                                ]),
                            ),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(Value::Text("uid"), Value::UInt(24))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-roots"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Map(vec![(
                                    Value::Text("uid"),
                                    Value::Text(
                                        "54a403b34202a7d94b4b95e0ec584d2aa6c8a15b471d4092e083eaf69d69ede1",
                                    ),
                                )]),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: false,
            role: "",
            scope: "format-context",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "ordinary-graft-binding-override",
            family: "historical-node",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("6772616674")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "7c2eff97aa81d83999f89cb55ebdb4c8f5e7a8ac0f39a9a26f641d3810d13704",
                                )),
                            ),
                            (
                                Value::UInt(7),
                                Value::Map(vec![(
                                    Value::Text("index-roots"),
                                    Value::Map(vec![
                                        (
                                            Value::Text("value"),
                                            Value::Map(vec![(
                                                Value::Text("uid"),
                                                Value::Text(
                                                    "54a403b34202a7d94b4b95e0ec584d2aa6c8a15b471d4092e083eaf69d69ede1",
                                                ),
                                            )]),
                                        ),
                                        (Value::Text("inherit"), Value::Bool(false)),
                                    ]),
                                )]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "property-placement",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "ordinary-owner-extra-node-field",
            family: "historical-node",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("66696c65")),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(1)),
                            (Value::UInt(2), Value::UInt(420)),
                            (Value::UInt(3), Value::UInt(1)),
                            (
                                Value::UInt(4),
                                Value::Array(vec![
                                    Value::UInt(0),
                                    Value::Bytes(hex(
                                        "abababababababababababababababababababababababababababababababab",
                                    )),
                                ]),
                            ),
                            (
                                Value::UInt(9),
                                Value::Map(vec![(Value::Text("uid"), Value::UInt(24))]),
                            ),
                        ]),
                    ])]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-roots"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Map(vec![(
                                    Value::Text("uid"),
                                    Value::Text(
                                        "54a403b34202a7d94b4b95e0ec584d2aa6c8a15b471d4092e083eaf69d69ede1",
                                    ),
                                )]),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
                (Value::UInt(4), Value::UInt(0)),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "format",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-target-wrong-width",
            family: "historical-node",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "ababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "",
            scope: "format",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-targets-unsorted",
            family: "historical-node",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![
                                    Value::Bytes(hex(
                                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                                    )),
                                    Value::Bytes(hex(
                                        "abababababababababababababababababababababababababababababababab",
                                    )),
                                ]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "",
            scope: "format",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-key-order-unsorted",
            family: "historical-node",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![
                        Value::Array(vec![
                            Value::Bytes(hex(
                                "1818abababababababababababababababababababababababababababababababab",
                            )),
                            Value::UInt(0),
                            Value::Map(vec![
                                (Value::UInt(1), Value::UInt(7)),
                                (
                                    Value::UInt(14),
                                    Value::Array(vec![Value::Bytes(hex(
                                        "abababababababababababababababababababababababababababababababab",
                                    ))]),
                                ),
                            ]),
                        ]),
                        Value::Array(vec![
                            Value::Bytes(hex(
                                "00abababababababababababababababababababababababababababababababab",
                            )),
                            Value::UInt(0),
                            Value::Map(vec![
                                (Value::UInt(1), Value::UInt(7)),
                                (
                                    Value::UInt(14),
                                    Value::Array(vec![Value::Bytes(hex(
                                        "abababababababababababababababababababababababababababababababab",
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
            role: "",
            scope: "format",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-first-shared-nonzero",
            family: "historical-node",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(1),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "",
            scope: "format",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-entry-extra-field",
            family: "historical-node",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (Value::UInt(2), Value::UInt(420)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "",
            scope: "format",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-object-suffix-mismatch",
            family: "historical-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex("1818aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(14),
                        Value::Array(vec![Value::Bytes(hex(
                            "abababababababababababababababababababababababababababababababab",
                        ))]),
                    ),
                ]),
            )],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "64fe4cc8b39d364364f13e71f362a179a1794ac49e68d75aac31d8eed3446a24",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-generic-multiple-targets",
            family: "historical-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![
                                    Value::Bytes(hex(
                                        "abababababababababababababababababababababababababababababababab",
                                    )),
                                    Value::Bytes(hex(
                                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                                    )),
                                ]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex("1818abababababababababababababababababababababababababababababababab"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(14),
                        Value::Array(vec![
                            Value::Bytes(hex(
                                "abababababababababababababababababababababababababababababababab",
                            )),
                            Value::Bytes(hex(
                                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            )),
                        ]),
                    ),
                ]),
            )],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "eb7bdbd2b91a90f16ed68b18c32d2c9d894d21c0d62147c3470feab987c45dda",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-root-in-ordinary-context",
            family: "historical-node",
            positive: false,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "format-context",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "historical-owner-detached-index-recipe",
            family: "historical-recipe",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::Text("index")),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Bytes(hex(
                        "7c2eff97aa81d83999f89cb55ebdb4c8f5e7a8ac0f39a9a26f641d3810d13704",
                    ))]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![
                        (Value::Text("profile"), Value::Text("terrane-index/v1")),
                        (Value::Text("attribute"), Value::Text("uid")),
                    ]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "owner-binding-uid-containing-node",
            family: "primitive-containing-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-roots"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Map(vec![(
                                    Value::Text("uid"),
                                    Value::Text(
                                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                    ),
                                )]),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "",
            identity: "dcd09742f6250b75861bcf8818764b4ac8d583d6e8ddaf3620d8ee35bc6f18cd",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "owner-binding-empty-containing-node",
            family: "primitive-containing-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-roots"),
                        Value::Map(vec![
                            (Value::Text("value"), Value::Map(vec![])),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "",
            identity: "eb5fc2ee4d90bed9a0b39313b2741d48c4acde4f0333b1196b3a6b03a149ed3f",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "owner-binding-two-containing-node",
            family: "primitive-containing-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![(
                        Value::Text("index-roots"),
                        Value::Map(vec![
                            (
                                Value::Text("value"),
                                Value::Map(vec![
                                    (
                                        Value::Text("gid"),
                                        Value::Text(
                                            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                        ),
                                    ),
                                    (
                                        Value::Text("uid"),
                                        Value::Text(
                                            "abababababababababababababababababababababababababababababababab",
                                        ),
                                    ),
                                ]),
                            ),
                            (Value::Text("inherit"), Value::Bool(false)),
                        ]),
                    )]),
                ),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "",
            scope: "",
            identity: "0beabf1f79d54b70903c7763545863d334e14c2cced63aacae829d41c15997a8",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-key-uint-containing-node",
            family: "primitive-containing-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "1818abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex("1818abababababababababababababababababababababababababababababababab"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(14),
                        Value::Array(vec![Value::Bytes(hex(
                            "abababababababababababababababababababababababababababababababab",
                        ))]),
                    ),
                ]),
            )],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "54a403b34202a7d94b4b95e0ec584d2aa6c8a15b471d4092e083eaf69d69ede1",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-key-opaque-bytes-containing-node",
            family: "primitive-containing-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "43002fffabababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex("43002fffabababababababababababababababababababababababababababababababab"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(14),
                        Value::Array(vec![Value::Bytes(hex(
                            "abababababababababababababababababababababababababababababababab",
                        ))]),
                    ),
                ]),
            )],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "8a5fcc039054062700da3e15784ee3badaed97d9b5fc5c4bb7e6cf2fa82995a5",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-key-array-containing-node",
            family: "primitive-containing-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "8300412ff6abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex("8300412ff6abababababababababababababababababababababababababababababababab"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(14),
                        Value::Array(vec![Value::Bytes(hex(
                            "abababababababababababababababababababababababababababababababab",
                        ))]),
                    ),
                ]),
            )],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "0903c85b57b1c6986edb0cfa26c9f91c44df5d0b8a249ed299cde893ad3f5d46",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-key-map-containing-node",
            family: "primitive-containing-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "a20141006375696400abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex(
                    "a20141006375696400abababababababababababababababababababababababababababababababab",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(14),
                        Value::Array(vec![Value::Bytes(hex(
                            "abababababababababababababababababababababababababababababababab",
                        ))]),
                    ),
                ]),
            )],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "01a1719083ac2e3cfd499f0a78278f906f7ff0e90a692083029da7fa47722102",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-key-exact-4096-containing-node",
            family: "primitive-containing-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "590fdd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex(
                    "590fdd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000abababababababababababababababababababababababababababababababab",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(14),
                        Value::Array(vec![Value::Bytes(hex(
                            "abababababababababababababababababababababababababababababababab",
                        ))]),
                    ),
                ]),
            )],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "f1c1890cc23b2606fcf4439655871e66f6d24b73fccd1df3dd48166b86eb21d5",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-key-deep-valid-4096-containing-node",
            family: "primitive-containing-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "8181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818100abababababababababababababababababababababababababababababababab",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(7)),
                            (
                                Value::UInt(14),
                                Value::Array(vec![Value::Bytes(hex(
                                    "abababababababababababababababababababababababababababababababab",
                                ))]),
                            ),
                        ]),
                    ])]),
                ),
            ]),
            full_entries: vec![(
                hex(
                    "8181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818100abababababababababababababababababababababababababababababababab",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(14),
                        Value::Array(vec![Value::Bytes(hex(
                            "abababababababababababababababababababababababababababababababab",
                        ))]),
                    ),
                ]),
            )],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "bd92d3df7d17a4340cd190f10778768b46a262e2cfb02a4f1353a3af00debb66",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-legacy-complete-commit",
            family: "historical-commit",
            positive: true,
            model: Value::Map(vec![
                (
                    Value::UInt(1),
                    Value::Bytes(hex(
                        "0101010101010101010101010101010101010101010101010101010101010101",
                    )),
                ),
                (Value::UInt(2), Value::Array(vec![])),
                (
                    Value::UInt(3),
                    Value::Map(vec![
                        (Value::UInt(1), Value::Text("issuer")),
                        (
                            Value::UInt(2),
                            Value::Bytes(hex("02020202020202020202020202020202")),
                        ),
                        (Value::UInt(3), Value::Text("subject")),
                        (Value::UInt(4), Value::UInt(2)),
                        (Value::UInt(6), Value::Text("fixture process")),
                        (Value::UInt(7), Value::UInt(24)),
                        (Value::UInt(8), Value::UInt(7)),
                        (Value::UInt(9), Value::UInt(1)),
                    ]),
                ),
                (Value::UInt(4), Value::UInt(24)),
                (Value::UInt(5), Value::Text("")),
                (
                    Value::UInt(6),
                    Value::Map(vec![
                        (Value::UInt(1), Value::UInt(1)),
                        (Value::UInt(2), Value::Text("cdc-1m")),
                        (
                            Value::UInt(3),
                            Value::Map(vec![
                                (Value::UInt(1), Value::Text("index")),
                                (
                                    Value::UInt(2),
                                    Value::Array(vec![
                                        Value::Bytes(hex(
                                            "0101010101010101010101010101010101010101010101010101010101010101",
                                        )),
                                        Value::Bytes(hex(
                                            "0202020202020202020202020202020202020202020202020202020202020202",
                                        )),
                                    ]),
                                ),
                            ]),
                        ),
                    ]),
                ),
            ]),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "96fcfc6ca92638183319214b4694ab33d72b64a557fc150a8264f4c137febc78",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "index-source-direct-chunk-O",
            family: "source-chunk",
            positive: true,
            model: Value::Bytes(hex(
                "696e65727420442d313034206469726563742d6368756e6b20666978747572650a",
            )),
            full_entries: vec![],
            usage: "index",
            is_root: true,
            role: "",
            scope: "",
            identity: "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
            source: "",
            lower: "",
            upper: "",
        },
    ]
}
