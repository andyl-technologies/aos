//! Literal independent sources models; no owning codec derives these fields.

use super::super::support::{Value, hex};
use super::Case;

/// Returns the complete literal namespace source roots models.
///
/// # Panics
/// Panics if a literal fixture contains malformed hexadecimal data.
pub(super) fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "carrier-empty-ordinary",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (Value::UInt(2), Value::Array(vec![])),
            ]),
            full_entries: vec![],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-child-source",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![
                        Value::Array(vec![
                            Value::Bytes(hex("6d697373696e67")),
                            Value::UInt(0),
                            Value::Map(vec![
                                (Value::UInt(1), Value::UInt(1)),
                                (Value::UInt(2), Value::UInt(420)),
                                (Value::UInt(3), Value::UInt(33)),
                                (
                                    Value::UInt(4),
                                    Value::Array(vec![
                                        Value::UInt(0),
                                        Value::Bytes(hex(
                                            "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                        )),
                                    ]),
                                ),
                            ]),
                        ]),
                        Value::Array(vec![
                            Value::Bytes(hex("70726573656e74")),
                            Value::UInt(0),
                            Value::Map(vec![
                                (Value::UInt(1), Value::UInt(1)),
                                (Value::UInt(2), Value::UInt(420)),
                                (Value::UInt(3), Value::UInt(33)),
                                (
                                    Value::UInt(4),
                                    Value::Array(vec![
                                        Value::UInt(0),
                                        Value::Bytes(hex(
                                            "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                        )),
                                    ]),
                                ),
                                (
                                    Value::UInt(9),
                                    Value::Map(vec![(Value::Text("uid"), Value::UInt(24))]),
                                ),
                            ]),
                        ]),
                    ]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![
                        (Value::Text("index"), Value::Array(vec![Value::Text("uid")])),
                        (Value::Text("domain"), Value::Text("public")),
                        (
                            Value::Text("index-roots"),
                            Value::Map(vec![
                                (
                                    Value::Text("value"),
                                    Value::Map(vec![(
                                        Value::Text("uid"),
                                        Value::Text(
                                            "cc9cad20b00e7a8f49bfb4292c04f243cb6ff25232d87c0fb2529dee54b410ed",
                                        ),
                                    )]),
                                ),
                                (Value::Text("inherit"), Value::Bool(false)),
                            ]),
                        ),
                    ]),
                ),
            ]),
            full_entries: vec![
                (
                    hex("6d697373696e67"),
                    Value::Map(vec![
                        (Value::UInt(1), Value::UInt(1)),
                        (Value::UInt(2), Value::UInt(420)),
                        (Value::UInt(3), Value::UInt(33)),
                        (
                            Value::UInt(4),
                            Value::Array(vec![
                                Value::UInt(0),
                                Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                )),
                            ]),
                        ),
                    ]),
                ),
                (
                    hex("70726573656e74"),
                    Value::Map(vec![
                        (Value::UInt(1), Value::UInt(1)),
                        (Value::UInt(2), Value::UInt(420)),
                        (Value::UInt(3), Value::UInt(33)),
                        (
                            Value::UInt(4),
                            Value::Array(vec![
                                Value::UInt(0),
                                Value::Bytes(hex(
                                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                                )),
                            ]),
                        ),
                        (
                            Value::UInt(9),
                            Value::Map(vec![(Value::Text("uid"), Value::UInt(24))]),
                        ),
                    ]),
                ),
            ],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-parent-owner",
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
                                (Value::UInt(1), Value::UInt(4)),
                                (
                                    Value::UInt(6),
                                    Value::Bytes(hex(
                                        "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
                                    )),
                                ),
                                (
                                    Value::UInt(7),
                                    Value::Map(vec![(
                                        Value::Text("acl"),
                                        Value::Array(vec![Value::Array(vec![
                                            Value::Text("reader-left"),
                                            Value::UInt(1),
                                        ])]),
                                    )]),
                                ),
                            ]),
                        ]),
                        Value::Array(vec![
                            Value::Bytes(hex("7269676874")),
                            Value::UInt(0),
                            Value::Map(vec![
                                (Value::UInt(1), Value::UInt(4)),
                                (
                                    Value::UInt(6),
                                    Value::Bytes(hex(
                                        "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
                                    )),
                                ),
                                (
                                    Value::UInt(7),
                                    Value::Map(vec![(
                                        Value::Text("acl"),
                                        Value::Array(vec![Value::Array(vec![
                                            Value::Text("reader-right"),
                                            Value::UInt(1),
                                        ])]),
                                    )]),
                                ),
                            ]),
                        ]),
                    ]),
                ),
                (
                    Value::UInt(3),
                    Value::Map(vec![
                        (Value::Text("index"), Value::Array(vec![Value::Text("uid")])),
                        (Value::Text("domain"), Value::Text("public")),
                        (
                            Value::Text("index-roots"),
                            Value::Map(vec![
                                (
                                    Value::Text("value"),
                                    Value::Map(vec![(
                                        Value::Text("uid"),
                                        Value::Text(
                                            "f517690891d770e2db6eff09009caa2a37eb98be658bd8ee19749c27adbf56e1",
                                        ),
                                    )]),
                                ),
                                (Value::Text("inherit"), Value::Bool(false)),
                            ]),
                        ),
                    ]),
                ),
            ]),
            full_entries: vec![
                (
                    hex("6c656674"),
                    Value::Map(vec![
                        (Value::UInt(1), Value::UInt(4)),
                        (
                            Value::UInt(6),
                            Value::Bytes(hex(
                                "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
                            )),
                        ),
                        (
                            Value::UInt(7),
                            Value::Map(vec![(
                                Value::Text("acl"),
                                Value::Array(vec![Value::Array(vec![
                                    Value::Text("reader-left"),
                                    Value::UInt(1),
                                ])]),
                            )]),
                        ),
                    ]),
                ),
                (
                    hex("7269676874"),
                    Value::Map(vec![
                        (Value::UInt(1), Value::UInt(4)),
                        (
                            Value::UInt(6),
                            Value::Bytes(hex(
                                "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
                            )),
                        ),
                        (
                            Value::UInt(7),
                            Value::Map(vec![(
                                Value::Text("acl"),
                                Value::Array(vec![Value::Array(vec![
                                    Value::Text("reader-right"),
                                    Value::UInt(1),
                                ])]),
                            )]),
                        ),
                    ]),
                ),
            ],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-zero-owner",
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
                            (Value::UInt(1), Value::UInt(1)),
                            (Value::UInt(2), Value::UInt(420)),
                            (Value::UInt(3), Value::UInt(33)),
                            (
                                Value::UInt(4),
                                Value::Array(vec![
                                    Value::UInt(0),
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
                    Value::Map(vec![
                        (Value::Text("index"), Value::Array(vec![Value::Text("uid")])),
                        (Value::Text("domain"), Value::Text("public")),
                        (
                            Value::Text("index-roots"),
                            Value::Map(vec![
                                (
                                    Value::Text("value"),
                                    Value::Map(vec![(
                                        Value::Text("uid"),
                                        Value::Text(
                                            "f215b67da8a292e4e25d3d4f022f907564ddf9df456f53971840850074f25429",
                                        ),
                                    )]),
                                ),
                                (Value::Text("inherit"), Value::Bool(false)),
                            ]),
                        ),
                    ]),
                ),
            ]),
            full_entries: vec![(
                hex("6d697373696e67"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(1)),
                    (Value::UInt(2), Value::UInt(420)),
                    (Value::UInt(3), Value::UInt(33)),
                    (
                        Value::UInt(4),
                        Value::Array(vec![
                            Value::UInt(0),
                            Value::Bytes(hex(
                                "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                            )),
                        ]),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "a02cd59ecc6c69d7d88205d577a18ef081e179f825b97c4a9ec22c8554aae8d6",
            source: "",
            lower: "",
            upper: "",
        },
    ]
}
