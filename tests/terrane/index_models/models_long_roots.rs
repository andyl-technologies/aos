//! Literal independent long_roots models; no owning codec derives these fields.

use super::super::support::{Value, hex};
use super::Case;

/// Returns the complete literal primary roots along the long local route models.
///
/// # Panics
/// Panics if a literal fixture contains malformed hexadecimal data.
pub(super) fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "carrier-long-00-primary",
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
                                        "e49963633ef336d292f9c3e7e4066cda85019eb77f8ccb7814135c7b67c63b9c",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "e49963633ef336d292f9c3e7e4066cda85019eb77f8ccb7814135c7b67c63b9c",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "a065148e6b40fdfb03fc2aabcd9186298d8093a4cbf0fe95907af87167dc340a",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-01-primary",
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
                                        "ec15f727da7dc59c477621b4492ea4b9caa73e0c50cbc6b8e5fb983ba7f56dbb",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "ec15f727da7dc59c477621b4492ea4b9caa73e0c50cbc6b8e5fb983ba7f56dbb",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "43ae02aebaea3727900fafa00590b7914cc0680e02936f36a9b049ef2f40ee3e",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-02-primary",
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
                                        "1aaadd9edfb5ad19923c9ee50af3552dd4f18b8cde2e697ba4420c2e635ff5f5",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "1aaadd9edfb5ad19923c9ee50af3552dd4f18b8cde2e697ba4420c2e635ff5f5",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "397702e410f1c5117ec96088d506eb64159eafec69f5c70214910d4e6cb3f2dd",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-03-primary",
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
                                        "5ecca000e545be2fec223118a7930b3901e1cfa284a88c9f1fb400598f6b4022",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "5ecca000e545be2fec223118a7930b3901e1cfa284a88c9f1fb400598f6b4022",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "191f975f9c0a1707a29b2a13136537398dd26fdaf8491571d4a8853730177a9a",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-04-primary",
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
                                        "e38db9ef1b10873b083d2e768bc9e7f58e5f643631829a6839420d66cb924710",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "e38db9ef1b10873b083d2e768bc9e7f58e5f643631829a6839420d66cb924710",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "6c3114eae25fe2c21e0f6486aebfa11d1e3274bf352e38a5c2eda5b6f7265e95",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-05-primary",
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
                                        "c21498b144f46c695d67d8102c7af499a2db29d235a57a52e8b30f3b9aaef598",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "c21498b144f46c695d67d8102c7af499a2db29d235a57a52e8b30f3b9aaef598",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "a6f88ba1cf30db87d34e598beb1907ca4a70b009045d6733985ae21107b935da",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-06-primary",
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
                                        "71c21561d67e556e6e5f926d480db2acdd45de7b0bcca522bb91c6aebac8ad3f",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "71c21561d67e556e6e5f926d480db2acdd45de7b0bcca522bb91c6aebac8ad3f",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "309e304a48b3d373f9393bbf254111c052260bc9a56ee96640ff5080ff09ac9a",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-07-primary",
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
                                        "758c8eb2e782ff4fd676f7d47a4de3653d8aafac3dc7fdfbe4639fc8c4d8fb29",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "758c8eb2e782ff4fd676f7d47a4de3653d8aafac3dc7fdfbe4639fc8c4d8fb29",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "1c9fb2452b88ef4ce46efd99310e4a10a2f6f886a6e47e2ea7cc3e73e5bc63fc",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-08-primary",
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
                                        "103f777138b3245cac2d5537ae2709b4cc4053f42a38ad176a07787a911bc900",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "103f777138b3245cac2d5537ae2709b4cc4053f42a38ad176a07787a911bc900",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "21fd25efe157a7d6913cfc546b293e5beb6df31375bc64b7dc8307b8cd75638b",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-09-primary",
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
                                        "d88e679be35eedac148348ac893b5f2fe229c8f15502883e7b172796a9f1d7ff",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "d88e679be35eedac148348ac893b5f2fe229c8f15502883e7b172796a9f1d7ff",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "4d076728ac8b50d37dab7ac23c79b5a895af46be3a15b8b41e613eac3dd74d21",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-10-primary",
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
                                        "ebaccf8b613b1b6c5d6be88e495e1957e64e2db15bfad195ac6b2536909e5aae",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "ebaccf8b613b1b6c5d6be88e495e1957e64e2db15bfad195ac6b2536909e5aae",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "24e4a4bfcef990954bff3224cbdebe8d296fc07ec8b8d9cd5c68a8ce6f8b733c",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-11-primary",
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
                                        "f4e4829d4a078556be8c25e75bed621ebd03f05b53cc589cbc886a8fe790fc51",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "f4e4829d4a078556be8c25e75bed621ebd03f05b53cc589cbc886a8fe790fc51",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "0db96bfa5ea2daf058238cce34e12e19b1249d2aaa146bc99661214ef2d3de20",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-12-primary",
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
                                        "4ec87659290d3faed289f1c147a8eda1161f5846a9e7de4ad3f7e5ea4b890683",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "4ec87659290d3faed289f1c147a8eda1161f5846a9e7de4ad3f7e5ea4b890683",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "ef95fbf450879593abada6b8f1d16bb11044e74a551f99b4ad54f7a36f4c16cc",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-13-primary",
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
                                        "3855eedad55dd1029bb910b411d32caa7a0e356c0a4cce8354dfe2eeb29f7a17",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "3855eedad55dd1029bb910b411d32caa7a0e356c0a4cce8354dfe2eeb29f7a17",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "dde8fb752177749786c93ba7656bbfae1f54dee0e72fdd9547b8ef11a37347c1",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-14-primary",
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
                                        "d0d0f5f017d7f211408efedaf6e9a3c313fe60595ca1c8c806f1e6207db5979d",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "d0d0f5f017d7f211408efedaf6e9a3c313fe60595ca1c8c806f1e6207db5979d",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "ca1d0a6f02a05826c3f255cc941d506bdfe94c5cc2ad9e1710b204f3f0d4ee9b",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-15-primary",
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
                                        "43599c08c74ccd6c9d2df6cd4cd1bd701a01f7cffc6151d09ce64c1e34d39fc5",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "43599c08c74ccd6c9d2df6cd4cd1bd701a01f7cffc6151d09ce64c1e34d39fc5",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "8ef6105582569e6766906d7b6a3b874d05293e76fbc26eedb825564901c3f8a2",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-16-primary",
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
                                        "23697915474fff239d7e8f090b0aff554afaf08aed080d7db56325e433527309",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "23697915474fff239d7e8f090b0aff554afaf08aed080d7db56325e433527309",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "b1493de713bc53883f775574130394c88a39eff59d312bbe9dcd1ef7a90842aa",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-17-primary",
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
                                        "44cb12e0ddf926a7dfc406ebf9f08966cb896bc3815c253efe7e602f0e6c613c",
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
                hex("1818030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602"),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(7)),
                    (
                        Value::UInt(9),
                        Value::Map(vec![(
                            Value::Text("index.occurrences"),
                            Value::Bytes(hex(
                                "44cb12e0ddf926a7dfc406ebf9f08966cb896bc3815c253efe7e602f0e6c613c",
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
            role: "primary uid without gaps",
            scope: "",
            identity: "6e42cad4d77a57b06a5e36fbab03abe0b65e5712554bd11c265a709d24f1738f",
            source: "",
            lower: "",
            upper: "",
        },
    ]
}
