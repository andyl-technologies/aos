//! Literal independent long_sources models; no owning codec derives these fields.

use super::super::support::{Value, hex};
use super::Case;

/// Returns the complete literal namespace roots along the long local route models.
///
/// # Panics
/// Panics if a literal fixture contains malformed hexadecimal data.
pub(super) fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "carrier-long-00-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex("656e64")),
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
                                            "a065148e6b40fdfb03fc2aabcd9186298d8093a4cbf0fe95907af87167dc340a",
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
                hex("656e64"),
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
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "cc6bb4cafbbc3a0a6f088c9438124cd2a91fa8f627a6eab15cb9e5dd8e837bcc",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-01-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "cc6bb4cafbbc3a0a6f088c9438124cd2a91fa8f627a6eab15cb9e5dd8e837bcc",
                                )),
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
                                            "43ae02aebaea3727900fafa00590b7914cc0680e02936f36a9b049ef2f40ee3e",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "cc6bb4cafbbc3a0a6f088c9438124cd2a91fa8f627a6eab15cb9e5dd8e837bcc",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "d7355f6a0ce736460dfbc323c3ef93a2f4d760004df16ee2ec14fec57bf43757",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-02-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "d7355f6a0ce736460dfbc323c3ef93a2f4d760004df16ee2ec14fec57bf43757",
                                )),
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
                                            "397702e410f1c5117ec96088d506eb64159eafec69f5c70214910d4e6cb3f2dd",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "d7355f6a0ce736460dfbc323c3ef93a2f4d760004df16ee2ec14fec57bf43757",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "afdc60b6c3d1e6dab8a8ed4b9f6f19bdf1461a76db2e07d8d93ba3bd641bab01",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-03-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "afdc60b6c3d1e6dab8a8ed4b9f6f19bdf1461a76db2e07d8d93ba3bd641bab01",
                                )),
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
                                            "191f975f9c0a1707a29b2a13136537398dd26fdaf8491571d4a8853730177a9a",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "afdc60b6c3d1e6dab8a8ed4b9f6f19bdf1461a76db2e07d8d93ba3bd641bab01",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "085b7e16e324a10e76c040f6ef8becca6cf5406e9685001550f9125f8dc97bdb",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-04-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "085b7e16e324a10e76c040f6ef8becca6cf5406e9685001550f9125f8dc97bdb",
                                )),
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
                                            "6c3114eae25fe2c21e0f6486aebfa11d1e3274bf352e38a5c2eda5b6f7265e95",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "085b7e16e324a10e76c040f6ef8becca6cf5406e9685001550f9125f8dc97bdb",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "91b5ec6d00f84ebfa7ee17b56316a477e48d737df97251375f8da44694185830",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-05-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "91b5ec6d00f84ebfa7ee17b56316a477e48d737df97251375f8da44694185830",
                                )),
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
                                            "a6f88ba1cf30db87d34e598beb1907ca4a70b009045d6733985ae21107b935da",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "91b5ec6d00f84ebfa7ee17b56316a477e48d737df97251375f8da44694185830",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "f745d84b04cb47625d0226601d991f19566401910b943c06f1905e88587d22e2",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-06-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "f745d84b04cb47625d0226601d991f19566401910b943c06f1905e88587d22e2",
                                )),
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
                                            "309e304a48b3d373f9393bbf254111c052260bc9a56ee96640ff5080ff09ac9a",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "f745d84b04cb47625d0226601d991f19566401910b943c06f1905e88587d22e2",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "c7027057d95b8d5cd492df314b1ded79c9529655be58e8de11fd6e5167c2fbc6",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-07-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "c7027057d95b8d5cd492df314b1ded79c9529655be58e8de11fd6e5167c2fbc6",
                                )),
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
                                            "1c9fb2452b88ef4ce46efd99310e4a10a2f6f886a6e47e2ea7cc3e73e5bc63fc",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "c7027057d95b8d5cd492df314b1ded79c9529655be58e8de11fd6e5167c2fbc6",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "5263d11ff501d32cded4284fd0700aaaa6fbb1c21484ea132cf869ada7bdc99b",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-08-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "5263d11ff501d32cded4284fd0700aaaa6fbb1c21484ea132cf869ada7bdc99b",
                                )),
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
                                            "21fd25efe157a7d6913cfc546b293e5beb6df31375bc64b7dc8307b8cd75638b",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "5263d11ff501d32cded4284fd0700aaaa6fbb1c21484ea132cf869ada7bdc99b",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "add0984e36687f5ff303e03d10f7508f1441339260d18e46af5355d87b37a592",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-09-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "add0984e36687f5ff303e03d10f7508f1441339260d18e46af5355d87b37a592",
                                )),
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
                                            "4d076728ac8b50d37dab7ac23c79b5a895af46be3a15b8b41e613eac3dd74d21",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "add0984e36687f5ff303e03d10f7508f1441339260d18e46af5355d87b37a592",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "89602139933b6c38a03c65951db8a78d05bbaac83c8de76f011b758bf2c51f9e",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-10-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "89602139933b6c38a03c65951db8a78d05bbaac83c8de76f011b758bf2c51f9e",
                                )),
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
                                            "24e4a4bfcef990954bff3224cbdebe8d296fc07ec8b8d9cd5c68a8ce6f8b733c",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "89602139933b6c38a03c65951db8a78d05bbaac83c8de76f011b758bf2c51f9e",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "392eb12c6a11a4f6622d3a580290dbee5a24ae69c7eb35618730ac2f1bb06dfa",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-11-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "392eb12c6a11a4f6622d3a580290dbee5a24ae69c7eb35618730ac2f1bb06dfa",
                                )),
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
                                            "0db96bfa5ea2daf058238cce34e12e19b1249d2aaa146bc99661214ef2d3de20",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "392eb12c6a11a4f6622d3a580290dbee5a24ae69c7eb35618730ac2f1bb06dfa",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "c00d0c3a53e09ac01186bdb59ee8b15e39ce42919ec46756bc22739846bc9e98",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-12-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "c00d0c3a53e09ac01186bdb59ee8b15e39ce42919ec46756bc22739846bc9e98",
                                )),
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
                                            "ef95fbf450879593abada6b8f1d16bb11044e74a551f99b4ad54f7a36f4c16cc",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "c00d0c3a53e09ac01186bdb59ee8b15e39ce42919ec46756bc22739846bc9e98",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "4f6ac42678060f34bd934f4426abeaa4f21fdb3466bacc6ac08adf2b1b4ab2f2",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-13-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "4f6ac42678060f34bd934f4426abeaa4f21fdb3466bacc6ac08adf2b1b4ab2f2",
                                )),
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
                                            "dde8fb752177749786c93ba7656bbfae1f54dee0e72fdd9547b8ef11a37347c1",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "4f6ac42678060f34bd934f4426abeaa4f21fdb3466bacc6ac08adf2b1b4ab2f2",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "9e5701d480bd7c0708c3dfcd9de1fae5003626c677c016314bd27f54e7dbf511",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-14-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "9e5701d480bd7c0708c3dfcd9de1fae5003626c677c016314bd27f54e7dbf511",
                                )),
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
                                            "ca1d0a6f02a05826c3f255cc941d506bdfe94c5cc2ad9e1710b204f3f0d4ee9b",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "9e5701d480bd7c0708c3dfcd9de1fae5003626c677c016314bd27f54e7dbf511",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "3a8fdb4a067763c943ab2734624deb18bcd728a6e85d93b680cfcca13185689f",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-15-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "3a8fdb4a067763c943ab2734624deb18bcd728a6e85d93b680cfcca13185689f",
                                )),
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
                                            "8ef6105582569e6766906d7b6a3b874d05293e76fbc26eedb825564901c3f8a2",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "3a8fdb4a067763c943ab2734624deb18bcd728a6e85d93b680cfcca13185689f",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "6d7a0f10e8fc71b2af10008bf82c735ca51328d6de689b725a59958c4ee9f7c6",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-16-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "6d7a0f10e8fc71b2af10008bf82c735ca51328d6de689b725a59958c4ee9f7c6",
                                )),
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
                                            "b1493de713bc53883f775574130394c88a39eff59d312bbe9dcd1ef7a90842aa",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "6d7a0f10e8fc71b2af10008bf82c735ca51328d6de689b725a59958c4ee9f7c6",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "d56caf8d33f3518387caeeebabfb64f78fbc1cd45250f6d87ebc2e5e8a9c2900",
            source: "",
            lower: "",
            upper: "",
        },
        Case {
            name: "carrier-long-17-owner",
            family: "carrier-node",
            positive: true,
            model: Value::Map(vec![
                (Value::UInt(1), Value::UInt(0)),
                (
                    Value::UInt(2),
                    Value::Array(vec![Value::Array(vec![
                        Value::Bytes(hex(
                            "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                        )),
                        Value::UInt(0),
                        Value::Map(vec![
                            (Value::UInt(1), Value::UInt(4)),
                            (
                                Value::UInt(6),
                                Value::Bytes(hex(
                                    "d56caf8d33f3518387caeeebabfb64f78fbc1cd45250f6d87ebc2e5e8a9c2900",
                                )),
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
                                            "6e42cad4d77a57b06a5e36fbab03abe0b65e5712554bd11c265a709d24f1738f",
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
                hex(
                    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                ),
                Value::Map(vec![
                    (Value::UInt(1), Value::UInt(4)),
                    (
                        Value::UInt(6),
                        Value::Bytes(hex(
                            "d56caf8d33f3518387caeeebabfb64f78fbc1cd45250f6d87ebc2e5e8a9c2900",
                        )),
                    ),
                ]),
            )],
            usage: "ordinary",
            is_root: true,
            role: "ordinary namespace root",
            scope: "",
            identity: "3abdc700e59582ad7e68513f61b45014cef37f9d81ae0f378c836562fede59c1",
            source: "",
            lower: "",
            upper: "",
        },
    ]
}
