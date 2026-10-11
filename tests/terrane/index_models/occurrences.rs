//! Independent complete recurrence expectations, including inert policy layers.

use super::{Occurrence, Value, digest, encode, hex};

/// Carries one literal finite-source recurrence and its complete expected occurrences.
pub(super) struct Graph {
    /// Published graph recurrence name.
    pub name: &'static str,
    /// Literal namespace owner R digest.
    pub owner: &'static str,
    /// Literal completed primary I digest.
    pub primary: &'static str,
    /// Expected number of present source occurrences, including repeated grafts.
    pub present: usize,
    /// Expected number of missing source occurrences, including repeated grafts.
    pub missing: usize,
    /// Complete local hops, object/value pairs, and opaque property layers.
    pub occurrences: Vec<Occurrence>,
}

/// Returns complete literal recurrence expectations and opaque policy layers.
///
/// # Panics
/// Panics if a literal fixture contains malformed hexadecimal data.
pub(super) fn graphs() -> Vec<Graph> {
    vec![
        Graph {
            name: "child",
            owner: "31018b489dfee853c85742c2de79791b665673207f9124d5a94c799a13cc0a5d",
            primary: "cc9cad20b00e7a8f49bfb4292c04f243cb6ff25232d87c0fb2529dee54b410ed",
            present: 1,
            missing: 1,
            occurrences: vec![
                Occurrence {
                    hops: vec![hex("6d697373696e67")],
                    object: digest(&hex(
                        "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                    )),
                    value: None,
                    layers: vec![vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ]],
                },
                Occurrence {
                    hops: vec![hex("70726573656e74")],
                    object: digest(&hex(
                        "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                    )),
                    value: Some(hex("1818")),
                    layers: vec![vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ]],
                },
            ],
        },
        Graph {
            name: "repeated-grafts",
            owner: "2d3a6c9446627e4a41c399f511b1a05b709a5e159fb1ca1a55a6584b2bc1bee9",
            primary: "f517690891d770e2db6eff09009caa2a37eb98be658bd8ee19749c27adbf56e1",
            present: 2,
            missing: 2,
            occurrences: vec![
                Occurrence {
                    hops: vec![hex("6c656674"), hex("6d697373696e67")],
                    object: digest(&hex(
                        "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                    )),
                    value: None,
                    layers: vec![
                        vec![
                            (
                                "index".to_owned(),
                                encode(&Value::Array(vec![Value::Text("uid")])),
                            ),
                            ("domain".to_owned(), encode(&Value::Text("public"))),
                            (
                                "index-roots".to_owned(),
                                encode(&Value::Map(vec![
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
                                ])),
                            ),
                        ],
                        vec![(
                            "acl".to_owned(),
                            encode(&Value::Array(vec![Value::Array(vec![
                                Value::Text("reader-left"),
                                Value::UInt(1),
                            ])])),
                        )],
                        vec![
                            (
                                "index".to_owned(),
                                encode(&Value::Array(vec![Value::Text("uid")])),
                            ),
                            ("domain".to_owned(), encode(&Value::Text("public"))),
                            (
                                "index-roots".to_owned(),
                                encode(&Value::Map(vec![
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
                                ])),
                            ),
                        ],
                    ],
                },
                Occurrence {
                    hops: vec![hex("6c656674"), hex("70726573656e74")],
                    object: digest(&hex(
                        "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                    )),
                    value: Some(hex("1818")),
                    layers: vec![
                        vec![
                            (
                                "index".to_owned(),
                                encode(&Value::Array(vec![Value::Text("uid")])),
                            ),
                            ("domain".to_owned(), encode(&Value::Text("public"))),
                            (
                                "index-roots".to_owned(),
                                encode(&Value::Map(vec![
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
                                ])),
                            ),
                        ],
                        vec![(
                            "acl".to_owned(),
                            encode(&Value::Array(vec![Value::Array(vec![
                                Value::Text("reader-left"),
                                Value::UInt(1),
                            ])])),
                        )],
                        vec![
                            (
                                "index".to_owned(),
                                encode(&Value::Array(vec![Value::Text("uid")])),
                            ),
                            ("domain".to_owned(), encode(&Value::Text("public"))),
                            (
                                "index-roots".to_owned(),
                                encode(&Value::Map(vec![
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
                                ])),
                            ),
                        ],
                    ],
                },
                Occurrence {
                    hops: vec![hex("7269676874"), hex("6d697373696e67")],
                    object: digest(&hex(
                        "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                    )),
                    value: None,
                    layers: vec![
                        vec![
                            (
                                "index".to_owned(),
                                encode(&Value::Array(vec![Value::Text("uid")])),
                            ),
                            ("domain".to_owned(), encode(&Value::Text("public"))),
                            (
                                "index-roots".to_owned(),
                                encode(&Value::Map(vec![
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
                                ])),
                            ),
                        ],
                        vec![(
                            "acl".to_owned(),
                            encode(&Value::Array(vec![Value::Array(vec![
                                Value::Text("reader-right"),
                                Value::UInt(1),
                            ])])),
                        )],
                        vec![
                            (
                                "index".to_owned(),
                                encode(&Value::Array(vec![Value::Text("uid")])),
                            ),
                            ("domain".to_owned(), encode(&Value::Text("public"))),
                            (
                                "index-roots".to_owned(),
                                encode(&Value::Map(vec![
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
                                ])),
                            ),
                        ],
                    ],
                },
                Occurrence {
                    hops: vec![hex("7269676874"), hex("70726573656e74")],
                    object: digest(&hex(
                        "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                    )),
                    value: Some(hex("1818")),
                    layers: vec![
                        vec![
                            (
                                "index".to_owned(),
                                encode(&Value::Array(vec![Value::Text("uid")])),
                            ),
                            ("domain".to_owned(), encode(&Value::Text("public"))),
                            (
                                "index-roots".to_owned(),
                                encode(&Value::Map(vec![
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
                                ])),
                            ),
                        ],
                        vec![(
                            "acl".to_owned(),
                            encode(&Value::Array(vec![Value::Array(vec![
                                Value::Text("reader-right"),
                                Value::UInt(1),
                            ])])),
                        )],
                        vec![
                            (
                                "index".to_owned(),
                                encode(&Value::Array(vec![Value::Text("uid")])),
                            ),
                            ("domain".to_owned(), encode(&Value::Text("public"))),
                            (
                                "index-roots".to_owned(),
                                encode(&Value::Map(vec![
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
                                ])),
                            ),
                        ],
                    ],
                },
            ],
        },
        Graph {
            name: "zero-candidates",
            owner: "a02cd59ecc6c69d7d88205d577a18ef081e179f825b97c4a9ec22c8554aae8d6",
            primary: "f215b67da8a292e4e25d3d4f022f907564ddf9df456f53971840850074f25429",
            present: 0,
            missing: 1,
            occurrences: vec![Occurrence {
                hops: vec![hex("6d697373696e67")],
                object: digest(&hex(
                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                )),
                value: None,
                layers: vec![vec![
                    (
                        "index".to_owned(),
                        encode(&Value::Array(vec![Value::Text("uid")])),
                    ),
                    ("domain".to_owned(), encode(&Value::Text("public"))),
                    (
                        "index-roots".to_owned(),
                        encode(&Value::Map(vec![
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
                        ])),
                    ),
                ]],
            }],
        },
        Graph {
            name: "long-local-routes",
            owner: "3abdc700e59582ad7e68513f61b45014cef37f9d81ae0f378c836562fede59c1",
            primary: "6e42cad4d77a57b06a5e36fbab03abe0b65e5712554bd11c265a709d24f1738f",
            present: 1,
            missing: 0,
            occurrences: vec![Occurrence {
                hops: vec![
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex(
                        "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
                    ),
                    hex("656e64"),
                ],
                object: digest(&hex(
                    "030c6c95a4a970b83d30ac5917cf1d2c91a728a61aac9e141efaac34198a4602",
                )),
                value: Some(hex("1818")),
                layers: vec![
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                    vec![],
                    vec![
                        (
                            "index".to_owned(),
                            encode(&Value::Array(vec![Value::Text("uid")])),
                        ),
                        ("domain".to_owned(), encode(&Value::Text("public"))),
                        (
                            "index-roots".to_owned(),
                            encode(&Value::Map(vec![
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
                            ])),
                        ),
                    ],
                ],
            }],
        },
    ]
}
