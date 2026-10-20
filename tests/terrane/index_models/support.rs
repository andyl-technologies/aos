//! Independent primitive CBOR assembly and exact published field readers.

/// Represents independent primitive fields without an owning schema encoder.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    /// A shortest-form unsigned integer.
    UInt(u64),
    /// An opaque byte string.
    Bytes(Vec<u8>),
    /// A literal UTF-8 text string.
    Text(&'static str),
    /// An ordered primitive array.
    Array(Vec<Value>),
    /// Complete fields sorted by unsigned encoded-key bytes during assembly.
    Map(Vec<(Value, Value)>),
    /// A primitive boolean.
    Bool(bool),
    /// An explicit null value.
    Null,
    /// Exact deliberately malformed bytes or a bounded repeated-array assembly.
    Raw(Vec<u8>),
}

/// Decodes a literal hexadecimal fixture.
///
/// # Panics
/// Panics if the input has odd length, non-ASCII text, or invalid hexadecimal digits.
pub(crate) fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex fixture"))
        .collect()
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        out.push(major << 5 | value as u8);
        return;
    }
    for (width, additional) in [(1, 24), (2, 25), (4, 26), (8, 27)] {
        if width == 8 || value < 1u64 << (8 * width) {
            out.push(major << 5 | additional);
            out.extend_from_slice(&value.to_be_bytes()[8 - width..]);
            return;
        }
    }
}

/// Assembles primitive CBOR with unsigned encoded-byte map ordering.
pub(crate) fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        Value::UInt(n) => head(&mut out, 0, *n),
        Value::Bytes(b) => {
            head(&mut out, 2, b.len() as u64);
            out.extend(b);
        }
        Value::Text(t) => {
            head(&mut out, 3, t.len() as u64);
            out.extend(t.as_bytes());
        }
        Value::Array(a) => {
            head(&mut out, 4, a.len() as u64);
            for v in a {
                out.extend(encode(v));
            }
        }
        Value::Map(m) => {
            let mut fields: Vec<_> = m.iter().map(|(k, v)| (encode(k), encode(v))).collect();
            // TREE-25 compares unsigned encoded bytes across major types.
            fields.sort_by(|a, b| a.0.cmp(&b.0));
            head(&mut out, 5, fields.len() as u64);
            for (k, v) in fields {
                out.extend(k);
                out.extend(v);
            }
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
        Value::Raw(b) => out.extend(b),
    }
    out
}

impl Value {
    /// Borrows the complete fields of a primitive map.
    ///
    /// # Panics
    /// Panics if the value is not a map.
    pub(crate) fn fields(&self) -> &[(Value, Value)] {
        let Self::Map(v) = self else { panic!("map") };
        v
    }

    /// Borrows a required numbered map field.
    ///
    /// # Panics
    /// Panics if the value is not a map or the numbered field is absent.
    pub(crate) fn field(&self, n: u64) -> &Value {
        self.optional(n).expect("numbered field")
    }

    /// Borrows an optional numbered map field.
    ///
    /// # Panics
    /// Panics if the value is not a map.
    pub(crate) fn optional(&self, n: u64) -> Option<&Value> {
        self.fields()
            .iter()
            .find(|(k, _)| *k == Self::UInt(n))
            .map(|(_, v)| v)
    }

    /// Borrows a required text-keyed map field.
    ///
    /// # Panics
    /// Panics if the value is not a map or the named field is absent.
    pub(crate) fn named(&self, name: &str) -> &Value {
        self.fields()
            .iter()
            .find(|(k, _)| matches!(k,Self::Text(t) if *t==name))
            .map(|(_, v)| v)
            .expect("named field")
    }

    /// Returns the literal unsigned integer.
    ///
    /// # Panics
    /// Panics if the value is not an unsigned integer.
    pub(crate) fn uint(&self) -> u64 {
        let Self::UInt(n) = self else { panic!("uint") };
        *n
    }

    /// Borrows the literal byte string.
    ///
    /// # Panics
    /// Panics if the value is not a byte string.
    pub(crate) fn bytes(&self) -> &[u8] {
        let Self::Bytes(b) = self else {
            panic!("bytes")
        };
        b
    }

    /// Borrows the literal text string.
    ///
    /// # Panics
    /// Panics if the value is not a text string.
    pub(crate) fn text(&self) -> &'static str {
        let Self::Text(t) = self else { panic!("text") };
        t
    }

    /// Borrows the complete primitive array.
    ///
    /// # Panics
    /// Panics if the value is not an array.
    pub(crate) fn array(&self) -> &[Value] {
        let Self::Array(a) = self else {
            panic!("array")
        };
        a
    }
}

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));

/// Reads one exact hexadecimal field from a unique published case.
///
/// # Panics
/// Panics if the case heading is ambiguous, the field is absent, or its hexadecimal data is malformed.
pub(crate) fn published(name: &str, field: &str) -> Vec<u8> {
    let marker = format!("### {name}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1, "{name}");
    let section = REFERENCE
        .split_once(&marker)
        .unwrap()
        .1
        .split("\n### ")
        .next()
        .unwrap();
    let prefix = format!("{} = ", field.replace('_', " "));
    hex(section
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("published field"))
}

/// Retains fixture bytes for borrowed public format models.
pub(crate) fn leak(bytes: Vec<u8>) -> &'static [u8] {
    Box::leak(bytes.into_boxed_slice())
}
