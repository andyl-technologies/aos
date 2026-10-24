//! Compares borrowed object output with the authoritative enclosing Value codec.

use crucible_node_format::canonical;
use serde_json::{Map, Value, json};
use std::io::{self, Write};

#[test]
fn borrowed_objects_preserve_unicode_key_order_numbers_and_escaping() {
    let value = json!({
        "\u{e000}": [1e30, -0.0, 0.002, 333333333.3333333],
        "\u{10000}": {"quoted\"key": "\u{0}\n\t\\\""},
        "a": [null, false, true, "é"],
    });
    let expected = canonical::canonical_json(&value).unwrap();
    let mut actual = Vec::new();
    canonical::canonical_json_object_to_writer_at_depth(value.as_object().unwrap(), &mut actual, 0)
        .unwrap();

    assert_eq!(actual, expected);
    let tree: std::collections::BTreeMap<String, Value> = value
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let mut tree_output = Vec::new();
    canonical::canonical_json_btree_object_to_writer_at_depth(&tree, &mut tree_output, 0).unwrap();
    assert_eq!(tree_output, expected);
    assert!(
        actual
            .windows("\u{10000}".len())
            .position(|part| part == "\u{10000}".as_bytes())
            .unwrap()
            < actual
                .windows("\u{e000}".len())
                .position(|part| part == "\u{e000}".as_bytes())
                .unwrap()
    );
}

#[test]
fn enclosing_container_depth_and_array_limits_match_the_original_codec() {
    for containers in [0, 1, 61, 62, 63, 64, 65] {
        let mut value = Value::Null;
        for _ in 0..containers {
            value = json!({"child": value});
        }
        let mut body = Map::new();
        body.insert("leaf".into(), value);
        let whole = json!({"body": body});
        let expected = canonical::canonical_json(&whole);
        let mut actual = b"{\"body\":".to_vec();
        let outcome = canonical::canonical_json_object_to_writer_at_depth(
            whole["body"].as_object().unwrap(),
            &mut actual,
            1,
        );
        assert_eq!(outcome.is_ok(), expected.is_ok(), "{containers}");
        if let Ok(expected) = expected {
            actual.push(b'}');
            assert_eq!(actual, expected);
        }
    }

    let mut output = Vec::new();
    assert!(
        canonical::canonical_json_object_to_writer_at_depth(&Map::new(), &mut output, 64).is_err()
    );
    assert!(output.is_empty());
    let oversized = json!({"items": vec![Value::Null; 65_537]});
    assert!(
        canonical::canonical_json_object_to_writer_at_depth(
            oversized.as_object().unwrap(),
            &mut output,
            0
        )
        .is_err()
    );
}

struct RefusingWriter {
    bytes: Vec<u8>,
    allowance: usize,
}

impl Write for RefusingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.allowance - self.bytes.len();
        if remaining == 0 {
            return Err(io::ErrorKind::Other.into());
        }
        let count = remaining.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn every_sink_refusal_retains_the_same_original_canonical_prefix() {
    let value = json!({"nested": {"escaped": "\n\t\u{0}"}, "tail": [null, 1.25]});
    let expected = canonical::canonical_json(&value).unwrap();
    for allowance in 0..expected.len() {
        let mut sink = RefusingWriter {
            bytes: Vec::new(),
            allowance,
        };
        assert!(
            canonical::canonical_json_object_to_writer_at_depth(
                value.as_object().unwrap(),
                &mut sink,
                0
            )
            .is_err()
        );
        assert_eq!(sink.bytes, expected[..allowance]);
    }
}
