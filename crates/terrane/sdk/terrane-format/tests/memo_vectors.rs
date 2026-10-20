//! Consumes published common Memo bytes through the public owning codec.
//!
//! Independent primitive fields reproduce every positive and negative wire,
//! including empty strict prefixes. Record identities remain distinct from the
//! detached recipe lookup fields; these tests establish no replay or authority.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "published fixtures must match independently constructed test models"
)]

use terrane_format::derivation::Memo;
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));
const HEADING: &str = "## Common immutable memo record witnesses\n";

fn section(name: &str) -> &str {
    let marker = format!("### {name}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1, "{name}");
    REFERENCE
        .split_once(&marker)
        .unwrap()
        .1
        .split("\n## ")
        .next()
        .unwrap()
        .split("\n### ")
        .next()
        .unwrap()
}

fn hexadecimal(text: &str) -> Vec<u8> {
    let digits: String = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(digits.len() % 2, 0);
    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

fn wire(name: &str, index: usize) -> Vec<u8> {
    // Empty fences are deliberate: truncation zero must still reach the decoder.
    let text = section(name)
        .split("```hex\n")
        .nth(index + 1)
        .unwrap()
        .split_once("```")
        .unwrap()
        .0;
    hexadecimal(text)
}

fn field(name: &str, key: &str) -> Digest {
    let prefix = format!("{key} = ");
    let lines: Vec<_> = section(name)
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect();
    assert_eq!(lines.len(), 1);
    hexadecimal(lines[0]).try_into().unwrap()
}

fn head(major: u8, value: usize) -> Vec<u8> {
    let prefix = major << 5;
    if value < 24 {
        return vec![prefix | u8::try_from(value).unwrap()];
    }
    if let Ok(value) = u8::try_from(value) {
        return vec![prefix | 24, value];
    }
    panic!("independent model header exceeds its bounded fixture range")
}

fn concatenate(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn byte_string(value: &[u8]) -> Vec<u8> {
    concatenate(&[&head(2, value.len()), value])
}

fn pair(key: u8, value: &[u8]) -> Vec<u8> {
    concatenate(&[&head(0, usize::from(key)), value])
}

fn record(recipe: &[u8], result: &[u8]) -> Vec<u8> {
    concatenate(&[
        &head(5, 2),
        &pair(1, &byte_string(recipe)),
        &pair(2, &byte_string(result)),
    ])
}

fn positive_models() -> [(&'static str, Digest, Digest); 3] {
    [
        ("zero", [0; 32], [0; 32]),
        ("ff", [255; 32], [255; 32]),
        (
            "increasing",
            core::array::from_fn(|index| u8::try_from(index).unwrap()),
            core::array::from_fn(|index| u8::try_from(index + 32).unwrap()),
        ),
    ]
}

fn negative_models() -> Vec<(String, Vec<u8>)> {
    let (_, recipe, result) = positive_models()[2];
    let first = pair(1, &byte_string(&recipe));
    let second = pair(2, &byte_string(&result));
    let mut models: Vec<(String, Vec<u8>)> = [
        ("missing-recipe", concatenate(&[&[0xa1], &second])),
        ("missing-root", concatenate(&[&[0xa1], &first])),
        ("empty-map", vec![0xa0]),
        (
            "unknown-field",
            concatenate(&[&[0xa2], &first, &pair(3, &byte_string(&result))]),
        ),
        (
            "extra-field",
            concatenate(&[&[0xa3], &first, &second, &pair(3, &[0])]),
        ),
        ("duplicate-recipe", concatenate(&[&[0xa2], &first, &first])),
        ("duplicate-root", concatenate(&[&[0xa2], &second, &second])),
        ("reordered", concatenate(&[&[0xa2], &second, &first])),
        ("array-container", concatenate(&[&[0x82], &first, &second])),
        ("null-container", vec![0xf6]),
        (
            "text-key",
            concatenate(&[&[0xa2, 0x61, b'x'], &byte_string(&recipe), &second]),
        ),
    ]
    .into_iter()
    .map(|(label, wire)| (label.to_owned(), wire))
    .collect();

    for field in [1, 2] {
        for length in [31, 33] {
            let original = if field == 1 { recipe } else { result };
            let digest = if length == 31 {
                original[..31].to_vec()
            } else {
                concatenate(&[&original, &[0]])
            };
            let encoded = if field == 1 {
                record(&digest, &result)
            } else {
                record(&recipe, &digest)
            };
            models.push((format!("field-{field}-digest-{length}"), encoded));
        }
        let values = [
            ("wrong-uint", vec![0]),
            ("wrong-null", vec![0xf6]),
            ("wrong-array", vec![0x80]),
            ("wrong-text", concatenate(&[&[0x78, 0x20], &recipe])),
            (
                "nonminimal-length",
                concatenate(&[&[0x59, 0, 0x20], &recipe]),
            ),
            (
                "indefinite-bytes",
                concatenate(&[&[0x5f], &byte_string(&recipe), &[0xff]]),
            ),
            ("hostile-u64", concatenate(&[&[0x5b], &[255; 8]])),
        ];
        for (label, value) in values {
            let fields = if field == 1 {
                concatenate(&[&pair(1, &value), &second])
            } else {
                concatenate(&[&first, &pair(2, &value)])
            };
            models.push((
                format!("field-{field}-{label}"),
                concatenate(&[&[0xa2], &fields]),
            ));
        }
    }
    let remaining = [
        (
            "nonminimal-map",
            concatenate(&[&[0xb8, 2], &first, &second]),
        ),
        (
            "nonminimal-key-1",
            concatenate(&[&[0xa2, 0x18, 1], &byte_string(&recipe), &second]),
        ),
        (
            "nonminimal-key-2",
            concatenate(&[&[0xa2], &first, &[0x18, 2], &byte_string(&result)]),
        ),
        (
            "indefinite-map",
            concatenate(&[&[0xbf], &first, &second, &[0xff]]),
        ),
        ("hostile-map", concatenate(&[&[0xbb], &[255; 8]])),
        (
            "trailing-null",
            concatenate(&[&record(&recipe, &result), &[0xf6]]),
        ),
        ("oversize", vec![0; 72]),
    ];
    models.extend(
        remaining
            .into_iter()
            .map(|(label, bytes)| (label.to_owned(), bytes)),
    );

    for (label, recipe, result) in positive_models() {
        let encoded = record(&recipe, &result);
        for length in 0..71 {
            models.push((
                format!("{label}-truncated-{length}"),
                encoded[..length].to_vec(),
            ));
        }
    }
    models
}

#[test]
fn published_common_memos_match_independent_fields_bytes_and_record_identities() {
    assert_eq!(REFERENCE.matches(HEADING).count(), 1);
    for (label, recipe, result) in positive_models() {
        let name = format!("common-memo-{label}");
        let independent = record(&recipe, &result);
        assert_eq!(independent.len(), 71);
        assert_eq!(wire(&name, 0), independent);
        assert_eq!(field(&name, "recipe"), recipe);
        assert_eq!(field(&name, "result"), result);
        assert!(section(&name).lines().any(|line| line == "length = 71"));

        let model = Memo::new(recipe, result);
        assert_eq!(model.encode(), independent);
        let decoded = Memo::decode(&independent).unwrap();
        assert_eq!(decoded.recipe_hash(), recipe);
        assert_eq!(decoded.result_root(), result);
        assert_eq!(decoded.encode(), independent);
        assert_eq!(decoded, model);

        let identity = field(&name, "identity");
        assert_eq!(model.identity().unwrap(), identity);
        assert_eq!(
            TERRANE_V1
                .calculate(IdentityKind::Memo, &independent)
                .unwrap()
                .terrane_v1_digest()
                .unwrap(),
            identity
        );
        assert_ne!(identity, recipe);
    }
}

#[test]
fn published_common_memo_negatives_reproduce_independent_wires_and_are_rejected() {
    let models = negative_models();
    assert_eq!(models.len(), 249);
    let names: std::collections::BTreeSet<_> = models.iter().map(|(name, _)| name).collect();
    assert_eq!(names.len(), 249);
    let common_section = REFERENCE
        .split_once(HEADING)
        .unwrap()
        .1
        .split("\n## ")
        .next()
        .unwrap();
    assert_eq!(
        common_section.matches("### common-memo-reject-").count(),
        models.len()
    );
    assert_eq!(
        models.iter().filter(|(_, bytes)| bytes.is_empty()).count(),
        3
    );

    for (label, independent) in models {
        let name = format!("common-memo-reject-{label}");
        assert_eq!(wire(&name, 0), independent, "{name}");
        // Oversized malformed wires may hit the size cap before schema parsing.
        assert!(Memo::decode(&independent).is_err(), "{name}");
    }
}

#[test]
fn published_foundation_memo_payload_decodes_as_the_common_record() {
    let recipe: Digest =
        hexadecimal("740ff7032b23e99007d5f1680bc388ff54baced783524cd680f8d347a7956ca8")
            .try_into()
            .unwrap();
    let result: Digest =
        hexadecimal("c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81")
            .try_into()
            .unwrap();
    let identity: Digest =
        hexadecimal("8998fda8be60eeebffc48dcea22e4b9312ca1e32d99cac31ac2514319ac8fa13")
            .try_into()
            .unwrap();
    let independent = record(&recipe, &result);
    assert_eq!(wire("descriptor-memo", 1), independent);

    let decoded = Memo::decode(&independent).unwrap();
    assert_eq!(decoded.recipe_hash(), recipe);
    assert_eq!(decoded.result_root(), result);
    assert_eq!(decoded.encode(), independent);
    assert_eq!(Memo::new(recipe, result).encode(), independent);
    assert_eq!(decoded.identity().unwrap(), identity);
    assert_ne!(identity, recipe);
}
