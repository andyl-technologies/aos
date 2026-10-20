//! Shares deterministic model generation and structural malformed-byte checks.

use std::fmt::Debug;
use terrane_format::cbor::Decoder;

/// A fixed-seed xorshift generator; failures reproduce without environment state.
pub(super) struct Generator(u64);

impl Generator {
    /// Creates a reproducible generator from a nonzero seed.
    ///
    /// # Panics
    /// Panics if `seed` is zero, which is the xorshift absorbing state.
    pub(super) const fn new(seed: u64) -> Self {
        assert!(seed != 0);
        Self(seed)
    }

    /// Advances the xorshift state and returns the next reproducible word.
    pub(super) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Fills a fixed-size byte array from successive generated low bytes.
    pub(super) fn bytes<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.next() as u8)
    }

    /// Permutes a slice in place with the reproducible Fisher-Yates selection sequence.
    pub(super) fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let selected = (self.next() % (index + 1) as u64) as usize;
            values.swap(index, selected);
        }
    }
}

/// Checks byte uniqueness, every truncated prefix, and sampled mutations.
/// A mutation may describe another valid model; successful decodes must retain
/// its exact canonical bytes rather than being incorrectly required to fail.
///
/// # Panics
/// Panics if the original bytes fail reencoding, a truncated prefix is accepted,
/// or an accepted mutation reencodes differently. Propagates callback panics.
pub(super) fn byte_properties<E: Debug>(
    name: &str,
    bytes: &[u8],
    reencode: impl Fn(&[u8]) -> Result<Vec<u8>, E>,
) {
    assert_eq!(
        reencode(bytes).unwrap(),
        bytes,
        "{name}: canonical uniqueness"
    );
    for end in 0..bytes.len() {
        assert!(reencode(&bytes[..end]).is_err(), "{name}: prefix {end}");
    }

    for index in (0..bytes.len()).step_by((bytes.len() / 16).max(1)) {
        for mask in [1, 0x80, 0xff] {
            let mut altered = bytes.to_vec();
            altered[index] ^= mask;
            if let Ok(canonical) = reencode(&altered) {
                assert_eq!(canonical, altered, "{name}: mutation at {index}");
            }
        }
    }

    let seed = bytes.iter().fold(0x25ab_e297_f032_4401_u64, |value, byte| {
        value.rotate_left(7) ^ u64::from(*byte)
    });
    let mut generator = Generator::new(seed | 1);
    for _ in 0..32 {
        let mut altered = bytes.to_vec();
        let position = (generator.next() % altered.len().max(1) as u64) as usize;
        let length = (generator.next() % 8 + 1) as usize;
        let replacement: Vec<_> = (0..length).map(|_| generator.next() as u8).collect();
        let end = (position + length).min(altered.len());
        altered.splice(position..end, replacement);
        if let Ok(canonical) = reencode(&altered) {
            assert_eq!(canonical, altered, "{name}: seeded byte-range mutation");
        }
    }
}

/// Applies every nonminimal header variant and map duplicate/order mutation to
/// generated CBOR, including nested values rather than only its first byte.
///
/// # Panics
/// Panics on byte-property failures, accepted trailing/noncanonical variants or
/// input outside the walker's supported canonical CBOR subset. Propagates
/// callback panics.
pub(super) fn cbor_properties<E: Debug>(
    name: &str,
    bytes: &[u8],
    reencode: impl Fn(&[u8]) -> Result<Vec<u8>, E>,
) {
    byte_properties(name, bytes, &reencode);

    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(reencode(&trailing).is_err(), "{name}: trailing data");

    let mut variants = Vec::new();
    walk(&mut Decoder::new(bytes), bytes, &mut variants);
    for (index, malformed) in variants.iter().enumerate() {
        assert!(
            reencode(malformed).is_err(),
            "{name}: noncanonical variant {index}"
        );
    }
}

fn walk(decoder: &mut Decoder<'_>, bytes: &[u8], variants: &mut Vec<Vec<u8>>) {
    let start = decoder.position();
    let initial = bytes[start];
    let major = initial >> 5;
    if major < 7 {
        let width = match initial & 31 {
            0..=23 => 0,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => unreachable!("generated canonical header"),
        };
        let argument = if width == 0 {
            u64::from(initial & 31)
        } else {
            bytes[start + 1..start + 1 + width]
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
        };
        for (new_width, marker) in [(1, 24), (2, 25), (4, 26), (8, 27)] {
            if new_width > width {
                let mut changed = bytes[..start].to_vec();
                changed.push((major << 5) | marker);
                changed.extend_from_slice(&argument.to_be_bytes()[8 - new_width..]);
                changed.extend_from_slice(&bytes[start + 1 + width..]);
                variants.push(changed);
            }
        }
    }

    match major {
        0 => {
            decoder.uint().unwrap();
        }
        1 => {
            decoder.negative_argument().unwrap();
        }
        2 => {
            decoder.bytes(bytes.len()).unwrap();
        }
        3 => {
            decoder.text(bytes.len()).unwrap();
        }
        4 => {
            let count = decoder.array(bytes.len()).unwrap();
            for _ in 0..count {
                walk(decoder, bytes, variants);
            }
        }
        5 => {
            let count = decoder.map(bytes.len()).unwrap();
            let mut pairs = Vec::new();
            for _ in 0..count {
                let pair_start = decoder.position();
                walk(decoder, bytes, variants);
                let key_end = decoder.position();
                walk(decoder, bytes, variants);
                pairs.push((pair_start, key_end, decoder.position()));
            }
            for pair in pairs.windows(2) {
                let (first, key_end, end) = pair[0];
                let (second, second_key_end, second_end) = pair[1];
                let mut reordered = bytes[..first].to_vec();
                reordered.extend_from_slice(&bytes[second..second_end]);
                reordered.extend_from_slice(&bytes[first..end]);
                reordered.extend_from_slice(&bytes[second_end..]);
                variants.push(reordered);

                let mut duplicate = bytes[..second].to_vec();
                duplicate.extend_from_slice(&bytes[first..key_end]);
                duplicate.extend_from_slice(&bytes[second_key_end..]);
                variants.push(duplicate);
            }
        }
        7 => {
            decoder.simple().unwrap();
            let mut widened = bytes[..start].to_vec();
            widened.extend_from_slice(&[0xf8, initial & 31]);
            widened.extend_from_slice(&bytes[start + 1..]);
            variants.push(widened);
        }
        _ => unreachable!("generated subset value"),
    }

    if (2..=5).contains(&major) {
        // A short hostile header must fail before any claimed-size collection
        // can be materialized. This probes the real typed decoder at every
        // nested collection/string position, without allocating that size.
        let width = match initial & 31 {
            0..=23 => 0,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => unreachable!("generated canonical header"),
        };
        let mut excessive = bytes[..start].to_vec();
        excessive.push((major << 5) | 27);
        excessive.extend_from_slice(&u64::MAX.to_be_bytes());
        excessive.extend_from_slice(&bytes[start + width + 1..]);
        variants.push(excessive);

        let end = decoder.position();
        let mut indefinite = bytes[..start].to_vec();
        indefinite.push((major << 5) | 31);
        let payload = if major <= 3 { start } else { start + width + 1 };
        indefinite.extend_from_slice(&bytes[payload..end]);
        indefinite.push(0xff);
        indefinite.extend_from_slice(&bytes[end..]);
        variants.push(indefinite);
    }
}

macro_rules! check_record {
    ($name:expr, $model:expr, $ty:ty) => {{
        let model = $model;
        let bytes = model
            .encode()
            .unwrap_or_else(|error| panic!("{}: encode: {error:?}", $name));
        assert_eq!(
            <$ty>::decode(&bytes).unwrap(),
            model,
            "{}: model roundtrip",
            $name
        );
        assert_eq!(
            model.clone().encode().unwrap(),
            bytes,
            "{}: model uniqueness",
            $name
        );
        crate::support::cbor_properties($name, &bytes, |input| <$ty>::decode(input)?.encode());
    }};
}

/// Reexports the typed record roundtrip and canonical-byte property assertion macro.
///
/// # Panics
/// The macro panics if model encoding/decoding fails, roundtrips or bytes differ,
/// or a structural CBOR property assertion fails.
pub(super) use check_record;

/// Builds structurally valid envelopes with opaque, unauthenticated signatures.
pub(super) fn token_bytes(grants: usize, blocks: usize, generator: &mut Generator) -> Vec<u8> {
    use terrane_format::cbor;
    let mut bytes = vec![];
    cbor::write_array(&mut bytes, blocks);
    cbor::write_map(&mut bytes, 12);
    for (key, text) in [(1, "issuer"), (2, "key"), (3, "subject")] {
        cbor::write_uint(&mut bytes, key);
        cbor::write_text(&mut bytes, text);
    }
    cbor::write_uint(&mut bytes, 4);
    cbor::write_uint(&mut bytes, 2);
    cbor::write_uint(&mut bytes, 5);
    cbor::write_array(&mut bytes, 1);
    cbor::write_text(&mut bytes, "group");
    cbor::write_uint(&mut bytes, 6);
    cbor::write_uint(&mut bytes, u64::MAX);
    cbor::write_uint(&mut bytes, 7);
    cbor::write_uint(&mut bytes, 0);
    cbor::write_uint(&mut bytes, 8);
    cbor::write_bytes(&mut bytes, &generator.bytes::<16>());
    cbor::write_uint(&mut bytes, 9);
    cbor::write_array(&mut bytes, grants);
    for index in 0..grants {
        cbor::write_array(&mut bytes, 2);
        cbor::write_text(&mut bytes, &format!("refs/heads/_/branch-{index}"));
        cbor::write_uint(&mut bytes, 31);
    }
    cbor::write_uint(&mut bytes, 10);
    cbor::write_text(&mut bytes, "workload");
    cbor::write_uint(&mut bytes, 11);
    cbor::write_bytes(&mut bytes, &generator.bytes::<32>());
    cbor::write_uint(&mut bytes, 12);
    cbor::write_bytes(&mut bytes, &generator.bytes::<64>());
    for index in 1..blocks {
        cbor::write_map(&mut bytes, 6);
        cbor::write_uint(&mut bytes, 1);
        cbor::write_uint(&mut bytes, u64::MAX - index as u64);
        cbor::write_uint(&mut bytes, 2);
        cbor::write_uint(&mut bytes, index as u64);
        cbor::write_uint(&mut bytes, 3);
        cbor::write_array(&mut bytes, 1);
        cbor::write_array(&mut bytes, 2);
        cbor::write_text(&mut bytes, "refs/heads/_/branch-0");
        cbor::write_uint(&mut bytes, 1);
        cbor::write_uint(&mut bytes, 4);
        cbor::write_array(&mut bytes, 9);
        for name in [
            "before", "after", "ref", "root", "verb", "domain", "surface", "locality", "epoch",
        ] {
            cbor::write_array(&mut bytes, if name == "epoch" { 3 } else { 2 });
            cbor::write_text(&mut bytes, name);
            match name {
                "before" => cbor::write_uint(&mut bytes, u64::MAX),
                "after" => cbor::write_uint(&mut bytes, 0),
                "verb" => cbor::write_uint(&mut bytes, 1),
                "ref" | "epoch" => cbor::write_text(&mut bytes, "refs/heads/_/branch-0"),
                "root" => cbor::write_text(&mut bytes, "/"),
                "domain" => cbor::write_text(&mut bytes, "public"),
                "surface" => cbor::write_text(&mut bytes, "sdk"),
                "locality" => {
                    cbor::write_map(&mut bytes, 3);
                    for (key, label) in [(1, "region"), (2, "zone"), (3, "host")] {
                        cbor::write_uint(&mut bytes, key);
                        cbor::write_text(&mut bytes, label);
                    }
                }
                _ => unreachable!(),
            }
            if name == "epoch" {
                cbor::write_uint(&mut bytes, u64::MAX);
            }
        }
        cbor::write_uint(&mut bytes, 5);
        cbor::write_bytes(&mut bytes, &generator.bytes::<32>());
        cbor::write_uint(&mut bytes, 6);
        cbor::write_bytes(&mut bytes, &generator.bytes::<64>());
    }
    bytes
}

/// Builds the full key-size boundary while respecting every component bound.
pub(super) fn maximum_key() -> String {
    vec!["x".repeat(240); 17].join("/")
}
