//! Checks independent permissive wire examples without importing QEMU code.
//!
//! ```text
//! base<TAB>kind<TAB>complete-hex
//! case<TAB>kind<TAB>name<TAB>syntax<TAB>completed<TAB>length<TAB>patches<TAB>sha256
//! ```
//!
//! Each case resizes its complete base, appending zeros when needed, then
//! applies ordered, disjoint replacements. Every reconstructed digest and both
//! independent expected outcomes remain checked, including negative reports.
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::{manifest::NativeProfileManifest, probe::NativeProbeReport};

const FIXTURE: &str = include_str!("../../tests/fixtures/native-profile-probe-v1.tsv");
const FIXTURE_SHA256: &str = "ac90eed8eb97dd424aa462d994b9f09f6e1756113a350f523783b5f34ae77f78";

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());

    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn expected_flag(value: &str) -> bool {
    match value {
        "0" => false,
        "1" => true,
        _ => panic!("unexpected public vector flag: {value}"),
    }
}

fn public_vectors(kind: &'static str) -> impl Iterator<Item = (&'static str, bool, bool, Vec<u8>)> {
    assert_eq!(
        Sha256::digest(FIXTURE.as_bytes()).as_slice(),
        hex_bytes(FIXTURE_SHA256)
    );

    let base_line = FIXTURE
        .lines()
        .find(|line| line.starts_with(&format!("base\t{kind}\t")))
        .unwrap();
    let base = hex_bytes(base_line.split('\t').nth(2).unwrap());

    FIXTURE.lines().filter_map(move |line| {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.first() != Some(&"case") || fields.get(1) != Some(&kind) {
            return None;
        }
        assert_eq!(fields.len(), 8);
        let length = fields[5].parse::<usize>().unwrap();
        assert!(length <= 23_809);

        let mut bytes = base.clone();
        bytes.resize(length, 0);
        if fields[6] != "-" {
            let mut previous_end = 0;
            let mut count = 0;
            for patch in fields[6].split(',') {
                let (offset, hex) = patch.split_once(':').unwrap();
                let offset = offset.parse::<usize>().unwrap();
                let replacement = hex_bytes(hex);
                let end = offset.checked_add(replacement.len()).unwrap();
                assert!(!replacement.is_empty() && offset >= previous_end && end <= length);

                bytes[offset..end].copy_from_slice(&replacement);
                previous_end = end;
                count += 1;
            }
            assert!(count <= 177);
        }
        assert_eq!(
            Sha256::digest(&bytes).as_slice(),
            hex_bytes(fields[7]),
            "{}",
            fields[2]
        );

        Some((
            fields[2],
            expected_flag(fields[3]),
            expected_flag(fields[4]),
            bytes,
        ))
    })
}

#[test]
fn manifest_matches_all_independent_public_wire_vectors() {
    let mut names = BTreeSet::new();
    let mut accepted = 0;

    for (name, syntax, completed, bytes) in public_vectors("manifest") {
        assert!(names.insert(name), "{name}");
        assert!(
            !completed,
            "a manifest never describes probe completion: {name}"
        );

        let decoded = NativeProfileManifest::decode(&bytes);
        assert_eq!(decoded.is_ok(), syntax, "{name}");
        if let Ok(manifest) = decoded {
            assert_eq!(manifest.as_bytes(), bytes, "{name}");
            accepted += 1;
        }
    }

    assert_eq!((names.len(), accepted), (4461, 8));
}

#[test]
fn probe_matches_independent_syntax_and_completed_description_vectors() {
    let mut names = BTreeSet::new();
    let mut accepted = 0;
    let mut completed_count = 0;

    for (name, syntax, completed, bytes) in public_vectors("probe") {
        assert!(names.insert(name), "{name}");

        let decoded = NativeProbeReport::decode(&bytes);
        assert_eq!(decoded.is_ok(), syntax, "{name}");
        assert_eq!(
            decoded
                .as_ref()
                .is_ok_and(|report| report.has_completed_result()),
            completed,
            "{name}"
        );
        if let Ok(report) = decoded {
            assert_eq!(report.as_bytes(), bytes, "{name}");
            accepted += 1;
            completed_count += usize::from(completed);
        }
    }

    assert_eq!((names.len(), accepted, completed_count), (4217, 23, 6));
}
