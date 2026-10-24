//! Checks independent complete native-description correlation examples.
//!
//! ```text
//! base<TAB>kind<TAB>complete-hex
//! case<TAB>name<TAB>syntax<TAB>completed<TAB>runtime<TAB>transfer<TAB>manifest<TAB>probe
//! record = length:offset=hex,offset=hex:sha256
//! ```
//!
//! A dash replaces an empty patch list. Each bounded record resizes its own
//! complete base before applying ordered replacements. Expected correlation and
//! completion remain independent; neither predicate establishes paid custody.
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::{NativeTransfer, manifest::NativeProfileManifest, probe::NativeProbeReport};
use crate::runtime_artifact::RuntimeArtifactPair;

const FIXTURE: &str = include_str!("../../tests/fixtures/native-description-v1.tsv");
const FIXTURE_SHA256: &str = "de013fc5ce061357a0715b3cc31ccfa4c79391d3a95b980cdda4d91f6cac60ad";
const KINDS: [&str; 4] = ["runtime", "transfer", "manifest", "probe"];
const MAX_BYTES: [usize; 4] = [192, 1472, 3871, 3584];

fn hex_bytes(hex: &str) -> Vec<u8> {
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());

    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn expected_flag(flag: &str) -> bool {
    match flag {
        "0" => false,
        "1" => true,
        _ => panic!("unexpected public vector flag: {flag}"),
    }
}

fn reconstruct_record(base: &[u8], recipe: &str, maximum: usize) -> Vec<u8> {
    let fields = recipe.split(':').collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    let length = fields[0].parse::<usize>().unwrap();
    assert!(length <= maximum);

    let mut bytes = base.to_vec();
    bytes.resize(length, 0);
    if fields[1] != "-" {
        let patches = fields[1].split(',').collect::<Vec<_>>();
        assert!(patches.len() <= 5);
        let mut previous_end = 0;

        for patch in patches {
            let (offset, hex) = patch.split_once('=').unwrap();
            let offset = offset.parse::<usize>().unwrap();
            let replacement = hex_bytes(hex);
            let end = offset.checked_add(replacement.len()).unwrap();
            assert!(!replacement.is_empty() && offset >= previous_end && end <= length);

            bytes[offset..end].copy_from_slice(&replacement);
            previous_end = end;
        }
    }
    assert_eq!(Sha256::digest(&bytes).as_slice(), hex_bytes(fields[2]));
    bytes
}

fn corroborated_result(records: &[Vec<u8>; 4]) -> Result<bool, ()> {
    let runtime = RuntimeArtifactPair::decode(&records[0]).map_err(|_| ())?;
    let transfer = NativeTransfer::decode(&records[1]).map_err(|_| ())?;
    let manifest = NativeProfileManifest::decode(&records[2]).map_err(|_| ())?;
    let probe = NativeProbeReport::decode(&records[3]).map_err(|_| ())?;
    probe
        .corroborate_transfer(&transfer, &manifest, &runtime)
        .map_err(|_| ())?;

    assert_eq!(manifest.as_bytes(), records[2]);
    assert_eq!(probe.as_bytes(), records[3]);
    Ok(probe.has_completed_result())
}

#[test]
fn complete_description_matches_independent_correlation_and_completion_vectors() {
    assert_eq!(
        Sha256::digest(FIXTURE.as_bytes()).as_slice(),
        hex_bytes(FIXTURE_SHA256)
    );
    let bases: [Vec<u8>; 4] = std::array::from_fn(|index| {
        let prefix = format!("base\t{}\t", KINDS[index]);
        let line = FIXTURE.lines().find_map(|line| line.strip_prefix(&prefix));
        hex_bytes(line.unwrap())
    });
    let mut names = BTreeSet::new();
    let mut accepted = 0;
    let mut completed = 0;

    for line in FIXTURE.lines().filter(|line| line.starts_with("case\t")) {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 8);
        let name = fields[1];
        assert!(names.insert(name), "{name}");

        let records = std::array::from_fn(|index| {
            reconstruct_record(&bases[index], fields[index + 4], MAX_BYTES[index])
        });
        let result = corroborated_result(&records);
        assert_eq!(result.is_ok(), expected_flag(fields[2]), "{name}");
        assert_eq!(result == Ok(true), expected_flag(fields[3]), "{name}");

        accepted += usize::from(result.is_ok());
        completed += usize::from(result == Ok(true));
    }

    assert_eq!((names.len(), accepted, completed), (236, 7, 1));
}
