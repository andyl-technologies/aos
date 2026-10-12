//! Checks raw recorded tuples and selected evidence without trusted state.
#![allow(clippy::unwrap_used)]
// Private fixture modules share one immutable independent primitive model.
#[allow(clippy::duplicate_mod)]
#[path = "../encoding/recorded_models.rs"]
mod models;
use super::validate;
use alloc::{format, string::ToString, vec, vec::Vec};
use models::*;

#[test]
fn prov_recorded_context_decoder_requires_exact_revision_and_canonical_fence() {
    for revision in 1..=3 {
        let names = vocabulary(revision);
        let valid = context(revision, &names, &["future.value"], None);
        assert!(validate(&valid).is_ok());
        for end in 0..valid.len() {
            assert!(validate(&valid[..end]).is_err());
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(validate(&trailing).is_err());
        let mut nonminimal = valid.clone();
        nonminimal.splice(1..2, [0x18, 3]);
        assert!(validate(&nonminimal).is_err());
        for version in [0, 1, 2, 4] {
            let mut changed = valid.clone();
            changed[1] = version;
            assert!(validate(&changed).is_err());
        }
        for count in [6, 7, 9] {
            let mut changed = valid.clone();
            changed[0] = 0x80 | count;
            assert!(validate(&changed).is_err());
        }
        let mut names_missing = names.clone();
        names_missing.pop();
        let mut reversed = names.clone();
        reversed.reverse();
        for bad in [&names_missing, &reversed] {
            assert!(validate(&context(revision, bad, &[], None)).is_err());
        }
        for later in [vec![""], vec!["acl"], vec!["z", "a"], vec!["same", "same"]] {
            assert!(validate(&context(revision, &names, &later, None)).is_err());
        }
        assert!(validate(&context(4, &names, &[], None)).is_err());
        let oversized = "x".repeat(256);
        assert!(validate(&context(revision, &names, &[&oversized], None)).is_err());
    }
    // The aggregate bound includes payload UTF-8 bytes, not CBOR headers.
    let mut owned: Vec<_> = (0..257)
        .map(|i| format!("{i:03}{}", "x".repeat(252)))
        .collect();
    owned.push("z".to_string());
    let names = vocabulary(1);
    let refs: Vec<_> = owned.iter().map(|s| s.as_str()).collect();
    assert_eq!(refs.iter().map(|s| s.len()).sum::<usize>(), 65536);
    assert!(validate(&context(1, &names, &refs, None)).is_ok());
    owned.last_mut().unwrap().push('z');
    let refs: Vec<_> = owned.iter().map(|s| s.as_str()).collect();
    assert!(validate(&context(1, &names, &refs, None)).is_err());
    let mut wrong_root = context(1, &names, &[], None);
    // Find the independently known recorded root encoding, then change its width.
    let needle = bytes(&[2; 32]);
    let offset = wrong_root
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    wrong_root[offset + 1] = 31;
    assert!(validate(&wrong_root).is_err());
    let mut claimed_count = context(1, &names, &[], None);
    claimed_count.pop();
    claimed_count.extend(head(4, 65537));
    assert!(validate(&claimed_count).is_err());
}

#[test]
fn prov_recorded_context_selected_rows_keep_existing_relationships() {
    let names = vocabulary(3);
    let good = evidence(1, "private:test", "uid", "uid");
    assert!(validate(&context(3, &names, &[], Some(&good))).is_ok());
    for bad in [
        vec![],
        array(&[]),
        evidence(9, "private:test", "uid", "uid"),
        evidence(1, "public", "uid", "uid"),
        evidence(1, "private:test", "uid", "gid"),
    ] {
        assert!(validate(&context(3, &names, &[], Some(&bad))).is_err());
    }
    let row = &good[1..];
    let duplicate = array(&[row.to_vec(), row.to_vec()]);
    assert!(validate(&context(3, &names, &[], Some(&duplicate))).is_err());
    let mut noncanonical_value = good.clone();
    let needle = bytes(&uint(24));
    let offset = noncanonical_value
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    noncanonical_value.splice(offset..offset + needle.len(), bytes(&[0x18, 0x00]));
    assert!(validate(&context(3, &names, &[], Some(&noncanonical_value))).is_err());
}
