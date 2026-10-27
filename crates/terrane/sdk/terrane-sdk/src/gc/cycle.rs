//! Selects an unused cycle number from inert retained publication key names.
//!
//! Selection grants no collection authority. The caller must retain the actual
//! singleton lease and held publication through authenticated checkpoint creation.
//! Keys retained with absent values still reserve their cycle numbers.

use super::{CollectionError, denied};
use terrane_format::bucket::BucketKey;

/// Chooses above every registered GC checkpoint, copied reservation and Trash key.
///
/// # Errors
/// Rejects malformed keys in cycle-bearing namespaces and exhausted `u64` cycles.
pub(crate) fn next<'key>(keys: impl Iterator<Item = &'key str>) -> Result<u64, CollectionError> {
    let mut greatest = 0_u64;
    for key in keys {
        let cycle = if let Some(cycle) = key.strip_prefix("gc/cycle/") {
            Some(cycle)
        } else if let Some(rest) = key.strip_prefix("gc/") {
            if rest == "lease" {
                None
            } else {
                Some(rest.split_once('/').ok_or_else(denied)?.0)
            }
        } else if let Some(rest) = key.strip_prefix("trash/") {
            Some(rest.split_once('/').ok_or_else(denied)?.0)
        } else {
            None
        };
        let Some(cycle) = cycle else {
            continue;
        };
        BucketKey::parse(key).map_err(|_| denied())?;
        let cycle = cycle.parse::<u64>().map_err(|_| denied())?;
        greatest = greatest.max(cycle);
    }
    greatest.checked_add(1).ok_or_else(|| denied().into())
}

#[cfg(test)]
mod tests {
    //! Checks selection arithmetic without filesystem, lease or native effects.
    #![allow(
        clippy::unwrap_used,
        reason = "Pure selection tests require success and panic on an unexpected refusal."
    )]

    use super::*;

    #[test]
    fn empty_inventory_starts_at_one_and_ignores_unrelated_keys() {
        assert_eq!(next(std::iter::empty()).unwrap(), 1);
        assert_eq!(
            next(["gc/lease", "objects/index/999/MANIFEST"].into_iter()).unwrap(),
            1
        );
    }

    #[test]
    fn greatest_cycle_is_numeric_and_independent_of_listing_order() {
        let keys = [
            "gc/9/state",
            "gc/100/roots",
            "gc/11/mark/171/0",
            "gc/2/state",
        ];
        assert_eq!(next(keys.into_iter()).unwrap(), 101);
        assert_eq!(next(keys.into_iter().rev()).unwrap(), 101);
    }

    #[test]
    fn copied_reservations_and_trash_prevent_reuse() {
        let trash = "trash/71/000102030405060708090a0b0c0d0e0f";
        let deletion = "gc/73/delete/000102030405060708090a0b0c0d0e0f/404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        assert_eq!(next(["gc/cycle/70", trash].into_iter()).unwrap(), 72);
        assert_eq!(next([trash, deletion].into_iter()).unwrap(), 74);
        assert_eq!(next([deletion, "gc/cycle/80"].into_iter()).unwrap(), 81);
    }

    #[test]
    fn retained_absent_values_still_reserve_cycles() {
        let keys = std::collections::BTreeMap::from([
            ("gc/3/roots", Some(Vec::<u8>::new())),
            ("gc/20/state", None),
        ]);
        assert_eq!(next(keys.keys().copied()).unwrap(), 21);
    }

    #[test]
    fn malformed_or_unregistered_cycle_names_are_rejected() {
        for key in [
            "gc/01/roots",
            "gc/-1/state",
            "gc/2/unknown",
            "gc/2",
            "gc/cycle/3/extra",
            "gc/cycle/18446744073709551616",
            "trash/4/invalid",
            "trash/4",
        ] {
            assert!(next([key].into_iter()).is_err(), "{key}");
        }
    }

    #[test]
    fn exhausted_cycle_numbers_fail_without_wrapping() {
        assert!(next(["gc/18446744073709551615/roots"].into_iter()).is_err());
        assert_eq!(
            next(["gc/cycle/18446744073709551614"].into_iter()).unwrap(),
            u64::MAX
        );
    }
}
