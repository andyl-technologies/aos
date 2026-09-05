//! Tests for signed rollout channel partitions and fix-forward channel advancement.

use super::{
    ensure_channel_advance_fix_forward, parse_partition_list, select_partitions_for_advance,
};
use crate::registry::channel::PartitionMap;

#[test]
fn partition_list_accepts_decimal_and_hex() {
    assert_eq!(
        parse_partition_list("0,1,0a,0xff,1").unwrap(),
        vec![0, 1, 10, 255],
    );
    assert!(parse_partition_list("").is_err());
    assert!(parse_partition_list("256").is_err());
}

#[test]
fn channel_advance_selector_requires_one_mode() {
    let map = PartitionMap::all(semver::Version::parse("1.0.0").unwrap());
    let target = semver::Version::parse("1.1.0").unwrap();

    assert!(select_partitions_for_advance(None, None, &map, &target).is_err());
    assert!(select_partitions_for_advance(Some(1), Some("0"), &map, &target).is_err());
    assert_eq!(
        select_partitions_for_advance(Some(3), None, &map, &target).unwrap(),
        vec![0, 1, 2],
    );
}

#[test]
fn channel_advance_rejects_selected_partition_decrement() {
    let mut map = PartitionMap::all(semver::Version::parse("1.1.0").unwrap());
    map.set(2, semver::Version::parse("1.0.0").unwrap())
        .unwrap();
    let older = semver::Version::parse("1.0.0").unwrap();
    let same = semver::Version::parse("1.1.0").unwrap();
    let newer = semver::Version::parse("1.2.0").unwrap();

    let err = ensure_channel_advance_fix_forward(&map, &[0], &older).unwrap_err();
    assert!(format!("{err:#}").contains("decrement partition 00 from 1.1.0 to 1.0.0"));
    ensure_channel_advance_fix_forward(&map, &[0], &same).unwrap();
    ensure_channel_advance_fix_forward(&map, &[0, 2], &newer).unwrap();
}
