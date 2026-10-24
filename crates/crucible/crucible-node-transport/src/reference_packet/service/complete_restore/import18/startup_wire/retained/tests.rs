//! Exercises original immutable launch ownership through successful and failed decode.

use super::*;
use crate::reference_packet::service::complete_restore::import18::inert_bootstrap_fixtures::{
    boot, recipe, selected_launch,
};
use serde_json::json;

fn original(reactive: bool, bad_boot: bool) -> (OriginalImport18DecodedBodies, [[usize; 3]; 3]) {
    let mut boot = boot(32, json!({}));
    if bad_boot {
        boot["foreign_field"] = json!(true);
    }
    let raw = [recipe(), selected_launch(reactive), boot]
        .map(|value| canonical::canonical_json(&value).unwrap());
    let mut owner = OriginalImport18DecodedBodies::empty();
    let rows = owner
        .construction_data(raw.each_ref().map(Vec::as_slice), usize::MAX / 4)
        .unwrap();

    owner.decode_recipe(&raw[0]).unwrap();
    owner.decode_launch(&raw[1]).unwrap();
    if bad_boot {
        assert!(owner.decode_boot(&raw[2]).is_err());
    } else {
        owner.decode_boot(&raw[2]).unwrap();
    }
    (owner, rows)
}

#[test]
fn original_launch_graph_survives_its_decoder_through_the_same_shared_edge() {
    for reactive in [false, true] {
        let (owner, rows) = original(reactive, false);
        let launch = owner.shared_launch_data().unwrap();
        let address = std::ptr::from_ref(launch.launch_data());
        let before = owner.retained_backing_data().unwrap();
        let alias = Rc::clone(launch);
        let weak = Rc::downgrade(launch);

        assert!(Rc::ptr_eq(launch, &alias));
        assert!(std::ptr::eq(
            owner.bodies_data().unwrap().launch,
            alias.as_ref()
        ));
        assert_eq!(owner.retained_backing_data().unwrap(), before);
        assert!(rows.into_iter().map(|row| row[0]).sum::<usize>() >= before);

        drop(owner);

        assert_eq!(std::ptr::from_ref(alias.launch_data()), address);
        assert!(Rc::ptr_eq(&weak.upgrade().unwrap(), &alias));
        drop(alias);
        assert!(weak.upgrade().is_none());
    }
}

#[test]
fn equal_decoded_launches_have_distinct_original_owners() {
    for reactive in [false, true] {
        let (first, _) = original(reactive, false);
        let (second, _) = original(reactive, false);
        let first = first.shared_launch_data().unwrap();
        let second = second.shared_launch_data().unwrap();

        assert_eq!(
            serde_json::to_value(first.as_ref()).unwrap(),
            serde_json::to_value(second.as_ref()).unwrap(),
        );
        assert!(!Rc::ptr_eq(first, second));
    }
}

#[test]
fn later_boot_failure_keeps_the_original_launch_graph_and_refuses_replacement() {
    for reactive in [false, true] {
        let (mut owner, rows) = original(reactive, true);
        let original = Rc::clone(owner.shared_launch_data().unwrap());
        let before = owner.retained_backing_data().unwrap();
        let replacement = canonical::canonical_json(&selected_launch(reactive)).unwrap();

        assert_eq!(owner.partial_presence_data(), [true, true, false]);
        assert!(owner.bodies_data().is_err());
        assert!(owner.decode_launch(&replacement).is_err());

        assert!(Rc::ptr_eq(owner.shared_launch_data().unwrap(), &original));
        assert_eq!(owner.retained_backing_data().unwrap(), before);
        assert!(rows.into_iter().map(|row| row[0]).sum::<usize>() >= before);
    }
}
