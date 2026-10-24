//! Uses actual installed four-owner metadata without native or SDK dispatch.
//!
//! The fixture measures files and creates local startup descriptors.
//! Controls quote original metadata and exercise refusal paths before runtime attachment.

use super::*;
use crucible_engine::node_admission::{
    ConformanceGraph, FixedFourConformanceGraphConstructionInputs,
};

#[test]
fn actual_original_input_constructor_data_is_exact_and_one_short_without_issuance() {
    let (_scene, original) =
        crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
    let held = original.borrow();
    let before = held
        .authority
        .roster
        .sources
        .each_ref()
        .map(|source| source.original_report_startup_audit_data().unwrap());
    let peak = inputs::quote(&held, usize::MAX).unwrap();
    assert!(peak > 0);
    assert_eq!(inputs::quote(&held, peak).unwrap(), peak);
    assert!(matches!(
        inputs::quote(&held, peak - 1),
        Err(RuntimeError::ResourceLimit)
    ));
    assert!(held.runtime_members.iter().all(|slot| slot.get().is_none()));
    assert!(held.runtime_owners.borrow().schedule.is_none());
    assert_eq!(
        held.authority
            .roster
            .sources
            .each_ref()
            .map(|source| source.original_report_startup_audit_data().unwrap()),
        before
    );
}

#[test]
fn actual_fixed_four_graph_data_checks_all_original_tuple_roots() {
    let (_scene, original) =
        crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
    let held = original.borrow();
    let selected = held
        .authority
        .roster
        .sources
        .each_ref()
        .map(|source| source.installation());
    let host = held.authority.host_source().selection();
    let bytes = held
        .authority
        .graph_policy
        .original_runtime_content_data()
        .get(&held.authority.world().scenario_ref)
        .unwrap();
    let requirements: crucible_engine::node_admission::ScenarioRequirements =
        serde_json::from_slice(bytes).unwrap();
    let input = || FixedFourConformanceGraphConstructionInputs {
        world: held.authority.world(),
        descriptors: [
            &selected[0].descriptor,
            &selected[1].descriptor,
            &selected[2].descriptor,
            &host.descriptor,
        ],
        bindings: [
            &selected[0].binding,
            &selected[1].binding,
            &selected[2].binding,
            &host.binding,
        ],
        owners: [
            &selected[0].owner,
            &selected[1].owner,
            &selected[2].owner,
            &host.owner,
        ],
        requirements: &requirements,
        limits: graph::limits(),
        content: [
            &held.authority.population.bodies,
            held.authority.graph_policy.original_runtime_content_data(),
        ],
    };
    let data = ConformanceGraph::original_fixed_four_construction_storage_data(input(), usize::MAX)
        .unwrap();
    let peak = data
        .retained_requested_bytes()
        .checked_add(data.maximum_simultaneous_transient_bytes())
        .unwrap()
        .checked_add(data.declared_counter_scratch_bytes())
        .unwrap();
    assert_eq!(
        ConformanceGraph::original_fixed_four_construction_storage_data(input(), peak).unwrap(),
        data
    );
    assert!(matches!(
        ConformanceGraph::original_fixed_four_construction_storage_data(input(), peak - 1),
        Err(RuntimeError::ResourceLimit)
    ));
    let mut foreign = host.binding.clone();
    foreign.compatibility.node_id = crucible_node_format::Id::new("foreign-host-node").unwrap();
    let mut changed = input();
    changed.bindings[3] = &foreign;
    assert!(matches!(
        ConformanceGraph::original_fixed_four_construction_storage_data(changed, usize::MAX),
        Err(RuntimeError::InvalidRoute)
    ));
    assert!(held.runtime_members.iter().all(|slot| slot.get().is_none()));
}

#[test]
fn missing_initial_owners_spend_runtime_entry_without_sharing_or_source_mutation() {
    let (_scene, original) =
        crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
    let before = {
        let held = original.borrow();
        held.authority
            .roster
            .sources
            .each_ref()
            .map(|source| source.original_report_startup_audit_data().unwrap())
    };
    assert!(PacketCompleteReportStartupHolder::prepare_original_scene_runtime(&original).is_err());
    assert!(matches!(
        PacketCompleteReportStartupHolder::prepare_original_scene_runtime(&original),
        Err(RuntimeError::DuplicateOperation)
    ));
    let held = original.borrow();
    assert!(held.runtime_attempted[0].get());
    assert!(held.runtime_issuing.get().is_none());
    assert!(held.runtime_members.iter().all(|slot| slot.get().is_none()));
    assert!(held.receiver_reader.shared_data().is_err());
    assert!(held.runtime_owners.borrow().actor.is_none());
    assert_eq!(
        held.authority
            .roster
            .sources
            .each_ref()
            .map(|source| source.original_report_startup_audit_data().unwrap()),
        before
    );
}

#[test]
fn original_holder_refuses_fresh_runtime_and_cleanup_before_owner_changes() {
    let (_scene, original) =
        crate::node_qualification::packet_collection::complete::tests::report_startup_fixture();
    assert!(matches!(
        PacketCompleteReportStartupHolder::prepare_original_fresh_runtime(&original),
        Err(RuntimeError::OutstandingObligations)
    ));
    assert!(matches!(
        PacketCompleteReportStartupHolder::retire_original_fresh_restoration(&original),
        Err(RuntimeError::ForeignAuthority)
    ));
    let held = original.borrow();
    assert!(held.fresh_runtime.get().is_none());
    assert!(
        held.runtime_attempted
            .iter()
            .all(|attempted| !attempted.get())
    );
    assert!(
        held.runtime_members
            .iter()
            .all(|member| member.get().is_none())
    );
    assert!(held.receiver_reader.shared_data().is_err());
    assert!(!held.original_scene_retired.get());
}
