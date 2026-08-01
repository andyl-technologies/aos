//! Checks T-OBS-13 event-kind catalog freezing.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use crucible::{
    EVENT_KIND_CATALOG_VERSION, EventClass, event_kind_catalog, event_kind_catalog_canonical_bytes,
    event_kind_catalog_canonical_material, event_kind_catalog_class,
    event_kind_catalog_dependency_map, event_kind_catalog_entry,
};

const EXPECTED_CATALOG_SERIALIZATION: &str = "\
event_kind_catalog.version=1
event_kind_catalog.entries=41
entry kind=app_random class=causal sources=guest,node attributes=node,request_id,stream_domain,stream_name,value,width
entry kind=assertion_evaluated class=causal sources=engine,guest attributes=condition,detail.*.key,detail.*.value,details_len,flavor,id,message
entry kind=assertion_proximity class=observational sources=engine attributes=distance,id,node,quantifier
entry kind=assertion_state_changed class=causal sources=engine attributes=id,new_state
entry kind=backend_input class=causal sources=engine,node attributes=consumer,node,payload,producer,sequence,virtual_time
entry kind=console_output class=observational sources=node attributes=bytes,node
entry kind=control class=causal sources=command attributes=command,command_id,consumer,producer,sequence,virtual_time
entry kind=control_fault class=causal sources=command,engine attributes=action,at,command_id
entry kind=coverage class=observational sources=engine,guest attributes=block,block_len,execution_icount,guest_pc,id,kind,node,retired_icount
entry kind=delivery_order class=causal sources=engine attributes=at,events
entry kind=diagnostic class=observational sources=command,engine,node attributes=details,name
entry kind=evaluation_boundary class=causal sources=engine attributes=boundary
entry kind=event_activated class=causal sources=scenario attributes=event,summary
entry kind=fault_activated class=causal sources=engine,scenario attributes=description,kind,tag,targets
entry kind=fault_activation class=causal sources=engine,scenario attributes=consumer,fault,producer,sequence,virtual_time
entry kind=fault_fires class=causal sources=engine attributes=at,fault,fired
entry kind=fault_healed class=causal sources=engine,scenario attributes=tag
entry kind=fork class=causal sources=command,engine attributes=from_checkpoint_id,schedule_delta
entry kind=guest_marker class=observational sources=guest attributes=assertion,condition,detail.*.key,detail.*.value,details_len,flavor,location,marker,marker_kind,message,must_hit,node,retired_icount
entry kind=io_completion class=causal sources=engine,node attributes=consumer,delivery_icount,node,payload,producer,sequence,virtual_time
entry kind=memory_sample class=observational sources=engine,node attributes=node,place,sample_icount,value
entry kind=message_delivered class=causal sources=engine,node attributes=deliver_icount,from,len,link,seq,to
entry kind=message_dropped class=causal sources=engine,node attributes=from,link,reason,to
entry kind=network_delivered class=observational sources=engine,node attributes=link,payload
entry kind=node_completed class=causal sources=engine,node attributes=node,outcome
entry kind=node_crashed class=causal sources=engine,node attributes=node,reason
entry kind=node_started class=causal sources=engine,node attributes=node,ready_point
entry kind=node_state class=observational sources=engine,node attributes=node,state
entry kind=observed_io_completion class=observational sources=engine,node attributes=kind,node,payload
entry kind=override class=causal sources=engine attributes=choice,point
entry kind=preemption class=causal sources=engine attributes=at,kind,node
entry kind=probabilistic_fault class=causal sources=engine attributes=consumer,fault,producer,rate_basis_points,sequence,stream_domain,stream_name,virtual_time
entry kind=rng_draw class=causal sources=engine attributes=stream_domain,stream_name,value
entry kind=savepoint class=causal sources=command,engine attributes=checkpoint_id,event_log_offset
entry kind=state_transition class=causal sources=engine,node attributes=cause,from_state,node,to_state
entry kind=tick class=causal sources=engine attributes=icount,virtual_time
entry kind=timer_armed class=causal sources=engine,node attributes=fire_icount,node,timer
entry kind=timer_cancelled class=causal sources=engine,node attributes=node,timer
entry kind=timer_fired class=causal sources=engine,node attributes=node,timer
entry kind=trigger_action_applied class=causal sources=engine,scenario attributes=action,at,event,sequence
entry kind=trigger_fired class=causal sources=engine,scenario attributes=action,at,condition,event
event_kind_catalog.dependencies=5
dependency consumer=18-assertions-properties kinds=assertion_evaluated,assertion_proximity,assertion_state_changed,guest_marker
dependency consumer=20-session-control-plane kinds=*
dependency consumer=21-api kinds=*
dependency consumer=22-advanced-features kinds=assertion_proximity,coverage
dependency consumer=24-determinism-harness-testing kinds=app_random,assertion_evaluated,assertion_state_changed,backend_input,control,control_fault,delivery_order,evaluation_boundary,event_activated,fault_activated,fault_activation,fault_fires,fault_healed,fork,io_completion,message_delivered,message_dropped,node_completed,node_crashed,node_started,override,preemption,probabilistic_fault,rng_draw,savepoint,state_transition,tick,timer_armed,timer_cancelled,timer_fired,trigger_action_applied,trigger_fired";

#[test]
fn event_kind_catalog_is_versioned_sorted_and_single_source_for_classes() {
    assert_eq!(EVENT_KIND_CATALOG_VERSION, 1);

    let mut kinds = BTreeSet::new();
    let mut previous = "";
    for entry in event_kind_catalog() {
        assert!(
            previous < entry.kind(),
            "catalog kinds must be sorted and unique: {previous:?}, {:?}",
            entry.kind()
        );
        previous = entry.kind();
        assert!(kinds.insert(entry.kind()));
        assert_eq!(event_kind_catalog_class(entry.kind()), Some(entry.class()));
        assert_sorted_unique(entry.sources());
        assert_sorted_unique(entry.attributes());
        assert_eq!(entry.canonical_bytes(), entry.canonical_line().into_bytes());
    }
}

#[test]
fn event_kind_catalog_contains_rfc_19_7_required_kinds() {
    for (kind, class) in [
        ("state_transition", EventClass::Causal),
        ("event_activated", EventClass::Causal),
        ("trigger_fired", EventClass::Causal),
        ("fault_activated", EventClass::Causal),
        ("fault_healed", EventClass::Causal),
        ("node_started", EventClass::Causal),
        ("node_crashed", EventClass::Causal),
        ("node_completed", EventClass::Causal),
        ("timer_armed", EventClass::Causal),
        ("timer_fired", EventClass::Causal),
        ("timer_cancelled", EventClass::Causal),
        ("message_delivered", EventClass::Causal),
        ("message_dropped", EventClass::Causal),
        ("assertion_evaluated", EventClass::Causal),
        ("assertion_state_changed", EventClass::Causal),
        ("savepoint", EventClass::Causal),
        ("fork", EventClass::Causal),
        ("tick", EventClass::Causal),
        ("diagnostic", EventClass::Observational),
        ("coverage", EventClass::Observational),
        ("assertion_proximity", EventClass::Observational),
        ("guest_marker", EventClass::Observational),
    ] {
        let entry = event_kind_catalog_entry(kind)
            .unwrap_or_else(|| panic!("catalog should contain RFC kind {kind}"));
        assert_eq!(entry.class(), class, "{kind}");
    }
}

#[test]
fn event_kind_catalog_records_structural_dependency_map() {
    let dependencies = event_kind_catalog_dependency_map()
        .iter()
        .map(|dependency| (dependency.consumer(), dependency.kinds()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        dependencies
            .get("18-assertions-properties")
            .copied()
            .unwrap_or(&[]),
        &[
            "assertion_evaluated",
            "assertion_proximity",
            "assertion_state_changed",
            "guest_marker",
        ]
    );
    assert_eq!(
        dependencies
            .get("20-session-control-plane")
            .copied()
            .unwrap_or(&[]),
        &["*"]
    );
    assert_eq!(dependencies.get("21-api").copied().unwrap_or(&[]), &["*"]);
    assert_eq!(
        dependencies
            .get("22-advanced-features")
            .copied()
            .unwrap_or(&[]),
        &["assertion_proximity", "coverage"]
    );
    assert_eq!(
        dependencies
            .get("24-determinism-harness-testing")
            .copied()
            .unwrap_or(&[]),
        causal_kinds().as_slice()
    );
}

#[test]
fn event_kind_catalog_dependencies_resolve_to_catalog_entries() {
    for dependency in event_kind_catalog_dependency_map() {
        for kind in dependency.kinds() {
            if *kind == "*" {
                continue;
            }
            assert!(
                event_kind_catalog_entry(kind).is_some(),
                "{} dependency kind {kind} must resolve through the catalog",
                dependency.consumer()
            );
        }
    }
}

#[test]
fn event_kind_catalog_canonical_serialization_matches_golden_vector() {
    assert_eq!(
        event_kind_catalog_canonical_material(),
        EXPECTED_CATALOG_SERIALIZATION
    );
    assert_eq!(
        event_kind_catalog_canonical_bytes(),
        EXPECTED_CATALOG_SERIALIZATION.as_bytes()
    );
}

fn assert_sorted_unique(values: &[&str]) {
    let mut previous = "";
    for value in values {
        assert!(
            previous < *value,
            "catalog values must be sorted and unique: {previous:?}, {value:?}"
        );
        previous = value;
    }
}

fn causal_kinds() -> Vec<&'static str> {
    event_kind_catalog()
        .iter()
        .filter(|entry| entry.class() == EventClass::Causal)
        .map(|entry| entry.kind())
        .collect()
}
