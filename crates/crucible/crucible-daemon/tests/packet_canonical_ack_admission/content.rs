//! Preloads independently available promised declaration bytes before Child.

use super::{encoded, setup::Installed};
use crucible_node_format::{ContentRef, canonical};
use crucible_node_transport::client::ClientContent;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn references(value: &Value, output: &mut BTreeSet<ContentRef>) {
    match value {
        Value::Object(fields)
            if fields.contains_key("hash")
                && fields.contains_key("length")
                && fields.contains_key("media_type") =>
        {
            output.insert(serde_json::from_value(value.clone()).unwrap());
        }
        Value::Object(fields) => {
            for child in fields.values() {
                references(child, output);
            }
        }
        Value::Array(values) => {
            for child in values {
                references(child, output);
            }
        }
        _ => {}
    }
}

fn add_value(value: &Value, objects: &mut BTreeMap<ContentRef, Vec<u8>>) {
    let bytes = canonical::canonical_json(value).unwrap();
    objects.insert(
        canonical::content_ref(&bytes, "application/json").unwrap(),
        bytes,
    );
    match value {
        Value::Object(fields) => {
            for child in fields.values() {
                add_value(child, objects);
            }
        }
        Value::Array(values) => {
            for child in values {
                add_value(child, objects);
            }
        }
        _ => {}
    }
}

pub(super) fn selected(installed: &Installed, member: usize) -> ClientContent {
    let selected = &installed.scene.coordinator.participants[member];
    let source = installed.authority.semantic_source(member).unwrap();
    let mut needed = BTreeSet::new();
    references(
        &serde_json::to_value(&selected.realization).unwrap(),
        &mut needed,
    );
    references(
        &serde_json::to_value(&source.installation().provider).unwrap(),
        &mut needed,
    );
    references(
        &serde_json::to_value(&source.installation().profile).unwrap(),
        &mut needed,
    );
    let mut objects = installed.scene.content.clone();
    add_value(
        &serde_json::to_value(&installed.scene.coordinator).unwrap(),
        &mut objects,
    );
    for value in [
        serde_json::to_value(&source.installation().provider).unwrap(),
        serde_json::to_value(&source.installation().profile).unwrap(),
        serde_json::to_value(&source.installation().capabilities).unwrap(),
        serde_json::to_value(&source.installation().guarantees).unwrap(),
    ] {
        add_value(&value, &mut objects);
    }
    for bytes in [
        crucible_node_transport::reference_packet::contracts::immediate_packet_contract().unwrap(),
        crucible_node_transport::reference_packet::contracts::connected_packet_contract().unwrap(),
        crucible_node_transport::reference_packet::contracts::connected_ingress_contract().unwrap(),
        crucible_node_transport::reference_packet::continuation_contracts::complete_packet_contract().unwrap(),
        crucible_node_transport::reference_packet::continuation_contracts::complete_ingress_contract().unwrap(),
    ] {
        objects.insert(canonical::content_ref(&bytes, "application/json").unwrap(), bytes);
    }
    objects.insert(
        installed.measurements[0].peer.content.clone(),
        installed.peer_bytes.clone(),
    );
    let missing: Vec<_> = needed
        .iter()
        .filter(|reference| !objects.contains_key(*reference))
        .collect();
    for reference in &missing {
        eprintln!(
            "missing original declaration body: {} {} {}",
            reference.hash.digest,
            reference.length.get(),
            reference.media_type
        );
    }
    assert!(
        missing.is_empty(),
        "every promised static body must exist before Child"
    );
    let mut content = ClientContent::new(64 * 1024 * 1024, 1024, 4096).unwrap();
    for reference in needed {
        let bytes = objects.remove(&reference).unwrap();
        reference.verify(&bytes).unwrap();
        content.install(reference, bytes).unwrap();
    }
    let initial = encoded(&installed.scene.coordinator);
    content
        .install(
            canonical::content_ref(&initial, "application/json").unwrap(),
            initial,
        )
        .unwrap();
    content
}
