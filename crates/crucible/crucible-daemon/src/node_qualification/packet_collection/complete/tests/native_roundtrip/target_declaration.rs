//! Declares distinct live target owners while preserving durable compatibility.
//!
//! These are explicit fixture requests, not restored authority. The genuine
//! code graph, archive tickets and target constructors independently validate
//! their correspondence before any native or scheduler effect.

use super::*;
use crucible_engine::node_contract::{HostSchedulingOwner, HostSchedulingSelection, OwnerIdentity};
use crucible_node_format::{NodeBinding, U64, Validate};
use crucible_node_transport::reference_packet::coordinator::PacketNative5CoordinatorInstallation;

pub(in crate::node_qualification::packet_collection::complete) fn target_declaration(
    original: &serde_json::Value,
) -> serde_json::Value {
    target_declaration_for(original, "")
}

/// Requests a distinct fixture incarnation before either target code plan exists.
pub(in crate::node_qualification::packet_collection::complete) fn target_declaration_for(
    original: &serde_json::Value,
    label: &str,
) -> serde_json::Value {
    let prefix = if label.is_empty() {
        "installed-target".to_owned()
    } else {
        format!("installed-target-{label}")
    };
    let mut selected = original.clone();
    selected["schema"] = serde_json::json!("crucible.complete-scene.installation/6");
    let mut coordinator: PacketNative5CoordinatorInstallation =
        serde_json::from_value(original["coordinator"].clone()).unwrap();
    let old_generation: U64 =
        serde_json::from_value(coordinator.template["activation"]["generation"].clone()).unwrap();
    let resources: crucible_node_format::ResourceLimits =
        serde_json::from_value(selected["resources"].clone()).unwrap();
    let operations = resources.maximum_operations.get();
    assert!(operations > 0 && operations <= 256);
    let mut identities = Vec::with_capacity(4);
    for member in 0..3 {
        let requests: U64 = serde_json::from_value(
            selected["participants"][member]["storage"]["limits"]["requests"].clone(),
        )
        .unwrap();
        // The explicit target suffix reserves the actual installed scenario
        // count. Its declared native transport must carry that same finite
        // allowance; old Original15/legacy declarations remain unchanged.
        selected["participants"][member]["storage"]["limits"]["requests"] =
            serde_json::to_value(U64::new(requests.get().max(operations))).unwrap();
        let mut binding: NodeBinding = serde_json::from_value(
            selected["participants"][member]["installation"]["binding"].clone(),
        )
        .unwrap();
        let compatibility = binding.identity().unwrap();
        binding.authority.incarnation_id = id(&format!("{prefix}-native-incarnation-{member}"));
        binding.authority.owner_generation = U64::new(
            binding
                .authority
                .owner_generation
                .get()
                .checked_add(1)
                .unwrap(),
        );
        binding.validate().unwrap();
        assert_eq!(binding.identity().unwrap(), compatibility);
        let owner = OwnerIdentity {
            owner: coordinator.participants[member].realization.owner_bindings[0]
                .owner
                .id
                .clone(),
            incarnation: binding.authority.incarnation_id.clone(),
            generation: binding.authority.owner_generation,
        };
        selected["participants"][member]["installation"]["binding"] =
            serde_json::to_value(&binding).unwrap();
        coordinator.participants[member].realization.bindings[0] = binding.clone();
        coordinator.template["nodes"][member]["binding"] = serde_json::to_value(binding).unwrap();
        coordinator.template["nodes"][member]["route"]["owners"] = serde_json::json!([owner]);
        coordinator.template["owners"][member]["identity"] = serde_json::to_value(&owner).unwrap();
        identities.push(owner);
    }
    let mut host: HostSchedulingSelection =
        serde_json::from_value(selected["host"].clone()).unwrap();
    let compatibility = host.binding.identity().unwrap();
    host.binding.authority.incarnation_id = id(&format!("{prefix}-host-incarnation"));
    host.binding.authority.owner_generation = U64::new(
        host.binding
            .authority
            .owner_generation
            .get()
            .checked_add(1)
            .unwrap(),
    );
    host.binding.validate().unwrap();
    assert_eq!(host.binding.identity().unwrap(), compatibility);
    let world: crucible_node_format::WorldBinding =
        serde_json::from_value(selected["world"].clone()).unwrap();
    let owner = HostSchedulingOwner::new_complete_original_continuation(
        host.clone(),
        world.identity().unwrap(),
    )
    .unwrap();
    let source = owner.source();
    let initial = source.initial_node_record().unwrap();
    let identity = OwnerIdentity {
        owner: host.owner.owner.id.clone(),
        incarnation: host.binding.authority.incarnation_id.clone(),
        generation: host.binding.authority.owner_generation,
    };
    selected["host"] = serde_json::to_value(&host).unwrap();
    coordinator.host.binding = host.binding;
    coordinator.host.prepared_token = source.prepared_token().clone();
    coordinator.host.initial_node = initial.clone();
    coordinator.template["nodes"][3] = initial;
    coordinator.template["owners"][3]["identity"] = serde_json::to_value(&identity).unwrap();
    identities.push(identity);
    coordinator.template["activation"]["owners"] = serde_json::to_value(&identities).unwrap();
    coordinator.template["activation"]["generation"] =
        serde_json::to_value(U64::new(old_generation.get().checked_add(1).unwrap())).unwrap();
    coordinator.template["activation"]["activation_id"] = if label.is_empty() {
        serde_json::json!("installed-packet-restored-world")
    } else {
        serde_json::json!(format!("installed-packet-restored-world-{label}"))
    };
    for participant in &coordinator.participants {
        coordinator.validate(participant).unwrap();
    }
    selected["coordinator"] = serde_json::to_value(coordinator).unwrap();
    assert_eq!(selected["world"], original["world"]);
    selected
}

#[test]
fn fresh_owner_declaration_keeps_durable_world_and_advances_each_live_owner() {
    let scene = scene(&std::env::current_exe().unwrap());
    let mut original = super::super::scene_declaration(&scene);
    original["schema"] = serde_json::json!("crucible.complete-scene.installation/5");
    let target = target_declaration(&original);
    let old = &original["coordinator"]["template"]["activation"]["owners"];
    let new = &target["coordinator"]["template"]["activation"]["owners"];
    let old: Vec<OwnerIdentity> = serde_json::from_value(old.clone()).unwrap();
    let new: Vec<OwnerIdentity> = serde_json::from_value(new.clone()).unwrap();
    for (before, after) in old.iter().zip(&new) {
        assert_eq!(before.owner, after.owner);
        assert!(after.generation > before.generation);
        assert!(
            old.iter()
                .all(|historical| historical.incarnation != after.incarnation)
        );
    }
    assert_eq!(target["world"], original["world"]);
    let resources: crucible_node_format::ResourceLimits =
        serde_json::from_value(target["resources"].clone()).unwrap();
    for member in 0..3 {
        let actual: U64 = serde_json::from_value(
            target["participants"][member]["storage"]["limits"]["requests"].clone(),
        )
        .unwrap();
        let before: U64 = serde_json::from_value(
            original["participants"][member]["storage"]["limits"]["requests"].clone(),
        )
        .unwrap();
        assert_eq!(
            actual.get(),
            before.get().max(resources.maximum_operations.get())
        );
        assert!(actual.get() <= 256);
    }
    // This helper produces only static declarations: it cannot start a native
    // lifecycle or make any original Source select the suffix construction.
    assert!(scene.roster.sources.iter().all(|source| {
        !source
            .is_original_restored_suffix_declaration_data()
            .unwrap()
    }));
}

#[test]
fn sibling_declarations_have_distinct_live_identities_and_same_durable_world() {
    let scene = scene(&std::env::current_exe().unwrap());
    let original = super::super::scene_declaration(&scene);
    let first = target_declaration_for(&original, "first");
    let second = target_declaration_for(&original, "second");
    assert_eq!(first["world"], second["world"]);
    assert_ne!(
        first["coordinator"]["template"]["activation"]["activation_id"],
        second["coordinator"]["template"]["activation"]["activation_id"]
    );

    let first: Vec<OwnerIdentity> =
        serde_json::from_value(first["coordinator"]["template"]["activation"]["owners"].clone())
            .unwrap();
    let second: Vec<OwnerIdentity> =
        serde_json::from_value(second["coordinator"]["template"]["activation"]["owners"].clone())
            .unwrap();
    for (left, right) in first.iter().zip(&second) {
        assert_eq!(left.owner, right.owner);
        assert_eq!(left.generation, right.generation);
        assert!(
            second
                .iter()
                .all(|other| left.incarnation != other.incarnation)
        );
    }
}
