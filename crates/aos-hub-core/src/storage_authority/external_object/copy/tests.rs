//! Immutable-operation projection and copy-selector regression tests.

use super::*;

#[test]
fn scheduled_storage_permission_and_secondary_permission_are_preserved() {
    let mut value = original();
    value.topology.control_permission = Permission::StorageManage.as_str().into();
    value.topology.destination.control_permission = value.topology.control_permission.clone();
    value.validate().unwrap();
    assert_eq!(value.topology.control_permission, "storage.manage");

    value.topology.source.control_permission = Permission::StorageManage.as_str().into();
    assert!(value.validate().is_err());
    value.topology.source.control_permission = Permission::PlacementManage.as_str().into();
    value.topology.destination.control_permission = Permission::PlacementManage.as_str().into();
    assert!(value.validate().is_err());
    value.topology.control_permission = Permission::Publish.as_str().into();
    value.topology.source.control_permission = value.topology.control_permission.clone();
    value.topology.destination.control_permission = value.topology.control_permission.clone();
    assert!(value.validate().is_err());
}

#[test]
fn sql_placement_target_selectors_are_preserved_without_normalization() {
    let mut value = original();
    value.topology.source.stable_id = "registry:source/placement:Primary copy".into();
    value.topology.destination.stable_id = "registry:source/placement:Destination".into();
    value.validate().unwrap();
    assert_eq!(
        value.topology.source.stable_id,
        "registry:source/placement:Primary copy"
    );
    for invalid in [
        " ".to_owned(),
        " leading".to_owned(),
        "trailing ".to_owned(),
        "bad\nname".to_owned(),
        "x".repeat(256),
    ] {
        let mut changed = value.clone();
        changed.topology.source.stable_id = invalid;
        assert!(changed.validate().is_err());
    }
}

pub(super) fn original() -> ExternalCopyOriginal {
    let target = |stable_id: &str, generation_key| CopyTarget {
        stable_id: stable_id.into(),
        authorization_scope_key: "org:1/registry:2".into(),
        control_permission: "placement.manage".into(),
        generation_key: LeaseInteger::new(generation_key).unwrap(),
        configuration_digest: String::new(),
    };
    let placement = |placement_id, version, prefix: &str| CopyPlacementPin {
        placement_id: LeaseInteger::new(placement_id).unwrap(),
        binding_id: LeaseInteger::new(1).unwrap(),
        resource_version: LeaseInteger::new(version).unwrap(),
        write_spec_version: LeaseInteger::new(3).unwrap(),
        registry_id: Some(LeaseInteger::new(2).unwrap()),
        cache_id: None,
        prefix: prefix.into(),
    };
    ExternalCopyOriginal {
        version: 1,
        deployment_id: "deployment".into(),
        topology: CopyTopologyOriginal {
            operation_id: "retained-topology-operation".into(),
            operation_kind: CopyOperationKind::ReplicatePlacement,
            authorization_scope_key: "org:1/registry:2".into(),
            control_permission: "placement.manage".into(),
            created_at: LeaseInteger::new(100).unwrap(),
            source: target("source-placement", 4),
            destination: target("destination-placement", 5),
        },
        binding_id: LeaseInteger::new(1).unwrap(),
        binding_stable_id: "binding".into(),
        binding_resource_version: LeaseInteger::new(6).unwrap(),
        snapshot_revision: "a".repeat(64),
        source: placement(10, 4, "source/"),
        destination: placement(11, 5, "destination/"),
        path: "nar/object.nar".into(),
        source_object: CopySourceObject {
            provider_version: "actual-source-version".into(),
            etag: "\"source-tag\"".into(),
            bytes: LeaseInteger::new(11).unwrap(),
        },
        read_generation: LeaseInteger::new(2).unwrap(),
        write_generation: LeaseInteger::new(3).unwrap(),
        binding_write_revision: LeaseInteger::new(8).unwrap(),
        profile_digest: "b".repeat(64),
        part_bytes: LeaseInteger::new(MIN_DIRECT_PART_BYTES as i64).unwrap(),
        expected_sha256: None,
    }
}

#[test]
fn stable_owner_does_not_renew_or_readdress_changed_source() {
    let initial = original();
    let id = initial.copy_id().unwrap();
    let fingerprint = initial.fingerprint().unwrap();

    let mut changed = initial.clone();
    changed.source_object.provider_version = "replacement-source-version".into();
    assert_eq!(changed.copy_id().unwrap(), id);
    assert_ne!(changed.fingerprint().unwrap(), fingerprint);

    changed = initial.clone();
    changed.binding_resource_version = LeaseInteger::new(7).unwrap();
    assert_eq!(changed.copy_id().unwrap(), id);
    assert_ne!(changed.fingerprint().unwrap(), fingerprint);

    changed.path.push_str(".other");
    assert_ne!(changed.copy_id().unwrap(), id);
}

#[test]
fn projection_preserves_sealed_targets_and_excludes_mutable_claim_progress() {
    let expected = original().topology;
    let mut operation = TopologyOperationRecord {
        operation_id: expected.operation_id.clone(),
        operation_kind: "replicate_placement".into(),
        authorization_scope_key: expected.authorization_scope_key.clone(),
        control_permission: expected.control_permission.clone(),
        primary_target_kind: "placement".into(),
        primary_target_stable_id: expected.destination.stable_id.clone(),
        primary_target_generation_key: expected.destination.generation_key.get(),
        primary_target_configuration_digest: String::new(),
        state: "running".into(),
        progress_current: 0,
        progress_total: None,
        detail_json: "{}".into(),
        error: None,
        created_at: expected.created_at.get(),
        started_at: Some(101),
        finished_at: None,
        resource_version: 2,
    };
    let target = |role: &str, target: &CopyTarget| TopologyOperationTargetRecord {
        operation_id: expected.operation_id.clone(),
        role: role.into(),
        target_kind: "placement".into(),
        stable_id: target.stable_id.clone(),
        authorization_scope_key: target.authorization_scope_key.clone(),
        control_permission: Permission::PlacementManage,
        generation_key: target.generation_key.get(),
        configuration_digest: target.configuration_digest.clone(),
    };
    let source = target("source", &expected.source);
    let destination = target("primary", &expected.destination);
    assert_eq!(
        CopyTopologyOriginal::from_records(&operation, &source, &destination).unwrap(),
        expected
    );

    operation.resource_version += 1;
    operation.progress_current = 4;
    operation.detail_json = "{\"retry\":true}".into();
    assert_eq!(
        CopyTopologyOriginal::from_records(&operation, &source, &destination).unwrap(),
        expected
    );

    let mut foreign = destination;
    foreign.generation_key += 1;
    assert!(CopyTopologyOriginal::from_records(&operation, &source, &foreign).is_err());
}

#[test]
fn immutable_source_and_same_surface_pins_are_required() {
    for version in ["", "null"] {
        let mut value = original();
        value.source_object.provider_version = version.into();
        assert!(value.validate().is_err());
    }
    let mut value = original();
    value.source_object.etag = "W/\"weak\"".into();
    assert!(value.validate().is_err());

    value = original();
    value.destination.registry_id = Some(LeaseInteger::new(9).unwrap());
    assert!(value.validate().is_err());

    value = original();
    value.destination.binding_id = LeaseInteger::new(9).unwrap();
    assert!(value.validate().is_err());

    value = original();
    value.destination.prefix = value.source.prefix.clone();
    assert!(value.validate().is_err());

    value = original();
    value.source.resource_version = LeaseInteger::new(5).unwrap();
    assert!(value.validate().is_err());
}

#[test]
fn ranges_are_exact_and_long_original_paths_remain_lossless() {
    let mut value = original();
    value.source_object.bytes = LeaseInteger::new(MIN_DIRECT_PART_BYTES as i64 + 3).unwrap();
    value.path = "x".repeat(2048);
    value.validate().unwrap();
    assert_eq!(value.part_count().unwrap(), 2);
    assert_eq!(value.part_range(1).unwrap(), (0, MIN_DIRECT_PART_BYTES));
    assert_eq!(value.part_range(2).unwrap(), (MIN_DIRECT_PART_BYTES, 3));
    assert!(value.part_range(0).is_err());
    assert!(value.part_range(3).is_err());

    value.path.push('x');
    assert!(value.validate().is_err());
    value = original();
    value.source_object.bytes = LeaseInteger::new(0).unwrap();
    assert_eq!(value.part_count().unwrap(), 0);
    assert!(value.part_range(1).is_err());
}

#[test]
fn canonical_original_decoder_refuses_unrecognized_permission_fields() {
    let mut encoded = serde_json::to_value(original()).unwrap();
    encoded["renew_until"] = serde_json::json!(999999);
    assert!(serde_json::from_value::<ExternalCopyOriginal>(encoded).is_err());
}
