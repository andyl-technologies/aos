//! Tests extracted from the adjacent production module.

use super::*;

fn id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value)
        .unwrap_or_else(|error| panic!("test storage policy ID should be valid: {error}"))
}

#[test]
fn ninep_errno_and_object_paths_fail_closed() {
    let errno = WorldStoragePolicyArtifact {
        id: id("ninep-error"),
        semantic_version: 1,
        artifact: StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::NineP {
            errno: 0,
        }),
    };
    assert!(errno.validate().is_err());

    let object = WorldStoragePolicyArtifact {
        id: id("stale-object"),
        semantic_version: 1,
        artifact: StoragePolicyArtifactKind::NinePObject(StoragePolicyNinePObject {
            path: String::from("/safe/../escape"),
            version: 1,
            mode: 0o100_644,
            data: Vec::new(),
            deleted: false,
        }),
    };
    assert!(object.validate().is_err());
}

#[test]
fn service_classes_and_array_members_require_strict_canonical_order() {
    let operations = OperationSet::new(vec![FaultOperation::StorageRead])
        .unwrap_or_else(|error| panic!("test storage operation set should be valid: {error}"));
    let class = StoragePolicyServiceClass {
        class: id("foreground"),
        operations,
        priority: 0,
        weight: PositiveU64::new("weight", 1)
            .unwrap_or_else(|error| panic!("test weight should be valid: {error}")),
    };
    let service = WorldStoragePolicyArtifact {
        id: id("service"),
        semantic_version: 1,
        artifact: StoragePolicyArtifactKind::Service(StoragePolicyService {
            discipline: StoragePolicyQueueDiscipline::StrictPriority,
            classes: vec![class.clone(), class],
            rebuild_shares_service: true,
        }),
    };
    assert!(service.validate().is_err());

    let reversed_service = WorldStoragePolicyArtifact {
        id: id("reversed-service"),
        semantic_version: 1,
        artifact: StoragePolicyArtifactKind::Service(StoragePolicyService {
            discipline: StoragePolicyQueueDiscipline::StrictPriority,
            classes: vec![
                StoragePolicyServiceClass {
                    class: id("foreground-z"),
                    operations: OperationSet::new(vec![FaultOperation::StorageRead])
                        .unwrap_or_else(|error| panic!("operation set: {error}")),
                    priority: 0,
                    weight: PositiveU64::new("weight", 1)
                        .unwrap_or_else(|error| panic!("weight: {error}")),
                },
                StoragePolicyServiceClass {
                    class: id("foreground-a"),
                    operations: OperationSet::new(vec![FaultOperation::StorageWrite])
                        .unwrap_or_else(|error| panic!("operation set: {error}")),
                    priority: 1,
                    weight: PositiveU64::new("weight", 1)
                        .unwrap_or_else(|error| panic!("weight: {error}")),
                },
            ],
            rebuild_shares_service: true,
        }),
    };
    assert!(reversed_service.validate().is_err());

    let member = StoragePolicyArrayMemberState {
        member: id("member-a"),
        online: true,
    };
    let path = StoragePolicyArrayPathState {
        path: id("path-a"),
        online: true,
    };
    let array = WorldStoragePolicyArtifact {
        id: id("array-state"),
        semantic_version: 1,
        artifact: StoragePolicyArtifactKind::ArrayState {
            members: vec![member.clone(), member],
            paths: vec![path.clone()],
        },
    };
    assert!(array.validate().is_err());

    let reversed_array = WorldStoragePolicyArtifact {
        id: id("reversed-array-state"),
        semantic_version: 1,
        artifact: StoragePolicyArtifactKind::ArrayState {
            members: vec![
                StoragePolicyArrayMemberState {
                    member: id("member-z"),
                    online: true,
                },
                StoragePolicyArrayMemberState {
                    member: id("member-a"),
                    online: true,
                },
            ],
            paths: vec![path],
        },
    };
    assert!(reversed_array.validate().is_err());
}

#[test]
fn unknown_storage_policy_fields_are_rejected() {
    let json = r#"{
            "id":"result",
            "semantic_version":1,
            "artifact":{"kind":"typed_result","parameters":{"protocol":"block","result":"success","ignored":true}}
        }"#;
    assert!(serde_json::from_str::<WorldStoragePolicyArtifact>(json).is_err());

    let outer = r#"{
            "id":"bytes",
            "semantic_version":1,
            "artifact":{"kind":"bytes","parameters":{"bytes":[1]},"ignored":true}
        }"#;
    assert!(serde_json::from_str::<WorldStoragePolicyArtifact>(outer).is_err());

    let dirty_eviction = r#"{
            "id":"cache",
            "semantic_version":1,
            "artifact":{"kind":"cache","parameters":{
                "eviction":"fifo",
                "dirty_eviction":{"kind":"persist","ignored":true},
                "power_loss_protected":false
            }}
        }"#;
    assert!(serde_json::from_str::<WorldStoragePolicyArtifact>(dirty_eviction).is_err());

    let duplicate = r#"{
            "id":"duplicate",
            "semantic_version":1,
            "artifact":{"kind":"duplicate_completion","parameters":{
                "kind":"ignore","ignored":true
            }}
        }"#;
    assert!(serde_json::from_str::<WorldStoragePolicyArtifact>(duplicate).is_err());
}

#[test]
fn path_retry_results_are_nonempty_canonical_failures() {
    let path = |retry_results| WorldStoragePolicyArtifact {
        id: id("path-policy"),
        semantic_version: 1,
        artifact: StoragePolicyArtifactKind::Path(StoragePolicyPath {
            selection: StoragePolicyPathSelection::ActivePassive,
            maximum_attempts: BoundedCount::new(CountLimit::LargeStateEntries, 3)
                .unwrap_or_else(|error| panic!("attempt count: {error}")),
            retry_delay_nanos: PositiveU64::new("retry delay", 1)
                .unwrap_or_else(|error| panic!("retry delay: {error}")),
            recovery_probe_interval_nanos: PositiveU64::new("probe interval", 1)
                .unwrap_or_else(|error| panic!("probe interval: {error}")),
            retry_results,
        }),
    };
    assert!(
        path(vec![
            StoragePolicyResult::Busy,
            StoragePolicyResult::Timeout
        ])
        .validate()
        .is_ok()
    );
    assert!(path(Vec::new()).validate().is_err());
    assert!(
        path(vec![
            StoragePolicyResult::Timeout,
            StoragePolicyResult::Busy
        ])
        .validate()
        .is_err()
    );
    assert!(path(vec![StoragePolicyResult::Success]).validate().is_err());
}
