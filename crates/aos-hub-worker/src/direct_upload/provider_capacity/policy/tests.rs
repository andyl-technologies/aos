//! Source identity and accepted-bound separation for the common isolate policy.

use super::*;

fn policy() -> Policy {
    Policy {
        version: 1,
        deployment_id: "actual-deployment".into(),
        source_digest: "a".repeat(64),
        script_version: "actual-script".into(),
        maximum_provider_requests: 3,
    }
}

#[test]
fn independently_admitted_domains_use_one_effective_capacity() {
    let policy = policy();
    assert_eq!(policy.exact(3).unwrap(), 3);
    assert_eq!(policy.bounded(3, 3).unwrap(), 3);
    assert_eq!(policy.bounded(5, 3).unwrap(), 3);
    assert!(policy.bounded(2, 3).is_err());
    assert!(policy.exact(5).is_err());
}

#[test]
fn only_an_absent_binding_can_fall_back_to_legacy_capacity() {
    let policy = policy();
    let decode = |present, raw| {
        Policy::parse_binding(
            present,
            raw,
            &policy.deployment_id,
            &policy.source_digest,
            &policy.script_version,
        )
    };
    assert!(decode(false, None).unwrap().is_none());
    assert!(decode(true, None).is_err());
    assert!(decode(true, Some("null")).is_err());
    assert!(decode(true, Some("{}")).is_err());
    assert!(decode(false, Some("{}")).is_err());
    let raw = serde_json::to_string(&policy).unwrap();
    assert_eq!(decode(true, Some(&raw)).unwrap(), Some(policy));
}

#[test]
fn policy_cannot_relabel_qualification_or_enable_an_insufficient_copy_pool() {
    let mut policy = policy();
    policy.maximum_provider_requests = 2;
    assert!(policy.exact(3).is_err());
    assert!(policy.bounded(5, 3).is_err());
    assert_eq!(policy.bounded(5, 1).unwrap(), 2);
}

#[test]
fn installed_identity_unknown_fields_and_size_remain_checked() {
    let policy = policy();
    let raw = serde_json::to_string(&policy).unwrap();
    assert_eq!(
        Policy::parse(
            &raw,
            &policy.deployment_id,
            &policy.source_digest,
            &policy.script_version
        )
        .unwrap(),
        policy
    );
    assert!(
        Policy::parse(
            &raw,
            "another-deployment",
            &policy.source_digest,
            &policy.script_version
        )
        .is_err()
    );
    assert!(
        Policy::parse(
            &raw,
            &policy.deployment_id,
            &"b".repeat(64),
            &policy.script_version
        )
        .is_err()
    );
    assert!(
        Policy::parse(
            &raw,
            &policy.deployment_id,
            &policy.source_digest,
            "another-script"
        )
        .is_err()
    );
    let mut unknown = serde_json::to_value(&policy).unwrap();
    unknown["permission"] = serde_json::Value::Bool(true);
    assert!(
        Policy::parse(
            &unknown.to_string(),
            &policy.deployment_id,
            &policy.source_digest,
            &policy.script_version
        )
        .is_err()
    );
    assert!(
        Policy::parse(
            &" ".repeat(MAX_POLICY_BYTES + 1),
            &policy.deployment_id,
            &policy.source_digest,
            &policy.script_version
        )
        .is_err()
    );
}

#[tokio::test]
async fn ordinary_roles_and_paired_copy_keep_one_real_generation() {
    use super::super::{Class, acquire_class, configure, observation, transfer};

    let policy = policy();
    configure(policy.exact(3).unwrap()).unwrap();
    let atomic = acquire_class(2, Class::Bulk).await.unwrap();
    let (destination, source) = transfer::split(atomic).unwrap();
    let request_digest = policy.commitment().unwrap();
    let reservation = transfer::register(source, request_digest.clone()).unwrap();
    let ticket = reservation.ticket();

    // Each independently admitted role converges while the real pair is held.
    configure(policy.bounded(5, 3).unwrap()).unwrap();
    configure(policy.exact(3).unwrap()).unwrap();
    let source = transfer::accept(&ticket, &request_digest).unwrap().unwrap();
    assert_eq!(observation().active, 2);
    let metadata = acquire_class(1, Class::Metadata).await.unwrap();
    assert_eq!(observation().active, 3);
    assert_eq!(observation().maximum, 3);
    assert!(configure(5).is_err());
    assert!(policy.exact(5).is_err());
    assert!(transfer::accept(&ticket, &request_digest).is_err());

    drop(metadata);
    drop(source);
    drop(reservation);
    drop(destination);
    assert_eq!(observation().active, 0);
    let foreground = acquire_class(1, Class::Foreground).await.unwrap();
    assert_eq!(observation().active, 1);
    drop(foreground);
}
