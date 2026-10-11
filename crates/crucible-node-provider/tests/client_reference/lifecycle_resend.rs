//! Actual completed preparation duplicates beneath retained native child custody.
//!
//! This SDK component fixture authenticates only its measured provider/child and
//! original preparation results. Complete-world/window cohort qualification is
//! separate and needs a source-authorized runtime probe policy.

use super::*;

#[test]
fn actual_completed_realize_and_admit_duplicate_preserve_same_native_child_and_originals() {
    let count = 4;
    let (service, handshake, mut controller, originals) = observed_controller(256);
    let wire = controller
        .observe_resends(TransmissionLimits {
            maximum_transmissions: count,
            maximum_bytes: 8 * 1024 * 1024,
        })
        .unwrap();
    let realized = realize(&mut controller);
    let original_child = child_pid(&controller, &realized);
    let before = std::fs::read_to_string(format!(
        "/proc/{}/task/{}/children",
        service.process.id(),
        service.process.id()
    ))
    .unwrap();
    assert_eq!(
        before.split_whitespace().collect::<Vec<_>>(),
        vec![original_child.to_string()]
    );
    let binding = controller
        .profile
        .bind(controller.bootstrap.authority.clone())
        .unwrap()
        .0;
    let admitted = controller
        .call(
            fixture::id("completed-admit"),
            None,
            Method::Admit,
            false,
            AdmitRequest {
                bindings: vec![binding],
                world_binding_hash: controller.bootstrap.world_binding_hash.clone(),
                admission_receipt: controller.bootstrap.admission_receipt.clone(),
                extensions: Extensions::new(),
            },
        )
        .unwrap();
    assert!(matches!(admitted.shape, ResponseShape::Completed { .. }));
    let keys = originals.request_keys().unwrap();
    let before_originals = originals.snapshot(&keys, &[], output_limits()).unwrap();
    assert!(
        controller
            .resend_original_control(&fixture::id("observed-realize"))
            .is_err()
    );
    assert_eq!(
        serde_json::to_value(wire.snapshot(8 * 1024 * 1024).unwrap()).unwrap()["rows"],
        json!([])
    );

    for _ in 0..2 {
        let repeated = controller
            .resend_completed_lifecycle_original(&fixture::id("observed-realize"))
            .unwrap();
        assert_eq!(
            repeated.result,
            Some(MethodResult::Realize(realized.clone()))
        );
        assert_eq!(
            controller
                .resend_completed_lifecycle_original(&fixture::id("completed-admit"))
                .unwrap(),
            admitted
        );
        assert_eq!(child_pid(&controller, &realized), original_child);
        assert_eq!(
            std::fs::read_to_string(format!(
                "/proc/{}/task/{}/children",
                service.process.id(),
                service.process.id()
            ))
            .unwrap(),
            before
        );
    }
    let after_originals = originals.snapshot(&keys, &[], output_limits()).unwrap();
    assert_eq!(
        canonical::canonical_json(&serde_json::to_value(before_originals).unwrap()).unwrap(),
        canonical::canonical_json(&serde_json::to_value(after_originals).unwrap()).unwrap()
    );
    let observed = serde_json::to_value(wire.snapshot(8 * 1024 * 1024).unwrap()).unwrap();
    assert_eq!(observed["incomplete"], false);
    assert_eq!(observed["rows"].as_array().unwrap().len(), count);
    assert!(
        observed["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["write_completed"] == true && row["semantic_response_verified"] == true)
    );
    abort(&mut controller);
    assert!(!Path::new(&format!("/proc/{original_child}")).exists());
    controller.fence();
    drop(controller);
    drop(handshake);
    drop(service);
    assert_eq!(
        serde_json::to_value(wire.snapshot(8 * 1024 * 1024).unwrap()).unwrap(),
        observed
    );
}
