//! Pure preparation fences; these fixtures grant no SQL or provider authority.

use super::*;

fn original() -> MirrorOriginal {
    let mut original = MirrorOriginal {
        version: 1, job_id: String::new(), copy_operation_id: Some("ab".repeat(16)),
        registry_id: 1, registry_resource_version: 2, mirror_resource_version: 3,
        upstream_base: "https://upstream.example.org/git/".into(), path: "first".into(),
        placement_id: 4, placement_resource_version: 5, write_spec_version: 6,
        binding_id: 7, binding_resource_version: 8,
        placement_prefix: format!(".aos-mirror-qualification/{}/final", "ab".repeat(16)),
        protected_profile_digest: "cd".repeat(32), external_destination: None,
        verification: MirrorVerification::Sha256 { sha256: "ef".repeat(32), size: 256 * 1024 },
    };
    original.job_id = original.identity().unwrap();
    original.validate().unwrap();
    original
}

#[test]
fn metadata_preparation_refuses_reuse_raced_generation_and_advanced_progress() {
    let expected = original();
    ensure_fresh_metadata_original(&expected, &expected, "admitted", None).unwrap();
    let mut raced = expected.clone();
    raced.copy_operation_id = Some("01".repeat(16));
    raced.job_id = raced.identity().unwrap();
    assert!(ensure_fresh_metadata_original(&expected, &raced, "admitted", None).is_err());
    assert!(ensure_fresh_metadata_original(&expected, &expected, "published", None).is_err());
    let mut progress = MirrorProgress { original_digest: aos_hub_core::mirror_work::digest(&expected).unwrap(),
        ..MirrorProgress::default() };
    assert!(ensure_fresh_metadata_original(&expected, &expected, "admitted", Some(&progress)).is_err());
    ensure_pack_memory_boundary(&expected, &progress, false).unwrap();
    progress.stage_upload_id = Some("actual-fixture-create-receipt".into());
    ensure_pack_memory_boundary(&expected, &progress, true).unwrap();
    assert!(ensure_pack_memory_boundary(&expected, &progress, false).is_err());
    progress.destination_upload_id = Some("wrong-phase".into());
    assert!(ensure_pack_memory_boundary(&expected, &progress, true).is_err());
}

#[test]
fn metadata_preparation_requires_two_distinct_bounded_sha256_paths() {
    let verification = original().verification;
    let mut objects = [(1, "first".into(), verification.clone()), (1, "second".into(), verification)];
    validate_pack_memory_objects(&objects).unwrap();
    objects[1].1 = "first".into();
    assert!(validate_pack_memory_objects(&objects).is_err());
    objects[1].1 = "second".into();
    objects[1].2 = MirrorVerification::Sha256 { sha256: "ef".repeat(32), size: 256 * 1024 + 1 };
    assert!(validate_pack_memory_objects(&objects).is_err());
}
