//! Keeps executable assembly on the canonical independently confined signer.

#[test]
fn installed_source_signer_selects_only_its_role_dependency() {
    let manifest = include_str!("../../aos-sandbox-services/Cargo.toml");
    let feature = manifest.split("source-signer = [").nth(1)
        .and_then(|value| value.split(']').next()).expect("Source signer feature");
    let dependencies: Vec<_> = feature.lines().map(str::trim).map(|line| line.trim_end_matches(','))
        .filter(|line| !line.is_empty()).collect();

    assert_eq!(dependencies, ["\"dep:aos-sandbox-source-signer\""]);

    let entry = include_str!("../../aos-sandbox-services/src/bin/aos-sandbox-source-signerd.rs");
    assert!(entry.contains("use aos_sandbox_source_signer::run_selected_source_signer_service_v1;"));
    assert!(entry.contains("run_selected_source_signer_service_v1(controller_uid, controller_gid, signer_uid, signer_gid)"));
}
