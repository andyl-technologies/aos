//! Process-level admission checks for daemon-free container commands.

use std::process::Command;

#[test]
fn local_artifact_commands_do_not_require_nix_or_a_checkout() {
    let workspace = tempfile::tempdir().expect("temporary workspace");
    let input = workspace.path().join("not-an-oci-layout");
    std::fs::create_dir(&input).expect("local input directory");

    for arguments in [
        vec![
            "container".to_string(),
            "inspect".to_string(),
            input.display().to_string(),
        ],
        vec![
            "container".to_string(),
            "push".to_string(),
            input.display().to_string(),
            "127.0.0.1:5000/aos:latest".to_string(),
            "--hub".to_string(),
            "http://127.0.0.1:5000".to_string(),
            "--token".to_string(),
            "fixture-secret".to_string(),
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_aos"))
            .args(&arguments)
            .current_dir(workspace.path())
            .env_clear()
            .env("HOME", workspace.path())
            .output()
            .expect("run aos container command");

        assert!(!output.status.success(), "invalid OCI input must fail");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert!(
            stderr.contains("OCI layout"),
            "command did not reach local OCI validation: {stderr}"
        );
        assert!(
            !stderr.contains("nix-build"),
            "unexpected Nix lookup: {stderr}"
        );
        assert!(
            !stderr.contains("default.nix"),
            "unexpected checkout lookup: {stderr}"
        );
        assert!(
            !stderr.contains("fixture-secret"),
            "credential appeared in an error: {stderr}"
        );
    }
}

#[test]
fn unrelated_expired_hub_profile_does_not_block_public_pull() {
    let workspace = tempfile::tempdir().expect("temporary workspace");
    let config = workspace.path().join("config");
    std::fs::create_dir(&config).expect("config directory");
    std::fs::write(
        config.join("hub-profiles.json"),
        br#"{
          "schema_version":"aos.hub.profiles/v1",
          "active_origin":"http://127.0.0.1:1",
          "profiles":{"http://127.0.0.1:1":{
            "access_token":"expired-unrelated-secret",
            "access_expires_at":0,
            "refresh_token":"unrelated-refresh-secret",
            "refresh_expires_at":4102444800
          }}
        }"#,
    )
    .expect("unrelated profile fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_aos"))
        .args([
            "container",
            "pull",
            "127.0.0.1:9/aos:latest",
            "--hub",
            "http://127.0.0.1:9",
            "-o",
            "pulled.oci",
        ])
        .current_dir(workspace.path())
        .env_clear()
        .env("HOME", workspace.path())
        .env("AOS_CONFIG_HOME", &config)
        .output()
        .expect("run public pull");

    assert!(!output.status.success(), "closed loopback port must fail");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        stderr.contains("sending Distribution request"),
        "pull did not reach the requested public registry: {stderr}"
    );
    assert!(!stderr.contains("refreshing Hub profile"), "{stderr}");
    assert!(!stderr.contains("unrelated-refresh-secret"), "{stderr}");
}
