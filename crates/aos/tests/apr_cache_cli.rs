use std::fs;
use std::process::Command;

use anyhow::{Context, Result, bail};

#[test]
fn apr_cache_generate_cli_uploads_static_cache() -> Result<()> {
    let Some(store_path) = tiny_store_path_fixture()? else {
        eprintln!("skipping apr cache CLI e2e: nix or nix-store is unavailable");
        return Ok(());
    };

    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let registry_name = "cli-cache";
    let registry_dir = home
        .join(".local")
        .join("share")
        .join("apm")
        .join("registries")
        .join(registry_name);
    let config_dir = home.join(".config").join("apm").join("registries.d");
    let output_dir = tmp.path().join("cache-output");
    let upload_dir = tmp.path().join("cache-upload");

    fs::create_dir_all(registry_dir.join("packages/f"))?;
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join(format!("{registry_name}.toml")),
        format!(
            r#"[registry]
name = "{registry_name}"
url = "file://{}"
"#,
            registry_dir.display(),
        ),
    )?;
    fs::write(
        registry_dir.join("registry.toml"),
        format!(
            r#"[registry]
name = "{registry_name}"
"#,
        ),
    )?;
    fs::write(
        registry_dir.join("packages/f/fixture.toml"),
        package_toml(&store_path),
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_apr"))
        .env("HOME", &home)
        .args(["cache", "generate", "--registry", registry_name])
        .arg("--output")
        .arg(&output_dir)
        .arg("--upload-url")
        .arg(format!("file://{}", upload_dir.display()))
        .args(["--priority", "37"])
        .args([
            "--token",
            "token",
            "--view",
            "ops",
            "--http-user",
            "cache-user",
            "--http-password",
            "cache-pass",
            "--header",
            "X-Test: yes",
            "--s3-region",
            "us-west-2",
            "--s3-profile",
            "prod",
            "--s3-endpoint",
            "https://minio.example",
            "--ssh-key",
            "/tmp/aos-test-key",
            "--ssh-password",
            "ssh-pass",
            "--ssh-ask-pass",
        ])
        .output()
        .context("running apr cache generate")?;
    if !output.status.success() {
        bail!(
            "apr cache generate failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let cache_info = "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 37\n";
    assert_eq!(
        fs::read_to_string(output_dir.join("nix-cache-info"))?,
        cache_info,
    );
    assert_eq!(
        fs::read_to_string(upload_dir.join("nix-cache-info"))?,
        cache_info,
    );

    let narinfo_path = only_narinfo(&output_dir)?;
    let uploaded_narinfo_path = upload_dir.join(narinfo_path.file_name().unwrap());
    assert_eq!(
        fs::read_to_string(&uploaded_narinfo_path)?,
        fs::read_to_string(&narinfo_path)?,
    );

    let nar_path = only_file_in(&output_dir.join("nar"))?;
    let uploaded_nar_path = upload_dir.join("nar").join(nar_path.file_name().unwrap());
    assert_eq!(fs::read(&uploaded_nar_path)?, fs::read(&nar_path)?);

    Ok(())
}

fn only_narinfo(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let narinfos = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("narinfo"))
        .collect::<Vec<_>>();
    if narinfos.len() != 1 {
        bail!(
            "expected one narinfo in {}, found {}",
            dir.display(),
            narinfos.len()
        );
    }
    Ok(narinfos[0].clone())
}

fn only_file_in(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let files = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    if files.len() != 1 {
        bail!(
            "expected one file in {}, found {}",
            dir.display(),
            files.len()
        );
    }
    Ok(files[0].clone())
}

fn tiny_store_path_fixture() -> Result<Option<String>> {
    if command_missing("nix") || command_missing("nix-store") {
        return Ok(None);
    }

    let tmp = tempfile::Builder::new()
        .prefix("aos-cache-cli-fixture-")
        .tempfile_in("/private/tmp")?;
    fs::write(tmp.path(), b"aos apr cache cli fixture\n")?;
    let output = Command::new("nix-store")
        .args(["--add-fixed", "sha256"])
        .arg(tmp.path())
        .output()
        .context("running nix-store --add-fixed")?;
    if !output.status.success() {
        eprintln!(
            "skipping apr cache CLI e2e: nix-store --add-fixed failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

fn package_toml(store_path: &str) -> String {
    format!(
        r#"[package]
name = "fixture"
description = "Static cache fixture"
license = "MIT"
maintainer = "registry@example.com"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "{store_path}"
nar_hash = "sha256:placeholder"
nar_size = 1
closure_size = 1
source_drv = "{store_path}.drv"
source_nar_hash = "sha256:placeholder"
references = []
"#,
    )
}

fn command_missing(command: &str) -> bool {
    matches!(
        Command::new(command).arg("--version").output(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound
    )
}
