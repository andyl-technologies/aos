//! End-to-end coverage for `apr keys generate`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use aos_package::registry::keys;
use aos_package::security::parse_signing_key;
use aos_package::sshkey::Ed25519Keypair;

#[path = "support/git_ssh.rs"]
mod git_ssh;

#[test]
fn apr_keys_generate_creates_key_material_and_config() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    fs::create_dir_all(&home)?;

    // Generation works without a registry clone or config; it only warns
    // about the missing registries.d entry.
    let output = run_apr(&home, &["keys", "generate", "alice", "--registry", "core"])?;
    let trust_key = extract_public_key(&output)?;
    let (registry, algorithm, _pubkey) = parse_signing_key(&trust_key)?;
    assert_eq!(registry, "core");
    assert_eq!(algorithm, "Ed25519");
    assert!(output.contains("[registry.signing_keys]"), "{output}");

    let key_path = home.join(".config/apm/keys/core-alice.key");
    let pem = fs::read_to_string(&key_path)?;
    assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let file_mode = fs::metadata(&key_path)?.permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "private key file mode");
        let dir_mode = fs::metadata(key_path.parent().context("key dir")?)?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "key directory mode");
    }

    // Refuses to overwrite the existing private key file.
    let overwrite = run_apr_err(&home, &["keys", "generate", "alice", "--registry", "core"])?;
    assert!(output_text(&overwrite).contains("refusing to overwrite"));

    // With a registries.d config present, the key path is recorded in
    // [registry.signing_keys] so --key-id resolves.
    write_registry_config(&home, "core")?;
    run_apr(&home, &["keys", "generate", "bob", "--registry", "core"])?;
    let config = fs::read_to_string(home.join(".config/apm/registries.d/core.toml"))?;
    assert!(config.contains("[registry.signing_keys]"), "{config}");
    assert!(config.contains("\"bob\""), "{config}");
    assert!(config.contains("core-bob.key"), "{config}");
    // User-edited fields survive the rewrite.
    assert!(config.contains("url = \"file:///dev/null\""), "{config}");

    // The generated key actually signs: create a registry anchored on it.
    let generated_path = home.join(".config/apm/keys/core2-carol.key");
    let gen_out = run_apr(&home, &["keys", "generate", "carol", "--registry", "core2"])?;
    let carol_key = extract_public_key(&gen_out)?;
    run_apr(
        &home,
        &[
            "create",
            "core2",
            "--trust-key",
            &carol_key,
            "--key",
            generated_path.to_str().context("key path utf-8")?,
        ],
    )?;
    let registry_dir = home.join(".local/share/apm/registries/core2");
    assert!(git_ssh::verify_commit_signature(
        &registry_dir,
        "HEAD",
        &[carol_key],
    )?);

    Ok(())
}

#[test]
fn apr_keys_generate_add_appends_to_roster_with_signed_commit() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let initial = write_keypair(&home, "core", [41_u8; 32], "initial")?;
    let Some(registry_dir) = init_registry(&home, "core", Some(&initial))? else {
        eprintln!("skipping apr keys generate e2e: git cannot initialize a sha256 repository");
        return Ok(());
    };

    run_apr(
        &home,
        &[
            "keys",
            "generate",
            "second",
            "--add",
            "--key",
            initial.1.to_str().context("key path utf-8")?,
            "--registry",
            "core",
        ],
    )?;
    let roster = keys::load_keys_toml(&registry_dir)?.context("keys.toml exists")?;
    assert_eq!(
        roster
            .active
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        vec!["initial", "second"],
    );
    // The enrolling commit is signed by the existing maintainer key.
    assert!(git_ssh::verify_commit_signature(
        &registry_dir,
        "HEAD",
        &[initial.0.clone()],
    )?);

    Ok(())
}

#[test]
fn apr_keys_generate_add_on_empty_roster_directs_to_create() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let Some(_registry_dir) = init_registry(&home, "empty", None)? else {
        eprintln!("skipping apr keys generate e2e: git cannot initialize a sha256 repository");
        return Ok(());
    };

    let err = run_apr_err(
        &home,
        &["keys", "generate", "first", "--add", "--registry", "empty"],
    )?;
    let text = output_text(&err);
    assert!(text.contains("empty trust roster"), "{text}");
    assert!(text.contains("--trust-key"), "{text}");
    // The keypair itself was still generated before the roster error.
    assert!(home.join(".config/apm/keys/empty-first.key").exists());

    Ok(())
}

/// Extract the printed `registry:Ed25519:<base64>` public key line.
fn extract_public_key(output: &str) -> Result<String> {
    output
        .lines()
        .filter_map(|line| {
            let value = line.split_whitespace().last()?;
            parse_signing_key(value).ok().map(|_| value.to_string())
        })
        .next()
        .with_context(|| format!("no public key line in output:\n{output}"))
}

fn write_keypair(
    home: &Path,
    registry: &str,
    seed: [u8; 32],
    name: &str,
) -> Result<(String, PathBuf)> {
    let keypair = Ed25519Keypair::from_seed(seed);
    let dir = home.join("fixture-keys");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{registry}-{name}.key"));
    fs::write(&path, keypair.to_openssh_private_key(name))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok((keypair.trust_key_line(registry), path))
}

fn write_registry_config(home: &Path, name: &str) -> Result<()> {
    let dir = home.join(".config/apm/registries.d");
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join(format!("{name}.toml")),
        format!("[registry]\nname = \"{name}\"\nurl = \"file:///dev/null\"\n"),
    )?;
    Ok(())
}

fn init_registry(
    home: &Path,
    name: &str,
    initial: Option<&(String, PathBuf)>,
) -> Result<Option<PathBuf>> {
    let registry_dir = home.join(".local/share/apm/registries").join(name);
    fs::create_dir_all(&registry_dir)?;

    let init = Command::new("git")
        .args(["init", "--object-format=sha256"])
        .current_dir(&registry_dir)
        .output()
        .context("running git init --object-format=sha256")?;
    if !init.status.success() {
        return Ok(None);
    }

    fs::write(
        registry_dir.join("registry.toml"),
        format!("[registry]\nname = \"{name}\"\n"),
    )?;
    let keys_toml = match initial {
        Some((trust_key, _)) => {
            format!("schema = 1\n\n[[keys]]\nid = \"initial\"\nkey = \"{trust_key}\"\n")
        }
        None => "schema = 1\n".to_string(),
    };
    fs::write(registry_dir.join("keys.toml"), keys_toml)?;
    git(&registry_dir, &["add", "-A"])?;
    git(&registry_dir, &["commit", "-m", "initial registry"])?;
    Ok(Some(registry_dir))
}

/// Spawn `apr` against an isolated `HOME`, with a committer identity in the
/// environment: registry commits refuse to run without one.
fn apr_command(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_apr"));
    cmd.env("HOME", home)
        .env("USER", "registry-test")
        .env("LOGNAME", "registry-test")
        .env("GIT_AUTHOR_NAME", "Registry Test")
        .env("GIT_AUTHOR_EMAIL", "registry@example.com")
        .env("GIT_COMMITTER_NAME", "Registry Test")
        .env("GIT_COMMITTER_EMAIL", "registry@example.com");
    cmd
}

fn run_apr(home: &Path, args: &[&str]) -> Result<String> {
    let output = apr_command(home)
        .args(args)
        .output()
        .with_context(|| format!("running apr {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "apr {} failed:\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(output_text(&output))
}

fn run_apr_err(home: &Path, args: &[&str]) -> Result<Output> {
    let output = apr_command(home)
        .args(args)
        .output()
        .with_context(|| format!("running apr {}", args.join(" ")))?;
    if output.status.success() {
        bail!("apr {} unexpectedly succeeded", args.join(" "));
    }
    Ok(output)
}

/// Run a fixture git command insulated from the host's git configuration.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let mut command = Command::new("git");
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("USER", "registry-test")
        .env("LOGNAME", "registry-test")
        .env("GIT_AUTHOR_NAME", "Registry Test")
        .env("GIT_AUTHOR_EMAIL", "registry@example.com")
        .env("GIT_COMMITTER_NAME", "Registry Test")
        .env("GIT_COMMITTER_EMAIL", "registry@example.com")
        .args(args)
        .current_dir(dir);
    git_ssh::apply_git_ssh_program_env(&mut command);
    let output = command
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed:\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}
