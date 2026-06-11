use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use aos_package::registry::keys;
use aos_package::sshkey::Ed25519Keypair;

#[path = "support/git_ssh.rs"]
mod git_ssh;

#[test]
fn apr_keys_cli_manages_committed_roster() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let initial = TestKey::write(&home, "core", [11_u8; 32], "initial")?;
    let Some(registry_dir) = init_registry(&home, "core", Some(&initial))? else {
        eprintln!("skipping apr keys CLI e2e: git cannot initialize a sha256 repository");
        return Ok(());
    };

    assert_eq!(git(&registry_dir, &["rev-list", "--count", "HEAD"])?, "1");

    let list = run_apr(&home, &["keys", "list", "--registry", "core"])?;
    assert!(list.contains("initial"));
    assert!(list.contains("active:"));

    // Roster changes on a non-empty roster must be signed: without a key
    // the command refuses rather than producing an unsigned commit.
    let unsigned = run_apr_err(
        &home,
        &[
            "keys",
            "add",
            "next",
            "core:Ed25519:ZWZnaA==",
            "--registry",
            "core",
        ],
    )?;
    assert!(output_text(&unsigned).contains("must be signed"));
    assert_eq!(git(&registry_dir, &["rev-list", "--count", "HEAD"])?, "1");

    let next = TestKey::write(&home, "core", [12_u8; 32], "next")?;
    run_apr(
        &home,
        &[
            "keys",
            "add",
            "next",
            &next.trust_key,
            "--key",
            initial.path_str(),
            "--registry",
            "core",
        ],
    )?;
    let roster = keys::load_keys_toml(&registry_dir)?.expect("keys.toml exists");
    assert_eq!(
        roster
            .active
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        vec!["initial", "next"],
    );
    assert_eq!(git(&registry_dir, &["rev-list", "--count", "HEAD"])?, "2");
    // The enrolling commit is signed by the existing maintainer key.
    assert!(git_ssh::verify_commit_signature(
        &registry_dir,
        "HEAD",
        &[initial.trust_key.clone()],
    )?);
    assert!(!git_ssh::verify_commit_signature(
        &registry_dir,
        "HEAD",
        &[next.trust_key.clone()],
    )?);

    let duplicate = run_apr_err(
        &home,
        &[
            "keys",
            "add",
            "next",
            "core:Ed25519:aGlqa2w=",
            "--key",
            initial.path_str(),
            "--registry",
            "core",
        ],
    )?;
    assert!(output_text(&duplicate).contains("already exists"));

    // Retirement defaults to signing with the vouching survivor's key,
    // resolved through [registry.signing_keys].
    write_registry_config(&home, "core", &[("next", &next)])?;
    run_apr(
        &home,
        &[
            "keys",
            "retire",
            "initial",
            "--reason",
            "planned rotation",
            "--registry",
            "core",
        ],
    )?;
    let roster = keys::load_keys_toml(&registry_dir)?.expect("keys.toml exists");
    assert_eq!(
        roster
            .active
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        vec!["next"],
    );
    assert_eq!(roster.revoked.len(), 1);
    assert_eq!(roster.revoked[0].id, "initial");
    assert_eq!(
        roster.revoked[0].reason.as_deref(),
        Some("planned rotation")
    );
    assert_eq!(git(&registry_dir, &["rev-list", "--count", "HEAD"])?, "3");
    assert!(git_ssh::verify_commit_signature(
        &registry_dir,
        "HEAD",
        &[next.trust_key.clone()],
    )?);

    let last_key = run_apr_err(
        &home,
        &[
            "keys",
            "retire",
            "next",
            "--key",
            next.path_str(),
            "--registry",
            "core",
        ],
    )?;
    assert!(output_text(&last_key).contains("must keep an active survivor key"));

    let wrong_registry = run_apr_err(
        &home,
        &[
            "keys",
            "add",
            "foreign",
            "other:Ed25519:bW5vcA==",
            "--key",
            next.path_str(),
            "--registry",
            "core",
        ],
    )?;
    assert!(output_text(&wrong_registry).contains("expected 'core'"));

    let third = TestKey::write(&home, "core", [13_u8; 32], "third")?;
    run_apr(
        &home,
        &[
            "keys",
            "add",
            "third",
            &third.trust_key,
            "--key",
            next.path_str(),
            "--registry",
            "core",
        ],
    )?;
    run_apr(
        &home,
        &[
            "keys",
            "retire",
            "next",
            "--vouched-by",
            "third",
            "--key",
            third.path_str(),
            "--registry",
            "core",
        ],
    )?;
    let roster = keys::load_keys_toml(&registry_dir)?.expect("keys.toml exists");
    assert_eq!(
        roster
            .active
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>(),
        vec!["third"],
    );
    assert!(roster.revoked.iter().any(|entry| entry.id == "next"));

    Ok(())
}

#[test]
fn apr_keys_retire_fails_before_mutation_without_vouching_key() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let initial = TestKey::write(&home, "core", [14_u8; 32], "initial")?;
    let Some(registry_dir) = init_registry(&home, "core", Some(&initial))? else {
        eprintln!("skipping apr keys CLI e2e: git cannot initialize a sha256 repository");
        return Ok(());
    };
    let second = TestKey::write(&home, "core", [15_u8; 32], "second")?;
    run_apr(
        &home,
        &[
            "keys",
            "add",
            "second",
            &second.trust_key,
            "--key",
            initial.path_str(),
            "--registry",
            "core",
        ],
    )?;
    let roster_before = fs::read_to_string(registry_dir.join("keys.toml"))?;

    // Without --key and without a [registry.signing_keys] entry for the
    // vouching survivor, retirement fails before modifying anything.
    let err = run_apr_err(&home, &["keys", "retire", "initial", "--registry", "core"])?;
    let text = output_text(&err);
    assert!(
        text.contains("registries.d") || text.contains("signing_keys"),
        "{text}"
    );
    assert_eq!(
        fs::read_to_string(registry_dir.join("keys.toml"))?,
        roster_before,
        "keys.toml must be unchanged after a failed retirement"
    );
    assert_eq!(git(&registry_dir, &["rev-list", "--count", "HEAD"])?, "2");

    Ok(())
}

#[test]
fn apr_keys_add_on_empty_roster_may_commit_unsigned() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    let Some(registry_dir) = init_registry(&home, "boot", None)? else {
        eprintln!("skipping apr keys CLI e2e: git cannot initialize a sha256 repository");
        return Ok(());
    };

    // Bootstrap: the first key may be added without a signing key, since
    // no client can verify the registry yet.
    let first = TestKey::write(&home, "boot", [21_u8; 32], "first")?;
    run_apr(
        &home,
        &[
            "keys",
            "add",
            "first",
            &first.trust_key,
            "--registry",
            "boot",
        ],
    )?;
    let roster = keys::load_keys_toml(&registry_dir)?.expect("keys.toml exists");
    assert_eq!(roster.active.len(), 1);

    Ok(())
}

#[test]
fn apr_create_with_trust_key_requires_and_signs_initial_commit() -> Result<()> {
    let tmp = tempfile::TempDir::new()?;
    let home = tmp.path().join("home");
    if !git_supports_sha256(&home)? {
        eprintln!("skipping apr create e2e: git cannot initialize a sha256 repository");
        return Ok(());
    }
    let key = TestKey::write(&home, "fresh", [31_u8; 32], "initial")?;

    // --trust-key without a signing key is refused.
    let missing = run_apr_err(&home, &["create", "fresh", "--trust-key", &key.trust_key])?;
    assert!(output_text(&missing).contains("must be signed"));

    run_apr(
        &home,
        &[
            "create",
            "fresh",
            "--trust-key",
            &key.trust_key,
            "--key",
            key.path_str(),
        ],
    )?;
    let registry_dir = home.join(".local/share/apm/registries").join("fresh");
    assert!(git_ssh::verify_commit_signature(
        &registry_dir,
        "HEAD",
        &[key.trust_key.clone()],
    )?);

    Ok(())
}

struct TestKey {
    trust_key: String,
    path: PathBuf,
}

impl TestKey {
    /// Write a deterministic OpenSSH keypair under `home` and return its
    /// trust-key line and private key path.
    fn write(home: &Path, registry: &str, seed: [u8; 32], name: &str) -> Result<Self> {
        let keypair = Ed25519Keypair::from_seed(seed);
        let dir = home.join("keys");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{registry}-{name}.key"));
        fs::write(&path, keypair.to_openssh_private_key(name))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self {
            trust_key: keypair.trust_key_line(registry),
            path,
        })
    }

    fn path_str(&self) -> &str {
        self.path.to_str().unwrap_or_default()
    }
}

/// Write a user-scope registry config mapping key ids to private key paths.
fn write_registry_config(home: &Path, name: &str, keys: &[(&str, &TestKey)]) -> Result<()> {
    let dir = home.join(".config/apm/registries.d");
    fs::create_dir_all(&dir)?;
    let mut content = format!("[registry]\nname = \"{name}\"\nurl = \"file:///dev/null\"\n");
    if !keys.is_empty() {
        content.push_str("\n[registry.signing_keys]\n");
        for (id, key) in keys {
            content.push_str(&format!("\"{id}\" = \"{}\"\n", key.path.display()));
        }
    }
    fs::write(dir.join(format!("{name}.toml")), content)?;
    Ok(())
}

fn git_supports_sha256(home: &Path) -> Result<bool> {
    let probe = home.join(".sha256-probe");
    fs::create_dir_all(&probe)?;
    let init = Command::new("git")
        .args(["init", "--object-format=sha256"])
        .current_dir(&probe)
        .output()
        .context("running git init --object-format=sha256")?;
    Ok(init.status.success())
}

fn init_registry(home: &Path, name: &str, initial: Option<&TestKey>) -> Result<Option<PathBuf>> {
    let registry_dir = home
        .join(".local")
        .join("share")
        .join("apm")
        .join("registries")
        .join(name);
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
        format!(
            r#"[registry]
name = "{name}"
"#,
        ),
    )?;
    let keys_toml = match initial {
        Some(key) => format!(
            r#"schema = 1

[[keys]]
id = "initial"
key = "{}"
"#,
            key.trust_key,
        ),
        None => "schema = 1\n".to_string(),
    };
    fs::write(registry_dir.join("keys.toml"), keys_toml)?;
    git(&registry_dir, &["add", "-A"])?;
    git(&registry_dir, &["commit", "-m", "initial registry"])?;
    Ok(Some(registry_dir))
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
    git_ssh::apply_git_ssh_program_env(&mut cmd);
    cmd
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
