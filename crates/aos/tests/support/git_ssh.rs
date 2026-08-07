use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use aos_package::security::parse_signing_key;

static GIT_SSH_PROGRAM: OnceLock<Option<PathBuf>> = OnceLock::new();

pub(crate) fn apply_git_ssh_program_env(command: &mut Command) {
    if let Some(program) = git_ssh_program() {
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "gpg.ssh.program")
            .env("GIT_CONFIG_VALUE_0", program);
    }
}

#[allow(dead_code)]
pub(crate) fn verify_commit_signature(
    repo_path: &Path,
    commit: &str,
    trusted_keys: &[String],
) -> Result<bool> {
    let signers_file = write_allowed_signers(trusted_keys)?;
    let mut command = Command::new("git");
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        // AOS's Nix builder exposes build dependencies through a broad
        // LD_LIBRARY_PATH. The packaged git and ssh-keygen have their own
        // runtime paths; inheriting the builder value can make ssh-keygen load
        // an ABI-incompatible libcrypto and turn a valid signature into a
        // false verification result.
        .env_remove("LD_LIBRARY_PATH")
        .arg("-c")
        .arg(format!(
            "gpg.ssh.allowedSignersFile={}",
            signers_file.path().display()
        ))
        .arg("verify-commit")
        .arg(commit)
        .current_dir(repo_path);
    apply_git_ssh_program_env(&mut command);
    let output = command.output().context("running git verify-commit")?;
    Ok(output.status.success())
}

#[allow(dead_code)]
fn write_allowed_signers(trusted_keys: &[String]) -> Result<tempfile::NamedTempFile> {
    if trusted_keys.is_empty() {
        bail!("empty trusted key set; refusing to verify signatures against no keys");
    }

    let mut signers_content = String::new();
    for key in trusted_keys {
        let (_reg, _algo, pubkey) = parse_signing_key(key)?;
        signers_content.push_str(&format!("registry ssh-ed25519 {pubkey}\n"));
    }

    let mut signers_file =
        tempfile::NamedTempFile::new().context("creating temporary allowed-signers file")?;
    std::io::Write::write_all(&mut signers_file, signers_content.as_bytes())
        .context("writing temporary allowed-signers file")?;
    Ok(signers_file)
}

fn git_ssh_program() -> Option<&'static Path> {
    GIT_SSH_PROGRAM
        .get_or_init(find_working_ssh_keygen)
        .as_deref()
}

fn find_working_ssh_keygen() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("AOS_TEST_GIT_SSH_PROGRAM") {
        candidates.push(PathBuf::from(path));
    }
    for env_var in ["AOS_HOST_PATH", "PATH"] {
        let Some(path) = std::env::var_os(env_var) else {
            continue;
        };
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("ssh-keygen");
            if !candidates.iter().any(|seen| seen == &candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file() && ssh_keygen_can_sign(candidate))
}

fn ssh_keygen_can_sign(candidate: &Path) -> bool {
    let Ok(tmp) = tempfile::TempDir::new() else {
        return false;
    };
    let key = tmp.path().join("key");
    let Ok(keygen) = Command::new(candidate)
        .env_remove("LD_LIBRARY_PATH")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "registry-test", "-f"])
        .arg(&key)
        .output()
    else {
        return false;
    };
    if !keygen.status.success() {
        return false;
    }

    let payload = tmp.path().join("payload");
    if std::fs::write(&payload, b"registry-test").is_err() {
        return false;
    }

    Command::new(candidate)
        .env_remove("LD_LIBRARY_PATH")
        .arg("-Y")
        .arg("sign")
        .arg("-f")
        .arg(&key)
        .arg("-n")
        .arg("git")
        .arg(&payload)
        .output()
        .is_ok_and(|output| output.status.success())
}
