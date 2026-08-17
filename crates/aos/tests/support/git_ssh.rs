use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use anyhow::Result;

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
    // CLI assertions must exercise the same in-process verifier that accepts
    // registry commits in production. Stock-Git interoperability belongs to
    // the security module's focused tests, which create signatures with Git
    // and verify them through this production boundary. Keeping the CLI suite
    // on that boundary also avoids making its result depend on a build-only
    // git/ssh-keygen pair or the Nix builder's dynamic-library environment.
    aos_package::security::verify_commit_signature(repo_path, commit, trusted_keys)
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
