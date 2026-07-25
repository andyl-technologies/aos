//! `apr change list|show|merge` over a SHA-256 registry with hub change
//! requests (RFC-0004 "Configuration management", git-backed path).
//!
//! Builds a real SHA-256 bare origin carrying a `refs/hub/changes/<id>` draft
//! (a hub-authored edit to `registry.toml`), clones it under a temp
//! `XDG_DATA_HOME`, and drives the `apr change` subcommands against it. The
//! test is gated on host `git` + `ssh-keygen` (mirroring the hub's
//! `git_interop` gate); when the toolchain is absent it skips with a notice.
//!
//! Env-sensitive paths (`XDG_*`, `HOME`) are mutated, so the whole test runs
//! under a process-wide mutex and restores the prior values on exit.

use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

use aos_core::output::Printer;
use aos_package::ChangeCommand;
use aos_package::config::ApmConfig;
use aos_package::types::ProfileScope;

/// Serializes the env-var mutation across tests in this binary.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Run a git command in `dir`, panicking with stderr on failure.
fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Run a git command capturing trimmed stdout.
fn git_out(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Whether the host can build the SHA-256 + SSH-signed fixture.
fn host_supports(probe: &Path) -> bool {
    let git_ok = Command::new("git")
        .args(["init", "--object-format=sha256", "-q", "probe"])
        .current_dir(probe)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let keygen_ok = Command::new("ssh-keygen")
        .arg("-h")
        .output()
        .map(|_| true)
        .unwrap_or(false);
    git_ok && keygen_ok
}

// The test holds a std Mutex across `.await` points solely to serialize the
// process-wide env mutation it performs; there is no real cross-task contention
// (each call completes before the next), so the async-Mutex advice does not
// apply here.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn change_list_show_and_merge() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let root = tempfile::tempdir().unwrap();

    if !host_supports(root.path()) {
        eprintln!("skipping change_requests: host lacks sha256 git or ssh-keygen");
        return;
    }

    // Generate a roster signing key (the maintainer key `apr change merge`
    // re-signs with).
    let key_path = root.path().join("id_ed25519");
    let kg = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        kg.status.success(),
        "ssh-keygen: {}",
        String::from_utf8_lossy(&kg.stderr)
    );

    // -- the authoring clone (where we commit, then publish to the origin) ---
    let work = root.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(
        &work,
        &["init", "-q", "--object-format=sha256", "-b", "stable"],
    );
    git(&work, &["config", "user.name", "Maintainer"]);
    git(&work, &["config", "user.email", "m@example.com"]);
    git(&work, &["config", "gpg.format", "ssh"]);
    git(
        &work,
        &["config", "user.signingkey", key_path.to_str().unwrap()],
    );
    std::fs::write(
        work.join("registry.toml"),
        "[registry]\nname = \"demo\"\ndescription = \"original\"\n",
    )
    .unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-S", "-m", "initial"]);
    let base = git_out(&work, &["rev-parse", "HEAD"]);

    // The bare origin.
    let origin = root.path().join("origin.git");
    git(
        root.path(),
        &[
            "init",
            "-q",
            "--bare",
            "--object-format=sha256",
            "origin.git",
        ],
    );
    git(
        &work,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&work, &["push", "-q", "origin", "stable"]);

    // -- the hub-authored draft change request on the origin -----------------
    // Build a draft commit (child of base) editing registry.toml, with the
    // AOS-Change-Id trailer, and push it to refs/hub/changes/<id> on the origin.
    let change_id = "01JCHANGEMERGE";
    std::fs::write(
        work.join("registry.toml"),
        "[registry]\nname = \"demo\"\ndescription = \"edited by hub\"\n",
    )
    .unwrap();
    git(&work, &["add", "-A"]);
    // The draft can be signed by anything (a hub draft key); here we reuse the
    // same key for fixture simplicity — the point is the merge RE-signs it.
    git(
        &work,
        &[
            "commit",
            "-q",
            "-S",
            "-m",
            &format!("config: edit registry.toml\n\nAOS-Change-Id: {change_id}"),
        ],
    );
    let draft_commit = git_out(&work, &["rev-parse", "HEAD"]);
    git(
        &work,
        &[
            "push",
            "-q",
            "origin",
            &format!("HEAD:refs/hub/changes/{change_id}"),
        ],
    );
    // Reset the authoring clone back to base so the draft is only on the origin
    // ref, not on the branch.
    git(&work, &["reset", "-q", "--hard", &base]);

    // -- the apr-managed clone under XDG_DATA_HOME ---------------------------
    let xdg_data = root.path().join("xdg-data");
    let xdg_config = root.path().join("xdg-config");
    std::fs::create_dir_all(&xdg_data).unwrap();
    std::fs::create_dir_all(&xdg_config).unwrap();
    let registry_name = "demo";
    let clone_dir = xdg_data.join("apm/registries").join(registry_name);
    std::fs::create_dir_all(clone_dir.parent().unwrap()).unwrap();
    git(
        root.path(),
        &[
            "clone",
            "-q",
            "-b",
            "stable",
            origin.to_str().unwrap(),
            clone_dir.to_str().unwrap(),
        ],
    );
    git(&clone_dir, &["config", "user.name", "Maintainer"]);
    git(&clone_dir, &["config", "user.email", "m@example.com"]);

    // Point the apm config dirs at the temp XDG tree.
    let prev_data = std::env::var_os("XDG_DATA_HOME");
    let prev_config = std::env::var_os("XDG_CONFIG_HOME");
    // SAFETY: the whole test holds ENV_LOCK, so no other thread reads or writes
    // these vars concurrently; they are restored below.
    unsafe {
        std::env::set_var("XDG_DATA_HOME", &xdg_data);
        std::env::set_var("XDG_CONFIG_HOME", &xdg_config);
    }

    let result = drive_change_commands(registry_name, change_id, &key_path).await;

    // Restore env before asserting so a panic doesn't leak it.
    // SAFETY: still under ENV_LOCK; restores the captured prior values.
    unsafe {
        match prev_data {
            Some(v) => std::env::set_var("XDG_DATA_HOME", v),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        match prev_config {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }
    result.expect("apr change list/show/merge succeed");

    // The merge produced a NEW commit on stable (not the draft commit) whose
    // tree carries the edit, signed by the roster key, and pushed to the origin.
    let promoted = git_out(&clone_dir, &["rev-parse", "HEAD"]);
    assert_ne!(
        promoted, draft_commit,
        "merge re-commits, not a literal cherry of the draft oid"
    );
    assert_ne!(promoted, base, "stable advanced past the base commit");

    // The promoted commit is signed by the roster key (a gpgsig header exists).
    let raw = git_out(&clone_dir, &["cat-file", "-p", "HEAD"]);
    assert!(raw.contains("gpgsig"), "promoted commit is signed: {raw}");

    // The promoted tree carries the hub's edit.
    let committed = git_out(&clone_dir, &["show", "HEAD:registry.toml"]);
    assert!(
        committed.contains("edited by hub"),
        "edit landed: {committed}"
    );

    // The origin's stable branch now points at the promoted commit (pushed).
    let origin_stable = git_out(&origin, &["rev-parse", "stable"]);
    assert_eq!(
        origin_stable, promoted,
        "the promotion was pushed to the origin"
    );
}

/// Run `apr change list`, then `show`, then `merge` against the configured
/// registry. Loads the apm config from the (already env-pointed) XDG tree.
async fn drive_change_commands(
    registry_name: &str,
    change_id: &str,
    key_path: &Path,
) -> anyhow::Result<()> {
    let config = ApmConfig::load(ProfileScope::User)?;
    let printer = Printer::new(0, true, false);

    // change list: the draft appears with its summary.
    aos_package::registry_ops::run_change(
        &config,
        &ChangeCommand::List {
            registry: Some(registry_name.to_string()),
        },
        &printer,
    )
    .await?;

    // change show: a diff vs HEAD shows the edited description.
    aos_package::registry_ops::run_change(
        &config,
        &ChangeCommand::Show {
            id: change_id.to_string(),
            stat: false,
            registry: Some(registry_name.to_string()),
        },
        &printer,
    )
    .await?;

    // change merge: re-sign the draft's tree onto stable with the roster key
    // and push.
    aos_package::registry_ops::run_change(
        &config,
        &ChangeCommand::Merge {
            id: change_id.to_string(),
            key: Some(key_path.to_str().unwrap().to_string()),
            key_id: None,
            registry: Some(registry_name.to_string()),
        },
        &printer,
    )
    .await?;
    Ok(())
}
