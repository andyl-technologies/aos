//! Parser-divergence guard: real-git-produced surfaces must verify.
//!
//! RFC-0004's testing story, tier 1: the hub's pure-Rust reader and the
//! git toolchain `apr`/`apm` actually use must agree on the wire format.
//! This test builds a registry surface with the *real* `git` binary —
//! SHA-256 object format, SSH-signed commit and tags via `ssh-keygen` —
//! exports it exactly the way `apr origin upload` lays files out, and
//! requires the hub to verify and index it fail-closed.
//!
//! The test skips (with a notice) on hosts whose git lacks SHA-256
//! support or where `ssh-keygen` is unavailable — e.g. inside hermetic
//! sandboxes without the toolchain — so it gates correctness where it
//! can run without breaking builds where it cannot.

mod common;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use aos_hub::db::Database;
use aos_hub::fetch::LocalFsFetch;
use aos_hub::indexer::index_and_record;

/// Run a command, panicking with full output on failure.
fn run(dir: &Path, program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("running {program} {args:?}: {e}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Whether the host toolchain can build a SHA-256, SSH-signed repo.
fn host_supports_fixture(probe_dir: &Path) -> bool {
    let git_ok = Command::new("git")
        .args(["init", "--object-format=sha256", "-q", "probe"])
        .current_dir(probe_dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let ssh_keygen_ok = Command::new("ssh-keygen")
        .arg("-h")
        .output()
        .map(|_| true)
        .unwrap_or(false);
    git_ok && ssh_keygen_ok
}

#[tokio::test]
async fn real_git_surface_verifies_and_indexes() {
    let dir = tempfile::tempdir().unwrap();
    if !host_supports_fixture(dir.path()) {
        eprintln!("skipping: host git/ssh-keygen cannot build a sha256 SSH-signed fixture");
        return;
    }

    // Maintainer key, OpenSSH-generated.
    let keydir = dir.path().join("keys");
    std::fs::create_dir_all(&keydir).unwrap();
    run(
        &keydir,
        "ssh-keygen",
        &[
            "-t",
            "ed25519",
            "-N",
            "",
            "-q",
            "-C",
            "maintainer",
            "-f",
            "key",
        ],
    );
    let pubkey = std::fs::read_to_string(keydir.join("key.pub")).unwrap();
    let key_b64 = pubkey
        .split_whitespace()
        .nth(1)
        .expect("ssh public key has base64 blob");
    let trust_key = format!("demo:Ed25519:{key_b64}");
    let signing_key = keydir.join("key");

    // A SHA-256 repo with one committed registry tree, SSH-signed.
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    run(
        &repo,
        "git",
        &["init", "-q", "--object-format=sha256", "-b", "stable"],
    );
    for (key, value) in [
        ("user.name", "AOS Test"),
        ("user.email", "test@aos"),
        ("gpg.format", "ssh"),
        ("user.signingkey", signing_key.to_str().unwrap()),
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
    ] {
        run(&repo, "git", &["config", key, value]);
    }

    std::fs::write(
        repo.join("registry.toml"),
        "[registry]\nname = \"demo\"\ndescription = \"git interop\"\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("keys.toml"),
        format!("schema = 1\n\n[[keys]]\nid = \"maintainer\"\nkey = \"{trust_key}\"\n"),
    )
    .unwrap();
    std::fs::create_dir_all(repo.join("packages/c")).unwrap();
    std::fs::write(
        repo.join("packages/c/curl.toml"),
        "[package]\nname = \"curl\"\ndescription = \"URL transfers\"\nlicense = \"MIT\"\n\
         maintainer = \"aos\"\n\n[[versions]]\nversion = \"8.5.0\"\n\n\
         [versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0\"\n\
         nar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\n\
         source_drv = \"/var/lib/store/x.drv\"\nsource_nar_hash = \"sha256:bb\"\n",
    )
    .unwrap();
    run(&repo, "git", &["add", "-A"]);
    run(&repo, "git", &["commit", "-q", "-m", "release 1.0.0"]);

    // Signed release tag, then a partition payload exactly as apr writes
    // it: a temporary signed tag named after the channel, targeting the
    // release *tag object*, cat-file'd into the partition files.
    run(&repo, "git", &["tag", "-s", "1.0.0", "-m", "release 1.0.0"]);
    run(
        &repo,
        "git",
        &["tag", "-s", "-f", "stable", "-m", "partition", "1.0.0"],
    );
    let partition_payload = {
        let output = Command::new("git")
            .args(["cat-file", "tag", "refs/tags/stable"])
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(output.status.success());
        output.stdout
    };
    let release_tag_oid = run(&repo, "git", &["rev-parse", "refs/tags/1.0.0"]);
    run(&repo, "git", &["tag", "-d", "stable"]);
    run(&repo, "git", &["update-server-info"]);

    // Export the surface the way `apr origin upload` lays it out.
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(surface.join("info")).unwrap();
    copy_tree(&repo.join(".git/objects"), &surface.join("objects"));
    std::fs::write(surface.join("HEAD"), "ref: refs/heads/stable\n").unwrap();
    // update-server-info omits the deleted temp tag; keep refs as-is and
    // append the peeled line for the release tag if git didn't.
    let refs = std::fs::read_to_string(repo.join(".git/info/refs")).unwrap();
    std::fs::write(surface.join("info/refs"), refs).unwrap();
    let channel_dir = surface.join("channels/stable");
    std::fs::create_dir_all(&channel_dir).unwrap();
    for bucket in 0u16..=255 {
        std::fs::write(
            channel_dir.join(format!("{bucket:02x}")),
            &partition_payload,
        )
        .unwrap();
    }

    // The hub verifies and indexes the git-produced surface fail-closed.
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry("demo", &[trust_key], true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let outcome = index_and_record(&db, &LocalFsFetch::new(&surface), &registry)
        .await
        .unwrap();
    assert_eq!(outcome.packages, 1);
    assert_eq!(outcome.releases, 1);
    assert_eq!(outcome.channels, 1);

    let releases = db.list_releases(registry.id).await.unwrap();
    assert_eq!(releases[0].semver, "1.0.0");
    assert_eq!(releases[0].tag_oid, release_tag_oid.trim());
    assert_eq!(releases[0].signer.as_deref(), Some(key_b64));
    let channels = db.list_channels(registry.id).await.unwrap();
    assert_eq!(channels[0].frontier.as_deref(), Some("1.0.0"));
    assert_eq!(channels[0].partitions.iter().flatten().count(), 256);
}

/// Recursively copy a directory tree.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}
