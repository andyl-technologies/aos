//! Native apply, observation, reconfiguration, and removal checks.

use super::*;
use tempfile::TempDir;

fn fixture() -> (TempDir, NativeFilesystem) {
    let directory = tempfile::tempdir().unwrap();
    let handler = NativeFilesystem {
        state_root: directory.path().join("claims"),
        roots: vec![directory.path().to_path_buf()],
        immutable_roots: vec![directory.path().join("immutable")],
    };
    (directory, handler)
}

fn invocation(path: &Path) -> NativeInvocation {
    let input = json!({"path":path, "mode":"0700", "owner":null, "group":null});
    serde_json::from_value(json!({
        "id":"test-directory", "revision":"revision-one", "action":"apply", "previous":null,
        "input":input,
        "effect": {
            "owner":"filesystem", "identity":["test", "filesystem", "directory", "main"],
            "input":input, "inputs":{}, "input_type":{"kind":"submodule","open":true,"fields":{}},
            "after":[], "results":{"path":{"kind":"string"},"resource":{"kind":"string"}},
            "handler":{"kind":"process","artifact":"/nix/store/00000000000000000000000000000000-handler","executable":"/nix/store/00000000000000000000000000000000-handler/bin/handler"},
            "dependencies":[], "revision":"revision-one", "lifetime":"instance", "timeout_ms":1000
        }
    })).unwrap()
}

fn call(
    handler: &NativeFilesystem,
    action: &str,
    invocation: &NativeInvocation,
) -> serde_json::Value {
    serde_json::from_slice(
        &handler
            .handle(action, &serde_json::to_vec(invocation).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn native_directory_reconfigures_without_deleting_contents_and_removes_exact_claim() {
    let (temporary, handler) = fixture();
    let path = temporary.path().join("data");
    let mut invocation = invocation(&path);

    assert_eq!(
        call(&handler, "observe", &invocation)["status"],
        "retry-safe"
    );
    assert_eq!(
        call(&handler, "apply", &invocation)["resource"],
        "test-directory"
    );
    fs::write(path.join("payload"), b"retained contents").unwrap();
    assert_eq!(call(&handler, "observe", &invocation)["status"], "current");

    invocation.input["mode"] = "0750".into();
    invocation.revision = "revision-two".into();
    call(&handler, "apply", &invocation);
    assert_eq!(
        fs::read(path.join("payload")).unwrap(),
        b"retained contents"
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o750
    );
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("payload"), b"foreign contents").unwrap();
    std::os::unix::fs::symlink(&outside, path.join("outside-link")).unwrap();

    invocation.action = Action::Remove;
    call(&handler, "remove", &invocation);
    assert_eq!(call(&handler, "observe", &invocation)["status"], "absent");
    assert!(!path.exists());
    assert_eq!(
        fs::read(outside.join("payload")).unwrap(),
        b"foreign contents"
    );
}

#[test]
fn native_directory_refuses_unclaimed_paths_and_accepts_rematerialization() {
    let (temporary, handler) = fixture();
    let path = temporary.path().join("data");
    let mut invocation = invocation(&path);
    fs::create_dir(&path).unwrap();

    assert_eq!(
        call(&handler, "observe", &invocation)["status"],
        "indeterminate"
    );
    assert!(
        handler
            .handle("apply", &serde_json::to_vec(&invocation).unwrap())
            .is_err()
    );
    fs::remove_dir(&path).unwrap();
    call(&handler, "apply", &invocation);
    let original = fs::metadata(&path).unwrap();
    fs::rename(&path, temporary.path().join("original")).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let materialized = fs::metadata(&path).unwrap();

    assert_ne!(original.ino(), materialized.ino());
    assert_eq!(call(&handler, "observe", &invocation)["status"], "current");
    call(&handler, "apply", &invocation);

    invocation.action = Action::Remove;
    call(&handler, "remove", &invocation);
    assert!(!path.exists());
    assert!(temporary.path().join("original").is_dir());
}

#[test]
fn directory_claim_replays_with_cloned_device_and_inode_metadata() {
    let (temporary, handler) = fixture();
    let path = temporary.path().join("data");
    let mut invocation = invocation(&path);
    call(&handler, "apply", &invocation);
    let claim_path = handler.claim_path(&invocation.id);
    let mut claim: Claim = read_private_record(&claim_path, "test claim")
        .unwrap()
        .unwrap();
    claim.device += 1;
    claim.inode += 1;
    write_private_record(&handler.state_root, &claim_path, &claim).unwrap();
    fs::write(path.join("payload"), b"materialized contents").unwrap();

    assert_eq!(call(&handler, "observe", &invocation)["status"], "current");
    invocation.input["mode"] = "0750".into();
    invocation.revision = "revision-two".into();
    call(&handler, "apply", &invocation);

    assert_eq!(call(&handler, "observe", &invocation)["status"], "current");
    assert_eq!(
        fs::read(path.join("payload")).unwrap(),
        b"materialized contents"
    );
    let updated: Claim = read_private_record(&claim_path, "test claim")
        .unwrap()
        .unwrap();
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(
        (updated.device, updated.inode),
        (metadata.dev(), metadata.ino())
    );
}

#[test]
fn claimed_directory_metadata_drift_is_reconciled_at_the_same_path() {
    let (temporary, handler) = fixture();
    let path = temporary.path().join("data");
    let invocation = invocation(&path);
    call(&handler, "apply", &invocation);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(
        call(&handler, "observe", &invocation)["status"],
        "retry-safe"
    );
    call(&handler, "apply", &invocation);

    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(call(&handler, "observe", &invocation)["status"], "current");
}

#[test]
fn directory_claim_rejects_a_file_or_symlink_at_the_claimed_path() {
    for symlink in [false, true] {
        let (temporary, handler) = fixture();
        let path = temporary.path().join("data");
        let mut invocation = invocation(&path);
        call(&handler, "apply", &invocation);
        fs::rename(&path, temporary.path().join("original")).unwrap();
        let target = temporary.path().join("foreign");
        fs::write(&target, b"foreign contents").unwrap();
        if symlink {
            std::os::unix::fs::symlink(&target, &path).unwrap();
        } else {
            fs::write(&path, b"replacement contents").unwrap();
        }

        if let Ok(observed) = handler.handle("observe", &serde_json::to_vec(&invocation).unwrap()) {
            let observed: serde_json::Value = serde_json::from_slice(&observed).unwrap();
            assert_eq!(observed["status"], "indeterminate");
        }
        assert!(
            handler
                .handle("apply", &serde_json::to_vec(&invocation).unwrap())
                .is_err()
        );
        invocation.action = Action::Remove;
        assert!(
            handler
                .handle("remove", &serde_json::to_vec(&invocation).unwrap())
                .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"foreign contents");
        assert!(fs::symlink_metadata(&path).is_ok());
    }
}

#[test]
fn interrupted_quarantine_cleanup_is_retryable_and_never_reported_absent() {
    let (temporary, handler) = fixture();
    let path = temporary.path().join("data");
    let mut invocation = invocation(&path);
    call(&handler, "apply", &invocation);
    let quarantine = path.with_file_name(format!(
        ".aos-native-release-{}",
        Sha256Digest::of_bytes(invocation.id.as_bytes()).hex()
    ));
    fs::rename(&path, &quarantine).unwrap();

    invocation.action = Action::Remove;
    assert_eq!(
        call(&handler, "observe", &invocation)["status"],
        "retry-safe"
    );
    call(&handler, "remove", &invocation);
    assert!(!quarantine.exists());
    assert_eq!(call(&handler, "observe", &invocation)["status"], "absent");
}

#[test]
fn native_file_copies_bounded_source_and_observes_content_drift() {
    let (temporary, handler) = fixture();
    let source = temporary.path().join("source");
    let destination = temporary.path().join("destination");
    fs::write(&source, b"first").unwrap();
    let mut invocation = invocation(&destination);
    invocation.effect.identity[2] = "entry".into();
    invocation.input["kind"] = "copied-file".into();
    invocation.input["sourcePath"] = json!(source);
    invocation.input["maxBytes"] = 5.into();

    call(&handler, "apply", &invocation);
    assert_eq!(fs::read(&destination).unwrap(), b"first");
    assert_eq!(call(&handler, "observe", &invocation)["status"], "current");
    fs::write(&destination, b"other").unwrap();
    assert_eq!(
        call(&handler, "observe", &invocation)["status"],
        "retry-safe"
    );
    fs::write(&source, b"too many bytes").unwrap();
    assert!(
        handler
            .handle("apply", &serde_json::to_vec(&invocation).unwrap())
            .is_err()
    );
    assert_eq!(fs::read(&destination).unwrap(), b"other");
}

#[test]
fn native_mutable_file_preserves_contents_and_inode_across_reconfiguration() {
    let (temporary, handler) = fixture();
    let path = temporary.path().join("application.log");
    let mut invocation = invocation(&path);
    invocation.effect.identity[2] = "entry".into();
    invocation.input["kind"] = "empty-file".into();
    invocation.input["mode"] = "0660".into();
    invocation.input["maxBytes"] = 1.into();

    call(&handler, "apply", &invocation);
    let initial = fs::metadata(&path).unwrap();
    assert_eq!(initial.len(), 0);
    fs::write(&path, b"application-owned log contents\n").unwrap();
    assert_eq!(call(&handler, "observe", &invocation)["status"], "current");

    invocation.input["mode"] = "0640".into();
    invocation.revision = "revision-two".into();
    call(&handler, "apply", &invocation);

    let updated = fs::metadata(&path).unwrap();
    assert_eq!(
        (initial.dev(), initial.ino()),
        (updated.dev(), updated.ino())
    );
    assert_eq!(updated.permissions().mode() & 0o7777, 0o640);
    assert_eq!(
        fs::read(&path).unwrap(),
        b"application-owned log contents\n"
    );
    assert_eq!(call(&handler, "observe", &invocation)["status"], "current");

    invocation.action = Action::Remove;
    call(&handler, "remove", &invocation);
    assert_eq!(call(&handler, "observe", &invocation)["status"], "absent");
}

#[test]
fn native_mutable_file_refuses_unclaimed_files_and_replacement_inodes() {
    let (temporary, handler) = fixture();
    let path = temporary.path().join("application.log");
    let mut invocation = invocation(&path);
    invocation.effect.identity[2] = "entry".into();
    invocation.input["kind"] = "empty-file".into();
    fs::write(&path, b"operator-owned contents").unwrap();

    assert_eq!(
        call(&handler, "observe", &invocation)["status"],
        "indeterminate"
    );
    assert!(
        handler
            .handle("apply", &serde_json::to_vec(&invocation).unwrap())
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), b"operator-owned contents");

    fs::remove_file(&path).unwrap();
    call(&handler, "apply", &invocation);
    fs::rename(&path, temporary.path().join("original")).unwrap();
    fs::write(&path, b"replacement contents").unwrap();

    assert_eq!(
        call(&handler, "observe", &invocation)["status"],
        "indeterminate"
    );
    assert!(
        handler
            .handle("apply", &serde_json::to_vec(&invocation).unwrap())
            .is_err()
    );
    invocation.action = Action::Remove;
    assert!(
        handler
            .handle("remove", &serde_json::to_vec(&invocation).unwrap())
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), b"replacement contents");
}

#[test]
fn native_mutable_file_rejects_sources_and_symlinks_before_mutation() {
    let (temporary, handler) = fixture();
    let path = temporary.path().join("application.log");
    let target = temporary.path().join("target");
    fs::write(&target, b"untouched contents").unwrap();
    let mut invocation = invocation(&path);
    invocation.effect.identity[2] = "entry".into();
    invocation.input["kind"] = "empty-file".into();
    invocation.input["sourcePath"] = json!(target);

    assert!(
        handler
            .handle("apply", &serde_json::to_vec(&invocation).unwrap())
            .is_err()
    );
    assert!(!path.exists());

    invocation
        .input
        .as_object_mut()
        .unwrap()
        .remove("sourcePath");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(
        handler
            .handle("apply", &serde_json::to_vec(&invocation).unwrap())
            .is_err()
    );
    assert_eq!(fs::read(&target).unwrap(), b"untouched contents");
    assert!(
        fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn native_tree_owns_only_link_and_retains_source_after_teardown() {
    let (temporary, handler) = fixture();
    let source = temporary.path().join("immutable");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("config"), b"retained configuration").unwrap();
    let path = temporary.path().join("configuration");
    let mut invocation = invocation(&path);
    invocation.effect.identity[2] = "symlinkTree".into();
    invocation.input["mode"] = "0777".into();
    invocation.input["sourcePath"] = json!(source);

    call(&handler, "apply", &invocation);
    assert_eq!(fs::read_link(&path).unwrap(), source);
    assert_eq!(call(&handler, "observe", &invocation)["status"], "current");
    invocation.action = Action::Remove;
    call(&handler, "remove", &invocation);

    assert!(fs::symlink_metadata(&path).is_err());
    assert_eq!(
        fs::read(source.join("config")).unwrap(),
        b"retained configuration"
    );
}

#[test]
fn parent_ordering_alone_does_not_authorize_nested_allocation() {
    let (temporary, handler) = fixture();
    let parent_path = temporary.path().join("data");
    let parent = invocation(&parent_path);
    call(&handler, "apply", &parent);
    let mut child = invocation(&parent_path.join("child"));
    child.id = "child".into();
    child.effect.dependencies = vec![parent.id.clone()];

    assert!(
        handler
            .handle("apply", &serde_json::to_vec(&child).unwrap())
            .is_err()
    );
    child.input["parentResource"] = json!(parent.id);
    call(&handler, "apply", &child);
    assert!(parent_path.join("child").is_dir());
}

#[test]
fn nested_allocation_accepts_rematerialized_claimed_parent() {
    let (temporary, handler) = fixture();
    let path = temporary.path().join("data");
    let parent = invocation(&path);
    call(&handler, "apply", &parent);
    let mut child = invocation(&path.join("child"));
    child.id = "child".into();
    child.effect.dependencies = vec![parent.id.clone()];
    child.input["parentResource"] = json!(parent.id);
    fs::rename(&path, temporary.path().join("original")).unwrap();
    fs::create_dir(&path).unwrap();

    call(&handler, "apply", &child);
    assert!(path.join("child").is_dir());
    assert!(!temporary.path().join("original/child").exists());
}

#[test]
fn production_policy_accepts_platform_entries_and_rejects_shared_or_immutable_paths() {
    let handler = NativeFilesystem::production();

    for path in [
        "/var/etc/ssh",
        "/var/empty",
        "/var/db/sudo",
        "/var/log/sudo-io",
        "/run/apm",
        "/etc/ssh/authorized_keys",
        "/nix/var/nix/gcroots/aos-profiles",
    ] {
        handler.validate_path(Path::new(path), false).unwrap();
    }

    for root in &handler.roots {
        assert!(handler.validate_path(root, false).is_err(), "{root:?}");
    }
    for path in [
        "/",
        "/nix",
        "/nix/store/unowned",
        "/usr/lib/unowned",
        "/home/unowned",
        "/var/../etc/unowned",
        "/var/lib/aos/native-filesystem",
        "/var/lib/aos/native-filesystem/claim.json",
        "/var/lib/aos",
    ] {
        assert!(
            handler.validate_path(Path::new(path), false).is_err(),
            "{path}"
        );
    }
}

#[test]
fn production_policy_realizes_var_and_gc_entries_without_adopting_existing_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let production = NativeFilesystem::production();
    let relocated = |path: &Path| temporary.path().join(path.strip_prefix("/").unwrap());
    let handler = NativeFilesystem {
        state_root: relocated(&production.state_root),
        roots: production
            .roots
            .iter()
            .map(|root| relocated(root))
            .collect(),
        immutable_roots: production
            .immutable_roots
            .iter()
            .map(|root| relocated(root))
            .collect(),
    };
    for root in &handler.roots {
        fs::create_dir_all(root).unwrap();
    }
    fs::create_dir_all(relocated(Path::new("/var/db"))).unwrap();

    for path in [
        "/var/etc/ssh",
        "/var/empty",
        "/var/db/sudo",
        "/nix/var/nix/gcroots/aos-profiles",
    ] {
        let path = relocated(Path::new(path));
        let mut invocation = invocation(&path);

        call(&handler, "apply", &invocation);
        assert_eq!(call(&handler, "observe", &invocation)["status"], "current");
        invocation.action = Action::Remove;
        call(&handler, "remove", &invocation);
        assert!(!path.exists());

        fs::create_dir(&path).unwrap();
        invocation.action = Action::Apply;
        assert!(
            handler
                .handle("apply", &serde_json::to_vec(&invocation).unwrap())
                .is_err()
        );
        assert!(path.exists());
        fs::remove_dir(&path).unwrap();
    }

    let link = relocated(Path::new("/var/etc/redirect"));
    std::os::unix::fs::symlink(temporary.path(), &link).unwrap();
    let invocation = invocation(&link.join("unowned"));
    assert!(
        handler
            .handle("apply", &serde_json::to_vec(&invocation).unwrap())
            .is_err()
    );
    assert!(!temporary.path().join("unowned").exists());
}
