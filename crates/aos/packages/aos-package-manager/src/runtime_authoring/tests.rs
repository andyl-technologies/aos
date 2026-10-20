//! Exercises absent-only authoring publication and exact retained source selection.

use super::*;

fn fixture(parent: &Path) -> PathBuf {
    let source = parent.join("source");
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("_imports")).unwrap();
    fs::write(
        source.join("host.nix"),
        "{ imports = [ ./_imports/policy.nix ]; }\n",
    )
    .unwrap();
    fs::write(
        source.join("_imports/policy.nix"),
        "{ bootPolicy = true; }\n",
    )
    .unwrap();
    source
}

fn stage(source: &Path, parent: &Path) -> Result<StagedRuntime> {
    let directory = tempfile::tempdir_in(parent)?;
    let path = directory.path().join("tree");
    copy_tree(source, &path)?;
    Ok(StagedRuntime {
        _directory: directory,
        path,
    })
}

#[tokio::test]
async fn first_add_preserves_boot_source_and_relative_imports() {
    let scratch = tempfile::tempdir().unwrap();
    let source = fixture(scratch.path());
    let worktree = scratch.path().join("modules.d");
    initialize_with(&worktree, |parent| stage(&source, parent)).unwrap();
    let daemon = scratch.path().join("daemon.nix");
    fs::write(&daemon, "{ daemon = true; }\n").unwrap();

    crate::run_runtime_config_command(
        &crate::RuntimeConfigCommand::Add {
            source: daemon,
            name: Some("daemon.nix".into()),
            worktree: worktree.clone(),
        },
        false,
        &aos_cli_ui::output::Printer::new(0, true, false),
    )
    .await
    .unwrap();

    assert_eq!(
        fs::read(worktree.join("host.nix")).unwrap(),
        fs::read(source.join("host.nix")).unwrap()
    );
    assert_eq!(
        fs::read(worktree.join("_imports/policy.nix")).unwrap(),
        fs::read(source.join("_imports/policy.nix")).unwrap()
    );
    assert_eq!(
        crate::runtime_modules::list_entrypoints(&worktree).unwrap(),
        [PathBuf::from("daemon.nix"), PathBuf::from("host.nix")]
    );
    assert_eq!(
        fs::metadata(&worktree).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(worktree.join("host.nix"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[tokio::test]
async fn seeded_host_can_be_replaced_and_removed_normally() {
    let scratch = tempfile::tempdir().unwrap();
    let source = fixture(scratch.path());
    let worktree = scratch.path().join("modules.d");
    initialize_with(&worktree, |parent| stage(&source, parent)).unwrap();
    let replacement = scratch.path().join("replacement.nix");
    fs::write(&replacement, "{ operatorPolicy = true; }\n").unwrap();
    let printer = aos_cli_ui::output::Printer::new(0, true, false);

    crate::run_runtime_config_command(
        &crate::RuntimeConfigCommand::Replace {
            name: "host.nix".into(),
            source: replacement,
            worktree: worktree.clone(),
        },
        false,
        &printer,
    )
    .await
    .unwrap();
    assert_eq!(
        fs::read_to_string(worktree.join("host.nix")).unwrap(),
        "{ operatorPolicy = true; }\n"
    );

    crate::run_runtime_config_command(
        &crate::RuntimeConfigCommand::Remove {
            name: "host.nix".into(),
            worktree: worktree.clone(),
        },
        false,
        &printer,
    )
    .await
    .unwrap();
    initialize_with(&worktree, |_| {
        panic!("existing authoring choice must not be reseeded")
    })
    .unwrap();
    assert!(!worktree.join("host.nix").exists());
    assert!(
        crate::runtime_modules::list_entrypoints(&worktree)
            .unwrap()
            .is_empty()
    );
    assert!(worktree.join("_imports/policy.nix").is_file());
}

#[test]
fn existing_empty_and_modified_worktrees_never_load_committed_sources() {
    let scratch = tempfile::tempdir().unwrap();
    let worktree = scratch.path().join("modules.d");
    fs::create_dir(&worktree).unwrap();
    initialize_with(&worktree, |_| {
        panic!("intentionally empty worktree is authoritative")
    })
    .unwrap();
    fs::write(worktree.join("host.nix"), "{ modified = true; }\n").unwrap();
    initialize_with(&worktree, |_| panic!("modified worktree is authoritative")).unwrap();
    assert_eq!(
        fs::read_to_string(worktree.join("host.nix")).unwrap(),
        "{ modified = true; }\n"
    );
}

#[test]
fn failed_custody_loading_does_not_publish_a_partial_worktree() {
    let scratch = tempfile::tempdir().unwrap();
    let worktree = scratch.path().join("modules.d");
    let error =
        initialize_with(&worktree, |_| anyhow::bail!("missing original admission")).unwrap_err();
    assert!(error.to_string().contains("missing original admission"));
    assert!(!worktree.exists());
}

#[test]
fn selected_tree_rejects_missing_custody_and_multiple_roots() {
    let first = PathBuf::from("/nix/store/00000000000000000000000000000000-runtime");
    let second = PathBuf::from("/nix/store/11111111111111111111111111111111-runtime");
    let inputs = vec![
        first.to_str().unwrap().into(),
        second.to_str().unwrap().into(),
    ];
    assert_eq!(
        retained_root(&[first.join("host.nix"), first.join("extra.nix")], &inputs).unwrap(),
        Some(first.clone())
    );
    assert!(retained_root(&[first.join("host.nix")], &[]).is_err());
    assert!(
        retained_root(&[first.join("host.nix"), second.join("extra.nix")], &inputs)
            .unwrap_err()
            .to_string()
            .contains("multiple distinct source roots")
    );
    assert!(retained_root(std::slice::from_ref(&first), &inputs).is_err());
}

#[test]
fn private_preview_preserves_absent_worktree_and_rejects_unselected_siblings() {
    let scratch = tempfile::tempdir().unwrap();
    let source = fixture(scratch.path());
    let worktree = scratch.path().join("modules.d");
    let preview = stage(&source, scratch.path()).unwrap();
    let root = Path::new("/nix/store/00000000000000000000000000000000-runtime");
    validate_entrypoints(&preview.path, root, &[root.join("host.nix")]).unwrap();
    assert!(!worktree.exists());

    fs::write(preview.path.join("extra.nix"), "{}\n").unwrap();
    assert!(validate_entrypoints(&preview.path, root, &[root.join("host.nix")]).is_err());
}

#[test]
fn aliases_and_non_nix_sources_are_not_copied() {
    let scratch = tempfile::tempdir().unwrap();
    let source = fixture(scratch.path());
    fs::write(source.join("unsafe.json"), "{}").unwrap();
    assert!(stage(&source, scratch.path()).is_err());
    fs::remove_file(source.join("unsafe.json")).unwrap();
    std::os::unix::fs::symlink(source.join("host.nix"), source.join("linked.nix")).unwrap();
    assert!(stage(&source, scratch.path()).is_err());
    let worktree = scratch.path().join("modules.d");
    std::os::unix::fs::symlink(&source, &worktree).unwrap();
    assert!(
        initialize_with(&worktree, |_| panic!(
            "alias must reject before reading custody"
        ))
        .is_err()
    );
}
