//! Tests for registry Git commands, commit identities, signed commits, and index refresh.

use super::{commit_registry_paths, current_git_head, git, semver_versions_from_tag_list};
use crate::registry_ops::provenance::{
    PACKAGE_PROVENANCE_TRANSPARENCY_LOG, append_package_provenance_transparency_log,
};
use crate::registry_ops::publish::RegistryPublishLock;
use crate::registry_ops::store_paths::StorePathInfo;
use crate::registry_ops::test_support::{
    init_test_transparency_repo, sample_transparency_provenance, write_sample_package_toml,
    write_sample_provenance_artifact, write_sample_store_record,
    write_sample_store_record_with_deps,
};
use std::fs;
use tempfile::TempDir;

#[test]
fn semver_tag_list_filters_and_sorts_registry_releases() {
    let versions = semver_versions_from_tag_list("not-a-release\n1.2.0\nv1.3.0\n1.1.9\n1.2.0\n");
    assert_eq!(
        versions,
        vec![
            semver::Version::parse("1.1.9").unwrap(),
            semver::Version::parse("1.2.0").unwrap(),
        ],
    );
}

#[test]
fn commit_registry_paths_rejects_prestaged_statement_change_without_log_change() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
        ],
    )
    .unwrap();
    git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

    fs::write(&provenance_path, "{}\n").unwrap();
    git(&repo, &["add", artifact.path.as_str()]).unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("digest mismatch"));
}

#[test]
fn commit_registry_paths_rejects_first_provenance_statement_without_log() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (_, _, artifact) = sample_transparency_provenance();
    write_sample_provenance_artifact(&repo, &artifact);
    git(&repo, &["add", artifact.path.as_str()]).unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("transparency log is missing"));
}

#[test]
fn commit_registry_paths_allows_package_toml_without_versions() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let package_toml = repo.join("packages").join("s").join("stub.toml");
    fs::create_dir_all(package_toml.parent().unwrap()).unwrap();
    fs::write(
        &package_toml,
        "[package]\n\
         name = \"stub\"\n\
         description = \"\"\n\
         license = \"MIT\"\n\
         maintainer = \"aos-team\"\n",
    )
    .unwrap();

    commit_registry_paths(&repo, "publish stub", &[package_toml], None).unwrap();

    assert!(current_git_head(&repo).is_ok());
}

#[test]
fn commit_registry_paths_allows_semantically_empty_rfc0001_tables_without_provenance() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let package_toml = repo.join("packages").join("w").join("webapp.toml");
    fs::create_dir_all(package_toml.parent().unwrap()).unwrap();
    fs::write(
        &package_toml,
        "[package]\n\
         name = \"webapp\"\n\
         description = \"\"\n\
         license = \"MIT\"\n\
         maintainer = \"aos-team\"\n\
         \n\
         [[versions]]\n\
         version = \"1.0.0\"\n\
         \n\
         [versions.platforms.x86_64-linux]\n\
         store_path = \"/nix/store/abc123-webapp-1.0.0\"\n\
         closure_size = 1\n\
         source_drv = \"\"\n\
         source_nar_hash = \"\"\n\
         \n\
         [versions.platforms.x86_64-linux.permissions]\n\
         capabilities = []\n\
         cgroup-delegate = false\n\
         \n\
         [versions.platforms.x86_64-linux.bpf_lsm]\n\
         policies = []\n",
    )
    .unwrap();

    commit_registry_paths(&repo, "publish webapp", &[package_toml], None).unwrap();

    assert!(current_git_head(&repo).is_ok());
}

#[test]
fn commit_registry_paths_joins_current_process_publish_lock() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let _publish_lock = RegistryPublishLock::acquire(&repo).unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap();

    assert!(current_git_head(&repo).is_ok());
}

#[test]
fn commit_registry_paths_fails_before_staging_when_publish_lock_is_foreign() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    fs::write(repo.join(".git").join("apr-publish.lock"), "pid=999999\n").unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("another publisher may be running"));
    assert_eq!(
        git(&repo, &["diff", "--cached", "--name-only"]).unwrap(),
        ""
    );
}

#[test]
fn commit_registry_paths_rejects_package_toml_provenance_removal() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

    let content = fs::read_to_string(&package_toml).unwrap();
    let without_provenance = content
        .lines()
        .filter(|line| !line.trim_start().starts_with("provenance = "))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&package_toml, format!("{without_provenance}\n")).unwrap();
    git(
        &repo,
        &[
            "add",
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("removes committed provenance"));
}

#[test]
fn commit_registry_paths_rejects_package_toml_provenance_type_change() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

    let provenance = artifact.attestation.provenance.as_deref().unwrap();
    let content = fs::read_to_string(&package_toml).unwrap();
    fs::write(
        &package_toml,
        content.replace(&format!("provenance = \"{provenance}\""), "provenance = []"),
    )
    .unwrap();
    git(
        &repo,
        &[
            "add",
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("provenance must be a string"));
}

#[test]
fn commit_registry_paths_rejects_package_toml_source_nar_hash_mismatch() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

    let content = fs::read_to_string(&package_toml).unwrap();
    fs::write(
        &package_toml,
        content.replace(
            &format!("source_nar_hash = \"{}\"", source.nar_hash),
            &format!("source_nar_hash = \"sha256:{}\"", "f".repeat(64)),
        ),
    )
    .unwrap();
    git(
        &repo,
        &[
            "add",
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("source_nar_hash mismatch"));
}

#[test]
fn commit_registry_paths_rejects_unlogged_provenanced_store_bytes() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    let store_record = write_sample_store_record(&repo, &info, None);
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

    let bad_nar_hash = format!("sha256:{}", "e".repeat(64));
    write_sample_store_record(&repo, &info, Some(&bad_nar_hash));
    git(
        &repo,
        &[
            "add",
            store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("blesses NAR"));
}

#[test]
fn commit_registry_paths_rejects_provenanced_store_nar_size_mismatch() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    let store_record = write_sample_store_record(&repo, &info, None);
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

    write_sample_store_record(&repo, &info, Some(&info.nar_hash));
    git(
        &repo,
        &[
            "add",
            store_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("blesses NAR"));
}

#[test]
fn commit_registry_paths_rejects_reachable_dependency_store_change() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    init_test_transparency_repo(&repo);
    let (info, source, artifact) = sample_transparency_provenance();
    let dep = StorePathInfo {
        path: "/nix/store/lib123-runtime-1.0".into(),
        nar_hash: format!("sha256:{}", "1".repeat(64)),
        nar_size: 4096,
        references: vec![],
        closure_size: 4096,
    };
    let provenance_path = write_sample_provenance_artifact(&repo, &artifact);
    append_package_provenance_transparency_log(
        &repo,
        "webapp",
        "1.0.0",
        "x86_64-linux",
        &info,
        Some(&source),
        &artifact,
        &provenance_path,
    )
    .unwrap();
    let package_toml = write_sample_package_toml(&repo, &info, &source, &artifact, None);
    let root_record = write_sample_store_record_with_deps(&repo, &info, &[&dep.path], None);
    let dep_record = write_sample_store_record(&repo, &dep, None);
    git(
        &repo,
        &[
            "add",
            PACKAGE_PROVENANCE_TRANSPARENCY_LOG,
            artifact.path.as_str(),
            package_toml.strip_prefix(&repo).unwrap().to_str().unwrap(),
            root_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
            dep_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["commit", "-m", "publish webapp"]).unwrap();

    let bad_nar_hash = format!("sha256:{}", "2".repeat(64));
    write_sample_store_record(&repo, &dep, Some(&bad_nar_hash));
    git(
        &repo,
        &[
            "add",
            dep_record.strip_prefix(&repo).unwrap().to_str().unwrap(),
        ],
    )
    .unwrap();
    let registry_toml = repo.join("registry.toml");
    fs::write(&registry_toml, "[registry]\nname = \"test\"\n").unwrap();

    let err = commit_registry_paths(&repo, "metadata change", &[registry_toml], None).unwrap_err();

    assert!(format!("{err:#}").contains("reachable dependency"));
}
