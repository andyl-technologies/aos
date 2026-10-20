//! Genuine reviewed List selection, refusal and read-only output custody.

use std::os::unix::fs::PermissionsExt as _;

use super::*;

#[path = "list_cohort_race_tests.rs"]
mod head_race;

async fn list_fixture() -> Fixture {
    fixture_with_database_and_purposes(
        Database::open_in_memory().await.unwrap(),
        &["list", "presign", "read", "write"],
    )
    .await
}

async fn export(
    fixture: &Fixture,
    path: &Path,
) -> Result<super::super::list_cohort::ListCohortExport> {
    export_list_cohort(
        &fixture.db,
        &PhysicalStorageAuthorityId::parse(AUTHORITY)?,
        &fixture.configuration,
        "bootstrap-association",
        PREFIX,
        path,
    )
    .await
}

#[tokio::test]
async fn actual_reviewed_list_selection_is_canonical_private_and_material_free() {
    let fixture = list_fixture().await;
    let parent = relative_private_directory(&fixture.directory);
    let output = parent.join("list-export");
    let selection = export(&fixture, &output).await.unwrap();
    assert_eq!(selection.list_cohort.credential.purpose, LeasePurpose::List);
    assert_eq!(selection.list_cohort.allowed_effects, [LeaseEffect::List]);
    let bytes = std::fs::read(output.join("list-cohort.json")).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&selection).unwrap());
    assert!(!String::from_utf8(bytes)
        .unwrap()
        .contains(std::str::from_utf8(MATERIAL).unwrap()));
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(output.join("list-cohort.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(export(&fixture, &output).await.is_err());
    assert!(!fixture.configuration.signing_seed_file.exists());

    let insecure = parent.join("public-parent");
    std::fs::create_dir(&insecure).unwrap();
    std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(export(&fixture, &insecure.join("export")).await.is_err());
    assert!(!insecure.join("export").exists());
}

#[tokio::test]
async fn missing_purpose_foreign_scope_blocked_and_stale_sql_refuse() {
    let fixture = fixture().await;
    let parent = relative_private_directory(&fixture.directory);
    assert!(export(&fixture, &parent.join("missing-list"))
        .await
        .is_err());

    let fixture = list_fixture().await;
    let authority = PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap();
    let parent = relative_private_directory(&fixture.directory);
    for (association, prefix) in [
        ("other", PREFIX),
        ("bootstrap-association", "unreviewed/prefix"),
    ] {
        assert!(export_list_cohort(
            &fixture.db,
            &authority,
            &fixture.configuration,
            association,
            prefix,
            &parent.join("bad-scope")
        )
        .await
        .is_err());
    }
    for case in 0..3 {
        let mut configuration = fixture.configuration.clone();
        match case {
            0 => configuration.installation.executor_identity = "other-executor".into(),
            1 => configuration.installation.authority.guard_namespace_id = "other-namespace".into(),
            _ => configuration.installation.authority.qualification_digest = "f".repeat(64),
        }
        assert!(export_list_cohort(
            &fixture.db,
            &authority,
            &configuration,
            "bootstrap-association",
            PREFIX,
            &parent.join("bad-issuer")
        )
        .await
        .is_err());
    }
    super::publication_export::set_admission(
        &fixture,
        pb::StorageAuthorityDesiredState::Blocked,
        "list-block",
    )
    .await;
    assert!(export(&fixture, &parent.join("blocked")).await.is_err());
    super::publication_export::set_admission(
        &fixture,
        pb::StorageAuthorityDesiredState::Admitted,
        "list-readmit",
    )
    .await;
    fixture
        .db
        .set_binding_credential_revision(
            fixture.binding_id,
            "list",
            "secret://bootstrap/list/v2",
            1,
            &hex::encode(Sha256::digest(b"changed")),
            "operator",
        )
        .await
        .unwrap();
    assert!(export(&fixture, &parent.join("stale")).await.is_err());
}

#[tokio::test]
async fn actual_cli_opens_readonly_sql_and_exports_the_exact_list_selection() {
    use clap::Parser as _;

    let directory = private_directory();
    let path = directory.path().join("existing.db");
    let fixture = fixture_with_database_and_purposes(
        Database::open(&path).await.unwrap(),
        &["list", "presign", "read", "write"],
    )
    .await;
    let parent = relative_private_directory(&directory);
    let url_file = parent.join("database-url");
    let configuration_file = parent.join("issuer.json");
    for (name, bytes) in [
        (&url_file, path.to_str().unwrap().as_bytes().to_vec()),
        (
            &configuration_file,
            serde_json::to_vec(&fixture.configuration).unwrap(),
        ),
    ] {
        std::fs::write(name, bytes).unwrap();
        std::fs::set_permissions(name, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let output = parent.join("cli-list-export");
    let before = std::fs::read(&path).unwrap();
    let args = crate::Args::try_parse_from([
        "aos-hub-authority-bootstrap",
        "--database-url-file",
        url_file.to_str().unwrap(),
        "export-list-cohort",
        "--authority-id",
        AUTHORITY,
        "--issuer-configuration",
        configuration_file.to_str().unwrap(),
        "--association-id",
        "bootstrap-association",
        "--admitted-prefix",
        PREFIX,
        "--output",
        output.to_str().unwrap(),
    ])
    .unwrap();
    crate::run(args).await.unwrap();
    let actual: super::super::list_cohort::ListCohortExport =
        serde_json::from_slice(&std::fs::read(output.join("list-cohort.json")).unwrap()).unwrap();
    let reader = open_existing(path.to_str().unwrap()).await.unwrap();
    let expected = export_list_cohort(
        &reader,
        &PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap(),
        &fixture.configuration,
        "bootstrap-association",
        PREFIX,
        &parent.join("direct-list-export"),
    )
    .await
    .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(reader
        .create_user("forbidden-cli@example.test", None)
        .await
        .is_err());
}
