//! Actual reviewed admission transitions and read-only canonical publication export.

use aos_hub_core::storage_authority::StorageAuthorityAdmissionState;

use super::*;

async fn set_admission(fixture: &Fixture, state: pb::StorageAuthorityDesiredState, key: &str) {
    let authority = PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap();
    let head = fixture
        .db
        .desired_storage_authority_admission(&authority)
        .await
        .unwrap()
        .unwrap();
    let admitted = state == pb::StorageAuthorityDesiredState::Admitted;
    decision(
        &fixture.rpc,
        &fixture.auth,
        pb::storage_authority_decision::Input::SetAdmission(
            pb::SetStorageAuthorityAdmissionDecision {
                authority_id: AUTHORITY.into(),
                expected_generation: head.generation.to_string(),
                expected_digest: Some(head.digest),
                guard_namespace_id: NAMESPACE.into(),
                state: state as i32,
                attestation_id: admitted.then(|| "bootstrap-attestation".into()),
                association_ids: if admitted {
                    vec!["bootstrap-association".into()]
                } else {
                    vec![]
                },
            },
        ),
        &head.generation.to_string(),
        key,
    )
    .await;
}

async fn check_export(db: &Database, directory: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let authority = PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap();
    let expected = db
        .storage_authority_publication(&authority, NAMESPACE, EXECUTOR)
        .await
        .unwrap();
    let receipt = export_publication(db, &authority, NAMESPACE, EXECUTOR, directory)
        .await
        .unwrap();
    let bytes = std::fs::read(directory.join("publication.json")).unwrap();
    assert_eq!(bytes, serde_json::to_vec(&expected).unwrap());
    assert_eq!(receipt.authority_id, authority);
    assert_eq!(receipt.generation, expected.generation);
    assert_eq!(receipt.admission_digest, expected.digest);
    assert_eq!(
        receipt.publication_sha256,
        hex::encode(Sha256::digest(&bytes))
    );
    assert_eq!(receipt.state, expected.admission.state);
    assert_eq!(
        std::fs::read(directory.join("publication-receipt.json")).unwrap(),
        serde_json::to_vec(&receipt).unwrap()
    );
    assert!(!String::from_utf8(bytes)
        .unwrap()
        .contains(std::str::from_utf8(MATERIAL).unwrap()));
    assert_eq!(
        std::fs::metadata(directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in ["publication.json", "publication-receipt.json"] {
        assert_eq!(
            std::fs::metadata(directory.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(
        export_publication(db, &authority, NAMESPACE, EXECUTOR, directory)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn reviewed_admit_block_readmit_and_retire_export_exact_sql_heads() {
    let fixture = fixture().await;
    let directory = relative_private_directory(&fixture.directory);
    check_export(&fixture.db, &directory.join("admitted")).await;
    for (state, name) in [
        (pb::StorageAuthorityDesiredState::Blocked, "blocked"),
        (pb::StorageAuthorityDesiredState::Admitted, "readmitted"),
        (pb::StorageAuthorityDesiredState::Retired, "retired"),
    ] {
        set_admission(&fixture, state, name).await;
        check_export(&fixture.db, &directory.join(name)).await;
        let publication: StorageAuthorityPublication = serde_json::from_slice(
            &std::fs::read(directory.join(name).join("publication.json")).unwrap(),
        )
        .unwrap();
        if state != pb::StorageAuthorityDesiredState::Admitted {
            assert!(publication.aliases.is_empty());
            assert!(publication.associations.is_empty());
            assert!(publication.attestation.is_none());
            assert!(matches!(
                publication.admission.state,
                StorageAuthorityAdmissionState::Blocked | StorageAuthorityAdmissionState::Retired
            ));
        }
    }
    assert!(!fixture.configuration.signing_seed_file.exists());
}

#[tokio::test]
async fn readonly_export_refuses_foreign_domain_stale_pins_and_corrupt_history() {
    use clap::Parser as _;
    use std::os::unix::fs::PermissionsExt as _;

    let directory = private_directory();
    let path = directory.path().join("existing.db");
    let fixture = fixture_with_database(Database::open(&path).await.unwrap()).await;
    let reader = open_existing(path.to_str().unwrap()).await.unwrap();
    let output = relative_private_directory(&directory);
    let authority = PhysicalStorageAuthorityId::parse(AUTHORITY).unwrap();
    let before = std::fs::read(&path).unwrap();
    check_export(&reader, &output.join("readonly")).await;
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let url_file = output.join("database-url");
    std::fs::write(&url_file, path.to_str().unwrap()).unwrap();
    std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cli_output = output.join("cli-export");
    let args = crate::Args::try_parse_from([
        "aos-hub-authority-bootstrap",
        "--database-url-file",
        url_file.to_str().unwrap(),
        "export-publication",
        "--authority-id",
        AUTHORITY,
        "--guard-namespace-id",
        NAMESPACE,
        "--executor-identity",
        EXECUTOR,
        "--output",
        cli_output.to_str().unwrap(),
    ])
    .unwrap();
    crate::run(args).await.unwrap();
    assert_eq!(
        std::fs::read(cli_output.join("publication.json")).unwrap(),
        std::fs::read(output.join("readonly/publication.json")).unwrap()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(reader
        .create_user("forbidden-export@example.test", None)
        .await
        .is_err());
    for (namespace, executor, name) in [
        ("foreign-namespace", EXECUTOR, "foreign-namespace"),
        (NAMESPACE, "foreign-executor", "foreign-executor"),
    ] {
        assert!(
            export_publication(&reader, &authority, namespace, executor, &output.join(name))
                .await
                .is_err()
        );
        assert!(!output.join(name).exists());
    }

    fixture
        .db
        .set_binding_credential_revision(
            fixture.binding_id,
            "read",
            "secret://bootstrap/read/v2",
            1,
            &hex::encode(Sha256::digest(b"changed")),
            "operator",
        )
        .await
        .unwrap();
    assert!(export_publication(
        &reader,
        &authority,
        NAMESPACE,
        EXECUTOR,
        &output.join("stale")
    )
    .await
    .is_err());
    assert!(!output.join("stale").exists());

    // A blocked head carries no credential members, but still requires valid
    // persisted admission and permanent binding identity history.
    set_admission(
        &fixture,
        pb::StorageAuthorityDesiredState::Blocked,
        "blocked-for-corruption",
    )
    .await;
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute(
        "UPDATE storage_authority_admission_revisions SET specification_digest = ?1 WHERE generation = 2",
        [&"f".repeat(64)],
    ).unwrap();
    assert!(export_publication(
        &reader,
        &authority,
        NAMESPACE,
        EXECUTOR,
        &output.join("corrupt-head")
    )
    .await
    .is_err());
    assert!(!output.join("corrupt-head").exists());
    connection.execute(
        "UPDATE topology_plans SET plan_kind = 'delete_binding', input_versions_json = '{}' WHERE plan_id = (SELECT MIN(plan_id) FROM topology_plans)",
        [],
    ).unwrap();
    assert!(open_existing(path.to_str().unwrap()).await.is_err());
    assert!(export_publication(
        &reader,
        &authority,
        NAMESPACE,
        EXECUTOR,
        &output.join("corrupt-history")
    )
    .await
    .is_err());
    assert!(!output.join("corrupt-history").exists());
    connection
        .execute("UPDATE hub_schema_identity SET identity = 'foreign'", [])
        .unwrap();
    assert!(open_existing(path.to_str().unwrap()).await.is_err());
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_readonly_role_exports_actual_reviewed_heads_with_sixteen_table_grants() {
    let Ok(url) = std::env::var("AOS_HUB_PUBLICATION_EXPORT_TEST_PG_URL") else {
        return;
    };
    let fixture = fixture_with_database(Database::connect(&url).await.unwrap()).await;
    let owner = sqlx::PgPool::connect(&url).await.unwrap();
    let role = format!("publication_reader_{}", uuid::Uuid::new_v4().simple());
    let password = uuid::Uuid::new_v4().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
    ))
    .execute(&owner)
    .await
    .unwrap();
    sqlx::query(&format!("GRANT USAGE ON SCHEMA public TO {role}"))
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query(&format!(
        "GRANT SELECT ON schema_version, hub_schema_identity,
        physical_storage_authorities, physical_storage_aliases,
        binding_storage_authority_revisions, storage_authority_attestations,
        storage_authority_admission_heads, storage_authority_admission_revisions,
        bindings, binding_credential_heads, binding_credential_revisions,
        binding_write_revisions, topology_operations, binding_write_state,
        binding_identity_reservations, topology_plans TO {role}"
    ))
    .execute(&owner)
    .await
    .unwrap();
    let mut address = url::Url::parse(&url).unwrap();
    address.set_username(&role).unwrap();
    address.set_password(Some(&password)).unwrap();
    let reader = open_existing(address.as_str()).await.unwrap();
    let directory = relative_private_directory(&fixture.directory);
    check_export(&reader, &directory.join("pg-admitted")).await;
    set_admission(
        &fixture,
        pb::StorageAuthorityDesiredState::Blocked,
        "pg-block",
    )
    .await;
    check_export(&reader, &directory.join("pg-blocked")).await;
    set_admission(
        &fixture,
        pb::StorageAuthorityDesiredState::Admitted,
        "pg-readmit",
    )
    .await;
    check_export(&reader, &directory.join("pg-readmitted")).await;
    assert!(reader
        .create_user("forbidden-export@example.test", None)
        .await
        .is_err());
    drop(reader);
    sqlx::query(&format!("DROP OWNED BY {role}"))
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&owner)
        .await
        .unwrap();
}
