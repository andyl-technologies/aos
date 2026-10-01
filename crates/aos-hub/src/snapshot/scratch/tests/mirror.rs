//! Real current mirror captures and paired hostile foreign-key originals.

use aos_hub_core::backend::SqlxBackend;
use aos_hub_core::db::Database;
use aos_hub_core::mirror_work::{
    MirrorOriginal, MirrorPart, MirrorProgress, MirrorVerification, MirrorVerifiedObject, digest,
};
use aos_hub_core::snapshot::{ClassifiedCell, SnapshotClassifier, SnapshotRowDisposition};
use aos_hub_core::storage_work::StorageObjectIdentity;
use aos_hub_core::value::{Row, Value};

use super::*;

fn original(registry_id: i64) -> MirrorOriginal {
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("4".repeat(32)),
        registry_id,
        registry_resource_version: 1,
        mirror_resource_version: 1,
        upstream_base: "https://mirror.example.invalid/registry".into(),
        path: "nar/source.nar".into(),
        placement_id: 3,
        placement_resource_version: 4,
        write_spec_version: 5,
        binding_id: 6,
        binding_resource_version: 7,
        protected_profile_digest: "3".repeat(64),
        placement_prefix: "mirror".into(),
        verification: MirrorVerification::Sha256 {
            sha256: "1".repeat(64),
            size: 11,
        },
    };
    original.job_id = original.identity().unwrap();
    original
}

fn progress(original: &MirrorOriginal) -> MirrorProgress {
    let stage = StorageObjectIdentity {
        key: original.stage_key(),
        size: 11,
        etag: "\"stage-etag\"".into(),
        provider_version: Some("private-source-incarnation".into()),
    };
    let part = MirrorPart {
        part_number: 1,
        size: 11,
        sha256: "1".repeat(64),
        etag: "\"part-etag\"".into(),
    };
    let verified = MirrorVerifiedObject {
        object: stage.clone(),
        sha256: "1".repeat(64),
        nar_sha256: None,
        nar_size: None,
    };
    MirrorProgress {
        original_digest: digest(original).unwrap(),
        upstream_etag: Some("\"source-etag\"".into()),
        stage_upload_id: Some("private-stage-upload".into()),
        stage_parts: vec![part.clone()],
        stage_object: Some(stage),
        verified: Some(verified.clone()),
        destination_upload_id: Some("private-final-upload".into()),
        destination_parts: vec![part],
        destination: Some(MirrorVerifiedObject {
            object: StorageObjectIdentity {
                key: aos_hub_core::keymap::r2_key(&original.placement_prefix, &original.path),
                size: 11,
                etag: "\"final-etag\"".into(),
                provider_version: Some("private-final-incarnation".into()),
            },
            ..verified
        }),
    }
}

async fn mirror_fixture() -> (Fixture, MirrorOriginal) {
    let (_directory, path, pool) = source().await;
    let db = Database::with_backend(Box::new(SqlxBackend::Sqlite(pool.clone())))
        .await
        .unwrap();
    let registry_id = db
        .register_registry("snapshot-mirror", &[], false)
        .await
        .unwrap();
    let original = original(registry_id);
    let progress = progress(&original);

    // These are schema/record fixtures, not issued provider authorization. The
    // snapshot must preserve them without granting restored effects authority.
    sqlx::query(
        "INSERT INTO mirror_import_objects
             (job_id, registry_id, original_digest, original_json, progress_json,
              state, commit_digest, created_at, updated_at, source_path, source_path_digest, copy_operation_id)
         VALUES (?1, ?2, ?3, ?4, ?5, 'committed', ?6, 1, 2, ?7, ?8, ?9)",
    )
    .bind(&original.job_id)
    .bind(registry_id)
    .bind(digest(&original).unwrap())
    .bind(serde_json::to_string(&original).unwrap())
    .bind(serde_json::to_string(&progress).unwrap())
    .bind(progress.commit_digest(&original).unwrap())
    .bind(&original.path)
    .bind(original.source_path_digest())
    .bind(&original.copy_operation_id)
    .execute(&pool)
    .await
    .unwrap();
    let fixture = capture_path(&path, options()).await;
    pool.close().await;
    (fixture, original)
}

fn mirror_row(original: &MirrorOriginal) -> Row {
    let progress = progress(original);
    Row::new(vec![
        Value::Text(original.job_id.clone()),
        Value::Int(original.registry_id),
        Value::Text(digest(original).unwrap()),
        Value::Text(serde_json::to_string(original).unwrap()),
        Value::Text(serde_json::to_string(&progress).unwrap()),
        Value::Text("committed".into()),
        Value::Text(progress.commit_digest(original).unwrap()),
        Value::Int(1),
        Value::Int(2),
        Value::Text(original.path.clone()),
        Value::Text(original.source_path_digest()),
        original
            .copy_operation_id
            .clone()
            .map(Value::Text)
            .unwrap_or(Value::Null),
        Value::Null,
    ])
}

// Rebuild every locator and commitment using the real classifier, then reseal
// both streams. The hostile orphan remains a valid complete mirror record.
fn replace_mirror_original(metadata: &mut [Json], private: &mut [Json], original: &MirrorOriginal) {
    let capture = SnapshotClassifier::for_supported_generation(7)
        .unwrap()
        .capture_private_row("mirror_import_objects", &mirror_row(original))
        .unwrap();
    let SnapshotRowDisposition::Retained(classified) = capture.classified() else {
        panic!("mirror original omitted")
    };
    let start = metadata
        .iter()
        .position(|line| line["kind"] == "table_start" && line["table"] == "mirror_import_objects")
        .unwrap();
    for line in &mut metadata[start + 1..] {
        if line["kind"] == "table_end" {
            break;
        }
        if line["kind"] != "cell" {
            continue;
        }
        let column = line["column"].as_str().unwrap();
        match &classified.cells[column] {
            ClassifiedCell::Scalar(scalar) => {
                line["scalar"] = serde_json::to_value(scalar).unwrap();
                line["external"] = Json::Null;
            }
            ClassifiedCell::External(_) => {
                let dependency = classified
                    .private_dependencies
                    .iter()
                    .find(|dependency| dependency.column == column)
                    .unwrap();
                let mut wire = serde_json::to_value(dependency).unwrap();
                wire["payload_bytes"] = json!(dependency.payload_bytes.to_string());
                line["external"] = wire;
                line["scalar"] = Json::Null;
            }
        }
    }
    for line in private.iter_mut().filter(|line| {
        line["kind"] == "private_cell" && line["dependency"]["table"] == "mirror_import_objects"
    }) {
        let column = line["dependency"]["column"].as_str().unwrap();
        let original = capture
            .private_cells()
            .iter()
            .find(|original| original.dependency().column == column)
            .unwrap();
        let mut encoded = Vec::new();
        original.write_private_scalar_json(&mut encoded).unwrap();
        let scalar: Json = serde_json::from_slice(&encoded).unwrap();
        let mut dependency = serde_json::to_value(original.dependency()).unwrap();
        dependency["payload_bytes"] = json!(original.dependency().payload_bytes.to_string());
        line["dependency"] = dependency;
        line["scalar"] = scalar["scalar"].clone();
    }
}

#[tokio::test]
async fn generation8_replays_mirror_child_before_registry_with_exact_private_originals() {
    let (fixture, original) = mirror_fixture().await;
    let mut recovered = Vec::new();
    aos_hub_core::snapshot::archive::records::verify_database_capture(
        fixture.output.root.as_bytes(),
        &trust(&fixture),
        &fixture.wrapping,
        &[],
        Cursor::new(&fixture.output.metadata),
        Cursor::new(&fixture.output.private),
        Default::default(),
        |table, _, row| {
            if table == "mirror_import_objects" {
                row.with_private_row(|row| recovered.push(row.clone()));
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(recovered, vec![mirror_row(&original)]);
    let report = scratch(&fixture).await.unwrap();
    assert_eq!(report.records().counts().tables, 279);
    assert_eq!(report.checked_tables(), 269);
    assert_eq!(report.synthetic_lineage_rows(), 2);
    let (metadata, _) = plaintext(&fixture);
    let names = lines(&metadata)
        .into_iter()
        .filter(|line| line["kind"] == "table_start")
        .map(|line| line["table"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(
        names
            .iter()
            .position(|name| name == "mirror_import_objects")
            < names.iter().position(|name| name == "registries")
    );
    assert!(!format!("{report:?}").contains("private-stage-upload"));
}

#[tokio::test]
async fn paired_canonical_mirror_original_with_missing_registry_fails_final_constraints() {
    let (mut fixture, original) = mirror_fixture().await;
    let mut orphan = original;
    orphan.registry_id += 1;
    orphan.job_id = orphan.identity().unwrap();
    mutate(&mut fixture, |metadata, private| {
        replace_mirror_original(metadata, private, &orphan)
    });
    assert_eq!(
        scratch(&fixture).await.unwrap_err(),
        ScratchVerificationError::Constraints
    );
}

#[tokio::test]
async fn changed_private_mirror_progress_cannot_return_a_scratch_report() {
    let (mut fixture, _) = mirror_fixture().await;
    let (metadata, private) = plaintext(&fixture);
    let mut private = lines(&private);
    let cell = private
        .iter_mut()
        .find(|line| {
            line["kind"] == "private_cell"
                && line["dependency"]["table"] == "mirror_import_objects"
                && line["dependency"]["column"] == "progress_json"
        })
        .unwrap();
    let mut progress: Json =
        serde_json::from_str(cell["scalar"]["value"].as_str().unwrap()).unwrap();
    progress["destination"]["object"]["provider_version"] = json!("different-final-incarnation");
    cell["scalar"]["value"] = json!(serde_json::to_string(&progress).unwrap());
    reseal(&mut fixture, lines(&metadata), private);
    assert_eq!(
        scratch(&fixture).await.unwrap_err(),
        ScratchVerificationError::Records
    );
}

#[tokio::test]
async fn authenticated_capture_with_changed_mirror_index_is_refused() {
    for column in ["source_path_digest", "copy_operation_id"] {
        let (mut fixture, _) = mirror_fixture().await;
        let (metadata, private) = plaintext(&fixture);
        let mut metadata = lines(&metadata);
        let start = metadata
            .iter()
            .position(|line| {
                line["kind"] == "table_start" && line["table"] == "mirror_import_objects"
            })
            .unwrap();
        let cell = metadata[start + 1..]
            .iter_mut()
            .find(|line| line["kind"] == "cell" && line["column"] == column)
            .unwrap();
        cell["scalar"]["value"] = json!("5".repeat(if column == "copy_operation_id" {
            32
        } else {
            64
        }));
        // This correctly signed archive fails record reconstruction itself.
        // The SQL-only mutation helper intentionally requires that to succeed.
        reseal(&mut fixture, metadata, lines(&private));
        assert_eq!(
            scratch(&fixture).await.unwrap_err(),
            ScratchVerificationError::Records
        );
    }
}
