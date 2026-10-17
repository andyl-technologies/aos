//! Checks closed geometry without installing a source or constructing authority.

use super::*;

// Canonical body and document encoding failures keep their original typed errors.
#[derive(Debug, thiserror::Error)]
enum GeometryTestError {
    #[error(transparent)]
    Contract(crucible_node_contract::ContractError),
    #[error(transparent)]
    Json(serde_json::Error),
}

fn bodies() -> Result<Vec<InputPayload>, GeometryTestError> {
    let mut objects: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
        .into_iter()
        .map(|bytes| {
            Ok(InputPayload {
                reference: crucible_node_contract::canonical::content_ref(
                    bytes,
                    "application/json",
                )
                .map_err(GeometryTestError::Contract)?,
                bytes: bytes.to_vec(),
            })
        })
        .collect::<Result<Vec<_>, GeometryTestError>>()?;
    objects.sort_by(|left, right| left.reference.cmp(&right.reference));
    Ok(objects)
}

#[test]
fn complete_data_rows_refuse_cycle_missing_dependency_and_orphan() -> Result<(), GeometryTestError>
{
    let objects = bodies()?;
    let root = &objects[0].reference;
    let mut rows = vec![
        OriginalLineageRow {
            object: root.clone(),
            dependencies: vec![objects[1].reference.clone()],
        },
        OriginalLineageRow {
            object: objects[1].reference.clone(),
            dependencies: Vec::new(),
        },
    ];

    assert_eq!(validate_rows(root, &objects, &rows), Ok(()));
    rows[1].dependencies.push(root.clone());
    assert_eq!(
        validate_rows(root, &objects, &rows),
        Err(RuntimeError::InvalidReceipt),
    );

    rows[1].dependencies.clear();
    rows[0].dependencies.clear();
    assert_eq!(
        validate_rows(root, &objects, &rows),
        Err(RuntimeError::InvalidReceipt),
    );
    let foreign = crucible_node_contract::canonical::content_ref(b"absent", "application/json")
        .map_err(GeometryTestError::Contract)?;
    rows[0].dependencies.push(foreign);
    assert_eq!(
        validate_rows(root, &objects, &rows),
        Err(RuntimeError::InvalidReceipt),
    );
    Ok(())
}

#[test]
fn aggregate_edge_and_object_credit_refuses_before_closed_body_decode()
-> Result<(), GeometryTestError> {
    // These are intentionally not valid typed CFs. ResourceLimit establishes
    // that the nonretaining pass refused before allocating decoded native rows.
    let objects = serde_json::to_vec(&serde_json::json!({
        "native_evidence":{"objects":vec![();MAXIMUM_INPUT_OBJECTS+1]},
    }))
    .map_err(GeometryTestError::Json)?;
    assert!(matches!(
        parse_staging(&objects),
        Err(RuntimeError::ResourceLimit)
    ));

    let edges = serde_json::to_vec(&serde_json::json!({
        "native_evidence":{"rows":[
            {"dependencies":vec![();MAXIMUM_EDGES/2+1]},
            {"dependencies":vec![();MAXIMUM_EDGES/2+1]},
        ]},
    }))
    .map_err(GeometryTestError::Json)?;
    assert!(matches!(
        parse_staging(&edges),
        Err(RuntimeError::ResourceLimit)
    ));
    Ok(())
}

#[test]
fn source_staging_codec_refuses_unknown_and_duplicate_top_fields() -> Result<(), GeometryTestError>
{
    let objects = bodies()?;
    let object = &objects[0];
    let document = serde_json::json!({
        "schema":"crucible.original-staged-input-witness.v1",
        "input":null,"provenance":null,"publications":null,
        "acknowledgement":null,"coordinator_commit":null,"committed":true,
        "native_evidence":{
            "root":object.reference,"objects":[object],
            "rows":[{"object":object.reference,"dependencies":[]}],
        },
    });
    let bytes = serde_json::to_vec(&document).map_err(GeometryTestError::Json)?;
    assert!(parse_staging(&bytes).is_ok());

    let mut foreign = document;
    foreign["extra_role"] = serde_json::json!({"verified":true});
    assert!(matches!(
        parse_staging(&serde_json::to_vec(&foreign).map_err(GeometryTestError::Json)?),
        Err(RuntimeError::InvalidReceipt),
    ));
    let duplicate = [b"{\"schema\":\"other\",".as_slice(), &bytes[1..]].concat();
    assert!(matches!(
        parse_staging(&duplicate),
        Err(RuntimeError::InvalidReceipt)
    ));
    Ok(())
}
