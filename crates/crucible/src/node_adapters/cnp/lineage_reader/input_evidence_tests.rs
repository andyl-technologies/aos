//! Exercises complete ACK closure credits without granting native source authority.

use super::*;
use crucible_node_contract::canonical;

fn object(bytes: &[u8]) -> Result<InputPayload, Box<dyn std::error::Error>> {
    Ok(InputPayload {
        reference: canonical::content_ref(bytes, "application/octet-stream")?,
        bytes: bytes.to_vec(),
    })
}

#[test]
fn full_closure_credit_precedes_every_copy() -> Result<(), Box<dyn std::error::Error>> {
    let leaf = object(b"original input")?;
    let ack = object(b"original native ACK")?;
    let objects = BTreeMap::from([
        (leaf.reference.clone(), leaf.clone()),
        (ack.reference.clone(), ack.clone()),
    ]);
    let rows = BTreeMap::from([
        (leaf.reference.clone(), Vec::new()),
        (ack.reference.clone(), vec![leaf.reference.clone()]),
    ]);
    let exact = leaf.bytes.len() + ack.bytes.len();
    let mut limits = OriginalInputLineageLimits {
        maximum_objects: 2,
        maximum_bytes: exact,
        maximum_edges: 1,
    };

    COPIES.with(|count| count.set(0));
    limits.maximum_bytes -= 1;
    assert!(copy_closure(&objects, &rows, &ack.reference, limits).is_err());
    assert_eq!(COPIES.with(|count| count.get()), 0);
    limits.maximum_bytes = exact;
    limits.maximum_objects = 1;
    assert!(copy_closure(&objects, &rows, &ack.reference, limits).is_err());
    limits.maximum_objects = 2;
    limits.maximum_edges = 0;
    assert!(copy_closure(&objects, &rows, &ack.reference, limits).is_err());
    assert_eq!(COPIES.with(|count| count.get()), 0);

    limits.maximum_edges = 1;
    let evidence =
        copy_closure(&objects, &rows, &ack.reference, limits).map_err(|error| error.reason)?;
    assert_eq!(COPIES.with(|count| count.get()), 2);
    assert_eq!(evidence.root, ack.reference);
    assert_eq!(evidence.objects.len(), 2);
    for (body, row) in evidence.objects.iter().zip(&evidence.rows) {
        assert_eq!(objects.get(&body.reference), Some(body));
        assert_eq!(rows.get(&row.object), Some(&row.dependencies));
    }
    Ok(())
}

#[test]
fn missing_rows_and_cycles_refuse_before_copies() -> Result<(), Box<dyn std::error::Error>> {
    let ack = object(b"original ACK")?;
    let leaf = object(b"original input")?;
    let mut objects = BTreeMap::from([
        (ack.reference.clone(), ack.clone()),
        (leaf.reference.clone(), leaf.clone()),
    ]);
    let mut rows = BTreeMap::from([(ack.reference.clone(), vec![leaf.reference.clone()])]);
    let limits = OriginalInputLineageLimits::default();

    COPIES.with(|count| count.set(0));
    assert!(copy_closure(&objects, &rows, &ack.reference, limits).is_err());
    rows.insert(leaf.reference.clone(), vec![ack.reference.clone()]);
    assert!(copy_closure(&objects, &rows, &ack.reference, limits).is_err());
    rows.insert(leaf.reference.clone(), Vec::new());
    objects.remove(&leaf.reference);
    assert!(copy_closure(&objects, &rows, &ack.reference, limits).is_err());
    assert_eq!(COPIES.with(|count| count.get()), 0);
    Ok(())
}
