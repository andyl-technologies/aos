//! Original-body closure tests; these do not qualify a native source.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn repeated_original_body_is_retained_once_and_reopens_exactly() -> TestResult {
    let body = vec![0x5c; 65_537];
    let mut store = EvidenceDag::new(32, 1 << 20);
    let leaf = store
        .add(&body, "application/octet-stream", Vec::new())
        .map_err(|error| error.reason)?;
    let mut branches = Vec::new();
    for number in 0..8 {
        let bytes = format!("original decision {number}");
        branches.push(
            store
                .add(bytes.as_bytes(), "text/plain", vec![leaf.clone()])
                .map_err(|error| error.reason)?,
        );
        store
            .insert(leaf.clone(), &body, Vec::new())
            .map_err(|error| error.reason)?;
    }
    let root = store
        .add(b"complete original history", "text/plain", branches)
        .map_err(|error| error.reason)?;
    let bytes = store
        .encode(vec![root.clone()])
        .map_err(|error| error.reason)?;
    let (reopened, roots) =
        EvidenceDag::decode(&bytes, 32, 1 << 20).map_err(|error| error.reason)?;

    assert_eq!(reopened.objects().count(), 10);
    assert_eq!(reopened.body(&leaf).map_err(|error| error.reason)?, body);
    assert_eq!(roots, [root]);
    assert_eq!(reopened.encode(roots).map_err(|error| error.reason)?, bytes);
    assert!(bytes.len() < 150_000);
    Ok(())
}

#[test]
fn missing_dependency_extra_body_and_cycles_refuse_complete_closure() -> TestResult {
    let mut store = EvidenceDag::new(8, 4096);
    let absent = canonical::content_ref(b"absent original", "text/plain")?;
    let root = store
        .add(b"original root", "text/plain", vec![absent.clone()])
        .map_err(|error| error.reason)?;
    assert!(store.encode(vec![root.clone()]).is_err());

    store
        .insert(absent.clone(), b"absent original", vec![root.clone()])
        .map_err(|error| error.reason)?;
    assert!(store.encode(vec![root]).is_err());

    let mut store = EvidenceDag::new(8, 4096);
    let root = store
        .add(b"closed original", "text/plain", Vec::new())
        .map_err(|error| error.reason)?;
    store
        .add(b"unbound substitute", "text/plain", Vec::new())
        .map_err(|error| error.reason)?;
    assert!(store.encode(vec![root]).is_err());
    Ok(())
}

#[test]
fn original_metadata_edges_and_credit_cannot_be_changed() -> TestResult {
    let mut store = EvidenceDag::new(2, 32);
    let original = store
        .add(b"original", "text/plain", Vec::new())
        .map_err(|error| error.reason)?;
    let absent = canonical::content_ref(b"different", "text/plain")?;

    assert!(
        store
            .insert(original.clone(), b"changed", Vec::new())
            .is_err()
    );
    assert!(
        store
            .insert(original.clone(), b"original", vec![absent])
            .is_err()
    );
    let alias = canonical::content_ref(b"original", "application/octet-stream")?;
    assert!(store.insert(alias, b"original", Vec::new()).is_err());
    assert!(
        store
            .add(&[1; 33], "application/octet-stream", Vec::new())
            .is_err()
    );
    assert_eq!(store.objects().count(), 1);
    assert_eq!(
        store.body(&original).map_err(|error| error.reason)?,
        b"original"
    );
    // Raw-body credit alone is insufficient: the full wire object must also
    // fit before a caller can publish a complete closure.
    assert!(store.encode(vec![original]).is_err());
    Ok(())
}
