//! Pure fixed-size tree decoding and legacy malformed-priority witnesses.
//!
//! This private prototype borrows canonical bytes. It neither reads a provider
//! nor accepts an operation result before the provider's actual checked EOF.

use super::*;
use crate::ram::canonical_tree::{preflight, read_tree_canonical as fixed_tree};
use crate::ram::codec::{TREE_SCHEMA, TreeNode, TreeRef, validate_tree};

fn legacy_tree(bytes: &[u8], expected: TreeRef) -> Result<TreeNode, RamStoreError> {
    preflight(bytes, expected)?;
    let envelope =
        crate::content_envelope::ContentEnvelope::from_canonical_bytes_with_child_limit(bytes, 2)?;
    if envelope.schema_version() != 1 {
        return Err(RamStoreError::Invalid("RAM envelope schema"));
    }
    validate_tree(&envelope, expected)
}

fn assert_same_result(
    actual: Result<TreeNode, RamStoreError>,
    expected: Result<TreeNode, RamStoreError>,
) {
    match (actual, expected) {
        (Ok(TreeNode::Padding), Ok(TreeNode::Padding)) => {}
        (
            Ok(TreeNode::Leaf { page, digest }),
            Ok(TreeNode::Leaf {
                page: old_page,
                digest: old_digest,
            }),
        ) => assert_eq!((page, digest), (old_page, old_digest)),
        (
            Ok(TreeNode::Branch { left, right }),
            Ok(TreeNode::Branch {
                left: old_left,
                right: old_right,
            }),
        ) => assert_eq!((left, right), (old_left, old_right)),
        (Err(RamStoreError::Envelope(actual)), Err(RamStoreError::Envelope(expected))) => {
            assert_eq!(actual, expected);
        }
        (Err(RamStoreError::Invalid(actual)), Err(RamStoreError::Invalid(expected))) => {
            assert_eq!(actual, expected);
        }
        (Err(actual), Err(expected)) => assert_eq!(format!("{actual:?}"), format!("{expected:?}")),
        (actual, expected) => panic!(
            "tree result mismatch: actual={} expected={}",
            actual.is_ok(),
            expected.is_ok()
        ),
    }
}

#[test]
fn fixed_parser_matches_actual_leaf_branch_and_padding_records() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(3 * 4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let operation = original.child().unwrap();
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &operation, &mut boundary).unwrap();
    let mut stack = vec![root.regions[0]];
    let mut kinds = [false; 3];
    while let Some(expected) = stack.pop() {
        let envelope = store.read_envelope(expected.id, &mut work).unwrap();
        let scope = operation.enter();
        let bytes = envelope.canonical_bytes();
        let node = fixed_tree(&bytes, expected).unwrap();
        match node {
            TreeNode::Padding => kinds[0] = true,
            TreeNode::Leaf { .. } => kinds[1] = true,
            TreeNode::Branch { left, right } => {
                kinds[2] = true;
                stack.extend([left, right]);
            }
        }
        assert_same_result(fixed_tree(&bytes, expected), legacy_tree(&bytes, expected));
        drop(scope);
    }
    assert_eq!(kinds, [true; 3]);
}

fn frame(
    schema: &[u8],
    version: u32,
    children: &[(&[u8], &[u8])],
    body: &[u8],
    declared_body: u64,
    suffix: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CRUCOBJE");
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(schema.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(schema);
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(children.len()).unwrap().to_be_bytes());
    for (role, id) in children {
        bytes.extend_from_slice(&u16::try_from(role.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(role);
        bytes.extend_from_slice(&u16::try_from(id.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(id);
    }
    bytes.extend_from_slice(&declared_body.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(suffix);
    bytes
}

#[test]
fn fixed_parser_preserves_legacy_malformed_priority_under_finite_originals() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let retention = Retention::default();
    let original = fixture_original(&store);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &retention,
            &original,
            &mut || Ok(()),
        )
        .unwrap();
    let reference = root.regions[0];
    let mut boundary = || Ok(());
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    let input = store.read_envelope(reference.id, &mut work).unwrap();
    drop(work);
    let setup = original.enter();
    let valid = input.canonical_bytes();
    let id = input.children().first().unwrap().id().encode();
    let body = input.body();
    let body_length = body.len() as u64;
    let mut invalid_kind = body.to_vec();
    invalid_kind[0] = 3;
    invalid_kind.push(0);
    let child = [(b"page".as_slice(), id.as_bytes())];
    let schema = TREE_SCHEMA.as_bytes();

    let cases = [
        (
            "schema check after body truncation",
            frame(b"?", 1, &child, body, u64::MAX, &[]),
        ),
        (
            "schema check after trailing bytes",
            frame(b"?", 0, &child, body, body_length, b"x"),
        ),
        (
            "schema identifier before zero version",
            frame(b"?", 0, &child, body, body_length, &[]),
        ),
        (
            "zero version after complete framing",
            frame(schema, 0, &child, body, body_length, &[]),
        ),
        (
            "invalid UTF8 schema before body",
            frame(&[0xff], 1, &child, body, u64::MAX, &[]),
        ),
        (
            "invalid ID before invalid role",
            frame(schema, 1, &[(b"?", b"x")], body, u64::MAX, &[]),
        ),
        (
            "invalid role before truncated body",
            frame(schema, 1, &[(b"?", id.as_bytes())], body, u64::MAX, &[]),
        ),
        (
            "invalid UTF8 role before ID",
            frame(schema, 1, &[(&[0xff], b"x")], body, body_length, &[]),
        ),
        (
            "duplicate children before body",
            frame(schema, 1, &[child[0], child[0]], body, u64::MAX, &[]),
        ),
        (
            "unsorted children before body",
            frame(
                schema,
                1,
                &[(b"right", id.as_bytes()), (b"left", id.as_bytes())],
                body,
                u64::MAX,
                &[],
            ),
        ),
        (
            "child bound before table or body",
            frame(
                schema,
                1,
                &[child[0], child[0], child[0]],
                body,
                u64::MAX,
                &[],
            ),
        ),
        (
            "oversized schema length",
            frame(&[b'a'; 129], 1, &child, body, body_length, &[]),
        ),
        (
            "oversized role length",
            frame(
                schema,
                1,
                &[(&[b'a'; 257], id.as_bytes())],
                body,
                body_length,
                &[],
            ),
        ),
        (
            "oversized ID length",
            frame(
                schema,
                1,
                &[(b"page", &[b'a'; 161])],
                body,
                body_length,
                &[],
            ),
        ),
        (
            "RAM version before tree schema",
            frame(b"valid-other-schema", 2, &child, body, body_length, &[]),
        ),
        (
            "missing children with trailing node body",
            frame(schema, 1, &[], body, body_length, &[]),
        ),
        (
            "invalid tree kind before node trailing bytes",
            frame(
                schema,
                1,
                &child,
                &invalid_kind,
                invalid_kind.len() as u64,
                &[],
            ),
        ),
    ];
    drop(setup);

    let compare = |bytes: &[u8]| {
        // Only the actual authenticated ID is changed: malformed framing is
        // examined rather than rejected first as an unrelated digest mismatch.
        let expected = TreeRef {
            id: ContentId::for_bytes(ObjectKind::RamTree, 1, bytes),
            ..reference
        };
        let operation = original.child().unwrap();
        let scope = operation.enter();
        assert_same_result(fixed_tree(bytes, expected), legacy_tree(bytes, expected));
        drop(scope);
        drop(operation);
        original.verify_live().unwrap();
    };

    for (name, bytes) in &cases {
        eprintln!("malformed_priority={name}");
        compare(bytes);
    }
    for end in 0..valid.len() {
        compare(&valid[..end]);
    }
    for offset in 0..valid.len() {
        let mut bytes = valid.clone();
        bytes[offset] ^= 0x80;
        compare(&bytes);
    }
    compare(&valid);
    eprintln!(
        "explicit_priorities={} truncated_prefixes={} single_byte_mutations={} accepted_control=1",
        cases.len(),
        valid.len(),
        valid.len()
    );
}

#[test]
fn shared_continuation_failure_exceeds_the_existing_validation_extent() {
    use std::alloc::Layout;
    use std::convert::Infallible;
    use std::sync::atomic::AtomicUsize;

    struct ContinuationBody {
        first: RamFailureCause<RamStoreError>,
        returned: StoreError,
        credit: crate::owned_decode::DecodeScratch,
    }

    let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<ContinuationBody>())
        .unwrap();
    let proposed = u64::try_from(layout.pad_to_align().size()).unwrap();
    let existing = PreparedRamFailure::<Infallible>::allocation_bytes().unwrap();
    // This is the preserved negative design witness, not a larger reservation.
    assert!(proposed > existing);
    eprintln!(
        "continuation_body={} continuation_align={} continuation_arc={} existing_validation_arc={} ram_error={} store_error={} scratch={} first_handle={}",
        std::mem::size_of::<ContinuationBody>(),
        std::mem::align_of::<ContinuationBody>(),
        proposed,
        existing,
        std::mem::size_of::<RamStoreError>(),
        std::mem::size_of::<StoreError>(),
        std::mem::size_of::<crate::owned_decode::DecodeScratch>(),
        std::mem::size_of::<RamFailureCause<RamStoreError>>(),
    );

    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path(), RamStoreLimits::default());
    let original = fixture_original(&store);
    let first = PreparedRamFailure::new(&original).unwrap().retain(
        Some(RamStoreError::Canceled),
        StoreError::Unavailable.into(),
    );
    let credit = original.reserve_scratch_bytes(existing).unwrap();
    let body = ContinuationBody {
        first,
        returned: StoreError::Quota,
        credit,
    };
    assert!(matches!(
        body.first.first_boundary(),
        Some(RamStoreError::Canceled)
    ));
    assert!(matches!(
        body.first.storage_failure(),
        RamStoreError::Store(StoreError::Unavailable)
    ));
    assert!(matches!(body.returned, StoreError::Quota));

    // The modeled outer body stays on the stack; this probe does not claim an
    // allocated continuation control or its terminal deallocation ordering.
    let ContinuationBody {
        first,
        returned,
        credit,
    } = body;
    drop(first);
    drop(returned);
    drop(credit);
    original.verify_live().unwrap();
}
