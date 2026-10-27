//! Lower-bound selection over actual authenticated Packed leaf and branch pages.
//!
//! Pure codec fixtures own their test allocations; they issue no runtime credit.

use super::*;

fn key(number: u8) -> Key {
    Key::pack(PackId([number; 32]))
}

fn page(count: usize, branch: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PAGE_BYTES);
    begin_node(&mut bytes, u8::from(branch));
    for slot in 0..count {
        bytes.extend_from_slice(&key((slot * 3 + 3) as u8).0);
        if branch {
            PageReference {
                offset: slot as u64 * PAGE_BYTES as u64,
                length: (PAGE_HEADER_BYTES + LEAF_ROW_BYTES + 32) as u32,
                digest: [slot as u8; 32],
                records: 1,
                height: 0,
            }
            .append(&mut bytes);
        } else {
            bytes.extend_from_slice(
                &Value::pack(PackRecord {
                    physical_bytes: 1,
                    objects: 1,
                    logical_bytes: 1,
                })
                .0,
            );
        }
    }
    finish_node(&mut bytes, count, count as u64).expect("bounded canonical page");
    bytes
}

fn linear_position(node: &Node<'_>, key: Key) -> Result<usize, StoreError> {
    for slot in 0..node.count {
        if node.key(slot)? >= key {
            return Ok(slot);
        }
    }
    Ok(node.count)
}

#[test]
fn leaves_match_the_previous_linear_position_at_every_boundary() {
    for count in 0..=MAX_ROWS {
        let bytes = page(count, false);
        let node = Node::parse(&bytes, true).expect("authenticated canonical leaf");
        for number in 0..=u8::MAX {
            let query = key(number);
            assert_eq!(
                node.position(query).expect("bounded lower bound"),
                linear_position(&node, query).expect("previous linear reference"),
                "leaf count {count}, query {number}"
            );
        }
        assert_eq!(
            node.position(Key::object(ContentId::for_bytes(
                ObjectKind::Trace,
                1,
                b"earlier kind"
            )))
            .expect("earlier kind"),
            0
        );
    }
}

#[test]
fn branches_match_the_previous_child_selection_at_every_boundary() {
    for count in 2..=MAX_ROWS {
        let bytes = page(count, true);
        let node = Node::parse(&bytes, true).expect("authenticated canonical branch");
        for number in 0..=u8::MAX {
            let query = key(number);
            assert_eq!(
                node.position(query).expect("bounded child selection"),
                linear_position(&node, query).expect("previous child reference"),
                "branch count {count}, query {number}"
            );
        }
    }
}

#[test]
fn actual_lower_bound_reads_at_most_the_logarithmic_number_of_keys() {
    for count in 0..=MAX_ROWS {
        let bytes = page(count, false);
        let node = Node::parse(&bytes, true).expect("authenticated canonical leaf");
        let bound = (usize::BITS - count.leading_zeros()) as usize;
        for number in 0..=u8::MAX {
            let query = key(number);
            let mut reads = 0;
            let position = lower_bound(node.count, query, |slot| {
                reads += 1;
                node.key(slot)
            })
            .expect("the production search over the actual parsed node");
            assert_eq!(
                position,
                node.position(query).expect("actual node selection")
            );
            assert!(
                reads <= bound,
                "count {count}, query {number}: {reads} > {bound}"
            );
        }
    }
}

#[test]
fn malformed_order_is_still_rejected_before_any_selection() {
    let mut bytes = page(2, false);
    let first = bytes[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + LEAF_ROW_BYTES].to_vec();
    let second =
        bytes[PAGE_HEADER_BYTES + LEAF_ROW_BYTES..PAGE_HEADER_BYTES + 2 * LEAF_ROW_BYTES].to_vec();
    bytes[PAGE_HEADER_BYTES..PAGE_HEADER_BYTES + LEAF_ROW_BYTES].copy_from_slice(&second);
    bytes[PAGE_HEADER_BYTES + LEAF_ROW_BYTES..PAGE_HEADER_BYTES + 2 * LEAF_ROW_BYTES]
        .copy_from_slice(&first);
    bytes.truncate(bytes.len() - 32);
    append_checksum(PAGE_DOMAIN, &mut bytes);
    assert!(matches!(
        Node::parse(&bytes, true),
        Err(StoreError::Incompatible)
    ));
}
