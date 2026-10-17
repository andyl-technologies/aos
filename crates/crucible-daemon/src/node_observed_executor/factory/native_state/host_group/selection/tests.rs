//! Data-only exact source-selection controls, without any native authority.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- fixture invariants and exact source refusal intentionally panic.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::super::super::super::{InstalledGem5Isa, InstalledScriptedSourceProfile};
use super::*;
use crucible_node_contract::{Id, U64, canonical};

fn fixture(block_name: &str, source_name: &str) -> Vec<InstalledNodeSelection> {
    let id = |name: &str| Id::new(name).unwrap();
    let mut group = vec![
        InstalledNodeSelection {
            node: id(block_name),
            owner: id(&format!("owner/{block_name}")),
            kind: InstalledNodeKind::HostIo {
                profile: InstalledHostIoProfile::Block {
                    base_image: canonical::content_ref(&[0; 512], "application/octet-stream")
                        .unwrap(),
                    source_node: 7,
                    read_ns: U64::new(1),
                    write_ns: U64::new(1),
                    flush_ns: U64::new(1),
                    get_length_ns: U64::new(1),
                    per_byte_ns: U64::new(1),
                },
            },
        },
        InstalledNodeSelection {
            node: id(source_name),
            owner: id(&format!("owner/{source_name}")),
            kind: InstalledNodeKind::HostScripted {
                profile: InstalledScriptedSourceProfile {
                    script: canonical::content_ref(
                        b"data-only script identity",
                        "application/octet-stream",
                    )
                    .unwrap(),
                    consumer: id(block_name),
                },
            },
        },
    ];
    group.sort_by(|left, right| left.node.cmp(&right.node));
    let mut selections = vec![
        InstalledNodeSelection {
            node: id("clock"),
            owner: id("owner/clock"),
            kind: InstalledNodeKind::HostClock,
        },
        InstalledNodeSelection {
            node: id("cpu"),
            owner: id("owner/cpu"),
            kind: InstalledNodeKind::Gem5Closed {
                isa: InstalledGem5Isa::X86_64,
            },
        },
    ];
    selections.extend(group);
    selections
}

#[test]
fn authored_names_and_order_are_independent_of_one_recipe() {
    for (block, source) in [("disk", "source"), ("storage", "requester")] {
        let selections = fixture(block, source);
        let group = IndependentGroupSelection::new(&selections).unwrap();

        assert_eq!(group.block.node.as_str(), block);
        assert_eq!(group.source.node.as_str(), source);
        assert_eq!(group.selections.len(), 2);
        assert!(selected(&selections));
    }
}

#[test]
fn cross_cpu_route_and_aliased_owner_refuse_before_resources() {
    let mut changed = fixture("disk", "source");
    let source = changed
        .iter_mut()
        .find(|selected| selected.node.as_str() == "source")
        .unwrap();
    let InstalledNodeKind::HostScripted { profile } = &mut source.kind else {
        panic!("original source fixture")
    };
    profile.consumer = Id::new("cpu").unwrap();
    assert!(IndependentGroupSelection::new(&changed).is_err());

    let mut changed = fixture("disk", "source");
    changed[2].owner = changed[1].owner.clone();
    assert!(IndependentGroupSelection::new(&changed).is_err());
}

#[test]
fn preserving_native_and_incomplete_group_refuse() {
    let mut changed = fixture("disk", "source");
    changed[1].kind = InstalledNodeKind::Gem5ClosedPreserving {
        isa: InstalledGem5Isa::X86_64,
    };
    assert!(IndependentGroupSelection::new(&changed).is_err());

    let changed = fixture("disk", "source");
    assert!(IndependentGroupSelection::new(&changed[..3]).is_err());
    assert!(!selected(&changed[..2]));
}
