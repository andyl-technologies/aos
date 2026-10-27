//! Checks bounded fairness and changing candidate inventories using inert format data.

use super::*;
use terrane_format::gc::retirement::RecordPointer;

fn owner(id: u8) -> PermanentBurnOwner {
    PermanentBurnOwner {
        pack: [id; 16],
        selection: PermanentOwnerSelection::Permanent(RecordPointer {
            key: format!("candidate-owner-{id}"),
            digest: [id; 32],
        }),
    }
}

fn exclusion(id: u8) -> PackExclusion {
    PackExclusion {
        pack_id: [id; 16],
        cycle: 1,
        epoch: 2,
    }
}

fn family(hint: &MaintenanceHint) -> (bool, u8) {
    match hint {
        MaintenanceHint::PermanentOwner { pack, .. }
        | MaintenanceHint::CopiedRetirement { pack } => (false, pack.as_bytes()[0]),
        MaintenanceHint::ExcludedPack(row) => (true, row.pack_id[0]),
    }
}

#[test]
fn single_hint_calls_alternate_families_and_revisit_every_stable_candidate() {
    let owners = [owner(2), owner(4), owner(6)];
    let exclusions = [exclusion(1), exclusion(3)];
    let mut cursor = MaintenanceCursor::default();
    let sequence: Vec<_> = (0..12)
        .map(|_| {
            let hints = select(&owners, &exclusions, &[], &mut cursor, 1);
            assert_eq!(hints.len(), 1);
            family(&hints[0])
        })
        .collect();

    assert_eq!(
        sequence,
        [
            (false, 2),
            (true, 1),
            (false, 4),
            (true, 3),
            (false, 6),
            (true, 1),
            (false, 2),
            (true, 3),
            (false, 4),
            (true, 1),
            (false, 6),
            (true, 3),
        ]
    );
}

#[test]
fn one_batch_contains_no_duplicates_and_burns_are_not_restoration_candidates() {
    let mut owners = [owner(2), owner(4)];
    owners[1].selection = PermanentOwnerSelection::CopiedVisibility;
    let exclusions = [exclusion(1), exclusion(2), exclusion(4)];
    let mut cursor = MaintenanceCursor::default();

    let hints = select(
        &owners,
        &exclusions,
        &[[2; 16], [4; 16]],
        &mut cursor,
        MAX_HINTS,
    );

    assert_eq!(hints.len(), 3);
    assert_eq!(
        hints.iter().map(family).collect::<Vec<_>>(),
        [(false, 2), (true, 1), (false, 4)]
    );
    assert!(matches!(hints[2], MaintenanceHint::CopiedRetirement { .. }));
    assert!(select(&[], &[], &[], &mut cursor, MAX_HINTS).is_empty());
}

#[test]
fn removed_positions_and_new_lower_keys_do_not_starve_remaining_work() {
    let mut cursor = MaintenanceCursor::default();
    assert_eq!(
        family(&select(&[owner(5)], &[], &[], &mut cursor, 1)[0]),
        (false, 5)
    );

    let owners = [owner(1), owner(7)];
    let first = select(&owners, &[], &[], &mut cursor, 1);
    let second = select(&owners, &[], &[], &mut cursor, 1);
    let third = select(&owners, &[], &[], &mut cursor, 1);

    assert_eq!(family(&first[0]), (false, 7));
    assert_eq!(family(&second[0]), (false, 1));
    assert_eq!(family(&third[0]), (false, 7));
}

#[test]
fn a_large_family_cannot_starve_a_small_family_across_batch_boundaries() {
    let owners: Vec<_> = (1..=200).map(owner).collect();
    let exclusions = [exclusion(250)];
    let mut cursor = MaintenanceCursor::default();
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..100 {
        let hints = select(&owners, &exclusions, &[], &mut cursor, 3);
        assert_eq!(hints.len(), 3);
        assert_eq!(hints.iter().filter(|hint| family(hint).0).count(), 1);
        for hint in &hints {
            seen.insert(family(hint));
        }
    }

    assert_eq!(seen.len(), 201);
}
