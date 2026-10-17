//! Checks frozen semantic arithmetic, source order and prelaunch scope refusal.

use super::*;

fn peers() -> Result<[TypedReaderProgrammePeer; 3], ProviderError> {
    fn peer(name: &str) -> Result<TypedReaderProgrammePeer, ProviderError> {
        Ok(TypedReaderProgrammePeer {
            node: Id::new(name)?,
            owner: Id::new(format!("{name}/owner"))?,
            incarnation: Id::new(format!("{name}/incarnation"))?,
        })
    }
    Ok([peer("producer-a")?, peer("producer-b")?, peer("consumer")?])
}

#[test]
fn fixed_original_programme_retains_four_deliveries_and_cumulative_modulo_state()
-> Result<(), ProviderError> {
    let package = canonical::content_ref(b"inert source identity", "application/json")?;
    let programme = TypedReaderProgramme::new(package, peers()?)?;
    let consumer = Id::new("consumer")?;

    assert_eq!(programme.windows().len(), 9);
    assert_eq!(PRODUCER_BYTES.len(), 38);
    assert_eq!(
        programme
            .window(&consumer, U64::new(0))?
            .output
            .checksum
            .get(),
        0
    );
    let first = programme.window(&consumer, U64::new(1))?;
    let second = programme.window(&consumer, U64::new(2))?;
    // These independent integer constants were computed from the frozen 38-byte
    // canonical source payload, not from any observed native result.
    assert_eq!(first.output.bytes_processed.get(), 76);
    assert_eq!(first.output.checksum.get(), 13_406_937_834_436_471_122);
    assert_eq!(second.checksum_before, first.output.checksum);
    assert_eq!(second.output.checksum.get(), 2_483_074_512_356_223_652);
    assert_eq!(first.producers.len() + second.producers.len(), 4);
    programme.reference().verify(programme.bytes())?;
    Ok(())
}

#[test]
fn foreign_duplicate_or_reversed_producer_identity_refuses_before_original_enrollment()
-> Result<(), ProviderError> {
    let package = canonical::content_ref(b"inert source identity", "application/json")?;
    let mut duplicated = peers()?;
    duplicated[1].owner = duplicated[0].owner.clone();
    assert!(TypedReaderProgramme::new(package.clone(), duplicated).is_err());

    let mut reversed = peers()?;
    reversed.swap(0, 1);
    assert!(TypedReaderProgramme::new(package, reversed).is_err());
    Ok(())
}

#[test]
fn same_extent_changed_payload_has_a_different_independent_checksum() {
    let mut altered = PRODUCER_BYTES.to_vec();
    altered[1] = b'x';
    assert_ne!(
        rolling_checksum(0, &altered),
        rolling_checksum(0, PRODUCER_BYTES)
    );
}

#[test]
fn complete_population_keeps_every_obligation_unexecuted_after_window_collection()
-> Result<(), ProviderError> {
    let object = canonical::content_ref(b"inert fixture axis", "application/json")?;
    let programme = TypedReaderProgramme::new(object.clone(), peers()?)?;
    let unit = QualificationUnit {
        implementation: object.clone(),
        realization: object.clone(),
        descriptors: object.clone(),
        contracts: object.clone(),
        port_profiles: object.clone(),
        environment: object.clone(),
        harness: object.clone(),
        fixtures: programme.reference().clone(),
        specification: normative_specification().map_err(|_| invalid())?.0,
    };
    let plan = programme.witness_plan(unit.clone(), object.clone())?;
    assert_eq!(plan.requirements.len(), 382);
    assert_eq!(plan.cases.len(), 391);
    for (requirement, criterion) in &plan.requirements {
        let WitnessCriterion::Applicable { cases, .. } = criterion else {
            return Err(invalid());
        };
        assert!(cases.contains(&format!("unexecuted/{requirement}")));
    }
    let mut changed = unit;
    changed.fixtures = object.clone();
    assert!(programme.witness_plan(changed, object).is_err());
    Ok(())
}

#[test]
fn original_stage_ack_requires_every_expected_reachable_body_and_rejects_extras()
-> Result<(), crucible_node_provider::ProviderError> {
    use super::super::programme_completion::require_complete_input_closure;
    use crucible::node_contract::{OriginalInputEvidence, OriginalLineageRow};
    use crucible::node_scheduling::InputPayload;
    use std::collections::BTreeMap;
    let root = canonical::content_ref(b"stage", "application/json")?;
    let child = canonical::content_ref(b"input", "application/json")?;
    let foreign = canonical::content_ref(b"foreign", "application/json")?;
    let dependencies = vec![child.clone()];
    let empty: Vec<ContentRef> = Vec::new();
    let expected = BTreeMap::from([
        (&root, (b"stage".as_slice(), dependencies.as_slice())),
        (&child, (b"input".as_slice(), empty.as_slice())),
    ]);
    let mut objects = vec![
        InputPayload {
            reference: root.clone(),
            bytes: b"stage".to_vec(),
        },
        InputPayload {
            reference: child.clone(),
            bytes: b"input".to_vec(),
        },
    ];
    objects.sort_by(|a, b| a.reference.cmp(&b.reference));
    let rows = objects
        .iter()
        .map(|object| OriginalLineageRow {
            object: object.reference.clone(),
            dependencies: if object.reference == root {
                dependencies.clone()
            } else {
                Vec::new()
            },
        })
        .collect();
    let mut evidence = OriginalInputEvidence {
        root: root.clone(),
        objects,
        rows,
    };
    assert!(require_complete_input_closure(&root, &expected, &evidence).is_ok());
    evidence.objects.retain(|object| object.reference != child);
    assert!(require_complete_input_closure(&root, &expected, &evidence).is_err());
    evidence.objects.push(InputPayload {
        reference: foreign,
        bytes: b"foreign".to_vec(),
    });
    assert!(require_complete_input_closure(&root, &expected, &evidence).is_err());
    Ok(())
}
