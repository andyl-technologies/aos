//! Checks complete required catalog geometry without any native/class authority.

// crucible-lint: allow panic-shortcut -- These model-only controls use assertions as the failure oracle.
#![allow(clippy::unwrap_used)]

use super::*;

fn unit(reference: &ContentRef) -> QualificationUnit {
    QualificationUnit {
        implementation: reference.clone(),
        realization: reference.clone(),
        descriptors: reference.clone(),
        contracts: reference.clone(),
        port_profiles: reference.clone(),
        environment: reference.clone(),
        harness: reference.clone(),
        fixtures: reference.clone(),
        specification: reference.clone(),
    }
}

#[test]
fn original_catalog_cannot_be_reduced_or_substituted() {
    let (reference, ids) = requirement_catalog().unwrap();
    let unit = unit(&reference);
    let mut bodies = BTreeMap::new();

    assert!(normative_rows(&mut bodies, &unit, &reference, &ids[..381]).is_err());
    let foreign = canonical::content_ref(b"foreign-catalog", "text/plain").unwrap();
    assert!(normative_rows(&mut bodies, &unit, &foreign, &ids).is_err());
    assert!(bodies.is_empty());
}

#[test]
fn packet_observations_never_replace_required_original_obligations() {
    let (reference, ids) = requirement_catalog().unwrap();
    let mut bodies = BTreeMap::new();

    let (cases, requirements) =
        normative_rows(&mut bodies, &unit(&reference), &reference, &ids).unwrap();

    assert_eq!(cases.len(), 382);
    assert_eq!(requirements.len(), 382);
    for id in ids {
        let WitnessCriterion::Applicable { cases, criterion } = &requirements[id] else {
            panic!("no unproved applicability exclusion is installed");
        };
        assert!(cases.contains(&format!("unexecuted-original-{id}")));
        assert!(bodies.contains_key(criterion));
        if id == "CN-TEST-025" || id == "CN-TEST-038" {
            assert_eq!(cases.len(), 3);
            assert!(cases.contains(&BEFORE.to_owned()));
            assert!(cases.contains(&AFTER.to_owned()));
        } else {
            assert_eq!(cases.len(), 1);
        }
    }
}

#[test]
fn prospective_body_credit_refuses_before_canonical_retention() {
    let mut bodies = BTreeMap::new();
    let reference = canonical::content_ref(b"credit", "text/plain").unwrap();
    bodies.insert(reference, vec![0; 8 * 1024 * 1024]);

    let error = retain(&mut bodies, &"new");

    assert!(error.is_err());
    assert_eq!(bodies.len(), 1);
}
