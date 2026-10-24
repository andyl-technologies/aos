//! Exercises actual code authority, full rosters and retained-file revocation.
//!
//! The two positive controls use the same actual fixture recipe and compiled
//! batch/individual authenticators for ordinary same-binary comparison. They
//! perform file/ELF measurements and allocate fixture DATA, never native launch.

use super::*;
use crucible_engine::node_admission::{
    ConformanceAdmissionAuthority, EvidenceError, InstalledConformancePlan,
};
use crucible_node_format::{NodeBinding, SchemaRef, U64};

fn code_authority(
    scene: &Scene,
) -> (
    PacketCompleteGraphOwner,
    Rc<super::super::InstalledPacketCompleteCollectionAuthority>,
    InstalledConformancePlan,
) {
    let mut launches = authority::launches(scene);
    for (source, launch) in scene.roster.sources.iter().zip(&mut launches) {
        launch.complete_restore_selection = source.selected_complete_restore_selection().unwrap();
        launch.restore_input_emitter_selection =
            source.selected_restore_input_emitter_selection().unwrap();
        launch.controller_uid = U64::new(u64::from(rustix::process::geteuid().as_raw()));
    }
    let (owner, authority) = authority::try_collection_authority(scene, launches).unwrap();
    let plan = authority.collection_plan().unwrap();
    (owner, authority, plan)
}

fn batch(
    authority: &super::super::InstalledPacketCompleteCollectionAuthority,
    plan: &InstalledConformancePlan,
    binding: &NodeBinding,
    schemas: &[SchemaRef],
) -> Result<(), EvidenceError> {
    authority
        .authenticate_complete_archive_code_schema_roster(plan, binding, schemas)
        .unwrap()
}

#[test]
fn full_thirty_two_schema_code_rosters_use_bracketed_authentication() {
    let executable = std::env::current_exe().unwrap();
    let scene = native_roundtrip::scene(&executable);
    let (_owner, authority, plan) = code_authority(&scene);

    for source in &scene.roster.sources {
        let binding = &source.installation().binding;
        let schemas = &binding.compatibility.implementation.formats;
        assert_eq!(schemas.len(), 32);

        batch(&authority, &plan, binding, schemas).unwrap();
        batch(&authority, &plan, binding, schemas).unwrap();
    }
    authority.current().unwrap();
}

#[test]
fn full_thirty_two_schema_code_rosters_keep_the_individual_fallback() {
    let executable = std::env::current_exe().unwrap();
    let scene = native_roundtrip::scene(&executable);
    let (_owner, authority, _plan) = code_authority(&scene);

    for source in &scene.roster.sources {
        let schemas = &source
            .installation()
            .binding
            .compatibility
            .implementation
            .formats;
        assert_eq!(schemas.len(), 32);

        for schema in schemas {
            authority.authenticate_schema(schema).unwrap();
        }
    }
    authority.current().unwrap();
}

#[test]
fn code_schema_roster_binds_actual_plan_binding_and_sticky_current_files() {
    let scene = Scene::new();
    let (_owner, authority, plan) = code_authority(&scene);
    let (_other_owner, other_authority, other_plan) = code_authority(&scene);
    let first = &scene.roster.sources[0].installation().binding;
    let other = &scene.roster.sources[1].installation().binding;
    let schemas = &first.compatibility.implementation.formats;
    assert_ne!(schemas, &other.compatibility.implementation.formats);
    // Equal plan documents cannot replace the other actual owning issuer.
    assert_eq!(plan.evidence().plan_ref, other_plan.evidence().plan_ref);
    assert!(!Rc::ptr_eq(&authority, &other_authority));

    batch(&authority, &plan, first, schemas).unwrap();
    assert!(batch(&authority, &other_plan, first, schemas).is_err());
    assert!(batch(&authority, &plan, other, schemas).is_err());
    assert!(batch(&authority, &plan, first, &schemas[..schemas.len() - 1]).is_err());
    let mut changed_schema = schemas.to_vec();
    changed_schema[0].version += 1;
    assert!(batch(&authority, &plan, first, &changed_schema).is_err());

    // This file belongs only to Scene's private TempDir, not repository code
    // or either ELF. Drift between the actual begin/end authentications must
    // revoke the retained file owner; restoring bytes never renews it.
    let path = &scene.measurements.sources[0].path;
    let original = std::fs::read(path).unwrap();
    let mut changed = original.clone();
    changed[0] ^= 1;
    batch(&authority, &plan, first, schemas).unwrap();
    std::fs::write(path, &changed).unwrap();
    assert!(batch(&authority, &plan, first, schemas).is_err());
    std::fs::write(path, original).unwrap();
    assert!(batch(&authority, &plan, first, schemas).is_err());
}
