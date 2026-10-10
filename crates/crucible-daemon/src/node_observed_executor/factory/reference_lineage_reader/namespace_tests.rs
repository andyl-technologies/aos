//! Inspects fixed installed namespace predicates without native execution credit.
//!
//! These deliberate data mutations invoke the same installed authority used by
//! the live cohort. They do not supply original kernel custody or class claims.

use super::*;

#[test]
#[ignore = "requires the exact source-built installed reader manifest"]
fn installed_namespace_refuses_changed_original_axes_before_child() {
    let path = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_LINEAGE_READER_IMPLEMENTATION_MANIFEST")
            .expect("selected manifest required"),
    );
    let original =
        canonical::content_ref(include_bytes!("installed-fixture.json"), "application/json")
            .unwrap();
    let package = InstalledReaderPackage::load(&path, &original).unwrap();
    let profiles = ["disk", "link", "source"]
        .into_iter()
        .map(|node| {
            package
                .profile(
                    id(node),
                    id(&format!("{node}-owner")),
                    U64::new(1000),
                    U64::new(1_000_000_000),
                    node == "source",
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    let definition = graph::Definition::build(
        &profiles,
        b"source-inspection-data-only".to_vec(),
        BTreeMap::new(),
    );
    let installations = profiles
        .into_iter()
        .map(|profile| installed(package.clone(), profile, &definition))
        .collect::<Vec<_>>();
    let authority = ReaderExtensionPolicy::new(
        package.clone(),
        definition.world.clone(),
        installations
            .iter()
            .map(|installed| {
                (
                    installed.profile.descriptor.id.clone(),
                    (installed.binding.clone(), installed.policy.clone()),
                )
            })
            .collect(),
    )
    .unwrap();
    let selected = package.definition().regenerated();
    let declaration = selected.declaration();
    let selection = selected.selection();
    let semantics = authority.semantics().clone();

    authority
        .authenticate_namespace(declaration, selection)
        .unwrap();
    authority.authenticate_schema(&declaration.schema).unwrap();
    authority
        .authenticate_handler(declaration, selected.handler(), &semantics)
        .unwrap();
    for dependency in &declaration.dependencies {
        let ExtensionDependency::Core {
            identifier,
            version,
            definition,
        } = dependency
        else {
            panic!("closed source has only core prerequisites")
        };
        authority
            .authenticate_core_contract(identifier, *version, definition)
            .unwrap();
        assert!(
            authority
                .authenticate_core_contract(identifier, version + 1, definition)
                .is_err()
        );
    }

    let changed = canonical::content_ref(b"changed original role", "text/plain").unwrap();
    let mut changed_version = selection.clone();
    changed_version.semantic_version.major = U64::new(2);
    assert!(
        authority
            .authenticate_namespace(declaration, &changed_version)
            .is_err()
    );
    let mut changed_namespace = declaration.clone();
    changed_namespace.owner.publication_origin = changed.clone();
    assert!(
        authority
            .authenticate_namespace(&changed_namespace, selection)
            .is_err()
    );
    let mut changed_schema = declaration.schema.clone();
    changed_schema.definition = changed.clone();
    assert!(authority.authenticate_schema(&changed_schema).is_err());
    assert!(
        authority
            .authenticate_handler(declaration, &changed, &semantics)
            .is_err()
    );

    for axis in 0..8 {
        let mut altered = semantics.clone();
        match axis {
            0 => altered.class_contract = changed.clone(),
            1 => altered.facet_contract = changed.clone(),
            2 => altered.mode_contract = changed.clone(),
            3 => altered.port_contract = changed.clone(),
            4 => altered.timing_contract = changed.clone(),
            5 => altered.state_contract = changed.clone(),
            6 => altered.error_contract = changed.clone(),
            7 => altered.qualification_contract = changed.clone(),
            _ => unreachable!("fixed eight-axis population"),
        }
        assert!(
            authority
                .authenticate_handler(declaration, selected.handler(), &altered)
                .is_err()
        );
    }
    assert!(
        installations
            .iter()
            .all(|installed| installed.authenticate_enrolled().is_err())
    );
    assert!(InstalledReaderPackage::load(&path, &changed).is_err());
}
