//! Exercises missing-policy and finite-credit refusal before source effects.

use std::cell::Cell;

use crucible::node_admission::{
    EvidenceError, ExtensionInstallationAuthority, ExtensionRegistryLimits,
    ExtensionSemanticContract,
};
use crucible_node_contract::{ExtensionDeclaration, ExtensionSelection, SchemaRef, canonical};

use super::*;

#[derive(Default)]
struct RefusingInstallation(Cell<usize>);

impl RefusingInstallation {
    fn refuse<T>(&self) -> Result<T, EvidenceError> {
        self.0.set(self.0.get() + 1);
        Err(EvidenceError {
            message: "inert authority refuses all publications".into(),
        })
    }
}

impl ExtensionInstallationAuthority for RefusingInstallation {
    fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, EvidenceError> {
        self.refuse()
    }

    fn authenticate_namespace(
        &self,
        _: &ExtensionDeclaration,
        _: &ExtensionSelection,
    ) -> Result<(), EvidenceError> {
        self.refuse()
    }

    fn authenticate_core_contract(
        &self,
        _: &Id,
        _: u16,
        _: &ContentRef,
    ) -> Result<(), EvidenceError> {
        self.refuse()
    }

    fn authenticate_schema(&self, _: &SchemaRef) -> Result<(), EvidenceError> {
        self.refuse()
    }

    fn authenticate_handler(
        &self,
        _: &ExtensionDeclaration,
        _: &ContentRef,
        _: &ExtensionSemanticContract,
    ) -> Result<(), EvidenceError> {
        self.refuse()
    }
}

#[derive(Default)]
struct RefusingPolicy(Cell<usize>);

impl InstalledTypedReaderCatalogPolicy for RefusingPolicy {
    fn prepare_original_policy(
        &self,
        _: &Rc<InstalledTypedReaderPackage>,
        _: &ReferenceProfile,
        _: &InstalledExtensionPeerPolicy,
        _: Option<(&AdmittedGraph, &Id)>,
        _: usize,
    ) -> Result<Box<dyn LineageReferenceQualification>, NodeObservedError> {
        self.0.set(self.0.get() + 1);
        Err(refused("inert owning policy refuses"))
    }
}

fn configuration(
    maximum_operations: usize,
) -> Result<InstalledTypedReaderConfiguration, Box<dyn std::error::Error>> {
    Ok(InstalledTypedReaderConfiguration {
        node: Id::new("reader")?,
        owner: Id::new("owner/reader")?,
        quantum_ps: U64::new(1000),
        host_budget_ns: U64::new(1_000_000),
        closed_ingress: true,
        maximum_operations,
    })
}

fn empty_registry() -> Result<Rc<InstalledExtensionRegistry>, EvidenceError> {
    let authority = RefusingInstallation::default();
    let registry = InstalledExtensionRegistry::install(
        Vec::new(),
        &authority,
        ExtensionRegistryLimits::default(),
    )
    .map_err(|error| EvidenceError {
        message: error.to_string(),
    })?;
    assert_eq!(authority.0.get(), 0);
    Ok(Rc::new(registry))
}

#[test]
fn missing_policy_refuses_before_absent_descriptor_read() -> Result<(), Box<dyn std::error::Error>>
{
    let catalog = InstalledTypedReaderCatalog::new(
        PathBuf::from("/not-installed-typed-reader/implementation.json"),
        canonical::content_ref(b"inert original", "application/json")?,
        empty_registry()?,
        None,
    )?;

    let refusal = catalog
        .prepare(configuration(1)?)
        .err()
        .ok_or("missing refusal")?;

    assert_eq!(
        refusal.to_string(),
        refused("installed typed reader owning policy unavailable").to_string()
    );
    Ok(())
}

#[test]
fn unsupported_operation_credit_refuses_before_read_or_callback()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = Rc::new(RefusingPolicy::default());
    let catalog = InstalledTypedReaderCatalog::new(
        PathBuf::from("/not-installed-typed-reader/implementation.json"),
        canonical::content_ref(b"inert original", "application/json")?,
        empty_registry()?,
        Some(policy.clone()),
    )?;

    for credit in [0, 65, usize::MAX] {
        let refusal = catalog
            .prepare(configuration(credit)?)
            .err()
            .ok_or("missing refusal")?;
        assert_eq!(
            refusal.to_string(),
            refused("typed reader finite operation credit unsupported").to_string()
        );
    }
    assert_eq!(policy.0.get(), 0);
    Ok(())
}

#[test]
fn changed_installation_refuses_without_calling_owning_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = Rc::new(RefusingPolicy::default());
    let catalog = InstalledTypedReaderCatalog::new(
        PathBuf::from("/not-installed-typed-reader/implementation.json"),
        canonical::content_ref(b"inert original", "application/json")?,
        empty_registry()?,
        Some(policy.clone()),
    )?;

    assert!(catalog.prepare(configuration(64)?).is_err());
    assert_eq!(policy.0.get(), 0);
    assert!(
        InstalledTypedReaderCatalog::new(
            PathBuf::from("relative"),
            canonical::content_ref(b"inert original", "application/json")?,
            empty_registry()?,
            Some(policy.clone())
        )
        .is_err()
    );
    assert_eq!(policy.0.get(), 0);
    Ok(())
}

#[test]
#[ignore = "requires independently measured CRUCIBLE_TYPED_READER_MANIFEST"]
fn actual_package_cannot_supply_missing_registry_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let descriptor = PathBuf::from(std::env::var("CRUCIBLE_TYPED_READER_MANIFEST")?);
    let bytes = std::fs::read(&descriptor)?;
    let policy = Rc::new(RefusingPolicy::default());
    let catalog = InstalledTypedReaderCatalog::new(
        descriptor,
        canonical::content_ref(&bytes, "application/json")?,
        empty_registry()?,
        Some(policy.clone()),
    )?;

    assert!(catalog.prepare(configuration(1)?).is_err());
    assert_eq!(policy.0.get(), 0);
    Ok(())
}
