//! Original native-child role reads and refusal before source hooks.
//!
//! The forwarding observer owns the real child. It counts native readonly hooks;
//! it never supplies a substitute lifecycle, identity, executable or receipt.

// crucible-lint: allow panic-shortcut -- These actual-child controls panic on failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{cell::Cell, rc::Rc};

use crucible_node_transport::ProviderError;

use super::*;

struct ObservedOriginalChild {
    original: ReferenceDevice,
    hooks: Rc<Cell<usize>>,
}

impl control::sealed::Sealed for ObservedOriginalChild {}

impl ObservedOriginalChild {
    fn observed(&self) {
        self.hooks.set(self.hooks.get() + 1);
    }
}

impl ControlledReference for ObservedOriginalChild {
    fn status(&self) -> DeviceStatus {
        self.observed();
        self.original.status()
    }

    fn child_pid(&self) -> u32 {
        self.observed();
        self.original.child_pid()
    }

    fn supervision_id(&self) -> U64 {
        self.observed();
        self.original.supervision_id()
    }

    fn owner_id(&self) -> &Id {
        self.observed();
        self.original.owner_id()
    }

    fn incarnation_id(&self) -> &Id {
        self.observed();
        self.original.incarnation_id()
    }

    fn generation(&self) -> U64 {
        self.observed();
        self.original.generation()
    }

    fn quantized_facet(&self) -> &str {
        self.observed();
        self.original.quantized_facet()
    }

    fn stage(&mut self, grant: DeviceGrant, bytes: &[u8]) -> Result<(), ProviderError> {
        self.original.stage(grant, bytes)
    }

    fn activate(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.original.activate(grant)
    }

    fn close(&mut self, grant: &DeviceGrant) -> Result<DeviceReceipt, ProviderError> {
        self.original.close(grant)
    }

    fn validate_receipt(&self, receipt: &DeviceReceipt) -> Result<(), ProviderError> {
        self.original.validate_receipt(receipt)
    }

    fn acknowledge_publication(&mut self, grant: &DeviceGrant) -> Result<(), ProviderError> {
        self.original.acknowledge_publication(grant)
    }

    fn uses_host_owned_input_custody(&self) -> bool {
        self.original.uses_host_owned_input_custody()
    }

    fn validate_host_owned_input_custody(
        &self,
        original: &RuntimeInputBatch,
        commit: &crate::node_scheduling::InputCustodyCommit,
    ) -> Result<(), OperationFailure> {
        self.original
            .validate_host_owned_input_custody(original, commit)
    }

    fn quarantine(&mut self) -> Result<bool, ProviderError> {
        self.original.quarantine()
    }
}

#[test]
#[ignore = "requires CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE source-built companion"]
fn actual_enrolled_role_getter_keeps_original_child_and_refuses_before_hooks() {
    let executable = PathBuf::from(
        std::env::var_os("CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE")
            .expect("set source-built CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"),
    );
    let bytes = fs::read(&executable).unwrap();
    assert!(bytes.len() <= 4 * 1024 * 1024);
    let (graph, _) = crate::node_admission::test_fixture_reference_device(bytes);
    let directory = Directory::new();
    let id = Id::new("a").unwrap();
    let binding = graph.binding(&id).unwrap();
    let original = ReferenceDevice::spawn(
        &executable,
        &directory.0,
        binding.compatibility.execution_owner.id.clone(),
        binding.authority.incarnation_id.clone(),
        binding.authority.owner_generation,
        Duration::from_secs(2),
    )
    .unwrap();
    let original_pid = original.child_pid();
    let hooks = Rc::new(Cell::new(0));
    let child = ObservedOriginalChild {
        original,
        hooks: Rc::clone(&hooks),
    };
    let mut node = ControlledReferenceNode::from_controlled_prepared(
        &graph,
        &id,
        child,
        Id::new(REFERENCE_DEVICE_QUANTIZED_PROFILE).unwrap(),
        &|child, descriptor, binding| {
            NativeQualification.authenticate_child(&child.original, descriptor, binding)
        },
        16,
    )
    .unwrap();
    hooks.set(0);

    let view = node.external_description().unwrap();
    assert_eq!(view.declaration.role.as_str(), "external_device");
    assert!(std::ptr::eq(
        view.role_profile(),
        &node.binding.compatibility.profile_ref
    ));
    assert_eq!(view.quantum_ps, 100);
    assert_eq!(view.host_budget_ns, 1_000_000_000);
    assert!(view.original_staged_inputs);
    assert!(!view.physical_pause);
    assert!(!view.native_memory_preservation);
    assert!(!view.external_rewind);
    assert_eq!(hooks.get(), 5);
    assert_eq!(node.child.original.status(), DeviceStatus::Parked);
    assert_eq!(node.child.original.child_pid(), original_pid);
    assert!(node.staged.is_none());
    assert!(node.ready.is_none());
    assert!(node.windows.is_empty());

    // The actual child PID is a genuine foreign process identity. Injecting it
    // checks the early cached-owner path without claiming fork execution.
    let original_process = node.role_process;
    assert_ne!(original_pid, original_process);
    node.role_process = original_pid;
    hooks.set(0);
    assert!(node.external_description().is_err());
    assert_eq!(hooks.get(), 0);
    node.role_process = original_process;

    // A genuine foreign thread identity is refused without moving the !Send
    // native capsule or borrowing it across threads.
    let original_thread = node.thread;
    node.thread = std::thread::spawn(|| std::thread::current().id())
        .join()
        .unwrap();
    hooks.set(0);
    assert!(node.external_description().is_err());
    assert_eq!(hooks.get(), 0);
    node.thread = original_thread;

    let original_descriptor = node.descriptor.clone();
    node.descriptor.roles = vec![Id::new("clock").unwrap()];
    assert!(node.external_description().is_err());
    assert_eq!(hooks.get(), 0);
    node.descriptor = original_descriptor;

    node.binding.compatibility.operating_contract.facets[0].version = 2;
    assert!(node.external_description().is_err());
    assert_eq!(hooks.get(), 0);
    node.binding.compatibility.operating_contract.facets[0].version = 1;
    assert_eq!(node.child.original.status(), DeviceStatus::Parked);
    assert_eq!(node.child.original.child_pid(), original_pid);
    assert!(node.external_description().is_ok());

    assert!(node.child.original.quarantine().unwrap());
    assert_eq!(node.child.original.status(), DeviceStatus::Reaped);
    assert!(node.external_description().is_err());
}
