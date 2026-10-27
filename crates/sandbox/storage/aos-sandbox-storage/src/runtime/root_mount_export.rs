//! Sole detached-root export orchestration and its selected native reservoir.
//!
//! Both adapters run the existing before-inventory, actual catalog export and
//! after-inventory algorithm. The selected adapter continuously borrows the
//! same prepaid Storage original; ordinary code retains its previous native
//! calls and coarse boundary classifications. Neither adapter issues Host
//! launch authority from an inventory row or returned mount descriptor.

use super::*;
use crate::pin_worker_runtime::FreshWorkspaceCatalogObservationV1;
use aos_sandbox_protocol::storage_inventory::ValidatedStorageInventory;
use aos_sandbox_protocol::semantics::storage_guest_root::StorageGuestRootCurrentPublicationDataV2;
use aos_sandbox_model::{AccountingError, ResourceVector};

type Composition = (crate::workspace_catalog::StorageWorkspaceCatalogPlanV1,
    Option<AuthenticatedWorkspaceCatalogPhysicalPlanV1>);

enum Worker<'stage, 'flight, 'original> {
    Ordinary,
    RootExport(&'stage mut aos_sandbox_controller_domain::StorageRootLaunchExportReceivingLoanV2<'flight, 'original>),
}

#[derive(Clone, Copy)]
enum Failure {
    Gate, BeforeClock, BeforeCutoff, BeforeInventory, BeforeMarkers, BeforeDecode,
    BeforeProof, Composition, Nonce, Request, Encoding, Export, AfterClock,
    AfterCutoff, AfterInventory, AfterMarkers, AfterDecode, AfterProof,
    ReadbackDemand(usize), ReadbackPayment(usize),
}

/// Owns the actual body/native results through independent outer posts.
#[derive(Default)]
pub(super) struct RootMountExportOriginalV2 {
    dispatch: Option<repair_worker_drain::WorkerDispatchLease>,
    before_clock: Option<Result<u64, ZfsWorkerError>>,
    before_cutoff: Option<Result<u64, StorageRuntimeError>>,
    before_catalog: inventory_catalog::InventoryCatalogOriginalV1,
    before_inventory: Option<Result<Vec<u8>, StorageRuntimeError>>,
    before_markers: Option<Result<Vec<u8>, crate::guest_root_inventory::GuestRootInventoryErrorV1>>,
    before_markers_original: crate::guest_root_inventory::GuestRootInventoryReadbackOriginalV1,
    before_decode: Option<Result<ValidatedStorageInventory, aos_sandbox_protocol::ProtocolValidationError>>,
    composition: Option<Result<Composition, StorageBrokerError>>,
    nonce: Option<Result<[u8; 32], ZfsWorkerError>>,
    request: Option<Result<WorkspaceCatalogObservationRequestV1, StorageRuntimeError>>,
    encoding: Option<Result<Vec<u8>, ZfsWorkerError>>,
    export: Option<Result<(FreshWorkspaceCatalogObservationV1, OwnedFd), ZfsWorkerError>>,
    after_clock: Option<Result<u64, ZfsWorkerError>>,
    after_cutoff: Option<Result<u64, StorageRuntimeError>>,
    after_catalog: inventory_catalog::InventoryCatalogOriginalV1,
    after_inventory: Option<Result<Vec<u8>, StorageRuntimeError>>,
    after_markers: Option<Result<Vec<u8>, crate::guest_root_inventory::GuestRootInventoryErrorV1>>,
    after_markers_original: crate::guest_root_inventory::GuestRootInventoryReadbackOriginalV1,
    after_decode: Option<Result<ValidatedStorageInventory, aos_sandbox_protocol::ProtocolValidationError>>,
    readback_demand: [Option<Result<ResourceVector, AccountingError>>; 2],
    readback_payment: [Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>; 2],
    gate: Option<StorageRuntimeError>,
    first: Option<Failure>,
    entered: bool,
    positive: bool,
}

impl RootMountExportOriginalV2 {
    fn fail<T>(&mut self, first: Failure) -> Result<T, StorageRuntimeError> {
        self.first.get_or_insert(first);
        if matches!(first, Failure::Gate | Failure::BeforeProof | Failure::AfterProof) {
            self.gate.get_or_insert(StorageRuntimeError::Recovery);
        }
        Err(StorageRuntimeError::Receiving)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { value.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            Failure::ReadbackDemand(index) => error(&self.readback_demand[index]),
            Failure::ReadbackPayment(index) => error(&self.readback_payment[index]),
            Failure::BeforeClock => error(&self.before_clock),
            Failure::BeforeCutoff => error(&self.before_cutoff),
            Failure::BeforeInventory => self.before_catalog.failure().or_else(|| error(&self.before_inventory)),
            Failure::BeforeMarkers => self.before_markers_original.failure().or_else(|| error(&self.before_markers)),
            Failure::BeforeDecode => error(&self.before_decode),
            Failure::Composition => error(&self.composition),
            Failure::Nonce => error(&self.nonce),
            Failure::Request => error(&self.request),
            Failure::Encoding => error(&self.encoding),
            Failure::Export => error(&self.export),
            Failure::AfterClock => error(&self.after_clock),
            Failure::AfterCutoff => error(&self.after_cutoff),
            Failure::AfterInventory => self.after_catalog.failure().or_else(|| error(&self.after_inventory)),
            Failure::AfterMarkers => self.after_markers_original.failure().or_else(|| error(&self.after_markers)),
            Failure::AfterDecode => error(&self.after_decode),
            Failure::Gate | Failure::BeforeProof | Failure::AfterProof => self.gate.as_ref().map(|cause| cause as _),
        }
    }

    pub(super) fn failure_with_receiving_v2<'owner>(
        &'owner self,
        receiving: &'owner aos_sandbox_controller_domain::StorageRootLaunchExportReceivingLoanV2<'_, '_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        self.failure_with_selected_receiving_v2(receiving.catalog_worker_failure_v2(), receiving.failure())
    }

    pub(super) fn failure_with_original_v2<'owner>(
        &'owner self,
        original: &'owner aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        self.failure_with_selected_receiving_v2(original.root_export_catalog_failure_v2(), original.root_export_receiving_failure_v2())
    }

    fn failure_with_selected_receiving_v2<'owner>(
        &'owner self,
        catalog_cause: Option<&'owner (dyn std::error::Error + 'static)>,
        financial_cause: Option<&'owner (dyn std::error::Error + 'static)>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        let selected_readback_payment = match self.first? {
            Failure::ReadbackPayment(_) => true,
            Failure::BeforeMarkers => self.before_markers_original.failure()
                .is_some_and(|cause| cause.is::<aos_sandbox_controller_domain::StorageReceivingClosedV1>()),
            Failure::AfterMarkers => self.after_markers_original.failure()
                .is_some_and(|cause| cause.is::<aos_sandbox_controller_domain::StorageReceivingClosedV1>()),
            _ => false,
        };
        if selected_readback_payment {
            return financial_cause.or_else(|| self.failure());
        }
        let selected_native = match self.first? {
            Failure::BeforeInventory => self.before_catalog.failure()
                .is_some_and(|cause| cause.is::<aos_sandbox_controller_domain::StorageReceivingClosedV1>()),
            Failure::AfterInventory => self.after_catalog.failure()
                .is_some_and(|cause| cause.is::<aos_sandbox_controller_domain::StorageReceivingClosedV1>()),
            Failure::Export => self.export.as_ref().and_then(|result| result.as_ref().err())
                .and_then(ZfsWorkerError::physical_native_refusal_v1).is_some(),
            _ => false,
        };
        if selected_native { catalog_cause.or_else(|| self.failure()) }
        else { self.failure() }
    }

    pub(super) fn observe_receiving_v2(
        &mut self,
        runtime: &mut StorageBrokerRuntime,
        expected_proof: GuestRootPublicationProofV1,
        template: &ProtectedGuestRootTemplateV1,
        original_cutoff: u64,
        receiving: &mut aos_sandbox_controller_domain::StorageRootLaunchExportReceivingLoanV2<'_, '_>,
        current: Option<StorageGuestRootCurrentPublicationDataV2>,
    ) -> Result<(), StorageRuntimeError> {
        self.observe(runtime, expected_proof, template, original_cutoff, Worker::RootExport(receiving), current)
    }

    fn observe(
        &mut self,
        runtime: &mut StorageBrokerRuntime,
        expected_proof: GuestRootPublicationProofV1,
        template: &ProtectedGuestRootTemplateV1,
        deadline: u64,
        mut worker: Worker<'_, '_, '_>,
        current: Option<StorageGuestRootCurrentPublicationDataV2>,
    ) -> Result<(), StorageRuntimeError> {
        if self.entered || self.first.is_some() { return Err(StorageRuntimeError::Receiving); }
        self.entered = true;
        self.dispatch = Some(match runtime.worker_dispatch.enter() {
            Ok(dispatch) => dispatch,
            Err(()) => return self.fail(Failure::Gate),
        });
        self.before_clock = Some(boottime_now_nanoseconds());
        let Some(Ok(now)) = self.before_clock.as_ref().map(|result| result.as_ref().copied()) else { return self.fail(Failure::BeforeClock); };
        self.before_cutoff = Some(guest_root_inventory_cutoff(now, deadline));
        let Some(Ok(cutoff)) = self.before_cutoff.as_ref() else { return self.fail(Failure::BeforeCutoff); };
        let cutoff = *cutoff;
        self.before_inventory = Some(match &mut worker {
            Worker::Ordinary => runtime.inventory_resources(deadline, cutoff),
            Worker::RootExport(receiving) => runtime.complete_root_export_inventory_v2(
                &mut self.before_catalog, deadline, cutoff, receiving,
            ),
        });
        let Some(Ok(before)) = self.before_inventory.as_ref() else { return self.fail(Failure::BeforeInventory); };
        if let Worker::RootExport(receiving) = &mut worker {
            self.readback_demand[0] = Some(runtime.inventory_workspace_rows_v2().and_then(|rows|
                crate::guest_root_inventory::additional_complete_marker_readback_demand_v2(rows, template)));
            let Some(Ok(demand)) = self.readback_demand[0].as_ref() else {
                return self.fail(Failure::ReadbackDemand(0));
            };
            self.readback_payment[0] = Some(receiving.reserve_guest_root_readback_delta_v2(
                runtime.coordinator.recovery_encoding_journal_v1(), *demand,
            ));
            if !matches!(self.readback_payment[0], Some(Ok(()))) {
                return self.fail(Failure::ReadbackPayment(0));
            }
            self.before_markers_original.mark_complete_projection_prepaid_v2();
        }
        self.before_markers = Some(match &mut worker {
            Worker::Ordinary => attach_guest_root_publication_readback_v1(before, template),
            Worker::RootExport(receiving) => {
                let mut labels = crate::guest_root_inventory::GuestRootLabelReceivingV2::root_export_v2(
                    runtime.coordinator.recovery_encoding_journal_v1(), receiving,
                );
                crate::guest_root_inventory::attach_guest_root_publication_readback_current_v2(
                    before, template, &mut self.before_markers_original, &runtime.coordinator, &mut labels,
                )
            },
        });
        let Some(Ok(before)) = self.before_markers.as_ref() else { return self.fail(Failure::BeforeMarkers); };
        self.before_decode = Some(decode_storage_resource_inventory_response(before, MAXIMUM_RESPONSE_BYTES));
        let Some(Ok(before)) = self.before_decode.as_ref() else { return self.fail(Failure::BeforeDecode); };
        if !before.workspaces().iter().any(|row| matches_publication_v2(
            row, expected_proof, current.as_ref(), matches!(&worker, Worker::RootExport(_)),
        ))
        { return self.fail(Failure::BeforeProof); }

        let Some(validated) = runtime.workspaces.as_ref() else { return self.fail(Failure::Gate); };
        self.composition = Some(runtime.coordinator.workspace_catalog_activation_plan());
        let Some(Ok((plan, physical))) = self.composition.as_ref() else { return self.fail(Failure::Composition); };
        let Some(physical) = physical.as_ref() else { return self.fail(Failure::Gate); };
        self.nonce = Some(catalog_observation_nonce());
        let Some(Ok(nonce)) = self.nonce.as_ref() else { return self.fail(Failure::Nonce); };
        self.request = Some(runtime.catalog_observation_request(validated, plan, physical, *nonce, deadline)
            .and_then(|request| request.with_root_export(expected_proof).map_err(Into::into)));
        let Some(Ok(request)) = self.request.as_ref() else { return self.fail(Failure::Request); };
        self.encoding = Some(encode_request(request));
        let Some(Ok(encoded)) = self.encoding.as_ref() else { return self.fail(Failure::Encoding); };
        self.export = Some(match &mut worker {
            Worker::Ordinary => runtime.pin_io.export_catalog_root(encoded, request, cutoff),
            Worker::RootExport(receiving) => {
                let mut stage = crate::process::receiving_stage::StoragePhysicalWorkerStageV1::root_export_v2(
                    receiving, runtime.coordinator.recovery_encoding_journal_v1(),
                );
                runtime.pin_io.export_catalog_root_receiving_v1(encoded, request, cutoff, &mut stage)
            }
        });
        if !matches!(self.export, Some(Ok(_))) { return self.fail(Failure::Export); }

        self.after_clock = Some(boottime_now_nanoseconds());
        let Some(Ok(now)) = self.after_clock.as_ref().map(|result| result.as_ref().copied()) else { return self.fail(Failure::AfterClock); };
        self.after_cutoff = Some(guest_root_inventory_cutoff(now, deadline));
        let Some(Ok(cutoff)) = self.after_cutoff.as_ref() else { return self.fail(Failure::AfterCutoff); };
        self.after_inventory = Some(match &mut worker {
            Worker::Ordinary => runtime.inventory_resources(deadline, *cutoff),
            Worker::RootExport(receiving) => runtime.complete_root_export_inventory_v2(
                &mut self.after_catalog, deadline, *cutoff, receiving,
            ),
        });
        let Some(Ok(after)) = self.after_inventory.as_ref() else { return self.fail(Failure::AfterInventory); };
        if let Worker::RootExport(receiving) = &mut worker {
            self.readback_demand[1] = Some(runtime.inventory_workspace_rows_v2().and_then(|rows|
                crate::guest_root_inventory::additional_complete_marker_readback_demand_v2(rows, template)));
            let Some(Ok(demand)) = self.readback_demand[1].as_ref() else {
                return self.fail(Failure::ReadbackDemand(1));
            };
            self.readback_payment[1] = Some(receiving.reserve_guest_root_readback_delta_v2(
                runtime.coordinator.recovery_encoding_journal_v1(), *demand,
            ));
            if !matches!(self.readback_payment[1], Some(Ok(()))) {
                return self.fail(Failure::ReadbackPayment(1));
            }
            self.after_markers_original.mark_complete_projection_prepaid_v2();
        }
        self.after_markers = Some(match &mut worker {
            Worker::Ordinary => attach_guest_root_publication_readback_v1(after, template),
            Worker::RootExport(receiving) => {
                let mut labels = crate::guest_root_inventory::GuestRootLabelReceivingV2::root_export_v2(
                    runtime.coordinator.recovery_encoding_journal_v1(), receiving,
                );
                crate::guest_root_inventory::attach_guest_root_publication_readback_current_v2(
                    after, template, &mut self.after_markers_original, &runtime.coordinator, &mut labels,
                )
            },
        });
        let Some(Ok(after)) = self.after_markers.as_ref() else { return self.fail(Failure::AfterMarkers); };
        self.after_decode = Some(decode_storage_resource_inventory_response(after, MAXIMUM_RESPONSE_BYTES));
        let Some(Ok(after)) = self.after_decode.as_ref() else { return self.fail(Failure::AfterDecode); };
        if !after.workspaces().iter().any(|row| matches_publication_v2(
            row, expected_proof, current.as_ref(), matches!(&worker, Worker::RootExport(_)),
        ))
        { return self.fail(Failure::AfterProof); }
        self.positive = true;
        Ok(())
    }

    pub(super) fn mount_v2(&self) -> Option<&OwnedFd> {
        if !self.positive || self.first.is_some() { return None; }
        self.export.as_ref()?.as_ref().ok().map(|(_, mount)| mount)
    }

    // A failed later catalog/proof check must not suppress the independently
    // owed native mount observation. This private borrow exposes only the
    // actual already-owned successful export handle to that fixed post; it
    // establishes no positive body, authority or caller-adoptable owner.
    pub(super) fn retained_mount_for_owed_post_v2(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.export.as_ref()?.as_ref().ok().map(|(_, mount)| mount.as_fd())
    }

    // The actual outer positive continuation calls this only AFTER signed
    // source/currentness, native send and every independent post succeeded.
    // No further fallible operation or grant follows this local retirement.
    pub(super) fn dispose_positive_after_posts_v2(&mut self) {
        if !self.positive || self.first.is_some() || !matches!(self.export, Some(Ok(_))) {
            std::process::abort();
        }
        drop(self.export.take());
        drop(self.dispatch.take());
    }

    fn into_ordinary_result(mut self) -> Result<OwnedFd, StorageRuntimeError> {
        fn take_error<T, E>(value: &mut Option<Result<T, E>>) -> Option<E> {
            match value.take() {
                Some(Err(error)) => Some(error),
                original => { *value = original; None }
            }
        }
        if self.positive && self.first.is_none() {
            if let Some(Ok((_, mount))) = self.export.take() {
                drop(self.dispatch.take());
                return Ok(mount);
            }
        }
        let error = match self.first {
            Some(Failure::BeforeClock) => take_error(&mut self.before_clock).map(Into::into),
            Some(Failure::BeforeCutoff) => take_error(&mut self.before_cutoff),
            Some(Failure::BeforeInventory) => take_error(&mut self.before_inventory),
            Some(Failure::Composition) => take_error(&mut self.composition).map(Into::into),
            Some(Failure::Nonce) => take_error(&mut self.nonce).map(Into::into),
            Some(Failure::Request) => take_error(&mut self.request),
            Some(Failure::Encoding) => take_error(&mut self.encoding).map(Into::into),
            Some(Failure::Export) => take_error(&mut self.export).map(Into::into),
            Some(Failure::AfterClock) => take_error(&mut self.after_clock).map(Into::into),
            Some(Failure::AfterCutoff) => take_error(&mut self.after_cutoff),
            Some(Failure::AfterInventory) => take_error(&mut self.after_inventory),
            _ => Some(StorageRuntimeError::Recovery),
        }.unwrap_or(StorageRuntimeError::Recovery);
        // A mount obtained before a refused later inventory closes at the old
        // ordinary return boundary; selected failure keeps that same real FD.
        drop(self.export.take());
        drop(self.dispatch.take());
        Err(error)
    }
}

pub(super) fn export_ordinary_v2(
    runtime: &mut StorageBrokerRuntime,
    proof: GuestRootPublicationProofV1,
    template: &ProtectedGuestRootTemplateV1,
    deadline: u64,
) -> Result<OwnedFd, StorageRuntimeError> {
    let mut original = RootMountExportOriginalV2::default();
    let _ = original.observe(runtime, proof, template, deadline, Worker::Ordinary, None);
    original.into_ordinary_result()
}

/// Compares the immutable physical root and the separately current publication.
fn matches_publication_v2(
    workspace: &ValidatedStorageWorkspace,
    physical: GuestRootPublicationProofV1,
    expected: Option<&StorageGuestRootCurrentPublicationDataV2>,
    retained: bool,
) -> bool {
    if workspace.workspace_handle() != &physical.workspace_handle
        || workspace.guest_root_publication_proof() != Some(physical)
    {
        return false;
    }
    if !retained {
        return true;
    }
    let Some(actual) = workspace.current_guest_root_publication_v2() else { return false; };
    if actual.require_workspace_v2(workspace).is_err() { return false; }
    match expected {
        Some(expected) => actual == expected,
        // An old creation-only Host grant remains creation-only. It cannot
        // export a root whose independently authenticated current assignment
        // has advanced, nor infer currentness from a missing binding.
        None => match (actual.current_assignment_v2(), workspace.fence().broker_assignment()) {
            (Ok(current), Ok(creation)) => current == creation,
            _ => false,
        },
    }
}
