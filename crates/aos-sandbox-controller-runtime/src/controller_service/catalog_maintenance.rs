//! Runs paid cold and actual refresh cycles on the worker's four held Sessions.
//!
//! This module owns whole native and SDK prefixes. The outer worker already
//! holds the Session mutex; Node/executor never locks it recursively. Every
//! reached native entry finishes independently before any completion claim.

use super::*;
use aos_sandbox::{CatalogMaintenanceClosedV2, CatalogMaintenanceOriginalV2};
use aos_sandbox_broker_session_security::controller_composition::{
    ControllerCatalogMaintenanceCycleOriginalV2, OutputPreparationClosedV1,
};
use worker::{CatalogStatus, CycleFailure};

mod signing;

enum CompletedReceiptV2 {
    Cold(aos_sandbox_broker_session_security::controller_composition::ControllerCatalogMaintenanceColdReceiptV2),
    Refresh(aos_sandbox_broker_session_security::controller_composition::ControllerCatalogMaintenanceRefreshReceiptV2),
}

pub(super) struct CatalogMaintenanceWorkerOriginalV2 {
    native: CatalogMaintenanceOriginalV2,
    sdk: ControllerCatalogMaintenanceCycleOriginalV2,
    signing: signing::MaintenanceStorageSigningOriginalV3,
    shape: Option<
        Result<
            aos_sandbox::CatalogMaintenanceSdkShapeDataV2,
            aos_sandbox::ResourceReservationErrorV1,
        >,
    >,
    entry: Option<Result<(), CatalogMaintenanceClosedV2>>,
    body: Option<Result<(), OutputPreparationClosedV1>>,
    qualification:
        Option<Result<(), aos_sandbox_broker_session_security::BrokerSessionSecurityError>>,
    disposed: Option<Result<(), OutputPreparationClosedV1>>,
    completed: Option<Result<(), aos_sandbox::ResourceReservationErrorV1>>,
}

impl CatalogMaintenanceWorkerOriginalV2 {
    pub(super) fn continuation_failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.native.original_failure_selected_v2() { return self.native.failure_v2(); }
        self.signing.failure().or_else(|| self.sdk.continuation_failure_v3())
    }

    fn new() -> Self {
        Self {
            native: CatalogMaintenanceOriginalV2::new(),
            sdk: ControllerCatalogMaintenanceCycleOriginalV2::new(),
            signing: Default::default(),
            shape: None,
            entry: None,
            body: None,
            qualification: None,
            disposed: None,
            completed: None,
        }
    }
}

fn closed() -> CycleFailure {
    CycleFailure::Fatal(
        "paid catalog maintenance refused; actual originals remain retained".to_owned(),
    )
}

pub(super) fn observe_cold_once_v2(
    controller: &mut ProductionController,
    sessions: &mut ControllerBrokerSessions,
) -> Result<CatalogStatus, CycleFailure> {
    observe_once_v2(controller, sessions, true, None, None, None)
}

pub(super) fn observe_refresh_once_v2(
    controller: &mut ProductionController,
    sessions: &mut ControllerBrokerSessions,
    pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    ownership: Option<&super::ownership::ControllerOwnershipConfigurationV1>,
    signer: Option<&super::plan_signer::ControllerBrokerPlanSignerV1>,
) -> Result<CatalogStatus, CycleFailure> {
    observe_once_v2(controller, sessions, false, pins, ownership, signer)
}

fn observe_once_v2(
    controller: &mut ProductionController,
    sessions: &mut ControllerBrokerSessions,
    cold: bool,
    pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    ownership: Option<&super::ownership::ControllerOwnershipConfigurationV1>,
    signer: Option<&super::plan_signer::ControllerBrokerPlanSignerV1>,
) -> Result<CatalogStatus, CycleFailure> {
    if sessions.catalog_maintenance.is_some()
        || (cold && sessions.catalog_cold_completion.is_some())
        || (!cold && sessions.catalog_cold_completion.is_none())
        || sessions.storage_root.has_pending()
    {
        return Err(closed());
    }
    let (bank, profile, runtime) = initial_broker_sessions::maintenance_context_parts_v2(sessions)?;
    let (bank, profile, runtime) = (Arc::clone(bank), Arc::clone(profile), Arc::clone(runtime));
    // The whole-roster check above completes before borrowing these disjoint
    // actual context and Session fields for the continuous SDK window.
    let recovered = sessions
        .initial_context
        .as_ref()
        .and_then(|context| context.recovered_context_data_v2());
    let captures = &sessions.initial_slots;
    let mut host = sessions
        .host
        .as_mut()
        .ok_or_else(closed)?
        .borrow_catalog_maintenance_session_v2(
            captures[0].completed_capture_v1().ok_or_else(closed)?,
        )
        .map_err(|_| closed())?;
    let mut mount = sessions
        .mount
        .as_mut()
        .ok_or_else(closed)?
        .borrow_catalog_maintenance_session_v2(
            captures[1].completed_capture_v1().ok_or_else(closed)?,
        )
        .map_err(|_| closed())?;
    let mut storage = sessions
        .storage
        .as_mut()
        .ok_or_else(closed)?
        .borrow_catalog_maintenance_session_v2(
            captures[2].completed_capture_v1().ok_or_else(closed)?,
        )
        .map_err(|_| closed())?;
    let mut network = sessions
        .network
        .as_mut()
        .ok_or_else(closed)?
        .borrow_catalog_maintenance_session_v2(
            captures[3].completed_capture_v1().ok_or_else(closed)?,
        )
        .map_err(|_| closed())?;
    sessions.catalog_maintenance = Some(CatalogMaintenanceWorkerOriginalV2::new());
    let original = sessions.catalog_maintenance.as_mut().ok_or_else(closed)?;
    original.shape = Some((|| {
        let mut shape = ControllerCatalogMaintenanceCycleOriginalV2::receiving_shape_v2()?;
        // Native2Self and SDK2Self are supplied by their actual owners. This
        // adds only this Runtime's distinct enclosing result/header carriers.
        let runtime = std::mem::size_of::<CatalogMaintenanceWorkerOriginalV2>()
            .checked_sub(std::mem::size_of::<CatalogMaintenanceOriginalV2>())
            .and_then(|bytes| {
                bytes.checked_sub(std::mem::size_of::<
                    ControllerCatalogMaintenanceCycleOriginalV2,
                >())
            })
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        // Both historical slots remain alongside the next full flight; the
        // new receipt's construction carrier is distinct from those residents.
        let receipt = std::mem::size_of::<CompletedReceiptV2>()
            .checked_mul(4).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        shape.inline_and_construction_bytes = shape
            .inline_and_construction_bytes
            .checked_add(runtime)
            .and_then(|bytes| bytes.checked_add(receipt))
            .ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?;
        Ok(shape)
    })());
    let shape = original
        .shape
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .copied()
        .ok_or_else(closed)?;
    original.entry = Some(if cold {
        controller.begin_catalog_maintenance_once_v2(
            &mut original.native, &bank, &profile, &runtime, shape,
        )
    } else {
        controller.begin_catalog_refresh_once_v2(
            &mut original.native, &bank, &profile, &runtime, shape,
        )
    });
    original.body = Some(if matches!(original.entry, Some(Ok(()))) {
        original.qualification = Some((|| {
            if let Some(context) = recovered {
                let bank = bank.lock().map_err(|_| {
                    aos_sandbox_broker_session_security::BrokerSessionSecurityError::Currentness
                })?;
                for completed in [&mut host, &mut mount, &mut storage, &mut network] {
                    completed.require_recovered_ordinary_context_with_node_v2(
                        controller, context, &bank, &profile,
                    )?;
                }
            }
            Ok(())
        })());
        if !matches!(original.qualification, Some(Ok(()))) {
            Err(OutputPreparationClosedV1)
        } else {
            match controller.borrow_catalog_maintenance_interval_v2(&mut original.native) {
                Ok(mut loan) => if cold {
                    original.sdk.observe_cold_once_v2(
                        &mut loan, &mut host, &mut mount, &mut storage, &mut network,
                    )
                } else {
                    (|| -> Result<(), OutputPreparationClosedV1> {
                        let required = original.sdk.begin_refresh_once_v3(
                            &mut loan, &mut host, &mut mount, &mut storage, &mut network, pins)?;
                        if required {
                            let ownership = ownership.ok_or(OutputPreparationClosedV1)?;
                            let signer = signer.ok_or(OutputPreparationClosedV1)?;
                            let verifier = ownership.verifier();
                            let mut signing = original.sdk.borrow_refresh_signer_once_v3(
                                &mut loan, &mut storage, verifier)?;
                            original.signing.sign_once_v3(&mut signing, verifier, signer)
                                .map_err(|_| OutputPreparationClosedV1)?;
                            drop(signing);
                        }
                        original.sdk.finish_refresh_once_v3(&mut loan, &mut host, &mut storage, pins)
                    })()
                },
                Err(_) => Err(OutputPreparationClosedV1),
            }
        }
    } else {
        Err(OutputPreparationClosedV1)
    });
    original
        .native
        .retain_body_result_v2(if matches!(original.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(CatalogMaintenanceClosedV2)
        });
    controller.finish_catalog_maintenance_once_v2(&mut original.native);
    if !matches!(original.body, Some(Ok(()))) {
        return Err(closed());
    }
    original.disposed = Some(original.sdk.dispose_after_node_posts_once_v2(
        controller,
        &mut original.native,
        &mut host,
    ));
    if !matches!(original.disposed, Some(Ok(()))) {
        return Err(closed());
    }
    original.completed = Some(if cold {
        original.sdk.completed_cold_with_node_v2(controller, &original.native).map(|_| ())
    } else {
        original.sdk.completed_refresh_with_node_v2(controller, &original.native).map(|_| ())
    });
    if !matches!(original.completed, Some(Ok(()))) {
        return Err(closed());
    }
    // Only the actual consuming completion port may retire this whole graph.
    // A failed completion returns both native and SDK originals for restoration.
    let mut original = sessions.catalog_maintenance.take().ok_or_else(closed)?;
    let retired = if cold {
        original.sdk.retire_completed_cold_with_node_v2(controller, original.native)
            .map(CompletedReceiptV2::Cold)
    } else {
        original.sdk.retire_completed_refresh_with_node_v2(controller, original.native)
            .map(CompletedReceiptV2::Refresh)
    };
    match retired {
        Ok(receipt) => {
            let (generation, digest) = match receipt {
                CompletedReceiptV2::Cold(receipt) => {
                    let status = receipt.catalog_status_data_v2();
                    sessions.catalog_cold_completion = Some(receipt);
                    status
                }
                CompletedReceiptV2::Refresh(receipt) => {
                    let status = receipt.catalog_status_data_v2();
                    sessions.catalog_refresh_completion = Some(receipt);
                    status
                }
            };
            Ok(CatalogStatus { generation, digest })
        }
        Err((sdk, native)) => {
            original.sdk = sdk;
            original.native = native;
            sessions.catalog_maintenance = Some(original);
            Err(closed())
        }
    }
}
