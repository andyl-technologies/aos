//! Runs the systemd-activated SourceProvider catalog and closed source boundary.
//!
//! Startup installs a signed catalog locator from a named systemd credential.
//! The service retains the fixed authenticated owner and answers fresh catalog
//! challenges. A selected LocalLive Acquire may reach authenticated Storage
//! readback; a genuine native original pair may reach local Held and Complete
//! transmission. Root acceptance, relay and settlement remain closed.
//! Holder Inventory
//! uses the fixed owner's durable admission and
//! reopens every active source before claiming completeness. A cold selected
//! reservation retries only its original signed plan; production backend
//! effects and SourceRoot descriptors remain unavailable.

use std::process::ExitCode;
use std::time::Duration;

use aos_sandbox_broker_session_security::{
    ProductionBrokerDeadlineErrorV1, ProductionBrokerSessionActivationErrorV1,
    ProductionSourceProviderCatalogInstallErrorV1, ProductionSourceProviderIngressErrorV1,
    ProductionSourceProviderIngressV1, ProductionSourceProviderStorageReadbackV1,
    ProductionSelectedSourceProviderOriginalV1,
    install_fixed_source_provider_catalog_credential,
    install_fixed_selected_source_provider_catalog_credential, production_deadline_after,
};
use aos_sandbox_source_provider::{
    FixedProviderBackendRequestOutcomeV1, FixedProviderIngressProgressV1,
    FixedProviderOriginalCompletionProgressV5, FixedProviderOwnerV1,
    FixedSelectedProviderProgressV1, NativeNoDispatchSettlementV1, ProviderLedgerError,
};
use aos_sandbox_source_provider_security::{
    ProtectedProviderCustodyV1, SourceProviderSecurityError,
    validate_fixed_provider_authority_v1,
};

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

enum RecoveryAnswerV1 {
    Native(NativeNoDispatchSettlementV1),
    LocalLive(aos_sandbox_core::ObjectDigest),
}

#[derive(Debug, thiserror::Error)]
enum SourceProviderDaemonErrorV1 {
    #[error("usage: aos-source-providerd [--install-catalog | --check-source-provider-authority]")]
    Arguments,
    #[error("catalog installation failed: {0}")]
    Catalog(#[from] ProductionSourceProviderCatalogInstallErrorV1),
    #[error("SourceProvider requires real and effective UID zero")]
    Identity,
    #[error("SourceProvider protected authority failed: {0}")]
    Authority(#[from] SourceProviderSecurityError),
    #[error("deadline failed: {0}")]
    Deadline(#[from] ProductionBrokerDeadlineErrorV1),
    #[error("ingress failed: {0}")]
    Ingress(#[from] ProductionSourceProviderIngressErrorV1),
    #[error("SourceProvider protected source request failed: {0}")]
    Source(#[from] ProviderLedgerError),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-source-providerd: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), SourceProviderDaemonErrorV1> {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    match (arguments.next().as_deref(), arguments.next()) {
        (Some("--install-catalog"), None) => {
            install_fixed_source_provider_catalog_credential()?;
            Ok(())
        }
        (Some("--install-catalog"), Some(selected))
            if selected == "--selected-mount-source" && arguments.next().is_none() =>
        {
            if let Err(_original) = install_fixed_selected_source_provider_catalog_credential() {
                // This typed owner keeps actual partial credentials, writes and
                // readback resident. Death is release, not a drained receipt.
                eprintln!("aos-source-providerd: selected catalog installation refused");
                std::process::exit(1);
            }
            Ok(())
        }
        (Some("--check-source-provider-authority"), None) => {
            if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
                return Err(SourceProviderDaemonErrorV1::Identity);
            }
            validate_fixed_provider_authority_v1()?;
            Ok(())
        }
        (Some("--check-source-provider-authority"), Some(selected))
            if selected == "--selected-mount-source" && arguments.next().is_none() =>
        {
            check_selected_provider_authority()
        }
        (None, None) => serve_authenticated_ingress(),
        (Some("--selected-mount-source"), None) => serve_selected_authenticated_ingress(),
        _ => Err(SourceProviderDaemonErrorV1::Arguments),
    }
}

// This is a prestart check, not a transferable currentness or signing loan.
// A failed selected opening stays resident until intentional process death.
// Success releases custody normally after its final original-owner bookend.
fn check_selected_provider_authority() -> Result<(), SourceProviderDaemonErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(SourceProviderDaemonErrorV1::Identity);
    }

    let mut opening = ProtectedProviderCustodyV1::begin_fixed_selected_mount_source();
    if opening.open_once().is_err() {
        eprintln!("aos-source-providerd: selected authority opening refused");
        std::process::exit(1);
    }

    let mut custody = opening.take_provider_custody();
    let final_observation = match custody.as_mut() {
        Some(custody) => Some(custody.revalidated_configuration()),
        None => None,
    };
    if !matches!(final_observation.as_ref(), Some(Ok(_))) {
        // Keep the genuine returned custody and actual final cause resident.
        // Process death releases them; this is not queue or owner settlement.
        eprintln!("aos-source-providerd: selected authority final check refused");
        std::process::exit(1);
    }

    Ok(())
}

fn serve_authenticated_ingress() -> Result<(), SourceProviderDaemonErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(SourceProviderDaemonErrorV1::Identity);
    }

    let mut ingress = adopt_fixed_ingress()?;
    loop {
        let deadline = production_deadline_after(ACCEPT_TIMEOUT)?;
        match ingress.accept_authenticated_owner(deadline) {
            Ok((mut owner, _report)) => {
                loop {
                    // Keep failed original custody owned; no old backend or
                    // replacement Session may resume it. The paired producer
                    // is a separate required frontier, not enabled here.
                    if owner.original_native_ingress_closed() {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    let progress = match ingress.advance_authenticated_ingress(&mut owner) {
                        Ok(progress) => progress,
                        Err(error) if owner.original_native_pair_pending() => {
                            owner.close_original_native_ingress_after_failure();
                            eprintln!("original native ingress remains closed: {error}");
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };
                    match progress {
                        FixedProviderIngressProgressV1::Pending => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        FixedProviderIngressProgressV1::CatalogReplied => {}
                        FixedProviderIngressProgressV1::OriginalRootPreparedRetained => {
                            // No reservation, signing, nonce, bridge or dispatch
                            // capability is available from this classification.
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        FixedProviderIngressProgressV1::OriginalPairRetained => {
                            serve_original_native_completion(&ingress, &mut owner);
                        }
                        FixedProviderIngressProgressV1::Recovery(query) => {
                            let mut storage = ProductionSourceProviderStorageReadbackV1;
                            // A retained no-dispatch cut needs no current row manifest.
                            let native_settlement = owner
                                .backend_session(&mut storage)
                                .settle_native_no_dispatch_recovery_for_query(&query);
                            let answer = match native_settlement {
                                Ok(settlement) => RecoveryAnswerV1::Native(settlement),
                                Err(ProviderLedgerError::Unavailable) => {
                                    let (publication, manifest) =
                                        ingress.read_current_catalog_manifest()?;
                                    let mut session = owner.backend_session_with_catalog(
                                        &mut storage,
                                        &publication,
                                        &manifest,
                                    );
                                    RecoveryAnswerV1::LocalLive(
                                        session
                                            .inspect_selected_storage_recovery_for_query(&query)?,
                                    )
                                }
                                Err(error) => return Err(error.into()),
                            };

                            match answer {
                                RecoveryAnswerV1::Native(settlement) => {
                                    while !owner
                                        .send_native_recovery_unavailable(&query, &settlement)?
                                    {
                                        std::thread::sleep(Duration::from_millis(2));
                                    }
                                }
                                RecoveryAnswerV1::LocalLive(signed_plan_digest) => {
                                    // LocalLive readback remains nonterminal pending evidence.
                                    while !owner
                                        .send_recovery_unavailable(&query, signed_plan_digest)?
                                    {
                                        std::thread::sleep(Duration::from_millis(2));
                                    }
                                }
                            }
                        }
                        FixedProviderIngressProgressV1::InventoryReadback(query) => loop {
                            let historical = owner.readback_inventory_by_digest(&query)?;
                            if owner.send_inventory_readback(&query, historical)? {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        },
                        FixedProviderIngressProgressV1::Source(request) => {
                            let (publication, manifest) =
                                ingress.read_current_catalog_manifest()?;
                            let mut storage = ProductionSourceProviderStorageReadbackV1;
                            let mut session = owner.backend_session_with_catalog(
                                &mut storage,
                                &publication,
                                &manifest,
                            );
                            match session.execute_authenticated_source_request(request)? {
                                FixedProviderBackendRequestOutcomeV1::Reply(reply)
                                | FixedProviderBackendRequestOutcomeV1::CachedRecovery {
                                    reply,
                                    ..
                                } => {
                                    session.send_reply(reply)?;
                                }
                                FixedProviderBackendRequestOutcomeV1::RecoveryPending
                                | FixedProviderBackendRequestOutcomeV1::Released { .. } => {
                                    return Err(ProviderLedgerError::Unavailable.into());
                                }
                            }
                        }
                    }
                }
            }
            Err(ProductionSourceProviderIngressErrorV1::Activation(
                ProductionBrokerSessionActivationErrorV1::Deadline,
            )) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

// Ordinary serving keeps its original activation adoption recipe. Selected
// serving captures the exclusive complete INITIAL table below instead.
fn adopt_fixed_ingress()
    -> Result<ProductionSourceProviderIngressV1, SourceProviderDaemonErrorV1>
{
    // SAFETY: process startup is single-threaded and no other owner has
    // claimed systemd FD 3 before exact activation adoption.
    Ok(unsafe { ProductionSourceProviderIngressV1::adopt_systemd()? })
}

fn serve_selected_authenticated_ingress() -> Result<(), SourceProviderDaemonErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(SourceProviderDaemonErrorV1::Identity);
    }

    let mut ingress = ProductionSourceProviderIngressV1::new_selected_initial();
    // SAFETY: serving entry remains single-threaded, no other FD owner or
    // runtime exists, and the same INITIAL scanner exclusively adopts0/1/2/3.
    if unsafe { ingress.capture_selected_initial_once() }.is_err() {
        terminate_selected_ingress(&mut ingress);
    }
    let deadline_result = production_deadline_after(ACCEPT_TIMEOUT);
    let deadline = match &deadline_result {
        Ok(deadline) => *deadline,
        _ => terminate_selected_ingress(&mut ingress),
    };
    match ingress.accept_selected_pending_owner(deadline) {
        Ok(original) => serve_selected_original(&mut ingress, original),
        Err(cause) => {
            // The returned outer marker remains alongside real nested native
            // custody until intentional death. No failed selected accept retries.
            let _cause = cause;
            terminate_selected_ingress(&mut ingress)
        }
    }
}

// The genuine accepted socket is already in this value before role, protected
// file, catalog, Journal or HELLO effects. Returned failures remain nested in
// that same owner. No selected error enters the consuming legacy route.
struct SelectedSourceDaemonFlightV1<'owner> {
    ingress: &'owner mut ProductionSourceProviderIngressV1,
    original: ProductionSelectedSourceProviderOriginalV1,
}

impl Drop for SelectedSourceDaemonFlightV1<'_> {
    fn drop(&mut self) {
        self.ingress.end_selected_initial();
        self.original.end_original();
    }
}

fn serve_selected_original(
    ingress: &mut ProductionSourceProviderIngressV1,
    original: ProductionSelectedSourceProviderOriginalV1,
) -> ! {
    let mut flight = SelectedSourceDaemonFlightV1 { ingress, original };
    if flight.original.open_once(flight.ingress).is_err() {
        terminate_selected_original(flight.ingress, &mut flight.original);
    }

    loop {
        match flight.original.advance_opening(flight.ingress) {
            Ok(FixedSelectedProviderProgressV1::Pending) => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Ok(FixedSelectedProviderProgressV1::OriginalCurrent) => break,
            Err(_) => terminate_selected_original(flight.ingress, &mut flight.original),
        }
    }

    let mut paired = false;
    loop {
        if !paired {
            match flight.original.advance_original_ingress(flight.ingress) {
                Ok(FixedProviderIngressProgressV1::Pending)
                | Ok(FixedProviderIngressProgressV1::CatalogReplied)
                | Ok(FixedProviderIngressProgressV1::OriginalRootPreparedRetained) => {}
                Ok(FixedProviderIngressProgressV1::OriginalPairRetained) => {
                    // The pair stays inside the selected original owner. Its
                    // narrow driver uses the accepted same-original engine.
                    paired = true;
                }
                Ok(_) => {
                    terminate_selected_original(flight.ingress, &mut flight.original);
                }
                Err(_) => terminate_selected_original(flight.ingress, &mut flight.original),
            }
        } else {
            match flight.original.advance_original_native_completion(flight.ingress) {
                Ok(FixedProviderOriginalCompletionProgressV5::Pending)
                | Ok(FixedProviderOriginalCompletionProgressV5::CompleteCommitted)
                | Ok(FixedProviderOriginalCompletionProgressV5::HeldStored)
                | Ok(FixedProviderOriginalCompletionProgressV5::ProviderHeldSent)
                | Ok(FixedProviderOriginalCompletionProgressV5::CompleteSent)
                | Ok(FixedProviderOriginalCompletionProgressV5::RootDispositionPrepared)
                | Ok(FixedProviderOriginalCompletionProgressV5::RelayStored)
                | Ok(FixedProviderOriginalCompletionProgressV5::RelaySent)
                | Ok(FixedProviderOriginalCompletionProgressV5::StorageSettlementRecorded)
                | Ok(FixedProviderOriginalCompletionProgressV5::ProviderSettledPrepared)
                | Ok(FixedProviderOriginalCompletionProgressV5::ProviderSettledStored)
                | Ok(FixedProviderOriginalCompletionProgressV5::ProviderSettledSent)
                | Ok(FixedProviderOriginalCompletionProgressV5::RootTerminalRecorded)
                | Ok(FixedProviderOriginalCompletionProgressV5::ReleaseAdmitted) => {}
                Ok(FixedProviderOriginalCompletionProgressV5::Closed)
                | Err(_) => terminate_selected_original(flight.ingress, &mut flight.original),
            }
        }

        std::thread::sleep(Duration::from_millis(2));
    }
}

fn terminate_selected_ingress(ingress: &mut ProductionSourceProviderIngressV1) -> ! {
    ingress.end_selected_initial();
    eprintln!("aos-source-providerd: selected Source INITIAL failed");
    std::process::exit(1)
}

fn terminate_selected_original(
    ingress: &mut ProductionSourceProviderIngressV1,
    original: &mut ProductionSelectedSourceProviderOriginalV1,
) -> ! {
    ingress.end_selected_initial();
    original.end_original();
    // No raw body, key, path, FD or remote error string is emitted. The actual
    // owning first cause is still in `original` during this diagnostic and
    // intentional process death. A diagnostic unwind first runs its same-queue
    // shutdown Drop; death is not a Drained or settled-queue receipt.
    eprintln!("aos-source-providerd: selected original Source flight failed");
    std::process::exit(1)
}

// The selected original owner never returns to the consuming legacy route.
// Both an outer typed cause and all nested offer custody stay resident even
// after expiry, ambiguous reply, readback refusal or a diagnostic panic.
fn serve_original_native_completion(
    ingress: &ProductionSourceProviderIngressV1,
    owner: &mut FixedProviderOwnerV1,
) -> ! {
    let mut first_failure = None;
    let _crossing = OriginalStorageOfferDaemonCrossingV5;
    let mut closed = false;
    loop {
        if !closed {
            match ingress.advance_original_native_completion(owner) {
                Ok(FixedProviderOriginalCompletionProgressV5::Pending)
                | Ok(FixedProviderOriginalCompletionProgressV5::CompleteCommitted)
                | Ok(FixedProviderOriginalCompletionProgressV5::HeldStored)
                | Ok(FixedProviderOriginalCompletionProgressV5::ProviderHeldSent)
                | Ok(FixedProviderOriginalCompletionProgressV5::CompleteSent) => {}
                Ok(FixedProviderOriginalCompletionProgressV5::Closed) => {
                    closed = true;
                    if let Some(cause) = owner.original_completion_failure_v5() {
                        eprintln!("original completion remains closed: {cause}");
                    }
                }
                Ok(FixedProviderOriginalCompletionProgressV5::RootDispositionPrepared)
                | Ok(FixedProviderOriginalCompletionProgressV5::RelayStored)
                | Ok(FixedProviderOriginalCompletionProgressV5::RelaySent)
                | Ok(FixedProviderOriginalCompletionProgressV5::StorageSettlementRecorded)
                | Ok(FixedProviderOriginalCompletionProgressV5::ProviderSettledPrepared)
                | Ok(FixedProviderOriginalCompletionProgressV5::ProviderSettledStored)
                | Ok(FixedProviderOriginalCompletionProgressV5::ProviderSettledSent)
                | Ok(FixedProviderOriginalCompletionProgressV5::RootTerminalRecorded)
                | Ok(FixedProviderOriginalCompletionProgressV5::ReleaseAdmitted) => {
                    // This old driver cannot enter the selected receipt purpose.
                    // Refuse any impossible progress without lending a permit.
                    closed = true;
                    owner.close_original_storage_offer_after_failure_v5();
                    eprintln!("original completion remains closed: unexpected Root disposition");
                }
                Err(cause) => {
                    first_failure = Some(cause);
                    closed = true;
                    owner.close_original_storage_offer_after_failure_v5();
                    if let Some(cause) = &first_failure {
                        eprintln!("original completion remains closed: {cause}");
                    }
                }
            }
        }
        // Do not drop an owning outer error after diagnostics or reuse a lane.
        let _resident_cause = &first_failure;
        std::thread::sleep(Duration::from_millis(2));
    }
}

struct OriginalStorageOfferDaemonCrossingV5;

impl Drop for OriginalStorageOfferDaemonCrossingV5 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}
