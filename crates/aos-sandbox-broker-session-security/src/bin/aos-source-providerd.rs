//! Runs the systemd-activated SourceProvider catalog and closed source boundary.
//!
//! Startup installs a signed catalog locator from a named systemd credential.
//! The service retains the fixed authenticated owner and answers fresh catalog
//! challenges. A selected LocalLive Acquire may reach authenticated Storage
//! readback; a native selected Acquire remains unavailable. Holder Inventory
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
    install_fixed_source_provider_catalog_credential, production_deadline_after,
};
use aos_sandbox_source_provider::{
    FixedProviderBackendRequestOutcomeV1, FixedProviderIngressProgressV1,
    NativeNoDispatchSettlementV1, ProviderLedgerError,
};
use aos_sandbox_source_provider_security::{
    SourceProviderSecurityError, validate_fixed_provider_authority_v1,
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
        (Some("--check-source-provider-authority"), None) => {
            if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
                return Err(SourceProviderDaemonErrorV1::Identity);
            }
            validate_fixed_provider_authority_v1()?;
            Ok(())
        }
        (None, None) => serve_authenticated_ingress(),
        _ => Err(SourceProviderDaemonErrorV1::Arguments),
    }
}

fn serve_authenticated_ingress() -> Result<(), SourceProviderDaemonErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(SourceProviderDaemonErrorV1::Identity);
    }

    // SAFETY: process startup is single-threaded and no other owner has
    // claimed systemd FD 3 before exact activation adoption.
    let mut ingress = unsafe { ProductionSourceProviderIngressV1::adopt_systemd()? };
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
                        FixedProviderIngressProgressV1::OriginalRootPreparedRetained
                        | FixedProviderIngressProgressV1::OriginalPairRetained => {
                            // No reservation, signing, nonce, bridge or dispatch
                            // capability is available from this classification.
                            std::thread::sleep(Duration::from_millis(2));
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
