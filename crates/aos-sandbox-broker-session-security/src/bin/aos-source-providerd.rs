//! Runs the systemd-activated SourceProvider catalog and closed source boundary.
//!
//! Startup installs a signed catalog locator from a named systemd credential.
//! The service retains the fixed authenticated owner and answers fresh catalog
//! challenges. A selected LocalLive Acquire may reach authenticated Storage
//! readback. Holder Inventory uses the fixed owner's durable admission and
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
    FixedProviderBackendRequestOutcomeV1, FixedProviderIngressProgressV1, ProviderLedgerError,
};

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
enum SourceProviderDaemonErrorV1 {
    #[error("usage: aos-source-providerd [--install-catalog]")]
    Arguments,
    #[error("catalog installation failed: {0}")]
    Catalog(#[from] ProductionSourceProviderCatalogInstallErrorV1),
    #[error("SourceProvider requires real and effective UID zero")]
    Identity,
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
                    match ingress.advance_authenticated_ingress(&mut owner)? {
                        FixedProviderIngressProgressV1::Pending => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        FixedProviderIngressProgressV1::CatalogReplied => {}
                        FixedProviderIngressProgressV1::Recovery(query) => {
                            let (publication, manifest) =
                                ingress.read_current_catalog_manifest()?;
                            let mut storage = ProductionSourceProviderStorageReadbackV1;
                            let mut session = owner.backend_session_with_catalog(
                                &mut storage,
                                &publication,
                                &manifest,
                            );
                            let signed_plan_digest =
                                session.inspect_selected_storage_recovery_for_query(&query)?;
                            drop(session);

                            // The answer is a fresh-session, descriptor-free
                            // observation. Applying stays pending for a later
                            // explicit resolution; no old response is replayed.
                            while !owner.send_recovery_unavailable(&query, signed_plan_digest)? {
                                std::thread::sleep(Duration::from_millis(2));
                            }
                        }
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
