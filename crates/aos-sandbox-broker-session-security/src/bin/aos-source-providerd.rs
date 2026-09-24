//! Runs the systemd-activated SourceProvider catalog-currentness boundary.
//!
//! Startup installs a signed catalog locator from a named systemd credential.
//! The service retains the fixed authenticated owner and answers only fresh
//! catalog-currentness challenges. It deliberately does not dispatch backend
//! or source effect requests.

use std::process::ExitCode;
use std::time::Duration;

use aos_sandbox_broker_session_security::{
    ProductionBrokerDeadlineErrorV1, ProductionBrokerSessionActivationErrorV1,
    ProductionSourceProviderCatalogInstallErrorV1, ProductionSourceProviderIngressErrorV1,
    ProductionSourceProviderIngressV1, install_fixed_source_provider_catalog_credential,
    production_deadline_after,
};
use aos_sandbox_source_provider::FixedProviderCatalogProgressV1;

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
        (None, None) => serve_catalog_currentness(),
        _ => Err(SourceProviderDaemonErrorV1::Arguments),
    }
}

fn serve_catalog_currentness() -> Result<(), SourceProviderDaemonErrorV1> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err(SourceProviderDaemonErrorV1::Identity);
    }

    // SAFETY: process startup is single-threaded and no other owner has
    // claimed systemd FD 3 before exact activation adoption.
    let mut ingress = unsafe { ProductionSourceProviderIngressV1::adopt_systemd()? };
    loop {
        let deadline = production_deadline_after(ACCEPT_TIMEOUT)?;
        match ingress.accept_authenticated_owner(deadline) {
            Ok((mut owner, _report)) => loop {
                match ingress.advance_catalog_currentness(&mut owner)? {
                    FixedProviderCatalogProgressV1::Pending => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    FixedProviderCatalogProgressV1::Replied => {}
                }
            },
            Err(ProductionSourceProviderIngressErrorV1::Activation(
                ProductionBrokerSessionActivationErrorV1::Deadline,
            )) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}
