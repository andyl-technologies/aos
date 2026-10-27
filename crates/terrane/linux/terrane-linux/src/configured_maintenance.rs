//! Composes configured reconciliation with the original recovered cache owners.
//!
//! Serve binds every protected domain listener before reporting readiness. GC
//! installs confinement before its executor or socket connections and performs
//! one bounded authenticated exchange per domain. Requests contain no cache row,
//! descriptor or closure evidence; only the retained serving owner makes effects.
//! This is draining-exposure reconciliation, not repository or host-tier GC.

use std::{collections::BTreeMap, future::pending, io, path::PathBuf, time::Duration};

use futures_util::{StreamExt, stream::FuturesUnordered};
use terrane_sdk::config::host::HostTier;

use crate::{
    host_cache::{NativeExposureReconciliation, NativeMetadataOwner},
    maintenance_channel::{
        MaintenanceClient, MaintenanceLimits, MaintenanceListener, MaintenanceRoles,
    },
    quota_confinement,
};

/// Retains pure validated role, domain and finite transport inputs.
pub(crate) struct Plan {
    roles: MaintenanceRoles,
    limits: MaintenanceLimits,
    sockets: BTreeMap<String, PathBuf>,
}

impl Plan {
    pub(crate) fn from_host(host: &HostTier) -> io::Result<Option<Self>> {
        let Some(settings) = &host.maintenance else {
            return Ok(None);
        };
        settings.validate(host).map_err(io::Error::other)?;
        let publisher = host
            .publisher
            .as_ref()
            .ok_or_else(|| invalid("maintenance serving identity absent"))?;
        Ok(Some(Self {
            roles: MaintenanceRoles {
                serve_uid: publisher.serve_uid,
                gc_uid: settings.gc_uid,
            },
            limits: MaintenanceLimits {
                max_connections: settings.max_connections,
                max_requests: settings.max_requests,
                connection_timeout: Duration::from_millis(settings.connection_timeout_ms),
                request_timeout: Duration::from_millis(settings.request_timeout_ms),
            },
            sockets: settings
                .sockets
                .iter()
                .map(|(domain, path)| (domain.clone(), PathBuf::from(path)))
                .collect(),
        }))
    }

    /// Binds all configured domains only after exact original-owner coverage.
    pub(crate) fn bind(
        &self,
        owners: &BTreeMap<&str, &NativeMetadataOwner>,
    ) -> io::Result<Bindings> {
        if self
            .sockets
            .keys()
            .map(String::as_str)
            .ne(owners.keys().copied())
        {
            return Err(invalid(
                "maintenance differs from recovered domain inventory",
            ));
        }
        let mut listeners = BTreeMap::new();
        for (domain, path) in &self.sockets {
            listeners.insert(domain.clone(), MaintenanceListener::bind(path, self.roles)?);
        }
        Ok(Bindings {
            listeners,
            limits: self.limits,
        })
    }
}

/// Keeps the original protected listener inodes through every accepted exchange.
pub(crate) struct Bindings {
    listeners: BTreeMap<String, MaintenanceListener>,
    limits: MaintenanceLimits,
}

impl Bindings {
    /// Retires every original name after all borrowed request futures have ended.
    pub(crate) fn retire(self) -> io::Result<()> {
        let mut failure = None;
        for listener in self.listeners.into_values() {
            if let Err(error) = listener.retire() {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Borrows the original owners without detached connection tasks.
    pub(crate) async fn serve(
        &self,
        owners: &BTreeMap<&str, &NativeMetadataOwner>,
    ) -> io::Result<()> {
        let mut services = FuturesUnordered::new();
        for (domain, listener) in &self.listeners {
            let owner = owners
                .get(domain.as_str())
                .ok_or_else(|| invalid("maintenance lost original domain owner"))?;
            services.push(listener.serve_until(owner, self.limits, pending()));
        }
        match services.next().await {
            Some(Err(error)) => Err(error),
            Some(Ok(())) | None => Err(invalid("configured maintenance listener stopped")),
        }
    }
}

/// Reports one actual original-owner response without granting release authority.
#[derive(Debug)]
pub struct DomainReconciliation {
    /// Canonical configured domain whose original owner handled the request.
    pub domain: String,
    /// Native owner counts; retained obligations remain owned by that process.
    pub reconciliation: NativeExposureReconciliation,
}

/// Requests one bounded draining reconciliation from each configured serving owner.
///
/// Validates the complete host-maintenance composition before confinement,
/// executor creation or socket I/O. The calling process must be fresh and
/// single-threaded, with the configured GC identity and no capabilities. It
/// opens no repository, token, signing key or private cache state. A partial
/// result is never reported as success; already accepted native work retains its
/// original owner and durable obligations even after client failure or shutdown.
/// Socket names are never removed, replaced or rebound by GC.
/// All domains share the configured request deadline for the entire pass;
/// SIGINT and SIGTERM cancel outstanding transport and return interruption.
///
/// # Errors
/// Rejects missing/invalid maintenance inputs, a different GC identity or an
/// existing executor. Returns confinement, executor, protected-path, peer,
/// transport, deadline or original-owner failures. Failure after confinement
/// installation requires process termination rather than another role or retry.
pub fn run_configured_gc(host: &HostTier) -> io::Result<Vec<DomainReconciliation>> {
    let plan = Plan::from_host(host)?
        .ok_or_else(|| invalid("host GC requires explicit maintenance endpoints"))?;
    if rustix::process::geteuid().as_raw() != plan.roles.gc_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "configured maintenance GC identity differs",
        ));
    }
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(invalid("maintenance startup requires a fresh process"));
    }
    let installed = quota_confinement::install()?;
    installed.check_current()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let exchange = async {
            let mut responses = Vec::with_capacity(plan.sockets.len());
            for (domain, path) in &plan.sockets {
                installed.check_current()?;
                let client = MaintenanceClient::connect(path, plan.roles)?;
                let reconciliation = client
                    .reconcile_draining_once(plan.limits.request_timeout)
                    .await?;
                responses.push(DomainReconciliation {
                    domain: domain.clone(),
                    reconciliation,
                });
            }
            Ok(responses)
        };
        // All domains share a finite pass budget. Cancelling an accepted request
        // closes transport; it cannot cancel the original owner's physical work.
        tokio::select! {
            biased;
            _ = terminate.recv() => Err(io::ErrorKind::Interrupted.into()),
            _ = interrupt.recv() => Err(io::ErrorKind::Interrupted.into()),
            result = tokio::time::timeout(plan.limits.request_timeout, exchange) => {
                result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            }
        }
    });
    drop(runtime);
    installed.check_current()?;
    result
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
