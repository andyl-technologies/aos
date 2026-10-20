//! Owns the dedicated, bounded transport-only Gateway service lifecycle.
//!
//! Exactly two stable residents borrow one fixed credential acceptor. The
//! existing transport, original-request, funding and disposal engines remain
//! sole owners. There is no response, READY callback, Git effect, remote Drain
//! receipt or authority conversion. Hard service memcg limits and known body
//! funding are distinct from advisory live node-memory admission. This profile
//! promises no hard all-node network bound or per-project Git operation budget.

use std::sync::Arc;

use crate::public_api_session::PublicApiSessionAcceptor;

use super::gateway_registry::GatewayTransportRegistryV1;

pub(super) mod startup;

use startup::{GatewayAdmissionV1, GatewayListenerV1, GatewayStartupV1};

/// Reports a redacted failure of the fixed transport-only service.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GitGatewayServiceErrorV1 {
    /// Fixed arguments or environment do not select the closed service role.
    #[error("Gateway configuration rejected")]
    Configuration,
    /// The original process launch table is unavailable or contains foreign FDs.
    #[error("Gateway initial descriptor custody rejected")]
    InheritedDescriptors,
    /// The retained task, cgroup or effective hard limits are unavailable or changed.
    #[error("Gateway kernel service envelope rejected")]
    KernelEnvelope,
    /// PID1 delivery or the original service invocation is unavailable or changed.
    #[error("Gateway original PID1 service rejected")]
    Service,
    /// Original immutable executable or unit-fragment custody does not hold.
    #[error("Gateway immutable image custody rejected")]
    Image,
    /// The actual enforcing subject or selected-kernel policy does not match.
    #[error("Gateway enforcing MAC readback rejected")]
    Mac,
    /// Fixed credential delivery or the existing acceptor rejects its inputs.
    #[error("Gateway fixed credential delivery rejected")]
    Credentials,
    /// A stronger node-network profile is unavailable; retained for compatibility.
    #[error("Gateway node-network envelope producer is not implemented")]
    NodeNetworkEnvelopeMissing,
    /// The original procfs/meminfo objects or bounded kernel estimate are unavailable.
    #[error("Gateway original node-memory observation rejected")]
    NodeMemoryObservation,
    /// A fresh available-memory estimate is below the selected admission minimum.
    #[error("Gateway observed node-memory pressure rejected admission")]
    NodeMemoryPressure,
    /// The sole original numeric TCP listener is unavailable or changed.
    #[error("Gateway original listener rejected")]
    Listener,
    /// The bounded service runtime or stop observation is unavailable.
    #[error("Gateway runtime or stop observation unavailable")]
    Runtime,
    /// A cancelled or unwound original service readback closes admission.
    #[error("Gateway original service readback interrupted")]
    Interrupted,
    /// Local shutdown debt prevents admission; this is not a remote Drain result.
    #[error("Gateway local transport shutdown debt observed")]
    LocalShutdownDebt,
    /// Original resident accounting release failed; capacity is not reused.
    #[error("Gateway local retirement accounting rejected")]
    Retirement,
}

/// Runs only the installed Gateway's fixed-environment transport lifecycle.
///
/// Requires an explicit service-memcg/observed-node-memory profile and minimum,
/// the original fixed PID1 owner, and fresh observations before TCP binding and
/// at acceptance/processing bookends. Observations may race other allocations;
/// they are not reserved capacity, a hard node limit or guaranteed headroom.
/// This transport lifecycle neither authorizes Git nor returns a successful Git
/// response. Project operation budgets and the backend remain separate work.
///
/// # Errors
///
/// Rejects foreign launch FDs, configuration, PID1 delivery, original images,
/// credentials, MAC, task/cgroup hard limits, original node-memory observations,
/// observed pressure below the explicit minimum, listener custody, transport
/// shutdown debt or accounting release.
///
/// # Panics
///
/// Tokio, TLS and H2 providers may panic. Ordinary driving loans unwind before
/// local disposal. The selected inspection lifecycle aborts on abandonment
/// before retained fields drop; crash, abort and OOM recovery are not claimed.
pub fn run_git_gateway_transport_from_environment_v1() -> Result<(), GitGatewayServiceErrorV1> {
    // This one-shot table observation precedes every reactor or retained open.
    let startup = GatewayStartupV1::capture()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| GitGatewayServiceErrorV1::Runtime)?;

    runtime.block_on(async {
        let admission = startup.admit().await?;
        let listener = admission.bind_listener().await?;

        admission.recheck().await?;
        let acceptor = Arc::new(
            PublicApiSessionAcceptor::from_systemd_credentials()
                .map_err(|_| GitGatewayServiceErrorV1::Credentials)?,
        );
        admission.recheck().await?;
        let mut residents = GatewayResidentsV1::new(acceptor);
        if admission.delegation_controller_ids().is_some() {
            residents.inspection_selected = true;
            residents.first.select_delegated_read();
            residents.second.select_delegated_read();
        }
        let mut stop = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| GitGatewayServiceErrorV1::Runtime)?;

        // No spawn, detached task, dynamic resident list or per-peer queue.
        // This inner scope destroys borrowing driver futures before retirement.
        let driven = {
            let both = async {
                tokio::try_join!(
                    drive_slot(&mut residents.first, &listener, &admission),
                    drive_slot(&mut residents.second, &listener, &admission),
                )?;
                Ok::<(), GitGatewayServiceErrorV1>(())
            };
            tokio::pin!(both);
            tokio::select! {
                biased;
                stopped = stop.recv() => {
                    stopped.ok_or(GitGatewayServiceErrorV1::Runtime).map(|_| ())
                }
                result = &mut both => result,
            }
        };

        // Try both residents even if the first release fails. No replacement
        // registry is constructed to erase either original debt.
        if admission.delegation_controller_ids().is_some() && driven.is_err() {
            // Terminal inspection errors retain the actual local channel,
            // original HTTP/TLS graph and first cause until process exit.
            std::process::exit(1);
        }
        let retired = residents.retire();
        driven?;
        retired
    })
}

struct GatewayResidentsV1 {
    inspection_selected: bool,
    first: GatewayTransportRegistryV1,
    second: GatewayTransportRegistryV1,
    retirement_attempted: bool,
}

impl GatewayResidentsV1 {
    fn new(acceptor: Arc<PublicApiSessionAcceptor>) -> Self {
        Self {
            inspection_selected: false,
            first: GatewayTransportRegistryV1::from_fixed_acceptor(Arc::clone(&acceptor)),
            second: GatewayTransportRegistryV1::from_fixed_acceptor(acceptor),
            retirement_attempted: false,
        }
    }

    fn retire(&mut self) -> Result<(), GitGatewayServiceErrorV1> {
        self.retirement_attempted = true;
        let first = retire_slot(&mut self.first);
        let second = retire_slot(&mut self.second);
        first?;
        second
    }
}

impl Drop for GatewayResidentsV1 {
    fn drop(&mut self) {
        if self.inspection_selected && !self.retirement_attempted {
            // Abort before fields release on abandonment or uncaught unwind.
            // Ordinary transport disposal and explicit local retirement retain
            // their existing order; this fence proves neither recovery nor Drain.
            std::process::abort();
        }
        // Bounded synchronous disposal also covers unwind after driver loans
        // drop. Errors never authorize reuse, restart or a remote Drain ACK.
        if !self.retirement_attempted {
            let _ = self.retire();
        }
    }
}

async fn drive_slot(
    registry: &mut GatewayTransportRegistryV1,
    listener: &GatewayListenerV1,
    admission: &GatewayAdmissionV1,
) -> Result<(), GitGatewayServiceErrorV1> {
    loop {
        admission.recheck().await?;
        listener.recheck()?;

        // prepare() funds the actual body allocation before this future exists.
        // Cancellation uses the already-existing armed original loan guards.
        let accepted = registry.accept_original(listener.listener()).await.is_ok();
        if accepted {
            admission.recheck().await?;
            listener.recheck()?;

            if registry.drive_handshake().await.is_ok() {
                admission.recheck().await?;
                listener.recheck()?;
                match registry.receive_original().await {
                    Ok(mut ready) => {
                        admission.recheck().await?;
                        listener.recheck()?;

                        // Do not retain the returned error outside this scope:
                        // it may own the transport's actual first Arc cause.
                        if admission.delegation_controller_ids().is_some() {
                            ready.inspect_delegated(admission).await?;
                        } else {
                            let current = ready.recheck().await;
                            drop(current);
                        }
                        admission.recheck().await?;
                        drop(ready);
                    }
                    Err(_) => {}
                }
            }
        }

        // The actual first cause remains borrowed inside this resident until
        // this deliberate local retirement. No diagnostic body/peer escapes.
        let resident_cause = registry.failure();
        drop(resident_cause);
        retire_slot(registry)?;
    }
}

fn retire_slot(
    registry: &mut GatewayTransportRegistryV1,
) -> Result<(), GitGatewayServiceErrorV1> {
    let disposed = registry
        .dispose_local()
        .map_err(|_| GitGatewayServiceErrorV1::Retirement)?;
    if disposed.shutdown_debt_observed() {
        return Err(GitGatewayServiceErrorV1::LocalShutdownDebt);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_error_is_finite_and_redacted() {
        assert_eq!(
            GitGatewayServiceErrorV1::NodeNetworkEnvelopeMissing.to_string(),
            "Gateway node-network envelope producer is not implemented",
        );
        assert_eq!(
            GitGatewayServiceErrorV1::NodeMemoryObservation.to_string(),
            "Gateway original node-memory observation rejected",
        );
        assert_eq!(
            GitGatewayServiceErrorV1::NodeMemoryPressure.to_string(),
            "Gateway observed node-memory pressure rejected admission",
        );
    }

    #[test]
    fn two_local_body_charges_are_not_the_service_envelope() {
        let one = (256_u64 * 1024 * 1024) + (16 * 1024);
        assert_eq!(2 * one, 536_903_680);
        assert!(2 * one < startup::MEMORY_MAX_BYTES);
        // This inequality proves no headroom or attribution of opaque bytes.
    }
}
