//! Runs the shared consuming PID1 property read used by fixed role recipes.
//!
//! The worker owns its runtime and connection through completion and join. This
//! ordinary transport returns property DATA; it establishes no role admission,
//! receiving payment, retained observer interval or currentness authority.

use std::time::Duration;

use crate::{OwnedValue, SystemdClient};

const UNIT_PROPERTIES: &[&str] = &["FragmentPath", "DropInPaths", "Transient", "InvocationID"];

/// Selects one existing ordinary PID1 connection recipe.
#[derive(Clone, Copy)]
pub enum Pid1PropertyReadRecipeV1 {
    /// Uses the existing ordinary systemd manager connection.
    Legacy,
    /// Uses the fixed Nix offline hardware observer connection.
    NixOfflineHardware,
}

/// Preserves the ordinary coarse refusal of the consuming worker.
#[derive(Debug, thiserror::Error)]
#[error("PID1 property observation refused")]
pub struct Pid1PropertyReadErrorV1;

/// Reads service properties and the same four unit properties on one worker.
///
/// The original worker name, five-second timeout, connection selection and
/// runtime/connection/thread destruction order are preserved. Callers retain
/// their fixed role and property predicates; this function provides DATA only.
///
/// # Errors
/// Returns an error if worker creation, runtime construction, connection,
/// property observation, timeout or worker join fails.
pub fn read_pid1_startup_properties_v1(
    unit_name: &'static str,
    pid: u32,
    properties: &'static [&'static str],
    recipe: Pid1PropertyReadRecipeV1,
) -> Result<(Vec<OwnedValue>, Vec<OwnedValue>), Pid1PropertyReadErrorV1> {
    std::thread::Builder::new()
        .name("normal-root-pid1-readback".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Pid1PropertyReadErrorV1)?;
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    let manager = match recipe {
                        Pid1PropertyReadRecipeV1::Legacy => SystemdClient::connect().await,
                        Pid1PropertyReadRecipeV1::NixOfflineHardware => {
                            SystemdClient::connect_nix_offline_hardware_observer().await
                        }
                    }
                        .map_err(|_| Pid1PropertyReadErrorV1)?;
                    manager
                        .observe_pid1_service_startup_properties(
                            unit_name,
                            pid,
                            properties,
                            UNIT_PROPERTIES,
                        )
                        .await
                        .map_err(|_| Pid1PropertyReadErrorV1)
                })
                .await
                .map_err(|_| Pid1PropertyReadErrorV1)?
            })
        })
        .map_err(|_| Pid1PropertyReadErrorV1)?
        .join()
        .map_err(|_| Pid1PropertyReadErrorV1)?
}
