//! Non-authorizing startup verification of deployed Host backend evidence.
//!
//! Both Host entrypoints call this shared gate. A missing optional phase-0
//! credential preserves observation-only service; a present invalid one fails
//! startup. Successful partial verification never constructs `NspawnConfig`.

use std::path::Path;

use aos_systemd::SystemdClient;

use super::{
    BackendReadinessBlocker, ProtectedBackendReadinessEvidence, VerifiedLiveSelinuxPolicyV1,
};
use crate::{HostError, Result};

/// Verifies every currently implemented, non-authorizing deployment check.
///
/// The protected phase-0 credential is optional because Host observation must
/// remain available before the independent probe/filter/shifted-payload
/// producers exist. A present credential cannot bypass any live check.
///
/// # Errors
///
/// Rejects a malformed or stale credential, packaged executable mismatch,
/// foreign PID 1/service policy, non-enforcing or foreign SELinux policy, or
/// an unexpected change in the explicit launch-blocker set.
pub async fn verify_optional_backend_deployment_v1(
    credential_directory: &Path,
    state_root: &Path,
    nspawn_executable: &str,
    selinux_policy: &str,
) -> Result<()> {
    let Some(readiness) = ProtectedBackendReadinessEvidence::load_protected_optional(
        credential_directory,
        state_root,
        nspawn_executable,
    )?
    else {
        return Ok(());
    };

    let packaged = readiness.verify_packaged_runtime()?;
    let live_mac = VerifiedLiveSelinuxPolicyV1::verify(selinux_policy)?;
    let systemd = SystemdClient::connect()
        .await
        .map_err(|error| HostError::State(format!("PID 1 bus unavailable: {error}")))?;
    packaged
        .verify_live_pid1_service(&readiness, &systemd)
        .await?;
    live_mac.revalidate(selinux_policy)?;

    if readiness.runtime_blockers()
        != [
            BackendReadinessBlocker::Phase0ClaimVerification,
            BackendReadinessBlocker::ShiftedPayloadPidfdNamespaceInspection,
            BackendReadinessBlocker::PayloadRootPolicyDeploymentVerification,
        ]
    {
        return Err(HostError::State(
            "host backend readiness boundary changed without launch wiring".to_owned(),
        ));
    }
    Ok(())
}
