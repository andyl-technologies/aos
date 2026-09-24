//! Readback of the installed nspawn supervisor service envelope.
//!
//! PID 1's live properties are checked independently of the protected
//! publisher claim. This is a partial proof: descriptor values, the complete
//! transient property program, and payload kernel state are not covered.

use aos_systemd::{OwnedValue, PayloadRootContinuityPolicyV1, SandboxUnitSpec, SystemdClient};

use super::{
    ProtectedBackendReadinessEvidence, ReadinessBindingIdentityV1, VerifiedPackagedRuntimeV1,
};
use crate::{HostError, Result};

/// Retains a live PID 1 readback of the fixed supervisor service envelope.
///
/// This proof covers selected scalar properties of one running unit. It
/// cannot create [`crate::plan::BackendReadiness`].
pub struct VerifiedLiveSupervisorPolicyV1 {
    binding_identity: ReadinessBindingIdentityV1,
    unit_semantics_digest: [u8; 32],
    supervisor_pid: u32,
}

const SUPERVISOR_SERVICE_PROPERTIES: &[&str] = &[
    "Type",
    "NotifyAccess",
    "Delegate",
    "DelegateSubgroup",
    "Restart",
    "KillMode",
    "CapabilityBoundingSet",
    "ProtectSystem",
    "SELinuxContext",
    "LockPersonality",
    "PrivateTmp",
    "DevicePolicy",
];

impl VerifiedPackagedRuntimeV1 {
    /// Checks one running nspawn supervisor's PID 1 service policy.
    ///
    /// The typed unit specification and admitted package must name the same
    /// executable. PID 1's unique bus owner, unit invocation, and main PID
    /// are checked around the property read. This does not attest a phase-0
    /// payload or make [`crate::plan::BackendReadiness`] constructible.
    ///
    /// # Errors
    ///
    /// Rejects a changed package, mismatched specification, absent or changed
    /// live unit, malformed properties, or a policy different from the sealed
    /// compiler projection.
    pub async fn verify_live_supervisor_policy(
        &self,
        evidence: &ProtectedBackendReadinessEvidence,
        systemd: &SystemdClient,
        spec: &SandboxUnitSpec,
        supervisor_pid: u32,
    ) -> Result<VerifiedLiveSupervisorPolicyV1> {
        self.revalidate(evidence)?;
        let policy = spec.payload_root_continuity_policy();
        if spec.executable() != evidence.binding.executable_path
            || policy.digest() != self.policy_digest
        {
            return Err(HostError::State(
                "supervisor specification differs from packaged readiness".to_owned(),
            ));
        }

        let values = systemd
            .observe_pid1_service_properties(
                spec.name().as_str(),
                supervisor_pid,
                SUPERVISOR_SERVICE_PROPERTIES,
            )
            .await
            .map_err(|error| HostError::State(format!("supervisor readback failed: {error}")))?;
        verify_live_supervisor_properties(&values, policy)?;
        self.revalidate(evidence)?;

        Ok(VerifiedLiveSupervisorPolicyV1 {
            binding_identity: self.binding_identity,
            unit_semantics_digest: spec.semantic_digest_v1(),
            supervisor_pid,
        })
    }
}

impl VerifiedLiveSupervisorPolicyV1 {
    /// Repeats the live unit and package checks for the admitted supervisor.
    ///
    /// # Errors
    ///
    /// Rejects a changed specification, PID, package, boot, or installed
    /// service policy.
    pub async fn revalidate(
        &self,
        packaged: &VerifiedPackagedRuntimeV1,
        evidence: &ProtectedBackendReadinessEvidence,
        systemd: &SystemdClient,
        spec: &SandboxUnitSpec,
        supervisor_pid: u32,
    ) -> Result<()> {
        if self.binding_identity != packaged.binding_identity
            || self.unit_semantics_digest != spec.semantic_digest_v1()
            || self.supervisor_pid != supervisor_pid
        {
            return Err(HostError::State(
                "supervisor policy readback changed after verification".to_owned(),
            ));
        }
        packaged
            .verify_live_supervisor_policy(evidence, systemd, spec, supervisor_pid)
            .await?;
        Ok(())
    }
}

fn verify_live_supervisor_properties(
    values: &[OwnedValue],
    policy: PayloadRootContinuityPolicyV1,
) -> Result<()> {
    let [
        service_type,
        notify_access,
        delegate,
        delegate_subgroup,
        restart,
        kill_mode,
        capabilities,
        protect_system,
        selinux_context,
        lock_personality,
        private_tmp,
        device_policy,
    ] = values
    else {
        return Err(HostError::State(
            "supervisor service readback is incomplete".to_owned(),
        ));
    };
    let is_string = |value: &OwnedValue, expected: &str| {
        <&str>::try_from(value).is_ok_and(|actual| actual == expected)
    };
    let is_true = |value: &OwnedValue| bool::try_from(value) == Ok(true);
    if !is_string(service_type, "notify")
        || !is_string(notify_access, "main")
        || !is_true(delegate)
        || !is_string(delegate_subgroup, "supervisor")
        || !is_string(restart, "no")
        || !is_string(kill_mode, "mixed")
        || u64::try_from(capabilities) != Ok(policy.supervisor_capability_bounding_set())
        || !is_string(protect_system, "strict")
        || !is_string(selinux_context, policy.supervisor_selinux_context())
        || !is_true(lock_personality)
        || !is_true(private_tmp)
        || !is_string(device_policy, "closed")
    {
        return Err(HostError::State(
            "PID 1 supervisor policy differs from the compiled profile".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_supervisor_policy_rejects_each_changed_property() {
        let policy = PayloadRootContinuityPolicyV1::fixed();
        let string = |value: &str| OwnedValue::try_from(aos_systemd::Value::from(value)).unwrap();
        let values = vec![
            string("notify"),
            string("main"),
            OwnedValue::from(true),
            string("supervisor"),
            string("no"),
            string("mixed"),
            OwnedValue::from(policy.supervisor_capability_bounding_set()),
            string("strict"),
            string(policy.supervisor_selinux_context()),
            OwnedValue::from(true),
            OwnedValue::from(true),
            string("closed"),
        ];
        assert!(verify_live_supervisor_properties(&values, policy).is_ok());

        for position in 0..values.len() {
            let mut changed = values
                .iter()
                .map(OwnedValue::try_clone)
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            changed[position] = OwnedValue::from(false);
            assert!(verify_live_supervisor_properties(&changed, policy).is_err());
        }

        let mut changed = values
            .iter()
            .map(OwnedValue::try_clone)
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        changed[6] = OwnedValue::from(policy.supervisor_capability_bounding_set() | (1 << 11));
        assert!(verify_live_supervisor_properties(&changed, policy).is_err());

        changed[6] = OwnedValue::from(policy.supervisor_capability_bounding_set());
        changed[8] = string("system_u:system_r:foreign_t:s0");
        assert!(verify_live_supervisor_properties(&changed, policy).is_err());
        assert!(verify_live_supervisor_properties(&values[..11], policy).is_err());
    }
}
