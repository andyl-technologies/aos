//! Backend-keyed architectural continuation without physical CPU microstate.
//!
//! This schema is deliberately distinct from exact SIM continuation. It commits
//! to all exposed state and retained effects, but does not promise identical
//! future CPU retirement, host scheduling, cache or speculative state.

use std::collections::BTreeSet;

use crucible_node_contract::{ContentRef, HashRef, Id, Position, U64, Validate};
use serde::{Deserialize, Serialize};

use super::clock::KvmFrozenClock;
use super::{KvmArchitecture, KvmProfileError};

/// Keys architectural continuation to one native implementation and realization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvmCaptureIdentity {
    /// Selects the native CPU state and device ABI.
    pub architecture: KvmArchitecture,
    /// Binds the actual kernel implementation, including mediation patches.
    pub kernel_build_ref: HashRef,
    /// Binds the actual QEMU executable and state serialization implementation.
    pub emulator_build_ref: HashRef,
    /// Binds the realized CPU model, topology, firmware and devices.
    pub configuration_ref: HashRef,
    /// Binds the qualified architectural capture schema and clock policy.
    pub capture_profile_ref: HashRef,
}

impl KvmCaptureIdentity {
    fn validate(&self) -> Result<(), KvmProfileError> {
        self.kernel_build_ref.validate()?;
        self.emulator_build_ref.validate()?;
        self.configuration_ref.validate()?;
        self.capture_profile_ref.validate()?;
        Ok(())
    }
}

/// Commits to one indivisible native CPU or device owner's exposed state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvmCapturedState {
    /// Identifies the owner within the authenticated realized inventory.
    pub owner_id: Id,
    /// References complete exposed state using its qualified serialization schema.
    pub state_ref: ContentRef,
}

/// Describes a closed architectural cut with explicit native implementation keys.
///
/// Restoration creates fresh VM, vCPU and device objects. Serialized content
/// cannot include live descriptors, `kvm_run` mappings or parent execution
/// handles. The host must resolve and authenticate every referenced object and
/// the actual unchanged-cut receipt before invoking any native restoration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvmArchitecturalCapture {
    /// Selects version one of the weaker native architectural schema.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// States the exact advertised scope; only `architectural-v1` is admitted.
    pub capture_scope: String,
    /// Binds the original implementation and realized configuration.
    pub implementation: KvmCaptureIdentity,
    /// Records the closed coordinator boundary without advancing guest execution.
    pub cut: Position,
    /// Preserves frozen controller time without a host clock epoch.
    pub frozen_clock: KvmFrozenClock,
    /// Records the old incarnation generation for provenance, never fresh authority.
    pub captured_generation: U64,
    /// Commits to each exposed vCPU register, feature and extended-state domain.
    pub vcpus: Vec<KvmCapturedState>,
    /// Commits to every realized device and interrupt-controller state owner.
    pub devices: Vec<KvmCapturedState>,
    /// Commits to complete guest RAM under the qualified memory capture schema.
    pub memory_ref: ContentRef,
    /// Commits to pending timers, interrupts and unfinished exit-emulation disposition.
    pub native_pending_ref: ContentRef,
    /// Commits to input, output, outstanding I/O and publication custody ledgers.
    pub effect_custody_ref: ContentRef,
    /// Commits to unchanged-cut native pause and complete owner-domain proof.
    pub capture_receipt_ref: ContentRef,
}

impl KvmArchitecturalCapture {
    /// Checks backend keys and complete state membership before resolving content.
    ///
    /// Inventories must come from independently authenticated realization. This
    /// syntax and identity check grants no native restore or execution authority.
    /// Physical CPU microstate and identical future execution remain outside scope.
    ///
    /// # Errors
    /// Refuses exact-state claims, incompatible implementations, invalid cuts or
    /// references, future frozen timestamps, and missing, extra or duplicate owners.
    pub fn validate_for(
        &self,
        target: &KvmCaptureIdentity,
        realized_vcpus: &BTreeSet<Id>,
        realized_devices: &BTreeSet<Id>,
    ) -> Result<(), KvmProfileError> {
        if self.schema_version != 1
            || self.capture_scope != "architectural-v1"
            || self.captured_generation.get() == 0
            || &self.implementation != target
        {
            return Err(KvmProfileError::Identity {
                field: "architectural capture implementation/scope/generation",
            });
        }

        self.implementation.validate()?;
        target.validate()?;
        self.cut.validate()?;
        self.frozen_clock.policy.validate()?;
        if self.frozen_clock.current_ps > self.cut.time_ps {
            return Err(KvmProfileError::Identity {
                field: "frozen counter exceeds capture cut",
            });
        }

        if realized_vcpus.is_empty() {
            return Err(KvmProfileError::Identity {
                field: "architectural capture has no realized vCPUs",
            });
        }
        validate_states(&self.vcpus, realized_vcpus)?;
        validate_states(&self.devices, realized_devices)?;
        self.memory_ref.validate()?;
        self.native_pending_ref.validate()?;
        self.effect_custody_ref.validate()?;
        self.capture_receipt_ref.validate()?;
        Ok(())
    }
}

fn validate_states(
    states: &[KvmCapturedState],
    inventory: &BTreeSet<Id>,
) -> Result<(), KvmProfileError> {
    if states.len() > crucible_node_contract::MAX_ARRAY_ELEMENTS {
        return Err(KvmProfileError::Identity {
            field: "native capture owner bound",
        });
    }
    let mut previous = None;
    let mut observed = BTreeSet::new();
    for state in states {
        state.state_ref.validate()?;
        if previous.is_some_and(|id: &Id| id >= &state.owner_id) {
            return Err(KvmProfileError::Identity {
                field: "native capture owner order",
            });
        }
        previous = Some(&state.owner_id);
        observed.insert(state.owner_id.clone());
    }
    if &observed != inventory {
        return Err(KvmProfileError::Identity {
            field: "native capture complete owner membership",
        });
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These capture tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use crucible_node_contract::{Phase, canonical};

    use super::*;
    use crate::kvm_profile::clock::KvmClockPolicy;

    fn fixture() -> KvmArchitecturalCapture {
        let hash = canonical::hash("cnp.kvm-test-identity.v1", b"implementation").unwrap();
        let content = ContentRef {
            hash: canonical::hash("cnp.blob.v1", b"state").unwrap(),
            length: U64::new(5),
            media_type: "application/octet-stream".to_owned(),
        };
        KvmArchitecturalCapture {
            schema_version: 1,
            capture_scope: "architectural-v1".to_owned(),
            implementation: KvmCaptureIdentity {
                architecture: KvmArchitecture::X86_64,
                kernel_build_ref: hash.clone(),
                emulator_build_ref: hash.clone(),
                configuration_ref: hash.clone(),
                capture_profile_ref: hash,
            },
            cut: Position {
                time_ps: U64::new(1000),
                microstep: U64::new(0),
                phase: Phase::Publication,
            },
            frozen_clock: KvmFrozenClock {
                policy: KvmClockPolicy {
                    logical_ps_numerator: U64::new(1000),
                    host_ns_denominator: U64::new(1),
                },
                current_ps: U64::new(500),
            },
            captured_generation: U64::new(1),
            vcpus: vec![KvmCapturedState {
                owner_id: Id::new("vcpu/0").unwrap(),
                state_ref: content.clone(),
            }],
            devices: vec![],
            memory_ref: content.clone(),
            native_pending_ref: content.clone(),
            effect_custody_ref: content.clone(),
            capture_receipt_ref: content,
        }
    }

    #[test]
    fn weaker_capture_cannot_become_exact_or_cross_an_implementation_key() {
        let mut capture = fixture();
        let identity = capture.implementation.clone();
        let inventory = BTreeSet::from([Id::new("vcpu/0").unwrap()]);
        capture
            .validate_for(&identity, &inventory, &BTreeSet::new())
            .unwrap();
        capture.capture_scope = "exact-state-v1".to_owned();
        assert!(
            capture
                .validate_for(&identity, &inventory, &BTreeSet::new())
                .is_err()
        );
        capture.capture_scope = "architectural-v1".to_owned();
        capture.implementation.architecture = KvmArchitecture::Aarch64;
        assert!(
            capture
                .validate_for(&identity, &inventory, &BTreeSet::new())
                .is_err()
        );
    }

    #[test]
    fn capture_requires_complete_cpu_and_device_membership_at_an_unchanged_cut() {
        let mut capture = fixture();
        let identity = capture.implementation.clone();
        let inventory = BTreeSet::from([Id::new("vcpu/0").unwrap(), Id::new("vcpu/1").unwrap()]);
        assert!(
            capture
                .validate_for(&identity, &inventory, &BTreeSet::new())
                .is_err()
        );
        let inventory = BTreeSet::from([Id::new("vcpu/0").unwrap()]);
        assert!(
            capture
                .validate_for(
                    &identity,
                    &inventory,
                    &BTreeSet::from([Id::new("device/0").unwrap()])
                )
                .is_err()
        );
        capture.frozen_clock.current_ps = U64::new(1001);
        assert!(
            capture
                .validate_for(&identity, &inventory, &BTreeSet::new())
                .is_err()
        );
    }
}
