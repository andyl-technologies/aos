//! Complete native clock and effect-path claims requiring installed qualification.

use std::collections::BTreeSet;

use crucible_node_contract::{HashRef, U64, Validate};
use serde::{Deserialize, Serialize};

use super::{KvmArchitecture, KvmProfileError};

/// Names an architecture or machine-specific guest time and timer surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KvmClockSource {
    /// Reads the architectural x86 TSC.
    Tsc,
    /// Reads the x86 TSC with auxiliary CPU identity.
    Rdtscp,
    /// Writes x86 TSC and adjustment MSRs.
    TscWrites,
    /// Extrapolates the KVM paravirtual clock from guest counter values.
    Pvclock,
    /// Reads Hyper-V clocks or schedules synthetic timers.
    HypervClock,
    /// Reads Xen paravirtual time and timer interfaces.
    XenClock,
    /// Reads VMware backdoor time interfaces.
    VmwareClock,
    /// Reads admitted architecture and firmware frequency reports.
    FrequencyReports,
    /// Expires x86 local APIC periodic timers.
    LapicPeriodic,
    /// Expires x86 local APIC one-shot timers.
    LapicOneShot,
    /// Expires the x86 TSC deadline timer.
    TscDeadline,
    /// Reads or expires the legacy x86 PIT.
    Pit,
    /// Reads or expires HPET comparators.
    Hpet,
    /// Reads the ACPI power-management timer.
    AcpiPm,
    /// Reads or expires RTC updates and alarms.
    Rtc,
    /// Reads exposed PMU counters or generates PMU interrupts.
    PerformanceCounters,
    /// Reads ARM virtual architectural counters, including admitted alternate views.
    ArmVirtualCounter,
    /// Reads ARM physical architectural counters, including admitted alternate views.
    ArmPhysicalCounter,
    /// Reads ARM counter frequency reports.
    ArmCounterFrequency,
    /// Reads, programs or expires the ARM virtual generic timer.
    ArmVirtualTimer,
    /// Reads, programs or expires the ARM physical generic timer.
    ArmPhysicalTimer,
    /// Updates GIC distributor, redistributor and CPU-interface timer/IRQ state.
    ArmGic,
}

/// Classifies native coverage without confusing offsets with controlled time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KvmMediationMechanism {
    /// The admitted guest ABI and actual realization make this source inaccessible.
    UnavailableToGuest,
    /// A kernel interception or emulation path derives from the common capped domain.
    KernelControllerDomain,
    /// The QEMU device model derives reads and effects from the capped domain.
    EmulatorControllerDomain,
    /// Kernel and emulator coordinate the source and all pending effects.
    KernelAndEmulatorControllerDomain,
    /// Ordinary hardware offset/scaling remains active without a clock ceiling.
    NativeOffsetOrScaling,
    /// No qualified native coverage exists for the realized source.
    Unqualified,
}

/// Binds one guest source to implementation evidence for its actual mediation path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvmMediationEntry {
    /// Names one source in the actual realized guest clock inventory.
    pub source: KvmClockSource,
    /// Classifies the covered mechanism, or explicit lack of coverage.
    pub mechanism: KvmMediationMechanism,
    /// References installed implementation evidence, not self-reported qualification.
    pub evidence_ref: HashRef,
}

/// Reports one native realization's complete clock and closure implementation claims.
///
/// This is a closed claim schema. The host must authenticate its kernel/emulator
/// measurements, resolve evidence against installed qualification and bind the
/// inventory to actual CPU/device realization before granting authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KvmMediationManifest {
    /// Selects version one of this native mediation schema.
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    pub schema_version: u16,
    /// Names the native architecture actually realized.
    pub architecture: KvmArchitecture,
    /// Binds the actual host kernel and mediation implementation measurement.
    pub kernel_build_ref: HashRef,
    /// Binds the actual QEMU executable and controller implementation measurement.
    pub emulator_build_ref: HashRef,
    /// Binds the canonical CPU/machine/device configuration and clock policy.
    pub configuration_ref: HashRef,
    /// Counts all realized vCPUs, including every native run thread.
    pub realized_vcpus: U64,
    /// Lists each actual guest-visible clock source exactly once in canonical order.
    pub clock_sources: Vec<KvmMediationEntry>,
    /// Reports implemented all-vCPU physical stop acknowledgment.
    pub all_vcpu_stop_acknowledgment: bool,
    /// Reports complete pending exit-emulation disposition before native closure.
    pub pending_exit_emulation_closure: bool,
    /// Reports controller-authorized interrupt staging and delivery custody.
    pub interrupt_custody: bool,
    /// Reports complete emulated and accelerated I/O/DMA path mediation.
    pub io_dma_custody: bool,
    /// Reports complete pending timer disposition under the same clock domain.
    pub pending_timer_closure: bool,
    /// Reports exclusion or qualified mediation of independent passthrough effects.
    pub no_unmediated_effect_paths: bool,
}

impl KvmMediationManifest {
    /// Checks complete inventory and closure claims before native qualification.
    ///
    /// `realized_sources` comes from independently authenticated realization,
    /// not from this manifest's own list. A successful check only establishes
    /// local consistency of claims, not authenticity or production admission.
    ///
    /// # Errors
    /// Refuses unsupported editions, stale architecture, absent/extra/duplicate
    /// sources, offsets-only coverage, wrong counter mechanism or partial closure.
    pub fn validate_inventory(
        &self,
        architecture: KvmArchitecture,
        realized_sources: &BTreeSet<KvmClockSource>,
    ) -> Result<(), KvmProfileError> {
        if self.schema_version != 1
            || self.architecture != architecture
            || self.realized_vcpus.get() == 0
        {
            return Err(KvmProfileError::Identity {
                field: "native mediation schema/architecture/vCPU count",
            });
        }
        self.kernel_build_ref.validate()?;
        self.emulator_build_ref.validate()?;
        self.configuration_ref.validate()?;
        if self.clock_sources.len() > crucible_node_contract::MAX_ARRAY_ELEMENTS {
            return Err(KvmProfileError::Identity {
                field: "native clock inventory bound",
            });
        }
        let mut previous = None;
        let mut observed = BTreeSet::new();
        for entry in &self.clock_sources {
            entry.evidence_ref.validate()?;
            if previous.is_some_and(|source| source >= entry.source)
                || !observed.insert(entry.source)
            {
                return Err(KvmProfileError::MissingMediation {
                    requirement: "clock inventory must be sorted and unique".to_owned(),
                });
            }
            previous = Some(entry.source);
            if matches!(
                entry.mechanism,
                KvmMediationMechanism::NativeOffsetOrScaling | KvmMediationMechanism::Unqualified
            ) {
                return Err(KvmProfileError::MissingMediation {
                    requirement: format!("{:?} lacks a capped controller domain", entry.source),
                });
            }
            if matches!(
                entry.source,
                KvmClockSource::Tsc
                    | KvmClockSource::Rdtscp
                    | KvmClockSource::TscWrites
                    | KvmClockSource::ArmVirtualCounter
                    | KvmClockSource::ArmPhysicalCounter
            ) && !matches!(
                entry.mechanism,
                KvmMediationMechanism::KernelControllerDomain
                    | KvmMediationMechanism::KernelAndEmulatorControllerDomain
            ) {
                return Err(KvmProfileError::MissingMediation {
                    requirement: format!(
                        "mandatory native counter {:?} requires kernel mediation",
                        entry.source
                    ),
                });
            }
        }
        if &observed != realized_sources {
            return Err(KvmProfileError::MissingMediation {
                requirement: "clock claims differ from authenticated realized inventory".to_owned(),
            });
        }
        for (complete, requirement) in [
            (
                self.all_vcpu_stop_acknowledgment,
                "all-vCPU physical stop acknowledgment",
            ),
            (
                self.pending_exit_emulation_closure,
                "pending exit-emulation closure",
            ),
            (self.interrupt_custody, "interrupt custody"),
            (self.io_dma_custody, "I/O and DMA custody"),
            (self.pending_timer_closure, "pending timer closure"),
            (
                self.no_unmediated_effect_paths,
                "absence of unmediated effects",
            ),
        ] {
            if !complete {
                return Err(KvmProfileError::MissingMediation {
                    requirement: requirement.to_owned(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These coverage tests deliberately panic on invalid fixtures or failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hash() -> HashRef {
        crucible_node_contract::canonical::hash("cnp.kvm-test-identity.v1", b"implementation")
            .unwrap()
    }

    fn manifest() -> KvmMediationManifest {
        KvmMediationManifest {
            schema_version: 1,
            architecture: KvmArchitecture::X86_64,
            kernel_build_ref: hash(),
            emulator_build_ref: hash(),
            configuration_ref: hash(),
            realized_vcpus: U64::new(2),
            clock_sources: vec![KvmMediationEntry {
                source: KvmClockSource::Tsc,
                mechanism: KvmMediationMechanism::KernelControllerDomain,
                evidence_ref: hash(),
            }],
            all_vcpu_stop_acknowledgment: true,
            pending_exit_emulation_closure: true,
            interrupt_custody: true,
            io_dma_custody: true,
            pending_timer_closure: true,
            no_unmediated_effect_paths: true,
        }
    }

    #[test]
    fn native_offsets_never_satisfy_complete_clock_coverage() {
        let mut manifest = manifest();
        manifest.clock_sources[0].mechanism = KvmMediationMechanism::NativeOffsetOrScaling;
        assert!(
            manifest
                .validate_inventory(
                    KvmArchitecture::X86_64,
                    &BTreeSet::from([KvmClockSource::Tsc])
                )
                .is_err()
        );
        manifest.clock_sources[0].mechanism = KvmMediationMechanism::EmulatorControllerDomain;
        assert!(
            manifest
                .validate_inventory(
                    KvmArchitecture::X86_64,
                    &BTreeSet::from([KvmClockSource::Tsc])
                )
                .is_err()
        );
    }

    #[test]
    fn partial_interrupt_timer_or_dma_closure_cannot_enable_native_run() {
        let mut manifest = manifest();
        let inventory = BTreeSet::from([KvmClockSource::Tsc]);
        manifest
            .validate_inventory(KvmArchitecture::X86_64, &inventory)
            .unwrap();
        manifest.pending_timer_closure = false;
        assert!(
            manifest
                .validate_inventory(KvmArchitecture::X86_64, &inventory)
                .is_err()
        );
        manifest.pending_timer_closure = true;
        manifest.io_dma_custody = false;
        assert!(
            manifest
                .validate_inventory(KvmArchitecture::X86_64, &inventory)
                .is_err()
        );
    }

    #[test]
    fn missing_realized_source_and_duplicate_claims_are_rejected() {
        let mut manifest = manifest();
        assert!(
            manifest
                .validate_inventory(
                    KvmArchitecture::X86_64,
                    &BTreeSet::from([KvmClockSource::Tsc, KvmClockSource::Pit])
                )
                .is_err()
        );
        manifest
            .clock_sources
            .push(manifest.clock_sources[0].clone());
        assert!(
            manifest
                .validate_inventory(
                    KvmArchitecture::X86_64,
                    &BTreeSet::from([KvmClockSource::Tsc])
                )
                .is_err()
        );
    }
}
