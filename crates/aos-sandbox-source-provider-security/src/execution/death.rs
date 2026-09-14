//! Opaque same-boot and cross-boot provider death evidence.

use super::{CurrentKernelBootV1, ProcessExecutionEvidenceV1};
use crate::SourceProviderSecurityError;
use crate::carrier::ClosedSourceProviderCarrierV1;

/// Proves one exact provider execution cannot continue an unresolved session.
///
/// The proof alone grants no journal mutation or session-replacement authority.
/// Constructors remain sealed until the future AOSSPL ledger supplies exact
/// unresolved-session and recovered-execution receipts.
pub struct DeadProviderExecutionV1 {
    evidence: DeathEvidenceV1,
}

enum DeathEvidenceV1 {
    SameBoot {
        boot_id: [u8; 16],
        process_id: u32,
        start_time_ticks: u64,
    },
    CrossBoot {
        old_boot_id: [u8; 16],
        current_boot_id: [u8; 16],
        process_instance: [u8; 16],
    },
}

impl core::fmt::Debug for DeadProviderExecutionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let _ = &self.evidence;
        formatter.write_str("DeadProviderExecutionV1([redacted])")
    }
}

pub(super) struct UnresolvedProviderSessionReceiptV1 {
    _private: (),
}

pub(super) struct RecoveredProviderExecutionV1 {
    pub(super) old_boot_id: [u8; 16],
    pub(super) process_instance: [u8; 16],
}

impl DeadProviderExecutionV1 {
    pub(super) fn same_boot(
        execution: &ProcessExecutionEvidenceV1,
        _closed_carrier: ClosedSourceProviderCarrierV1,
        _unresolved: UnresolvedProviderSessionReceiptV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        let boot_before = CurrentKernelBootV1::capture()?;
        if boot_before.boot_id() != execution.boot_id() || execution.is_alive()? {
            return Err(SourceProviderSecurityError::DeathNotEstablished);
        }
        let boot_after = CurrentKernelBootV1::capture()?;
        if boot_after.boot_id() != boot_before.boot_id() || execution.is_alive()? {
            return Err(SourceProviderSecurityError::DeathNotEstablished);
        }
        Ok(Self {
            evidence: DeathEvidenceV1::SameBoot {
                boot_id: execution.boot_id(),
                process_id: execution.pid(),
                start_time_ticks: execution.start_time_ticks(),
            },
        })
    }

    pub(super) fn cross_boot(
        current: &CurrentKernelBootV1,
        recovered: RecoveredProviderExecutionV1,
    ) -> Result<Self, SourceProviderSecurityError> {
        current.revalidate()?;
        if current.boot_id() == recovered.old_boot_id
            || recovered.old_boot_id == [0; 16]
            || recovered.process_instance == [0; 16]
        {
            return Err(SourceProviderSecurityError::DeathNotEstablished);
        }
        Ok(Self {
            evidence: DeathEvidenceV1::CrossBoot {
                old_boot_id: recovered.old_boot_id,
                current_boot_id: current.boot_id(),
                process_instance: recovered.process_instance,
            },
        })
    }
}
