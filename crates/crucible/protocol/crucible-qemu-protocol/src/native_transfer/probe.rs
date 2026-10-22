//! Borrows a paid-probe report while preserving partial and negative birth facts.
//!
//! ```text
//! CRUCNPR1 | schema1:u32 | length3584:u32 | factual-header[496] |
//! producers[16][192]
//! ```
//!
//! Report bytes perform no birth, wait, reap, producer authentication or resource
//! return. Completed result syntax is separate from genuine paid probe ownership
//! and independent producer/outside-owner closure.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::manifest::{NativeProfileManifest, NativeProfileProducer, validate_producers};
use super::{NativeTransfer, read32, read64, read_identity};
use crate::runtime_artifact::RuntimeArtifactPair;
use sha2::{Digest, Sha256};

/// Gives the exact complete paid-probe report extent in this edition.
pub const NATIVE_PROBE_REPORT_BYTES: usize = 3584;

const HEADER_BYTES: usize = 512;
const PRODUCER_BYTES: usize = 192;
const ATTEMPTED: u32 = 1;
const RETURNED: u32 = 2;
const BORN: u32 = 4;
const BIRTH_UNKNOWN: u32 = 8;
const EXIT_OBSERVED: u32 = 16;
const REAPED: u32 = 32;
const LOCAL_CUSTODY_RETAINED: u32 = 64;
const SETTLEMENT_CONSUMED: u32 = 128;
const COMPLETED: u32 = ATTEMPTED | RETURNED | BORN | EXIT_OBSERVED | REAPED;

/// Refuses malformed or uncorrelated paid-probe descriptions without allocating.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid prebirth paid-probe report")]
pub struct NativeProbeDecodeError;

/// Describes separately retained factual cuts without authenticating their origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeProbeFacts {
    /// Records an attempted actual birth operation.
    pub attempted: bool,
    /// Records observation of that birth operation's return.
    pub returned: bool,
    /// Describes known birth with retained positive child witnesses.
    pub born: bool,
    /// Retains uncertainty about whether the attempted child was born.
    pub birth_unknown: bool,
    /// Describes a separately observed process exit.
    pub exit_observed: bool,
    /// Describes the launcher's matching kernel reap observation.
    pub reaped: bool,
    /// Describes surviving local custody independently of process exit.
    pub local_custody_retained: bool,
    /// Describes a consumed settlement cut without granting resource return.
    pub settlement_consumed: bool,
    /// Identifies the birth attempt, including known no-birth refusals.
    pub birth_attempt_sequence: u64,
    /// Retains a known kernel-child handle sequence, or zero when unknown.
    pub kernel_handle_sequence: u64,
    /// Gives a positive Linux PID witness, or zero when unknown.
    pub pid_witness: u32,
    /// Identifies the actual factual event, or zero before an attempt.
    pub event_sequence: u64,
    /// Retains the exact raw wait word only when a reap is described.
    pub raw_wait_status: u32,
    /// Retains the first errno magnitude, including zero for no recorded error.
    pub first_errno: u16,
}

/// Borrows one structurally checked report, including incomplete negative histories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeProbeReport<'a> {
    bytes: &'a [u8],
}

impl<'a> NativeProbeReport<'a> {
    /// Borrows the exact report after validating framing and factual implications.
    ///
    /// Negative results, unknown birth and reap after a lost launch-return remain
    /// representable. Successful parsing establishes no issuer or wait authority.
    ///
    /// # Errors
    /// Refuses invalid size/schema, absent descriptive identities, exhausted
    /// epochs, impossible flag/witness combinations, out-of-range errno/PID,
    /// malformed producer rows or nonzero reserved bytes.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, NativeProbeDecodeError> {
        if bytes.len() != NATIVE_PROBE_REPORT_BYTES
            || bytes[..8] != *b"CRUCNPR1"
            || read32(bytes, 8) != 1
            || read32(bytes, 12) as usize != NATIVE_PROBE_REPORT_BYTES
            || read32(bytes, 384) != 16
            || read32(bytes, 388) != 4096
            || bytes[400..HEADER_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(NativeProbeDecodeError);
        }
        for offset in [16, 24, 32, 40, 48] {
            if matches!(read64(bytes, offset), 0 | u64::MAX) {
                return Err(NativeProbeDecodeError);
            }
        }
        for offset in [56, 88, 120, 152, 184, 216, 248, 280, 312] {
            if read_identity(bytes, offset) == [0; 32] {
                return Err(NativeProbeDecodeError);
            }
        }
        validate_facts(bytes)?;
        validate_producers(&bytes[HEADER_BYTES..]).map_err(|_| NativeProbeDecodeError)?;
        Ok(Self { bytes })
    }

    /// Returns the exact unchanged report bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns independent factual cuts without inferring a missing launch return.
    #[must_use]
    pub fn facts(&self) -> NativeProbeFacts {
        let flags = read32(self.bytes, 376);
        NativeProbeFacts {
            attempted: flags & ATTEMPTED != 0,
            returned: flags & RETURNED != 0,
            born: flags & BORN != 0,
            birth_unknown: flags & BIRTH_UNKNOWN != 0,
            exit_observed: flags & EXIT_OBSERVED != 0,
            reaped: flags & REAPED != 0,
            local_custody_retained: flags & LOCAL_CUSTODY_RETAINED != 0,
            settlement_consumed: flags & SETTLEMENT_CONSUMED != 0,
            birth_attempt_sequence: read64(self.bytes, 344),
            kernel_handle_sequence: read64(self.bytes, 352),
            pid_witness: read64(self.bytes, 360) as u32,
            event_sequence: read64(self.bytes, 368),
            raw_wait_status: read32(self.bytes, 380),
            first_errno: read64(self.bytes, 392) as u16,
        }
    }

    /// Checks only the completed normal-exit-zero result predicate.
    ///
    /// This does not establish paid birth, matching reap, mechanically enforced
    /// bounds, complete post histories or outside-owner closure. A false result
    /// preserves the same borrowed report and every represented negative fact.
    #[must_use]
    pub fn has_completed_result(&self) -> bool {
        let flags = read32(self.bytes, 376);
        flags & COMPLETED == COMPLETED
            && flags & BIRTH_UNKNOWN == 0
            && read64(self.bytes, 392) == 0
            && read32(self.bytes, 380) == 0
    }

    /// Iterates the exact sixteen producer descriptions retained by this report.
    pub fn producers(&self) -> impl ExactSizeIterator<Item = NativeProfileProducer> + '_ {
        let (rows, _) = self.bytes[HEADER_BYTES..].as_chunks::<PRODUCER_BYTES>();
        rows.iter().map(|bytes| NativeProfileProducer::read(bytes))
    }

    /// Corroborates complete manifest, transfer and exact runtime descriptions.
    ///
    /// Actual probe producer-child identities may differ from future recipient
    /// children. Their kind, edition, implementation, compiled layout, limits
    /// and liability assignment must match exactly. Negative report facts are
    /// preserved; callers must separately check completed results and real owners.
    ///
    /// # Errors
    /// Refuses independently valid foreign parent/request/process/account/Source
    /// coordinates, complete report/profile digests, kernel/issued-contract
    /// digests, selected producer contracts or runtime file identities.
    pub fn corroborate_transfer(
        &self,
        transfer: &NativeTransfer,
        manifest: &NativeProfileManifest<'_>,
        runtime: &RuntimeArtifactPair,
    ) -> Result<(), NativeProbeDecodeError> {
        manifest
            .corroborate_transfer(transfer, runtime)
            .map_err(|_| NativeProbeDecodeError)?;
        let profile = manifest.as_bytes();
        for (report_offset, profile_offset) in [(32, 24), (40, 32), (48, 40)] {
            if read64(self.bytes, report_offset) != read64(profile, profile_offset) {
                return Err(NativeProbeDecodeError);
            }
        }
        for (report_offset, profile_offset) in [(88, 80), (184, 48), (248, 176), (280, 224)] {
            if read_identity(self.bytes, report_offset) != read_identity(profile, profile_offset) {
                return Err(NativeProbeDecodeError);
            }
        }
        let profile_digest: [u8; 32] = Sha256::digest(profile).into();
        let report_digest: [u8; 32] = Sha256::digest(self.bytes).into();
        if read_identity(self.bytes, 216) != profile_digest
            || transfer.paid_probe_sha256 != report_digest
        {
            return Err(NativeProbeDecodeError);
        }
        for (observed, selected) in self.producers().zip(manifest.producers()) {
            if observed.kind != selected.kind
                || observed.disposition != selected.disposition
                || observed.edition != selected.edition
                || observed.implementation_sha256 != selected.implementation_sha256
                || observed.layout_sha256 != selected.layout_sha256
                || observed.limits != selected.limits
                || observed.liability_kind != selected.liability_kind
            {
                return Err(NativeProbeDecodeError);
            }
        }
        Ok(())
    }
}

fn validate_facts(bytes: &[u8]) -> Result<(), NativeProbeDecodeError> {
    let flags = read32(bytes, 376);
    let attempted = flags & ATTEMPTED != 0;
    let born = flags & BORN != 0;
    let unknown = flags & BIRTH_UNKNOWN != 0;
    let exit = flags & EXIT_OBSERVED != 0;
    let reaped = flags & REAPED != 0;
    let birth_sequence = read64(bytes, 344);
    let kernel_sequence = read64(bytes, 352);
    let pid = read64(bytes, 360);
    let event_sequence = read64(bytes, 368);

    if flags & !255 != 0
        || (flags != 0 && !attempted)
        || (born && unknown)
        || (exit && !born)
        || (reaped && !(born && exit))
        || (flags & SETTLEMENT_CONSUMED != 0 && !reaped)
        || [birth_sequence, kernel_sequence, event_sequence].contains(&u64::MAX)
        || pid > i32::MAX as u64
        || read64(bytes, 392) > 4095
        || (attempted && (birth_sequence == 0 || event_sequence == 0))
        || (!attempted
            && (birth_sequence != 0 || kernel_sequence != 0 || pid != 0 || event_sequence != 0))
        || (born && (kernel_sequence == 0 || pid == 0))
        || (!born && !unknown && (kernel_sequence != 0 || pid != 0))
        || (!reaped && read32(bytes, 380) != 0)
    {
        return Err(NativeProbeDecodeError);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
