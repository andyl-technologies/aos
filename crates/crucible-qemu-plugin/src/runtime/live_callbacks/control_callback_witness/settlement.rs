//! Fixed, advisory observations of the original admitted bridge settlement.
//!
//! These observations do not certify native wake delivery. A missing observation
//! can mean no admitted request or unavailable diagnostic storage. Collection
//! makes one nonblocking lock attempt; it never borrows the command bridge.

use std::io::{self, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy)]
pub(in crate::runtime::live_callbacks) struct SettlementContext {
    callback: u64,
    raw: u64,
    token: u32,
    frontier: u64,
}

#[derive(Clone, Copy)]
pub(in crate::runtime::live_callbacks) enum SettlementReason {
    Entered,
    PumpActive,
    FrontierPending,
    PublicationBackpressure,
    FrontierUnsettled,
    Settled,
    Error,
}

impl SettlementReason {
    fn label(self) -> &'static str {
        match self {
            Self::Entered => "entered",
            Self::PumpActive => "pump-active",
            Self::FrontierPending => "frontier-pending",
            Self::PublicationBackpressure => "publication-backpressure",
            Self::FrontierUnsettled => "frontier-unsettled",
            Self::Settled => "settled",
            Self::Error => "error",
        }
    }
}

/// Immutable binding supplied by the original joined teardown handle.
pub(super) struct FinalSettlementReport<'a> {
    pub(super) identity: crucible_shmem::SetupRegionBackingIdentity,
    pub(super) slot: u32,
    pub(super) generation: u64,
    pub(super) teardown: &'a str,
    pub(super) final_token: u32,
}

#[derive(Default)]
pub(super) struct LastSettlement {
    value: Mutex<Option<(SettlementContext, SettlementReason)>>,
    lost: AtomicBool,
}

impl LastSettlement {
    pub(super) fn clear(&self) {
        match self.value.try_lock() {
            Ok(mut value) => {
                *value = None;
                self.lost.store(false, Ordering::Relaxed);
            }
            Err(_) => self.lost.store(true, Ordering::Relaxed),
        }
    }

    fn snapshot(&self) -> Option<(SettlementContext, SettlementReason)> {
        if self.lost.load(Ordering::Relaxed) {
            return None;
        }
        match self.value.try_lock() {
            Ok(value) if !self.lost.load(Ordering::Relaxed) => *value,
            _ => {
                self.lost.store(true, Ordering::Relaxed);
                None
            }
        }
    }

    pub(super) fn write_final_to(
        &self,
        writer: &mut impl Write,
        report: FinalSettlementReport<'_>,
        inherited: bool,
    ) -> io::Result<()> {
        let FinalSettlementReport {
            identity,
            slot,
            generation,
            teardown,
            final_token,
        } = report;
        let mut bytes = [0_u8; 512];
        let mut cursor = io::Cursor::new(bytes.as_mut_slice());
        write!(
            cursor,
            "CRUCIBLE-CONTROL-SETTLEMENT-LAST-V1 phase=after-drain teardown={teardown} pid={} device={} inode={} length={} slot={slot} generation={generation} final_token={final_token}",
            std::process::id(),
            identity.device(),
            identity.inode(),
            identity.length(),
        )?;
        match (!inherited).then(|| self.snapshot()).flatten() {
            Some((context, reason)) => write!(
                cursor,
                " callback={} raw={} token={} frontier={} reason={}",
                context.callback,
                context.raw,
                context.token,
                context.frontier,
                reason.label(),
            )?,
            None => write!(cursor, " observation=unavailable")?,
        }
        writeln!(cursor)?;
        let length = cursor.position() as usize;
        writer.write_all(&bytes[..length])
    }
}

impl super::ControlCallbackWitness {
    pub(in crate::runtime::live_callbacks) fn settlement_context(
        &self,
        callback: Option<u64>,
        raw: u64,
        token: u32,
        frontier: u64,
    ) -> Option<SettlementContext> {
        self.enabled.then_some(SettlementContext {
            callback: callback?,
            raw,
            token,
            frontier,
        })
    }

    pub(in crate::runtime::live_callbacks) fn retain_settlement(
        &self,
        context: Option<SettlementContext>,
        reason: SettlementReason,
    ) {
        let Some(context) = context else { return };
        match self.settlement.value.try_lock() {
            Ok(mut value) => *value = Some((context, reason)),
            Err(_) => self.settlement.lost.store(true, Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_settlement_is_bounded_and_contention_or_fork_is_unavailable() {
        let witness = super::super::ControlCallbackWitness::new(true);
        let context = witness.settlement_context(Some(u64::MAX), u64::MAX, u32::MAX, u64::MAX);
        witness.retain_settlement(context, SettlementReason::PublicationBackpressure);
        let identity =
            crucible_shmem::SetupRegionBackingIdentity::from_parts(u64::MAX, u64::MAX, u64::MAX)
                .unwrap_or_else(|| panic!("valid bounded diagnostic identity"));
        let report = || {
            let mut bytes = Vec::new();
            witness
                .settlement
                .write_final_to(
                    &mut bytes,
                    FinalSettlementReport {
                        identity,
                        slot: u32::MAX,
                        generation: u64::MAX,
                        teardown: "run-control-fault",
                        final_token: u32::MAX,
                    },
                    false,
                )
                .unwrap_or_else(|error| panic!("bounded diagnostic row: {error}"));
            assert!(bytes.len() <= 512);
            String::from_utf8(bytes).unwrap_or_else(|error| panic!("ASCII row: {error}"))
        };
        assert!(report().ends_with("reason=publication-backpressure\n"));

        let owned = witness
            .settlement
            .value
            .try_lock()
            .unwrap_or_else(|error| panic!("retained diagnostic owner: {error}"));
        witness.retain_settlement(context, SettlementReason::Settled);
        drop(owned);
        assert!(report().ends_with("observation=unavailable\n"));
        witness
            .process_id
            .store(std::process::id().wrapping_add(1), Ordering::Relaxed);
        witness.entry_record(7);
        assert!(witness.settlement.snapshot().is_none());
        witness.retain_settlement(context, SettlementReason::Entered);
        assert!(report().ends_with("reason=entered\n"));
    }
}
