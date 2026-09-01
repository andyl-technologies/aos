//! Canonical host ledger for plugin-owned inbound frame consumption.
//!
//! The QEMU plugin is the sole consumer of the router-to-VM SPSC ring. The
//! host retains only delivery keys so it can authorize quantum ceilings and
//! verify, without dequeuing payloads, that the plugin consumes every frame at
//! its exact delivery coordinate.

use std::collections::VecDeque;

use crucible_shmem::{
    FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT, FrameDeliveryKey, FrameDeliveryState, FrameEntry,
    MAX_FRAME_DELIVERY_ATTEMPTS,
};

use super::support::{QemuQuantumError, inbound_live_count, inbound_ring_capacity};
use super::{
    QemuInboundConsumptionBaseline, QemuPendingQuantum, QemuQuantumOperation,
    QemuQuantumShmemHotPath, QemuQuantumShmemView,
};

impl QemuQuantumShmemHotPath<'_> {
    pub(super) fn snapshot_inbound_consumption(
        &mut self,
    ) -> Result<QemuInboundConsumptionBaseline, QemuQuantumError> {
        self.record(QemuQuantumOperation::ObserveInboundConsumption);
        let (read_idx, write_idx, ring_ledger, next_wake_icount) =
            inbound_delivery_snapshot_from_view(&self.view)?;
        if self.inbound_delivery_ledger.get() != &ring_ledger {
            *self.inbound_delivery_ledger.get_mut() = ring_ledger;
        }
        let ledger = self.inbound_delivery_ledger.get();
        let delivery_keys = ledger.iter().copied().collect::<Vec<_>>();

        Ok(QemuInboundConsumptionBaseline {
            read_idx,
            write_idx,
            delivery_keys,
            next_wake_icount,
        })
    }

    pub(super) fn observe_inbound_consumption(
        &mut self,
        pending: &QemuPendingQuantum,
        current_icount: u64,
    ) -> Result<usize, QemuQuantumError> {
        self.record(QemuQuantumOperation::ObserveInboundConsumption);
        let baseline = &pending.inbound_consumption;
        let final_write_idx = self.view.inbound_ring.write_index();
        let final_read_idx = self.view.inbound_ring.read_index();
        let consumed = final_read_idx.checked_sub(baseline.read_idx).ok_or(
            QemuQuantumError::InboundConsumerAdvancedBeyondPublished {
                initial_read_idx: baseline.read_idx,
                initial_write_idx: baseline.write_idx,
                final_read_idx,
            },
        )?;
        let produced = final_write_idx.checked_sub(baseline.write_idx).ok_or(
            QemuQuantumError::InboundDeliveryLedgerIndexRegressed {
                initial_write_idx: baseline.write_idx,
                final_write_idx,
            },
        )?;
        self.reconcile_inbound_publications(baseline, produced)?;
        let ledger = self.inbound_delivery_ledger.get();
        let expected_ledger_len = baseline
            .delivery_keys
            .len()
            .checked_add(produced as usize)
            .ok_or(QemuQuantumError::InboundDeliveryLedgerLengthOverflow)?;
        if ledger.len() != expected_ledger_len
            || !ledger
                .iter()
                .take(baseline.delivery_keys.len())
                .copied()
                .eq(baseline.delivery_keys.iter().copied())
        {
            return Err(QemuQuantumError::InboundDeliveryLedgerMismatch {
                ring_live: final_write_idx.saturating_sub(final_read_idx),
                ledger_live: ledger.len(),
            });
        }
        if consumed > ledger.len() as u64 {
            return Err(QemuQuantumError::InboundConsumerAdvancedBeyondPublished {
                initial_read_idx: baseline.read_idx,
                initial_write_idx: baseline.write_idx,
                final_read_idx,
            });
        }
        for frame in ledger.iter().take(consumed as usize) {
            if frame.delivery_icount > current_icount {
                return Err(QemuQuantumError::InboundFrameConsumedBeforeDelivery {
                    current_icount,
                    frame: *frame,
                });
            }
        }
        if let Some(frame) = ledger
            .iter()
            .skip(consumed as usize)
            .find(|frame| frame.delivery_icount <= current_icount)
        {
            let head = self
                .view
                .inbound_ring
                .peek(self.view.inbound_entries)
                .map_err(|source| QemuQuantumError::SpscRing {
                    operation: "observe retained inbound head",
                    source,
                })?;
            let retained = head
                .as_ref()
                .filter(|head| {
                    ledger
                        .get(consumed as usize)
                        .is_some_and(|expected| head.delivery_key() == *expected)
                })
                .is_some_and(|head| {
                    head.delivery_state()
                        .is_ok_and(|state| state == FrameDeliveryState::Retained)
                });
            if let Some(head) = head.as_ref()
                && let Err(source) = head.delivery_state()
            {
                return Err(QemuQuantumError::InboundFrameDeliveryState {
                    frame: head.delivery_key(),
                    source,
                });
            }
            if !retained {
                return Err(QemuQuantumError::InboundFrameNotConsumedAtDelivery {
                    current_icount,
                    frame: *frame,
                });
            }
        }
        self.inbound_delivery_ledger
            .get_mut()
            .drain(..consumed as usize);
        Ok(consumed as usize)
    }

    fn reconcile_inbound_publications(
        &mut self,
        baseline: &QemuInboundConsumptionBaseline,
        produced: u64,
    ) -> Result<(), QemuQuantumError> {
        let ledger = self.inbound_delivery_ledger.get_mut();
        let baseline_len = baseline.delivery_keys.len();
        let recorded = ledger.len().checked_sub(baseline_len).ok_or(
            QemuQuantumError::InboundDeliveryLedgerMismatch {
                ring_live: self
                    .view
                    .inbound_ring
                    .write_index()
                    .saturating_sub(self.view.inbound_ring.read_index()),
                ledger_live: ledger.len(),
            },
        )?;
        if recorded as u64 > produced {
            return Err(QemuQuantumError::InboundDeliveryLedgerMismatch {
                ring_live: self
                    .view
                    .inbound_ring
                    .write_index()
                    .saturating_sub(self.view.inbound_ring.read_index()),
                ledger_live: ledger.len(),
            });
        }
        let capacity = inbound_ring_capacity(self.view.inbound_entries)?;
        if recorded as u64 != produced && produced > capacity {
            return Err(QemuQuantumError::InboundDeliveryHistoryOverwritten { produced, capacity });
        }
        for offset in recorded as u64..produced {
            let slot = ((baseline.write_idx.wrapping_add(offset)) & (capacity - 1)) as usize;
            ledger.push_back(self.view.inbound_entries[slot].delivery_key());
        }
        Ok(())
    }
}

pub(super) fn inbound_delivery_ledger_from_view(
    view: &QemuQuantumShmemView<'_>,
) -> Result<VecDeque<FrameDeliveryKey>, QemuQuantumError> {
    inbound_delivery_snapshot_from_view(view).map(|(_, _, ledger, _)| ledger)
}

fn inbound_delivery_snapshot_from_view(
    view: &QemuQuantumShmemView<'_>,
) -> Result<(u64, u64, VecDeque<FrameDeliveryKey>, Option<u64>), QemuQuantumError> {
    let capacity = inbound_ring_capacity(view.inbound_entries)?;
    stable_inbound_delivery_snapshot(
        capacity,
        || view.inbound_ring.read_index(),
        || view.inbound_ring.write_index(),
        |slot| view.inbound_entries[slot].delivery_key(),
        |slot| inbound_frame_wake_icount(&view.inbound_entries[slot]),
    )
}

fn inbound_frame_wake_icount(frame: &FrameEntry) -> Result<u64, QemuQuantumError> {
    let key = frame.delivery_key();
    let state = frame
        .delivery_state()
        .map_err(|source| QemuQuantumError::InboundFrameDeliveryState { frame: key, source })?;
    let attempts = frame.delivery_attempts();
    let last_attempt_icount = frame.last_delivery_attempt_icount();
    match state {
        FrameDeliveryState::Pending if attempts == 0 && last_attempt_icount == 0 => {
            Ok(frame.delivery_icount)
        }
        FrameDeliveryState::Pending => Err(QemuQuantumError::InboundFrameDeliveryAttempts {
            frame: key,
            state,
            attempts,
            last_attempt_icount,
        }),
        FrameDeliveryState::Retained
            if attempts == 0
                || attempts > MAX_FRAME_DELIVERY_ATTEMPTS
                || last_attempt_icount < frame.delivery_icount =>
        {
            Err(QemuQuantumError::InboundFrameDeliveryAttempts {
                frame: key,
                state,
                attempts,
                last_attempt_icount,
            })
        }
        FrameDeliveryState::Retained => last_attempt_icount
            .checked_add(FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT)
            .ok_or(QemuQuantumError::InboundFrameRetryCoordinateOverflow {
                frame: key,
                last_attempt_icount,
                retry_interval_icount: FRAME_DELIVERY_RETRY_INTERVAL_ICOUNT,
            }),
    }
}

fn stable_inbound_delivery_snapshot(
    capacity: u64,
    mut read_index: impl FnMut() -> u64,
    mut write_index: impl FnMut() -> u64,
    mut entry_key: impl FnMut(usize) -> FrameDeliveryKey,
    mut head_wake_icount: impl FnMut(usize) -> Result<u64, QemuQuantumError>,
) -> Result<(u64, u64, VecDeque<FrameDeliveryKey>, Option<u64>), QemuQuantumError> {
    for _ in 0..=capacity {
        let read_idx = read_index();
        let write_idx = write_index();
        let live = inbound_live_count(read_idx, write_idx, capacity)?;
        let mut ledger = VecDeque::with_capacity(live as usize);
        for offset in 0..live {
            let slot = ((read_idx.wrapping_add(offset)) & (capacity - 1)) as usize;
            ledger.push_back(entry_key(slot));
        }
        if read_index() != read_idx {
            continue;
        }
        let next_wake_icount = if live == 0 {
            Ok(None)
        } else {
            let head_slot = (read_idx & (capacity - 1)) as usize;
            head_wake_icount(head_slot).map(Some)
        };
        if read_index() == read_idx {
            return Ok((read_idx, write_idx, ledger, next_wake_icount?));
        }
    }
    Err(QemuQuantumError::InboundConsumptionSnapshotUnstable { capacity })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_snapshot_retries_if_plugin_consumes_during_capture() {
        let reads = [0_u64, 1, 1, 1];
        let mut next_read = reads.into_iter();
        let key = FrameDeliveryKey {
            delivery_icount: 7,
            src_node: 31,
            seq: 0,
        };

        let snapshot = stable_inbound_delivery_snapshot(
            2,
            || next_read.next().unwrap_or(1),
            || 1,
            |_| key,
            |_| Ok(7),
        )
        .unwrap_or_else(|error| panic!("snapshot should retry to coherence: {error}"));

        assert_eq!(snapshot, (1, 1, VecDeque::new(), None));
    }
}
