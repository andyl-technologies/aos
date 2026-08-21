//! Canonical host ledger for plugin-owned inbound frame consumption.
//!
//! The QEMU plugin is the sole consumer of the router-to-VM SPSC ring. The
//! host retains only delivery keys so it can authorize quantum ceilings and
//! verify, without dequeuing payloads, that the plugin consumes every frame at
//! its exact delivery coordinate.

use std::collections::VecDeque;

use crucible_shmem::FrameDeliveryKey;

use super::support::{QemuQuantumError, inbound_live_count, inbound_ring_capacity};
use super::{
    QemuInboundConsumptionBaseline, QemuPendingQuantum, QemuQuantumOperation,
    QemuQuantumShmemHotPath, QemuQuantumShmemView,
};

impl QemuQuantumShmemHotPath<'_> {
    pub(super) fn snapshot_inbound_consumption(
        &mut self,
        current_icount: u64,
    ) -> Result<QemuInboundConsumptionBaseline, QemuQuantumError> {
        self.record(QemuQuantumOperation::ObserveInboundConsumption);
        let read_idx = self.view.inbound_ring.read_index();
        let write_idx = self.view.inbound_ring.write_index();
        let ring_ledger = inbound_delivery_ledger_from_view(&self.view)?;
        if self.inbound_delivery_ledger.get() != &ring_ledger {
            *self.inbound_delivery_ledger.get_mut() = ring_ledger;
        }
        let ledger = self.inbound_delivery_ledger.get();
        let delivery_keys = ledger.iter().copied().collect::<Vec<_>>();

        for entry in &delivery_keys {
            if entry.delivery_icount < current_icount {
                return Err(QemuQuantumError::DeliveryAlreadyPassed {
                    passed_delivery_floor_icount: current_icount,
                    current_icount,
                    frame: *entry,
                });
            }
        }
        Ok(QemuInboundConsumptionBaseline {
            read_idx,
            write_idx,
            delivery_keys,
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
            return Err(QemuQuantumError::InboundFrameNotConsumedAtDelivery {
                current_icount,
                frame: *frame,
            });
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
    let capacity = inbound_ring_capacity(view.inbound_entries)?;
    let read_idx = view.inbound_ring.read_index();
    let write_idx = view.inbound_ring.write_index();
    let live = inbound_live_count(read_idx, write_idx, capacity)?;
    let mut ledger = VecDeque::with_capacity(live as usize);
    for offset in 0..live {
        let slot = ((read_idx.wrapping_add(offset)) & (capacity - 1)) as usize;
        ledger.push_back(view.inbound_entries[slot].delivery_key());
    }
    Ok(ledger)
}
