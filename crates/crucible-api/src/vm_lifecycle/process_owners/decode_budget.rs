//! Reentrant allocation accounting for durable process-owner decoding.

#[derive(Clone, Copy)]
struct DurableDecodeShape {
    current_processes: usize,
    staged_processes: usize,
    lifecycle_nodes: usize,
    completed_exits: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DurableDecodeUsage {
    event_records: u64,
    event_log_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::vm_lifecycle) struct DurableDecodeAllocation {
    pub(in crate::vm_lifecycle) field: &'static str,
    pub(in crate::vm_lifecycle) current: u64,
    pub(in crate::vm_lifecycle) requested: u64,
}

std::thread_local! {
    static DURABLE_DECODE_SHAPE: std::cell::Cell<Option<DurableDecodeShape>> = const {
        std::cell::Cell::new(None)
    };
    static DURABLE_DECODE_ALLOCATION: std::cell::Cell<Option<DurableDecodeAllocation>> = const {
        std::cell::Cell::new(None)
    };
    static DURABLE_DECODE_USAGE: std::cell::Cell<DurableDecodeUsage> = const {
        std::cell::Cell::new(DurableDecodeUsage {
            event_records: 0,
            event_log_bytes: 0,
        })
    };
}

pub(in crate::vm_lifecycle) struct DurableDecodeShapeGuard {
    previous: Option<DurableDecodeShape>,
    previous_allocation: Option<DurableDecodeAllocation>,
    previous_usage: DurableDecodeUsage,
}

impl Drop for DurableDecodeShapeGuard {
    fn drop(&mut self) {
        DURABLE_DECODE_SHAPE.set(self.previous);
        DURABLE_DECODE_ALLOCATION.set(self.previous_allocation);
        DURABLE_DECODE_USAGE.set(self.previous_usage);
    }
}

pub(in crate::vm_lifecycle) fn enter_durable_decode_shape(
    current_processes: usize,
    staged_processes: usize,
    lifecycle_nodes: usize,
    completed_exits: usize,
) -> DurableDecodeShapeGuard {
    let shape = DurableDecodeShape {
        current_processes,
        staged_processes,
        lifecycle_nodes,
        completed_exits,
    };
    let previous = DURABLE_DECODE_SHAPE.replace(Some(shape));
    let previous_allocation = DURABLE_DECODE_ALLOCATION.replace(None);
    let previous_usage = DURABLE_DECODE_USAGE.replace(DurableDecodeUsage::default());
    DurableDecodeShapeGuard {
        previous,
        previous_allocation,
        previous_usage,
    }
}

pub(in crate::vm_lifecycle) fn take_durable_decode_allocation() -> Option<DurableDecodeAllocation> {
    DURABLE_DECODE_ALLOCATION.take()
}

pub(super) fn record_decode_allocation(field: &'static str, current: u64, requested: usize) {
    if DURABLE_DECODE_ALLOCATION.get().is_none() {
        DURABLE_DECODE_ALLOCATION.set(Some(DurableDecodeAllocation {
            field,
            current,
            requested: u64::try_from(requested).unwrap_or(u64::MAX),
        }));
    }
}

pub(super) fn decode_usage(field: &'static str) -> u64 {
    DURABLE_DECODE_USAGE.with(|usage| match field {
        "event_records" => usage.get().event_records,
        "event_log_bytes" => usage.get().event_log_bytes,
        _ => 0,
    })
}

pub(super) fn account_decode_usage(field: &'static str, amount: usize) {
    let amount = u64::try_from(amount).unwrap_or(u64::MAX);
    DURABLE_DECODE_USAGE.with(|usage| {
        let mut current = usage.get();
        match field {
            "event_records" => {
                current.event_records = current.event_records.saturating_add(amount);
            }
            "event_log_bytes" => {
                current.event_log_bytes = current.event_log_bytes.saturating_add(amount);
            }
            _ => {}
        }
        usage.set(current);
    });
}

pub(super) fn current_processes_expected() -> Option<usize> {
    DURABLE_DECODE_SHAPE
        .get()
        .map(|shape| shape.current_processes)
}

pub(super) fn staged_processes_expected() -> Option<usize> {
    DURABLE_DECODE_SHAPE
        .get()
        .map(|shape| shape.staged_processes)
}

pub(super) fn lifecycle_nodes_expected() -> Option<usize> {
    DURABLE_DECODE_SHAPE
        .get()
        .map(|shape| shape.lifecycle_nodes)
}

pub(super) fn completed_exits_expected() -> Option<usize> {
    DURABLE_DECODE_SHAPE
        .get()
        .map(|shape| shape.completed_exits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lifecycle::process_owners::{FallibleLifecycleRecords, deserialize_records};

    #[test]
    fn lifecycle_record_allocation_reports_previously_owned_record_usage() {
        let _guard = enter_durable_decode_shape(0, 0, 1, usize::MAX);
        let mut first = serde_json::Deserializer::from_str("[1]");
        let _records: FallibleLifecycleRecords<u8> = deserialize_records(&mut first, Some(1))
            .unwrap_or_else(|error| panic!("first record should decode: {error}"));

        let mut refused = serde_json::Deserializer::from_str("[]");
        let error = deserialize_records::<_, u8>(&mut refused, Some(usize::MAX));
        assert!(error.is_err());
        assert_eq!(
            take_durable_decode_allocation(),
            Some(DurableDecodeAllocation {
                field: "event_records",
                current: 1,
                requested: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
            })
        );
    }
}
