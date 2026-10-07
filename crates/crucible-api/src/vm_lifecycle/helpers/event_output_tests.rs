//! Linear prefix transfer and final-reader custody for lifecycle event output.

use super::*;
use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::atomic::{AtomicU64, Ordering};

struct Authority(Arc<AtomicU64>);
struct Credit {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.0.load(Ordering::Acquire) > 1024 * 1024 {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= 1024 * 1024)
            })
            .map_err(|_| DecodeAdmissionError::new(std::io::Error::other("fixture capacity")))?;
        Ok(Arc::new(Credit {
            used: Arc::clone(&self.0),
            bytes,
        }))
    }
}

fn append(sequence: u64) -> Result<SchedulerEventLogAppend, Box<dyn std::error::Error>> {
    let budget = crucible::owned_decode::require_current_child_budget()?;
    let _scope = budget.enter();
    let mut entries = Vec::new();
    crucible::owned_decode::reserve_vec(&mut entries, 1)?;
    entries.push(crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        VirtualTime { ticks: sequence },
        crucible::SchedulerEvaluationBoundaryKind::Quantum,
    )?);
    let mut segment_bytes = Vec::new();
    crucible::owned_decode::reserve_vec(&mut segment_bytes, 1)?;
    segment_bytes.push(u8::try_from(sequence)?);
    crucible::owned_decode::charge_bytes(1)?;
    let segment_text = String::from("x");
    Ok(SchedulerEventLogAppend {
        entries,
        segment_hash: Some(ContentHash::from_bytes(&segment_bytes)),
        segment_bytes,
        segment_text,
        offset: crucible::EventLogOffset::new(Default::default(), 0, sequence + 1),
        event_log_custody: crucible::EventLogOutputCustody::retain_current()?,
    })
}

fn outcome() -> QuantumOutcome {
    QuantumOutcome {
        configuration: Configuration::genesis(ScenarioDef::from_canonical_material(
            "api.prefix-transfer",
            "fixture",
        )),
        frontier: VirtualTime::default(),
        advanced_node: None,
        resolved_events: Vec::new(),
        decisions: Vec::new(),
        discovered_choices: Vec::new(),
        event_log_entries: Vec::new(),
        event_log_segment_bytes: Vec::new(),
        event_log_segment_text: String::new(),
        event_log_segment_hash: None,
        event_log_offset: Default::default(),
        scheduler_quiescence: None,
        event_log_custody: Default::default(),
    }
}

#[test]
fn prefix_moves_last_segment_and_retains_sources_until_output_closes()
-> Result<(), Box<dyn std::error::Error>> {
    let used = Arc::new(AtomicU64::new(0));
    let budget = DecodeBudget::new(Arc::new(Authority(Arc::clone(&used))), 1024 * 1024)?;
    let mut output = outcome();
    let (bytes_pointer, text_pointer) = {
        let _scope = budget.enter();
        let first = append(0)?;
        let last = append(1)?;
        let pointers = (last.segment_bytes.as_ptr(), last.segment_text.as_ptr());
        prepend_event_log_appends(&mut output, vec![first, last])?;
        pointers
    };
    drop(budget);

    assert!(
        output
            .event_log_entries
            .iter()
            .map(|entry| entry.sequence())
            .eq(0..2)
    );
    assert_eq!(output.event_log_segment_bytes.as_ptr(), bytes_pointer);
    assert_eq!(output.event_log_segment_text.as_ptr(), text_pointer);
    assert_eq!(output.event_log_segment_bytes, [1]);
    assert!(used.load(Ordering::Acquire) > 0);
    drop(output);
    assert_eq!(used.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn prefix_preserves_existing_final_segment_and_moves_all_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let _scope = crucible::test_support::fixture_decode_scope(1024 * 1024)?;
    let mut output = outcome();
    merge_event_log_append(&mut output, append(2)?)?;
    let pointer = output.event_log_segment_bytes.as_ptr();
    let hash = output.event_log_segment_hash;
    let offset = output.event_log_offset;
    prepend_event_log_appends(&mut output, vec![append(0)?, append(1)?])?;

    assert!(
        output
            .event_log_entries
            .iter()
            .map(|entry| entry.sequence())
            .eq(0..3)
    );
    assert_eq!(output.event_log_segment_bytes.as_ptr(), pointer);
    assert_eq!(output.event_log_segment_bytes, [2]);
    assert_eq!(output.event_log_segment_hash, hash);
    assert_eq!(output.event_log_offset, offset);
    Ok(())
}
