//! Exact material, original-credit refusal and returned API output custody.

use super::*;
use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use crucible::{Action, ControlOperationKind, Predicate, SchedulerEventLogEntry, VirtualTime};
use crucible_session::{
    BreakpointDisposition, BreakpointPolicy, BreakpointSpec, EventLogCursor, SessionCommandKind,
    SessionControlLogEntry, SessionControlPayload, SessionControlResult, SessionEventLogFrame,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

struct Authority {
    used: Arc<AtomicU64>,
    maximum: u64,
}

struct Credit {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.used.load(Ordering::SeqCst) > self.maximum {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("finite output allowance"))
            })?;
        Ok(crucible_cas::owned_decode::ResourceLoan::new(Credit {
            used: self.used.clone(),
            bytes,
        }))
    }
}

fn authority(maximum: u64) -> Arc<Authority> {
    Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum,
    })
}

pub(crate) fn tracked_fixture_budget(
    maximum: u64,
) -> Result<(DecodeBudget, Arc<AtomicU64>), DecodeAdmissionError> {
    let authority = authority(maximum);
    let used = Arc::clone(&authority.used);
    Ok((DecodeBudget::new(authority, maximum)?, used))
}

fn entry() -> SessionControlLogEntry {
    SessionControlLogEntry {
        sequence: 7,
        command: SessionCommandKind::SetBreakpoint,
        payload: SessionControlPayload::SetBreakpoint {
            spec: BreakpointSpec {
                predicate: Predicate::AllOf {
                    predicates: vec![
                        Predicate::named("é\nwater"),
                        Predicate::At {
                            at: VirtualTime { ticks: 91 },
                        },
                    ],
                },
                disposition: BreakpointDisposition::Action(Action::Group(vec![
                    Action::CreateSavepoint {
                        label: Some(String::from("water\n水")),
                    },
                    Action::Group(vec![
                        Action::Fail {
                            reason: String::from("no\nspoof"),
                        },
                        Action::Pass,
                    ]),
                ])),
                policy: BreakpointPolicy::OneShot,
            },
        },
        frontier: VirtualTime { ticks: 91 },
        quanta: 3,
        event_log_sequence_before: 21,
        result: SessionControlResult::Accepted,
        scheduler_batch: 2,
        scheduler_control: Some(ControlOperationKind::Snapshot),
    }
}

#[test]
fn admitted_reproduction_preserves_nested_material_and_releases_each_copy()
-> Result<(), Box<dyn std::error::Error>> {
    let original = entry();
    let expected_predicate = match &original.payload {
        SessionControlPayload::SetBreakpoint { spec } => spec.predicate.canonical_summary(),
        _ => return Err(std::io::Error::other("fixture breakpoint").into()),
    };
    fn hex(value: &str) -> String {
        value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    let savepoint = format!("action=create-savepoint\nlabel={}\n", hex("water\n水"));
    let failure = format!("action=fail\nreason={}\n", hex("no\nspoof"));
    let inner = format!(
        "action=group\ncount=2\nmember.0={}\nmember.1={}\n",
        hex(&failure),
        hex("action=pass\n")
    );
    let action = format!(
        "action=group\ncount=2\nmember.0={}\nmember.1={}\n",
        hex(&savepoint),
        hex(&inner)
    );
    let expected = format!(
        "payload=set-breakpoint\npredicate={}\ndisposition=action:{}\npolicy=one-shot\n",
        hex(&expected_predicate),
        hex(&action)
    );
    let owner = authority(1024 * 1024);
    let budget = DecodeBudget::new(owner.clone(), owner.maximum)?;
    let _scope = budget.enter();
    let baseline = owner.used.load(Ordering::SeqCst);

    let first = crate::ReproductionCommandRecord::from_admitted(&original)?;
    assert_eq!(first.value().payload.command_payload, expected);
    assert_eq!(first.value().sequence, original.sequence);
    let one = owner.used.load(Ordering::SeqCst) - baseline;
    assert!(one > 0);
    let second = crate::ReproductionCommandRecord::from_admitted(&original)?;
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline + one * 2);
    let escaped_payload = first.value().payload.clone();
    drop(first);
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline + one * 2);
    assert_eq!(escaped_payload.command_payload, expected);
    drop(escaped_payload);
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline + one);
    drop(second);
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline);
    for _ in 0..20 {
        let output = crate::ReproductionCommandRecord::from_admitted(&original)?;
        assert_eq!(output.value().payload.command_payload, expected);
        drop(output);
        assert_eq!(owner.used.load(Ordering::SeqCst), baseline);
    }
    Ok(())
}

#[test]
fn admitted_streaming_projection_matches_component_shape_and_transfers_custody()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = authority(1024 * 1024);
    let budget = DecodeBudget::new(owner.clone(), owner.maximum)?;
    let _scope = budget.enter();
    let baseline = owner.used.load(Ordering::SeqCst);
    let entry = SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        VirtualTime { ticks: 4 },
        "lifetime\né",
    )?;
    let frame = SessionEventLogFrame::from_entry_admitted(
        2,
        EventLogCursor::new(0),
        EventLogCursor::new(1),
        &entry,
    )?;
    let expected = crate::open_set_event_envelope_from_entry(&frame.entry);

    let output = crate::StreamingEventFrame::from_admitted(frame)?;
    assert_eq!(&**output.value().event, &expected);
    assert!(owner.used.load(Ordering::SeqCst) > baseline);
    let (value, custody) = output.into_parts();
    assert_eq!(&**value.event, &expected);
    let escaped_body = value.event.clone();
    drop(value);
    drop(custody);
    assert!(owner.used.load(Ordering::SeqCst) > baseline);
    assert_eq!(&**escaped_body, &expected);
    drop(escaped_body);
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline);
    Ok(())
}

#[test]
fn original_credit_refusal_returns_no_partial_reproduction_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let original = entry();
    let owner = authority(4096);
    let budget = DecodeBudget::new(owner.clone(), owner.maximum)?;
    let _scope = budget.enter();
    let baseline = owner.used.load(Ordering::SeqCst);
    let held = owner.reserve(owner.maximum - baseline - 1)?;
    let saturated = owner.used.load(Ordering::SeqCst);
    assert!(matches!(
        crate::ReproductionCommandRecord::from_admitted(&original),
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
    assert_eq!(owner.used.load(Ordering::SeqCst), saturated);
    drop(held);
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline);
    Ok(())
}

#[test]
fn owning_output_refuses_missing_original_authority() {
    assert!(matches!(
        crate::ReproductionCommandRecord::from_entry_admitted(&entry()),
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
}

#[test]
fn moving_output_shape_retains_credit_outside_the_original_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let (budget, used) = tracked_fixture_budget(1024 * 1024)?;
    let scope = budget.enter();
    let baseline = used.load(Ordering::SeqCst);
    struct WireBody {
        bytes: Vec<u8>,
    }
    let output = AdmittedOutput::build(|| {
        owned_decode::charge_array::<u8>(32).map_err(admission)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(32)
            .map_err(|source| admission(DecodeAdmissionError::new(source)))?;
        bytes.extend_from_slice(b"same original output custody");
        Ok(WireBody { bytes })
    })?;
    let retained = used.load(Ordering::SeqCst);
    assert!(retained > baseline);

    drop(scope);
    let projected = output.map(|body| body.bytes);
    assert_eq!(used.load(Ordering::SeqCst), retained);
    let wire = projected.into_wire_bytes()?;
    let final_reader = wire.clone();
    let with_header = used.load(Ordering::SeqCst);
    assert!(with_header > retained);
    drop(wire);
    assert_eq!(final_reader.as_ref(), b"same original output custody");
    assert_eq!(used.load(Ordering::SeqCst), with_header);
    drop(final_reader);
    assert_eq!(used.load(Ordering::SeqCst), baseline);
    drop(budget);
    assert_eq!(used.load(Ordering::SeqCst), 0);
    Ok(())
}

/// Supplies a finite original account for API output component fixtures.
///
/// # Errors
/// Refuses the fixture's finite original allocation admission.
pub(crate) fn fixture_budget() -> Result<DecodeBudget, DecodeAdmissionError> {
    Ok(fixture_budget_with_counter()?.0)
}

/// Returns the original finite fixture authority's retained-byte counter.
///
/// # Errors
/// Refuses the fixture's finite original allocation admission.
pub(crate) fn fixture_budget_with_counter()
-> Result<(DecodeBudget, Arc<AtomicU64>), DecodeAdmissionError> {
    let owner = authority(1024 * 1024);
    let budget = DecodeBudget::new(owner.clone(), owner.maximum)?;
    Ok((budget, owner.used.clone()))
}
