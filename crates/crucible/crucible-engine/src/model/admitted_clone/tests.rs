//! Original resource refusal and semantic identity tests for admitted model copies.

use super::*;
use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
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
    ) -> Result<crate::owned_decode::ResourceLoan, DecodeAdmissionError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(io::Error::other("fixture allowance exhausted"))
            })?;
        Ok(crate::owned_decode::ResourceLoan::new(Credit {
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

fn form() -> Result<ScenarioDefForm, EngineError> {
    let world = World::from_nodes(vec![WorldNode {
        id: NodeId { name: "é".into() },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: "quiet 水".into(),
        ready_point: ReadyPoint::ConsoleMarker {
            marker: "ready".into(),
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
    )
}

#[test]
fn admitted_form_copy_preserves_canonical_identity_and_retains_actual_credit()
-> Result<(), Box<dyn Error>> {
    let original = form()?;
    let authority = authority(4 * 1024 * 1024);
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let scope = budget.enter();
    let copied = original.try_clone_admitted()?;
    assert_eq!(original, copied);
    assert_eq!(
        original.to_compact_binary(),
        copied.to_compact_binary_admitted()?
    );
    assert_eq!(original.id(), copied.id());
    let custody = budget.custody();
    drop(scope);
    drop(budget);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    drop(copied);
    drop(custody);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn admitted_copy_refuses_exhaustion_without_changing_cached_identity() -> Result<(), Box<dyn Error>>
{
    let original = form()?;
    let expected = original.id();
    let budget = DecodeBudget::new(authority(4096), 4096)?;
    let _scope = budget.enter();
    assert!(budget.charge_bytes(4096).is_err());
    assert!(matches!(
        original.try_clone_admitted(),
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
    assert_eq!(original.id(), expected);
    assert_eq!(original.scenario_def().id(), expected);
    assert!(matches!(
        canonical_scenario_definition(
            original.world(),
            original.plan(),
            original.properties(),
            original.measurements(),
            original.selectables(),
            original.seed(),
            original.app_random_draw_cap()
        ),
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
    Ok(())
}

#[test]
fn admitted_schedule_prefix_preserves_dynamic_decision_fields() -> Result<(), EngineError> {
    let schedule = Schedule::from_decisions(vec![Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: "é/水".into()
        },
        choice: ChoiceTag {
            name: "selected".into(),
        },
    })]);
    let copied = schedule.try_clone_admitted()?;
    assert_eq!(copied, schedule);
    assert_eq!(schedule.prefix_admitted(1)?, schedule);
    assert_eq!(schedule.prefix_admitted(0)?, Schedule::empty());
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("copy"),
        value: 7,
    });
    assert_eq!(
        schedule.appended_admitted(decision.clone())?,
        schedule.appended(decision)
    );
    assert!(schedule.prefix_admitted(2).is_err());
    Ok(())
}

#[test]
fn runtime_append_preserves_fields_beyond_artifact_string_limits() -> Result<(), EngineError> {
    let decision = Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: "x".repeat(MAX_SCENARIO_BINARY_STRING_BYTES + 1),
        },
        choice: ChoiceTag { name: "é".into() },
    });
    let original = Schedule {
        _decode_custody: Default::default(),
        decisions: vec![decision],
    };
    let next = Decision::RngDraw(RngDecision {
        stream: RngStreamId::new("domain", "name"),
        value: 9,
    });
    let expected = original.appended(next.clone());
    let actual = original.appended_admitted(next)?;
    assert_eq!(actual, expected);
    assert_eq!(actual.content_hash(), expected.content_hash());
    assert_eq!(original.try_clone_admitted()?, original);
    let configuration = Configuration {
        def: form()?.scenario_def(),
        schedule: original,
    };
    let appended = Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: "runtime".into(),
        },
        choice: ChoiceTag {
            name: "after-large-field".into(),
        },
    });
    let expected = Configuration {
        def: configuration.def.clone(),
        schedule: configuration.schedule.appended(appended.clone()),
    };
    let actual = try_step(&configuration, appended)?;
    assert_eq!(actual, expected);
    assert_eq!(actual.id(), expected.id());
    Ok(())
}

#[test]
fn partial_structural_copy_refuses_without_publishing_and_retains_credit()
-> Result<(), Box<dyn Error>> {
    let original = Schedule {
        _decode_custody: Default::default(),
        decisions: vec![Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: "x".repeat(4096),
            },
            choice: ChoiceTag {
                name: "unchanged".into(),
            },
        })],
    };
    let authority = authority(2048);
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let scope = budget.enter();
    let before = original.content_hash();
    let next = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("next"),
        value: 8,
    });
    assert!(matches!(
        original.appended_admitted(next),
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
    assert_eq!(original.content_hash(), before);
    assert_eq!(original.len(), 1);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    let custody = budget.custody();
    drop(scope);
    drop(budget);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    drop(custody);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn structural_copy_preserves_delivery_and_preemption_selection_evidence()
-> Result<(), Box<dyn Error>> {
    let root = Configuration::genesis(form()?.scenario_def());
    let config = PreemptionBranchConfig {
        node: NodeId { name: "é".into() },
        deadline: SimInstant { ticks: 2 },
        horizon: SimInstant { ticks: 2 },
        step: 1,
        switch_from_vcpu: VcpuId { index: 0 },
        switch_to_vcpu: VcpuId { index: 0 },
        target_vcpu: VcpuId { index: 0 },
        irq: IrqVector { vector: 32 },
    };
    let choices = preemption_branch_choices(&root, &config)?.1;
    let choice = choices.first().ok_or("missing preemption fixture")?;
    let selection = match choice.decision() {
        Decision::Selection(selection) => selection,
        _ => return Err("fixture lacks authenticated selection".into()),
    };
    let expected_json = serde_json::json!({
        "canonical_selection": selection.canonical_bytes(),
        "preemption_config": selection.preemption_config(),
    });
    let mut source = Schedule {
        _decode_custody: Default::default(),
        decisions: choice.decisions().to_vec(),
    };
    let endpoint = SchedulerNodeId {
        node: NodeId {
            name: "producer/水".into(),
        },
        kind: SchedulingNodeKind::Vm,
    };
    source
        .decisions
        .push(Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 7 },
            order: vec![EventKey::new(
                VirtualTime { ticks: 7 },
                endpoint.clone(),
                endpoint,
                9,
            )],
        }));
    let authority = authority(128 * 1024);
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let _scope = budget.enter();
    let copied = source.try_clone_admitted()?;
    assert_eq!(copied, source);
    assert_eq!(copied.content_hash(), source.content_hash());
    assert_eq!(copied.to_compact_binary(), source.to_compact_binary());
    let copied_selection = selection.try_clone_admitted()?;
    assert_eq!(copied_selection.preemption_config(), Some(&config));
    assert_eq!(serde_json::to_value(&copied_selection)?, expected_json);
    assert!(authority.used.load(Ordering::SeqCst) > 0);
    Ok(())
}

#[test]
fn dropped_runtime_copies_release_original_authority_without_accumulating()
-> Result<(), Box<dyn Error>> {
    let source = Schedule::from_decisions([Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: "retained runtime point".repeat(16),
        },
        choice: ChoiceTag {
            name: "choice".into(),
        },
    })]);
    let authority = authority(64 * 1024);
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let scope = budget.enter();
    let baseline = authority.used.load(Ordering::SeqCst);

    for _ in 0..2048 {
        let copied = source.try_clone_admitted()?;
        assert_eq!(copied.content_hash(), source.content_hash());
        assert!(authority.used.load(Ordering::SeqCst) > baseline);
        drop(copied);
        assert_eq!(authority.used.load(Ordering::SeqCst), baseline);
    }

    let first = source.try_clone_admitted()?;
    let one_copy = authority.used.load(Ordering::SeqCst) - baseline;
    let second = source.try_clone_admitted()?;
    assert_eq!(
        authority.used.load(Ordering::SeqCst),
        baseline + 2 * one_copy
    );
    drop(first);
    assert_eq!(authority.used.load(Ordering::SeqCst), baseline + one_copy);
    drop(scope);
    drop(budget);
    assert_eq!(authority.used.load(Ordering::SeqCst), one_copy);
    drop(second);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}
