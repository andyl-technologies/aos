//! Typed QEMU occurrence evidence validation and lifecycle decisions.

use super::*;

#[path = "evidence/event_evidence.rs"]
mod event_evidence;
pub(crate) use event_evidence::{qemu_event_matches_commit, validate_node_event_evidence};

pub(super) const LIFECYCLE_EVIDENCE_BYTES: usize = 304;
pub(super) const HANG_EVIDENCE_BYTES: usize = 192;
pub(super) const LIFECYCLE_TERMINAL_CAUSE_NONE: u32 = 0;
pub(super) const LIFECYCLE_TERMINAL_CAUSE_DIRECT: u32 = 1;
pub(super) const LIFECYCLE_TERMINAL_CAUSE_READY_EXHAUSTED: u32 = 2;
pub(super) const LIFECYCLE_TERMINAL_CAUSE_FAIL_CLOSED: u32 = 3;
pub(super) const LIFECYCLE_TERMINAL_PRE_EXIT_VALID: u32 = 1 << 0;
pub(super) const LIFECYCLE_TERMINAL_EXIT_REQUIRED: u32 = 1 << 1;
pub(super) const LIFECYCLE_TERMINAL_KNOWN_FLAGS: u32 =
    LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED;

pub(super) fn node_lifecycle_decision(
    node: &NodeId,
    action_identity: ContentHash,
    event: &DequeuedFaultEvent,
) -> Option<QemuNodeLifecycleDecision> {
    if event.payload.get(0..8) != Some(b"CRUCLIF1") {
        return None;
    }
    let requested_transition =
        lifecycle_transition_from_tag(u32::from(read_u16(&event.payload, 10)?))?;
    let effective_transition = lifecycle_transition_from_tag(read_u32(&event.payload, 288)?)?;
    let flags = read_u32(&event.payload, 296)?;
    let expected_exit_code = if flags & LIFECYCLE_TERMINAL_EXIT_REQUIRED != 0 {
        Some(match effective_transition {
            NodeLifecycleTransition::Crash => 70,
            NodeLifecycleTransition::PowerOff => 71,
            NodeLifecycleTransition::PermanentFailure => 72,
            _ => return None,
        })
    } else {
        None
    };
    let pre_exit_hash = if flags & 1 != 0 {
        Some(ContentHash {
            bytes: event.payload[256..288].try_into().ok()?,
        })
    } else {
        None
    };
    let mut authorization_evidence: [u8; LIFECYCLE_EVIDENCE_BYTES] =
        event.payload.as_slice().try_into().ok()?;
    authorization_evidence[24..32].fill(0);
    Some(QemuNodeLifecycleDecision {
        node: node.clone(),
        action: action_identity,
        requested_transition,
        effective_transition,
        cause: read_u32(&event.payload, 292)?,
        expected_exit_code,
        observed_icount: event.header.observed_icount,
        pre_exit_hash,
        event_evidence: ContentHash {
            bytes: Sha256::digest(authorization_evidence).into(),
        },
    })
}

pub(super) fn node_boot_requests(
    actions: &[ResolvedBindingAction],
) -> Result<BTreeSet<NodeId>, ProductionFaultRuntimeError> {
    let mut nodes = BTreeSet::new();
    for action in actions {
        let EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
            transition: NodeLifecycleTransition::Boot,
            ..
        }) = action.effect.specification()
        else {
            continue;
        };
        let crucible::model::ResolvedFaultTarget::Node { node } = &action.target else {
            return Err(BackendError::Rejected {
                message: format!(
                    "boot lifecycle action `{}` resolved to a non-node target",
                    action.binding
                ),
            }
            .into());
        };
        nodes.insert(NodeId {
            name: node.as_str().to_owned(),
        });
    }
    Ok(nodes)
}

pub(super) const fn lifecycle_transition_from_tag(tag: u32) -> Option<NodeLifecycleTransition> {
    match tag {
        1 => Some(NodeLifecycleTransition::Boot),
        2 => Some(NodeLifecycleTransition::Crash),
        3 => Some(NodeLifecycleTransition::Reset),
        4 => Some(NodeLifecycleTransition::PowerOff),
        5 => Some(NodeLifecycleTransition::PowerCycle),
        6 => Some(NodeLifecycleTransition::PermanentFailure),
        _ => None,
    }
}

pub(super) fn validate_lifecycle_evidence(
    event: &DequeuedFaultEvent,
    effect: &NodeEffectSpecification,
) -> bool {
    let bytes = event.payload.as_slice();
    if bytes.len() != LIFECYCLE_EVIDENCE_BYTES
        || bytes.get(0..8) != Some(b"CRUCLIF1")
        || read_u16(bytes, 8) != Some(4)
        || !matches!(
            event.header.outcome,
            FaultEventOutcomeV1::Applied | FaultEventOutcomeV1::Error
        )
        || read_u64(bytes, 24) != Some(event.header.observed_icount)
        || bytes.get(64..96) != Some(event.header.binding_hash.as_slice())
        || bytes.get(128..160) != Some(event.header.before_hash.as_slice())
        || bytes.get(160..192) != Some(event.header.after_hash.as_slice())
    {
        return false;
    }
    let Some(transition) = read_u16(bytes, 10) else {
        return false;
    };
    let Some(volatile_policy) = read_u32(bytes, 12) else {
        return false;
    };
    let Some(device_policy) = read_u32(bytes, 16) else {
        return false;
    };
    let Some(preserved_domains) = read_u32(bytes, 20) else {
        return false;
    };
    let Some(virtual_before) = read_u64(bytes, 32) else {
        return false;
    };
    let Some(downtime) = read_u64(bytes, 40) else {
        return false;
    };
    let Some(virtual_after) = read_u64(bytes, 96) else {
        return false;
    };
    let expected_preserved_domains = if matches!(transition, 1 | 3 | 5) {
        u32::from(volatile_policy == 1) | (u32::from(device_policy == 1) << 1)
    } else {
        0
    };
    if !(1..=6).contains(&transition)
        || !(1..=2).contains(&volatile_policy)
        || !(1..=3).contains(&device_policy)
        || preserved_domains != expected_preserved_domains
        || virtual_before.checked_add(downtime) != Some(virtual_after)
        || read_u64(bytes, 48).is_none_or(|ram_bytes| ram_bytes == 0)
        || read_u64(bytes, 56).is_none()
    {
        return false;
    }
    let Some(effective_transition) = read_u32(bytes, 288) else {
        return false;
    };
    let Some(terminal_cause) = read_u32(bytes, 292) else {
        return false;
    };
    let Some(terminal_flags) = read_u32(bytes, 296) else {
        return false;
    };
    if !(1..=6).contains(&effective_transition)
        || terminal_flags & !LIFECYCLE_TERMINAL_KNOWN_FLAGS != 0
        || bytes.get(300..304) != Some([0_u8; 4].as_slice())
        || !validate_lifecycle_terminal_shape(
            event,
            bytes,
            transition,
            effective_transition,
            terminal_cause,
            terminal_flags,
        )
    {
        return false;
    }
    match effect {
        NodeEffectSpecification::Lifecycle {
            transition: expected_transition,
            downtime_nanos,
            boot_policy,
            volatile_state_policy,
            device_state_policy,
        } => {
            let boot_is_valid = validate_boot_evidence(bytes, boot_policy);
            transition == lifecycle_tag(*expected_transition)
                && downtime == *downtime_nanos
                && volatile_policy == state_policy_tag(*volatile_state_policy)
                && device_policy == state_policy_tag(*device_state_policy)
                && boot_is_valid
                && validate_lifecycle_terminal_policy(
                    boot_policy,
                    effective_transition,
                    terminal_cause,
                )
        }
        NodeEffectSpecification::Hang {
            watchdog_policy: NodeWatchdogPolicy::TransitionAfter { boot_policy, .. },
            ..
        } => {
            validate_boot_evidence_shape(bytes)
                && validate_lifecycle_terminal_policy(
                    boot_policy,
                    effective_transition,
                    terminal_cause,
                )
        }
        _ => false,
    }
}

/// Validates the lifecycle evidence emitted by the real-QEMU negative gate.
///
/// This is the same production decoder used during normal event admission; the
/// gate wrapper fixes only the authored effect whose real output it requested.
pub(crate) fn validate_live_gate_lifecycle_event(event: &DequeuedFaultEvent) -> bool {
    validate_lifecycle_evidence(
        event,
        &NodeEffectSpecification::Lifecycle {
            transition: NodeLifecycleTransition::Crash,
            downtime_nanos: 1,
            boot_policy: NodeBootPolicy::Immediate,
            volatile_state_policy: NodeStatePolicy::Preserve,
            device_state_policy: NodeStatePolicy::Clear,
        },
    )
}

/// Summarizes the independent lifecycle-evidence predicates used by the live gate.
pub(crate) fn live_gate_lifecycle_event_diagnostic(event: &DequeuedFaultEvent) -> String {
    let bytes = event.payload.as_slice();
    let transition = read_u16(bytes, 10);
    let volatile_policy = read_u32(bytes, 12);
    let device_policy = read_u32(bytes, 16);
    let effective_transition = read_u32(bytes, 288);
    let terminal_cause = read_u32(bytes, 292);
    let terminal_flags = read_u32(bytes, 296);
    let terminal_shape = transition
        .zip(effective_transition)
        .zip(terminal_cause)
        .zip(terminal_flags)
        .is_some_and(|(((requested, effective), cause), flags)| {
            validate_lifecycle_terminal_shape(event, bytes, requested, effective, cause, flags)
        });
    let boot_valid = validate_boot_evidence(bytes, &NodeBootPolicy::Immediate);
    let terminal_policy =
        effective_transition
            .zip(terminal_cause)
            .is_some_and(|(effective, cause)| {
                validate_lifecycle_terminal_policy(&NodeBootPolicy::Immediate, effective, cause)
            });

    format!(
        "len={} magic={} version={:?} outcome={:?} observed={} binding={} payload_before={} payload_after={} transition={transition:?} volatile={volatile_policy:?} device={device_policy:?} preserved={:?} virtual_before={:?} downtime={:?} virtual_after={:?} ram_before={:?} device_before={:?} ram_after={:?} device_after={:?} effective={effective_transition:?} cause={terminal_cause:?} flags={terminal_flags:?} terminal_shape={terminal_shape} boot={boot_valid} terminal_policy={terminal_policy}",
        bytes.len(),
        bytes.get(0..8) == Some(b"CRUCLIF1"),
        read_u16(bytes, 8),
        event.header.outcome,
        read_u64(bytes, 24) == Some(event.header.observed_icount),
        bytes.get(64..96) == Some(event.header.binding_hash.as_slice()),
        bytes.get(128..160) == Some(event.header.before_hash.as_slice()),
        bytes.get(160..192) == Some(event.header.after_hash.as_slice()),
        read_u32(bytes, 20),
        read_u64(bytes, 32),
        read_u64(bytes, 40),
        read_u64(bytes, 96),
        read_u64(bytes, 48),
        read_u64(bytes, 56),
        read_u64(bytes, 112),
        read_u64(bytes, 120),
    )
}

pub(super) fn validate_lifecycle_terminal_shape(
    event: &DequeuedFaultEvent,
    bytes: &[u8],
    requested_transition: u16,
    effective_transition: u32,
    cause: u32,
    flags: u32,
) -> bool {
    let pre_exit = bytes.get(256..288);
    let pre_exit_valid = flags & LIFECYCLE_TERMINAL_PRE_EXIT_VALID != 0;
    let exit_required = flags & LIFECYCLE_TERMINAL_EXIT_REQUIRED != 0;
    let effective_is_terminal = matches!(effective_transition, 2 | 4 | 6);
    let digest_is_valid = pre_exit_valid
        && pre_exit.is_some_and(|hash| {
            let mut material = [0_u8; 48];
            material[0..8].copy_from_slice(b"CRUCTRM1");
            material[8..12].copy_from_slice(&effective_transition.to_le_bytes());
            material[16..48].copy_from_slice(hash);
            let derived: [u8; 32] = Sha256::digest(material).into();
            hash != [0_u8; 32] && derived == event.header.after_hash
        });

    match cause {
        LIFECYCLE_TERMINAL_CAUSE_NONE => {
            event.header.outcome == FaultEventOutcomeV1::Applied
                && effective_transition == u32::from(requested_transition)
                && flags == 0
                && pre_exit == Some([0_u8; 32].as_slice())
                && lifecycle_terminal_counts_are_valid(bytes)
        }
        LIFECYCLE_TERMINAL_CAUSE_DIRECT => {
            event.header.outcome == FaultEventOutcomeV1::Applied
                && matches!(requested_transition, 2 | 4 | 6)
                && effective_transition == u32::from(requested_transition)
                && flags == LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED
                && digest_is_valid
                && lifecycle_terminal_counts_are_valid(bytes)
        }
        LIFECYCLE_TERMINAL_CAUSE_READY_EXHAUSTED => {
            event.header.outcome == FaultEventOutcomeV1::Applied
                && effective_is_terminal
                && flags == LIFECYCLE_TERMINAL_PRE_EXIT_VALID | LIFECYCLE_TERMINAL_EXIT_REQUIRED
                && digest_is_valid
                && lifecycle_terminal_counts_are_valid(bytes)
        }
        LIFECYCLE_TERMINAL_CAUSE_FAIL_CLOSED => {
            event.header.outcome == FaultEventOutcomeV1::Error
                && effective_transition
                    == u32::from(lifecycle_tag(NodeLifecycleTransition::PermanentFailure))
                && exit_required
                && if pre_exit_valid {
                    digest_is_valid && lifecycle_terminal_counts_are_valid(bytes)
                } else {
                    pre_exit == Some([0_u8; 32].as_slice())
                        && event.header.after_hash == event.header.before_hash
                        && read_u64(bytes, 112) == Some(0)
                        && read_u64(bytes, 120) == Some(0)
                }
        }
        _ => false,
    }
}

pub(super) fn lifecycle_terminal_counts_are_valid(bytes: &[u8]) -> bool {
    read_u64(bytes, 112) == read_u64(bytes, 48)
        && read_u64(bytes, 120).is_some_and(|device_bytes| device_bytes != 0)
}

pub(super) fn validate_lifecycle_terminal_policy(
    boot_policy: &NodeBootPolicy,
    effective_transition: u32,
    cause: u32,
) -> bool {
    match cause {
        LIFECYCLE_TERMINAL_CAUSE_READY_EXHAUSTED => matches!(
            boot_policy,
            NodeBootPolicy::RequireReady { exhausted, .. }
                if effective_transition == u32::from(lifecycle_tag(*exhausted))
        ),
        LIFECYCLE_TERMINAL_CAUSE_FAIL_CLOSED => {
            matches!(
                boot_policy,
                NodeBootPolicy::RequireReady { .. } | NodeBootPolicy::Immediate
            )
        }
        _ => true,
    }
}

pub(super) fn validate_boot_evidence(bytes: &[u8], policy: &NodeBootPolicy) -> bool {
    match policy {
        NodeBootPolicy::Immediate => {
            read_u32(bytes, 192) == Some(1)
                && read_u32(bytes, 196) == Some(1)
                && read_u32(bytes, 200) == Some(1)
                && read_u32(bytes, 204) == Some(0)
                && read_u64(bytes, 208) == Some(0)
                && read_u64(bytes, 216) == Some(u64::MAX)
                && bytes.get(224..256) == Some([0_u8; 32].as_slice())
        }
        NodeBootPolicy::RequireReady {
            ready_marker,
            maximum_attempts,
            retry_delay_nanos,
            exhausted,
        } => {
            let marker_hash: [u8; 32] = Sha256::digest(ready_marker.as_str().as_bytes()).into();
            read_u32(bytes, 192) == Some(2)
                && read_u32(bytes, 196)
                    .is_some_and(|attempt| attempt > 0 && attempt <= maximum_attempts.get())
                && read_u32(bytes, 200) == Some(maximum_attempts.get())
                && read_u32(bytes, 204) == Some(u32::from(lifecycle_tag(*exhausted)))
                && read_u64(bytes, 208) == Some(*retry_delay_nanos)
                && read_u64(bytes, 216).is_some_and(|deadline| deadline != u64::MAX)
                && bytes.get(224..256) == Some(marker_hash.as_slice())
        }
    }
}

pub(super) fn validate_boot_evidence_shape(bytes: &[u8]) -> bool {
    match read_u32(bytes, 192) {
        Some(1) => {
            read_u32(bytes, 196) == Some(1)
                && read_u32(bytes, 200) == Some(1)
                && read_u32(bytes, 204) == Some(0)
                && read_u64(bytes, 208) == Some(0)
                && read_u64(bytes, 216) == Some(u64::MAX)
                && bytes.get(224..256) == Some([0_u8; 32].as_slice())
        }
        Some(2) => {
            read_u32(bytes, 196).is_some_and(|attempt| attempt > 0)
                && read_u32(bytes, 200).is_some_and(|maximum| maximum > 0)
                && read_u32(bytes, 196) <= read_u32(bytes, 200)
                && read_u32(bytes, 204).is_some_and(|transition| (2..=6).contains(&transition))
                && read_u64(bytes, 216).is_some_and(|deadline| deadline != u64::MAX)
                && bytes.get(224..256).is_some_and(|hash| hash != [0_u8; 32])
        }
        _ => false,
    }
}

pub(super) fn validate_hang_evidence(
    event: &DequeuedFaultEvent,
    effect: &NodeEffectSpecification,
) -> bool {
    let NodeEffectSpecification::Hang {
        scope,
        watchdog_policy,
        ..
    } = effect
    else {
        return false;
    };
    let bytes = event.payload.as_slice();
    if bytes.len() != HANG_EVIDENCE_BYTES || event.header.outcome != FaultEventOutcomeV1::Applied {
        return false;
    }
    match bytes.get(0..8) {
        Some(b"CRUCHNG1") => {
            read_u16(bytes, 8) == Some(1)
                && read_u16(bytes, 10).is_some_and(|kind| kind == 1 || kind == 2)
                && read_u32(bytes, 12) == Some(hang_scope_tag(scope))
                && read_u64(bytes, 56) == Some(event.header.observed_icount)
                && read_u64(bytes, 48) == Some(event.header.generation)
                && bytes.get(64..96) == Some(event.header.binding_hash.as_slice())
                && bytes.get(96..128) == Some(event.header.action_hash.as_slice())
                && bytes.get(128..160) == Some(event.header.before_hash.as_slice())
                && bytes.get(160..192) == Some(event.header.after_hash.as_slice())
        }
        Some(b"CRUCWDC1") => {
            let NodeWatchdogPolicy::TransitionAfter {
                transition,
                downtime_nanos,
                volatile_state_policy,
                device_state_policy,
                ..
            } = watchdog_policy
            else {
                return false;
            };
            read_u16(bytes, 8) == Some(1)
                && read_u16(bytes, 10) == Some(lifecycle_tag(*transition))
                && read_u16(bytes, 12).is_some_and(|value| (1..=6).contains(&value))
                && read_u32(bytes, 16) == Some(state_policy_tag(*volatile_state_policy))
                && read_u32(bytes, 20) == Some(state_policy_tag(*device_state_policy))
                && read_u32(bytes, 24).is_some_and(|value| (1..=2).contains(&value))
                && read_u32(bytes, 28).is_some_and(|value| (1..=3).contains(&value))
                && read_u64(bytes, 32) == Some(*downtime_nanos)
                && read_u64(bytes, 48) == read_u64(bytes, 56)
                && bytes.get(64..96) == Some(event.header.binding_hash.as_slice())
                && bytes.get(128..160) == Some(event.header.action_hash.as_slice())
                && bytes.get(96..128).is_some_and(|hash| hash != [0_u8; 32])
                && bytes.get(160..192).is_some_and(|hash| hash != [0_u8; 32])
        }
        _ => false,
    }
}

pub(super) const fn lifecycle_tag(value: NodeLifecycleTransition) -> u16 {
    match value {
        NodeLifecycleTransition::Boot => 1,
        NodeLifecycleTransition::Crash => 2,
        NodeLifecycleTransition::Reset => 3,
        NodeLifecycleTransition::PowerOff => 4,
        NodeLifecycleTransition::PowerCycle => 5,
        NodeLifecycleTransition::PermanentFailure => 6,
    }
}

pub(super) const fn state_policy_tag(value: NodeStatePolicy) -> u32 {
    match value {
        NodeStatePolicy::Preserve => 1,
        NodeStatePolicy::Clear => 2,
        NodeStatePolicy::DeviceReset => 3,
    }
}

pub(super) const fn hang_scope_tag(value: &NodeHangScope) -> u32 {
    match value {
        NodeHangScope::Node => 1,
        NodeHangScope::Vcpus(_) => 2,
        NodeHangScope::Device(_) => 3,
    }
}

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

pub(super) fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}
