//! Observation-only reconciliation of durable host authority with systemd.
//!
//! This module joins one already authenticated [`crate::state::HostState`]
//! with one structurally validated, bounded discovery snapshot. It cannot
//! establish the snapshot's provenance. It does not adopt a unit, pin a
//! process, call a worker, or authorize a lifecycle effect. A current match is
//! only name correspondence; any later mutation requires a fresh unit
//! observation and independent invocation, cgroup, and process binding.

use std::collections::{BTreeMap, BTreeSet};

use aos_systemd::{
    DiscoveredSandboxUnit, FreezerState, SandboxDiscoveryConflict, SandboxQuarantineEvidence,
    SandboxUnitDiscoverySnapshot, SandboxUnitName,
};

use crate::worker::HostRuntimeIdentity;
use crate::{HostError, Result};

const MAXIMUM_DISCOVERED_OBJECTS: usize = 1_024;
const MAXIMUM_FIELD_BYTES: usize = 4_096;
const MAXIMUM_DISCOVERY_BYTES: usize = 1024 * 1024;

/// Selects the closed host operation retained by one durable request.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RetainedRuntimeIntent {
    /// Starts a new incarnation from descriptor-pinned inputs.
    Launch,
    /// Stops the incarnation's transient service.
    Stop,
    /// Freezes the incarnation's complete cgroup subtree.
    Freeze,
    /// Thaws the incarnation's complete cgroup subtree.
    Thaw,
    /// Kills every process in the incarnation's service cgroup.
    Kill,
}

/// Reports whether one retained request has a durable completion receipt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RetainedEffectDurability {
    /// The effect may have happened, but no completion receipt is durable.
    Pending,
    /// The request has an authenticated durable completion receipt.
    Complete,
}

/// Describes one authenticated runtime effect retained by host state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetainedRuntimeEffect {
    /// Assignment identity authenticated by the retained fence.
    pub identity: HostRuntimeIdentity,
    /// Exact durable request identifier.
    pub request_id: [u8; 16],
    /// Closed operation authenticated for this request.
    pub intent: RetainedRuntimeIntent,
    /// Durable receipt status of this request.
    pub durability: RetainedEffectDurability,
}

/// Joins one current durable expectation with a same-name systemd unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentRuntimeMatch {
    /// Current witness request for this sandbox.
    pub expected: RetainedRuntimeEffect,
    /// Ephemeral systemd observation; this is not adoption authority.
    pub observed: DiscoveredSandboxUnit,
}

/// Reports a current durable expectation absent from the discovery snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissingCurrentRuntime {
    /// Current witness request whose incarnation was not discovered.
    pub expected: RetainedRuntimeEffect,
}

/// Reports an observed unit retained only by historical host authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalRuntimeResidual {
    /// Incarnation encoded by the residual unit name.
    pub incarnation: [u8; 16],
    /// Every retained historical request for this incarnation, in stable order.
    pub retained: Vec<RetainedRuntimeEffect>,
    /// Ephemeral systemd observation; this is not cleanup authority.
    pub observed: DiscoveredSandboxUnit,
}

/// Reports historical authority for an incarnation not observed in systemd.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnobservedRuntimeHistory {
    /// Retained historical incarnation.
    pub incarnation: [u8; 16],
    /// Every retained historical request for this incarnation, in stable order.
    pub retained: Vec<RetainedRuntimeEffect>,
}

/// Complete bounded join of authenticated host state and systemd discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRuntimeRecoveryReport {
    /// Current expectations with a same-name observed unit.
    pub current: Vec<CurrentRuntimeMatch>,
    /// Current expectations with no observed unit.
    pub missing: Vec<MissingCurrentRuntime>,
    /// Observed units retained only by historical authority.
    pub historical_residuals: Vec<HistoricalRuntimeResidual>,
    /// Historical incarnations with no observed unit.
    pub unobserved_history: Vec<UnobservedRuntimeHistory>,
    /// Canonical observed units absent from all retained host authority.
    pub quarantine: Vec<SandboxQuarantineEvidence>,
    /// Prefix lookalikes retained verbatim for operator inspection.
    pub conflicts: Vec<SandboxDiscoveryConflict>,
}

#[derive(Debug)]
pub(crate) struct RetainedRuntimeInventory {
    pub(crate) current: Vec<RetainedRuntimeEffect>,
    pub(crate) historical: Vec<RetainedRuntimeEffect>,
}

pub(crate) fn reconcile(
    retained: RetainedRuntimeInventory,
    snapshot: SandboxUnitDiscoverySnapshot,
) -> Result<HostRuntimeRecoveryReport> {
    validate_snapshot(&snapshot)?;

    let mut current_by_incarnation = BTreeMap::new();
    for effect in retained.current {
        if current_by_incarnation
            .insert(*effect.identity.incarnation_id(), effect)
            .is_some()
        {
            return Err(invalid("duplicate current retained incarnation"));
        }
    }
    let mut historical_by_incarnation = BTreeMap::<_, Vec<_>>::new();
    for effect in retained.historical {
        historical_by_incarnation
            .entry(*effect.identity.incarnation_id())
            .or_default()
            .push(effect);
    }
    for effects in historical_by_incarnation.values_mut() {
        effects.sort_unstable();
    }

    let mut current = Vec::new();
    let mut historical_residuals = Vec::new();
    let mut quarantine = Vec::new();
    reserve(&mut current, snapshot.units.len(), "current matches")?;
    reserve(
        &mut historical_residuals,
        snapshot.units.len(),
        "historical residuals",
    )?;
    reserve(&mut quarantine, snapshot.units.len(), "quarantine evidence")?;

    for observed in snapshot.units {
        if let Some(expected) = current_by_incarnation.remove(&observed.incarnation) {
            current.push(CurrentRuntimeMatch { expected, observed });
        } else if let Some(retained) = historical_by_incarnation.remove(&observed.incarnation) {
            historical_residuals.push(HistoricalRuntimeResidual {
                incarnation: observed.incarnation,
                retained,
                observed,
            });
        } else {
            quarantine.push(SandboxQuarantineEvidence {
                observed,
                reason: "canonical systemd unit is absent from authenticated host authority"
                    .to_owned(),
            });
        }
    }

    let mut missing = Vec::new();
    reserve(
        &mut missing,
        current_by_incarnation.len(),
        "missing current runtimes",
    )?;
    missing.extend(
        current_by_incarnation
            .into_values()
            .map(|expected| MissingCurrentRuntime { expected }),
    );
    let mut unobserved_history = Vec::new();
    reserve(
        &mut unobserved_history,
        historical_by_incarnation.len(),
        "unobserved runtime history",
    )?;
    unobserved_history.extend(historical_by_incarnation.into_iter().map(
        |(incarnation, retained)| UnobservedRuntimeHistory {
            incarnation,
            retained,
        },
    ));
    Ok(HostRuntimeRecoveryReport {
        current,
        missing,
        historical_residuals,
        unobserved_history,
        quarantine,
        conflicts: snapshot.conflicts,
    })
}

fn validate_snapshot(snapshot: &SandboxUnitDiscoverySnapshot) -> Result<()> {
    if snapshot
        .units
        .len()
        .checked_add(snapshot.conflicts.len())
        .is_none_or(|count| count > MAXIMUM_DISCOVERED_OBJECTS)
    {
        return Err(invalid("systemd discovery exceeds its object ceiling"));
    }
    let mut bytes = 0_usize;
    let mut names = BTreeSet::new();
    let mut object_paths = BTreeSet::new();
    for (index, unit) in snapshot.units.iter().enumerate() {
        if unit.incarnation == [0; 16]
            || unit.unit != SandboxUnitName::from_incarnation(unit.incarnation)
            || !names.insert(unit.unit.as_str())
            || !object_paths.insert(unit.object_path.as_str())
        {
            return Err(invalid(
                "systemd discovery contains a noncanonical or duplicate unit",
            ));
        }
        if index > 0 && snapshot.units[index - 1].unit.cmp(&unit.unit).is_ge() {
            return Err(invalid("systemd discovery units are not strictly sorted"));
        }
        for (value, allow_empty) in [
            (unit.unit.as_str(), false),
            (unit.unit.guardian(), false),
            (unit.object_path.as_str(), false),
            (unit.load_state.as_str(), false),
            (unit.active_state.as_str(), false),
            (unit.sub_state.as_str(), false),
        ] {
            charge(value, allow_empty, &mut bytes)?;
        }
        charge_fixed(16, &mut bytes)?;
        if !valid_unit_object_path(&unit.object_path)
            || unit
                .cgroup
                .as_ref()
                .is_some_and(|cgroup| cgroup != &unit.unit.cgroup_path())
            || unit.invocation_id == Some([0; 16])
            || (unit.supervisor_pid.is_some()
                && (unit.cgroup.is_none() || unit.invocation_id.is_none()))
        {
            return Err(invalid("systemd discovery unit fields are inconsistent"));
        }
        if let FreezerState::Unknown(value) = &unit.freezer_state {
            if matches!(value.as_str(), "running" | "freezing" | "frozen") {
                return Err(invalid("systemd freezer state is noncanonical"));
            }
            charge(value, false, &mut bytes)?;
        }
        if let Some(cgroup) = &unit.cgroup {
            charge(cgroup.as_str(), false, &mut bytes)?;
        }
        if unit.invocation_id.is_some() {
            charge_fixed(16, &mut bytes)?;
        }
    }
    for (index, conflict) in snapshot.conflicts.iter().enumerate() {
        if index > 0 && snapshot.conflicts[index - 1].cmp(conflict).is_ge() {
            return Err(invalid(
                "systemd discovery conflicts are not strictly sorted",
            ));
        }
        if !conflict.reported_name.starts_with("aos-sandbox-")
            || SandboxUnitName::from_service_name(&conflict.reported_name).is_some()
            || !names.insert(conflict.reported_name.as_str())
            || !object_paths.insert(conflict.object_path.as_str())
            || !valid_unit_object_path(&conflict.object_path)
            || conflict.job_id != 0
            || !conflict.job_type.is_empty()
            || conflict.job_object_path != "/"
            || conflict.reason.is_empty()
        {
            return Err(invalid("systemd discovery conflict is inconsistent"));
        }
        for (value, allow_empty) in [
            (conflict.reported_name.as_str(), false),
            (conflict.object_path.as_str(), false),
            (conflict.description.as_str(), true),
            (conflict.load_state.as_str(), false),
            (conflict.active_state.as_str(), false),
            (conflict.sub_state.as_str(), false),
            (conflict.followed.as_str(), true),
            (conflict.job_type.as_str(), true),
            (conflict.job_object_path.as_str(), false),
            (conflict.reason.as_str(), false),
        ] {
            charge(value, allow_empty, &mut bytes)?;
        }
    }
    Ok(())
}

fn charge(value: &str, allow_empty: bool, aggregate: &mut usize) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > MAXIMUM_FIELD_BYTES
        || value.contains('\0')
    {
        return Err(invalid("systemd discovery contains an invalid string"));
    }
    charge_fixed(value.len(), aggregate)
}

fn valid_unit_object_path(value: &str) -> bool {
    value
        .strip_prefix("/org/freedesktop/systemd1/unit/")
        .is_some_and(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn charge_fixed(count: usize, aggregate: &mut usize) -> Result<()> {
    *aggregate = aggregate
        .checked_add(count)
        .ok_or_else(|| invalid("systemd discovery byte count overflow"))?;
    if *aggregate > MAXIMUM_DISCOVERY_BYTES {
        return Err(invalid("systemd discovery exceeds its byte ceiling"));
    }
    Ok(())
}

fn reserve<T>(values: &mut Vec<T>, count: usize, label: &str) -> Result<()> {
    values
        .try_reserve_exact(count)
        .map_err(|_| invalid(format!("cannot reserve bounded {label}")))
}

fn invalid(message: impl Into<String>) -> HostError {
    HostError::State(format!(
        "invalid systemd runtime discovery: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::num::NonZeroU32;

    use super::*;

    fn effect(incarnation: u8, request: u8) -> RetainedRuntimeEffect {
        RetainedRuntimeEffect {
            identity: HostRuntimeIdentity::new(
                [incarnation.wrapping_add(40); 16],
                [incarnation; 16],
                1,
                1,
                [incarnation.wrapping_add(80); 32],
            ),
            request_id: [request; 16],
            intent: RetainedRuntimeIntent::Launch,
            durability: RetainedEffectDurability::Complete,
        }
    }

    fn unit(incarnation: u8) -> DiscoveredSandboxUnit {
        let incarnation = [incarnation; 16];
        let unit = SandboxUnitName::from_incarnation(incarnation);
        DiscoveredSandboxUnit {
            unit: unit.clone(),
            incarnation,
            object_path: format!("/org/freedesktop/systemd1/unit/test_{}", incarnation[0]),
            load_state: "loaded".to_owned(),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            freezer_state: FreezerState::Running,
            cgroup: Some(unit.cgroup_path()),
            supervisor_pid: NonZeroU32::new(100),
            invocation_id: Some([9; 16]),
        }
    }

    fn conflict(name: &str) -> SandboxDiscoveryConflict {
        SandboxDiscoveryConflict {
            reported_name: name.to_owned(),
            object_path: format!("/org/freedesktop/systemd1/unit/lookalike_{}", name.len()),
            description: String::new(),
            load_state: "loaded".to_owned(),
            active_state: "inactive".to_owned(),
            sub_state: "dead".to_owned(),
            followed: String::new(),
            job_id: 0,
            job_type: String::new(),
            job_object_path: "/".to_owned(),
            reason: "noncanonical sandbox name".to_owned(),
        }
    }

    #[test]
    fn unknown_units_conflicts_and_unobserved_history_remain_distinct() {
        let mut conflicts = vec![conflict("aos-sandbox-z.service")];
        conflicts.sort();
        let report = reconcile(
            RetainedRuntimeInventory {
                current: vec![effect(1, 1)],
                historical: vec![effect(3, 2)],
            },
            SandboxUnitDiscoverySnapshot {
                units: vec![unit(2)],
                conflicts,
            },
        )
        .unwrap();

        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.unobserved_history.len(), 1);
        assert_eq!(report.quarantine.len(), 1);
        assert_eq!(report.quarantine[0].observed.incarnation, [2; 16]);
        assert_eq!(report.conflicts.len(), 1);
        assert!(report.current.is_empty());
        assert!(report.historical_residuals.is_empty());
    }

    #[test]
    fn malformed_public_snapshots_fail_before_the_join() {
        let mut mismatched = unit(1);
        mismatched.incarnation = [2; 16];
        let mismatch = reconcile(
            RetainedRuntimeInventory {
                current: Vec::new(),
                historical: Vec::new(),
            },
            SandboxUnitDiscoverySnapshot {
                units: vec![mismatched],
                conflicts: Vec::new(),
            },
        );
        assert!(matches!(mismatch, Err(HostError::State(_))));

        let mut zero_invocation = unit(1);
        zero_invocation.invocation_id = Some([0; 16]);
        let inconsistent = reconcile(
            RetainedRuntimeInventory {
                current: Vec::new(),
                historical: Vec::new(),
            },
            SandboxUnitDiscoverySnapshot {
                units: vec![zero_invocation],
                conflicts: Vec::new(),
            },
        );
        assert!(matches!(inconsistent, Err(HostError::State(_))));

        let unicode = reconcile(
            RetainedRuntimeInventory {
                current: Vec::new(),
                historical: Vec::new(),
            },
            SandboxUnitDiscoverySnapshot {
                units: Vec::new(),
                conflicts: vec![conflict("aos-sandbox-éééééééééééééééé.service")],
            },
        );
        assert!(unicode.is_ok());

        let canonical = unit(4);
        let mut first = conflict("aos-sandbox-lookalike.service");
        first.object_path = canonical.object_path.clone();
        let overlap = reconcile(
            RetainedRuntimeInventory {
                current: Vec::new(),
                historical: Vec::new(),
            },
            SandboxUnitDiscoverySnapshot {
                units: vec![canonical],
                conflicts: vec![first],
            },
        );
        assert!(matches!(overlap, Err(HostError::State(_))));

        let first = conflict("aos-sandbox-duplicate.service");
        let mut second = first.clone();
        second.object_path = "/org/freedesktop/systemd1/unit/other".to_owned();
        second.reason = "different row with the same name".to_owned();
        let mut conflicts = vec![first, second];
        conflicts.sort();
        let duplicate = reconcile(
            RetainedRuntimeInventory {
                current: Vec::new(),
                historical: Vec::new(),
            },
            SandboxUnitDiscoverySnapshot {
                units: Vec::new(),
                conflicts,
            },
        );
        assert!(matches!(duplicate, Err(HostError::State(_))));
    }

    #[test]
    fn public_snapshot_object_ceiling_is_enforced_before_entry_validation() {
        let snapshot = SandboxUnitDiscoverySnapshot {
            units: vec![unit(1); MAXIMUM_DISCOVERED_OBJECTS + 1],
            conflicts: Vec::new(),
        };
        let result = reconcile(
            RetainedRuntimeInventory {
                current: Vec::new(),
                historical: Vec::new(),
            },
            snapshot,
        );
        assert!(matches!(result, Err(HostError::State(_))));
    }

    #[test]
    fn public_snapshot_field_and_aggregate_byte_ceilings_are_enforced() {
        let mut oversized = unit(1);
        oversized.sub_state = "x".repeat(MAXIMUM_FIELD_BYTES + 1);
        let field = reconcile(
            RetainedRuntimeInventory {
                current: Vec::new(),
                historical: Vec::new(),
            },
            SandboxUnitDiscoverySnapshot {
                units: vec![oversized],
                conflicts: Vec::new(),
            },
        );
        assert!(matches!(field, Err(HostError::State(_))));

        let mut conflicts = (0..257)
            .map(|index| {
                let mut row = conflict(&format!("aos-sandbox-invalid-{index:04}.service"));
                row.object_path = format!("/org/freedesktop/systemd1/unit/conflict_{index:04}");
                row.description = "x".repeat(MAXIMUM_FIELD_BYTES);
                row
            })
            .collect::<Vec<_>>();
        conflicts.sort();
        let aggregate = reconcile(
            RetainedRuntimeInventory {
                current: Vec::new(),
                historical: Vec::new(),
            },
            SandboxUnitDiscoverySnapshot {
                units: Vec::new(),
                conflicts,
            },
        );
        assert!(matches!(aggregate, Err(HostError::State(_))));
    }
}
