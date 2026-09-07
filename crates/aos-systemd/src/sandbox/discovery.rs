//! Bounded discovery of transient AOS sandbox units after host restart.
//!
//! Discovery is observation only. A complete snapshot neither authorizes an
//! unknown unit nor permits adopting or killing it. Since systemd does not
//! expose an atomic multi-unit snapshot, two complete passes must agree;
//! disagreement produces an indeterminate result that callers must rescan.
//! Equal passes cannot exclude an ABA transition between reads. Consumers must
//! rescan before making a later lifecycle decision and independently bind any
//! PID, cgroup, and invocation identity used as authority.
//!
//! The current zbus 5 transport rejects messages above 128 MiB after reading
//! the fixed header and before resizing its receive buffer. Typed decoding of
//! any accepted message necessarily allocates before this module sees it. The
//! tighter limits here apply immediately after decoding and before secondary
//! collection or property retention; a zbus upgrade must re-audit that outer
//! transport ceiling.

use std::num::NonZeroU32;

use zbus::proxy::CacheProperties;

use super::{FreezerState, SandboxCgroupPath, SandboxUnitName, parse_cgroup, parse_invocation_id};
use crate::SystemdClient;
use crate::error::Result;
use crate::manager_proxy::{ListUnitsEntry, ServiceProxy, UnitProxy};

const PATTERN: &str = "aos-sandbox-*.service";
const MAX_UNITS: usize = 1024;
const MAX_STRING_BYTES: usize = 4096;
const MAX_DECODED_BYTES: usize = 1024 * 1024;
const REQUIRED_PROPERTIES_PER_UNIT: usize = 8;
const MAX_PROPERTIES: usize = MAX_UNITS * REQUIRED_PROPERTIES_PER_UNIT;

/// One validated point-in-time systemd observation of a canonical sandbox unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredSandboxUnit {
    /// Canonical incarnation-derived unit identity.
    pub unit: SandboxUnitName,
    /// Incarnation encoded by [`Self::unit`].
    pub incarnation: [u8; 16],
    /// Stable D-Bus object path observed in both passes.
    pub object_path: String,
    /// Unit load state.
    pub load_state: String,
    /// Unit active state.
    pub active_state: String,
    /// Unit sub-state.
    pub sub_state: String,
    /// Current freezer state.
    pub freezer_state: FreezerState,
    /// Validated canonical cgroup, if systemd has realized one.
    pub cgroup: Option<SandboxCgroupPath>,
    /// Current systemd service leader, if nonzero.
    pub supervisor_pid: Option<NonZeroU32>,
    /// Current systemd invocation identifier, if nonzero.
    pub invocation_id: Option<[u8; 16]>,
}

/// Evidence that a prefix-matching unit was not a canonical sandbox identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SandboxDiscoveryConflict {
    /// Name returned by systemd.
    pub reported_name: String,
    /// D-Bus object path returned for the row.
    pub object_path: String,
    /// Human-readable description returned for the row.
    pub description: String,
    /// Listed load state.
    pub load_state: String,
    /// Listed active state.
    pub active_state: String,
    /// Listed sub-state.
    pub sub_state: String,
    /// Listed alias target, if any.
    pub followed: String,
    /// Listed job identifier.
    pub job_id: u32,
    /// Listed job type.
    pub job_type: String,
    /// Listed job object path.
    pub job_object_path: String,
    /// Fail-closed validation reason.
    pub reason: String,
}

/// A deterministic complete observation of the systemd sandbox-unit namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxUnitDiscoverySnapshot {
    /// Canonical units, sorted by incarnation-derived name.
    pub units: Vec<DiscoveredSandboxUnit>,
    /// Prefix lookalikes that require operator quarantine, sorted by name.
    pub conflicts: Vec<SandboxDiscoveryConflict>,
}

/// Evidence that a discovered canonical unit is unknown to expected host state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxQuarantineEvidence {
    /// Complete observed unit evidence.
    pub observed: DiscoveredSandboxUnit,
    /// Stable reason for quarantine.
    pub reason: String,
}

/// Observation-only comparison against stable expected unit identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxDiscoveryComparison {
    /// Observed units also present in the expected identity set.
    pub matched: Vec<DiscoveredSandboxUnit>,
    /// Expected identities absent from this observation.
    pub missing: Vec<SandboxUnitName>,
    /// Observed canonical identities absent from expected state.
    pub quarantine: Vec<SandboxQuarantineEvidence>,
    /// Prefix lookalikes carried through from discovery.
    pub conflicts: Vec<SandboxDiscoveryConflict>,
}

/// Reason a coherent two-pass snapshot could not be established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxDiscoveryIndeterminate {
    /// Diagnostic suitable for logs; callers must rescan rather than parse it.
    pub reason: String,
}

/// Result of one bounded discovery attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxDiscoveryOutcome {
    /// Both independently collected passes agreed.
    Complete(SandboxUnitDiscoverySnapshot),
    /// A reload, transport failure, or observation race prevented consistency.
    Indeterminate(SandboxDiscoveryIndeterminate),
}

impl SandboxUnitDiscoverySnapshot {
    /// Compares this observation with stable expected unit identities.
    ///
    /// This method produces evidence only. It does not authorize adoption or
    /// perform lifecycle operations.
    ///
    /// # Errors
    ///
    /// Returns an error if `expected` exceeds the unit ceiling, contains a
    /// zero, noncanonical, or duplicate identity, or bounded comparison
    /// evidence cannot be reserved.
    pub fn compare_expected(
        &self,
        expected: &[SandboxUnitName],
    ) -> Result<SandboxDiscoveryComparison> {
        if expected.len() > MAX_UNITS {
            return Err(super::invalid(
                "expected sandbox identities exceed unit ceiling",
            ));
        }
        for (index, unit) in expected.iter().enumerate() {
            if parse_name(unit.as_str()).is_none() {
                return Err(super::invalid(format!(
                    "expected sandbox unit {unit} is zero or noncanonical"
                )));
            }
            if expected[..index].contains(unit) {
                return Err(super::invalid(format!(
                    "duplicate expected sandbox unit {unit}"
                )));
            }
        }

        let mut matched = Vec::new();
        let mut quarantine = Vec::new();
        matched
            .try_reserve_exact(self.units.len())
            .map_err(|_| super::invalid("cannot reserve bounded matched-unit evidence"))?;
        quarantine
            .try_reserve_exact(self.units.len())
            .map_err(|_| super::invalid("cannot reserve bounded quarantine evidence"))?;
        for unit in &self.units {
            if expected.contains(&unit.unit) {
                matched.push(unit.clone());
            } else {
                quarantine.push(SandboxQuarantineEvidence {
                    observed: unit.clone(),
                    reason: "canonical systemd unit is unknown to expected host state".to_owned(),
                });
            }
        }
        let mut missing = Vec::new();
        missing
            .try_reserve_exact(expected.len())
            .map_err(|_| super::invalid("cannot reserve bounded missing-unit evidence"))?;
        missing.extend(
            expected
                .iter()
                .filter(|expected_unit| {
                    !self
                        .units
                        .iter()
                        .any(|observed| &observed.unit == *expected_unit)
                })
                .cloned(),
        );
        missing.sort();
        Ok(SandboxDiscoveryComparison {
            matched,
            missing,
            quarantine,
            conflicts: self.conflicts.clone(),
        })
    }
}

impl SystemdClient {
    /// Discovers a deterministic, bounded snapshot of canonical sandbox units.
    ///
    /// The operation performs two uncached passes. systemd offers no atomic
    /// multi-unit transaction, so any disagreement or reload produces
    /// [`SandboxDiscoveryOutcome::Indeterminate`] and requires a later rescan.
    /// Equal passes cannot detect an ABA transition; a complete result remains
    /// observation, never authority, and must be rescanned before a later
    /// lifecycle decision.
    ///
    /// # Errors
    ///
    /// This version represents transport and consistency failures as a typed
    /// indeterminate outcome. The `Result` leaves room for future caller-input
    /// validation without conflating it with a rescan requirement.
    pub async fn discover_sandbox_units(&self) -> Result<SandboxDiscoveryOutcome> {
        if self.is_reloading() {
            return Ok(indeterminate("systemd reload was active before discovery"));
        }
        let first = match self.collect_sandbox_discovery_pass().await {
            Ok(pass) => pass,
            Err(_error) => {
                return Ok(indeterminate(
                    "first discovery pass failed validation or transport; rescan required",
                ));
            }
        };
        if self.is_reloading() {
            return Ok(indeterminate("systemd reload began during discovery"));
        }
        let second = match self.collect_sandbox_discovery_pass().await {
            Ok(pass) => pass,
            Err(_error) => {
                return Ok(indeterminate(
                    "second discovery pass failed validation or transport; rescan required",
                ));
            }
        };
        if self.is_reloading() || first != second {
            return Ok(indeterminate(
                "systemd unit membership or required properties changed between passes",
            ));
        }
        Ok(SandboxDiscoveryOutcome::Complete(first))
    }

    async fn collect_sandbox_discovery_pass(&self) -> Result<SandboxUnitDiscoverySnapshot> {
        let listed = self.manager.list_units_by_patterns(&[], &[PATTERN]).await?;
        let mut retained_bytes = validate_listing_admission(&listed)?;
        let mut units = Vec::new();
        let mut conflicts = Vec::new();
        units
            .try_reserve_exact(listed.len())
            .map_err(|_| super::invalid("cannot reserve bounded sandbox discovery result"))?;
        conflicts
            .try_reserve_exact(listed.len())
            .map_err(|_| super::invalid("cannot reserve bounded sandbox conflict evidence"))?;

        for entry in listed {
            let object_path = entry.object_path.to_string();
            if !entry.name.starts_with(super::UNIT_PREFIX) {
                return Err(super::invalid(format!(
                    "server filter returned unrelated unit {:?}",
                    entry.name
                )));
            }
            let Some((unit_name, incarnation)) = parse_name(&entry.name) else {
                conflicts.push(SandboxDiscoveryConflict {
                    reported_name: entry.name,
                    object_path,
                    description: entry.description,
                    load_state: entry.load_state,
                    active_state: entry.active_state,
                    sub_state: entry.sub_state,
                    followed: entry.followed,
                    job_id: entry.job_id,
                    job_type: entry.job_type,
                    job_object_path: entry.job_object_path.to_string(),
                    reason: "prefix-matching name is not canonical lowercase incarnation syntax"
                        .to_owned(),
                });
                continue;
            };
            if !entry.followed.is_empty() {
                return Err(super::invalid(format!(
                    "canonical unit {} followed alias {:?}",
                    unit_name, entry.followed
                )));
            }
            let resolved = self.manager.get_unit(unit_name.as_str()).await?;
            if resolved != entry.object_path {
                return Err(super::invalid(format!(
                    "GetUnit path substituted for {unit_name}"
                )));
            }
            let unit = UnitProxy::builder(&self.conn)
                .path(resolved.clone())?
                .cache_properties(CacheProperties::No)
                .build()
                .await?;
            let service = ServiceProxy::builder(&self.conn)
                .path(resolved)?
                .cache_properties(CacheProperties::No)
                .build()
                .await?;
            let id = unit.id().await?;
            charge_string(&id, &mut retained_bytes)?;
            let load_state = unit.load_state().await?;
            charge_string(&load_state, &mut retained_bytes)?;
            let active_state = unit.active_state().await?;
            charge_string(&active_state, &mut retained_bytes)?;
            let sub_state = unit.sub_state().await?;
            charge_string(&sub_state, &mut retained_bytes)?;
            let freezer = unit.freezer_state().await?;
            charge_string(&freezer, &mut retained_bytes)?;
            let invocation = unit.invocation_id().await?;
            if invocation.len() != 16 {
                return Err(super::invalid(format!(
                    "unit {unit_name} returned malformed invocation length"
                )));
            }
            retained_bytes = retained_bytes
                .checked_add(invocation.len())
                .ok_or_else(|| super::invalid("sandbox discovery byte count overflow"))?;
            if retained_bytes > MAX_DECODED_BYTES {
                return Err(super::invalid(
                    "sandbox discovery response exceeds decoded-byte ceiling",
                ));
            }
            let cgroup_value = service.control_group().await?;
            charge_string(&cgroup_value, &mut retained_bytes)?;
            if id != entry.name
                || load_state != entry.load_state
                || active_state != entry.active_state
                || sub_state != entry.sub_state
            {
                return Err(super::invalid(format!(
                    "listed properties changed for {unit_name}"
                )));
            }
            units.push(DiscoveredSandboxUnit {
                unit: unit_name.clone(),
                incarnation,
                object_path,
                load_state,
                active_state,
                sub_state,
                freezer_state: FreezerState::from_systemd(freezer),
                cgroup: parse_cgroup(&unit_name, cgroup_value)?,
                supervisor_pid: NonZeroU32::new(service.main_pid().await?),
                invocation_id: parse_invocation_id(invocation)?,
            });
        }
        units.sort_by(|left, right| left.unit.cmp(&right.unit));
        conflicts.sort();
        Ok(SandboxUnitDiscoverySnapshot { units, conflicts })
    }
}

fn indeterminate(reason: impl Into<String>) -> SandboxDiscoveryOutcome {
    SandboxDiscoveryOutcome::Indeterminate(SandboxDiscoveryIndeterminate {
        reason: reason.into(),
    })
}

fn validate_listing_admission(entries: &[ListUnitsEntry]) -> Result<usize> {
    if entries.len() > MAX_UNITS
        || entries.len().saturating_mul(REQUIRED_PROPERTIES_PER_UNIT) > MAX_PROPERTIES
    {
        return Err(super::invalid(
            "sandbox discovery response exceeds unit/property ceiling",
        ));
    }
    let mut aggregate = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        charge_entry(entry, &mut aggregate)?;
        if entries[..index]
            .iter()
            .any(|prior| prior.name == entry.name)
        {
            return Err(super::invalid(format!(
                "duplicate listed unit name {:?}",
                entry.name
            )));
        }
        if entries[..index]
            .iter()
            .any(|prior| prior.object_path == entry.object_path)
        {
            return Err(super::invalid(format!(
                "duplicate listed object path {:?}",
                entry.object_path
            )));
        }
        if entry.job_id != 0 || !entry.job_type.is_empty() || entry.job_object_path.as_str() != "/"
        {
            return Err(super::invalid(format!(
                "unit {:?} has an in-flight systemd job",
                entry.name
            )));
        }
    }
    Ok(aggregate)
}

fn charge_entry(entry: &ListUnitsEntry, aggregate: &mut usize) -> Result<()> {
    for value in [
        entry.name.as_str(),
        entry.description.as_str(),
        entry.load_state.as_str(),
        entry.active_state.as_str(),
        entry.sub_state.as_str(),
        entry.followed.as_str(),
        entry.object_path.as_str(),
        entry.job_type.as_str(),
        entry.job_object_path.as_str(),
    ] {
        charge_string(value, aggregate)?;
    }
    Ok(())
}

fn charge_string(value: &str, aggregate: &mut usize) -> Result<()> {
    if value.len() > MAX_STRING_BYTES {
        return Err(super::invalid(
            "sandbox discovery string exceeds per-field ceiling",
        ));
    }
    *aggregate = aggregate
        .checked_add(value.len())
        .ok_or_else(|| super::invalid("sandbox discovery byte count overflow"))?;
    if *aggregate > MAX_DECODED_BYTES {
        return Err(super::invalid(
            "sandbox discovery response exceeds decoded-byte ceiling",
        ));
    }
    Ok(())
}

fn parse_name(value: &str) -> Option<(SandboxUnitName, [u8; 16])> {
    SandboxUnitName::from_service_name(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_names_round_trip_and_lookalikes_fail_closed() {
        let name = SandboxUnitName::from_incarnation([0xab; 16]);
        assert_eq!(parse_name(name.as_str()).unwrap().1, [0xab; 16]);
        for hostile in [
            "aos-sandbox-.service",
            "aos-sandbox-ABABABABABABABABABABABABABABABAB.service",
            "aos-sandbox-abababababababababababababababab.service.evil",
            "aos-sandbox-abababababababababababababababa.service",
            "aos-sandbox-abababababababababababababababag.service",
            "aos-sandbox-00000000000000000000000000000000.service",
        ] {
            assert!(parse_name(hostile).is_none(), "accepted {hostile}");
        }
    }

    #[test]
    fn comparison_never_silently_ignores_unknown_units() {
        let unknown = SandboxUnitName::from_incarnation([2; 16]);
        let snapshot = SandboxUnitDiscoverySnapshot {
            units: vec![DiscoveredSandboxUnit {
                unit: unknown.clone(),
                incarnation: [2; 16],
                object_path: "/unit".to_owned(),
                load_state: "loaded".to_owned(),
                active_state: "active".to_owned(),
                sub_state: "running".to_owned(),
                freezer_state: FreezerState::Running,
                cgroup: Some(unknown.cgroup_path()),
                supervisor_pid: NonZeroU32::new(7),
                invocation_id: Some([3; 16]),
            }],
            conflicts: Vec::new(),
        };
        let comparison = snapshot.compare_expected(&[]).unwrap();
        assert!(comparison.matched.is_empty());
        assert_eq!(comparison.quarantine.len(), 1);
        assert_eq!(comparison.quarantine[0].observed.unit, unknown);
    }

    #[test]
    fn duplicate_expected_identity_is_rejected() {
        let unit = SandboxUnitName::from_incarnation([4; 16]);
        let snapshot = SandboxUnitDiscoverySnapshot {
            units: Vec::new(),
            conflicts: Vec::new(),
        };
        assert!(snapshot.compare_expected(&[unit.clone(), unit]).is_err());
    }

    #[test]
    fn expected_identities_reject_zero_and_missing_is_sorted() {
        let lower = SandboxUnitName::from_incarnation([1; 16]);
        let higher = SandboxUnitName::from_incarnation([3; 16]);
        let zero = SandboxUnitName::from_incarnation([0; 16]);
        let snapshot = SandboxUnitDiscoverySnapshot {
            units: Vec::new(),
            conflicts: Vec::new(),
        };

        assert!(snapshot.compare_expected(&[zero]).is_err());
        let comparison = snapshot
            .compare_expected(&[higher.clone(), lower.clone()])
            .unwrap();
        assert_eq!(comparison.missing, vec![lower, higher]);
    }
}
