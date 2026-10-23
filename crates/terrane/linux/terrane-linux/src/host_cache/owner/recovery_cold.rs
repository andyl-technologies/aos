//! Preserves cold policy candidates until verified native backing reconciles them.
//!
//! This snapshot contains policy data, not adoption or serving authority. Every
//! unresolved pin and lease survives unchanged; old residence rows must agree with
//! independently reconstructed ranges before recovery can complete. Only actual
//! native retirement can release disposable derived-index copy allowances.

use super::{NativeCacheOwnerConfig, recovery_manifest_state::require_same};
use std::{collections::BTreeSet, io, sync::Arc};
use terrane_sdk::host::cache::{CacheState, ReservationRecord, ResidenceRecord};

/// Retains the original bounded policy as comparison data throughout recovery.
#[derive(Clone)]
pub(super) struct ColdPolicy {
    state: Arc<CacheState>,
}

impl ColdPolicy {
    /// Reports remaining promises needing independent native backing recovery.
    pub(super) fn requires_backing(&self) -> bool {
        !self.state.pins.is_empty() || !self.state.residences.is_empty()
    }

    /// Removes only disposable surface-copy holds after native namespace retirement.
    ///
    /// The caller must first retire every recognized derived index and inspect a
    /// fresh exhaustive namespace under its actual funded Drain turn. Physical
    /// kernel references remain charged by fresh project quota observations.
    ///
    /// # Errors
    /// Refuses malformed reserved tokens or holds with dependent pins or leases.
    /// The original cold policy remains unchanged on success and failure.
    #[cfg(feature = "surface-fuse")]
    pub(super) fn without_surface_reservations(&self) -> io::Result<Option<Self>> {
        let mut next = self.state.as_ref().clone();
        let mut remove = BTreeSet::new();
        for hold in &self.state.reservations {
            let Some(token) = hold.id.strip_prefix("surface-index:") else {
                continue;
            };
            if token.len() != 32
                || !token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || self.state.leases.iter().any(|lease| lease.owner == hold.id)
                || self.state.pins.iter().any(|pin| pin.owner == hold.id)
            {
                return Err(invalid(
                    "cold surface hold has unrecognized or dependent policy",
                ));
            }
            remove.insert(hold.id.as_str());
        }
        if remove.is_empty() {
            return Ok(None);
        }
        next.reservations
            .retain(|hold| !remove.contains(hold.id.as_str()));
        Ok(Some(Self {
            state: Arc::new(next),
        }))
    }

    /// Copies validated candidates without interpreting them as native proof.
    ///
    /// # Errors
    /// Refuses invalid state, foreign charge owners and pins without a lease.
    pub(super) fn capture(config: &NativeCacheOwnerConfig, state: &CacheState) -> io::Result<Self> {
        Self::capture_checked(config, state, false)
    }

    /// Copies draining policy without treating any backing row as native proof.
    ///
    /// # Errors
    /// Refuses non-draining or unbound exposures, invalid policy, foreign charge
    /// owners and pins without a lease. Native recovery still verifies all pins.
    #[cfg(feature = "surface-fuse")]
    pub(super) fn capture_draining(
        config: &NativeCacheOwnerConfig,
        state: &CacheState,
    ) -> io::Result<Self> {
        Self::capture_checked(config, state, true)
    }

    fn capture_checked(
        config: &NativeCacheOwnerConfig,
        state: &CacheState,
        draining: bool,
    ) -> io::Result<Self> {
        state.encoded_len(config.state).map_err(io::Error::other)?;
        if state.exposures.iter().any(|row| {
            !draining
                || row.phase != terrane_sdk::host::cache::ExposurePhase::Draining
                || row.backings.is_empty()
        }) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "cold exposure requires retained-kernel-reference reconciliation",
            ));
        }
        if state
            .reservations
            .iter()
            .any(|hold| hold.owner != config.quota_owner)
            || state
                .pins
                .iter()
                .any(|pin| !state.leases.iter().any(|lease| lease.owner == pin.owner))
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "cold policy has unresolved lease or charge ownership",
            ));
        }
        Ok(Self {
            state: Arc::new(state.clone()),
        })
    }

    /// Borrows original residence candidates without treating them as verified.
    ///
    /// Selection can prefer one only after receiving that exact range from
    /// independently verified recovery output. Missing candidates stay unresolved.
    pub(super) fn residences(&self) -> &[ResidenceRecord] {
        &self.state.residences
    }

    /// Recognizes the original ledger's metadata allowance for a consumer lease.
    ///
    /// This compares policy data only. Cleanup additionally requires the actual
    /// completed recovery and acknowledged Running owner; this issues no read
    /// handle and cannot establish native backing from a token.
    pub(super) fn retained_consumer_hold(&self, token: &str, owner: &str) -> Option<u64> {
        if !self.state.leases.iter().any(|lease| {
            lease.owner == format!("consumer:{token}")
                || lease.owner == format!("consumer-grace:{token}")
        }) {
            return None;
        }
        self.state
            .reservations
            .iter()
            .find(|hold| hold.id == token && hold.owner == owner)
            .map(|hold| hold.bytes)
    }

    /// Compares original metadata promises with a separately verified body/pack pair.
    ///
    /// These tokens are policy data only. They authorize no native operation;
    /// cleanup additionally requires original registered backing, acknowledged
    /// Resume and the actual body's typed final-removal completion. Unrecognized
    /// or changed groups remain protected, including extra dependent pins.
    pub(super) fn retained_metadata_holds(
        &self,
        current: &CacheState,
        charge_owner: &str,
        bytes: u64,
        object: &str,
        pack: &str,
    ) -> BTreeSet<String> {
        let mut matched = BTreeSet::new();
        let expected = BTreeSet::from([object, pack]);
        let deadline = super::RETAINED_LEASE_DEADLINE;
        for hold in &self.state.reservations {
            if hold.owner != charge_owner
                || hold.bytes != bytes
                || hold.id.len() != 32
                || !hold
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                continue;
            }
            let purpose = format!("metadata:{}", hold.id);
            let unchanged_hold = current
                .reservations
                .iter()
                .filter(|row| row.id == hold.id)
                .count()
                == 1
                && current.reservations.iter().any(|row| {
                    row.id == hold.id && row.owner == hold.owner && row.bytes == hold.bytes
                });
            if !unchanged_hold
                || !metadata_group_matches(&self.state, &purpose, &expected, deadline)
                || !metadata_group_matches(current, &purpose, &expected, deadline)
            {
                continue;
            }
            matched.insert(hold.id.clone());
        }
        matched
    }

    /// Adds the genuine new bootstrap hold while preserving every cold record.
    ///
    /// # Errors
    /// Refuses a reservation collision or a snapshot exceeding configured bounds.
    pub(super) fn bootstrap(
        &self,
        config: &NativeCacheOwnerConfig,
        id: &[u8; 16],
    ) -> io::Result<CacheState> {
        let id = hex(id);
        if self.state.reservations.iter().any(|hold| hold.id == id) {
            return Err(invalid("cold policy collides with recovery bootstrap"));
        }
        let mut state = self.state.as_ref().clone();
        state.reservations.push(ReservationRecord {
            id,
            owner: config.quota_owner.clone(),
            bytes: config.metadata_sync_hold_bytes,
        });
        state.encoded_len(config.state).map_err(io::Error::other)?;
        Ok(state)
    }

    /// Checks every original residence and pin against verified recovery outputs.
    ///
    /// Additional hashes must come from actual retained verified packs or chunks.
    /// A filename, old row or digest alone is insufficient input at the caller.
    /// This comparison issues no native completion or read capability.
    ///
    /// # Errors
    /// Refuses changed or missing residences and pins outside the verified closure.
    pub(super) fn reconcile(
        &self,
        residences: &[ResidenceRecord],
        verified_hashes: &[String],
    ) -> io::Result<()> {
        if self.state.residences.iter().any(|old| {
            !residences.iter().any(|new| {
                old.chunk == new.chunk
                    && old.object == new.object
                    && old.offset == new.offset
                    && old.length == new.length
            })
        }) {
            return Err(invalid(
                "cold residence differs from verified native backing",
            ));
        }
        let hashes: BTreeSet<&str> = residences
            .iter()
            .flat_map(|row| [row.chunk.as_str(), row.object.as_str()])
            .chain(verified_hashes.iter().map(String::as_str))
            .collect();
        if self
            .state
            .pins
            .iter()
            .any(|pin| !hashes.contains(pin.hash.as_str()))
        {
            return Err(invalid("cold pin lacks verified native backing"));
        }
        Ok(())
    }

    /// Compares a current snapshot with the exact original records and bootstrap.
    ///
    /// # Errors
    /// Refuses any changed, removed or unexpected policy record.
    pub(super) fn check_bootstrap(
        &self,
        config: &NativeCacheOwnerConfig,
        state: &CacheState,
        id: &[u8; 16],
    ) -> io::Result<()> {
        require_same(state, &self.bootstrap(config, id)?)
    }
}

/// Recognizes only the complete two-pin metadata promise, with no extra dependents.
fn metadata_group_matches(
    state: &CacheState,
    purpose: &str,
    expected: &BTreeSet<&str>,
    deadline: u64,
) -> bool {
    let leases = state
        .leases
        .iter()
        .filter(|row| row.owner == purpose)
        .collect::<Vec<_>>();
    let pins = state
        .pins
        .iter()
        .filter(|row| row.owner == purpose)
        .collect::<Vec<_>>();
    leases.len() == 1
        && leases[0].expires == deadline
        && pins.len() == 2
        && pins.iter().all(|pin| pin.expires == deadline)
        && pins
            .iter()
            .map(|pin| pin.hash.as_str())
            .collect::<BTreeSet<_>>()
            == *expected
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use terrane_sdk::host::cache::{LeaseRecord, PinRecord};

    fn candidates() -> ColdPolicy {
        let mut state = CacheState::default();
        state.leases.push(LeaseRecord {
            owner: "consumer".into(),
            expires: 100,
        });
        state.pins.push(PinRecord {
            owner: "consumer".into(),
            hash: "11".repeat(32),
            expires: 100,
        });
        state.reservations.push(ReservationRecord {
            id: "original-hold".into(),
            owner: "original-owner".into(),
            bytes: 4096,
        });
        state.residences.push(ResidenceRecord {
            chunk: "11".repeat(32),
            object: "22".repeat(32),
            offset: 7,
            length: 3,
        });
        ColdPolicy {
            state: Arc::new(state),
        }
    }

    #[cfg(feature = "surface-fuse")]
    mod surface_tests;

    #[test]
    fn cold_pins_require_complete_verified_backing_without_erasing_candidates() {
        // Pure policy comparison only: these rows create no native authority.
        let cold = candidates();
        assert!(cold.reconcile(&[], &[]).is_err());
        let mut wrong = cold.state.residences.clone();
        wrong[0].offset += 1;
        assert!(cold.reconcile(&wrong, &[]).is_err());
        assert!(cold.reconcile(&cold.state.residences, &[]).is_ok());
        assert_eq!(cold.state.pins.len(), 1);
        assert_eq!(cold.state.leases[0].expires, 100);
        assert_eq!(cold.state.residences[0].offset, 7);
        assert_eq!(cold.state.reservations[0].id, "original-hold");
        assert_eq!(cold.state.reservations[0].bytes, 4096);
    }

    #[test]
    fn cold_metadata_pins_require_the_separate_verified_source_closure() {
        let mut state = CacheState::default();
        state.pins.push(PinRecord {
            owner: "metadata".into(),
            hash: "33".repeat(32),
            expires: 100,
        });
        let cold = ColdPolicy {
            state: Arc::new(state),
        };

        assert!(cold.reconcile(&[], &[]).is_err());
        assert!(cold.reconcile(&[], &["44".repeat(32)]).is_err());
        assert!(cold.reconcile(&[], &["33".repeat(32)]).is_ok());
        assert_eq!(cold.state.pins[0].hash, "33".repeat(32));

        // Exact cold groups can be compared only as data. A separately verified
        // native body/pack and final removal still supply all cleanup authority.
        let token = "ab".repeat(16);
        let purpose = format!("metadata:{token}");
        let object = "11".repeat(32);
        let pack = "22".repeat(32);
        let mut original = CacheState::default();
        original.reservations.push(ReservationRecord {
            id: token.clone(),
            owner: "fixture".into(),
            bytes: 4096,
        });
        original.leases.push(LeaseRecord {
            owner: purpose.clone(),
            expires: super::super::RETAINED_LEASE_DEADLINE,
        });
        for hash in [&object, &pack] {
            original.pins.push(PinRecord {
                owner: purpose.clone(),
                hash: hash.clone(),
                expires: super::super::RETAINED_LEASE_DEADLINE,
            });
        }
        let cold = ColdPolicy {
            state: Arc::new(original.clone()),
        };
        assert_eq!(
            cold.retained_metadata_holds(&original, "fixture", 4096, &object, &pack),
            BTreeSet::from([token])
        );
        assert!(
            cold.retained_metadata_holds(&original, "foreign", 4096, &object, &pack)
                .is_empty()
        );
        assert!(
            cold.retained_metadata_holds(&original, "fixture", 8192, &object, &pack)
                .is_empty()
        );
        assert!(
            cold.retained_metadata_holds(&original, "fixture", 4096, &pack, &pack)
                .is_empty()
        );
        let mut changed = original.clone();
        changed.pins.push(PinRecord {
            owner: purpose,
            hash: "33".repeat(32),
            expires: super::super::RETAINED_LEASE_DEADLINE,
        });
        assert!(
            cold.retained_metadata_holds(&changed, "fixture", 4096, &object, &pack)
                .is_empty()
        );
        let mut changed = original.clone();
        changed.leases[0].expires -= 1;
        assert!(
            cold.retained_metadata_holds(&changed, "fixture", 4096, &object, &pack)
                .is_empty()
        );
        assert_eq!(cold.state.pins.len(), 2);
        assert_eq!(
            cold.state.leases[0].expires,
            super::super::RETAINED_LEASE_DEADLINE
        );
        assert_eq!(cold.state.reservations[0].bytes, 4096);
    }

    #[test]
    fn standalone_replacement_cannot_erase_an_original_cold_range() {
        let cold = candidates();
        let hashes = vec!["11".repeat(32), "22".repeat(32)];

        // Both identities can be backed while the original range assertion is
        // still unresolved. Recovery cannot treat content closure as a durable
        // acknowledgement of the missing residence transition.
        assert!(cold.reconcile(&[], &hashes).is_err());
        assert!(cold.reconcile(&cold.state.residences, &hashes).is_ok());
        assert_eq!(cold.state.residences.len(), 1);
        assert_eq!(cold.state.residences[0].offset, 7);
        assert_eq!(cold.state.reservations[0].bytes, 4096);
    }
}
