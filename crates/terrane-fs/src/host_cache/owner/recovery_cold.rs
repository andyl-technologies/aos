//! Preserves cold policy candidates until verified native backing reconciles them.
//!
//! This snapshot contains policy data, not adoption or serving authority. Every
//! old pin, lease and hold survives unchanged; old residence rows must agree
//! with independently reconstructed ranges before recovery can complete.

use super::{NativeCacheOwnerConfig, recovery_manifest_state::require_same};
use std::{collections::BTreeSet, io, sync::Arc};
use terrane::host::cache::{CacheState, ReservationRecord, ResidenceRecord};

/// Retains the original bounded policy as comparison data throughout recovery.
#[derive(Clone)]
pub(super) struct ColdPolicy {
    state: Arc<CacheState>,
}

impl ColdPolicy {
    /// Copies validated candidates without interpreting them as native proof.
    ///
    /// # Errors
    /// Refuses invalid state, foreign charge owners and pins without a lease.
    pub(super) fn capture(config: &NativeCacheOwnerConfig, state: &CacheState) -> io::Result<Self> {
        state.encoded_len(config.state).map_err(io::Error::other)?;
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
    /// Metadata hashes must come from actual retained and verified source packs.
    /// A filename, old row or digest alone is insufficient input at the caller.
    /// This comparison issues no native completion or read capability.
    ///
    /// # Errors
    /// Refuses changed or missing residences and pins outside the verified closure.
    pub(super) fn reconcile(
        &self,
        residences: &[ResidenceRecord],
        metadata_hashes: &[String],
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
            .chain(metadata_hashes.iter().map(String::as_str))
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use terrane::host::cache::{LeaseRecord, PinRecord};

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
    }
}
