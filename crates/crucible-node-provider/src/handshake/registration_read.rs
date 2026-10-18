//! Reads the original registrar gate without exposing registration or wire data.

use super::ConnectionAuthority;
use crate::ProviderError;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

pub(crate) struct RegistrationRead {
    gate: Arc<Mutex<()>>,
    current: Arc<AtomicU64>,
    original: u64,
}

/// Borrows historical registrar facts without carrying a live registration grant.
///
/// The retained owner ties this projection to the actual alias walk. Epoch values
/// describe the sampled owner, including a revoked read; no lock is acquired.
#[derive(serde::Serialize)]
struct RegistrationReadHistoricalData<'a> {
    #[serde(skip)]
    _owner: &'a RegistrationRead,
    schema: &'static str,
    saved_epoch: u64,
    observed_epoch: u64,
    gate_role: &'static str,
    epoch_role: &'static str,
}

impl RegistrationRead {
    pub(crate) fn borrowed_settled_history_data(&self) -> impl serde::Serialize + '_ {
        let Self {
            gate: _,
            current,
            original,
        } = self;
        RegistrationReadHistoricalData {
            _owner: self,
            schema: "source-private.registrar-read-history/17",
            saved_epoch: *original,
            observed_epoch: current.load(Ordering::Acquire),
            gate_role: "registrar-gate",
            epoch_role: "registrar-epoch",
        }
    }

    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        use std::mem::{size_of, size_of_val};

        let terms = [
            size_of::<RegistrationRead>(),
            size_of::<&RegistrationRead>(),
            size_of::<&ConnectionAuthority>(),
            size_of::<bool>(),
            size_of::<RegistrationReadHistoricalData<'_>>(),
            size_of::<&RegistrationReadHistoricalData<'_>>(),
            size_of::<(&Arc<Mutex<()>>, &Arc<AtomicU64>, &u64)>(),
            size_of::<(&Arc<AtomicU64>, &u64)>(),
            size_of::<u64>(),
            size_of::<crate::retained_metadata::MetadataObserver<'_>>(),
            size_of::<Result<(), ProviderError>>(),
        ];
        size_of_val(&terms)
            + size_of::<std::array::IntoIter<usize, 11>>()
            + terms.into_iter().sum::<usize>()
    }

    pub(crate) fn observe_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.ensure_current()?;
        self.observe_retained_metadata_data(observer)
    }

    pub(crate) fn observe_retained_metadata_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            gate,
            current,
            original,
        } = self;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::RegistrarGate,
            gate.as_ref(),
        )?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::RegistrarEpoch,
            current.as_ref(),
        )?;
        observer.observe(original)
    }

    pub(crate) fn ensure_current(&self) -> Result<(), ProviderError> {
        // A contended gate is uncertainty, rather than permission to wait past
        // the caller's final native-dispatch boundary.
        let _gate = self
            .gate
            .try_lock()
            .map_err(|_| ProviderError::Correlation("original registrar read gate unavailable"))?;
        if self.current.load(Ordering::Acquire) != self.original {
            return Err(ProviderError::Correlation(
                "original registrar read revoked",
            ));
        }
        Ok(())
    }

    /// Compares real retained parent registration edges without locking or renewal.
    pub(crate) fn same_authority_data(&self, authority: &ConnectionAuthority) -> bool {
        Arc::ptr_eq(&self.gate, &authority.registration_gate)
            && Arc::ptr_eq(&self.current, &authority.shared_epoch)
            && self.original == authority.epoch
    }

    pub(crate) fn same_original(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.gate, &other.gate)
            && Arc::ptr_eq(&self.current, &other.current)
            && self.original == other.original
    }
}

impl ConnectionAuthority {
    pub(crate) fn original_registration_read(&self) -> Result<RegistrationRead, ProviderError> {
        self.ensure_live()?;
        Ok(RegistrationRead {
            gate: Arc::clone(&self.registration_gate),
            current: Arc::clone(&self.shared_epoch),
            original: self.epoch,
        })
    }
}

#[cfg(test)]
#[path = "registration_read_tests.rs"]
mod tests;

#[cfg(test)]
mod settled_history_tests {
    use super::*;

    #[test]
    fn revoked_and_locked_registrar_remains_inert_history() -> Result<(), ProviderError> {
        let gate = Arc::new(Mutex::new(()));
        let current = Arc::new(AtomicU64::new(8));
        let owner = RegistrationRead {
            gate: Arc::clone(&gate),
            current,
            original: 7,
        };
        let held = gate.try_lock().map_err(|_| {
            ProviderError::Correlation("registrar history fixture gate unavailable")
        })?;

        let value = serde_json::to_value(owner.borrowed_settled_history_data()).map_err(|_| {
            ProviderError::Correlation("registrar history fixture serialization failed")
        })?;
        assert_eq!(value["schema"], "source-private.registrar-read-history/17");
        assert_eq!(value["saved_epoch"], 7);
        assert_eq!(value["observed_epoch"], 8);
        assert_eq!(value["gate_role"], "registrar-gate");
        assert_eq!(value["epoch_role"], "registrar-epoch");
        assert_eq!(value.as_object().map(|fields| fields.len()), Some(5));
        assert!(owner.ensure_current().is_err());

        drop(held);
        assert!(owner.ensure_current().is_err());
        Ok(())
    }

    #[test]
    fn actual_aliases_use_precharged_partial_banks() -> Result<(), ProviderError> {
        use crate::retained_metadata::{
            MetadataObserver, aliases::MetadataAliasBank, records::MetadataRecordBank,
        };

        let owner = RegistrationRead {
            gate: Arc::new(Mutex::new(())),
            current: Arc::new(AtomicU64::new(7)),
            original: 7,
        };
        let mut records = MetadataRecordBank::reserve(2)?;
        let mut aliases = MetadataAliasBank::reserve(2)?;
        let record_capacity = records.capacity_rows();
        let mut observer = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
        owner.observe_retained_metadata_data(&mut observer)?;
        let facts = observer.finish();
        assert_eq!(facts.shared_backing_views, 2);
        assert_eq!(records.capacity_rows(), record_capacity);
        assert_eq!(
            serde_json::to_value(&aliases).map_err(|_| {
                ProviderError::Correlation("registrar history alias serialization failed")
            })?,
            serde_json::json!([["registrar-gate", 0], ["registrar-epoch", 1]])
        );

        let mut short = MetadataRecordBank::reserve(1)?;
        let capacity = short.capacity_rows();
        let mut observer = MetadataObserver::recording_with_aliases(&mut short, &mut aliases);
        assert!(owner.observe_retained_metadata_data(&mut observer).is_err());
        assert_eq!(short.capacity_rows(), capacity);
        assert_eq!(short.rows().len(), 1);
        Ok(())
    }
}

#[cfg(test)]
mod historical_parent_tests {
    use super::*;

    #[test]
    fn negotiated_parent_identity_survives_revocation_without_renewal() -> Result<(), ProviderError>
    {
        // Dropping the real registrar revokes its epoch before the explicit change.
        let (_registrar, authority) = crate::handshake::tests::authority();
        let (_foreign_registrar, foreign) = crate::handshake::tests::authority();
        authority.ensure_live()?;
        foreign.ensure_live()?;
        let read = authority.original_registration_read()?;
        assert!(read.same_authority_data(&authority));
        assert!(!read.same_authority_data(&foreign));

        authority.shared_epoch.fetch_add(1, Ordering::AcqRel);
        assert!(read.ensure_current().is_err());
        assert!(authority.ensure_live().is_err());
        assert!(read.same_authority_data(&authority));
        assert!(!read.same_authority_data(&foreign));
        Ok(())
    }
}
