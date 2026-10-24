//! Observes actual inert historical graph owners, including partial decodes.
//!
//! The closed visitor follows only reconstructed typed data. It creates no
//! registrar, stream, native lease, callback or currentness proof. Rc/Arc edges
//! preserve their actual backing and are conservatively counted per view; no
//! alias refund, old encoded layout, demand scalar or historical group label
//! substitutes for current capacities and concrete reconstructed payload sizes.

use crate::{
    ProviderError,
    retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    sync::Arc,
};

pub(super) trait HistoricalStorage {
    const NESTED_OWNERS: bool = true;
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError>;
}

// This trait is private to the closed historical graph. It adds no blanket
// ObserveMetadata implementation or support for erased live SDK owners.
macro_rules! fields {
    ($ty:ty, $($field:ident),+ $(,)?) => {
        impl $crate::protocol_snapshot::owned11::retained_storage::HistoricalStorage for $ty {
            fn observe_historical(&self, observer: &mut $crate::retained_metadata::MetadataObserver)
                -> Result<(), $crate::ProviderError> {
                let Self { $($field),+ } = self;
                $($crate::protocol_snapshot::owned11::retained_storage::HistoricalStorage::observe_historical($field, observer)?;)+
                Ok(())
            }
        }
    };
}
pub(super) use fields;

macro_rules! observed {
    ($($ty:ty),+ $(,)?) => {$(impl HistoricalStorage for $ty {
        fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
            observer.observe(self)
        }
    })+};
}

macro_rules! numeric_copy {
    ($($ty:ty),+ $(,)?) => {$(impl HistoricalStorage for $ty {
        const NESTED_OWNERS: bool = false;
        fn observe_historical(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
            fn require_copy<T: Copy>(_: &T) {}
            require_copy(self);
            Ok(())
        }
    })+};
}

observed!(
    String,
    crucible_node_format::Id,
    crucible_node_format::Bytes,
    crucible_node_format::ContentRef,
    crucible_node_format::HashRef,
    crucible_node_format::SchemaRef,
    crucible_node_format::ImplementationIdentity,
    crucible_node_format::ExtensionSelection,
    crucible_node_format::Position,
    crate::envelope::Envelope,
    crate::client::ClientOriginal,
    crate::handshake::Limits,
    crate::reference_packet::control::PacketControlSelection,
    crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation,
    crate::reference_packet::service::PacketNative5CaptureProfile,
    crate::reference_packet::service::capture_allocation::PacketNativeCaptureAllocationReport,
    serde_json::Value
);

// Each listed type is actual fixed numeric/closed-selector DATA. Copy is a
// compile-time barrier to adding an owned String, Vec or shared owner silently.
numeric_copy!(u8, u16, u32, u64, usize, bool, crucible_node_format::U64,
    crate::blob::BlobLimits, crate::envelope::RequestOrigin,
    crate::connection::ConnectionFailure,
    crate::retained_metadata::RetainedProtocolMetadataFacts,
    crate::retained_metadata::aliases::MetadataSharedKind,
    crate::client::compact_cursor::ContentGroupKind,
    crate::client::CanonicalAckCodecMetadataExtent,
    crate::reference_packet::service::confirmation::PacketNative5ConfirmationSelection,
    crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection,
    crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection,
    crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection,
    crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection,
    crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
    crate::reference_packet::service::PacketNative5ProtocolMetadataLimits,
    crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow,
    crate::connection::NativeCaptureSdkStateData,
    super::native::blob::HistoricalNativePinPhase);

impl<T: HistoricalStorage> HistoricalStorage for Vec<T> {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.vector::<T>(self.capacity())?;
        if T::NESTED_OWNERS {
            for value in self {
                value.observe_historical(observer)?;
            }
        }
        Ok(())
    }
}

impl<T: HistoricalStorage> HistoricalStorage for Option<T> {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        if let Some(value) = self {
            value.observe_historical(observer)?;
        }
        Ok(())
    }
}

impl<T: HistoricalStorage, const N: usize> HistoricalStorage for [T; N] {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        if T::NESTED_OWNERS {
            for value in self {
                value.observe_historical(observer)?;
            }
        }
        Ok(())
    }
}

impl<T: HistoricalStorage> HistoricalStorage for [T] {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        if T::NESTED_OWNERS {
            for value in self {
                value.observe_historical(observer)?;
            }
        }
        Ok(())
    }
}

impl<T: HistoricalStorage + ?Sized> HistoricalStorage for Rc<T> {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.shared_value(self.as_ref())?;
        self.as_ref().observe_historical(observer)
    }
}

impl<T: HistoricalStorage + ?Sized> HistoricalStorage for Arc<T> {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.shared_value(self.as_ref())?;
        self.as_ref().observe_historical(observer)
    }
}

impl<K: HistoricalStorage, V: HistoricalStorage> HistoricalStorage for BTreeMap<K, V> {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.tree::<K, V>(self.len())?;
        for (key, value) in self {
            key.observe_historical(observer)?;
            value.observe_historical(observer)?;
        }
        Ok(())
    }
}

impl<T: HistoricalStorage> HistoricalStorage for BTreeSet<T> {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        observer.tree::<T, ()>(self.len())?;
        for value in self {
            value.observe_historical(observer)?;
        }
        Ok(())
    }
}

impl<A: HistoricalStorage, B: HistoricalStorage> HistoricalStorage for (A, B) {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        self.0.observe_historical(observer)?;
        self.1.observe_historical(observer)
    }
}

fields!(
    crate::blob::TransferKey,
    origin,
    session,
    incarnation,
    transfer
);
fields!(
    crate::connection::ConnectionIncident,
    session,
    incarnation,
    connection,
    failure,
    transport_fenced,
    outgoing,
    incoming
);
fields!(
    crate::reference_packet::service::native_startup::PacketNativeStartupAllocation,
    schema,
    private_bootstrap,
    native_birth,
    restore_prepare
);
fields!(
    crate::reference_packet::service::ack_emitter::PacketCanonicalAckAdmissionContext,
    schema,
    algorithm,
    source_birth,
    kernel_binding,
    policy_binding,
    host_registration,
    native_registration,
    hello_request,
    hello_response,
    assigned_admit
);
fields!(
    crate::reference_packet::service::ack_emitter::PacketCanonicalAckAdmissionProof,
    schema,
    algorithm,
    context_digest,
    mac
);

impl HistoricalStorage for crate::blob::BlobRetirement {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::AbandonInert => Ok(()),
            Self::Operation { owner, receipt } => {
                owner.observe_historical(observer)?;
                receipt.observe_historical(observer)
            }
            Self::DurableStore { receipt } => receipt.observe_historical(observer),
        }
    }
}

impl HistoricalStorage for crate::client::ClientContent {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        self.observe_historical_retained_metadata(observer)
    }
}

impl HistoricalStorage for crate::transport::DecodedCompactOriginalFrames {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        self.observe_historical_retained_metadata(observer)
    }
}

impl HistoricalStorage for crate::reference_packet::service::HistoricalNativeSupervisorBanks {
    fn observe_historical(&self, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
        self.observe_historical_retained_metadata(observer)
    }
}

/// Names explicit historical owning-observer views before the caller's walk.
///
/// Typed source/caller counters, recursive/compiler frames and allocator
/// residency remain independent. Shared children are traversed sequentially.
pub(super) fn counter_scratch_data() -> usize {
    std::mem::size_of::<MetadataObserver<'static>>()
        + std::mem::size_of::<RetainedProtocolMetadataFacts>()
        + std::mem::size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + std::mem::size_of::<[&(); 4]>()
}

pub(super) fn facts<T: HistoricalStorage>(
    value: &T,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::new();
    value.observe_historical(&mut observer)?;
    Ok(observer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::Id;

    #[test]
    fn repeated_actual_aliases_keep_each_conservative_view_and_spare_capacity() {
        let mut text = String::with_capacity(41);
        text.push_str("held");
        let id = Id::new(text).unwrap();
        let id_capacity = id.allocated_capacity();
        let mut rows = Vec::with_capacity(9);
        rows.push(id);
        let capacity = rows.capacity();
        let shared = Rc::new(rows);
        let originals = [Rc::clone(&shared), Rc::clone(&shared)];

        let observed = facts(&originals).unwrap();

        assert_eq!(observed.shared_backing_views, 2);
        assert_eq!(
            observed.vector_capacity_bytes,
            2 * capacity * std::mem::size_of::<Id>()
        );
        assert_eq!(observed.string_capacity_bytes, 2 * id_capacity);
        assert!(Rc::ptr_eq(&originals[0], &originals[1]));
        assert_eq!(Rc::strong_count(&shared), 3);
    }

    #[test]
    fn empty_typed_tree_keeps_its_actual_container_and_key_value_layout() {
        let rows = BTreeMap::<String, serde_json::Value>::new();

        let observed = facts(&rows).unwrap();

        assert_eq!(observed.tree_containers, 1);
        assert_eq!(observed.tree_entries, 0);
        assert_eq!(
            observed.maximum_tree_key_value_bytes,
            std::mem::size_of::<String>() + std::mem::size_of::<serde_json::Value>()
        );
    }
}
