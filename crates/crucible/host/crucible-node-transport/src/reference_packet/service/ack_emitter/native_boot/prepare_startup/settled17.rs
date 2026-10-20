//! Preserves the actual prepare startup allocation as inert historical DATA.
//!
//! The two role edges resolve only already defined17 Boot/Policy alias groups.
//! Neither a decoded row nor the historical digests recreate a native scope.

use super::*;
use crate::connection::settled17::{BorrowedDigest17, HistoricalDigest17};
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, historical_struct, invalid, plain_string,
};
use crate::reference_packet::Native5Policy;
use crate::retained_metadata::{
    MetadataObserver, aliases::MetadataSharedKind, records::MetadataRecordKind,
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::mem::{align_of, size_of};

impl OriginalNativePrepareStartupAllocation {
    /// Borrows the actual scope after checking both independently held Rc edges.
    ///
    /// # Errors
    /// Refuses a different Boot or Policy, foreign creator, or borrowed Boot.
    pub(crate) fn borrowed_settled17_data<'a>(
        &'a self,
        boot: &'a Rc<RefCell<NativeAckBoot>>,
        policy: &'a Rc<Native5Policy>,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        if !Rc::ptr_eq(&self.boot, boot) || !Rc::ptr_eq(&self.policy, policy) {
            return Err(invalid());
        }
        boot.try_borrow().map_err(|_| invalid())?.ensure_origin()?;
        Ok(Startup17(self))
    }

    /// Appends actual repeated shared edges without revisiting their payloads.
    ///
    /// # Errors
    /// Refuses exhausted metadata capacity or invalid actual parent edges.
    pub(crate) fn observe_settled17_metadata(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        policy: &Rc<Native5Policy>,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.borrowed_settled17_data(boot, policy)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, self.boot.as_ref())?;
        observer.shared_original(MetadataSharedKind::NativePolicy, self.policy.as_ref())?;
        observer.observe(&self.row.retained_requested_bytes)?;
        observer.observe(&self.row.maximum_simultaneous_transient_bytes)?;
        observer.observe(&self.row.declared_counter_scratch_bytes)?;
        observer.observe(&self.source_digest.as_bytes().len())?;
        observer.observe(&self.launch_digest.as_bytes().len())?;
        observer.observe(&self.started)?;
        self.storage.observe_metadata_data(observer)?;
        Ok(())
    }
}

struct Startup17<'a>(&'a OriginalNativePrepareStartupAllocation);

impl Serialize for Startup17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let OriginalNativePrepareStartupAllocation {
            boot,
            policy,
            row,
            source_digest,
            launch_digest,
            started,
            storage,
        } = self.0;
        let _parent_edges = (boot, policy);
        let mut fields =
            serializer.serialize_struct("OriginalNativePrepareStartupAllocation17", 7)?;
        fields.serialize_field("boot", "native-boot")?;
        fields.serialize_field("policy", "native-policy")?;
        fields.serialize_field("row", row)?;
        fields.serialize_field("source_digest", &BorrowedDigest17(source_digest.as_bytes()))?;
        fields.serialize_field("launch_digest", &BorrowedDigest17(launch_digest.as_bytes()))?;
        fields.serialize_field("started", started)?;
        fields.serialize_field("storage", &Storage17(storage))?;
        fields.end()
    }
}

/// Retains DATA fields and checked local group ordinals without native owners.
pub(crate) struct HistoricalPrepareStartupAllocation17 {
    boot_group: usize,
    policy_group: usize,
    pub(crate) row: PacketNativeStartupAllocationRow,
    pub(crate) source_digest: HistoricalDigest17,
    pub(crate) launch_digest: HistoricalDigest17,
    pub(crate) started: bool,
    pub(crate) storage: HistoricalPrepareStartupStorage17,
}

impl HistoricalPrepareStartupAllocation17 {
    /// Returns archive-local DATA ordinals for whole-parent correspondence.
    pub(crate) const fn group_ids_data(&self) -> (usize, usize) {
        (self.boot_group, self.policy_group)
    }
}

impl HistoricalPrepareStartupAllocation17 {
    /// Reads complete inert fields and returns the same-pass shared groups.
    ///
    /// # Errors
    /// Refuses malformed fields/roles, unavailable backing or changed aliases.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, (usize, usize)), ProviderError> {
        let mut fields = Fields::object(input)?;
        if plain_string(fields.named("boot")?)? != "native-boot"
            || ledger.row_aligned(
                MetadataRecordKind::Shared,
                1,
                align_of::<RefCell<NativeAckBoot>>(),
            )? != size_of::<RefCell<NativeAckBoot>>()
        {
            return Err(invalid());
        }
        let boot_group = ledger.shared_reference(
            MetadataSharedKind::NativeBoot,
            size_of::<RefCell<NativeAckBoot>>(),
        )?;
        if plain_string(fields.named("policy")?)? != "native-policy"
            || ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<Native5Policy>())?
                != size_of::<Native5Policy>()
        {
            return Err(invalid());
        }
        let policy_group = ledger
            .shared_reference(MetadataSharedKind::NativePolicy, size_of::<Native5Policy>())?;
        let row = ledger.read::<PacketNativeStartupAllocationRow>(fields.named("row")?, build)?;
        let source_digest =
            ledger.read::<HistoricalDigest17>(fields.named("source_digest")?, build)?;
        let launch_digest =
            ledger.read::<HistoricalDigest17>(fields.named("launch_digest")?, build)?;
        let started = ledger.read::<bool>(fields.named("started")?, build)?;
        let storage =
            ledger.read::<HistoricalPrepareStartupStorage17>(fields.named("storage")?, build)?;
        fields.finish()?;
        let groups = (boot_group, policy_group);
        if !build {
            return Ok((None, groups));
        }
        Ok((
            Some(Self {
                boot_group,
                policy_group,
                row: row.ok_or_else(invalid)?,
                source_digest: source_digest.ok_or_else(invalid)?,
                launch_digest: launch_digest.ok_or_else(invalid)?,
                started: started.ok_or_else(invalid)?,
                storage: storage.ok_or_else(invalid)?,
            }),
            groups,
        ))
    }
}
impl HistoricalType for HistoricalPrepareStartupAllocation17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|fields| fields.0)
    }
}

struct Storage17<'a>(&'a PacketNativePrepareStartupStorageData);

impl Serialize for Storage17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let PacketNativePrepareStartupStorageData {
            retained_growth_bytes,
            maximum_simultaneous_transient_bytes,
            declared_counter_scratch_bytes,
            authority_clone_bytes,
            maximum_features,
            maximum_original_bytes,
            maximum_body_bytes,
        } = self.0;
        let mut fields = serializer.serialize_struct("PrepareStartupStorage17", 7)?;
        fields.serialize_field("retained_growth_bytes", retained_growth_bytes)?;
        fields.serialize_field(
            "maximum_simultaneous_transient_bytes",
            maximum_simultaneous_transient_bytes,
        )?;
        fields.serialize_field(
            "declared_counter_scratch_bytes",
            declared_counter_scratch_bytes,
        )?;
        fields.serialize_field("authority_clone_bytes", authority_clone_bytes)?;
        fields.serialize_field("maximum_features", maximum_features)?;
        fields.serialize_field("maximum_original_bytes", maximum_original_bytes)?;
        fields.serialize_field("maximum_body_bytes", maximum_body_bytes)?;
        fields.end()
    }
}

/// Retains all seven fixed Prepare plan fields as quantities only.
pub(crate) struct HistoricalPrepareStartupStorage17 {
    pub(crate) retained_growth_bytes: usize,
    pub(crate) maximum_simultaneous_transient_bytes: usize,
    pub(crate) declared_counter_scratch_bytes: usize,
    pub(crate) authority_clone_bytes: usize,
    pub(crate) maximum_features: usize,
    pub(crate) maximum_original_bytes: usize,
    pub(crate) maximum_body_bytes: usize,
}

historical_struct!(HistoricalPrepareStartupStorage17 {
    retained_growth_bytes: usize,
    maximum_simultaneous_transient_bytes: usize,
    declared_counter_scratch_bytes: usize,
    authority_clone_bytes: usize,
    maximum_features: usize,
    maximum_original_bytes: usize,
    maximum_body_bytes: usize,
});
