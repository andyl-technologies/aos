//! Preserves the actual report startup allocation as inert historical DATA.
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

impl OriginalNativeReportStartupAllocation {
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
        observer.observe(&match self.purpose {
            PacketNativeReportStartupPurpose::OriginalObserve12 => 0u8,
            PacketNativeReportStartupPurpose::FreshCompletedAdmit13 => 1u8,
        })?;
        observer.observe(&self.row.raw_report_capacity)?;
        observer.observe(&self.row.retained_growth_bytes)?;
        observer.observe(&self.row.maximum_simultaneous_transient_bytes)?;
        observer.observe(&self.row.declared_counter_scratch_bytes)?;
        observer.observe(&self.source_digest.as_bytes().len())?;
        Ok(())
    }
}

struct Startup17<'a>(&'a OriginalNativeReportStartupAllocation);

impl Serialize for Startup17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let OriginalNativeReportStartupAllocation {
            boot,
            policy,
            purpose,
            row,
            source_digest,
        } = self.0;
        let _parent_edges = (boot, policy);
        let mut fields =
            serializer.serialize_struct("OriginalNativeReportStartupAllocation17", 5)?;
        fields.serialize_field("boot", "native-boot")?;
        fields.serialize_field("policy", "native-policy")?;
        fields.serialize_field("purpose", purpose)?;
        fields.serialize_field("row", row)?;
        fields.serialize_field("source_digest", &BorrowedDigest17(source_digest.as_bytes()))?;
        fields.end()
    }
}

/// Retains DATA fields and checked local group ordinals without native owners.
pub(crate) struct HistoricalReportStartupAllocation17 {
    boot_group: usize,
    policy_group: usize,
    pub(crate) purpose: PacketNativeReportStartupPurpose,
    pub(crate) row: PacketNativeReportStartupAllocationRow,
    pub(crate) source_digest: HistoricalDigest17,
}

impl HistoricalReportStartupAllocation17 {
    /// Returns archive-local DATA ordinals for whole-parent correspondence.
    pub(crate) const fn group_ids_data(&self) -> (usize, usize) {
        (self.boot_group, self.policy_group)
    }
}

impl HistoricalReportStartupAllocation17 {
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
        let purpose =
            ledger.read::<PacketNativeReportStartupPurpose>(fields.named("purpose")?, build)?;
        let row =
            ledger.read::<PacketNativeReportStartupAllocationRow>(fields.named("row")?, build)?;
        let source_digest =
            ledger.read::<HistoricalDigest17>(fields.named("source_digest")?, build)?;
        fields.finish()?;
        let groups = (boot_group, policy_group);
        if !build {
            return Ok((None, groups));
        }
        Ok((
            Some(Self {
                boot_group,
                policy_group,
                purpose: purpose.ok_or_else(invalid)?,
                row: row.ok_or_else(invalid)?,
                source_digest: source_digest.ok_or_else(invalid)?,
            }),
            groups,
        ))
    }
}
impl HistoricalType for HistoricalReportStartupAllocation17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|fields| fields.0)
    }
}

impl HistoricalType for PacketNativeReportStartupPurpose {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let value = match plain_string(input)? {
            "original_observe12" => Self::OriginalObserve12,
            "fresh_completed_admit13" => Self::FreshCompletedAdmit13,
            _ => return Err(invalid()),
        };
        Ok(build.then_some(value))
    }
}

historical_struct!(PacketNativeReportStartupAllocationRow {
    raw_report_capacity: U64,
    retained_growth_bytes: U64,
    maximum_simultaneous_transient_bytes: U64,
    declared_counter_scratch_bytes: U64,
});
