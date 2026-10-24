//! Reads complete retained service, Control and endpoint quote historical fields.
//!
//! Quotes preserve historical scalar facts and exact shared role edges. They
//! neither create allocation credit nor reconstruct an operational deadline.

use super::current_facts::HistoricalMetadataFacts17;
use super::current_shared::{read_reference17, shared_row17};
use crate::ProviderError;
use crate::protocol_snapshot::ProtocolSnapshotAllocationFacts;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::reference_packet::{Native5Policy, service::ack_emitter::NativeAckBoot};
use crate::retained_metadata::aliases::MetadataSharedKind;
use crucible_node_format::ContentRef;
use std::mem::{align_of, size_of};

fn role(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

fn policy_reference(ledger: &mut Ledger<'_, '_, '_>) -> Result<usize, ProviderError> {
    read_reference17(
        ledger,
        MetadataSharedKind::NativePolicy,
        (size_of::<Native5Policy>(), align_of::<Native5Policy>()),
    )
}

pub(crate) struct CurrentStartupBanks17(pub(crate) [ProtocolSnapshotAllocationFacts; 2]);

impl HistoricalType for CurrentStartupBanks17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let first = ledger.read::<ProtocolSnapshotAllocationFacts>(
            fields.next_value()?.ok_or_else(invalid)?,
            build,
        )?;
        let second = ledger.read::<ProtocolSnapshotAllocationFacts>(
            fields.next_value()?.ok_or_else(invalid)?,
            build,
        )?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self([
            first.ok_or_else(invalid)?,
            second.ok_or_else(invalid)?,
        ])))
    }
}

pub(crate) struct CurrentEndpointQuote17 {
    pub(crate) creator: u32,
    pub(crate) policy_group: usize,
    pub(crate) facts: HistoricalMetadataFacts17,
    pub(crate) startup_banks: Option<CurrentStartupBanks17>,
}

impl HistoricalType for CurrentEndpointQuote17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role(
            fields.named("schema")?,
            "source-private.native-endpoint-restore-quote/17",
        )?;
        let creator = ledger.read::<u32>(fields.named("creator")?, build)?;
        role(
            fields.named("thread_role")?,
            "same-original-native-thread-history-only",
        )?;
        role(fields.named("policy_role")?, "native-policy")?;
        let policy_group = policy_reference(ledger)?;
        let facts = ledger.read::<HistoricalMetadataFacts17>(fields.named("facts")?, build)?;
        let startup_banks =
            ledger.read::<Option<CurrentStartupBanks17>>(fields.named("startup_banks")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            policy_group,
            facts: facts.ok_or_else(invalid)?,
            startup_banks: startup_banks.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) struct CurrentControlQuote17 {
    pub(crate) creator: u32,
    pub(crate) control_identity_group: usize,
    pub(crate) policy_group: usize,
    pub(crate) facts: HistoricalMetadataFacts17,
    pub(crate) endpoint: CurrentEndpointQuote17,
    pub(crate) gate: ContentRef,
}

impl HistoricalType for CurrentControlQuote17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role(
            fields.named("schema")?,
            "source-private.native-control-restore-quote/17",
        )?;
        let creator = ledger.read::<u32>(fields.named("creator")?, build)?;
        role(
            fields.named("control_identity_role")?,
            "current-native-control-identity",
        )?;
        let control_identity_group = read_reference17(
            ledger,
            MetadataSharedKind::NativeControlIdentity,
            (size_of::<()>(), align_of::<()>()),
        )?;
        role(fields.named("policy_role")?, "native-policy")?;
        let policy_group = policy_reference(ledger)?;
        let facts = ledger.read::<HistoricalMetadataFacts17>(fields.named("facts")?, build)?;
        let endpoint = ledger.read::<CurrentEndpointQuote17>(fields.named("endpoint")?, build)?;
        let gate = ledger.read::<ContentRef>(fields.named("gate")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            control_identity_group,
            policy_group,
            facts: facts.ok_or_else(invalid)?,
            endpoint: endpoint.ok_or_else(invalid)?,
            gate: gate.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) struct CurrentServiceQuote17 {
    pub(crate) creator: u32,
    pub(crate) boot_group: usize,
    pub(crate) policy_group: usize,
    pub(crate) facts: HistoricalMetadataFacts17,
}

impl CurrentServiceQuote17 {
    /// Conjoins the sole enclosing Boot backedge with its actual in-progress group.
    pub(crate) fn read_with_native_parent_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        expected_boot_group: usize,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role(
            fields.named("schema")?,
            "source-private.native-service-restore-quote/17",
        )?;
        let creator = ledger.read::<u32>(fields.named("creator")?, build)?;
        role(
            fields.named("thread_role")?,
            "same-original-native-thread-history-only",
        )?;
        role(fields.named("boot_role")?, "native-boot")?;
        let layout = NativeAckBoot::current_boot_shared_layout17_data();
        shared_row17(ledger, layout)?;
        let boot_group =
            ledger.shared_native_boot_parent_reference(expected_boot_group, layout.0)?;
        role(fields.named("policy_role")?, "native-policy")?;
        let policy_group = policy_reference(ledger)?;
        role(fields.named("cut_role")?, "historical-operational-deadline")?;
        let facts = ledger.read::<HistoricalMetadataFacts17>(fields.named("facts")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            boot_group,
            policy_group,
            facts: facts.ok_or_else(invalid)?,
        }))
    }
}
