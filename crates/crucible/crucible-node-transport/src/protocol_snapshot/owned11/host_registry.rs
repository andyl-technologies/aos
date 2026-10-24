//! Reconstructs the closed host registry archive as inert historical data.
//!
//! ```text
//! ["source-private.cnp-protocol/11", host-registry/12, capacity-records, aliases]
//! ```
//!
//! A complete borrowed pass checks the typed roster, every capacity and all five
//! shared groups before reconstruction. Original creators, secrets and registrar
//! generations remain historical data. Fresh enrollment creates new live owners.

use super::{
    aliases::{HistoricalAliasSummary, ValidatedHistoricalAliases},
    native::registrar::HistoricalNativeNegotiation,
    outer::{
        HistoricalControllerState, OwnedProtocol11AllocationDemand, OwnedProtocol11DataLimits,
    },
    state::{HistoricalAuthority, next, selected_extensions, tag},
    typed::{Fields, HistoricalType, Ledger, invalid, plain_string, unsigned},
};
use crate::{
    ProviderError,
    handshake::ORIGINAL_HOST_EXTENSION_REGISTRY_FORMAT,
    retained_metadata::{
        aliases::MetadataSharedKind,
        records::{MetadataRecordKind, ValidatedMetadataRecords},
    },
};
use crucible_node_format::{ContentRef, ExtensionSelection};
use std::sync::Arc;

const EMPTY_REGISTRY: &str = "source-private.sdk-empty-extension-registry/12";
const CREATOR_FORMAT: &str = "source-private.original-creator-rust-thread/12";

/// Retains a captured creator descriptor without constructing an original actor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HistoricalHostRegistryCreator {
    pid: u32,
    thread: [u8; 64],
    thread_length: usize,
}

impl HistoricalHostRegistryCreator {
    /// Reports the original process identifier as historical data.
    pub const fn process_id_data(&self) -> u32 {
        self.pid
    }

    /// Borrows the source-pinned original Rust thread spelling as historical bytes.
    pub fn thread_data(&self) -> &[u8] {
        &self.thread[..self.thread_length]
    }
}

/// Preserves the complete known callback family without any live callback.
///
/// Private fields permit immutable data inspection only. Equal group numbers
/// describe aliases in this archive; they cannot locate an original allocation
/// or authorize a fresh registrar, source association or native installation.
pub struct HistoricalHostExtensionRegistry {
    negotiation: HistoricalNativeNegotiation,
    authority: HistoricalAuthority,
    selected: Arc<[ExtensionSelection]>,
    creator: HistoricalHostRegistryCreator,
}

impl HistoricalHostExtensionRegistry {
    /// Borrows the original complete negotiation fields and private secrets.
    pub const fn negotiation_data(&self) -> &HistoricalNativeNegotiation {
        &self.negotiation
    }

    /// Borrows the exact original authenticated authority data.
    pub const fn authority_data(&self) -> &HistoricalAuthority {
        &self.authority
    }

    /// Borrows the same reconstructed selected slice shared by this authority.
    pub fn selected_data(&self) -> &[ExtensionSelection] {
        &self.selected
    }

    /// Borrows the repeated original creator descriptor as historical data.
    pub const fn creator_data(&self) -> &HistoricalHostRegistryCreator {
        &self.creator
    }

    /// Conjoins this registry's exact authority with a complete historical host.
    ///
    /// This comparison does not infer original Rc identity across independent
    /// archives. The source's signed closure authenticates their original common
    /// producer and body references before enrollment in a fresh target.
    ///
    /// # Errors
    /// Refuses a partial host class or any different registrar/negotiation data.
    pub fn authenticate_host_data(
        &self,
        host: &HistoricalControllerState,
    ) -> Result<(), ProviderError> {
        host.require_complete_reader_state()?;
        self.authenticate_data()?;
        for authority in [&host.session.authority, &host.session.connection.authority] {
            if !same_authority(&self.authority, authority) {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn authenticate_data(&self) -> Result<(), ProviderError> {
        let negotiation = &self.negotiation;
        let authority = &self.authority;
        if negotiation.contained
            || negotiation.registration_gate_poisoned
            || negotiation.epoch != negotiation.shared_epoch
            || negotiation.epoch != authority.epoch
            || negotiation.current_connection.as_ref() != Some(&authority.connection)
            || negotiation.installation.session != authority.session
            || negotiation.installation.incarnation != authority.incarnation
            || negotiation.selected_features.as_ref() != Some(&authority.features)
            || !self.selected.is_empty()
            || authority
                .extensions
                .as_ref()
                .is_none_or(|actual| !Arc::ptr_eq(actual, &self.selected))
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn same_authority(left: &HistoricalAuthority, right: &HistoricalAuthority) -> bool {
    left.connection == right.connection
        && left.session == right.session
        && left.incarnation == right.incarnation
        && left.epoch == right.epoch
        && left.limits == right.limits
        && left.features == right.features
        && left.envelope_extensions == right.envelope_extensions
        && left.extensions.as_deref() == right.extensions.as_deref()
}

fn authenticate_borrowed_registration(
    negotiation: &[u8],
    authority: &[u8],
) -> Result<(), ProviderError> {
    let mut original = Fields::object(negotiation)?;
    if plain_string(original.named("schema")?)? != "source-private.original-negotiation/5" {
        return Err(invalid());
    }
    let mut installation = Fields::array(original.named("installation")?)?;
    let session = next(&mut installation)?;
    let incarnation = next(&mut installation)?;
    let _implementation = next(&mut installation)?;
    let _receipt = next(&mut installation)?;
    let _secret = next(&mut installation)?;
    installation.finish()?;
    let _policy = original.named("policy")?;
    let epoch = original.named("epoch")?;
    let connection = original.named("current_connection")?;
    let features = original.named("selected_features")?;
    let _resume_token = original.named("resume_token")?;
    let contained = original.named("contained")?;
    let _hello_ids = original.named("hello_request_ids")?;
    let shared_epoch = original.named("shared_epoch")?;
    let poisoned = original.named("registration_gate_poisoned")?;
    original.finish()?;

    let mut actual = Fields::array(authority)?;
    tag(&mut actual, "source-private.connection-authority/11")?;
    if connection != next(&mut actual)?
        || session != next(&mut actual)?
        || incarnation != next(&mut actual)?
        || epoch != next(&mut actual)?
        || epoch != shared_epoch
        || contained != b"false"
        || poisoned != b"false"
    {
        return Err(invalid());
    }
    let _limits = next(&mut actual)?;
    if features != next(&mut actual)? {
        return Err(invalid());
    }
    let _envelope_extensions = next(&mut actual)?;
    if next(&mut actual)? != b"[]" {
        return Err(invalid());
    }
    tag(
        &mut actual,
        "original-registration-backing-retained-by-opaque-source",
    )?;
    actual.finish()
}

fn creator(input: &[u8]) -> Result<HistoricalHostRegistryCreator, ProviderError> {
    let mut fields = Fields::array(input)?;
    tag(&mut fields, CREATOR_FORMAT)?;
    let pid = u32::try_from(unsigned(next(&mut fields)?)?).map_err(|_| invalid())?;
    let thread = plain_string(next(&mut fields)?)?.as_bytes();
    fields.finish()?;
    let number = thread
        .strip_prefix(b"ThreadId(")
        .and_then(|value| value.strip_suffix(b")"))
        .ok_or_else(invalid)?;
    if pid == 0 || thread.len() > 64 || unsigned(number)? == 0 {
        return Err(invalid());
    }
    let mut retained = [0; 64];
    retained[..thread.len()].copy_from_slice(thread);
    Ok(HistoricalHostRegistryCreator {
        pid,
        thread: retained,
        thread_length: thread.len(),
    })
}

fn shared_registry(marker: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
    if plain_string(marker)? != EMPTY_REGISTRY
        || ledger.row_aligned(MetadataRecordKind::Shared, 1, 1)? != 0
    {
        return Err(invalid());
    }
    ledger.shared(MetadataSharedKind::InstalledRegistry, 0, marker, b"")?;
    Ok(())
}

fn shared_creator(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<HistoricalHostRegistryCreator, ProviderError> {
    let value = creator(input)?;
    let layout = std::mem::size_of::<crate::protocol_snapshot::ProtocolCaptureOwner>();
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        std::mem::align_of::<crate::protocol_snapshot::ProtocolCaptureOwner>(),
    )? != layout
    {
        return Err(invalid());
    }
    ledger.shared(MetadataSharedKind::ProtocolOwner, layout, input, b"")?;
    Ok(value)
}

impl HistoricalType for HistoricalHostExtensionRegistry {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        tag(&mut fields, ORIGINAL_HOST_EXTENSION_REGISTRY_FORMAT)?;
        let negotiation_input = next(&mut fields)?;
        let authority_input = next(&mut fields)?;
        authenticate_borrowed_registration(negotiation_input, authority_input)?;
        let negotiation = ledger.read::<HistoricalNativeNegotiation>(negotiation_input, build)?;
        let authority = ledger.read::<HistoricalAuthority>(authority_input, build)?;
        let erased = next(&mut fields)?;
        let concrete = next(&mut fields)?;
        let selected_input = next(&mut fields)?;
        let retained_creator = next(&mut fields)?;
        let source_creator = next(&mut fields)?;
        fields.finish()?;
        if selected_input != b"[]" || erased != concrete || retained_creator != source_creator {
            return Err(invalid());
        }
        // Follow the actual borrowed observer, including the source-held third
        // registry view, whose fixed zero-field marker repeats the same family.
        shared_registry(erased, ledger)?;
        shared_registry(concrete, ledger)?;
        let creator = shared_creator(retained_creator, ledger)?;
        shared_creator(source_creator, ledger)?;
        shared_registry(erased, ledger)?;
        let selected = selected_extensions(selected_input, ledger, build)?;
        if !build {
            return Ok(None);
        }
        let historical = Self {
            negotiation: negotiation.ok_or_else(invalid)?,
            authority: authority.ok_or_else(invalid)?,
            selected: selected.ok_or_else(invalid)?.ok_or_else(invalid)?,
            creator,
        };
        historical.authenticate_data()?;
        Ok(Some(historical))
    }
}

fn complete_alias_roster(input: &[u8]) -> Result<(), ProviderError> {
    let expected = [
        ("registrar-epoch", 0),
        ("registrar-gate", 1),
        ("registrar-epoch", 0),
        ("registrar-gate", 1),
        ("selected-extensions", 2),
        ("installed-registry", 3),
        ("installed-registry", 3),
        ("protocol-owner", 4),
        ("protocol-owner", 4),
        ("installed-registry", 3),
        ("selected-extensions", 2),
    ];
    let mut fields = Fields::array(input)?;
    for (kind, group) in expected {
        let mut row = Fields::array(next(&mut fields)?)?;
        if plain_string(next(&mut row)?)? != kind || unsigned(next(&mut row)?)? != group {
            return Err(invalid());
        }
        row.finish()?;
    }
    fields.finish()
}

/// Borrows a fully checked registry body and caller-precharged alias summaries.
pub struct ValidatedHostExtensionRegistry<'a, 'scratch> {
    input: &'a [u8],
    data: &'a [u8],
    records: ValidatedMetadataRecords<'a>,
    aliases: ValidatedHistoricalAliases<'a, 'scratch>,
    limits: OwnedProtocol11DataLimits,
    demand: OwnedProtocol11AllocationDemand,
}

impl<'a, 'scratch> ValidatedHostExtensionRegistry<'a, 'scratch> {
    /// Validates the complete registry class, capacities and original alias graph.
    ///
    /// This borrowed pass performs no owned field reconstruction. The source
    /// separately admits its full demand, encoded body and actual summary bank.
    ///
    /// # Errors
    /// Refuses another class, malformed or mismatched fields, wrong capacities,
    /// changed aliases, trailing rows or any exceeded finite data bound.
    pub fn validate(
        input: &'a [u8],
        limits: OwnedProtocol11DataLimits,
        summaries: &'scratch mut [HistoricalAliasSummary],
    ) -> Result<Self, ProviderError> {
        if input.len() > limits.json.maximum_input_bytes {
            return Err(invalid());
        }
        super::outer::validate_outer_work(input, limits.json.maximum_nodes)?;
        let mut fields = Fields::array(input)?;
        tag(&mut fields, "source-private.cnp-protocol/11")?;
        let data = next(&mut fields)?;
        let records = ValidatedMetadataRecords::validate(
            next(&mut fields)?,
            limits.maximum_metadata_rows,
            limits.json.maximum_owned_backing_bytes,
        )?;
        let aliases_input = next(&mut fields)?;
        complete_alias_roster(aliases_input)?;
        let mut aliases = ValidatedHistoricalAliases::validate(
            aliases_input,
            summaries,
            limits.maximum_metadata_rows,
        )?;
        fields.finish()?;
        let mut demand = super::outer::demand_records(&records)?;
        if demand.tree_entries > limits.json.maximum_tree_entries {
            return Err(invalid());
        }
        let selected_slice_staging_bytes = {
            let mut ledger = super::outer::make_ledger(&records, limits);
            ledger.aliases = Some(aliases.views()?);
            ledger.read::<HistoricalHostExtensionRegistry>(data, false)?;
            if ledger.rows.next().is_some() {
                return Err(invalid());
            }
            ledger.aliases.take().ok_or_else(invalid)?.finish()?;
            ledger.selected_slice_staging_bytes
        };
        demand.alias_groups = aliases.group_count();
        demand.alias_rows = aliases.row_count();
        demand.alias_summary_entries = aliases.group_count();
        demand.alias_summary_layout_bytes = aliases
            .group_count()
            .checked_mul(std::mem::size_of::<HistoricalAliasSummary>())
            .ok_or_else(invalid)?;
        demand.selected_group_lookup_bytes = aliases
            .group_count()
            .checked_mul(std::mem::size_of::<Option<Arc<[ExtensionSelection]>>>())
            .ok_or_else(invalid)?;
        demand.selected_slice_staging_bytes = selected_slice_staging_bytes;
        Ok(Self {
            input,
            data,
            records,
            aliases,
            limits,
            demand,
        })
    }

    /// Borrows the complete known requested-storage report before reconstruction.
    pub const fn allocation_demand(&self) -> &OwnedProtocol11AllocationDemand {
        &self.demand
    }

    /// Reconstructs immutable historical fields without creating a registrar.
    ///
    /// # Errors
    /// Refuses occupied output, failed exact reservations or defensive row/alias
    /// mismatch. Any completed owner remains in the caller's slot on refusal.
    pub fn reconstruct_complete_into(
        &mut self,
        completed: &mut Option<HistoricalHostExtensionRegistry>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(invalid());
        }
        let count = self.aliases.group_count();
        let mut selected = Vec::new();
        selected.try_reserve_exact(count).map_err(|_| invalid())?;
        if selected.capacity() != count {
            return Err(invalid());
        }
        selected.resize_with(count, || None);
        let mut ledger = super::outer::make_ledger(&self.records, self.limits);
        ledger.aliases = Some(self.aliases.views()?);
        ledger.selected_groups = Some(&mut selected);
        *completed = ledger.read::<HistoricalHostExtensionRegistry>(self.data, true)?;
        if ledger.rows.next().is_some() {
            return Err(invalid());
        }
        ledger.aliases.take().ok_or_else(invalid)?.finish()?;
        completed.as_ref().ok_or_else(invalid)?.authenticate_data()
    }

    /// Moves a precharged encoded bank beside its exact immutable decoded owner.
    ///
    /// # Errors
    /// Refuses occupied output, a used/undersized bank, a wrong body commitment,
    /// failed reconstruction or incomplete correspondence. Once the bank moves,
    /// the partial sealed owner remains in the destination on later refusal.
    pub fn reconstruct_sealed_into(
        &mut self,
        reference: &ContentRef,
        encoded_bank: &mut Option<Vec<u8>>,
        completed: &mut Option<SealedHistoricalHostExtensionRegistry>,
    ) -> Result<(), ProviderError> {
        if completed.is_some()
            || encoded_bank
                .as_ref()
                .is_none_or(|bank| !bank.is_empty() || bank.capacity() < self.input.len())
        {
            return Err(invalid());
        }
        reference.verify(self.input).map_err(|_| invalid())?;
        *completed = Some(SealedHistoricalHostExtensionRegistry {
            reference: reference.clone(),
            encoded: encoded_bank.take().ok_or_else(invalid)?,
            historical: None,
            complete: false,
        });
        let retained = completed.as_mut().ok_or_else(invalid)?;
        retained.encoded.extend_from_slice(self.input);
        self.reconstruct_complete_into(&mut retained.historical)?;
        retained.complete = true;
        Ok(())
    }
}

/// Retains an immutable complete registry beside its verified original bytes.
///
/// This data provenance owner contains no current callback, creator or registrar.
/// Fresh source enrollment is authenticated separately against the signed archive.
pub struct SealedHistoricalHostExtensionRegistry {
    reference: ContentRef,
    encoded: Vec<u8>,
    historical: Option<HistoricalHostExtensionRegistry>,
    complete: bool,
}

impl SealedHistoricalHostExtensionRegistry {
    /// Borrows the verified complete archive body reference.
    pub const fn body_reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the exact retained original encoded body.
    pub fn encoded_body(&self) -> &[u8] {
        &self.encoded
    }

    /// Reports the actual encoded byte bank capacity.
    pub fn encoded_capacity(&self) -> usize {
        self.encoded.capacity()
    }

    /// Borrows only the fully reconstructed immutable registry data.
    ///
    /// # Errors
    /// Refuses a partially constructed or failed historical owner.
    pub fn historical(&self) -> Result<&HistoricalHostExtensionRegistry, ProviderError> {
        if !self.complete {
            return Err(invalid());
        }
        self.historical.as_ref().ok_or_else(invalid)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "closed historical-data fixture assertions"
)]
mod tests {
    use super::*;

    const ALIASES: &[u8] = br#"[["registrar-epoch",0],["registrar-gate",1],["registrar-epoch",0],["registrar-gate",1],["selected-extensions",2],["installed-registry",3],["installed-registry",3],["protocol-owner",4],["protocol-owner",4],["installed-registry",3],["selected-extensions",2]]"#;

    #[test]
    fn registry_alias_roster_requires_same_original_creators_and_selected_slice() {
        complete_alias_roster(ALIASES).unwrap();

        let different_creator = std::str::from_utf8(ALIASES).unwrap().replacen(
            "[\"protocol-owner\",4],[\"protocol-owner\",4]",
            "[\"protocol-owner\",4],[\"protocol-owner\",5]",
            1,
        );
        assert!(complete_alias_roster(different_creator.as_bytes()).is_err());
        let different_selected = std::str::from_utf8(ALIASES).unwrap().replacen(
            "[\"selected-extensions\",2]",
            "[\"selected-extensions\",3]",
            1,
        );
        assert!(complete_alias_roster(different_selected.as_bytes()).is_err());
        let mut trailing = ALIASES[..ALIASES.len() - 1].to_vec();
        trailing.extend_from_slice(br#",["protocol-owner",4]]"#);
        assert!(complete_alias_roster(&trailing).is_err());
        assert!(complete_alias_roster(br#"[["registrar-epoch",0]]"#).is_err());
    }

    #[test]
    fn creator_preserves_exact_historical_data_and_refuses_unrepresentable_forms() {
        let data =
            creator(br#"["source-private.original-creator-rust-thread/12",42,"ThreadId(7)"]"#)
                .unwrap();
        assert_eq!(data.process_id_data(), 42);
        assert_eq!(data.thread_data(), b"ThreadId(7)");
        assert!(
            creator(br#"["source-private.original-creator-rust-thread/12",0,"ThreadId(7)"]"#)
                .is_err()
        );
        assert!(
            creator(br#"["source-private.original-creator-rust-thread/12",42,"ThreadId(0)"]"#)
                .is_err()
        );
        assert!(
            creator(br#"["source-private.original-creator-rust-thread/12",42,"ThreadId(07)"]"#)
                .is_err()
        );
        assert!(
            creator(
                br#"["source-private.original-creator-rust-thread/12",4294967296,"ThreadId(7)"]"#
            )
            .is_err()
        );
        assert!(
            creator(br#"["source-private.original-creator-rust-thread/12",42,"ThreadId(7)",0]"#)
                .is_err()
        );
    }

    #[test]
    fn borrowed_registration_checks_full_current_data_before_owned_reconstruction() {
        let negotiation = br#"{"schema":"source-private.original-negotiation/5","installation":["session","incarnation",{},null,[]],"policy":[],"epoch":"3","current_connection":"connection","selected_features":["typed"],"resume_token":null,"contained":false,"hello_request_ids":[],"shared_epoch":"3","registration_gate_poisoned":false}"#;
        let authority = br#"["source-private.connection-authority/11","connection","session","incarnation","3",{},["typed"],[],[],"original-registration-backing-retained-by-opaque-source"]"#;
        authenticate_borrowed_registration(negotiation, authority).unwrap();

        let poisoned = std::str::from_utf8(negotiation).unwrap().replace(
            "\"registration_gate_poisoned\":false",
            "\"registration_gate_poisoned\":true",
        );
        assert!(authenticate_borrowed_registration(poisoned.as_bytes(), authority).is_err());
        let foreign_generation = std::str::from_utf8(negotiation)
            .unwrap()
            .replace("\"shared_epoch\":\"3\"", "\"shared_epoch\":\"4\"");
        assert!(
            authenticate_borrowed_registration(foreign_generation.as_bytes(), authority).is_err()
        );
        let foreign_session = std::str::from_utf8(authority)
            .unwrap()
            .replace("\"session\"", "\"foreign\"");
        assert!(
            authenticate_borrowed_registration(negotiation, foreign_session.as_bytes()).is_err()
        );
        let nonempty_selection = std::str::from_utf8(authority).unwrap().replace(
            ",[],[],\"original-registration",
            ",[],[{}],\"original-registration",
        );
        assert!(
            authenticate_borrowed_registration(negotiation, nonempty_selection.as_bytes()).is_err()
        );
    }
}

// The closed owning walk fails to compile if a historical field is added.
super::retained_storage::fields!(HistoricalHostRegistryCreator, pid, thread, thread_length);
super::retained_storage::fields!(
    HistoricalHostExtensionRegistry,
    negotiation,
    authority,
    selected,
    creator
);

super::retained_storage::fields!(
    SealedHistoricalHostExtensionRegistry,
    reference,
    encoded,
    historical,
    complete
);

impl SealedHistoricalHostExtensionRegistry {
    /// Observes actual initialized registry graph and encoded-bank capacities.
    ///
    /// Includes partial decoder owners and grants no registrar or currentness
    /// authority. The enclosing original owner authenticates its own creator.
    /// The enclosing concrete root header is counted separately by its owner.
    ///
    /// # Errors
    /// Refuses checked typed traversal or metadata/layout overflow.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, crate::ProviderError> {
        super::retained_storage::facts(self)
    }

    /// Names the actual fixed views before the raw historical graph walk.
    pub fn original_retained_metadata_counter_scratch_data() -> usize {
        super::retained_storage::counter_scratch_data()
    }
}
