//! Borrows original complete-endpoint fields without creating a new endpoint.
//!
//! ```text
//! {schema,creator,thread_role,storage,profile,hello,metadata_limits,
//!  metadata_birth_facts,before,after,poisoned,unwind_payload}
//! ```
//!
//! Independently present snapshot banks remain independent. An opaque retained
//! panic payload refuses without moving or dropping any original owner.

use super::*;
use crate::native_hello::HistoricalNativeHello17;
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, invalid, plain_string};
use crate::protocol_snapshot::settled_reservation17::HistoricalReservation17;
use crate::reference_packet::service::{
    PacketNative5ProtocolMetadataBirthFacts, PacketNative5ProtocolMetadataLimits,
};
use crate::retained_metadata::MetadataObserver;
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct CompleteHistory<'a>(&'a CompleteEndpointState);

impl CompleteEndpointState {
    fn authenticate_settled17_data(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if self.unwind_payload.is_some() {
            return Err(ProviderError::Correlation(
                "native17 opaque complete endpoint panic payload",
            ));
        }
        Ok(())
    }

    /// Borrows all complete endpoint fields while preserving each optional bank.
    ///
    /// # Errors
    /// Refuses foreign origin or an opaque retained panic payload without release.
    pub(crate) fn borrowed_settled17_data(&self) -> Result<impl Serialize + '_, ProviderError> {
        self.authenticate_settled17_data()?;
        Ok(CompleteHistory(self))
    }

    /// Appends actual complete-state capacities and original association edges.
    ///
    /// # Errors
    /// Refuses foreign or opaque state, changed bank edges or exhausted admission.
    pub(crate) fn observe_settled17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled17_data()?;
        let Self {
            creator,
            thread,
            storage,
            profile,
            hello,
            metadata_limits,
            metadata_birth_facts,
            before,
            after,
            poisoned,
            unwind_payload,
        } = self;
        observer.observe(creator)?;
        // The encoded thread role denotes this checked original-thread relation;
        // it exposes no host thread coordinate or continuation permission.
        observer.observe(&(*thread == std::thread::current().id()))?;
        observer.observe(storage)?;
        observer.observe(profile)?;
        hello.observe_settled17_metadata_data(observer)?;
        observer.observe(metadata_limits)?;
        observer.observe(metadata_birth_facts)?;
        observer.observe(&before.is_some())?;
        if let Some(before) = before {
            before.observe_settled17_metadata_data(hello, observer)?;
        }
        observer.observe(&after.is_some())?;
        if let Some(after) = after {
            after.observe_settled17_metadata_data(hello, observer)?;
        }
        observer.observe(poisoned)?;
        observer.observe(&unwind_payload.is_some())?;
        Ok(())
    }

    /// Counts the defining borrowed complete-state serializer and result views.
    pub(crate) const fn settled17_counter_scratch_data() -> usize {
        std::mem::size_of::<CompleteHistory<'static>>()
            + std::mem::size_of::<Result<(), ProviderError>>()
    }
}

impl Serialize for CompleteHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .authenticate_settled17_data()
            .map_err(serde::ser::Error::custom)?;
        let CompleteEndpointState {
            creator,
            thread: _,
            storage,
            profile,
            hello,
            metadata_limits,
            metadata_birth_facts,
            before,
            after,
            poisoned,
            unwind_payload: _,
        } = self.0;
        let mut fields = serializer.serialize_struct("CompleteEndpointHistory17", 12)?;
        fields.serialize_field("schema", "source-private.complete-endpoint-history/17")?;
        fields.serialize_field("creator", creator)?;
        fields.serialize_field("thread_role", "same-original-native-thread-history-only")?;
        fields.serialize_field("storage", storage)?;
        fields.serialize_field("profile", profile)?;
        fields.serialize_field(
            "hello",
            &hello
                .borrowed_settled17_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("metadata_limits", metadata_limits)?;
        fields.serialize_field("metadata_birth_facts", metadata_birth_facts)?;
        fields.serialize_field(
            "before",
            &before
                .as_ref()
                .map(|bank| bank.borrowed_settled17_data(hello))
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field(
            "after",
            &after
                .as_ref()
                .map(|bank| bank.borrowed_settled17_data(hello))
                .transpose()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_field("poisoned", poisoned)?;
        fields.serialize_field("unwind_payload", &Option::<()>::None)?;
        fields.end()
    }
}

/// Retains independently present same-pass Hello and reservation associations.
#[derive(Clone, Copy)]
pub(crate) struct CompleteEndpoint17Groups {
    pub(crate) hello: usize,
    pub(crate) before: Option<(Option<usize>, Option<usize>, Option<usize>)>,
    pub(crate) after: Option<(Option<usize>, Option<usize>, Option<usize>)>,
    pub(crate) before_authority: Option<(usize, usize)>,
    pub(crate) after_authority: Option<(usize, usize)>,
}

/// Owns checked endpoint history beside the enclosing complete raw protocol body.
pub(crate) struct HistoricalCompleteEndpoint17 {
    pub(crate) creator: u32,
    pub(crate) storage: PacketNative5StorageLimits,
    pub(crate) profile: Option<PacketNative5CaptureProfile>,
    pub(crate) hello: HistoricalNativeHello17,
    pub(crate) metadata_limits: Option<PacketNative5ProtocolMetadataLimits>,
    pub(crate) metadata_birth_facts: Option<PacketNative5ProtocolMetadataBirthFacts>,
    pub(crate) before: Option<HistoricalReservation17>,
    pub(crate) after: Option<HistoricalReservation17>,
    pub(crate) poisoned: bool,
    groups: CompleteEndpoint17Groups,
}

impl HistoricalCompleteEndpoint17 {
    /// Reads exact complete-state fields with no native owner reconstruction.
    ///
    /// # Errors
    /// Refuses opaque payloads, malformed fields or unconsumed bank metadata.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_settled17_fields_data(input, ledger, build).map(|result| result.0)
    }

    /// Returns real Hello and reservation aliases during both reader passes.
    ///
    /// # Errors
    /// Refuses opaque payloads, malformed fields or changed bank associations.
    pub(crate) fn read_settled17_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, CompleteEndpoint17Groups), ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.complete-endpoint-history/17",
        )?;
        let creator = ledger
            .read::<u32>(fields.named("creator")?, true)?
            .ok_or_else(invalid)?;
        exact(
            fields.named("thread_role")?,
            "same-original-native-thread-history-only",
        )?;
        let storage = ledger.read::<PacketNative5StorageLimits>(fields.named("storage")?, build)?;
        let profile =
            ledger.read::<Option<PacketNative5CaptureProfile>>(fields.named("profile")?, build)?;
        let (hello, hello_group) = HistoricalNativeHello17::read_settled17_fields_data(
            fields.named("hello")?,
            ledger,
            build,
        )?;
        let metadata_limits = ledger.read::<Option<PacketNative5ProtocolMetadataLimits>>(
            fields.named("metadata_limits")?,
            build,
        )?;
        let metadata_birth_facts = ledger.read::<Option<PacketNative5ProtocolMetadataBirthFacts>>(
            fields.named("metadata_birth_facts")?,
            build,
        )?;
        let before = reservation_data(fields.named("before")?, ledger, build)?;
        let after = reservation_data(fields.named("after")?, ledger, build)?;
        let poisoned = ledger
            .read::<bool>(fields.named("poisoned")?, true)?
            .ok_or_else(invalid)?;
        if fields.named("unwind_payload")? != b"null" {
            return Err(invalid());
        }
        fields.finish()?;
        for reservation in [&before, &after].into_iter().flatten() {
            if reservation
                .group_ids_data()
                .0
                .is_some_and(|actual| actual != hello_group)
            {
                return Err(invalid());
            }
        }
        let groups = CompleteEndpoint17Groups {
            hello: hello_group,
            before: before.as_ref().map(HistoricalReservation17::group_ids_data),
            after: after.as_ref().map(HistoricalReservation17::group_ids_data),
            before_authority: before
                .as_ref()
                .and_then(HistoricalReservation17::issuer_registration_groups_data),
            after_authority: after
                .as_ref()
                .and_then(HistoricalReservation17::issuer_registration_groups_data),
        };
        if !build {
            return Ok((None, groups));
        }
        Ok((
            Some(Self {
                creator,
                storage: storage.ok_or_else(invalid)?,
                profile: profile.ok_or_else(invalid)?,
                hello: hello.ok_or_else(invalid)?,
                metadata_limits: metadata_limits.ok_or_else(invalid)?,
                metadata_birth_facts: metadata_birth_facts.ok_or_else(invalid)?,
                before,
                after,
                poisoned,
                groups,
            }),
            groups,
        ))
    }

    /// Returns the real same-pass Hello and independently present bank edges.
    pub(crate) const fn group_ids_data(&self) -> CompleteEndpoint17Groups {
        self.groups
    }
}

fn reservation_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalReservation17>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    HistoricalReservation17::read_settled17_data(input, ledger, build).map(Some)
}

fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}
