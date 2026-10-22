//! Reads every current Control17 field as inert, separately retained DATA.
//!
//! The serializer writes evidence before Hold. The metadata observer defines
//! Hold before following evidence edges, so the reader borrows those two spans
//! and consumes their children in that same allocation order. No native Control,
//! Program, restoration Hold, socket or source permission is reconstructed.
//!
//! ```text
//! {schema,selection,program,complete_restored_evidence,complete_restored_hold,
//!  restoration_activation_required,capture_creator,capture_identity_role,...}
//! ```

use super::*;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::reference_packet::continuation_models::settled_reader::{
    PacketSettledModel17Data, read_settled_model17_data,
};
use crate::reference_packet::coordinator::{
    PacketConnectedCoordinatorInstallation, PacketCoordinatorInstallation,
    PacketNative5CoordinatorInstallation, PacketWorldCoordinatorInstallation,
};
use crate::reference_packet::service::{
    PacketNative5AckEmitterSelection, PacketNative5CaptureProfile,
    PacketNative5ConfirmationSelection, PacketNative5ProtocolMetadataBirthFacts,
    PacketNative5ProtocolMetadataLimits,
    capture_allocation::PacketNative5CaptureAllocationSelection,
    complete_restore::{
        PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
    },
};
use crate::retained_metadata::records::MetadataRecordKind;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata, aliases::MetadataSharedKind};
use serde::ser::SerializeStruct;
use std::mem::{align_of, size_of};

mod maps;
use maps::{CurrentContent17Data, CurrentOriginals17Data};

const CONTROL_SCHEMA: &str = "source-owned.packet-native-control-restored-settled/17";
const HOLD_SCHEMA: &str = "source-private.native-restored-physical-hold-history/17";
const EVIDENCE_SCHEMA: &str = "source-private.native-restored-control-evidence-history/17";
const CONTROL_IDENTITY_ROLE: &str = "current-native-control-identity";

macro_rules! scalar_role {
    ($name:ident, $text:expr) => {
        struct $name;

        impl HistoricalType for $name {
            fn read(
                input: &[u8],
                _: &mut Ledger<'_, '_, '_>,
                build: bool,
            ) -> Result<Option<Self>, ProviderError> {
                if plain_string(input)? != $text {
                    return Err(invalid());
                }
                Ok(build.then_some(Self))
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str($text)
            }
        }
    };
}

scalar_role!(ControlSchema17, CONTROL_SCHEMA);
scalar_role!(HoldSchema17, HOLD_SCHEMA);
scalar_role!(EvidenceSchema17, EVIDENCE_SCHEMA);
scalar_role!(ThreadRole17, "same-original-thread-history-only");

struct ControlIdentity17Data {
    group: usize,
}

impl HistoricalType for ControlIdentity17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let group = read_current_control_identity17_data(input, ledger)?;
        Ok(build.then_some(Self { group }))
    }
}

/// Reads the original unit-identity root or one repeated complete unit view.
///
/// # Errors
/// Refuses a wrong role, capacity record, alias kind or repeated group view.
pub(crate) fn read_current_control_identity17_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<usize, ProviderError> {
    if plain_string(input)? != CONTROL_IDENTITY_ROLE {
        return Err(invalid());
    }
    let start = ledger.rows.encoded_position();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<()>())? != size_of::<()>() {
        return Err(invalid());
    }
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared(
        MetadataSharedKind::NativeControlIdentity,
        size_of::<()>(),
        input,
        rows,
    )
}

impl Serialize for ControlIdentity17Data {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(CONTROL_IDENTITY_ROLE)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum HoldPhase17Data {
    Preparing,
    Installing,
    Held,
    Released,
}

impl HistoricalType for HoldPhase17Data {
    fn read(
        input: &[u8],
        _: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let phase = match plain_string(input)? {
            "preparing" => Self::Preparing,
            "installing" => Self::Installing,
            "held" => Self::Held,
            "released" => Self::Released,
            _ => return Err(invalid()),
        };
        Ok(build.then_some(phase))
    }
}

/// Preserves complete immutable Hold history and inert local group identities.
#[derive(Serialize)]
pub(crate) struct CurrentControlHold17Data {
    schema: HoldSchema17,
    creator: u32,
    thread: ThreadRole17,
    control_identity_role: ControlIdentity17Data,
    phase: HoldPhase17Data,
    cursor: Position,
    inventory_hash: HashRef,
    #[serde(skip)]
    group: usize,
}

impl HistoricalType for CurrentControlHold17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_fields_data(input, ledger, build).map(|result| result.0)
    }
}

impl CurrentControlHold17Data {
    fn read_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(Option<Self>, CurrentControlHold17GroupIds), ProviderError> {
        let mut attempt = CurrentControlHold17ReadAttempt::default();
        let groups = attempt.read_into(input, ledger, build)?;
        Ok((attempt.take_completed_data(), groups))
    }
}

/// Reads a defining Hold root with its own exact Shared record and full payload.
///
/// # Errors
/// Refuses malformed fields, mismatching capacity/alias rows or exhausted limits.
pub(crate) fn read_current_control_hold_root17_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<CurrentControlHold17Data>, ProviderError> {
    ledger.read::<CurrentControlHold17Data>(input, build)
}

impl CurrentControlHold17Data {
    /// Returns the inert ordinal of the independently checked full Hold group.
    pub(crate) fn group_data(&self) -> usize {
        self.group
    }

    /// Returns the inert ordinal of the Hold's original Control identity.
    pub(crate) fn capture_identity_group_data(&self) -> usize {
        self.control_identity_role.group
    }

    /// Returns the original historical process scalar without authenticating it.
    pub(crate) fn historical_creator_data(&self) -> u32 {
        self.creator
    }

    /// Returns the unchanged first Hold cursor rather than a later Capture cut.
    pub(crate) fn original_cursor_data(&self) -> Position {
        self.cursor
    }

    /// Borrows the original immutable inventory identity.
    pub(crate) fn inventory_hash_data(&self) -> &HashRef {
        &self.inventory_hash
    }
}

struct CurrentEvidence17Data {
    boot: usize,
    commit: usize,
    hold: usize,
}

fn reference_role(
    input: &[u8],
    text: &str,
    kind: MetadataSharedKind,
    layout: (usize, usize),
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<usize, ProviderError> {
    if plain_string(input)? != text
        || ledger.row_aligned(MetadataRecordKind::Shared, 1, layout.1)? != layout.0
    {
        return Err(invalid());
    }
    ledger.shared_reference(kind, layout.0)
}

impl HistoricalType for CurrentEvidence17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        use crate::reference_packet::service::ack_emitter::NativeAckBoot;
        let mut fields = Fields::object(input)?;
        ledger.read::<EvidenceSchema17>(fields.named("schema")?, build)?;
        let boot = reference_role(
            fields.named("boot_role")?,
            "native-boot",
            MetadataSharedKind::NativeBoot,
            NativeAckBoot::current_boot_shared_layout17_data(),
            ledger,
        )?;
        let commit = reference_role(
            fields.named("commit_role")?,
            "native-complete-restore-commit",
            MetadataSharedKind::NativeRestoreCommitAttempt,
            NativeAckBoot::current_commit_shared_layout17_data(),
            ledger,
        )?;
        let hold = reference_role(
            fields.named("hold_role")?,
            "native-complete-restore-physical-hold",
            MetadataSharedKind::NativeRestoredPhysicalHold,
            (
                size_of::<PacketCompleteRestorePhysicalHold>(),
                align_of::<PacketCompleteRestorePhysicalHold>(),
            ),
            ledger,
        )?;
        fields.finish()?;
        Ok(build.then_some(Self { boot, commit, hold }))
    }
}

impl Serialize for CurrentEvidence17Data {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("InertCurrentControlEvidence17", 4)?;
        fields.serialize_field("schema", EVIDENCE_SCHEMA)?;
        fields.serialize_field("boot_role", "native-boot")?;
        fields.serialize_field("commit_role", "native-complete-restore-commit")?;
        fields.serialize_field("hold_role", "native-complete-restore-physical-hold")?;
        fields.end()
    }
}

enum CurrentProgram17Data {
    Model(PacketSettledModel17Data),
    RestorationInProgress,
}

impl HistoricalType for CurrentProgram17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        let kind = plain_string(fields.next_value()?.ok_or_else(invalid)?)?;
        let data = fields.next_value()?.ok_or_else(invalid)?;
        fields.finish()?;
        if kind == "restoration-in-progress" {
            if data != b"null" {
                return Err(invalid());
            }
            return Ok(build.then_some(Self::RestorationInProgress));
        }
        Ok(read_settled_model17_data(input, ledger, build)?.map(Self::Model))
    }
}

impl Serialize for CurrentProgram17Data {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Model(model) => model.borrowed_program17_data().serialize(serializer),
            Self::RestorationInProgress => {
                ("restoration-in-progress", None::<()>).serialize(serializer)
            }
        }
    }
}

/// Retains all current native Control fields without a live Control constructor.
#[derive(Serialize)]
pub(crate) struct CurrentControl17Data {
    schema: ControlSchema17,
    selection: PacketControlSelection,
    program: CurrentProgram17Data,
    complete_restored_evidence: Option<CurrentEvidence17Data>,
    complete_restored_hold: Option<CurrentControlHold17Data>,
    restoration_activation_required: bool,
    capture_creator: u32,
    capture_identity_role: ControlIdentity17Data,
    originals: CurrentOriginals17Data,
    begins: BTreeMap<Id, BeginRequest>,
    begin_requests: BTreeMap<Id, Id>,
    content: CurrentContent17Data,
    content_bytes: usize,
    realized: bool,
    admitted: bool,
    staged: Option<(ActivateRequest, ContentRef)>,
    active: Option<WorldActivateRequest>,
    fenced: bool,
    native_effect_attempted: bool,
    immediate: bool,
    current_operation: Option<Id>,
    terminals: BTreeMap<Id, Map<String, Value>>,
    common_coordinator: Option<PacketCoordinatorInstallation>,
    world_coordinator: Option<PacketWorldCoordinatorInstallation>,
    connected_coordinator: Option<PacketConnectedCoordinatorInstallation>,
    complete_coordinator: Option<PacketNative5CoordinatorInstallation>,
    complete_storage: Option<PacketNative5StorageSelection>,
    complete_capture_profile: Option<PacketNative5CaptureProfile>,
    complete_confirmation_selection: Option<PacketNative5ConfirmationSelection>,
    complete_ack_emitter_selection: Option<PacketNative5AckEmitterSelection>,
    complete_restore_selection: Option<PacketNative5CompleteRestoreSelection>,
    complete_protocol_metadata_limits: Option<PacketNative5ProtocolMetadataLimits>,
    complete_protocol_metadata_birth_facts: Option<PacketNative5ProtocolMetadataBirthFacts>,
    complete_restore_input_emitter_selection: Option<PacketNative5RestoreInputEmitterSelection>,
    complete_capture_allocation_selection: Option<PacketNative5CaptureAllocationSelection>,
}

impl HistoricalType for CurrentControl17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_encoding_data(input, ledger, build, ControlEncoding17::Standalone)
    }
}

#[derive(Clone, Copy)]
enum ControlEncoding17<'a> {
    Standalone,
    Rooted { hold: Option<&'a [u8]> },
}

/// Reads rooted Control fields using the same enclosing grammar's exact Hold span.
///
/// The span carries historical DATA only. The enclosing complete reader must
/// join its independently defined group with Boot, current Control and SDK
/// evidence; supplying bytes to this helper creates no native permission.
///
/// # Errors
/// Refuses another schema, a missing or extraneous Hold role, malformed complete
/// children, or any source capacity/alias/target construction mismatch.
pub(crate) fn read_current_rooted_control17_data(
    spans: &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<CurrentControl17Data>, ProviderError> {
    CurrentControl17Data::read_encoding_data(
        spans.control_data(),
        ledger,
        build,
        ControlEncoding17::Rooted {
            hold: spans.hold_data(),
        },
    )
}

impl CurrentControl17Data {
    fn read_encoding_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        encoding: ControlEncoding17<'_>,
    ) -> Result<Option<Self>, ProviderError> {
        Self::read_encoding_fields_data(input, ledger, build, encoding).map(|result| result.0)
    }

    fn read_encoding_fields_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        encoding: ControlEncoding17<'_>,
    ) -> Result<(Option<Self>, CurrentControl17GroupIds), ProviderError> {
        let mut attempt = CurrentControl17ReadAttempt::default();
        let groups = attempt.read_encoding_into(input, ledger, build, encoding)?;
        Ok((attempt.take_completed_data(), groups))
    }
}

impl CurrentControl17Data {
    /// Borrows complete current model DATA; unfinished restoration stays absent.
    pub(crate) fn model_data(&self) -> Option<&PacketSettledModel17Data> {
        match &self.program {
            CurrentProgram17Data::Model(model) => Some(model),
            CurrentProgram17Data::RestorationInProgress => None,
        }
    }

    /// Returns the independently checked original Control identity ordinal.
    pub(crate) fn capture_identity_group_data(&self) -> usize {
        self.capture_identity_role.group
    }

    /// Borrows the complete independently checked immutable Hold, when retained.
    pub(crate) fn hold_data(&self) -> Option<&CurrentControlHold17Data> {
        self.complete_restored_hold.as_ref()
    }

    /// Returns the checked historical Boot, Commit and Hold evidence ordinals.
    pub(crate) fn evidence_groups_data(&self) -> Option<(usize, usize, usize)> {
        self.complete_restored_evidence
            .as_ref()
            .map(|evidence| (evidence.boot, evidence.commit, evidence.hold))
    }

    /// Returns the original process scalar without authenticating this process.
    pub(crate) fn historical_creator_data(&self) -> u32 {
        self.capture_creator
    }

    /// Borrows the original complete selection for the enclosing graph join.
    pub(crate) fn selection_data(&self) -> &PacketControlSelection {
        &self.selection
    }

    /// Borrows every original cached reply and its exact independently owned evidence.
    pub(crate) fn originals_data(&self) -> &BTreeMap<Id, (HashRef, PacketControlReply)> {
        &self.originals.0
    }

    /// Borrows complete current content, including independently retained spare banks.
    pub(crate) fn content_data(&self) -> &BTreeMap<ContentRef, Vec<u8>> {
        &self.content.0
    }

    /// Borrows every retained field for independently admitted DATA comparison.
    pub(crate) fn borrowed_current_data(&self) -> impl Serialize + '_ {
        self
    }

    /// Observes the actual inert owners without pretending to reconstruct Rc roles.
    ///
    /// # Errors
    /// Refuses exhausted observer limits or checked backing-size overflow.
    pub(crate) fn observe_owned_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&self.selection)?;
        if let Some(model) = self.model_data() {
            model.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(hold) = &self.complete_restored_hold {
            observer.observe(&hold.creator)?;
            observer.observe(&hold.cursor)?;
            observer.observe(&hold.inventory_hash)?;
        }
        observer.observe(&self.originals)?;
        observer.observe(&self.begins)?;
        observer.observe(&self.begin_requests)?;
        observer.observe(&self.content)?;
        if let Some((request, reference)) = &self.staged {
            super::restored_settled_history::observe_activate(request, observer)?;
            observer.observe(reference)?;
        }
        if let Some(request) = &self.active {
            super::restored_settled_history::observe_world_activate(request, observer)?;
        }
        observer.observe(&self.current_operation)?;
        observer.observe(&self.terminals)?;
        if let Some(installed) = &self.common_coordinator {
            observer.observe(&installed.schema)?;
            observer.observe(&installed.template)?;
        }
        if let Some(installed) = &self.world_coordinator {
            observer.observe(&installed.schema)?;
            observer.observe(&installed.participants)?;
            observer.observe(&installed.template)?;
        }
        if let Some(installed) = &self.connected_coordinator {
            observer.observe(&installed.schema)?;
            observer.observe(&installed.participants)?;
            observer.observe(&installed.host)?;
            observer.observe(&installed.template)?;
        }
        observer.observe(&self.complete_coordinator)?;
        observer.observe(&self.complete_storage)?;
        observer.observe(&self.complete_capture_profile)?;
        observer.observe(&self.complete_confirmation_selection)?;
        observer.observe(&self.complete_ack_emitter_selection)?;
        observer.observe(&self.complete_protocol_metadata_limits)?;
        observer.observe(&self.complete_protocol_metadata_birth_facts)?;
        observer.observe(&self.complete_restore_selection)?;
        observer.observe(&self.complete_restore_input_emitter_selection)?;
        observer.observe(&self.complete_capture_allocation_selection)
    }

    /// Counts this inert root and all independently retained owned backing.
    ///
    /// # Errors
    /// Refuses checked layout overflow or a total beyond the supplied ceiling.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_owned_metadata_data(&mut observer)?;
        size_of::<Self>()
            .checked_add(
                crate::retained_metadata::requested_metadata_backing_storage_data(
                    &observer.finish(),
                )?,
            )
            .filter(|bytes| *bytes <= maximum)
            .ok_or(ProviderError::ResourceExhausted(
                "current Control17 typed backing",
            ))
    }

    /// Checks local identity joins after the complete typed object is retained.
    ///
    /// # Errors
    /// Refuses evidence without Hold or different creator/Control/Hold ordinals.
    /// The enclosing graph independently compares actual Boot/Commit ordinals.
    pub(crate) fn authenticate_local_groups_data(&self) -> Result<(), ProviderError> {
        if let Some(hold) = &self.complete_restored_hold
            && (hold.capture_identity_group_data() != self.capture_identity_group_data()
                || hold.historical_creator_data() != self.capture_creator)
        {
            return Err(invalid());
        }
        if let Some(evidence) = &self.complete_restored_evidence
            && self
                .complete_restored_hold
                .as_ref()
                .is_none_or(|hold| hold.group_data() != evidence.hold)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Names current Control/Hold fields and direct parser/alias observation views.
pub(crate) fn current_control17_counter_scratch_data() -> usize {
    macro_rules! field_views {
        ($($ty:ty),+ $(,)?) => { 0usize $(
            + size_of::<Option<$ty>>()
            + size_of::<Result<Option<$ty>, ProviderError>>()
            + size_of::<Result<$ty, ProviderError>>()
            + size_of::<&$ty>()
        )+ };
    }
    let terms = [
        field_views!(
            ControlSchema17,
            PacketControlSelection,
            CurrentProgram17Data,
            Option<CurrentEvidence17Data>,
            Option<CurrentControlHold17Data>,
            bool,
            u32,
            ControlIdentity17Data,
            CurrentOriginals17Data,
            BTreeMap<Id, BeginRequest>,
            BTreeMap<Id, Id>,
            CurrentContent17Data,
            usize,
            bool,
            bool,
            Option<(ActivateRequest, ContentRef)>,
            Option<WorldActivateRequest>,
            bool,
            bool,
            bool,
            Option<Id>,
            BTreeMap<Id, Map<String, Value>>,
            Option<PacketCoordinatorInstallation>,
            Option<PacketWorldCoordinatorInstallation>,
            Option<PacketConnectedCoordinatorInstallation>,
            Option<PacketNative5CoordinatorInstallation>,
            Option<PacketNative5StorageSelection>,
            Option<PacketNative5CaptureProfile>,
            Option<PacketNative5ConfirmationSelection>,
            Option<PacketNative5AckEmitterSelection>,
            Option<PacketNative5CompleteRestoreSelection>,
            Option<PacketNative5ProtocolMetadataLimits>,
            Option<PacketNative5ProtocolMetadataBirthFacts>,
            Option<PacketNative5RestoreInputEmitterSelection>,
            Option<PacketNative5CaptureAllocationSelection>,
            HoldSchema17,
            u32,
            ThreadRole17,
            ControlIdentity17Data,
            HoldPhase17Data,
            Position,
            HashRef,
            usize,
            EvidenceSchema17,
            CurrentEvidence17Data,
            CurrentProgram17Data,
        ),
        PacketControl::settled17_root_hold_counter_scratch_data(),
        size_of::<CurrentControl17Data>(),
        size_of::<CurrentControlHold17Data>(),
        size_of::<CurrentEvidence17Data>(),
        size_of::<CurrentProgram17Data>(),
        size_of::<ControlIdentity17Data>(),
        size_of::<ControlEncoding17<'static>>(),
        size_of::<Option<&'static [u8]>>(),
        size_of::<&crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'static>>(),
        size_of::<Fields<'static>>(),
        size_of::<&mut Ledger<'static, 'static, 'static>>(),
        size_of::<Result<Option<CurrentControl17Data>, ProviderError>>(),
        size_of::<Result<Option<CurrentControlHold17Data>, ProviderError>>(),
        size_of::<Result<Option<CurrentEvidence17Data>, ProviderError>>(),
        size_of::<Result<usize, ProviderError>>(),
        size_of::<Result<(), ProviderError>>(),
        8 * size_of::<&[u8]>(),
        4 * size_of::<usize>(),
        size_of::<(usize, usize)>(),
        size_of::<Option<(usize, usize, usize)>>(),
        crate::reference_packet::continuation_models::settled_reader::settled_model17_counter_scratch_data(),
        maps::counter_scratch_data(),
    ];
    std::mem::size_of_val(&terms) + terms.into_iter().sum::<usize>()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual finite model DATA serializer fixture assertions"
)]
mod tests;

#[cfg(test)]
mod rooted_tests;

mod group_ids;
pub(crate) use group_ids::{
    CurrentControl17GroupIds, CurrentControlHold17GroupIds,
    read_current_control_hold_root17_fields_data, read_current_rooted_control17_fields_data,
};

mod retained;
pub(crate) use retained::{
    CurrentControl17ReadAttempt, CurrentControlHold17ReadAttempt,
    read_current_control_hold_root17_into_data, read_current_rooted_control17_into_data,
};

mod output_pair17;

pub(crate) use retained::preflight_current_rooted_control17_fields_data;
