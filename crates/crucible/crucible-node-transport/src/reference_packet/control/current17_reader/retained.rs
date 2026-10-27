//! Retains each completed Control field and concrete nested partial on failure.
//!
//! The outer once owner installs this attempt before reading. Nothing is reset
//! after an error; a second call refuses before consuming another source row.
//! Generic contract-child internal builders are supplied by the central native17
//! foundation; this concrete owner already retains every completed direct child.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;

mod evidence;
mod hold;
mod program;

use super::maps::retained::{CurrentContent17ReadAttempt, CurrentOriginals17ReadAttempt};
use evidence::CurrentEvidence17ReadAttempt;
pub(crate) use hold::{
    CurrentControlHold17ReadAttempt, read_current_control_hold_root17_into_data,
};

/// Owns concrete Control fields, pending map rows and the final historical DTO.
#[derive(Default)]
pub(crate) struct CurrentControl17ReadAttempt {
    started: bool,
    completed: Option<CurrentControl17Data>,
    groups: Option<CurrentControl17GroupIds>,
    hold_attempt: CurrentControlHold17ReadAttempt,
    evidence_attempt: CurrentEvidence17ReadAttempt,
    originals_attempt: CurrentOriginals17ReadAttempt,
    content_attempt: CurrentContent17ReadAttempt,
    schema: Option<ControlSchema17>,
    selection: Option<PacketControlSelection>,
    selection_attempt: <PacketControlSelection as Native17Build>::Attempt,
    program: Option<CurrentProgram17Data>,
    program_attempt: <CurrentProgram17Data as Native17Build>::Attempt,
    complete_restored_evidence: Option<Option<CurrentEvidence17Data>>,
    complete_restored_hold: Option<Option<CurrentControlHold17Data>>,
    restoration_activation_required: Option<bool>,
    capture_creator: Option<u32>,
    capture_identity_role: Option<ControlIdentity17Data>,
    originals: Option<CurrentOriginals17Data>,
    begins: Option<BTreeMap<Id, BeginRequest>>,
    begins_attempt: <BTreeMap<Id, BeginRequest> as Native17Build>::Attempt,
    begin_requests: Option<BTreeMap<Id, Id>>,
    begin_requests_attempt: <BTreeMap<Id, Id> as Native17Build>::Attempt,
    content: Option<CurrentContent17Data>,
    content_bytes: Option<usize>,
    realized: Option<bool>,
    admitted: Option<bool>,
    staged: Option<Option<(ActivateRequest, ContentRef)>>,
    staged_attempt: <Option<(ActivateRequest, ContentRef)> as Native17Build>::Attempt,
    active: Option<Option<WorldActivateRequest>>,
    active_attempt: <Option<WorldActivateRequest> as Native17Build>::Attempt,
    fenced: Option<bool>,
    native_effect_attempted: Option<bool>,
    immediate: Option<bool>,
    current_operation: Option<Option<Id>>,
    current_operation_attempt: <Option<Id> as Native17Build>::Attempt,
    terminals: Option<BTreeMap<Id, Map<String, Value>>>,
    terminals_attempt: <BTreeMap<Id, Map<String, Value>> as Native17Build>::Attempt,
    common_coordinator: Option<Option<PacketCoordinatorInstallation>>,
    common_coordinator_attempt: <Option<PacketCoordinatorInstallation> as Native17Build>::Attempt,
    world_coordinator: Option<Option<PacketWorldCoordinatorInstallation>>,
    world_coordinator_attempt:
        <Option<PacketWorldCoordinatorInstallation> as Native17Build>::Attempt,
    connected_coordinator: Option<Option<PacketConnectedCoordinatorInstallation>>,
    connected_coordinator_attempt:
        <Option<PacketConnectedCoordinatorInstallation> as Native17Build>::Attempt,
    complete_coordinator: Option<Option<PacketNative5CoordinatorInstallation>>,
    complete_coordinator_attempt:
        <Option<PacketNative5CoordinatorInstallation> as Native17Build>::Attempt,
    complete_storage: Option<Option<PacketNative5StorageSelection>>,
    complete_capture_profile: Option<Option<PacketNative5CaptureProfile>>,
    complete_confirmation_selection: Option<Option<PacketNative5ConfirmationSelection>>,
    complete_ack_emitter_selection: Option<Option<PacketNative5AckEmitterSelection>>,
    complete_restore_selection: Option<Option<PacketNative5CompleteRestoreSelection>>,
    complete_protocol_metadata_limits: Option<Option<PacketNative5ProtocolMetadataLimits>>,
    complete_protocol_metadata_birth_facts: Option<Option<PacketNative5ProtocolMetadataBirthFacts>>,
    complete_restore_input_emitter_selection:
        Option<Option<PacketNative5RestoreInputEmitterSelection>>,
    complete_capture_allocation_selection: Option<Option<PacketNative5CaptureAllocationSelection>>,
}

impl CurrentControl17ReadAttempt {
    /// Borrows the final DTO without removing it from the once owner.
    pub(crate) fn completed_data(&self) -> Option<&CurrentControl17Data> {
        self.completed.as_ref()
    }

    /// Transfers a complete DTO after the enclosing whole read has succeeded.
    pub(crate) fn take_completed_data(&mut self) -> Option<CurrentControl17Data> {
        self.completed.take()
    }

    /// Borrows a successfully retained selection even after a later read error.
    pub(crate) fn partial_selection_data(&self) -> Option<&PacketControlSelection> {
        self.selection.as_ref()
    }

    /// Borrows retained reply rows before or after their enclosing field closes.
    pub(crate) fn partial_originals_data(&self) -> &BTreeMap<Id, (HashRef, PacketControlReply)> {
        self.originals
            .as_ref()
            .map_or_else(|| self.originals_attempt.rows_data(), |value| &value.0)
    }

    /// Borrows retained content rows before or after their enclosing field closes.
    pub(crate) fn partial_content_data(&self) -> &BTreeMap<ContentRef, Vec<u8>> {
        self.content
            .as_ref()
            .map_or_else(|| self.content_attempt.rows_data(), |value| &value.0)
    }

    /// Observes every actual retained child, including unfinished nested attempts.
    ///
    /// # Errors
    /// Refuses observer exhaustion or checked retained-backing overflow.
    pub(crate) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(completed) = &self.completed {
            completed.observe_owned_metadata_data(observer)?;
        }
        if let Some(value) = &self.selection {
            <PacketControlSelection as Native17Build>::observe_output_data(value, observer)?;
        }
        <PacketControlSelection as Native17Build>::observe_attempt_data(
            &self.selection_attempt,
            observer,
        )?;
        if let Some(value) = &self.program {
            <CurrentProgram17Data as Native17Build>::observe_output_data(value, observer)?;
        }
        <CurrentProgram17Data as Native17Build>::observe_attempt_data(
            &self.program_attempt,
            observer,
        )?;
        if let Some(value) = &self.begins {
            <BTreeMap<Id, BeginRequest> as Native17Build>::observe_output_data(value, observer)?;
        }
        <BTreeMap<Id, BeginRequest> as Native17Build>::observe_attempt_data(
            &self.begins_attempt,
            observer,
        )?;
        if let Some(value) = &self.begin_requests {
            <BTreeMap<Id, Id> as Native17Build>::observe_output_data(value, observer)?;
        }
        <BTreeMap<Id, Id> as Native17Build>::observe_attempt_data(
            &self.begin_requests_attempt,
            observer,
        )?;
        if let Some(value) = &self.staged {
            <Option<(ActivateRequest, ContentRef)> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <Option<(ActivateRequest, ContentRef)> as Native17Build>::observe_attempt_data(
            &self.staged_attempt,
            observer,
        )?;
        if let Some(value) = &self.active {
            <Option<WorldActivateRequest> as Native17Build>::observe_output_data(value, observer)?;
        }
        <Option<WorldActivateRequest> as Native17Build>::observe_attempt_data(
            &self.active_attempt,
            observer,
        )?;
        if let Some(value) = &self.current_operation {
            <Option<Id> as Native17Build>::observe_output_data(value, observer)?;
        }
        <Option<Id> as Native17Build>::observe_attempt_data(
            &self.current_operation_attempt,
            observer,
        )?;
        if let Some(value) = &self.terminals {
            <BTreeMap<Id, Map<String, Value>> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <BTreeMap<Id, Map<String, Value>> as Native17Build>::observe_attempt_data(
            &self.terminals_attempt,
            observer,
        )?;
        if let Some(value) = &self.common_coordinator {
            <Option<PacketCoordinatorInstallation> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <Option<PacketCoordinatorInstallation> as Native17Build>::observe_attempt_data(
            &self.common_coordinator_attempt,
            observer,
        )?;
        if let Some(value) = &self.world_coordinator {
            <Option<PacketWorldCoordinatorInstallation> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <Option<PacketWorldCoordinatorInstallation> as Native17Build>::observe_attempt_data(
            &self.world_coordinator_attempt,
            observer,
        )?;
        if let Some(value) = &self.connected_coordinator {
            <Option<PacketConnectedCoordinatorInstallation> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <Option<PacketConnectedCoordinatorInstallation> as Native17Build>::observe_attempt_data(
            &self.connected_coordinator_attempt,
            observer,
        )?;
        if let Some(value) = &self.complete_coordinator {
            <Option<PacketNative5CoordinatorInstallation> as Native17Build>::observe_output_data(
                value, observer,
            )?;
        }
        <Option<PacketNative5CoordinatorInstallation> as Native17Build>::observe_attempt_data(
            &self.complete_coordinator_attempt,
            observer,
        )?;
        if let Some(Some(hold)) = &self.complete_restored_hold {
            observer.observe(&hold.inventory_hash)?;
        }
        self.hold_attempt.observe_attempt_data(observer)?;
        if let Some(originals) = &self.originals {
            observer.observe(originals)?;
        }
        self.originals_attempt.observe_attempt_data(observer)?;
        if let Some(content) = &self.content {
            observer.observe(content)?;
        }
        self.content_attempt.observe_attempt_data(observer)
    }

    pub(super) fn read_encoding_into(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
        encoding: ControlEncoding17<'_>,
    ) -> Result<CurrentControl17GroupIds, ProviderError> {
        if self.started {
            return Err(ProviderError::Conflict(
                "native17 Control read already attempted",
            ));
        }
        self.started = true;

        let mut fields = Fields::object(input)?;
        let schema_bytes = fields.named("schema")?;
        self.schema = match encoding {
            ControlEncoding17::Standalone => ledger.read::<ControlSchema17>(schema_bytes, build)?,
            ControlEncoding17::Rooted { .. } => {
                if plain_string(schema_bytes)? != "source-private.native-rooted-control/17" {
                    return Err(invalid());
                }
                build.then_some(ControlSchema17)
            }
        };
        read_owned_field::<PacketControlSelection>(
            fields.named("selection")?,
            ledger,
            build,
            &mut self.selection_attempt,
            &mut self.selection,
        )?;
        read_owned_field::<CurrentProgram17Data>(
            fields.named("program")?,
            ledger,
            build,
            &mut self.program_attempt,
            &mut self.program,
        )?;
        // Serialized evidence precedes Hold; observed allocation order is the
        // reverse. Keep both exact spans and finish the full Hold before refs.

        let evidence_bytes = fields.named("complete_restored_evidence")?;
        let hold_field = fields.named("complete_restored_hold")?;
        let hold_bytes = match encoding {
            ControlEncoding17::Standalone => hold_field,
            ControlEncoding17::Rooted { hold: None } if hold_field == b"null" => b"null",
            ControlEncoding17::Rooted { hold: Some(hold) }
                if plain_string(hold_field)? == "current-native-control-hold" =>
            {
                hold
            }
            ControlEncoding17::Rooted { .. } => return Err(invalid()),
        };
        let hold_group = if hold_bytes == b"null" {
            self.complete_restored_hold = build.then_some(None);
            None
        } else {
            let groups = self.hold_attempt.read_into(hold_bytes, ledger, build)?;
            if build {
                self.complete_restored_hold = Some(Some(
                    self.hold_attempt
                        .take_completed_data()
                        .ok_or_else(invalid)?,
                ));
            }
            Some(groups.hold)
        };
        let evidence_groups = if evidence_bytes == b"null" {
            self.complete_restored_evidence = build.then_some(None);
            None
        } else {
            let groups = self
                .evidence_attempt
                .read_into(evidence_bytes, ledger, build)?;
            if build {
                self.complete_restored_evidence = Some(Some(
                    self.evidence_attempt.completed.take().ok_or_else(invalid)?,
                ));
            }
            Some(groups)
        };

        self.restoration_activation_required =
            ledger.read::<bool>(fields.named("restoration_activation_required")?, build)?;
        self.capture_creator = ledger.read::<u32>(fields.named("capture_creator")?, build)?;
        let identity = ledger
            .read::<ControlIdentity17Data>(fields.named("capture_identity_role")?, true)?
            .ok_or_else(invalid)?;
        let capture_identity = identity.group;
        self.capture_identity_role = build.then_some(identity);

        self.originals_attempt
            .read_into(fields.named("originals")?, ledger, build)?;
        if build {
            self.originals = Some(
                self.originals_attempt
                    .take_completed_data()
                    .ok_or_else(invalid)?,
            );
        }
        read_owned_field::<BTreeMap<Id, BeginRequest>>(
            fields.named("begins")?,
            ledger,
            build,
            &mut self.begins_attempt,
            &mut self.begins,
        )?;
        read_owned_field::<BTreeMap<Id, Id>>(
            fields.named("begin_requests")?,
            ledger,
            build,
            &mut self.begin_requests_attempt,
            &mut self.begin_requests,
        )?;
        self.content_attempt
            .read_into(fields.named("content")?, ledger, build)?;
        if build {
            self.content = Some(
                self.content_attempt
                    .take_completed_data()
                    .ok_or_else(invalid)?,
            );
        }

        self.content_bytes = ledger.read::<usize>(fields.named("content_bytes")?, build)?;
        self.realized = ledger.read::<bool>(fields.named("realized")?, build)?;
        self.admitted = ledger.read::<bool>(fields.named("admitted")?, build)?;
        read_owned_field::<Option<(ActivateRequest, ContentRef)>>(
            fields.named("staged")?,
            ledger,
            build,
            &mut self.staged_attempt,
            &mut self.staged,
        )?;
        read_owned_field::<Option<WorldActivateRequest>>(
            fields.named("active")?,
            ledger,
            build,
            &mut self.active_attempt,
            &mut self.active,
        )?;
        self.fenced = ledger.read::<bool>(fields.named("fenced")?, build)?;
        self.native_effect_attempted =
            ledger.read::<bool>(fields.named("native_effect_attempted")?, build)?;
        self.immediate = ledger.read::<bool>(fields.named("immediate")?, build)?;
        read_owned_field::<Option<Id>>(
            fields.named("current_operation")?,
            ledger,
            build,
            &mut self.current_operation_attempt,
            &mut self.current_operation,
        )?;
        read_owned_field::<BTreeMap<Id, Map<String, Value>>>(
            fields.named("terminals")?,
            ledger,
            build,
            &mut self.terminals_attempt,
            &mut self.terminals,
        )?;

        read_owned_field::<Option<PacketCoordinatorInstallation>>(
            fields.named("common_coordinator")?,
            ledger,
            build,
            &mut self.common_coordinator_attempt,
            &mut self.common_coordinator,
        )?;
        read_owned_field::<Option<PacketWorldCoordinatorInstallation>>(
            fields.named("world_coordinator")?,
            ledger,
            build,
            &mut self.world_coordinator_attempt,
            &mut self.world_coordinator,
        )?;
        read_owned_field::<Option<PacketConnectedCoordinatorInstallation>>(
            fields.named("connected_coordinator")?,
            ledger,
            build,
            &mut self.connected_coordinator_attempt,
            &mut self.connected_coordinator,
        )?;
        read_owned_field::<Option<PacketNative5CoordinatorInstallation>>(
            fields.named("complete_coordinator")?,
            ledger,
            build,
            &mut self.complete_coordinator_attempt,
            &mut self.complete_coordinator,
        )?;
        self.complete_storage = ledger.read::<Option<PacketNative5StorageSelection>>(
            fields.named("complete_storage")?,
            build,
        )?;

        self.complete_capture_profile = ledger.read::<Option<PacketNative5CaptureProfile>>(
            fields.named("complete_capture_profile")?,
            build,
        )?;
        self.complete_confirmation_selection = ledger
            .read::<Option<PacketNative5ConfirmationSelection>>(
                fields.named("complete_confirmation_selection")?,
                build,
            )?;
        self.complete_ack_emitter_selection = ledger
            .read::<Option<PacketNative5AckEmitterSelection>>(
                fields.named("complete_ack_emitter_selection")?,
                build,
            )?;

        let restore_selection_bytes = fields.named("complete_restore_selection")?;
        self.complete_protocol_metadata_limits =
            ledger.read::<Option<PacketNative5ProtocolMetadataLimits>>(
                fields.named("complete_protocol_metadata_limits")?,
                build,
            )?;
        self.complete_protocol_metadata_birth_facts =
            ledger.read::<Option<PacketNative5ProtocolMetadataBirthFacts>>(
                fields.named("complete_protocol_metadata_birth_facts")?,
                build,
            )?;
        self.complete_restore_selection = ledger
            .read::<Option<PacketNative5CompleteRestoreSelection>>(
                restore_selection_bytes,
                build,
            )?;
        self.complete_restore_input_emitter_selection =
            ledger.read::<Option<PacketNative5RestoreInputEmitterSelection>>(
                fields.named("complete_restore_input_emitter_selection")?,
                build,
            )?;
        self.complete_capture_allocation_selection =
            ledger.read::<Option<PacketNative5CaptureAllocationSelection>>(
                fields.named("complete_capture_allocation_selection")?,
                build,
            )?;
        fields.finish()?;

        let groups = CurrentControl17GroupIds {
            capture_identity,
            hold: hold_group,
            evidence: evidence_groups,
        };
        self.groups = Some(groups);
        if !build {
            return Ok(groups);
        }
        self.finish_data()?;
        Ok(groups)
    }

    fn finish_data(&mut self) -> Result<(), ProviderError> {
        // All presence checks precede every move. No allocation, parsing or
        // correspondence operation occurs after the first field is transferred.
        if self.completed.is_some()
            || self.schema.is_none()
            || self.selection.is_none()
            || self.program.is_none()
            || self.complete_restored_evidence.is_none()
            || self.complete_restored_hold.is_none()
            || self.restoration_activation_required.is_none()
            || self.capture_creator.is_none()
            || self.capture_identity_role.is_none()
            || self.originals.is_none()
            || self.begins.is_none()
            || self.begin_requests.is_none()
            || self.content.is_none()
            || self.content_bytes.is_none()
            || self.realized.is_none()
            || self.admitted.is_none()
            || self.staged.is_none()
            || self.active.is_none()
            || self.fenced.is_none()
            || self.native_effect_attempted.is_none()
            || self.immediate.is_none()
            || self.current_operation.is_none()
            || self.terminals.is_none()
            || self.common_coordinator.is_none()
            || self.world_coordinator.is_none()
            || self.connected_coordinator.is_none()
            || self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || self.complete_capture_profile.is_none()
            || self.complete_confirmation_selection.is_none()
            || self.complete_ack_emitter_selection.is_none()
            || self.complete_restore_selection.is_none()
            || self.complete_protocol_metadata_limits.is_none()
            || self.complete_protocol_metadata_birth_facts.is_none()
            || self.complete_restore_input_emitter_selection.is_none()
            || self.complete_capture_allocation_selection.is_none()
        {
            return Err(invalid());
        }
        self.completed = Some(CurrentControl17Data {
            schema: self.schema.take().ok_or_else(invalid)?,
            selection: self.selection.take().ok_or_else(invalid)?,
            program: self.program.take().ok_or_else(invalid)?,
            complete_restored_evidence: self
                .complete_restored_evidence
                .take()
                .ok_or_else(invalid)?,
            complete_restored_hold: self.complete_restored_hold.take().ok_or_else(invalid)?,
            restoration_activation_required: self
                .restoration_activation_required
                .take()
                .ok_or_else(invalid)?,
            capture_creator: self.capture_creator.take().ok_or_else(invalid)?,
            capture_identity_role: self.capture_identity_role.take().ok_or_else(invalid)?,
            originals: self.originals.take().ok_or_else(invalid)?,
            begins: self.begins.take().ok_or_else(invalid)?,
            begin_requests: self.begin_requests.take().ok_or_else(invalid)?,
            content: self.content.take().ok_or_else(invalid)?,
            content_bytes: self.content_bytes.take().ok_or_else(invalid)?,
            realized: self.realized.take().ok_or_else(invalid)?,
            admitted: self.admitted.take().ok_or_else(invalid)?,
            staged: self.staged.take().ok_or_else(invalid)?,
            active: self.active.take().ok_or_else(invalid)?,
            fenced: self.fenced.take().ok_or_else(invalid)?,
            native_effect_attempted: self.native_effect_attempted.take().ok_or_else(invalid)?,
            immediate: self.immediate.take().ok_or_else(invalid)?,
            current_operation: self.current_operation.take().ok_or_else(invalid)?,
            terminals: self.terminals.take().ok_or_else(invalid)?,
            common_coordinator: self.common_coordinator.take().ok_or_else(invalid)?,
            world_coordinator: self.world_coordinator.take().ok_or_else(invalid)?,
            connected_coordinator: self.connected_coordinator.take().ok_or_else(invalid)?,
            complete_coordinator: self.complete_coordinator.take().ok_or_else(invalid)?,
            complete_storage: self.complete_storage.take().ok_or_else(invalid)?,
            complete_capture_profile: self.complete_capture_profile.take().ok_or_else(invalid)?,
            complete_confirmation_selection: self
                .complete_confirmation_selection
                .take()
                .ok_or_else(invalid)?,
            complete_ack_emitter_selection: self
                .complete_ack_emitter_selection
                .take()
                .ok_or_else(invalid)?,
            complete_restore_selection: self
                .complete_restore_selection
                .take()
                .ok_or_else(invalid)?,
            complete_protocol_metadata_limits: self
                .complete_protocol_metadata_limits
                .take()
                .ok_or_else(invalid)?,
            complete_protocol_metadata_birth_facts: self
                .complete_protocol_metadata_birth_facts
                .take()
                .ok_or_else(invalid)?,
            complete_restore_input_emitter_selection: self
                .complete_restore_input_emitter_selection
                .take()
                .ok_or_else(invalid)?,
            complete_capture_allocation_selection: self
                .complete_capture_allocation_selection
                .take()
                .ok_or_else(invalid)?,
        });
        Ok(())
    }
}

/// Reads rooted Control into an attempt already installed in the outer once owner.
///
/// # Errors
/// Refuses repeated attempts or malformed source/alias/capacity fields. Every
/// completed direct field and every concrete pending row remains in `attempt`.
pub(crate) fn read_current_rooted_control17_into_data(
    spans: &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    attempt: &mut CurrentControl17ReadAttempt,
) -> Result<CurrentControl17GroupIds, ProviderError> {
    attempt.read_encoding_into(
        spans.control_data(),
        ledger,
        true,
        ControlEncoding17::Rooted {
            hold: spans.hold_data(),
        },
    )
}

fn read_owned_field<T: Native17Build>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    attempt: &mut T::Attempt,
    completed: &mut Option<T>,
) -> Result<(), ProviderError> {
    if build {
        T::read_into_data(input, ledger, attempt)?;
        *completed = Some(T::take_output_data(attempt).ok_or_else(invalid)?);
        Ok(())
    } else {
        T::preflight_data(input, ledger)
    }
}

impl Native17Build for CurrentControl17Data {
    type Attempt = CurrentControl17ReadAttempt;

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        attempt
            .read_encoding_into(input, ledger, true, ControlEncoding17::Standalone)
            .map(|_| ())
    }

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut attempt = CurrentControl17ReadAttempt::default();
        attempt
            .read_encoding_into(input, ledger, false, ControlEncoding17::Standalone)
            .map(|_| ())
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        attempt.observe_attempt_data(observer)
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        value.observe_owned_metadata_data(observer)
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed_data()
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.take_completed_data()
    }
}

#[cfg(test)]
mod tests;

/// Prices rooted Control children and returns their same-pass role groups.
///
/// # Errors
/// Refuses invalid fields, metadata, target backing demand or incomplete groups.
pub(crate) fn preflight_current_rooted_control17_fields_data(
    spans: &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<CurrentControl17GroupIds, ProviderError> {
    CurrentControl17ReadAttempt::default().read_encoding_into(
        spans.control_data(),
        ledger,
        false,
        ControlEncoding17::Rooted {
            hold: spans.hold_data(),
        },
    )
}
