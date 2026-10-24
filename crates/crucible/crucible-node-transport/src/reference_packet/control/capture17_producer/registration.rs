//! Registers the actual Source-bearing original in a retained failed-once owner.

use super::*;

/// Borrows the real ingress fields; this DATA does not authenticate their Source.
#[derive(Clone, Copy)]
pub(crate) struct NativeCapture17RegistrationInputs<'a> {
    pub(crate) original: &'a Envelope,
    pub(crate) begin: &'a BeginRequest,
    pub(crate) arguments: &'a CaptureArguments,
    pub(crate) request: &'a PacketRestoredSettledCaptureRequest,
}

/// Binds independent new owners to one unchanged actual Control/input geometry.
pub(crate) struct NativeCapture17RegistrationStorageData {
    pub(super) owner: Rc<()>,
    pub(super) original: [u8; 32],
    pub(super) input: [u8; 32],
    pub(super) lengths: [usize; 3],
    pub(super) row: PacketNativeStartupAllocationRow,
    pub(super) hash_row: PacketNativeStartupAllocationRow,
    pub(super) request: Shape,
    pub(super) unknown: Shape,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RegistrationPhase {
    Failed,
    Registered,
}

/// Retains hash, reservation and unresolved-body partials through every refusal.
///
/// Its private constructor cannot be reached from a historical reader. Native
/// current17 serialization is inert evidence, not reconstruction of this owner.
pub(crate) struct NativeCapture17RegistrationAttempt {
    pub(super) owner: Rc<()>,
    pub(super) creator: u32,
    pub(super) original: Option<[u8; 32]>,
    pub(super) admitted: PacketNativeStartupAllocationRow,
    pub(super) hash: Option<NativePendingCapture17RequestHashAttempt>,
    pub(super) expected_binding: Option<HashRef>,
    pub(super) reservation: Option<PacketOriginalCaptureReservation>,
    pub(super) unknown_reply: Option<Map<String, Value>>,
    pub(super) phase: RegistrationPhase,
}

impl NativeCapture17RegistrationStorageData {
    /// Returns separately derived complete axes, never native spending credit.
    pub(crate) fn row_data(&self) -> PacketNativeStartupAllocationRow {
        self.row
    }

    /// Rechecks exact Control/input correspondence before any cache transition.
    /// # Errors
    /// Refuses another owner/original, changed relevant map lengths or fields.
    pub(crate) fn authenticate_data(
        &self,
        control: &PacketControl,
        input: NativeCapture17RegistrationInputs<'_>,
    ) -> Result<(), ProviderError> {
        authenticate_owner(control, &self.owner, control.capture_creator)?;
        if self.original != original_identity(input.original)?
            || self.input != input_identity(input)?
            || self.lengths
                != [
                    control.originals.len(),
                    control.begins.len(),
                    control.begin_requests.len(),
                ]
        {
            return Err(refused());
        }
        control.authenticate_capture17_registration_fields_data(input)
    }
}

impl NativeCapture17RegistrationAttempt {
    // This constructs only a failed retained destination. It carries no phase
    // permission; the private token is checked separately before any effect.
    pub(super) fn failed_data(
        control: &PacketControl,
        admitted: PacketNativeStartupAllocationRow,
    ) -> Self {
        Self {
            owner: Rc::clone(&control.capture_identity),
            creator: control.capture_creator,
            original: None,
            admitted,
            hash: None,
            expected_binding: None,
            reservation: None,
            unknown_reply: None,
            phase: RegistrationPhase::Failed,
        }
    }
}

impl PacketControl {
    // The actual native5 constructor validates immutable selection/coordinator
    // and installs complete storage once. A private same-born Control scope is
    // mandatory for effects; merely-present fields cannot create that scope.
    fn authenticate_capture17_registration_fields_data(
        &self,
        input: NativeCapture17RegistrationInputs<'_>,
    ) -> Result<(), ProviderError> {
        let NativeCapture17RegistrationInputs {
            original,
            begin,
            arguments,
            request,
        } = input;
        Self::authenticate_capture17_borrowed_fields_data(original, begin, arguments)?;
        let [binding] = self.selection.realization.bindings.as_slice() else {
            return Err(refused());
        };
        let [owner] = self.selection.realization.owner_bindings.as_slice() else {
            return Err(refused());
        };
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let operation = original.operation_id.0.as_ref().ok_or_else(refused)?;
        if self.capture_creator != std::process::id()
            || self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || self.complete_restored_hold.is_none()
            || self.complete_restored_evidence.is_none()
            || original.message != MessageKind::Request
            || original.method != Method::Begin
            || original.sequence.get() == 0
            || original.session_id.0.as_ref() != Some(&binding.authority.session_id)
            || original.incarnation_id.0.as_ref() != Some(&binding.authority.incarnation_id)
            || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
            || original.capture_owner_id.0.as_ref() != Some(&binding.compatibility.capture_owner.id)
            || original.execution_owner_id.0.is_some()
            || !begin.extensions.is_empty()
            || begin.owner_generation != binding.authority.owner_generation
            || arguments.participant_ids != owner.owner.participant_ids
            || arguments.preservation_contract.as_str()
                != crate::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE
            || request.capture != *arguments
            || request.capture_owner != binding.compatibility.capture_owner.id
            || request.capture_operation != *operation
            || request.scope.target.world != self.selection.world
            || request.scope.target.owner != owner.owner.id
            || request.scope.target.binding_hash != begin.binding_hash
            || request.scope.target.native_pid.get() != u64::from(self.capture_creator)
            || self.active.as_ref().is_none_or(|active| {
                begin.activation_id.0.as_ref() != Some(&active.activation_id)
                    || begin.world_generation != active.world_generation
                    || active.world_binding_hash != self.selection.world
            })
            || self.fenced
            || !self.immediate
            || !self.restoration_activation_required
            || self.original_physical_gate_held()?
            || self.current_operation.is_some()
            || self.originals.len() >= ORIGINALS
            || self.begins.len() >= 64
            || self.originals.contains_key(id)
            || self.begins.contains_key(operation)
            || self.begin_requests.contains_key(operation)
        {
            return Err(refused());
        }
        self.program
            .authenticate_original_capture_cut(arguments.cut)?;
        Ok(())
    }

    /// Quotes the actual new registration trees/clones before their allocation.
    ///
    /// The caller first admits `capture17_prequote_work_data` under the genuine
    /// same native occurrence. No validator or generic body decoder runs here.
    /// The full row includes a separately retained normative hash phase, all
    /// complete cloned fields and every potentially split BTree node.
    /// # Errors
    /// Refuses changed closed routing/cut, excessive encoded frame, overflow or
    /// an independently short maximum. This produces DATA only.
    pub(crate) fn quote_capture17_registration_data(
        &self,
        original: &Envelope,
        begin: &BeginRequest,
        arguments: &CaptureArguments,
        request: &PacketRestoredSettledCaptureRequest,
        maximum_frame: usize,
        maximum: usize,
    ) -> Result<NativeCapture17RegistrationStorageData, ProviderError> {
        let input = NativeCapture17RegistrationInputs {
            original,
            begin,
            arguments,
            request,
        };
        self.authenticate_capture17_registration_fields_data(input)?;
        let original_shape =
            actual_serialization_storage_data(original, Default::default(), maximum)?;
        if original_shape.maximum_encoded_bytes > maximum_frame {
            return Err(exhausted());
        }
        let begin_shape = actual_serialization_storage_data(begin, Default::default(), maximum)?;
        let arguments_shape =
            actual_serialization_storage_data(arguments, Default::default(), maximum)?;
        let mut request_shape =
            actual_serialization_storage_data(request, Default::default(), maximum)?;
        // The actual request contains exactly one32-byte custom Bytes digest.
        // Prequote separately admits its43-byte formatter before this traversal.
        request_shape.serializer_temporary_requested_bytes = 43;
        if request_shape.requested_total()? > maximum {
            return Err(exhausted());
        }
        let hash = Self::quote_pending_capture17_request_hash_data(original, maximum)?;
        let mut projection = Projection::new(maximum)?;
        super::super::observe_control_growth::unknown_capture(&mut projection)?;
        let unknown = projection.finish(maximum)?;
        let owner = self
            .selection
            .realization
            .owner_bindings
            .first()
            .ok_or_else(refused)?;
        let binding = actual_serialization_storage_data(owner, Default::default(), maximum)?;
        let inventory = self.program.quote_original_capture_inventory(maximum)?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let operation = original.operation_id.0.as_ref().ok_or_else(refused)?;
        let hash_row = hash.row_data();
        let retained = sum(&[
            size_of::<NativeCapture17RegistrationAttempt>(),
            size_of::<NativeCapture17RegistrationStorageData>(),
            size_of::<PacketOriginalCaptureReservation>(),
            backing(original)?,
            multiply(2, backing(begin)?)?,
            arguments_backing(arguments)?,
            insertion::<Id, (HashRef, PacketControlReply)>(self.originals.len())?,
            insertion::<Id, BeginRequest>(self.begins.len())?,
            insertion::<Id, Id>(self.begin_requests.len())?,
            multiply(2, id.as_str().len())?,
            multiply(3, operation.as_str().len())?,
            unknown.retained_value_backing_bytes,
            "blake3-256".len() + "cnp.owner-binding.v1".len() + 64,
            "blake3-256".len() + "cnp.request.v1".len() + 64,
            usize::try_from(hash_row.retained_requested_bytes.get()).map_err(|_| exhausted())?,
        ])?;
        let argument_validation =
            arguments
                .participant_ids
                .windows(2)
                .try_fold(0usize, |maximum, pair| {
                    Ok::<_, ProviderError>(
                        maximum.max(sum(&[pair[0].as_str().len(), pair[1].as_str().len()])?),
                    )
                })?;
        let transient = sum(&[
            original_shape.requested_total()?,
            begin_shape.requested_total()?,
            arguments_shape.requested_total()?,
            request_shape.requested_total()?,
            unknown.requested_total()?,
            binding.requested_total()?,
            inventory.requested_total()?,
            argument_validation,
            usize::try_from(hash_row.maximum_simultaneous_transient_bytes.get())
                .map_err(|_| exhausted())?,
        ])?;
        Ok(NativeCapture17RegistrationStorageData {
            owner: Rc::clone(&self.capture_identity),
            original: original_identity(original)?,
            input: input_identity(input)?,
            lengths: [
                self.originals.len(),
                self.begins.len(),
                self.begin_requests.len(),
            ],
            row: row(
                retained,
                transient,
                capture17_producer_counter_scratch_data(),
                maximum,
            )?,
            hash_row,
            request: request_shape,
            unknown,
        })
    }
}

impl NativeCapture17RegistrationAttempt {
    /// Borrows completed same-owner fields without asserting current model state.
    /// # Errors
    /// Refuses failed/incomplete registration, another Control or altered original.
    pub(crate) fn registered_data(
        &self,
        control: &PacketControl,
    ) -> Result<(&PacketOriginalCaptureReservation, &HashRef), ProviderError> {
        authenticate_owner(control, &self.owner, self.creator)?;
        if !matches!(self.phase, RegistrationPhase::Registered) {
            return Err(refused());
        }
        let reservation = self.reservation.as_ref().ok_or_else(refused)?;
        if self.original != Some(original_identity(reservation.request())?) {
            return Err(refused());
        }
        let hash = self
            .hash
            .as_ref()
            .ok_or_else(refused)?
            .completed_data(reservation.request())?;
        Ok((reservation, hash))
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<NativeCapture17RegistrationInputs<'static>>()
        + size_of::<RegistrationInputIdentity<'static>>()
        + size_of::<serde_json::Serializer<&'static mut OriginalIdentity>>()
        + size_of::<NativeCapture17RegistrationStorageData>()
        + size_of::<NativeCapture17RegistrationAttempt>()
        + size_of::<Option<NativeCapture17RegistrationAttempt>>()
        + size_of::<RegistrationPhase>()
        + size_of::<Result<NativeCapture17RegistrationStorageData, ProviderError>>()
        + size_of::<Result<(&PacketOriginalCaptureReservation, &HashRef), ProviderError>>()
        + size_of::<[usize; 15]>()
        + size_of::<[usize; 9]>()
        + size_of::<std::slice::Windows<'static, Id>>()
        + size_of::<&[Id]>()
        + size_of::<[usize; 2]>()
        + size_of::<usize>()
        + size_of::<[usize; 3]>()
        + size_of::<HashRef>()
        + size_of::<PacketOriginalCaptureReservation>()
        + size_of::<NativePendingCapture17RequestHashStorageData<'static>>()
        + size_of::<Result<NativePendingCapture17RequestHashStorageData<'static>, ProviderError>>()
        + size_of::<&BeginRequest>()
        + size_of::<&CaptureArguments>()
        + size_of::<&PacketRestoredSettledCaptureRequest>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<ResponseShape>()
        + size_of::<Result<HashRef, ContractError>>()
}

#[derive(Serialize)]
struct RegistrationInputIdentity<'a> {
    original: &'a Envelope,
    begin: &'a BeginRequest,
    arguments: &'a CaptureArguments,
    request: &'a PacketRestoredSettledCaptureRequest,
}

fn input_identity(input: NativeCapture17RegistrationInputs<'_>) -> Result<[u8; 32], ProviderError> {
    let mut sink = OriginalIdentity(blake3::Hasher::new_derive_key(
        "source-private.native-capture-registration-input/17",
    ));
    serde_json::to_writer(
        &mut sink,
        &RegistrationInputIdentity {
            original: input.original,
            begin: input.begin,
            arguments: input.arguments,
            request: input.request,
        },
    )
    .map_err(|_| refused())?;
    Ok(*sink.0.finalize().as_bytes())
}
