//! Retains the real Capture result before settling the two actual Control caches.

use super::*;

pub(crate) struct NativeCapture17TerminalStorageData {
    pub(super) owner: Rc<()>,
    pub(super) original: [u8; 32],
    pub(super) terminals: usize,
    pub(super) row: PacketNativeStartupAllocationRow,
    pub(super) body: Shape,
    pub(super) envelope: Shape,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReplyPhase {
    Failed,
    Produced,
    Settled,
}

/// Keeps all typed reference and reply partials in the actual native occurrence.
pub(crate) struct NativeCapture17ReplyAttempt {
    pub(super) owner: Rc<()>,
    pub(super) creator: u32,
    pub(super) original: Option<[u8; 32]>,
    pub(super) admitted: PacketNativeStartupAllocationRow,
    pub(super) snapshot: Option<ContentRef>,
    pub(super) control: Option<ContentRef>,
    pub(super) anchor: Option<ContentRef>,
    pub(super) body: Option<Map<String, Value>>,
    pub(super) phase: ReplyPhase,
}

#[derive(Serialize)]
pub(super) struct CaptureResult17<'a> {
    pub(super) capture_manifest: &'a ContentRef,
    pub(super) owner_state_refs: [&'a ContentRef; 1],
    pub(super) unchanged_cut_receipt: &'a ContentRef,
}

#[derive(Serialize)]
pub(super) struct CaptureCompleted17<'a> {
    pub(super) status: &'static str,
    pub(super) operation_state: OperationState,
    pub(super) result: CaptureResult17<'a>,
    pub(super) extensions: Extensions,
}

pub(super) fn project_body(out: &mut Projection) -> Result<(), ProviderError> {
    project_object(out, &["status", "operation_state", "result", "extensions"])?;
    out.add_string("completed")?;
    out.add_value(&OperationState::Completed)?;
    project_object(
        out,
        &[
            "capture_manifest",
            "owner_state_refs",
            "unchanged_cut_receipt",
        ],
    )?;
    project_reference(out)?;
    out.add_array_extent(1)?;
    project_reference(out)?;
    project_reference(out)?;
    out.add_object()
}

fn project_terminal(original: &Envelope, maximum: usize) -> Result<Shape, ProviderError> {
    let mut out = Projection::new(maximum)?;
    project_terminal_header(&mut out, original)?;
    project_body(&mut out)?;
    out.add_object()?;
    out.finish(maximum)
}

impl NativeCapture17TerminalStorageData {
    pub(crate) fn row_data(&self) -> PacketNativeStartupAllocationRow {
        self.row
    }
    pub(crate) fn body_data(&self) -> &Shape {
        &self.body
    }
    pub(crate) fn envelope_data(&self) -> &Shape {
        &self.envelope
    }

    /// Checks the exact private Control/original and prospective terminal cache.
    /// # Errors
    /// Refuses another Control, changed full original or terminal-tree growth.
    pub(crate) fn authenticate_data(
        &self,
        control: &PacketControl,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        authenticate_owner(control, &self.owner, control.capture_creator)?;
        if self.original != original_identity(original)?
            || self.terminals != control.terminals.len()
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl NativeCapture17ReplyAttempt {
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
            admitted: admitted,
            snapshot: None,
            control: None,
            anchor: None,
            body: None,
            phase: ReplyPhase::Failed,
        }
    }
}

impl PacketControl {
    /// Quotes producer/cache owners separately from parent terminal and transport.
    ///
    /// This projects three complete body banks: retained producer, original
    /// reply cache and operation terminal cache. Parent prepared reply and full
    /// terminal Envelope/transport copies require their own independent rows.
    /// # Errors
    /// Refuses malformed baseline Capture IDs, an existing operation terminal,
    /// unsupported message/method or a short independently funded maximum.
    pub(crate) fn quote_capture17_terminal_data(
        &self,
        original: &Envelope,
        maximum: usize,
    ) -> Result<NativeCapture17TerminalStorageData, ProviderError> {
        let operation = original.operation_id.0.as_ref().ok_or_else(refused)?;
        if original.message != MessageKind::Request
            || original.method != Method::Begin
            || original.request_id.0.is_none()
            || self.terminals.contains_key(operation)
        {
            return Err(refused());
        }
        let mut out = Projection::new(maximum)?;
        project_body(&mut out)?;
        let body = out.finish(maximum)?;
        let envelope = project_terminal(original, maximum)?;
        let retained = sum(&[
            size_of::<NativeCapture17TerminalStorageData>(),
            size_of::<NativeCapture17ReplyAttempt>(),
            multiply(3, body.retained_value_backing_bytes)?,
            insertion::<Id, Map<String, Value>>(self.terminals.len())?,
            operation.as_str().len(),
            multiply(
                3,
                "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len(),
            )?,
        ])?;
        let priced = row(
            retained,
            sum(&[body.requested_total()?, envelope.requested_total()?])?,
            capture17_producer_counter_scratch_data(),
            maximum,
        )?;
        Ok(NativeCapture17TerminalStorageData {
            owner: Rc::clone(&self.capture_identity),
            original: original_identity(original)?,
            terminals: self.terminals.len(),
            row: priced,
            body,
            envelope,
        })
    }
}

impl NativeCapture17ReplyAttempt {
    /// Borrows a real completed producer body, never a publication witness.
    /// # Errors
    /// Refuses failed/partial production or absent retained DOM.
    pub(crate) fn body_data(&self) -> Result<&Map<String, Value>, ProviderError> {
        if !matches!(self.phase, ReplyPhase::Produced | ReplyPhase::Settled) {
            return Err(refused());
        }
        self.body.as_ref().ok_or_else(refused)
    }

    /// Rechecks private producer identity and its actual output tuple.
    /// # Errors
    /// Refuses failed/partial fields, foreign Control or another original.
    pub(crate) fn authenticate_data(
        &self,
        control: &PacketControl,
        registration: &NativeCapture17RegistrationAttempt,
    ) -> Result<(), ProviderError> {
        authenticate_owner(control, &self.owner, self.creator)?;
        let (reservation, _) = registration.registered_data(control)?;
        if self.original != Some(original_identity(reservation.request())?)
            || self.snapshot.is_none()
            || self.control.is_none()
            || self.anchor.is_none()
        {
            return Err(refused());
        }
        self.body_data()?;
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<NativeCapture17TerminalStorageData>()
        + size_of::<NativeCapture17ReplyAttempt>()
        + size_of::<Option<NativeCapture17ReplyAttempt>>()
        + size_of::<ReplyPhase>()
        + size_of::<CaptureCompleted17<'static>>()
        + size_of::<CaptureResult17<'static>>()
        + size_of::<Result<NativeCapture17TerminalStorageData, ProviderError>>()
        + size_of::<Result<&Map<String, Value>, ProviderError>>()
        + size_of::<[&ContentRef; 3]>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 2]>()
        + size_of::<Result<Value, serde_json::Error>>()
}
