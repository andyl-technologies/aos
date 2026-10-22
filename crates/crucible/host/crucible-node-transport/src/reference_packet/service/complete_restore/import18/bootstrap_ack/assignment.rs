//! Retains closed unsigned Bootstrap18 construction before fallible validation.
//!
//! This DATA owner carries no SDK slot, live Controller, deadline or proof. The
//! defining Controller keeps it beside its genuine typed owner and original cut.
//!
//! ```text
//! unsigned = CNP/1 request, sequence "2", method "native_import18_bootstrap"
//! session_id, incarnation_id, request_id = bounded IDs
//! node_id, execution_owner_id, capture_owner_id, operation_id = null
//! body = {schema, recipe_identity: base64(32 bytes), initial_funding: {R,T,S}}
//! extensions = {}
//! ```

use super::*;
use crate::envelope::Nullable;
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use base64::Engine;
use serde_json::{Map, Value};
use std::mem::size_of;

/// Names the last entered closed assignment construction step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketNativeImport18BootstrapAssignmentStep {
    /// Installs the independently owned request body and funding map.
    Body,
    /// Installs the original unsigned Envelope with null native routing.
    Envelope,
}

/// Retains independently derived unsigned-assignment component demand.
#[derive(Clone, Copy)]
pub struct PacketNativeImport18BootstrapAssignmentRowData {
    axes: [usize; 3],
}

impl PacketNativeImport18BootstrapAssignmentRowData {
    /// Returns retained, simultaneous transient and fixed-control requested bytes.
    pub const fn requested_storage_data(self) -> [usize; 3] {
        self.axes
    }
}

/// Retains every initialized unsigned-assignment output after either outcome.
pub struct PacketNativeImport18BootstrapAssignmentData {
    row: PacketNativeImport18BootstrapAssignmentRowData,
    step: Option<PacketNativeImport18BootstrapAssignmentStep>,
    body: Option<Value>,
    funding: Option<Value>,
    encoded_recipe: Option<String>,
    original: Option<Envelope>,
    assigned: bool,
    failed: bool,
}

/// Borrows actual partial construction without supplying original authority.
pub struct PacketNativeImport18BootstrapAssignmentHistoryData<'a> {
    /// Preserves the separately admitted component quote.
    pub requested_storage: [usize; 3],
    /// Preserves the last entered construction step.
    pub step: Option<PacketNativeImport18BootstrapAssignmentStep>,
    /// Borrows the body bank, including its empty root after moving its map.
    pub body: Option<&'a Value>,
    /// Borrows the funding bank, including its empty root after moving its map.
    pub funding: Option<&'a Value>,
    /// Borrows any retained base64 construction prefix.
    pub encoded_recipe: Option<&'a String>,
    /// Borrows the actual unsigned original without publishing or signing it.
    pub original: Option<&'a Envelope>,
    /// Reports successful structural construction only.
    pub assigned: bool,
    /// Preserves a refused attempt independently of its actual outputs.
    pub failed: bool,
}

impl PacketNativeImport18BootstrapAssignmentData {
    /// Borrows every initialized field without cloning or reconstructing authority.
    pub fn borrowed_history_data(&self) -> PacketNativeImport18BootstrapAssignmentHistoryData<'_> {
        PacketNativeImport18BootstrapAssignmentHistoryData {
            requested_storage: self.row.axes,
            step: self.step,
            body: self.body.as_ref(),
            funding: self.funding.as_ref(),
            encoded_recipe: self.encoded_recipe.as_ref(),
            original: self.original.as_ref(),
            assigned: self.assigned,
            failed: self.failed,
        }
    }

    /// Counts all surviving banks with their actual capacities on either outcome.
    ///
    /// # Errors
    /// Refuses checked metadata exhaustion or unsupported backing layouts.
    pub fn retained_requested_bytes_data(&self) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_retained_into_data(&mut observer)?;
        sum(&[
            size_of::<Self>(),
            requested_metadata_backing_storage_data(&observer.finish())?,
        ])
    }

    pub(crate) fn observe_retained_into_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            row: _,
            step: _,
            body,
            funding,
            encoded_recipe,
            original,
            assigned: _,
            failed: _,
        } = self;
        observer.observe(body)?;
        observer.observe(funding)?;
        observer.observe(encoded_recipe)?;
        if let Some(original) = original {
            let Envelope {
                protocol,
                message: _,
                session_id,
                incarnation_id,
                node_id,
                execution_owner_id,
                capture_owner_id,
                request_id,
                operation_id,
                sequence: _,
                method: _,
                body,
                extensions,
            } = original;
            observer.observe(protocol)?;
            observer.observe(session_id)?;
            observer.observe(incarnation_id)?;
            observer.observe(node_id)?;
            observer.observe(execution_owner_id)?;
            observer.observe(capture_owner_id)?;
            observer.observe(request_id)?;
            observer.observe(operation_id)?;
            observer.observe(body)?;
            observer.observe(extensions)?;
        }
        Ok(())
    }
}

/// Quotes closed unsigned construction independently of opaque Recipe/Initial.
///
/// The sealed request's independently projected backing dominates the unsigned
/// body, its funding map and three cloned bounded IDs. Empty moved-from roots
/// and every typed header are retained separately in the actual owner. No raw
/// parser, canonical bank, proof, SDK or Source work is admitted by this row.
///
/// # Errors
/// Refuses checked layout overflow or derived demand exceeding the restriction.
pub fn native_import18_bootstrap_assignment_quote_data(
    maximum: usize,
) -> Result<PacketNativeImport18BootstrapAssignmentRowData, ProviderError> {
    let projection = native_import18_bootstrap_envelope_projection_data(maximum)?;
    let retained = sum(&[
        size_of::<PacketNativeImport18BootstrapAssignmentData>(),
        projection.retained_value_backing_bytes_data()[0],
    ])?;
    let transient = sum(&[
        size_of::<PacketNativeImport18BootstrapAssignmentData>(),
        size_of::<Option<PacketNativeImport18BootstrapAssignmentData>>(),
        size_of::<Envelope>(),
        size_of::<Option<Envelope>>(),
        size_of::<Value>(),
        size_of::<Option<Value>>(),
        size_of::<Map<String, Value>>(),
        size_of::<String>(),
        size_of::<Option<String>>(),
        // The base64 builder and one decimal formatter may overlap an output
        // installation. All surviving output allocations are retained above.
        43,
        20,
    ])?;
    let axes = [
        retained,
        transient,
        native_import18_bootstrap_assignment_counter_scratch_data(),
    ];
    if sum(&axes)? > maximum {
        return Err(exhausted());
    }
    Ok(PacketNativeImport18BootstrapAssignmentRowData { axes })
}

/// Retains the unsigned original before returning any later construction refusal.
///
/// `ids` borrows session, incarnation and request IDs in that order. Each output
/// ID owns a separately charged clone; inputs and their spare capacities remain
/// with the caller. This helper neither claims live origin nor spends an SDK
/// sequence. The actual Controller separately authenticates its unchanged cut.
///
/// # Errors
/// Refuses an occupied destination, short restriction, malformed request, changed
/// component row, invalid original or actual retained demand exceeding its row.
pub fn native_import18_bootstrap_assignment_into_data(
    ids: [&Id; 3],
    request: &PacketNativeImport18BootstrapRequest,
    row: &PacketNativeImport18BootstrapAssignmentRowData,
    maximum: usize,
    output: &mut Option<PacketNativeImport18BootstrapAssignmentData>,
) -> Result<(), ProviderError> {
    if output.is_some() {
        return Err(invalid());
    }
    *output = Some(PacketNativeImport18BootstrapAssignmentData {
        row: *row,
        step: None,
        body: None,
        funding: None,
        encoded_recipe: None,
        original: None,
        assigned: false,
        failed: true,
    });
    let owner = output.as_mut().ok_or_else(invalid)?;
    let result = construct(owner, ids, request, maximum);
    let retained = owner.retained_requested_bytes_data();
    result?;
    if retained? > owner.row.axes[0] {
        return Err(exhausted());
    }
    owner.assigned = true;
    owner.failed = false;
    Ok(())
}

fn construct(
    owner: &mut PacketNativeImport18BootstrapAssignmentData,
    ids: [&Id; 3],
    request: &PacketNativeImport18BootstrapRequest,
    maximum: usize,
) -> Result<(), ProviderError> {
    request.validate_data()?;
    if owner.row.axes != native_import18_bootstrap_assignment_quote_data(maximum)?.axes {
        return Err(invalid());
    }
    owner.step = Some(PacketNativeImport18BootstrapAssignmentStep::Body);
    owner.body = Some(Value::Object(Map::new()));
    owner.funding = Some(Value::Object(Map::new()));
    owner.encoded_recipe = Some(String::with_capacity(43));
    let mut encoded = [0u8; 43];
    let written = base64::engine::general_purpose::STANDARD_NO_PAD
        .encode_slice(request.recipe_identity.as_slice(), &mut encoded)
        .map_err(|_| invalid())?;
    let text = std::str::from_utf8(&encoded[..written]).map_err(|_| invalid())?;
    owner
        .encoded_recipe
        .as_mut()
        .ok_or_else(invalid)?
        .push_str(text);

    let funding = object_mut(&mut owner.funding)?;
    for (key, value) in [
        (
            "retained_requested_bytes",
            request.initial_funding.retained_requested_bytes,
        ),
        (
            "maximum_simultaneous_transient_bytes",
            request.initial_funding.maximum_simultaneous_transient_bytes,
        ),
        (
            "declared_counter_scratch_bytes",
            request.initial_funding.declared_counter_scratch_bytes,
        ),
    ] {
        funding.insert(key.into(), Value::String(value.get().to_string()));
    }
    let body = object_mut(&mut owner.body)?;
    body.insert("schema".into(), Value::String(request.schema.clone()));
    body.insert(
        "recipe_identity".into(),
        Value::String(owner.encoded_recipe.take().ok_or_else(invalid)?),
    );
    let funding = std::mem::take(object_mut(&mut owner.funding)?);
    body.insert("initial_funding".into(), Value::Object(funding));

    owner.step = Some(PacketNativeImport18BootstrapAssignmentStep::Envelope);
    let body = std::mem::take(object_mut(&mut owner.body)?);
    owner.original = Some(Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(ids[0].clone())),
        incarnation_id: Nullable(Some(ids[1].clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(ids[2].clone())),
        operation_id: Nullable(None),
        sequence: U64::new(2),
        method: Method::NativeImport18Bootstrap,
        body,
        extensions: Default::default(),
    });
    owner.original.as_ref().ok_or_else(invalid)?.validate()
}

fn object_mut(value: &mut Option<Value>) -> Result<&mut Map<String, Value>, ProviderError> {
    value
        .as_mut()
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, value| {
        total.checked_add(*value).ok_or_else(exhausted)
    })
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("bootstrap unsigned assignment storage")
}

/// Names the defining builder, projection and shallow metadata controls.
pub fn native_import18_bootstrap_assignment_counter_scratch_data() -> usize {
    native_import18_bootstrap_envelope_projection_counter_scratch_data()
        + size_of::<PacketNativeImport18BootstrapAssignmentRowData>() * 2
        + size_of::<Result<PacketNativeImport18BootstrapAssignmentRowData, ProviderError>>()
        + size_of::<&mut Option<PacketNativeImport18BootstrapAssignmentData>>()
        + size_of::<&mut PacketNativeImport18BootstrapAssignmentData>()
        + size_of::<Option<&mut PacketNativeImport18BootstrapAssignmentData>>()
        + size_of::<Result<&mut PacketNativeImport18BootstrapAssignmentData, ProviderError>>()
        + size_of::<&PacketNativeImport18BootstrapAssignmentData>()
        + size_of::<[&Id; 3]>()
        + size_of::<&PacketNativeImport18BootstrapRequest>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<[(&str, U64); 3]>()
        + size_of::<std::array::IntoIter<(&'static str, U64), 3>>()
        + size_of::<(&str, U64)>()
        + size_of::<Option<(&str, U64)>>()
        + size_of::<&mut Map<String, Value>>() * 2
        + size_of::<Result<&mut Map<String, Value>, ProviderError>>()
        + size_of::<Option<&mut Value>>()
        + size_of::<Option<&Envelope>>()
        + size_of::<Result<&Envelope, ProviderError>>()
        + size_of::<&mut String>()
        + size_of::<[u8; 20]>()
        + size_of::<[u8; 43]>()
        + size_of::<Result<usize, base64::EncodeSliceError>>()
        + size_of::<Result<&str, std::str::Utf8Error>>()
        + size_of::<&[u8]>()
        + size_of::<&str>()
        + size_of::<[usize; 8]>()
        + size_of::<[usize; 3]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 2
        + MetadataObserver::native_import18_json_metadata_frame_counter_scratch_data() * 4
}

#[cfg(test)]
#[path = "assignment/tests.rs"]
mod tests;
