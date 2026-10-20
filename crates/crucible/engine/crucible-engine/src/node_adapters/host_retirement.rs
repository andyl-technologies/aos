//! Reads complete retained original Host history for operational failure custody.
//!
//! This closed format is not a Host native continuation edition. Its original
//! model, COW, pending state and preparation bytes remain owned by the same node
//! before and after graceful reclamation. It grants no restoration or release.
//!
//! ```text
//! host-failure-history.1 = binding + route + original model envelope +
//!   initial model + original preparation + Ready + original failed requests
//! ```

use serde::{Serialize, ser::SerializeSeq};

use super::*;

#[derive(Serialize)]
struct ClockPreparation<'a> {
    token: &'a Id,
    session: &'a ContentRef,
    session_bytes: &'a [u8],
    native_ready: &'a ContentRef,
    native_ready_bytes: &'a [u8],
    ready: Option<(
        crate::node_contract::RetirementActivation<'a>,
        &'a ReadyAttestation,
        &'a [u8],
    )>,
    history: &'a [crate::node_scheduling::InputPayload],
}

#[derive(Serialize)]
struct History<'a> {
    format: &'static str,
    version: u16,
    world: &'a HashRef,
    binding: &'a NodeBinding,
    route: &'a NodeRoute,
    initial: &'a [u8],
    native: &'a [u8],
    ready: Option<(
        crate::node_contract::RetirementActivation<'a>,
        &'a ReadyAttestation,
    )>,
    clock: Option<ClockPreparation<'a>>,
    model: Option<owned_preparation::RetirementPreparation<'a>>,
    failures: Failures<'a>,
}

struct Failures<'a>(&'a BTreeMap<Id, (OperationAdmission, OperationFailure)>);

impl Serialize for Failures<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (operation, (admission, failure)) in self.0 {
            sequence.serialize_element(&(operation, admission.request(), failure))?;
        }
        sequence.end()
    }
}

pub(super) fn history(
    node: &HostModelNode,
    maximum: usize,
) -> Result<(ContentRef, Vec<u8>), OperationFailure> {
    let maximum = maximum.min(node.limits.maximum_capture_bytes);
    let model = match (&node.model, &node.retired_model) {
        (Some(model), None) | (None, Some(model)) => model,
        _ => {
            return Err(failure(
                "original Host retirement model custody is ambiguous",
            ));
        }
    };
    let supported = matches!(model, HostModel::Clock(_) | HostModel::ScriptedSource(_))
        || matches!(model, HostModel::Io(io) if io.block_device().is_some());
    if !supported
        || node.recorded_ingress.is_some()
        || node.condition_preservation
        || node.preparation_origin != HostPreparationOrigin::Original
        || node.public_model_history.is_some()
    {
        return Err(failure(
            "Host failure history requires the selected original source",
        ));
    }
    let clock =
        node.public_preparation
            .as_ref()
            .map(|original| {
                if original.previous.is_some() {
                    return Err(failure("inherited Clock failure history is unsupported"));
                }
                original
                    .session
                    .verify(&original.session_bytes)
                    .map_err(|error| failure(&error.to_string()))?;
                original
                    .native_ready
                    .verify(&original.native_ready_bytes)
                    .map_err(|error| failure(&error.to_string()))?;
                if let Some((_, ready, bytes)) = &original.ready {
                    ready
                        .ready_receipt
                        .verify(bytes)
                        .map_err(|error| failure(&error.to_string()))?;
                }
                for payload in &original.history {
                    payload
                        .reference
                        .verify(&payload.bytes)
                        .map_err(|error| failure(&error.to_string()))?;
                }
                Ok(ClockPreparation {
                    token: &original.token,
                    session: &original.session,
                    session_bytes: &original.session_bytes,
                    native_ready: &original.native_ready,
                    native_ready_bytes: &original.native_ready_bytes,
                    ready: original.ready.as_ref().map(|(activation, ready, bytes)| {
                        (activation.into(), ready, bytes.as_slice())
                    }),
                    history: &original.history,
                })
            })
            .transpose()?;
    let prepared_model = node
        .public_model_preparation
        .as_ref()
        .map(|original| original.retirement_record(node.initial.as_slice()))
        .transpose()?;
    if clock.is_some() == prepared_model.is_some() {
        return Err(failure(
            "complete original Host preparation history is absent or ambiguous",
        ));
    }

    // The model codec has its existing selected ceiling. This retained-body
    // count precedes outer serialization; temporary model codec allocation is
    // bounded separately and is not claimed as allocator-wide peak accounting.
    let native = state::retirement_native(node, model, maximum)?;
    let history = History {
        format: "crucible.host-failure-history",
        version: 1,
        world: &node.world_hash,
        binding: &node.binding,
        route: &node.route,
        initial: node.initial.as_slice(),
        native: &native,
        ready: node
            .readiness
            .as_ref()
            .map(|(activation, ready)| (activation.into(), ready)),
        clock,
        model: prepared_model,
        failures: Failures(&node.failed),
    };
    let mut counter = Credit(maximum);
    serde_json::to_writer(&mut counter, &history).map_err(|error| failure(&error.to_string()))?;
    let bytes = state::bounded_bytes(&history, maximum)?;
    let reference = canonical::content_ref(&bytes, "application/json")
        .map_err(|error| failure(&error.to_string()))?;
    Ok((reference, bytes))
}

struct Credit(usize);

impl std::io::Write for Credit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("Host failure history credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
