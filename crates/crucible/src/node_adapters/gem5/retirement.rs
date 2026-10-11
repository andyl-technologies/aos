//! Retains complete original common gem5 history alongside native first attempts.
//!
//! This effect-free operational codec preserves original request scopes,
//! prefixes, result uncertainty, publication evidence and private ACK bytes.
//! It is distinct from every gem5 continuation format and grants no release.
//!
//! ```text
//! common-history.1 = actual binding/route/Ready + original requests/scopes +
//!   completed prefixes + outcomes/failures + retained full-CF bodies
//! ```

use serde::{Serialize, ser::SerializeSeq};

use super::*;
use crate::{node_contract::*, node_scheduling::InputPayload};

const NATIVE_BYTES: usize = 64 * 1024 * 1024;
const ACK_BYTES: usize = 65_536 * (2 * 516 + 128 + 9) + 64;

#[derive(Serialize)]
struct History<'a> {
    format: &'static str,
    version: u16,
    binding: &'a NodeBinding,
    route: &'a NodeRoute,
    world: Option<(RetirementActivation<'a>, &'a ReadyAttestation)>,
    prepared: Option<PreparedMapping<'a>>,
    authority: (&'a crucible_node_contract::ContentRef, &'a [u8]),
    operations: Operations<'a>,
    standalone: Standalone<'a>,
}

#[derive(Serialize)]
struct PreparedMapping<'a> {
    world: RetirementActivation<'a>,
    ready: &'a ReadyAttestation,
    owners: &'a [crucible_node_contract::PreparedOwner],
    original_session: &'a crucible_node_contract::ContentRef,
    original_packet: &'a crucible_node_contract::ContentRef,
}

struct Operations<'a>(&'a ledger::OperationLedger);

impl Serialize for Operations<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.operations().len()))?;
        for (operation, original) in self.0.operations() {
            sequence.serialize_element(&(
                operation,
                RetirementActivation::from(original.original.activation().record()),
                original.original.token().route(),
                original.original.request(),
                &original.prefixes,
                &original.prefix_scopes,
                &original.outcome,
                &original.evidence,
                original.acknowledged,
                &original.failure,
            ))?;
        }
        sequence.end()
    }
}

struct Standalone<'a>(&'a ledger::OperationLedger);

impl Serialize for Standalone<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.standalone().len()))?;
        for object in self.0.standalone() {
            sequence.serialize_element(object)?;
        }
        sequence.end()
    }
}

pub(super) fn history(
    node: &QualifiedGem5Node,
    maximum: usize,
) -> Result<Vec<InputPayload>, OperationFailure> {
    if maximum == 0
        || maximum > NATIVE_BYTES + ACK_BYTES
        || node.restored.is_some()
        || !node.public_preparation
        || node.prepared_mapping.is_none()
    {
        return Err(refusal(
            "original gem5 retirement history selection differs",
        ));
    }
    let authority = node.authority.evidence();
    authority
        .0
        .verify(authority.1)
        .map_err(|error| refusal(&error.to_string()))?;
    for (_, operation) in node.ledger.operations() {
        for object in &operation.evidence {
            object
                .reference
                .verify(&object.bytes)
                .map_err(|error| refusal(&error.to_string()))?;
        }
    }
    for object in node.ledger.standalone() {
        object
            .reference
            .verify(&object.bytes)
            .map_err(|error| refusal(&error.to_string()))?;
    }
    let history = History {
        format: "crucible.gem5.retirement-common-history",
        version: 1,
        binding: &node.preparation.binding,
        route: &node.preparation.route,
        world: node
            .world
            .as_ref()
            .map(|(activation, ready)| (activation.into(), ready)),
        prepared: node
            .prepared_mapping
            .as_ref()
            .map(|original| PreparedMapping {
                world: (&original.world).into(),
                ready: &original.ready,
                owners: &original.owners,
                original_session: &original.original_session,
                original_packet: &original.original_packet,
            }),
        authority,
        operations: Operations(&node.ledger),
        standalone: Standalone(&node.ledger),
    };
    let mut counter = Credit {
        remaining: NATIVE_BYTES.min(maximum),
    };
    serde_json::to_writer(&mut counter, &history).map_err(|error| refusal(&error.to_string()))?;
    let common_length = NATIVE_BYTES.min(maximum) - counter.remaining;
    let native_credit = NATIVE_BYTES
        .checked_sub(common_length)
        .ok_or_else(|| refusal("original combined native history credit exhausted"))?;
    let ack_credit = maximum
        .checked_sub(common_length + native_credit)
        .ok_or_else(|| refusal("original private ACK history credit exhausted"))?
        .min(ACK_BYTES);
    // Native/common history share their unchanged 64MiB ceiling. Private ACK
    // first-attempt bytes consume their separately prebirth-authenticated credit.
    let original = node
        .preparation
        .native
        .retirement_history_records(native_credit, ack_credit)
        .map_err(|error| refusal(&error.to_string()))?;
    let bytes = serde_json::to_vec(&history).map_err(|error| refusal(&error.to_string()))?;
    let reference = crucible_node_contract::canonical::content_ref(&bytes, "application/json")
        .map_err(|error| refusal(&error.to_string()))?;
    let mut bodies = Vec::new();
    bodies
        .try_reserve_exact(3)
        .map_err(|_| refusal("original gem5 history holder allocation"))?;
    bodies.push(InputPayload { reference, bytes });
    for (reference, bytes) in original {
        bodies.push(InputPayload { reference, bytes });
    }
    Ok(bodies)
}

struct Credit {
    remaining: usize,
}

impl std::io::Write for Credit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("original gem5 history credit exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
