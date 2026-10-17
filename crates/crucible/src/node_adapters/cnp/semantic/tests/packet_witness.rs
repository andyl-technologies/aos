//! Retains actual peer originals and observer bytes for independent review.
//!
//! This finite harness export is data only. It preserves failures and unresolved
//! responses; neither serialization nor a test label issues behavioral acceptance.

#![cfg(test)]

use std::collections::BTreeSet;
use std::io::Write;

use crucible_node_contract::*;
use crucible_node_provider::envelope::Envelope;
use serde::Serialize;
use serde_json::Value;

use super::{FRAME, Fixture, PacketControlSelection, PacketEvent};

const MAXIMUM_BYTES: usize = 32 * 1024 * 1024;
const MAXIMUM_OBJECTS: usize = 4096;

#[derive(Serialize)]
struct Original<'a> {
    request: &'a Envelope,
    identity: &'a HashRef,
    response: &'a Option<Envelope>,
}

#[derive(Serialize)]
struct Object<'a> {
    reference: &'a ContentRef,
    bytes: &'a [u8],
}

#[derive(Serialize)]
struct Record<'a> {
    schema: &'static str,
    authority: &'static str,
    case: &'a str,
    assertion_failure_in_progress: bool,
    original_pid: u32,
    measured_executable: &'a ContentRef,
    native_edition: u16,
    originals: &'a [Original<'a>],
    objects: &'a [Object<'a>],
    observed_effects: &'a [Vec<u8>],
    retained_native: Option<&'a [u8]>,
    selection: &'a PacketControlSelection,
    program: &'a [PacketEvent],
}

pub(super) fn save(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let Some(destination) = std::env::var_os("CRUCIBLE_PACKET_WITNESS_DIRECTORY") else {
        return Ok(());
    };
    let destination = std::path::PathBuf::from(destination);
    if !destination.is_dir() {
        return Err("predeclared witness directory missing".into());
    }
    let current_thread = std::thread::current();
    let case = current_thread.name().ok_or("original case name missing")?;
    let case_digest = canonical::hash("crucible.packet-case-name.v1", case.as_bytes())?;
    let originals = fixture
        .controller
        .originals()
        .map(|row| Original {
            request: &row.request,
            identity: &row.identity,
            response: &row.response,
        })
        .collect::<Vec<_>>();
    if originals.len() > 256 {
        return Err("original witness entry ceiling".into());
    }

    // Select full original dependency bodies before copying them. The measured
    // ELF is co-retained once by the outer evidence bundle, rather than copied
    // into every case report. All other referenced content must be available.
    let mut references = BTreeSet::new();
    for original in fixture.controller.originals() {
        collect_object(&original.request.body, &mut references)?;
        if let Some(response) = &original.response {
            collect_object(&response.body, &mut references)?;
        }
    }
    let objects = references
        .iter()
        .filter(|reference| *reference != fixture.controller.peer_executable())
        .map(|reference| {
            Ok(Object {
                reference,
                bytes: fixture.controller.content(reference)?,
            })
        })
        .collect::<Result<Vec<_>, crucible_node_provider::ProviderError>>()?;
    let retained_native = if fixture.bootstrap.retained_native.exists() {
        let metadata = std::fs::metadata(&fixture.bootstrap.retained_native)?;
        if metadata.len() > FRAME as u64 {
            return Err("original retained native witness ceiling".into());
        }
        Some(std::fs::read(&fixture.bootstrap.retained_native)?)
    } else {
        None
    };
    let effects = fixture.observed_effects.borrow();
    let record = Record {
        schema: "crucible.packet-original-witness.v1",
        authority: "none: original mechanism data, not an accepted class or Ready",
        case,
        assertion_failure_in_progress: std::thread::panicking(),
        original_pid: fixture.controller.peer_pid(),
        measured_executable: fixture.controller.peer_executable(),
        native_edition: if fixture.bootstrap.immediate { 2 } else { 1 },
        originals: &originals,
        objects: &objects,
        observed_effects: &effects,
        retained_native: retained_native.as_deref(),
        selection: &fixture.bootstrap.selection,
        program: &fixture.bootstrap.events,
    };
    let length =
        crate::node_adapters::cnp::semantic::budget::serialized_size(&record, MAXIMUM_BYTES)
            .map_err(|error| error.reason)?;
    let body = canonical::canonical_json(&serde_json::to_value(&record)?)?;
    if body.len() > length || body.len() > MAXIMUM_BYTES {
        return Err("full original witness body ceiling".into());
    }
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join(format!("{}.json", case_digest.digest)))?;
    output.write_all(&body)?;
    output.sync_all()?;
    Ok(())
}

fn collect_object(
    object: &serde_json::Map<String, Value>,
    references: &mut BTreeSet<ContentRef>,
) -> Result<(), Box<dyn std::error::Error>> {
    if object.contains_key("media_type")
        && object.contains_key("length")
        && object.contains_key("hash")
    {
        let reference: ContentRef = serde_json::from_value(Value::Object(object.clone()))?;
        reference.validate()?;
        if !references.contains(&reference) && references.len() == MAXIMUM_OBJECTS {
            return Err("original witness reference ceiling".into());
        }
        references.insert(reference);
    } else {
        for child in object.values() {
            collect(child, references)?;
        }
    }
    Ok(())
}

fn collect(
    value: &Value,
    references: &mut BTreeSet<ContentRef>,
) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        Value::Object(object) => collect_object(object, references)?,
        Value::Array(values) => {
            for child in values {
                collect(child, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}
