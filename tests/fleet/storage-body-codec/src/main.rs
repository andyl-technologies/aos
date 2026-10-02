//! Bounded observations of Copy controls and Native OCI Distribution bodies.
//!
//! This fixture codec cannot authenticate a MAC, authorize an actor, dispatch
//! provider work or assess Native bulk zero. Actual accepted-handler, source,
//! purpose, SQL and provider observations must be joined independently.

mod classify;
mod controls;
mod copy_request;
mod files;
mod ingress;
mod storage_work;

#[cfg(test)]
mod tests;

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use files::BodyFile;

const MAX_CASES: usize = 4096;
const MAX_CORPUS_BYTES: usize = 512 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    version: u32,
    source_digest: String,
    deployment_id: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Case {
    request_id: String,
    method: String,
    path_and_query: String,
    phase: Option<String>,
    status: u16,
    response_content_type: Option<String>,
    response_content_encoding: Option<String>,
    original_request: BodyFile,
    received_request: BodyFile,
    received_reply: BodyFile,
    original_ingress: Option<BodyFile>,
    received_ingress: Option<BodyFile>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    request_id: String,
    source_digest: String,
    request_sha256: String,
    reply_sha256: String,
    codec_source_sha256: String,
    exchange_id_sha256: String,
    original_context_sha256: String,
    operation: &'static str,
    class: &'static str,
    payload: Payload,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    request_raw_object_bytes: String,
    reply_raw_object_bytes: String,
    selected_data_bytes: String,
    semantic_oci_projection_bytes: String,
}

impl Payload {
    fn metadata() -> Self {
        Self {
            request_raw_object_bytes: "0".into(),
            reply_raw_object_bytes: "0".into(),
            selected_data_bytes: "0".into(),
            semantic_oci_projection_bytes: "0".into(),
        }
    }
}

fn inspect(manifest: Manifest) -> Result<Vec<Observation>> {
    ensure!(manifest.version == 1, "unsupported manifest version");
    ensure!(
        files::valid_digest(&manifest.source_digest),
        "invalid source"
    );
    ensure!(
        !manifest.cases.is_empty() && manifest.cases.len() <= MAX_CASES,
        "empty or excessive observation selection"
    );
    let mut identifiers = std::collections::BTreeSet::new();
    let mut consumed = 0usize;
    let mut observations = Vec::with_capacity(manifest.cases.len());

    for case in manifest.cases {
        ensure!(
            !case.request_id.is_empty()
                && case.request_id.len() <= 128
                && !case.request_id.chars().any(char::is_control)
                && identifiers.insert(case.request_id.clone()),
            "invalid or duplicate observation identity"
        );
        ensure!(
            case.response_content_encoding
                .as_deref()
                .is_none_or(|encoding| encoding.is_empty() || encoding == "identity"),
            "encoded bodies remain unsupported"
        );
        let original = files::read(&case.original_request, &mut consumed)?;
        let request = files::read(&case.received_request, &mut consumed)?;
        let reply = files::read(&case.received_reply, &mut consumed)?;
        ensure!(original == request, "original and received requests differ");
        observations.push(classify::classify(
            &case,
            &request,
            &reply,
            &manifest.source_digest,
            &manifest.deployment_id,
            &mut consumed,
        )?);
    }
    Ok(observations)
}

fn main() {
    let result = (|| -> Result<()> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() == 3 && args[1] == "copy-request" {
            let selection = files::read_manifest(std::path::Path::new(&args[2]))?;
            let observation = copy_request::inspect(serde_json::from_slice(&selection)?)?;
            println!("{}", serde_json::to_string(&observation)?);
            return Ok(());
        }
        ensure!(args.len() == 2, "expected one private selection file");
        let manifest = files::read_manifest(std::path::Path::new(&args[1]))?;
        let observations = inspect(serde_json::from_slice(&manifest)?)?;
        println!("{}", serde_json::to_string(&observations)?);
        Ok(())
    })();
    if result.is_err() {
        // Decoder error chains can contain private field values or paths.
        eprintln!("storage body observation refused");
        std::process::exit(1);
    }
}
