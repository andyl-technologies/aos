//! Exact retained qualification replies, parsed independently of producer summaries.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use serde::Deserialize;
use serde_json::Value;

use super::{files, selection::DirectReviewSelection};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reply {
    version: u32,
    request_sha256: String,
    nonce: String,
    source_digest: String,
    script_version: String,
    observed_at_millis: WireInteger,
    result: Value,
}

pub(super) struct Captures(BTreeMap<String, Reply>);

impl Captures {
    pub(super) fn load(
        base: &Path,
        selection: &DirectReviewSelection,
        artifact: &DirectWorkerQualificationArtifact,
    ) -> Result<Self> {
        ensure!(
            !selection.capture_files.is_empty() && selection.capture_files.len() <= 4096,
            "retained qualification replies absent or excessive"
        );
        let mut replies = BTreeMap::new();
        for file in &selection.capture_files {
            let reply: Reply = files::selected_document(base, file)?;
            ensure!(
                reply.version == 1
                    && valid_direct_digest(&reply.request_sha256)
                    && valid_direct_digest(&reply.nonce)
                    && reply.source_digest == selection.source_digest
                    && reply.script_version == selection.script_version
                    && reply.observed_at_millis.get() > 0,
                "retained qualification reply identity differs"
            );
            if let Some(original) = reply.result.get("original") {
                ensure!(
                    original.get("deploymentId").and_then(Value::as_str)
                        == Some(selection.deployment_id.as_str())
                        && original.get("publicOrigin").and_then(Value::as_str)
                            == Some(selection.public_origin.as_str())
                        && original.get("sourceDigest").and_then(Value::as_str)
                            == Some(selection.source_digest.as_str())
                        && original.get("scriptVersion").and_then(Value::as_str)
                            == Some(selection.script_version.as_str()),
                    "retained qualification original audience differs"
                );
                let material = &original["material"];
                let profile = &material["profile"];
                match material["kind"].as_str() {
                    Some("managed") => {
                        let actual: DirectManagedR2Profile =
                            serde_json::from_value(profile.clone()).map_err(|_| {
                                anyhow::anyhow!("retained managed material malformed")
                            })?;
                        let policy: DirectPrivateStagePolicyRef =
                            serde_json::from_value(material["policy"].clone()).map_err(|_| {
                                anyhow::anyhow!("retained private policy malformed")
                            })?;
                        ensure!(
                            artifact.evidence.managed_profile.as_ref() == Some(&actual)
                                && artifact.evidence.private_stage_policy.as_ref() == Some(&policy),
                            "retained managed material differs from selected installed facts"
                        );
                    }
                    Some("external") => {
                        let actual: DirectExternalStorageCapabilities =
                            serde_json::from_value(profile.clone()).map_err(|_| {
                                anyhow::anyhow!("retained external material malformed")
                            })?;
                        ensure!(
                            artifact
                                .evidence
                                .external_profiles
                                .iter()
                                .any(|item| item.profile == actual),
                            "retained external material differs from selected installed facts"
                        );
                    }
                    _ => anyhow::bail!("retained qualification material kind unsupported"),
                }
            }
            ensure!(
                replies.insert(file.sha256.clone(), reply).is_none(),
                "retained qualification reply duplicated"
            );
        }
        Ok(Self(replies))
    }

    pub(super) fn result(&self, sha: &str) -> Result<&Value> {
        self.0
            .get(sha)
            .map(|reply| &reply.result)
            .ok_or_else(|| anyhow::anyhow!("retained qualification reply commitment absent"))
    }

    pub(super) fn observed_at_millis(&self, sha: &str) -> Result<u64> {
        self.0
            .get(sha)
            .map(|reply| reply.observed_at_millis.get())
            .ok_or_else(|| anyhow::anyhow!("retained qualification reply commitment absent"))
    }

    pub(super) fn receipt(
        &self,
        sha: &str,
        object: &str,
        message: Option<&str>,
    ) -> Result<(&Value, &Value)> {
        let result = self.result(sha)?;
        ensure!(
            result.get("objectId").and_then(Value::as_str) == Some(object),
            "retained proof object differs"
        );
        let closed = result
            .get("closed")
            .filter(|value| value.is_object())
            .ok_or_else(|| anyhow::anyhow!("retained positive close absent"))?;
        let attempts = result
            .get("attempts")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("retained queue attempts absent"))?;
        let mut matching = attempts
            .iter()
            .filter_map(|attempt| attempt.get("receipt"))
            .filter(|receipt| {
                receipt.is_object()
                    && message.is_none_or(|message| {
                        receipt.get("messageId").and_then(Value::as_str) == Some(message)
                    })
            });
        let receipt = matching
            .next()
            .ok_or_else(|| anyhow::anyhow!("retained positive queue receipt absent"))?;
        ensure!(
            matching.next().is_none() && receipt["verificationReplayed"] == false,
            "retained proof selection ambiguous or verification was replayed"
        );
        Ok((closed, receipt))
    }
}

pub(super) fn integer(value: &Value, field: &str) -> Result<u64> {
    let value = value
        .get(field)
        .ok_or_else(|| anyhow::anyhow!("retained numeric observation absent"))?;
    if let Some(integer) = value.as_u64() {
        return Ok(integer);
    }
    let integer: WireInteger = serde_json::from_value(value.clone())
        .map_err(|_| anyhow::anyhow!("retained numeric observation malformed"))?;
    Ok(integer.get())
}

pub(super) fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("retained identity observation absent"))
}

pub(super) fn proof(receipt: &Value, sha: &str, size: u64, proof_sha: &str) -> Result<()> {
    let proof = receipt
        .get("proof")
        .ok_or_else(|| anyhow::anyhow!("retained immutable proof absent"))?;
    ensure!(
        valid_direct_digest(sha)
            && text(proof, "sha256")? == sha
            && integer(proof, "byte_size")? == size
            && files::digest(&serde_json::to_vec(proof)?) == proof_sha,
        "retained streamed proof differs"
    );
    Ok(())
}

pub(super) fn dispatches(receipt: &Value, isolate: &str) -> Result<u64> {
    let before = &receipt["attempt"]["providerBefore"];
    let after = &receipt["providerAfter"];
    ensure!(
        text(before, "isolateId")? == isolate && text(after, "isolateId")? == isolate,
        "retained provider counters cross isolates"
    );
    integer(after, "dispatches")?
        .checked_sub(integer(before, "dispatches")?)
        .filter(|count| *count > 0)
        .ok_or_else(|| anyhow::anyhow!("retained proof has no fresh provider dispatch"))
}
