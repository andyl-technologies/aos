//! Exact one-shot original, namespace and positive conditional full-read joins.

use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::{
    direct_upload::direct_qualification_digest, oci_sdk_emulation::OciSdkObjectObservation,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::{
    files,
    observations::{AnchorOriginal, AnchorReceipt},
    selection::OciSdkReviewSelection,
};

pub(super) fn utc_millis(value: &str) -> Result<u64> {
    ensure!(
        value.len() == 24
            && value.is_ascii()
            && &value[4..5] == "-"
            && &value[7..8] == "-"
            && &value[10..11] == "T"
            && &value[13..14] == ":"
            && &value[16..17] == ":"
            && &value[19..20] == "."
            && &value[23..24] == "Z",
        "OCI observation UTC spelling differs"
    );
    let number = |start: usize, end: usize| -> Result<u64> {
        let digits = &value[start..end];
        ensure!(
            digits.bytes().all(|byte| byte.is_ascii_digit()),
            "OCI UTC digits malformed"
        );
        digits
            .parse()
            .map_err(|_| anyhow::anyhow!("OCI UTC digits malformed"))
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [
        31_u64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        (1970..=9999).contains(&year)
            && (1..=12).contains(&month)
            && day > 0
            && day <= months[(month - 1) as usize]
            && hour < 24
            && minute < 60
            && second < 60,
        "OCI UTC calendar value differs"
    );
    let before = |year: u64| {
        let previous = year - 1;
        previous * 365 + previous / 4 - previous / 100 + previous / 400
    };
    let days =
        before(year) - before(1970) + months[..(month - 1) as usize].iter().sum::<u64>() + day - 1;
    Ok((((days * 24 + hour) * 60 + minute) * 60 + second) * 1000 + number(20, 23)?)
}

fn decode_canonical(value: &str, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= maximum.div_ceil(3) * 4,
        "OCI retained original payload exceeds its bound"
    );
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| anyhow::anyhow!("OCI retained original encoding malformed"))?;
    ensure!(
        bytes.len() <= maximum && STANDARD.encode(&bytes) == value,
        "OCI retained original encoding differs"
    );
    Ok(bytes)
}

pub(super) fn assemble(
    base: &Path,
    selected: &OciSdkReviewSelection,
) -> Result<(OciSdkObjectObservation, String)> {
    let original: AnchorOriginal = files::document(base, &selected.anchor_original)?;
    let receipt: AnchorReceipt = files::document(base, &selected.anchor_receipt)?;
    let namespace = files::selected_bytes(base, &selected.namespace_observation)?;
    let embedded = decode_canonical(
        &original.namespace_observation_base64,
        files::DOCUMENT_LIMIT as usize,
    )?;
    let payload = decode_canonical(&original.payload_base64, 1024)?;
    let completed = utc_millis(&receipt.completed_at)?;
    let issued = original
        .issued_at
        .get()
        .checked_mul(1000)
        .ok_or_else(|| anyhow::anyhow!("OCI SDK original issue time overflows"))?;
    let expiry = original
        .expires_at
        .get()
        .checked_mul(1000)
        .ok_or_else(|| anyhow::anyhow!("OCI SDK original cutoff overflows"))?;

    ensure!(
        original.version == 1
            && receipt.version == 1
            && receipt.status == "observed"
            && original.run_id.len() == 32
            && original
                .run_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            && original.run_id == receipt.run_id
            && issued > 0
            && issued < expiry
            && expiry - issued <= 30_000
            && completed >= issued
            && completed < expiry
            && completed
                <= selected
                    .issued_at
                    .checked_mul(1000)
                    .ok_or_else(|| anyhow::anyhow!("OCI review issue overflows"))?
            && receipt.original_sha256 == selected.anchor_original.sha256
            && original.namespace_observation_sha256 == selected.namespace_observation.sha256
            && receipt.namespace_observation_sha256 == selected.namespace_observation.sha256
            && embedded == namespace.as_slice()
            && !payload.is_empty()
            && u64::try_from(payload.len())? == original.payload_byte_size.get()
            && files::digest(&payload) == original.payload_sha256
            && receipt.anchor.object.key
                == format!(".aos-oci-sdk-qualification/{}/anchor", original.run_id)
            && receipt.anchor.object.size == original.payload_byte_size.get()
            && receipt.anchor.sha256 == original.payload_sha256
            && receipt.sdk_invocations.put == 1
            && receipt.sdk_invocations.get == 1,
        "OCI SDK original, actual positive receipt or namespace differs"
    );
    receipt.anchor.validate()?;
    let commitment = direct_qualification_digest(&(
        "aos.oci-documents.anchor-create-and-conditional-read.v1",
        &selected.anchor_original.sha256,
        &selected.anchor_receipt.sha256,
        &selected.namespace_observation.sha256,
        issued,
        expiry,
        completed,
    ))?;
    Ok((receipt.anchor, commitment))
}
