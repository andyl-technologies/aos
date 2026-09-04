//! Measured-boot PCR policy construction and public-key verification.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::canonical;
use aos_release::digest::Sha256Digest;
use aos_release::signing::{
    SignatureAlgorithm, SignatureResponseV1, SignerRole, SigningContext, SigningOperation,
    verify_response_binding,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::assembly::UnsignedImageAssemblyV1;
use crate::input::digest_regular_file;
use crate::request::{ImageRequestAuthorizer, ImageSigningIntent, verify_intent};
use crate::signer::ImageSigner;
use crate::tools::{PinnedTool, arguments};

const MAX_MEASURE_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_PCR_SIGNATURE_BYTES: u64 = 1024 * 1024;
const MAX_ONE_SIGNATURE_BYTES: usize = 64 * 1024;
const READY_PHASE: &str = "enter-initrd:leave-initrd:sysinit:ready";

/// Exact files measured into a normal UKI's PCR 11 policy.
pub struct PcrSections<'a> {
    /// Linux kernel section.
    pub linux: &'a Path,
    /// UKI os-release section.
    pub osrel: &'a Path,
    /// Slot-specific kernel command line.
    pub cmdline: &'a Path,
    /// Rebuilt normal initrd.
    pub initrd: &'a Path,
    /// Explicit AOS SBAT policy.
    pub sbat: &'a Path,
    /// Captured PCR public key embedded in the UKI.
    pub pcrpkey: &'a Path,
}

/// Signed `.pcrsig` plus independently derived ready-phase PCR 11.
#[derive(Debug)]
pub struct SignedPcrPolicyV1 {
    /// Canonical unsigned TPM policy-digest document sent to the provider.
    pub unsigned_policy: PathBuf,
    /// Canonical signed policy JSON embedded in the final UKI.
    pub signed_policy: PathBuf,
    /// Ready-phase expected PCR 11, serialized as `sha256:<hex>`.
    pub expected_ready_pcr11: Sha256Digest,
    /// Audited external provider response.
    pub signing_operation: SignatureResponseV1,
}

/// Signed ready-phase PCR evidence for one finalized normal UKI.
#[derive(Debug)]
pub struct UkiMeasurementV1 {
    /// Stable line-oriented measurement document consumed by runtime import.
    pub measurement: PathBuf,
    /// Raw SHA-256 signature over the measurement document.
    pub signature: PathBuf,
    /// Audited detached-signature provider response.
    pub signing_operation: SignatureResponseV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    sha256: Vec<PolicyRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyRecord {
    pcrs: Vec<u8>,
    pol: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedPolicyDocument {
    sha256: Vec<SignedPolicyRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedPolicyRecord {
    pcrs: Vec<u8>,
    pkfp: String,
    pol: String,
    sig: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalculationDocument {
    sha256: Vec<CalculationRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalculationRecord {
    phase: String,
    pcr: u8,
    hash: String,
}

/// Calculates PCR state, requests signatures, and verifies every signed policy.
///
/// # Errors
///
/// Returns an error for malformed/ambiguous measurement output, unauthorized
/// signer intent, response drift, policy-set changes, public-key mismatch, or
/// any invalid cryptographic signature.
pub async fn sign_pcr_policy(
    assembly: &UnsignedImageAssemblyV1,
    sections: &PcrSections<'_>,
    scratch: &Path,
    systemd_measure: &PinnedTool,
    openssl: &PinnedTool,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
) -> Result<SignedPcrPolicyV1> {
    fs::create_dir(scratch)?;
    let section_arguments = measure_arguments(sections)?;
    let mut calculation_arguments = arguments(["calculate", "--bank=sha256", "--json=short"]);
    calculation_arguments.extend(section_arguments.iter().cloned());
    let calculation = systemd_measure
        .run(calculation_arguments, MAX_MEASURE_OUTPUT_BYTES)
        .await?;
    let calculation: CalculationDocument =
        serde_json::from_slice(&calculation.stdout).context("parsing PCR calculation JSON")?;
    let expected_ready_pcr11 = ready_pcr11(&calculation)?;

    let mut policy_arguments = arguments(["policy-digest", "--bank=sha256", "--json=short"]);
    policy_arguments.extend(section_arguments);
    let policy = systemd_measure
        .run(policy_arguments, MAX_MEASURE_OUTPUT_BYTES)
        .await?;
    let policy: PolicyDocument =
        serde_json::from_slice(&policy.stdout).context("parsing PCR policy-digest JSON")?;
    validate_policy(&policy)?;
    let unsigned_policy = scratch.join("pcr-policy.json");
    fs::write(&unsigned_policy, canonical::to_vec(&policy)?)?;
    let (_, payload_digest) = digest_regular_file(&unsigned_policy)?;
    let intent = ImageSigningIntent {
        assembly_policy_id: &assembly.signer_roles.pcr,
        role: SignerRole::PcrPolicy,
        algorithm: SignatureAlgorithm::PcrPolicy,
        operation: SigningOperation::SignPcrPolicy,
        context: SigningContext::PcrPolicy {
            platform: assembly.platform,
            system_variant: assembly.system_variant.clone(),
            pcrs: vec![11],
        },
        payload_digest,
    };
    let request = authorizer.authorize(&intent)?;
    verify_intent(&request, &intent)?;
    let signed_policy = scratch.join("pcr-signature.json");
    let response = signer
        .transform(
            &request,
            &unsigned_policy,
            &signed_policy,
            MAX_PCR_SIGNATURE_BYTES,
        )
        .await?;
    verify_response_binding(&request, &response)?;
    let (_, signed_digest) = digest_regular_file(&signed_policy)?;
    let (_, public_key_digest) = digest_regular_file(sections.pcrpkey)?;
    if response.output_digest != Some(signed_digest)
        || response.verification_material_digest != public_key_digest
    {
        bail!("PCR signer response differs from signed bytes or public key");
    }
    let signed_bytes = fs::read(&signed_policy)?;
    canonical::require_canonical(&signed_bytes, "signed PCR policy")?;
    let signed: SignedPolicyDocument = canonical::from_slice(&signed_bytes, "signed PCR policy")?;
    verify_signed_policy(&policy, &signed, sections.pcrpkey, scratch, openssl).await?;
    Ok(SignedPcrPolicyV1 {
        unsigned_policy,
        signed_policy,
        expected_ready_pcr11,
        signing_operation: response,
    })
}

/// Signs a finalized UKI's exact digest and ready-phase PCR 11 prediction.
///
/// # Errors
///
/// Returns an error for an unauthorized request, malformed provider response,
/// public-key mismatch, invalid signature, or an existing output.
#[allow(clippy::too_many_arguments)]
pub async fn sign_uki_measurement(
    assembly: &UnsignedImageAssemblyV1,
    finalized_uki: &Path,
    expected_ready_pcr11: Sha256Digest,
    pcr_public_key: &Path,
    scratch: &Path,
    openssl: &PinnedTool,
    signer: &dyn ImageSigner,
    authorizer: &dyn ImageRequestAuthorizer,
) -> Result<UkiMeasurementV1> {
    let measurement = scratch.join("uki.measurement");
    let signature = scratch.join("uki.measurement.sig");
    let (_, uki_digest) = digest_regular_file(finalized_uki)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&measurement)?;
    writeln!(file, "aos.uki-measurement/v1")?;
    writeln!(file, "uki_sha256={}", uki_digest.hex())?;
    writeln!(file, "expected_pcr11={expected_ready_pcr11}")?;
    file.sync_all()?;

    let (_, payload_digest) = digest_regular_file(&measurement)?;
    let intent = ImageSigningIntent {
        assembly_policy_id: &assembly.signer_roles.pcr,
        role: SignerRole::PcrPolicy,
        algorithm: SignatureAlgorithm::PublicKeySha256,
        operation: SigningOperation::SignPayload,
        context: SigningContext::Payload {
            artifact_kind: "uki-measurement".to_owned(),
        },
        payload_digest,
    };
    let request = authorizer.authorize(&intent)?;
    verify_intent(&request, &intent)?;
    let response = signer.sign_detached(&request, &measurement).await?;
    verify_response_binding(&request, &response)?;
    let (_, public_key_digest) = digest_regular_file(pcr_public_key)?;
    if response.output_digest.is_some()
        || response.verification_material_digest != public_key_digest
    {
        bail!("measurement signer response differs from the PCR public key");
    }
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&response.signature_base64)
        .context("decoding UKI measurement signature")?;
    if signature_bytes.is_empty() || signature_bytes.len() > MAX_ONE_SIGNATURE_BYTES {
        bail!("UKI measurement signature is empty or oversized");
    }
    fs::write(&signature, signature_bytes)?;
    let _ = openssl
        .run(
            [
                "dgst",
                "-sha256",
                "-verify",
                path_text(pcr_public_key)?,
                "-signature",
                path_text(&signature)?,
                path_text(&measurement)?,
            ],
            1024,
        )
        .await?;
    Ok(UkiMeasurementV1 {
        measurement,
        signature,
        signing_operation: response,
    })
}

async fn verify_signed_policy(
    unsigned: &PolicyDocument,
    signed: &SignedPolicyDocument,
    public_key: &Path,
    scratch: &Path,
    openssl: &PinnedTool,
) -> Result<()> {
    if signed.sha256.len() != unsigned.sha256.len() {
        bail!("signed PCR policy changes the authorized policy count");
    }
    let public_der = scratch.join("pcr-public.der");
    let _ = openssl
        .run_to_new_file(
            [
                "pkey",
                "-pubin",
                "-in",
                path_text(public_key)?,
                "-outform",
                "DER",
            ],
            None,
            &public_der,
            1024 * 1024,
        )
        .await?;
    let fingerprint = digest_regular_file(&public_der)?.1.hex();

    for (index, (expected, actual)) in unsigned.sha256.iter().zip(&signed.sha256).enumerate() {
        if actual.pcrs != expected.pcrs || actual.pol != expected.pol || actual.pkfp != fingerprint
        {
            bail!("signed PCR policy changes policy identity or public-key fingerprint");
        }
        let policy_bytes = decode_hex_32(&actual.pol)?;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&actual.sig)
            .context("decoding PCR policy signature")?;
        if signature.is_empty() || signature.len() > MAX_ONE_SIGNATURE_BYTES {
            bail!("PCR policy signature is empty or oversized");
        }
        let policy_path = scratch.join(format!("policy-{index:02}.bin"));
        let signature_path = scratch.join(format!("policy-{index:02}.sig"));
        fs::write(&policy_path, policy_bytes)?;
        fs::write(&signature_path, signature)?;
        let _ = openssl
            .run(
                [
                    "dgst",
                    "-sha256",
                    "-verify",
                    path_text(public_key)?,
                    "-signature",
                    path_text(&signature_path)?,
                    path_text(&policy_path)?,
                ],
                1024,
            )
            .await?;
    }
    Ok(())
}

fn measure_arguments(sections: &PcrSections<'_>) -> Result<Vec<std::ffi::OsString>> {
    Ok([
        ("--linux=", sections.linux),
        ("--osrel=", sections.osrel),
        ("--cmdline=", sections.cmdline),
        ("--initrd=", sections.initrd),
        ("--sbat=", sections.sbat),
        ("--pcrpkey=", sections.pcrpkey),
    ]
    .into_iter()
    .map(|(prefix, path)| {
        let mut value = std::ffi::OsString::from(prefix);
        value.push(path);
        value
    })
    .collect())
}

fn validate_policy(policy: &PolicyDocument) -> Result<()> {
    if policy.sha256.is_empty() {
        bail!("systemd-measure returned no PCR policies");
    }
    let mut identities = std::collections::BTreeSet::new();
    for record in &policy.sha256 {
        if record.pcrs != [11] {
            bail!("systemd-measure returned a policy outside PCR 11");
        }
        decode_hex_32(&record.pol)?;
        if !identities.insert((&record.pcrs, &record.pol)) {
            bail!("systemd-measure returned duplicate PCR policies");
        }
    }
    Ok(())
}

fn ready_pcr11(calculation: &CalculationDocument) -> Result<Sha256Digest> {
    let values = calculation
        .sha256
        .iter()
        .filter(|record| record.phase == READY_PHASE && record.pcr == 11)
        .map(|record| record.hash.as_str())
        .collect::<Vec<_>>();
    if values.len() != 1 {
        bail!("PCR calculation lacks one unambiguous ready-phase PCR 11");
    }
    Sha256Digest::parse(&format!("sha256:{}", values[0]))
}

fn decode_hex_32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("PCR policy digest must be 64 lowercase hexadecimal digits");
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(decoded)
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("PCR policy path is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_the_ready_phase() -> Result<()> {
        let document = CalculationDocument {
            sha256: vec![CalculationRecord {
                phase: READY_PHASE.to_owned(),
                pcr: 11,
                hash: "a".repeat(64),
            }],
        };
        assert_eq!(ready_pcr11(&document)?.hex(), "a".repeat(64));
        Ok(())
    }

    #[test]
    fn rejects_policy_outside_pcr_eleven() {
        let policy = PolicyDocument {
            sha256: vec![PolicyRecord {
                pcrs: vec![7],
                pol: "a".repeat(64),
            }],
        };
        assert!(validate_policy(&policy).is_err());
    }
}
