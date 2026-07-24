//! The `aos.gen-attestation/v1` generation-attestation record.
//!
//! The locally-computed config manifest needs **no signature**: it is
//! `f(inputs)` under `--pure-eval`, so reproducibility from policy-authorized,
//! content-bound inputs is strictly stronger than a signature on the output.
//! What a remote verifier still cannot see
//! from a bare PCR-11 quote is *which* config-module inputs and `host.nix` the
//! evaluator consumed. This record closes that gap: it binds the five
//! content-addressed eval inputs (base lib, evaluator, config modules,
//! `host.nix`, instance facts) plus the F1 dm-verity roothash into a TPM2 quote
//! over PCR 7, 11, and the application PCR 15, turning attestation into full
//! re-derivation.
//!
//! # On-disk format
//!
//! Serialized to **canonical JSON** (the same canonicalization as the manifest
//! hash; see [`crate::graph_compile::reproject::hash_cjson`]) and persisted
//! alongside `gen-N/manifest.json`. Two boxes that derived the same generation
//! emit byte-identical records modulo the `quote` field.
//!
//! ```text
//! aos.gen-attestation/v1
//!   schema          : "aos.gen-attestation/v1"
//!   generation_id   : "<hex>"
//!   manifest_hash   : "sha256:<hex>"
//!   inputs:
//!     base_lib:        { pcr11_expected, abi_hash, module_abi,
//!                        root_verity_roothash, root_verity_uuid? }
//!     evaluator:       { store_path }
//!     config_modules:  { registry, release_tag, tag_signer_key, realization }
//!     host_nix:        { content_hash, bundle_hash?, trust_mode,
//!                        platform?, signer_key? }
//!     instance_facts:  { facts_hash, platform }
//!   eval_mode       : "pure-eval"
//!   quote           : "<hex of the TPM2 quote blob>"
//! ```
//!
//! # Quoting (build-spec §1.4)
//!
//! The record is bound to the TPM by extending its hash into application PCR 15,
//! then quoting PCR {7, 11, 15}:
//!
//! 1. canonicalize the record **without** `quote` -> `record_bytes`;
//! 2. `record_hash = sha256(record_bytes)`;
//! 3. `TPM2_PCR_Extend(15, record_hash)`;
//! 4. `quote = TPM2_Quote(PCR{7,11,15}, nonce)`.
//!
//! The seal mechanism is unchanged: `/var` stays sealed to PCR 7 + 11; PCR 15
//! carries only attestation evidence, never the seal. The TPM operations are
//! isolated behind [`TpmQuoter`] / [`QuoteChecker`] so the record logic is
//! unit-testable off-host with a mock TPM.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::graph_compile::reproject::hash_cjson;

/// Schema discriminator for the generation-attestation record.
pub const GEN_ATTESTATION_SCHEMA: &str = "aos.gen-attestation/v1";

/// Literal `eval_mode`, asserting the determinism precondition (build-spec §1.3).
pub const EVAL_MODE_PURE: &str = "pure-eval";

/// The application PCR the record hash is extended into (build-spec §1.4).
pub const APP_PCR_INDEX: u8 = 15;

/// The `aos.gen-attestation/v1` evidence bundle (build-spec §1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenAttestation {
    /// Always [`GEN_ATTESTATION_SCHEMA`]; rejected otherwise.
    pub schema: String,
    /// Content hash APM assigned the materialized config-generation directory.
    /// Read from the generation record, not recomputed.
    pub generation_id: String,
    /// `sha256:<hex>` of the canonicalized manifest (build-spec §1.3).
    pub manifest_hash: String,
    /// The five content-addressed eval inputs.
    pub inputs: AttestationInputs,
    /// Literal [`EVAL_MODE_PURE`].
    pub eval_mode: String,
    /// Hex of the TPM2 quote blob over PCR {7, 11, 15} + this record's hash.
    /// Empty in a freshly-built, not-yet-quoted record.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub quote: String,
}

/// The five content-addressed inputs that fully determine the generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationInputs {
    /// Base-lib + evaluator measured-boot binding (incl. F1 roothash).
    pub base_lib: BaseLibAttInput,
    /// The eval binary that produced the manifest.
    pub evaluator: EvaluatorAttInput,
    /// The signed-tag-blessed config-module set consumed.
    pub config_modules: ConfigModulesAttInput,
    /// The policy-authorized `host.nix`.
    pub host_nix: HostNixAttInput,
    /// The platform-supplied instance facts (recorded, not signed).
    pub instance_facts: InstanceFactsAttInput,
}

/// Base-lib measured-boot binding plus the F1 dm-verity roothash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseLibAttInput {
    /// `sha256:<hex>` ukify-predicted PCR-11 of the booted UKI (ties to measured
    /// boot). Read from the registry catalog's recorded `expected_pcr11`, not
    /// recomputed (build-spec §1.3).
    pub pcr11_expected: String,
    /// `sha256:<hex>` over the base-lib module API schema concatenated with
    /// `module_abi`.
    pub abi_hash: String,
    /// `AOS_MODULE_ABI` parsed from the running image's `/etc/os-release`.
    pub module_abi: u32,
    /// F1: Merkle root of the erofs root, read from `/proc/cmdline`'s
    /// `roothash=<hex>` token (which sd-stub measured into PCR 11). Validated
    /// `^[0-9a-f]{64}$`.
    pub root_verity_roothash: String,
    /// F1 (optional): the verity superblock UUID from `veritysetup status root`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_verity_uuid: Option<String>,
}

/// The eval binary consumed by `aos-eval.service`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorAttInput {
    /// Resolved store path of the `aos-eval` binary; recorded for re-derivation.
    pub store_path: String,
}

/// The signed-tag-blessed config-module set the resolver consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigModulesAttInput {
    /// Registry name the config modules came from.
    pub registry: String,
    /// The `verify_tag_chain` target (semver release tag).
    pub release_tag: String,
    /// `trusted-keys.d` fingerprint that signed the release tag
    /// ([`crate::security::key_fingerprint`], 8 hex).
    pub tag_signer_key: String,
    /// `sha256:<hex>` of the consumed signed `store/` realization-graph subset.
    pub realization: String,
}

/// The policy-authorized `host.nix` provenance (mirrors the manifest's
/// `inputs.host_nix`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostNixAttInput {
    /// `sha256:<hex>` of the exact `host.nix` bytes fed to the evaluator.
    pub content_hash: String,
    /// SHA-256 of the complete provisioning bundle, when an envelope was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
    /// Image-selected authorization policy: `platform` or `signed`.
    pub trust_mode: String,
    /// Detected control-plane identity in platform mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Trusted configuration-key fingerprint in signed mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<String>,
}

/// Platform-supplied instance facts (the second host-varying input).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceFactsAttInput {
    /// `sha256:<hex>` of the canonical `host.facts.*` tree.
    pub facts_hash: String,
    /// The IMDS platform tag (`aws`, `gcp`, …). Recorded, not signed.
    pub platform: String,
}

// ---------------------------------------------------------------------------
// TPM seams (mockable)
// ---------------------------------------------------------------------------

/// Produces a TPM2 quote binding a record hash to PCR {7, 11, 15}.
///
/// The production implementation extends `record_hash` into PCR 15 and runs
/// `tpm2_quote` (reusing the
/// [`crate::package_attestation`] machinery); tests inject a deterministic
/// mock so the record/compute logic is exercised off-host.
pub trait TpmQuoter {
    /// Extend PCR 15 with `record_hash`, then quote PCR {7, 11, 15} with
    /// `nonce`. Returns the opaque quote blob.
    ///
    /// # Errors
    ///
    /// Returns an error when the TPM cannot be driven (no device, tool failure).
    fn quote(&self, record_hash: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The PCR values a verifier recovered from a checked quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotedPcrs {
    /// SB-state PCR 7, lowercase hex.
    pub pcr7: String,
    /// Measured-boot PCR 11, lowercase hex.
    pub pcr11: String,
    /// Application PCR 15 (record binding), lowercase hex.
    pub pcr15: String,
}

/// Verifies a quote signature under an attestation key and recovers its PCRs.
///
/// The production implementation checks the TPM2B_ATTEST + signature under the
/// AK public key over `(PCR{7,11,15}, nonce)`; tests inject a mock that returns
/// scripted PCRs (or an error to model a bad signature).
pub trait QuoteChecker {
    /// Verify `quote` over `nonce` and return the quoted PCR values.
    ///
    /// # Errors
    ///
    /// Returns an error when the quote signature is invalid under the verifier's
    /// pinned AK, the nonce does not match, or the blob cannot be parsed.
    fn check(&self, quote: &[u8], nonce: &[u8]) -> anyhow::Result<QuotedPcrs>;
}

// ---------------------------------------------------------------------------
// Compute
// ---------------------------------------------------------------------------

/// Canonicalize a record **without** its `quote` field and return the
/// `sha256(record_bytes)` digest bytes (build-spec §1.4 steps 1-2).
///
/// The `quote` field is cleared before canonicalization so the digest is the
/// pre-quote record identity — the value extended into PCR 15.
pub fn record_hash(record: &GenAttestation) -> [u8; 32] {
    let mut bare = record.clone();
    bare.quote = String::new();
    // `hash_cjson` is the single canonicalization used everywhere (build-spec
    // §0): it returns "sha256:<hex>" over the canonical JSON bytes. The quoter
    // extends the 32 raw digest bytes into PCR 15, so decode the hex back to
    // bytes here rather than re-canonicalizing independently.
    let value = serde_json::to_value(&bare).unwrap_or(Value::Null);
    let digest_hex = hash_cjson(&value);
    let hex_part = digest_hex.strip_prefix("sha256:").unwrap_or(&digest_hex);
    let mut out = [0_u8; 32];
    if let Ok(bytes) = hex::decode(hex_part) {
        if bytes.len() == 32 {
            out.copy_from_slice(&bytes);
        }
    }
    out
}

/// Compute the canonical-JSON hash of the full record (incl. `quote`), the
/// `"sha256:<hex>"` content-address used to reference an emitted record.
///
/// # Errors
///
/// Returns an error if the record cannot be serialized to JSON.
pub fn attestation_content_hash(record: &GenAttestation) -> anyhow::Result<String> {
    let value = serde_json::to_value(record)?;
    Ok(hash_cjson(&value))
}

/// Build and quote a [`GenAttestation`] from its inputs (build-spec §1.4).
///
/// Assembles the record with an empty `quote`, computes [`record_hash`], drives
/// `quoter` to extend PCR 15 and quote PCR {7, 11, 15} with `nonce`, then stores
/// the hex-encoded quote blob. The host input must carry complete authorization
/// evidence for its named policy.
///
/// # Errors
///
/// Returns an error when host-input authorization evidence is incomplete, when
/// `base_lib.root_verity_roothash` is not 64 lowercase hex digits, or when the
/// `quoter` fails to produce a quote.
pub fn compute_gen_attestation(
    generation_id: impl Into<String>,
    manifest_hash: impl Into<String>,
    inputs: AttestationInputs,
    quoter: &dyn TpmQuoter,
    nonce: &[u8],
) -> anyhow::Result<GenAttestation> {
    match inputs.host_nix.trust_mode.as_str() {
        "platform"
            if inputs.host_nix.platform.is_some() && inputs.host_nix.signer_key.is_none() => {}
        "signed"
            if inputs.host_nix.signer_key.is_some() && inputs.host_nix.platform.is_none() => {}
        mode => {
            anyhow::bail!(
                "host.nix authorization evidence is incomplete for trust mode '{mode}'"
            );
        }
    }
    if !is_verity_roothash(&inputs.base_lib.root_verity_roothash) {
        anyhow::bail!(
            "base_lib.root_verity_roothash must be 64 lowercase hex digits, got '{}'",
            inputs.base_lib.root_verity_roothash
        );
    }

    let mut record = GenAttestation {
        schema: GEN_ATTESTATION_SCHEMA.to_string(),
        generation_id: generation_id.into(),
        manifest_hash: manifest_hash.into(),
        inputs,
        eval_mode: EVAL_MODE_PURE.to_string(),
        quote: String::new(),
    };

    let digest = record_hash(&record);
    let quote = quoter.quote(&digest, nonce)?;
    record.quote = hex::encode(quote);
    Ok(record)
}

/// Whether `s` is a 64-character lowercase-hex string (a dm-verity roothash).
pub fn is_verity_roothash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// Verify (build-spec §1.5)
// ---------------------------------------------------------------------------

/// The data a verifier checks a record against: the registry catalog's pinned
/// PCRs, the trusted operator/roster key sets, and the published image's root
/// roothash (build-spec §1.5).
#[derive(Debug, Clone)]
pub struct VerifierPolicy {
    /// Catalog `expected_pcr7` (SB-state pin), lowercase hex.
    pub expected_pcr7: String,
    /// Catalog `expected_pcr11` for the booted UKI, `sha256:<hex>`.
    pub expected_pcr11: String,
    /// The published image's `root.roothash` (UKI `.cmdline` token), 64 hex.
    pub expected_root_roothash: String,
    /// Operator config-key fingerprints in `trusted-config-keys.d`.
    pub trusted_config_keys: Vec<String>,
    /// Deployment platform identities accepted as control-plane authorities.
    pub trusted_platforms: Vec<String>,
    /// Registry roster fingerprints that may sign release tags.
    pub roster_fingerprints: Vec<String>,
    /// Release tags accepted by `verify_tag_chain` and not revoked.
    pub valid_release_tags: Vec<String>,
}

/// Why a [`GenAttestation`] failed verification (build-spec §1.5 FAIL points).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenAttestationFailure {
    /// `schema` is not [`GEN_ATTESTATION_SCHEMA`].
    Schema,
    /// The quote signature did not validate under the verifier's AK.
    Quote,
    /// PCR 15 did not equal `extend(0, sha256(record\quote))`.
    RecordBinding,
    /// PCR 7 did not match the catalog SB-state pin.
    SbState,
    /// PCR 11 did not match `pcr11_expected` and/or the catalog value.
    Pcr11,
    /// The F1 root-verity binding did not hold across record/catalog.
    RootVerity,
    /// The release tag is unsigned/revoked, or `tag_signer_key` is off-roster.
    Tag,
    /// Host-input authorization evidence does not satisfy verifier policy.
    HostNixTrust,
    /// `eval_mode` is not `pure-eval`.
    EvalMode,
    /// Optional re-derivation produced a different `manifest_hash`.
    Rederive,
}

impl std::fmt::Display for GenAttestationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GenAttestationFailure::Schema => "unrecognized attestation schema",
            GenAttestationFailure::Quote => "TPM quote signature invalid under the pinned AK",
            GenAttestationFailure::RecordBinding => {
                "PCR 15 does not bind this record (record-binding check failed)"
            }
            GenAttestationFailure::SbState => "PCR 7 does not match the catalog SB-state pin",
            GenAttestationFailure::Pcr11 => "PCR 11 does not match the expected measured-boot value",
            GenAttestationFailure::RootVerity => "F1 root-verity roothash binding failed",
            GenAttestationFailure::Tag => "release tag is unsigned, revoked, or off-roster",
            GenAttestationFailure::HostNixTrust => {
                "host.nix authorization evidence is untrusted"
            }
            GenAttestationFailure::EvalMode => "eval_mode is not 'pure-eval'",
            GenAttestationFailure::Rederive => "re-derived manifest hash does not match the record",
        };
        f.write_str(s)
    }
}

impl std::error::Error for GenAttestationFailure {}

/// Verify a generation-attestation record (build-spec §1.5 steps 1-9, with the
/// optional step-10 re-derivation supplied by `rederive`).
///
/// `checker` recovers the quoted PCR values (mock or real TPM); `policy` carries
/// the catalog pins and trusted key sets; `nonce` is the challenge the quote was
/// taken over. When `rederive` is `Some`, it is called with the record and must
/// return the re-computed `manifest_hash`; a mismatch is
/// [`GenAttestationFailure::Rederive`]. Pass `None` to stop at step 9.
///
/// # Errors
///
/// Returns the first [`GenAttestationFailure`] encountered, in build-spec order
/// (schema, quote, record-binding, SB-state, PCR 11, root-verity, tag,
/// host-nix-key, eval-mode, rederive). The checks are fail-closed: any error
/// means the box did **not** demonstrably derive its generation only from
/// trusted inputs.
pub fn verify_gen_attestation(
    record: &GenAttestation,
    checker: &dyn QuoteChecker,
    policy: &VerifierPolicy,
    nonce: &[u8],
    rederive: Option<&dyn Fn(&GenAttestation) -> String>,
) -> Result<(), GenAttestationFailure> {
    // 1. schema
    if record.schema != GEN_ATTESTATION_SCHEMA {
        return Err(GenAttestationFailure::Schema);
    }

    // 2. quote signature valid -> recover PCRs.
    let quote_bytes = hex::decode(&record.quote).map_err(|_| GenAttestationFailure::Quote)?;
    let pcrs = checker
        .check(&quote_bytes, nonce)
        .map_err(|_| GenAttestationFailure::Quote)?;

    // 3. PCR15 == extend(0, sha256(record\quote))
    let expected_pcr15 = expected_app_pcr(&record_hash(record));
    if !ct_eq(&pcrs.pcr15, &expected_pcr15) {
        return Err(GenAttestationFailure::RecordBinding);
    }

    // 4. PCR7 == catalog.expected_pcr7
    if !ct_eq(&pcrs.pcr7, &policy.expected_pcr7) {
        return Err(GenAttestationFailure::SbState);
    }

    // 5. PCR11 == record.base_lib.pcr11_expected AND == catalog.expected_pcr11
    let pcr11_hex = strip_sha256(&record.inputs.base_lib.pcr11_expected);
    let catalog_pcr11 = strip_sha256(&policy.expected_pcr11);
    if !ct_eq(&pcrs.pcr11, pcr11_hex) || !ct_eq(pcr11_hex, catalog_pcr11) {
        return Err(GenAttestationFailure::Pcr11);
    }

    // 6. F1 root binding: record roothash == catalog/published roothash.
    if !ct_eq(
        &record.inputs.base_lib.root_verity_roothash,
        &policy.expected_root_roothash,
    ) {
        return Err(GenAttestationFailure::RootVerity);
    }

    // 7. release tag signed by a roster key and not revoked.
    let cm = &record.inputs.config_modules;
    if !policy.valid_release_tags.contains(&cm.release_tag)
        || !policy.roster_fingerprints.contains(&cm.tag_signer_key)
    {
        return Err(GenAttestationFailure::Tag);
    }

    // 8. Host-input evidence satisfies the named image policy.
    let host = &record.inputs.host_nix;
    let host_trusted = match host.trust_mode.as_str() {
        "platform" => {
            host.signer_key.is_none()
                && host
                    .platform
                    .as_ref()
                    .is_some_and(|platform| policy.trusted_platforms.contains(platform))
        }
        "signed" => {
            host.platform.is_none()
                && host
                    .signer_key
                    .as_ref()
                    .is_some_and(|key| policy.trusted_config_keys.contains(key))
        }
        _ => false,
    };
    if !host_trusted {
        return Err(GenAttestationFailure::HostNixTrust);
    }

    // 9. eval_mode == "pure-eval".
    if record.eval_mode != EVAL_MODE_PURE {
        return Err(GenAttestationFailure::EvalMode);
    }

    // 10. optional full re-derivation.
    if let Some(rederive) = rederive {
        if rederive(record) != record.manifest_hash {
            return Err(GenAttestationFailure::Rederive);
        }
    }

    Ok(())
}

/// `extend(0, digest)` = `sha256(zeros32 || digest)`, the PCR value after a
/// single extend of a freshly-reset (all-zero) PCR (build-spec §1.5 step 3).
fn expected_app_pcr(digest: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update([0_u8; 32]);
    hasher.update(digest);
    hex::encode(hasher.finalize())
}

/// Strip an optional `sha256:`/`sha256-` prefix, returning the bare hex.
fn strip_sha256(s: &str) -> &str {
    s.strip_prefix("sha256:")
        .or_else(|| s.strip_prefix("sha256-"))
        .unwrap_or(s)
}

/// Constant-time-ish case-insensitive hex equality. Compares lengths first, then
/// bytes; used for PCR/digest comparison so a mismatch is total, not prefix.
fn ct_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock TPM that "extends" PCR 15 itself and returns a structured quote
    /// the matching [`MockChecker`] decodes — exercising the full
    /// compute->verify round trip with no real TPM.
    struct MockTpm {
        pcr7: String,
        pcr11: String,
    }

    impl TpmQuoter for MockTpm {
        fn quote(&self, record_hash: &[u8], nonce: &[u8]) -> anyhow::Result<Vec<u8>> {
            // The mock quote is just the three PCR values + nonce, JSON-encoded.
            let pcr15 = expected_app_pcr(&to_array(record_hash));
            let blob = serde_json::json!({
                "pcr7": self.pcr7,
                "pcr11": self.pcr11,
                "pcr15": pcr15,
                "nonce": hex::encode(nonce),
            });
            Ok(serde_json::to_vec(&blob)?)
        }
    }

    /// The verifier-side counterpart: decodes the mock quote and checks the
    /// nonce, returning the embedded PCRs.
    struct MockChecker;

    impl QuoteChecker for MockChecker {
        fn check(&self, quote: &[u8], nonce: &[u8]) -> anyhow::Result<QuotedPcrs> {
            let v: serde_json::Value = serde_json::from_slice(quote)?;
            let got_nonce = v["nonce"].as_str().unwrap_or_default();
            if got_nonce != hex::encode(nonce) {
                anyhow::bail!("nonce mismatch");
            }
            Ok(QuotedPcrs {
                pcr7: v["pcr7"].as_str().unwrap_or_default().to_string(),
                pcr11: v["pcr11"].as_str().unwrap_or_default().to_string(),
                pcr15: v["pcr15"].as_str().unwrap_or_default().to_string(),
            })
        }
    }

    fn to_array(b: &[u8]) -> [u8; 32] {
        let mut a = [0_u8; 32];
        a.copy_from_slice(b);
        a
    }

    const ROOTHASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const PCR11_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const PCR7_HEX: &str = "7777777777777777777777777777777777777777777777777777777777777777";

    fn sample_inputs() -> AttestationInputs {
        AttestationInputs {
            base_lib: BaseLibAttInput {
                pcr11_expected: format!("sha256:{PCR11_HEX}"),
                abi_hash: "sha256:aa".to_string(),
                module_abi: 1,
                root_verity_roothash: ROOTHASH.to_string(),
                root_verity_uuid: Some("11111111-2222-3333-4444-555555555555".to_string()),
            },
            evaluator: EvaluatorAttInput {
                store_path: "/nix/store/hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh-aos-eval-1".to_string(),
            },
            config_modules: ConfigModulesAttInput {
                registry: "andyl".to_string(),
                release_tag: "1.4.0".to_string(),
                tag_signer_key: "deadbeef".to_string(),
                realization: "sha256:cc".to_string(),
            },
            host_nix: HostNixAttInput {
                content_hash: "sha256:dd".to_string(),
                bundle_hash: Some("sha256:bundle".to_string()),
                trust_mode: "signed".to_string(),
                platform: None,
                signer_key: Some("0badf00d".to_string()),
            },
            instance_facts: InstanceFactsAttInput {
                facts_hash: "sha256:ee".to_string(),
                platform: "aws".to_string(),
            },
        }
    }

    fn sample_policy() -> VerifierPolicy {
        VerifierPolicy {
            expected_pcr7: PCR7_HEX.to_string(),
            expected_pcr11: format!("sha256:{PCR11_HEX}"),
            expected_root_roothash: ROOTHASH.to_string(),
            trusted_config_keys: vec!["0badf00d".to_string()],
            trusted_platforms: vec!["aws".to_string()],
            roster_fingerprints: vec!["deadbeef".to_string()],
            valid_release_tags: vec!["1.4.0".to_string()],
        }
    }

    fn computed() -> GenAttestation {
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        compute_gen_attestation("gen-7-cafe", "sha256:abc", sample_inputs(), &tpm, b"nonce-xyz")
            .expect("compute")
    }

    #[test]
    fn round_trips_through_canonical_json() {
        let record = computed();
        let json = serde_json::to_string(&record).unwrap();
        let back: GenAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
        assert_eq!(record.schema, GEN_ATTESTATION_SCHEMA);
        assert!(!record.quote.is_empty());
    }

    #[test]
    fn compute_refuses_incomplete_host_nix_evidence() {
        let mut inputs = sample_inputs();
        inputs.host_nix.signer_key = None;
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        let err = compute_gen_attestation("g", "h", inputs, &tpm, b"n").unwrap_err();
        assert!(format!("{err}").contains("authorization evidence is incomplete"));
    }

    #[test]
    fn compute_rejects_bad_roothash() {
        let mut inputs = sample_inputs();
        inputs.base_lib.root_verity_roothash = "tooshort".to_string();
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        assert!(compute_gen_attestation("g", "h", inputs, &tpm, b"n").is_err());
    }

    #[test]
    fn verifies_a_well_formed_record() {
        let record = computed();
        let res = verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None);
        assert!(res.is_ok(), "got {res:?}");
    }

    #[test]
    fn rejects_wrong_schema() {
        let mut record = computed();
        record.schema = "aos.gen-attestation/v2".to_string();
        let err = verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
            .unwrap_err();
        assert_eq!(err, GenAttestationFailure::Schema);
    }

    #[test]
    fn rejects_wrong_nonce() {
        let record = computed();
        // A different nonce makes the mock checker reject the quote (step 2).
        let err =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"WRONG", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::Quote);
    }

    #[test]
    fn rejects_tampered_record_binding() {
        let mut record = computed();
        // Tampering any covered field changes record_hash, so the quoted PCR15
        // (taken over the original) no longer binds it.
        record.manifest_hash = "sha256:tampered".to_string();
        let err = verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None)
            .unwrap_err();
        assert_eq!(err, GenAttestationFailure::RecordBinding);
    }

    #[test]
    fn rejects_pcr7_mismatch() {
        let record = computed();
        let mut policy = sample_policy();
        policy.expected_pcr7 = "00".repeat(32);
        let err = verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::SbState);
    }

    #[test]
    fn rejects_pcr11_catalog_mismatch() {
        let record = computed();
        let mut policy = sample_policy();
        policy.expected_pcr11 = format!("sha256:{}", "22".repeat(32));
        let err = verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::Pcr11);
    }

    #[test]
    fn rejects_root_verity_mismatch() {
        let record = computed();
        let mut policy = sample_policy();
        policy.expected_root_roothash = "00".repeat(32);
        let err = verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::RootVerity);
    }

    #[test]
    fn rejects_off_roster_tag_signer() {
        let record = computed();
        let mut policy = sample_policy();
        policy.roster_fingerprints = vec!["feedface".to_string()];
        let err = verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::Tag);
    }

    #[test]
    fn rejects_untrusted_operator_key() {
        let record = computed();
        let mut policy = sample_policy();
        policy.trusted_config_keys = vec!["abadcafe".to_string()];
        let err = verify_gen_attestation(&record, &MockChecker, &policy, b"nonce-xyz", None).unwrap_err();
        assert_eq!(err, GenAttestationFailure::HostNixTrust);
    }

    #[test]
    fn accepts_trusted_platform_evidence() {
        let mut inputs = sample_inputs();
        inputs.host_nix.trust_mode = "platform".to_string();
        inputs.host_nix.platform = Some("aws".to_string());
        inputs.host_nix.signer_key = None;
        let tpm = MockTpm {
            pcr7: PCR7_HEX.to_string(),
            pcr11: PCR11_HEX.to_string(),
        };
        let record =
            compute_gen_attestation("gen-platform", "sha256:abc", inputs, &tpm, b"nonce-xyz")
                .expect("compute platform-mode record");
        let result =
            verify_gen_attestation(&record, &MockChecker, &sample_policy(), b"nonce-xyz", None);
        assert!(result.is_ok(), "got {result:?}");
    }

    #[test]
    fn optional_rederivation_gate() {
        let record = computed();
        // A re-derivation that disagrees fails; one that agrees passes.
        let bad = verify_gen_attestation(
            &record,
            &MockChecker,
            &sample_policy(),
            b"nonce-xyz",
            Some(&|_r| "sha256:other".to_string()),
        );
        assert_eq!(bad.unwrap_err(), GenAttestationFailure::Rederive);

        let good = verify_gen_attestation(
            &record,
            &MockChecker,
            &sample_policy(),
            b"nonce-xyz",
            Some(&|r| r.manifest_hash.clone()),
        );
        assert!(good.is_ok());
    }
}
