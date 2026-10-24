//! Shared DSSE envelope contracts and pre-authentication encoding.
//!
//! Package provenance is stored as one envelope per JSONL line:
//!
//! ```json
//! {"payloadType":"application/vnd.in-toto+json","payload":"...","signatures":[{"keyid":"builder","sig":"..."}]}
//! ```

use serde::{Deserialize, Serialize};

/// Media type for in-toto statements in package-provenance DSSE envelopes.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// OpenSSH signature namespace for package-provenance DSSE envelopes.
pub const DSSE_SIGNATURE_NAMESPACE: &str = "aos-package-provenance-dsse-v1";

/// A DSSE envelope containing an encoded in-toto statement and signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    /// Media type of the decoded statement.
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded statement bytes.
    pub payload: String,
    /// Signatures over the DSSE pre-authentication encoding.
    #[serde(default)]
    pub signatures: Vec<DsseSignature>,
}

/// An encoded SSHSIG signature bound to a registry roster key identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    /// Stable identifier in the registry signing roster.
    #[serde(rename = "keyid")]
    pub key_id: String,
    /// Base64-encoded armored SSHSIG bytes.
    pub sig: String,
}

/// Encodes the media type and payload using DSSEv1 pre-authentication framing.
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);
    pae
}
