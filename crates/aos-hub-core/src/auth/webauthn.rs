//! The in-house WebAuthn relying-party verifier, `attestation: none` only.
//!
//! RFC-0004 ships passkeys as a small first-party WebAuthn relying party (RP)
//! rather than the `webauthn-rs` crate, which cannot build on the Cloudflare
//! Workers target (OpenSSL backend). The hub adopts a hard
//! **`attestation: "none"`** policy, which deletes the hard 80% of WebAuthn —
//! the attestation-format zoo (`packed`, `fido-u2f`, `tpm`, `android-key`, …)
//! and the metadata/trust-anchor chains they drag in. What remains, and what
//! this module implements end-to-end, is:
//!
//! - `clientDataJSON` checks (type / challenge / origin),
//! - `authenticatorData` parsing (rpIdHash, flags, sign count, attested
//!   credential data),
//! - COSE / CBOR public-key decode (OKP/Ed25519, EC2/P-256 ES256, RSA RS256),
//!   and
//! - signature verification on RustCrypto crates already proven wasm-clean
//!   ([`p256`], [`ed25519_dalek`], [`rsa`], [`sha2`]).
//!
//! The on-disk system of record (`webauthn_credentials`, `webauthn_challenges`;
//! migration v17) lives in [`crate::db`]; this module owns the wire-format
//! parsing and the two ceremonies ([`begin_registration`]/[`finish_registration`]
//! and [`begin_assertion`]/[`finish_assertion`]).
//!
//! # `clientDataJSON`
//!
//! The browser hashes this exact JSON and the authenticator signs over the hash.
//! The RP re-parses it and checks every field (W3C §7.1 / §7.2):
//!
//! ```text
//! {
//!   "type": "webauthn.create",   // or "webauthn.get" for an assertion
//!   "challenge": "<base64url>",  // must equal the challenge the RP staged
//!   "origin": "https://hub.example.com",   // must equal the RP origin
//!   "crossOrigin": false
//! }
//! ```
//!
//! # `authenticatorData`
//!
//! A binary structure: a fixed 37-byte header, optionally followed by attested
//! credential data (present iff the `AT` flag is set, i.e. on registration) and
//! extensions (`ED` flag). Lengths are big-endian (W3C §6.1):
//!
//! ```text
//! offset  size  field
//! 0       32    rpIdHash         = SHA-256(rpId)
//! 32      1     flags            bit0 UP, bit2 UV, bit6 AT, bit7 ED
//! 33      4     signCount        big-endian u32
//! --- attested credential data (only if AT) ---
//! 37      16    aaguid
//! 53      2     credentialIdLength  L (big-endian u16)
//! 55      L     credentialId
//! 55+L    ...   credentialPublicKey  (COSE_Key, CBOR)
//! ```
//!
//! # COSE public key (RFC 8152)
//!
//! The credential public key is a CBOR map keyed by small integers. The labels
//! this verifier reads:
//!
//! ```text
//! 1  (kty)  key type: 1 = OKP (Ed25519), 2 = EC2 (P-256), 3 = RSA
//! 3  (alg)  COSE algorithm: -8 EdDSA, -7 ES256, -257 RS256
//! -1 (crv)  curve (OKP/EC2): 6 = Ed25519, 1 = P-256
//! -2 (x)    OKP public key, or EC2 x-coordinate / RSA modulus n
//! -3 (y)    EC2 y-coordinate / RSA exponent e
//! ```
//!
//! # The signed message
//!
//! For both registration verification (when present) and every assertion, the
//! authenticator signs `authenticatorData || SHA-256(clientDataJSON)` (W3C
//! §7.2 step 19). [`verify_signature`] takes exactly that concatenation.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::Verifier as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::db::Database;

/// How long a WebAuthn ceremony challenge stays valid, in seconds (5 minutes).
pub const CHALLENGE_TTL_SECS: i64 = 5 * 60;

/// The ceremony-kind tag stored in `webauthn_challenges.kind` for registration.
pub const KIND_REGISTRATION: &str = "registration";

/// The ceremony-kind tag stored in `webauthn_challenges.kind` for assertion.
pub const KIND_ASSERTION: &str = "assertion";

/// The `clientDataJSON.type` value for a registration (`navigator.credentials.create`).
pub const TYPE_CREATE: &str = "webauthn.create";

/// The `clientDataJSON.type` value for an assertion (`navigator.credentials.get`).
pub const TYPE_GET: &str = "webauthn.get";

/// base64url engine (no padding) — the encoding WebAuthn uses for `challenge`,
/// credential ids, and the binary fields exchanged with the browser script.
const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Standard base64 (padded) — the at-rest encoding for the stored COSE key.
const B64STD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

// -- clientDataJSON ---------------------------------------------------------

/// The parsed `clientDataJSON` a browser produces for a ceremony.
///
/// See the [module docs](self#clientdatajson) for the on-wire shape. The
/// `challenge` is left base64url-encoded (the form it must equal the staged
/// challenge in).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientData {
    /// `webauthn.create` (registration) or `webauthn.get` (assertion).
    #[serde(rename = "type")]
    pub ty: String,
    /// The RP challenge, base64url-encoded, that the authenticator signed over.
    pub challenge: String,
    /// The origin the ceremony ran on; must equal the RP origin.
    pub origin: String,
    /// Whether the ceremony ran in a cross-origin context.
    #[serde(default, rename = "crossOrigin")]
    pub cross_origin: bool,
}

/// Parse `clientDataJSON` bytes into a [`ClientData`].
///
/// # Errors
///
/// Returns an error when the bytes are not valid UTF-8 JSON with the required
/// `type`, `challenge`, and `origin` fields.
pub fn parse_client_data(json_bytes: &[u8]) -> Result<ClientData> {
    serde_json::from_slice(json_bytes).context("parsing clientDataJSON")
}

/// Verify a [`ClientData`] against the expected ceremony parameters.
///
/// Checks (W3C §7.1 steps 7–9 / §7.2 steps 11–13):
///
/// - `type` equals `expected_type` (`webauthn.create` or `webauthn.get`),
/// - `challenge` equals the staged `expected_challenge` (base64url, constant
///   string comparison — the value is a public nonce, not a secret), and
/// - `origin` equals the RP `expected_origin`.
///
/// Cross-origin ceremonies are rejected: the hub never embeds itself in a
/// third-party frame.
///
/// # Errors
///
/// Returns an error naming the first failing check.
pub fn verify_client_data(
    client_data: &ClientData,
    expected_type: &str,
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<()> {
    if client_data.ty != expected_type {
        bail!(
            "clientDataJSON type mismatch: expected {expected_type}, got {}",
            client_data.ty
        );
    }
    if client_data.challenge != expected_challenge {
        bail!("clientDataJSON challenge does not match the staged challenge");
    }
    if client_data.origin != expected_origin {
        bail!(
            "clientDataJSON origin mismatch: expected {expected_origin}, got {}",
            client_data.origin
        );
    }
    if client_data.cross_origin {
        bail!("cross-origin WebAuthn ceremonies are not permitted");
    }
    Ok(())
}

// -- authenticatorData ------------------------------------------------------

/// The flag bits in the `authenticatorData` flags byte (W3C §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthFlags {
    /// User present (UP) — a gesture (tap/touch) was performed.
    pub user_present: bool,
    /// User verified (UV) — biometric/PIN verification was performed.
    pub user_verified: bool,
    /// Attested credential data is present (AT) — set on registration.
    pub attested_cred_data: bool,
    /// Extension data is present (ED).
    pub extension_data: bool,
}

/// Attested credential data embedded in registration `authenticatorData`.
#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    /// The authenticator's AAGUID (model identifier); ignored under
    /// `attestation: none` but retained for completeness.
    pub aaguid: [u8; 16],
    /// The raw credential id the authenticator minted.
    pub credential_id: Vec<u8>,
    /// The decoded COSE public key for the new credential.
    pub public_key: VerifyingPublicKey,
    /// The COSE public key in its original CBOR bytes, for re-encoding at rest.
    pub public_key_cbor: Vec<u8>,
}

/// Parsed `authenticatorData` (W3C §6.1).
#[derive(Debug, Clone)]
pub struct AuthData {
    /// `SHA-256(rpId)`; checked against the RP id on every ceremony.
    pub rp_id_hash: [u8; 32],
    /// The decoded flag bits.
    pub flags: AuthFlags,
    /// The authenticator's signature counter.
    pub sign_count: u32,
    /// Attested credential data, present iff the `AT` flag is set.
    pub attested_cred_data: Option<AttestedCredentialData>,
}

/// Parse raw `authenticatorData` bytes.
///
/// Parses the fixed 37-byte header and, when the `AT` flag is set, the attested
/// credential data and its trailing COSE public key. See the [module
/// docs](self#authenticatordata) for the byte layout.
///
/// # Errors
///
/// Returns an error when the buffer is shorter than the header, the attested
/// credential data is truncated, or the trailing COSE key fails to decode.
pub fn parse_authenticator_data(bytes: &[u8]) -> Result<AuthData> {
    if bytes.len() < 37 {
        bail!("authenticatorData is shorter than the 37-byte header");
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&bytes[0..32]);

    let flags = parse_flags(bytes[32]);
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

    let attested_cred_data = if flags.attested_cred_data {
        Some(parse_attested_credential_data(&bytes[37..])?)
    } else {
        None
    };

    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        attested_cred_data,
    })
}

/// Decode the flags byte into [`AuthFlags`].
fn parse_flags(byte: u8) -> AuthFlags {
    AuthFlags {
        user_present: byte & 0x01 != 0,
        user_verified: byte & 0x04 != 0,
        attested_cred_data: byte & 0x40 != 0,
        extension_data: byte & 0x80 != 0,
    }
}

/// Parse the attested-credential-data region (everything after the 37-byte
/// header), including the trailing COSE public key.
fn parse_attested_credential_data(bytes: &[u8]) -> Result<AttestedCredentialData> {
    if bytes.len() < 18 {
        bail!("attested credential data is truncated (aaguid + length)");
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&bytes[0..16]);
    let cred_id_len = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
    let cred_id_end = 18 + cred_id_len;
    if bytes.len() < cred_id_end {
        bail!("attested credential data is truncated (credentialId)");
    }
    let credential_id = bytes[18..cred_id_end].to_vec();

    // The remainder is the COSE_Key (CBOR). It may be followed by extension
    // bytes, but under our policy registration never requests extensions, and
    // ciborium reads exactly one CBOR item, ignoring any trailing bytes.
    let cose_bytes = &bytes[cred_id_end..];
    let public_key = decode_cose_key(cose_bytes)?;

    Ok(AttestedCredentialData {
        aaguid,
        credential_id,
        public_key,
        public_key_cbor: cose_bytes.to_vec(),
    })
}

/// Verify `authenticatorData` against the expected RP id.
///
/// Checks (W3C §7.2 steps 14–17):
///
/// - `rpIdHash == SHA-256(expected_rp_id)`, and
/// - the User Present (`UP`) flag is set.
///
/// User Verification (`UV`) is **not** required: passkeys may be single-factor
/// (presence only) at the authenticator's discretion, and the RP does not force
/// UV in this phase. Callers that need a UV guarantee can inspect
/// [`AuthData::flags`].
///
/// # Errors
///
/// Returns an error when the RP-id hash does not match or `UP` is clear.
pub fn verify_authenticator_data(auth_data: &AuthData, expected_rp_id: &str) -> Result<()> {
    let expected = Sha256::digest(expected_rp_id.as_bytes());
    if auth_data.rp_id_hash != expected.as_slice() {
        bail!("authenticatorData rpIdHash does not match the relying-party id");
    }
    if !auth_data.flags.user_present {
        bail!("authenticatorData User Present (UP) flag is not set");
    }
    Ok(())
}

// -- COSE key decode --------------------------------------------------------

/// A decoded COSE public key, ready to verify a signature.
#[derive(Debug, Clone)]
pub enum VerifyingPublicKey {
    /// An Ed25519 key (COSE OKP, crv Ed25519, alg EdDSA).
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
    /// A NIST P-256 key (COSE EC2, crv P-256, alg ES256).
    P256(Box<p256::ecdsa::VerifyingKey>),
    /// An RSA key (COSE RSA, alg RS256), holding modulus and exponent.
    Rsa(Box<rsa::RsaPublicKey>),
}

/// One COSE_Key entry value we care about: either an integer or a byte string.
#[derive(Debug)]
enum CoseValue {
    Int(i64),
    Bytes(Vec<u8>),
}

/// Decode a COSE_Key (RFC 8152) CBOR map into a [`VerifyingPublicKey`].
///
/// Reads the `kty` (label 1), `alg` (label 3), `crv` (label -1), and the key
/// material (`x` = label -2, `y` = label -3), then dispatches on `kty`:
///
/// - OKP / Ed25519 (kty 1, crv 6, alg -8): label -2 is the 32-byte public key.
/// - EC2 / P-256 (kty 2, crv 1, alg -7): labels -2/-3 are the 32-byte
///   coordinates; an uncompressed SEC1 point is reconstructed.
/// - RSA (kty 3, alg -257): label -1 is the modulus `n`, label -2 is the
///   exponent `e`.
///
/// The COSE `alg` label is required, must be in the supported set
/// {-8 EdDSA, -7 ES256, -257 RS256}, and must be consistent with the key type
/// (e.g. an EC2 key must carry `alg = -7`). A credential whose `alg` is missing,
/// outside the set, or inconsistent with its `kty`/`crv` is refused — hardening
/// against a malformed registration even though the assertion verifier
/// independently dispatches on the decoded key variant.
///
/// # Errors
///
/// Returns an error on malformed CBOR, a missing/unsupported/inconsistent
/// `alg`, an unsupported `kty`/`crv`, a missing key component, or an invalid
/// key encoding.
pub fn decode_cose_key(cbor: &[u8]) -> Result<VerifyingPublicKey> {
    let value: ciborium::value::Value =
        ciborium::de::from_reader(cbor).context("decoding COSE key CBOR")?;
    let map = value
        .as_map()
        .ok_or_else(|| anyhow!("COSE key is not a CBOR map"))?;

    let mut entries: Vec<(i64, CoseValue)> = Vec::with_capacity(map.len());
    for (k, v) in map {
        let Some(label) = cbor_as_int(k) else {
            continue; // non-integer label: ignore (string labels are not used here)
        };
        let parsed = match v {
            ciborium::value::Value::Integer(_) => {
                CoseValue::Int(cbor_as_int(v).ok_or_else(|| anyhow!("COSE integer out of range"))?)
            }
            ciborium::value::Value::Bytes(b) => CoseValue::Bytes(b.clone()),
            _ => continue,
        };
        entries.push((label, parsed));
    }

    let int = |label: i64| -> Option<i64> {
        entries.iter().find_map(|(l, v)| match v {
            CoseValue::Int(n) if *l == label => Some(*n),
            _ => None,
        })
    };
    let bytes = |label: i64| -> Option<&[u8]> {
        entries.iter().find_map(|(l, v)| match v {
            CoseValue::Bytes(b) if *l == label => Some(b.as_slice()),
            _ => None,
        })
    };

    let kty = int(1).ok_or_else(|| anyhow!("COSE key has no kty (label 1)"))?;
    // The credential's declared COSE algorithm (label 3) must be present, in the
    // supported set, and consistent with the key type below. Even though the
    // verifier later dispatches on the decoded key *variant* (so a forged `alg`
    // cannot induce algorithm confusion at verification time), a registration
    // whose `alg` disagrees with its `kty`/`crv` — or names an algorithm the hub
    // does not support — is malformed and is refused here so it never reaches
    // the credential store. Supported: -8 (EdDSA/Ed25519), -7 (ES256/P-256),
    // -257 (RS256/RSA).
    let alg = int(3).ok_or_else(|| anyhow!("COSE key has no alg (label 3)"))?;
    match alg {
        -8 | -7 | -257 => {}
        other => bail!(
            "unsupported COSE algorithm alg={other} \
             (only -8 EdDSA, -7 ES256, -257 RS256 are supported)"
        ),
    }
    match kty {
        // OKP / Ed25519.
        1 => {
            if alg != -8 {
                bail!("COSE alg={alg} is inconsistent with OKP key type (EdDSA / -8 required)");
            }
            let crv = int(-1).ok_or_else(|| anyhow!("OKP key has no crv"))?;
            if crv != 6 {
                bail!("unsupported OKP curve {crv} (only Ed25519 / crv 6 is supported)");
            }
            let x = bytes(-2).ok_or_else(|| anyhow!("OKP key has no x (public key)"))?;
            let arr: [u8; 32] = x
                .try_into()
                .map_err(|_| anyhow!("Ed25519 public key is not 32 bytes"))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .context("invalid Ed25519 public key")?;
            Ok(VerifyingPublicKey::Ed25519(Box::new(key)))
        }
        // EC2 / P-256, ES256.
        2 => {
            if alg != -7 {
                bail!("COSE alg={alg} is inconsistent with EC2 key type (ES256 / -7 required)");
            }
            let crv = int(-1).ok_or_else(|| anyhow!("EC2 key has no crv"))?;
            if crv != 1 {
                bail!("unsupported EC2 curve {crv} (only P-256 / crv 1 is supported)");
            }
            let x = bytes(-2).ok_or_else(|| anyhow!("EC2 key has no x coordinate"))?;
            let y = bytes(-3).ok_or_else(|| anyhow!("EC2 key has no y coordinate"))?;
            if x.len() != 32 || y.len() != 32 {
                bail!("EC2 P-256 coordinates must be 32 bytes each");
            }
            // Build an uncompressed SEC1 point: 0x04 || x || y.
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .context("invalid P-256 public key point")?;
            Ok(VerifyingPublicKey::P256(Box::new(key)))
        }
        // RSA, RS256.
        3 => {
            if alg != -257 {
                bail!("COSE alg={alg} is inconsistent with RSA key type (RS256 / -257 required)");
            }
            use rsa::traits::PublicKeyParts as _;
            use rsa::BigUint;
            let n = bytes(-1).ok_or_else(|| anyhow!("RSA key has no modulus n"))?;
            let e = bytes(-2).ok_or_else(|| anyhow!("RSA key has no exponent e"))?;
            let modulus = BigUint::from_bytes_be(n);
            let exponent = BigUint::from_bytes_be(e);
            let key =
                rsa::RsaPublicKey::new(modulus, exponent).context("invalid RSA public key")?;
            // Reject weak/degenerate RSA parameters that the `rsa` constructor
            // would otherwise accept: a short modulus is brute-forceable, and a
            // small/even public exponent is a classic RSA pitfall. Require a
            // >= 2048-bit modulus and an odd exponent of at least 65537 (F4).
            if key.n().bits() < 2048 {
                bail!("RSA modulus is {} bits (require >= 2048)", key.n().bits());
            }
            let e = key.e();
            if e < &BigUint::from(65_537u32) {
                bail!("RSA public exponent is too small (require >= 65537)");
            }
            // Odd iff the least-significant byte is odd.
            let lsb = e.to_bytes_le().first().copied().unwrap_or(0);
            if lsb & 1 == 0 {
                bail!("RSA public exponent must be odd");
            }
            Ok(VerifyingPublicKey::Rsa(Box::new(key)))
        }
        other => bail!("unsupported COSE key type kty={other}"),
    }
}

/// Read a CBOR value as an `i64` when it is an integer (positive or negative).
fn cbor_as_int(v: &ciborium::value::Value) -> Option<i64> {
    match v {
        ciborium::value::Value::Integer(i) => i128::from(*i).try_into().ok(),
        _ => None,
    }
}

// -- signature verification -------------------------------------------------

/// Verify a WebAuthn assertion/registration signature.
///
/// `message` is the signed input `authenticatorData || SHA-256(clientDataJSON)`
/// (the caller concatenates them). The algorithm is taken from the key variant:
///
/// - **Ed25519** — verified directly over `message` (EdDSA hashes internally).
/// - **ES256 (P-256)** — `message` is SHA-256'd and verified; the WebAuthn
///   signature is ASN.1 **DER**-encoded, so it is parsed with
///   [`p256::ecdsa::Signature::from_der`].
/// - **RS256 (RSA)** — PKCS#1 v1.5 over SHA-256 of `message`.
///
/// # Errors
///
/// Returns an error when the signature is malformed for the key's algorithm or
/// fails verification.
pub fn verify_signature(
    public_key: &VerifyingPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    match public_key {
        VerifyingPublicKey::Ed25519(key) => {
            let sig = ed25519_dalek::Signature::from_slice(signature)
                .context("Ed25519 signature is malformed")?;
            key.verify(message, &sig)
                .context("Ed25519 signature verification failed")
        }
        VerifyingPublicKey::P256(key) => {
            use p256::ecdsa::signature::Verifier as _;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .context("ES256 signature is not valid ASN.1 DER")?;
            key.verify(message, &sig)
                .context("ES256 signature verification failed")
        }
        VerifyingPublicKey::Rsa(key) => {
            let digest = Sha256::digest(message);
            let scheme = rsa::Pkcs1v15Sign::new::<Sha256>();
            key.verify(scheme, &digest, signature)
                .context("RS256 signature verification failed")
        }
    }
}

/// Build the signed message `authenticatorData || SHA-256(clientDataJSON)`.
#[must_use]
pub fn signed_message(authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let client_hash = Sha256::digest(client_data_json);
    let mut message = Vec::with_capacity(authenticator_data.len() + client_hash.len());
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(&client_hash);
    message
}

/// The relying-party id and origin derived from the hub's external URL.
///
/// The **RP id** is the registrable host (the URL's host, e.g.
/// `hub.example.com`) — the `rpId` an authenticator binds a credential to and
/// the value `SHA-256(rpId)` in `authenticatorData` must match. The **origin**
/// is the full `scheme://host[:port]` that `clientDataJSON.origin` must equal.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    /// The relying-party id (the host of the external URL).
    pub id: String,
    /// The relying-party origin (`scheme://host[:port]`).
    pub origin: String,
}

/// Derive the [`RelyingParty`] (id + origin) from the hub's external URL.
///
/// # Errors
///
/// Returns an error when `external_url` is not a valid absolute URL with a host.
pub fn relying_party(external_url: &str) -> Result<RelyingParty> {
    let url = url::Url::parse(external_url).context("external_url is not a valid URL")?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("external_url has no host"))?
        .to_string();
    let origin = url.origin().ascii_serialization();
    Ok(RelyingParty { id: host, origin })
}

/// Generate a fresh random ceremony challenge, base64url-encoded (256 bits).
#[must_use]
pub fn new_challenge() -> String {
    use rand::Rng as _;
    let bytes: [u8; 32] = rand::rng().random();
    B64URL.encode(bytes)
}

// -- registration ceremony --------------------------------------------------

/// The options a registration ceremony hands the browser script, which feeds
/// them to `navigator.credentials.create({ publicKey: … })`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistrationChallenge {
    /// The random challenge, base64url-encoded.
    pub challenge: String,
    /// The relying-party id (the hub's registrable domain).
    pub rp_id: String,
    /// The relying-party display name.
    pub rp_name: String,
    /// The user handle (the user's id, base64url-encoded), opaque to the IdP.
    pub user_handle: String,
    /// The user's display name (their email), shown in the authenticator UI.
    pub user_name: String,
    /// base64url credential ids the user already registered, so the
    /// authenticator can refuse to create a duplicate (`excludeCredentials`).
    pub exclude_credentials: Vec<String>,
}

/// The browser's response to a registration ceremony, base64url-decoded by the
/// route handler before it reaches [`finish_registration`].
#[derive(Debug, Clone)]
pub struct RegistrationResponse {
    /// The raw `clientDataJSON` bytes.
    pub client_data_json: Vec<u8>,
    /// The raw `attestationObject` bytes (CBOR: `fmt`, `authData`, `attStmt`).
    pub attestation_object: Vec<u8>,
}

/// Begin a registration ceremony for `user`: stage a challenge and build the
/// options the browser script needs.
///
/// Stores a `kind = registration` challenge bound to the user (5-minute TTL),
/// and returns the [`RegistrationChallenge`] including the user's existing
/// credential ids so the authenticator excludes duplicates.
///
/// # Errors
///
/// Returns an error on database failure while staging the challenge or loading
/// the user's existing credentials.
pub async fn begin_registration(
    db: &Database,
    user_id: i64,
    user_name: &str,
    rp_id: &str,
    rp_name: &str,
) -> Result<RegistrationChallenge> {
    let challenge = new_challenge();
    db.create_webauthn_challenge(
        &challenge,
        Some(user_id),
        KIND_REGISTRATION,
        CHALLENGE_TTL_SECS,
    )
    .await?;
    let exclude_credentials = db
        .list_user_credentials(user_id)
        .await?
        .into_iter()
        .map(|c| c.credential_id)
        .collect();
    Ok(RegistrationChallenge {
        challenge,
        rp_id: rp_id.to_string(),
        rp_name: rp_name.to_string(),
        user_handle: B64URL.encode(user_id.to_le_bytes()),
        user_name: user_name.to_string(),
        exclude_credentials,
    })
}

/// The `attestationObject` CBOR structure (W3C §6.5).
#[derive(Debug, Deserialize)]
struct AttestationObject {
    /// The attestation statement format identifier; must be `"none"`.
    fmt: String,
    /// The `authenticatorData` bytes carrying the attested credential.
    #[serde(rename = "authData", with = "serde_bytes_compat")]
    auth_data: Vec<u8>,
}

/// Finish a registration ceremony, persisting the new credential.
///
/// Steps (W3C §7.1, narrowed to `attestation: none`):
///
/// 1. Decode the `attestationObject` (CBOR), and **require `fmt == "none"`** —
///    any attestation format (`packed`, `fido-u2f`, `tpm`, …) is rejected by
///    policy.
/// 2. Verify `clientDataJSON` (`type == webauthn.create`, challenge matches the
///    staged-and-now-consumed challenge, origin matches the RP origin).
/// 3. Verify `authenticatorData` (`rpIdHash == SHA-256(rp_id)`, `UP` set), and
///    require attested credential data to be present.
/// 4. Decode the COSE public key and persist the credential
///    ([`Database::add_webauthn_credential`]).
///
/// The staged challenge is consumed (single-use) at the top, so a replayed
/// registration response is rejected before any signature work.
///
/// Returns the base64url credential id of the stored credential.
///
/// # Errors
///
/// Returns an error when the challenge is unknown/expired/replayed, the
/// challenge was not staged for this user, `fmt != "none"`, any `clientDataJSON`
/// or `authenticatorData` check fails, the attested credential data is absent,
/// or the credential cannot be persisted.
pub async fn finish_registration(
    db: &Database,
    user_id: i64,
    rp_id: &str,
    expected_origin: &str,
    response: &RegistrationResponse,
    label: Option<&str>,
) -> Result<String> {
    // 0. Parse clientDataJSON first so we know which challenge to consume.
    let client_data = parse_client_data(&response.client_data_json)?;

    // 1. Consume the staged challenge (single-use; expiry + kind enforced).
    let staged = db
        .take_webauthn_challenge(&client_data.challenge, KIND_REGISTRATION)
        .await?
        .ok_or_else(|| anyhow!("unknown, expired, or replayed registration challenge"))?;
    if staged.user_id != Some(user_id) {
        bail!("registration challenge was not staged for this user");
    }

    // 2. Decode the attestation object; enforce the attestation: none policy.
    let attestation: AttestationObject =
        ciborium::de::from_reader(&response.attestation_object[..])
            .context("decoding attestationObject CBOR")?;
    if attestation.fmt != "none" {
        bail!(
            "attestation format {:?} is rejected; this relying party requires attestation: none",
            attestation.fmt
        );
    }

    // 3. Verify clientDataJSON against the freshly-consumed challenge.
    verify_client_data(
        &client_data,
        TYPE_CREATE,
        &staged.challenge,
        expected_origin,
    )?;

    // 4. Parse + verify authenticatorData, and require attested credential data.
    let auth_data = parse_authenticator_data(&attestation.auth_data)?;
    verify_authenticator_data(&auth_data, rp_id)?;
    let attested = auth_data
        .attested_cred_data
        .ok_or_else(|| anyhow!("registration authenticatorData carries no attested credential"))?;

    // 5. Persist the credential (base64url id, base64 COSE key).
    let credential_id = B64URL.encode(&attested.credential_id);
    let public_key = B64STD.encode(&attested.public_key_cbor);
    db.add_webauthn_credential(
        user_id,
        &credential_id,
        &public_key,
        i64::from(auth_data.sign_count),
        None,
        label,
    )
    .await?;
    Ok(credential_id)
}

// -- assertion (login) ceremony ---------------------------------------------

/// The options an assertion ceremony hands the browser script, which feeds them
/// to `navigator.credentials.get({ publicKey: … })`.
///
/// This RP uses **discoverable credentials (usernameless)**: no
/// `allowCredentials` list is returned, so the browser offers every passkey it
/// holds for the RP id and resolves the user from the presented credential. The
/// alternative (username-first with an `allowCredentials` allow-list) is not
/// used here — usernameless keeps the login page a single button and avoids
/// leaking which emails have passkeys.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AssertionChallenge {
    /// The random challenge, base64url-encoded.
    pub challenge: String,
    /// The relying-party id (the hub's registrable domain).
    pub rp_id: String,
}

/// The browser's response to an assertion ceremony, base64url-decoded by the
/// route handler before it reaches [`finish_assertion`].
#[derive(Debug, Clone)]
pub struct AssertionResponse {
    /// The base64url credential id the authenticator asserted with.
    pub credential_id: String,
    /// The raw `clientDataJSON` bytes.
    pub client_data_json: Vec<u8>,
    /// The raw `authenticatorData` bytes.
    pub authenticator_data: Vec<u8>,
    /// The raw signature bytes.
    pub signature: Vec<u8>,
}

/// Begin an assertion (login) ceremony: stage a usernameless challenge.
///
/// Stores a `kind = assertion` challenge with `user_id = NULL` (the user is
/// resolved from the credential at verify), 5-minute TTL, and returns the
/// [`AssertionChallenge`].
///
/// # Errors
///
/// Returns an error on database failure while staging the challenge.
pub async fn begin_assertion(db: &Database, rp_id: &str) -> Result<AssertionChallenge> {
    let challenge = new_challenge();
    db.create_webauthn_challenge(&challenge, None, KIND_ASSERTION, CHALLENGE_TTL_SECS)
        .await?;
    Ok(AssertionChallenge {
        challenge,
        rp_id: rp_id.to_string(),
    })
}

/// Finish an assertion ceremony, returning the authenticated user id.
///
/// Steps (W3C §7.2):
///
/// 1. Look up the credential by its presented id; an unknown credential is
///    rejected.
/// 2. Consume the staged challenge (single-use; expiry + kind enforced).
/// 3. Verify `clientDataJSON` (`type == webauthn.get`, challenge matches,
///    origin matches).
/// 4. Verify `authenticatorData` (`rpIdHash`, `UP`).
/// 5. Verify the signature over `authenticatorData || SHA-256(clientDataJSON)`
///    with the stored COSE public key.
/// 6. **Enforce signature-counter monotonicity**: if the stored counter is
///    non-zero and the asserted counter is `<=` it, reject as a *cloned
///    authenticator*. A pair of zeros is allowed (some authenticators never
///    increment).
/// 7. Advance the stored counter and stamp `last_used_at`.
///
/// Returns the credential's owning user id; the caller mints the session.
///
/// # Errors
///
/// Returns an error when the credential is unknown, the challenge is
/// unknown/expired/replayed, any `clientDataJSON`/`authenticatorData` check
/// fails, the signature is invalid, or the counter regressed (clone detection).
pub async fn finish_assertion(
    db: &Database,
    rp_id: &str,
    expected_origin: &str,
    response: &AssertionResponse,
) -> Result<i64> {
    // 1. Resolve the credential (also yields the user — usernameless).
    let credential = db
        .webauthn_credential_by_id(&response.credential_id)
        .await?
        .ok_or_else(|| anyhow!("no passkey registered with that credential id"))?;

    // 2. Parse + consume the staged challenge.
    let client_data = parse_client_data(&response.client_data_json)?;
    let staged = db
        .take_webauthn_challenge(&client_data.challenge, KIND_ASSERTION)
        .await?
        .ok_or_else(|| anyhow!("unknown, expired, or replayed assertion challenge"))?;

    // 3. Verify clientDataJSON.
    verify_client_data(&client_data, TYPE_GET, &staged.challenge, expected_origin)?;

    // 4. Verify authenticatorData.
    let auth_data = parse_authenticator_data(&response.authenticator_data)?;
    verify_authenticator_data(&auth_data, rp_id)?;

    // 5. Verify the signature with the stored COSE key.
    let cose_cbor = B64STD
        .decode(&credential.public_key)
        .context("decoding stored COSE public key")?;
    let public_key = decode_cose_key(&cose_cbor)?;
    let message = signed_message(&response.authenticator_data, &response.client_data_json);
    verify_signature(&public_key, &message, &response.signature)?;

    // 6. Signature-counter monotonicity (clone detection).
    let stored = credential.sign_count;
    let asserted = i64::from(auth_data.sign_count);
    if stored > 0 && asserted <= stored {
        bail!(
            "signature counter regressed ({asserted} <= {stored}); possible cloned authenticator"
        );
    }

    // 7. Advance the counter + stamp last_used.
    db.update_credential_sign_count(credential.id, asserted)
        .await?;
    db.touch_credential(credential.id).await?;

    Ok(credential.user_id)
}

/// `serde` shim that accepts a CBOR byte string as `Vec<u8>`.
///
/// `ciborium` deserializes CBOR byte strings into `serde_bytes`-style sequences;
/// this adapter reads them as a plain `Vec<u8>` without pulling in the
/// `serde_bytes` crate.
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer};

    /// Deserialize a CBOR byte string into a `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error when the value is not a byte buffer.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = ciborium::value::Value::deserialize(deserializer)?;
        value
            .as_bytes()
            .cloned()
            .ok_or_else(|| serde::de::Error::custom("expected a CBOR byte string"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal software authenticator for tests: it mints a keypair, builds
    /// `authenticatorData` + `clientDataJSON`, and signs exactly as a real
    /// authenticator would, so the full ceremony can round-trip in-process.
    enum SoftAuthenticator {
        Ed25519 {
            signing: ed25519_dalek::SigningKey,
            credential_id: Vec<u8>,
        },
        P256 {
            signing: p256::ecdsa::SigningKey,
            credential_id: Vec<u8>,
        },
    }

    impl SoftAuthenticator {
        fn ed25519(cred_id: &[u8]) -> Self {
            let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            SoftAuthenticator::Ed25519 {
                signing,
                credential_id: cred_id.to_vec(),
            }
        }

        fn p256(cred_id: &[u8]) -> Self {
            // Deterministic 32-byte scalar (non-zero, < order) for reproducibility.
            let scalar = [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F, 0x10, 0x20,
            ];
            let signing = p256::ecdsa::SigningKey::from_bytes((&scalar).into()).unwrap();
            SoftAuthenticator::P256 {
                signing,
                credential_id: cred_id.to_vec(),
            }
        }

        fn credential_id(&self) -> &[u8] {
            match self {
                SoftAuthenticator::Ed25519 { credential_id, .. }
                | SoftAuthenticator::P256 { credential_id, .. } => credential_id,
            }
        }

        /// The COSE public key bytes for this authenticator's credential.
        fn cose_public_key(&self) -> Vec<u8> {
            use ciborium::value::{Integer, Value};
            let map = match self {
                SoftAuthenticator::Ed25519 { signing, .. } => {
                    let vk = signing.verifying_key();
                    vec![
                        (
                            Value::Integer(Integer::from(1)),
                            Value::Integer(Integer::from(1)),
                        ), // kty OKP
                        (
                            Value::Integer(Integer::from(3)),
                            Value::Integer(Integer::from(-8)),
                        ), // alg EdDSA
                        (
                            Value::Integer(Integer::from(-1)),
                            Value::Integer(Integer::from(6)),
                        ), // crv Ed25519
                        (
                            Value::Integer(Integer::from(-2)),
                            Value::Bytes(vk.to_bytes().to_vec()),
                        ),
                    ]
                }
                SoftAuthenticator::P256 { signing, .. } => {
                    let vk = signing.verifying_key();
                    let point = vk.to_encoded_point(false);
                    let x = point.x().unwrap().to_vec();
                    let y = point.y().unwrap().to_vec();
                    vec![
                        (
                            Value::Integer(Integer::from(1)),
                            Value::Integer(Integer::from(2)),
                        ), // kty EC2
                        (
                            Value::Integer(Integer::from(3)),
                            Value::Integer(Integer::from(-7)),
                        ), // alg ES256
                        (
                            Value::Integer(Integer::from(-1)),
                            Value::Integer(Integer::from(1)),
                        ), // crv P-256
                        (Value::Integer(Integer::from(-2)), Value::Bytes(x)),
                        (Value::Integer(Integer::from(-3)), Value::Bytes(y)),
                    ]
                }
            };
            let mut out = Vec::new();
            ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
            out
        }

        /// Build `authenticatorData`. With `attested`, embeds the credential
        /// (registration); otherwise just the 37-byte header (assertion).
        fn authenticator_data(&self, rp_id: &str, sign_count: u32, attested: bool) -> Vec<u8> {
            let mut data = Vec::new();
            data.extend_from_slice(Sha256::digest(rp_id.as_bytes()).as_slice());
            let flags = if attested { 0x01 | 0x40 } else { 0x01 }; // UP, + AT on register
            data.push(flags);
            data.extend_from_slice(&sign_count.to_be_bytes());
            if attested {
                data.extend_from_slice(&[0u8; 16]); // aaguid
                let cred_id = self.credential_id();
                data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
                data.extend_from_slice(cred_id);
                data.extend_from_slice(&self.cose_public_key());
            }
            data
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            match self {
                SoftAuthenticator::Ed25519 { signing, .. } => {
                    use ed25519_dalek::Signer as _;
                    signing.sign(message).to_bytes().to_vec()
                }
                SoftAuthenticator::P256 { signing, .. } => {
                    use p256::ecdsa::signature::Signer as _;
                    let sig: p256::ecdsa::Signature = signing.sign(message);
                    sig.to_der().as_bytes().to_vec()
                }
            }
        }
    }

    fn client_data_json(ty: &str, challenge: &str, origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{ty}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        )
        .into_bytes()
    }

    fn attestation_object(auth_data: &[u8], fmt: &str) -> Vec<u8> {
        use ciborium::value::{Integer, Value};
        let map = vec![
            (Value::Text("fmt".into()), Value::Text(fmt.into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (
                Value::Text("authData".into()),
                Value::Bytes(auth_data.to_vec()),
            ),
        ];
        let _ = Integer::from(0);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    const RP_ID: &str = "hub.example.com";
    const ORIGIN: &str = "https://hub.example.com";

    async fn register(db: &Database, user: i64, auth: &SoftAuthenticator) -> Result<String> {
        let challenge = begin_registration(db, user, "u@x.com", RP_ID, "Hub")
            .await?
            .challenge;
        let auth_data = auth.authenticator_data(RP_ID, 0, true);
        let cdj = client_data_json(TYPE_CREATE, &challenge, ORIGIN);
        let response = RegistrationResponse {
            client_data_json: cdj,
            attestation_object: attestation_object(&auth_data, "none"),
        };
        finish_registration(db, user, RP_ID, ORIGIN, &response, Some("yubikey")).await
    }

    async fn assert_login(
        db: &Database,
        auth: &SoftAuthenticator,
        sign_count: u32,
        origin: &str,
        tamper_challenge: Option<&str>,
        tamper_sig: bool,
    ) -> Result<i64> {
        let challenge = begin_assertion(db, RP_ID).await?.challenge;
        let used_challenge = tamper_challenge.map_or(challenge, str::to_string);
        let auth_data = auth.authenticator_data(RP_ID, sign_count, false);
        let cdj = client_data_json(TYPE_GET, &used_challenge, origin);
        let message = signed_message(&auth_data, &cdj);
        let mut signature = auth.sign(&message);
        if tamper_sig {
            signature[0] ^= 0xFF;
        }
        let response = AssertionResponse {
            credential_id: B64URL.encode(auth.credential_id()),
            client_data_json: cdj,
            authenticator_data: auth_data,
            signature,
        };
        finish_assertion(db, RP_ID, ORIGIN, &response).await
    }

    #[tokio::test]
    async fn ed25519_register_then_assert_roundtrip() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("u@x.com", None).await.unwrap();
        let auth = SoftAuthenticator::ed25519(b"ed-cred-1");
        let cred_id = register(&db, user, &auth).await.unwrap();
        assert!(!cred_id.is_empty());
        let got = assert_login(&db, &auth, 1, ORIGIN, None, false)
            .await
            .unwrap();
        assert_eq!(got, user);
    }

    #[tokio::test]
    async fn es256_register_then_assert_roundtrip() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("u@x.com", None).await.unwrap();
        let auth = SoftAuthenticator::p256(b"p256-cred-1");
        register(&db, user, &auth).await.unwrap();
        let got = assert_login(&db, &auth, 1, ORIGIN, None, false)
            .await
            .unwrap();
        assert_eq!(got, user);
    }

    #[tokio::test]
    async fn wrong_origin_rejected() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("u@x.com", None).await.unwrap();
        let auth = SoftAuthenticator::ed25519(b"ed-cred-2");
        register(&db, user, &auth).await.unwrap();
        let err = assert_login(&db, &auth, 1, "https://evil.example.com", None, false).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn wrong_challenge_rejected() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("u@x.com", None).await.unwrap();
        let auth = SoftAuthenticator::ed25519(b"ed-cred-3");
        register(&db, user, &auth).await.unwrap();
        // Present a different challenge than the one staged (and signed).
        let err = assert_login(&db, &auth, 1, ORIGIN, Some("bogus-challenge"), false).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("u@x.com", None).await.unwrap();
        let auth = SoftAuthenticator::p256(b"p256-cred-2");
        register(&db, user, &auth).await.unwrap();
        let err = assert_login(&db, &auth, 1, ORIGIN, None, true).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn non_none_attestation_rejected() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("u@x.com", None).await.unwrap();
        let auth = SoftAuthenticator::ed25519(b"ed-cred-4");
        let challenge = begin_registration(&db, user, "u@x.com", RP_ID, "Hub")
            .await
            .unwrap()
            .challenge;
        let auth_data = auth.authenticator_data(RP_ID, 0, true);
        let cdj = client_data_json(TYPE_CREATE, &challenge, ORIGIN);
        let response = RegistrationResponse {
            client_data_json: cdj,
            attestation_object: attestation_object(&auth_data, "packed"),
        };
        let err = finish_registration(&db, user, RP_ID, ORIGIN, &response, None).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn sign_count_rollback_rejected() {
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("u@x.com", None).await.unwrap();
        let auth = SoftAuthenticator::ed25519(b"ed-cred-5");
        register(&db, user, &auth).await.unwrap();
        // First assertion advances the stored counter to 5.
        assert_login(&db, &auth, 5, ORIGIN, None, false)
            .await
            .unwrap();
        // A later assertion at counter 3 is a regression -> cloned authenticator.
        let err = assert_login(&db, &auth, 3, ORIGIN, None, false).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn challenge_is_single_use() {
        let db = Database::open_in_memory().await.unwrap();
        db.create_webauthn_challenge("abc", None, KIND_ASSERTION, CHALLENGE_TTL_SECS)
            .await
            .unwrap();
        assert!(db
            .take_webauthn_challenge("abc", KIND_ASSERTION)
            .await
            .unwrap()
            .is_some());
        // Replay finds nothing.
        assert!(db
            .take_webauthn_challenge("abc", KIND_ASSERTION)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn unknown_credential_rejected() {
        let db = Database::open_in_memory().await.unwrap();
        let auth = SoftAuthenticator::ed25519(b"never-registered");
        let err = assert_login(&db, &auth, 1, ORIGIN, None, false).await;
        assert!(err.is_err());
    }

    #[test]
    fn cose_roundtrip_ed25519_and_p256() {
        let ed = SoftAuthenticator::ed25519(b"x");
        let key = decode_cose_key(&ed.cose_public_key()).unwrap();
        assert!(matches!(key, VerifyingPublicKey::Ed25519(_)));
        let p = SoftAuthenticator::p256(b"x");
        let key = decode_cose_key(&p.cose_public_key()).unwrap();
        assert!(matches!(key, VerifyingPublicKey::P256(_)));
    }

    /// Build a COSE RSA (kty=3) key CBOR with modulus `n` and exponent `e`.
    fn cose_rsa(n: &[u8], e: &[u8]) -> Vec<u8> {
        use ciborium::value::{Integer, Value};
        let map = vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(3)),
            ), // kty = RSA
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-257)),
            ), // alg RS256
            (Value::Integer(Integer::from(-1)), Value::Bytes(n.to_vec())), // n
            (Value::Integer(Integer::from(-2)), Value::Bytes(e.to_vec())), // e
        ];
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    /// Re-encode a COSE key CBOR map with the `alg` (label 3) entry replaced by
    /// `new_alg`, preserving every other entry. Used to forge an inconsistent or
    /// unsupported algorithm label.
    fn cose_with_alg(cose: &[u8], new_alg: i64) -> Vec<u8> {
        use ciborium::value::{Integer, Value};
        let value: Value = ciborium::de::from_reader(cose).unwrap();
        let mut map = value.as_map().unwrap().clone();
        for (k, v) in &mut map {
            if matches!(k, Value::Integer(i) if i128::from(*i) == 3) {
                *v = Value::Integer(Integer::from(new_alg));
            }
        }
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    #[test]
    fn cose_rejects_unsupported_and_inconsistent_alg() {
        // Supported, consistent keys decode (sanity: the helper preserves them).
        let ed = SoftAuthenticator::ed25519(b"x").cose_public_key();
        let p = SoftAuthenticator::p256(b"x").cose_public_key();
        assert!(decode_cose_key(&ed).is_ok());
        assert!(decode_cose_key(&p).is_ok());

        // An algorithm outside the supported set is rejected (ES384 = -35).
        assert!(
            decode_cose_key(&cose_with_alg(&p, -35)).is_err(),
            "an unsupported alg must be rejected"
        );

        // An EC2 (P-256) key labelled EdDSA (-8) is inconsistent -> rejected.
        assert!(
            decode_cose_key(&cose_with_alg(&p, -8)).is_err(),
            "alg=-8 on an EC2 key must be rejected"
        );
        // An OKP (Ed25519) key labelled ES256 (-7) is inconsistent -> rejected.
        assert!(
            decode_cose_key(&cose_with_alg(&ed, -7)).is_err(),
            "alg=-7 on an OKP key must be rejected"
        );
        // An OKP key labelled RS256 (-257) is inconsistent -> rejected.
        assert!(
            decode_cose_key(&cose_with_alg(&ed, -257)).is_err(),
            "alg=-257 on an OKP key must be rejected"
        );
    }

    #[tokio::test]
    async fn register_rejects_inconsistent_alg_credential() {
        // A full registration whose attested COSE key carries an inconsistent
        // alg must be refused at finish_registration, not just at decode.
        let db = Database::open_in_memory().await.unwrap();
        let user = db.create_user("u@x.com", None).await.unwrap();
        let auth = SoftAuthenticator::p256(b"p256-badalg");
        let challenge = begin_registration(&db, user, "u@x.com", RP_ID, "Hub")
            .await
            .unwrap()
            .challenge;
        // Build attested authenticatorData, then rewrite the embedded COSE key's
        // alg to an inconsistent value (-8 EdDSA on an EC2 key). The COSE key is
        // the trailing bytes of the attested authData.
        let auth_data = auth.authenticator_data(RP_ID, 0, true);
        let good_cose = auth.cose_public_key();
        let bad_cose = cose_with_alg(&good_cose, -8);
        let split = auth_data.len() - good_cose.len();
        let mut tampered = auth_data[..split].to_vec();
        tampered.extend_from_slice(&bad_cose);
        let cdj = client_data_json(TYPE_CREATE, &challenge, ORIGIN);
        let response = RegistrationResponse {
            client_data_json: cdj,
            attestation_object: attestation_object(&tampered, "none"),
        };
        let err = finish_registration(&db, user, RP_ID, ORIGIN, &response, None).await;
        assert!(
            err.is_err(),
            "inconsistent-alg registration must be refused"
        );
    }

    #[test]
    fn cose_rsa_rejects_weak_modulus_and_exponent() {
        // A 1024-bit modulus (128 bytes, high bit set) with F4 exponent: too
        // short, rejected.
        let mut small_n = vec![0u8; 128];
        small_n[0] = 0x80;
        let f4 = 65_537u32.to_be_bytes().to_vec();
        let f4 = f4.into_iter().skip_while(|&b| b == 0).collect::<Vec<_>>();
        assert!(
            decode_cose_key(&cose_rsa(&small_n, &f4)).is_err(),
            "a 1024-bit modulus must be rejected"
        );

        // A 2048-bit modulus (256 bytes, high bit set) with F4 is accepted.
        let mut big_n = vec![0u8; 256];
        big_n[0] = 0x80;
        big_n[255] = 1; // odd modulus, as RSA moduli are
        assert!(
            decode_cose_key(&cose_rsa(&big_n, &f4)).is_ok(),
            "a 2048-bit modulus with F4 exponent must be accepted"
        );

        // A 2048-bit modulus with an even exponent (2) is rejected.
        assert!(
            decode_cose_key(&cose_rsa(&big_n, &[2])).is_err(),
            "an even/small exponent must be rejected"
        );
        // Exponent 3 (odd but < 65537) is rejected.
        assert!(
            decode_cose_key(&cose_rsa(&big_n, &[3])).is_err(),
            "a small exponent must be rejected"
        );
    }
}
