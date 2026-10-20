//! Verifies the existing Controller genesis signature as comparison DATA.
//!
//! This is the single strict/mixed verifier used by native Root and existing
//! held Controller/Source consumers. A caller supplies its independently held
//! signer and original flight association. Verification creates no native
//! currentness, writer, completed flight or publication authority.
//!
//! ```text
//! AOSSGR01/02 (strict) or AOSSGR03/04 (Project) | version | signed phase |
//! signer generation | Controller/Source UIDs | both sequences | nonce |
//! immutable acceptance | both physical names | Source instance | signature
//! ```

use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1;
use ed25519_dalek::{Signature, VerifyingKey};

use super::SourceSignerGenesisDataErrorV1;

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], SourceSignerGenesisDataErrorV1> {
    crate::data::take(bytes, offset).map_err(SourceSignerGenesisDataErrorV1::from)
}

/// Names the original strict signed comparison frame.
#[doc(hidden)]
pub const MAGIC: &[u8; 8] = b"AOSSGR01";
/// Names the original strict signature and protected writer domain.
#[doc(hidden)]
pub const DOMAIN: &[u8] = b"aos.sandbox.source-genesis.controller-held-readback.v1\0/var/lib/aos/sandboxd/controller.journal\0";
/// Names the strict full-resource signature and writer domain.
#[doc(hidden)]
pub const RESOURCE_DOMAIN_V2: &[u8] = b"aos.sandbox.source-genesis.controller-held-readback.v2\0/var/lib/aos/sandboxd/controller.journal\0";
/// Bounds the original unsigned legacy body.
#[doc(hidden)]
pub use aos_sandbox_protocol::source_genesis_geometry::CONTROLLER_SOURCE_GENESIS_BODY_BYTES_V1 as BODY_BYTES;
/// Names the distinct Project comparison frame.
#[doc(hidden)]
pub const PROJECT_MAGIC_V3: &[u8; 8] = b"AOSSGR03";
/// Names the distinct Project signature and writer domain.
#[doc(hidden)]
pub const PROJECT_DOMAIN_V3: &[u8] = b"aos.sandbox.source-genesis.controller-mixed-readback.v3\0/var/lib/aos/sandboxd/controller.journal\0";
/// Names the full-resource Project comparison frame.
#[doc(hidden)]
pub const PROJECT_RESOURCE_MAGIC_V4: &[u8; 8] = b"AOSSGR04";
/// Names the full-resource Project signature and writer domain.
#[doc(hidden)]
pub const PROJECT_RESOURCE_DOMAIN_V4: &[u8] = b"aos.sandbox.source-genesis.controller-mixed-resource-readback.v4\0/var/lib/aos/sandboxd/controller.journal\0";

/// Selects the existing distinct strict or mixed signed comparison grammar.
#[derive(Clone, Copy)]
pub enum ControllerGenesisReadbackRecipeV3 {
    /// Checks the original global strict signed purpose.
    StrictV1,
    /// Checks the distinct selected Project signed purpose.
    ProjectV3,
}
/// Bounds the existing Controller-purpose genesis readback signature packet.
pub use aos_sandbox_protocol::source_genesis_geometry::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1;
/// Bounds the distinct strict Controller signature retaining full SGC02 input.
pub use aos_sandbox_protocol::source_genesis_geometry::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2;
/// Bounds the existing Project-purpose readback with a complete SGC02 input.
pub use aos_sandbox_protocol::source_genesis_geometry::CONTROLLER_PROJECT_RESOURCE_READBACK_BYTES_V4;

/// Retains verified comparison DATA without a current Root or held writer.
pub struct ControllerGenesisReadbackDataV1 {
    /// Complete immutable administrative acceptance.
    pub acceptance: ControllerSourceGenesisAcceptanceRecordV1,
    /// Whether the signed phase names retained history.
    pub historical: bool,
    /// Whether the signed phase reports durable Controller Complete.
    pub completed: bool,
    /// Whether the signed phase reports a vacant target.
    pub vacant: bool,
    /// Exact existing Source instance, absent only for global Empty.
    pub source_instance: Option<[u8; 32]>,
    /// Signed Source physical-name comparison.
    pub source_names: ProtectedJournalNamesV1,
    /// Signed Source next-sequence comparison.
    pub source_sequence: u64,
}

/// Checks the exact existing signature grammar and original comparison fields.
///
/// # Errors
/// Refuses noncanonical framing, phase, signer generation, UIDs, sequence,
/// nonce, accepted input, physical names, Source instance or signature.
pub fn verify_controller_source_genesis_readback_v1(
    packet: &[u8],
    generation: u64,
    key: &VerifyingKey,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
    recipe: ControllerGenesisReadbackRecipeV3,
) -> Result<ControllerGenesisReadbackDataV1, SourceSignerGenesisDataErrorV1> {
    let resource_version = packet.len() == CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2;
    let (magic, version, domain) = match recipe {
        ControllerGenesisReadbackRecipeV3::StrictV1 if resource_version => {
            (b"AOSSGR02" as &[u8; 8], 2_u16, RESOURCE_DOMAIN_V2)
        }
        ControllerGenesisReadbackRecipeV3::StrictV1 => (MAGIC, 1_u16, DOMAIN),
        ControllerGenesisReadbackRecipeV3::ProjectV3 if resource_version => {
            (PROJECT_RESOURCE_MAGIC_V4, 4_u16, PROJECT_RESOURCE_DOMAIN_V4)
        }
        ControllerGenesisReadbackRecipeV3::ProjectV3 => {
            (PROJECT_MAGIC_V3, 3_u16, PROJECT_DOMAIN_V3)
        }
    };
    let packet_bytes = if resource_version {
        CONTROLLER_PROJECT_RESOURCE_READBACK_BYTES_V4
    } else {
        CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1
    };
    if packet.len() != packet_bytes
        || packet.get(..8) != Some(magic.as_slice())
        || packet[8..10] != version.to_be_bytes()
        || packet[10] > 3
        || matches!(recipe, ControllerGenesisReadbackRecipeV3::ProjectV3) && packet[10] == 0
        || packet[11..16] != [0; 5]
        || nonce == [0; 16]
        || controller_uid == 0
        || source_uid == 0
        || u64::from_be_bytes(take(packet, 16)?) != generation
        || u32::from_be_bytes(take(packet, 24)?) != controller_uid
        || u32::from_be_bytes(take(packet, 28)?) != source_uid
        || u64::from_be_bytes(take(packet, 32)?) == 0
        || u64::from_be_bytes(take(packet, 40)?) == 0
        || take::<16>(packet, 48)? != nonce
    {
        return Err(SourceSignerGenesisDataErrorV1::NonCanonical);
    }
    let body_bytes = packet_bytes - 64;
    let names_offset = body_bytes - 128;
    ProtectedJournalNamesV1::from_bytes(&packet[names_offset..names_offset + 48])
        .map_err(SourceSignerGenesisDataErrorV1::from)?;
    let source_names =
        ProtectedJournalNamesV1::from_bytes(&packet[names_offset + 48..names_offset + 96])
            .map_err(SourceSignerGenesisDataErrorV1::from)?;
    let acceptance =
        ControllerSourceGenesisAcceptanceRecordV1::from_record_bytes(&packet[64..names_offset])
            .map_err(crate::data::SourceSuccessorDataErrorV2::from)?;
    let source_instance = take::<32>(packet, names_offset + 96)?;
    if (packet[10] == 0) != (source_instance == [0; 32])
        || acceptance.resource_envelope().is_some() != resource_version
    {
        return Err(SourceSignerGenesisDataErrorV1::NonCanonical);
    }
    key.verify_strict(
        &[domain, &packet[..body_bytes]].concat(),
        &Signature::from_bytes(&take(packet, body_bytes)?),
    )
    .map_err(|_| SourceSignerGenesisDataErrorV1::NonCanonical)?;
    Ok(ControllerGenesisReadbackDataV1 {
        acceptance,
        historical: matches!(packet[10], 1 | 3),
        completed: packet[10] == 3,
        vacant: packet[10] == 2,
        source_instance: (source_instance != [0; 32]).then_some(source_instance),
        source_names,
        source_sequence: u64::from_be_bytes(take(packet, 40)?),
    })
}
