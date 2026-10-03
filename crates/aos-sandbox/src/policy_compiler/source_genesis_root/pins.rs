//! Fixed independent administrative and observation pins for the Root owner.
//!
//! The complete canonical tuple is retained by Root before its first instance
//! or intent. Readback signer roles cannot issue either administrative input.
//! Historical recovery still requires these independently held exact pins;
//! a packet, receipt, or decoded floor cannot supply a replacement trust root.

use aos_sandbox_core::ObjectDigest;

use crate::hierarchy::genesis_profile::{
    ControllerSourceGenesisAcceptanceRecordV1, SourceGenesisErrorV1, hash,
};
use crate::hierarchy::source_seed::{
    ControllerSourceTreeSeedExpectedV1, PinnedControllerSourceTreeSeedIssuerV1,
    verify_controller_source_tree_seed_v1,
};
use crate::journal::{Journal, RecordNamespace};
use crate::public_api_session::PinnedSystemdCredential;
use crate::publisher_policy::{
    PinnedPublisherProjectAuthorizationIssuerV2, verify_signed_project_authorization_claims_v2,
};

use super::super::controller_hold_pin::CONTROLLER_HOLD_PIN_KEY;
use super::super::deployment_head::{SIGNER_PINS_KEY, decode_policy_signer_pins_v1};
use super::super::source_hold_pin::SOURCE_HOLD_PIN_KEY;
use super::super::{PinnedControllerHoldSignerV1, PinnedSourceHoldReadbackSignerV1};

const MAGIC: &[u8; 8] = b"AOSGPK01";
const DOMAIN: &[u8] = b"aos.sandbox.source-genesis.root-role-pins.v1\0";
const ADMINISTRATIVE_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.administrative-roles.v1\0";
const BYTES: usize = 488;

pub(super) struct RootGenesisRolePinsV1 {
    encoded: [u8; BYTES],
    seed_file: PinnedSystemdCredential,
    authorization_file: PinnedSystemdCredential,
    pub(super) controller: PinnedControllerHoldSignerV1,
    pub(super) source: PinnedSourceHoldReadbackSignerV1,
}

impl RootGenesisRolePinsV1 {
    pub(super) fn load(journal: &Journal) -> Result<Self, SourceGenesisErrorV1> {
        super::capacity::require_owner(journal)?;
        let seed_file = PinnedSystemdCredential::load_controller_source_tree_seed_issuer_v1()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let authorization_file = PinnedSystemdCredential::load_project_authorization_issuer_v2()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let seed: [u8; 80] = seed_file
            .bytes()
            .try_into()
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let authorization: [u8; 80] = authorization_file
            .bytes()
            .try_into()
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let controller: [u8; 80] = journal
            .get(RecordNamespace::DesiredState, CONTROLLER_HOLD_PIN_KEY)
            .ok_or(SourceGenesisErrorV1::Stale)?
            .try_into()
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let source: [u8; 80] = journal
            .get(RecordNamespace::DesiredState, SOURCE_HOLD_PIN_KEY)
            .ok_or(SourceGenesisErrorV1::Stale)?
            .try_into()
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let deployment: [u8; 120] = journal
            .get(RecordNamespace::DesiredState, SIGNER_PINS_KEY)
            .ok_or(SourceGenesisErrorV1::Stale)?
            .try_into()
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let encoded = encode(&seed, &authorization, &controller, &source, &deployment)?;
        let retained = Self {
            controller: PinnedControllerHoldSignerV1::decode(&controller)
                .map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
            source: PinnedSourceHoldReadbackSignerV1::decode(&source)
                .map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
            encoded,
            seed_file,
            authorization_file,
        };
        retained.recheck(journal)?;
        Ok(retained)
    }

    pub(super) fn recheck(&self, journal: &Journal) -> Result<(), SourceGenesisErrorV1> {
        super::capacity::require_owner(journal)?;
        self.seed_file
            .recheck()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        self.authorization_file
            .recheck()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        if journal.get(RecordNamespace::DesiredState, CONTROLLER_HOLD_PIN_KEY)
            != Some(&self.encoded[176..256])
            || journal.get(RecordNamespace::DesiredState, SOURCE_HOLD_PIN_KEY)
                != Some(&self.encoded[256..336])
            || journal.get(RecordNamespace::DesiredState, SIGNER_PINS_KEY)
                != Some(&self.encoded[336..456])
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    pub(super) fn record_bytes(&self) -> &[u8; BYTES] {
        &self.encoded
    }

    pub(super) fn digest(&self) -> ObjectDigest {
        hash(DOMAIN, &self.encoded)
    }

    pub(super) fn verify_administrative_input(
        &self,
        acceptance: &ControllerSourceGenesisAcceptanceRecordV1,
    ) -> Result<(), SourceGenesisErrorV1> {
        let seed_pin = PinnedControllerSourceTreeSeedIssuerV1::decode(&self.encoded[16..96])?;
        let authorization_pin =
            PinnedPublisherProjectAuthorizationIssuerV2::decode(&self.encoded[96..176])?;
        let seed = acceptance.seed_claims()?;
        let expected = ControllerSourceTreeSeedExpectedV1::new(
            seed.project(),
            seed.publisher_generation(),
            seed.publisher_head(),
            seed.project_authorization_head(),
            seed.request_id(),
            seed.epoch() - 1,
        )?;
        verify_controller_source_tree_seed_v1(acceptance.seed_packet(), &seed_pin, expected)?;
        verify_signed_project_authorization_claims_v2(
            acceptance.auth_packet(),
            &authorization_pin,
        )?;
        if acceptance.administrative_roles() != hash(ADMINISTRATIVE_DOMAIN, &self.encoded[16..176])
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }
}

pub(super) fn role_tuple_digest(bytes: &[u8]) -> Result<ObjectDigest, SourceGenesisErrorV1> {
    decode(bytes)?;
    Ok(hash(DOMAIN, bytes))
}

fn encode(
    seed: &[u8; 80],
    authorization: &[u8; 80],
    controller: &[u8; 80],
    source: &[u8; 80],
    deployment: &[u8; 120],
) -> Result<[u8; BYTES], SourceGenesisErrorV1> {
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    for (range, value) in [
        (16..96, seed.as_slice()),
        (96..176, authorization.as_slice()),
        (176..256, controller.as_slice()),
        (256..336, source.as_slice()),
        (336..456, deployment.as_slice()),
    ] {
        bytes[range].copy_from_slice(value);
    }
    let checksum = hash(DOMAIN, &bytes[..456]);
    bytes[456..].copy_from_slice(checksum.as_bytes());
    decode(&bytes)?;
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
    if bytes.len() != BYTES
        || bytes.get(..8) != Some(MAGIC.as_slice())
        || bytes[8..16] != [0, 1, 0, 0, 0, 0, 0, 0]
        || hash(DOMAIN, &bytes[..456]).as_bytes() != &bytes[456..]
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let seed = PinnedControllerSourceTreeSeedIssuerV1::decode(&bytes[16..96])?;
    let authorization = PinnedPublisherProjectAuthorizationIssuerV2::decode(&bytes[96..176])?;
    let controller = PinnedControllerHoldSignerV1::decode(&bytes[176..256])
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let source = PinnedSourceHoldReadbackSignerV1::decode(&bytes[256..336])
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let (_, deployment, _, project) = decode_policy_signer_pins_v1(&bytes[336..456])
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let keys = [
        seed.verifying_key(),
        authorization.verifying_key(),
        controller.verifying_key(),
        source.verifying_key(),
        &deployment,
        &project,
    ];
    for (index, key) in keys.iter().enumerate() {
        if keys[..index].contains(key) {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
    }
    Ok(())
}
