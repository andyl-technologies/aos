//! Fixed independent administrative and observation pins for the Root owner.
//!
//! The complete canonical tuple is retained by Root before its first instance
//! or intent. Readback signer roles cannot issue either administrative input.
//! Historical recovery still requires these independently held exact pins;
//! a packet, receipt, or decoded floor cannot supply a replacement trust root.

use aos_sandbox_policy::journal_keys::{
    CONTROLLER_HOLD_PIN_KEY, SIGNER_PINS_KEY, SOURCE_HOLD_PIN_KEY,
};

use aos_sandbox_policy::controller_readback::PinnedControllerHoldSignerV1;

use aos_sandbox_protocol::publisher_project_authorization::{
    PinnedPublisherProjectAuthorizationIssuerV2,
    verify_signed_project_authorization_claims_v2,
};

use aos_sandbox_model::ObjectDigest;

use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1;
use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, hash};
use aos_sandbox_protocol::controller_source_seed::{
    ControllerSourceTreeSeedExpectedV1, PinnedControllerSourceTreeSeedIssuerV1,
    verify_controller_source_tree_seed_v1,
};
use crate::journal::{Journal, RecordNamespace};
use crate::public_api_session::PinnedSystemdCredential;


use super::super::deployment_head::decode_policy_signer_pins_v1;

use super::super::PinnedSourceHoldReadbackSignerV1;

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
        let pinned = role_pins_from_journal_v1(
            journal,
            seed_file.bytes(),
            authorization_file.bytes(),
        )?;
        let retained = Self {
            controller: pinned.controller,
            source: pinned.source,
            encoded: pinned.encoded,
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
        saved_role_digest_v1(&self.encoded)
    }

    pub(super) fn verify_administrative_input(
        &self,
        acceptance: &ControllerSourceGenesisAcceptanceRecordV1,
    ) -> Result<(), SourceGenesisErrorV1> {
        verify_administrative_input_data_v1(&self.encoded, acceptance)
    }

    // The administrative key is the SAME independently retained seed issuer,
    // never an issuer selected by an approval or Source observation.
    pub(super) fn verify_first_source_successor_v2(
        &self,
        packet: &aos_sandbox_ledger_replay::successor::SourceSuccessorApprovalDataV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        verify_retained_first_source_successor_v2(&self.encoded, packet)
    }
}

// Both the historical owner and the new receiving owner use this exact pure
// tuple construction. Each caller separately retains/checks its actual writer
// and independent credential originals; this DATA type grants no authority.
pub(in crate::policy_compiler) struct RootRolePinsDataV1 {
    pub(in crate::policy_compiler) encoded: [u8; BYTES],
    pub(in crate::policy_compiler) controller: PinnedControllerHoldSignerV1,
    pub(in crate::policy_compiler) source: PinnedSourceHoldReadbackSignerV1,
}

pub(in crate::policy_compiler) fn role_pins_from_journal_v1(
    journal: &Journal,
    seed: &[u8],
    authorization: &[u8],
) -> Result<RootRolePinsDataV1, SourceGenesisErrorV1> {
    let seed: &[u8; 80] = seed.try_into().map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let authorization: &[u8; 80] = authorization.try_into()
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let controller: &[u8; 80] = journal
        .get(RecordNamespace::DesiredState, CONTROLLER_HOLD_PIN_KEY)
        .ok_or(SourceGenesisErrorV1::Stale)?
        .try_into().map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let source: &[u8; 80] = journal
        .get(RecordNamespace::DesiredState, SOURCE_HOLD_PIN_KEY)
        .ok_or(SourceGenesisErrorV1::Stale)?
        .try_into().map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let deployment: &[u8; 120] = journal
        .get(RecordNamespace::DesiredState, SIGNER_PINS_KEY)
        .ok_or(SourceGenesisErrorV1::Stale)?
        .try_into().map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    Ok(RootRolePinsDataV1 {
        encoded: encode(seed, authorization, controller, source, deployment)?,
        controller: PinnedControllerHoldSignerV1::decode(controller)
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
        source: PinnedSourceHoldReadbackSignerV1::decode(source)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
    })
}

// Cold replay checks the same independently retained public tuple. This
// authenticates provenance only; freshness still belongs to the live owner.
pub(super) fn verify_retained_first_source_successor_v2(
    encoded: &[u8],
    packet: &aos_sandbox_ledger_replay::successor::SourceSuccessorApprovalDataV2,
) -> Result<(), SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::replay::root_genesis_pins::verify_retained_first_source_successor_v2(encoded, packet)
        .map_err(SourceGenesisErrorV1::from)
}

pub(super) fn role_tuple_digest(bytes: &[u8]) -> Result<ObjectDigest, SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::replay::root_genesis_pins::role_tuple_digest(bytes)
        .map_err(SourceGenesisErrorV1::from)
}

fn encode(
    seed: &[u8; 80],
    authorization: &[u8; 80],
    controller: &[u8; 80],
    source: &[u8; 80],
    deployment: &[u8; 120],
) -> Result<[u8; BYTES], SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::replay::root_genesis_pins::encode(seed, authorization, controller, source, deployment)
        .map_err(SourceGenesisErrorV1::from)
}

fn decode(bytes: &[u8]) -> Result<(), SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::replay::root_genesis_pins::decode(bytes)
        .map_err(SourceGenesisErrorV1::from)
}

// This is the old complete historical signature comparison over independently
// supplied saved tuple DATA. Actual credential and writer gates remain callers.
pub(super) fn verify_administrative_input_data_v1(encoded: &[u8; BYTES],
    acceptance: &ControllerSourceGenesisAcceptanceRecordV1,
) -> Result<(), SourceGenesisErrorV1> {
        let seed_pin = PinnedControllerSourceTreeSeedIssuerV1::decode(&encoded[16..96])?;
        let authorization_pin =
            PinnedPublisherProjectAuthorizationIssuerV2::decode(&encoded[96..176])
                .map_err(crate::publisher_admin::policy::ProjectAuthorizationSourceErrorV2::from)?;
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
        )
            .map_err(crate::publisher_admin::policy::ProjectAuthorizationSourceErrorV2::from)?;
        if acceptance.administrative_roles() != hash(ADMINISTRATIVE_DOMAIN, &encoded[16..176])
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
 }

pub(super) fn saved_role_digest_v1(encoded: &[u8]) -> ObjectDigest {
    hash(DOMAIN, encoded)
}
