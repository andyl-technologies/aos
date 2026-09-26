//! Protected, nonauthorizing terminal evidence for a Root-last Source flight.
//!
//! ```text
//! AOSSFT01 | version:u16=1 | reserved[6]=0 | AOSPCB02[664] |
//! stage-nonce[16] | stage-issue:u64 | Source-hold-fields[136] |
//! Root-Source-nonce[16] | Root-Source-issue:u64 | Source-names[48] |
//! Source-packet-digest[32] | Cache-packet-digest[32] |
//! Root-preview-digest[32] | client-nonce[16] | AOSCTW01[248] | SHA-256[32]
//! ```
//!
//! The row is historical evidence, not a transferable writer lease. In
//! particular, neither it nor cold replay permits AOSPCB02, release, Create,
//! or Apply.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    JournalRecord, JournalTransaction, ProtectedJournalNamesV1, RecordNamespace,
    SourceDomainPolicyHoldV1,
};
use crate::policy_compiler::controller_hold_pin::CONTROLLER_HOLD_PIN_KEY;
use crate::policy_compiler::controller_hold_readback::{
    CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1, ControllerHoldReadbackChallengeV1,
    PinnedControllerHoldSignerV1, verify_controller_hold_readback_v1,
};
use crate::policy_compiler::source_hold_readback::SourceHoldReadbackChallengeV1;

use super::held_proof::{KEY as HELD_PROOF_KEY, RECORD_BYTES as HELD_PROOF_BYTES, RootHeldProofV2};
use super::*;

const KEY: &[u8] = b"\0aos-policy-compiler-source-terminal-v1\0";
const MAGIC: &[u8; 8] = b"AOSSFT01";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.source-terminal-cut.v1\0";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.source-terminal-record.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.source-terminal-transaction.v1\0";
const CLAIM_BYTES: usize =
    CLOSED_POLICY_BINDING_BYTES_V2 + 16 + 8 + 136 + 16 + 8 + 48 + 32 * 3 + 16;
const BODY_BYTES: usize = 16 + CLAIM_BYTES + CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1;
/// Bounds the exact, nonauthorizing protected Root terminal record.
pub const CLOSED_SOURCE_TERMINAL_RECORD_BYTES_V1: usize = BODY_BYTES + 32;

/// Retains the exact Root-last flight facts without granting authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedSourceTerminalClaimV1 {
    proposed: [u8; CLOSED_POLICY_BINDING_BYTES_V2],
    staged: StagedClosedPolicyRootBaseV2,
    source_hold: SourceDomainPolicyHoldV1,
    source_challenge: SourceHoldReadbackChallengeV1,
    source_issue: u64,
    names: ProtectedJournalNamesV1,
    source_packet: ObjectDigest,
    cache_packet: ObjectDigest,
    preview_digest: ObjectDigest,
    client_nonce: [u8; 16],
}

impl ClosedSourceTerminalClaimV1 {
    /// Constructs a canonical, inert terminal claim for the exact held flight.
    ///
    /// # Errors
    ///
    /// Rejects malformed proposals, stale Source fields, or zero issuance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposed: &[u8],
        staged: StagedClosedPolicyRootBaseV2,
        source_hold: SourceDomainPolicyHoldV1,
        source_challenge: SourceHoldReadbackChallengeV1,
        source_issue: u64,
        names: ProtectedJournalNamesV1,
        source_packet: ObjectDigest,
        cache_packet: ObjectDigest,
        preview_digest: ObjectDigest,
        client_nonce: [u8; 16],
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        let proposed: [u8; CLOSED_POLICY_BINDING_BYTES_V2] = proposed
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let binding = ClosedPolicyRootBindingV2::decode(&proposed)?;
        let base = staged.base();
        let expected_cut = staged_closed_policy_signer_challenge_v2(staged, &proposed)?.cut();
        if binding.root_predecessor != base.predecessor()
            || binding.root_generation != base.next_generation()
            || binding.barrier_epoch != base.next_generation()
            || binding.handoff_epoch != base.next_generation()
            || !source_hold.is_held()
            || source_hold.operation() != binding.operation
            || source_hold.sandbox() != binding.sandbox
            || source_hold.ancestry() != binding.ancestry_head
            || source_hold.binding() != closed_policy_binding_digest_v2(&proposed)?
            || source_hold.epoch() != binding.handoff_epoch
            || source_challenge.cut() != expected_cut
            || source_issue == 0
            || client_nonce == [0; 16]
            || source_packet.as_bytes() == &[0; 32]
            || cache_packet.as_bytes() == &[0; 32]
            || preview_digest.as_bytes() == &[0; 32]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(Self {
            proposed,
            staged,
            source_hold,
            source_challenge,
            source_issue,
            names,
            source_packet,
            cache_packet,
            preview_digest,
            client_nonce,
        })
    }

    fn encode(self) -> [u8; CLAIM_BYTES] {
        let mut bytes = [0; CLAIM_BYTES];
        let mut offset = 0;
        for field in [
            self.proposed.as_slice(),
            self.staged.challenge().as_slice(),
            self.staged.issue_epoch().to_be_bytes().as_slice(),
            self.source_hold.operation().as_bytes(),
            self.source_hold.sandbox().as_bytes(),
            self.source_hold.controller_source().as_bytes(),
            self.source_hold.ancestry().as_bytes(),
            self.source_hold.binding().as_bytes(),
            self.source_hold.epoch().to_be_bytes().as_slice(),
            self.source_challenge.nonce().as_slice(),
            self.source_issue.to_be_bytes().as_slice(),
            self.names.to_bytes().as_slice(),
            self.source_packet.as_bytes(),
            self.cache_packet.as_bytes(),
            self.preview_digest.as_bytes(),
            self.client_nonce.as_slice(),
        ] {
            bytes[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        bytes
    }

    /// Returns the exact Root-spent Source challenge and held cut to be signed.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical derived challenge.
    pub fn controller_challenge(
        self,
    ) -> Result<ControllerHoldReadbackChallengeV1, PolicyCompilerJournalErrorV1> {
        let cut = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(CUT_DOMAIN)
                .chain_update(self.encode())
                .finalize()
                .into(),
        );
        ControllerHoldReadbackChallengeV1::new(self.source_challenge.nonce(), cut)
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
    }

    /// Predicts the protected row digest after signing, for exact lost-reply replay.
    ///
    /// This computation does not verify the packet; Root verifies it against
    /// its protected Controller pin before writing or replaying the row.
    ///
    /// # Errors
    ///
    /// Rejects a packet of the wrong length.
    pub fn record_digest_for_packet(
        self,
        packet: &[u8],
    ) -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(encode_terminal_record(self, packet)?).into(),
        ))
    }

    fn decode(
        bytes: &[u8],
        base: ClosedPolicyRootCasBaseV2,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if bytes.len() != CLAIM_BYTES {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let mut offset = 0;
        let proposed = take_claim::<CLOSED_POLICY_BINDING_BYTES_V2>(bytes, &mut offset)?;
        let staged = StagedClosedPolicyRootBaseV2::from_untrusted_remote_fields(
            base,
            take_claim::<16>(bytes, &mut offset)?,
            u64::from_be_bytes(take_claim::<8>(bytes, &mut offset)?),
        )?;
        let source_hold = SourceDomainPolicyHoldV1::new(
            OperationId::from_bytes(take_claim::<16>(bytes, &mut offset)?),
            SandboxId::from_bytes(take_claim::<16>(bytes, &mut offset)?),
            ObjectDigest::from_bytes(take_claim::<32>(bytes, &mut offset)?),
            ObjectDigest::from_bytes(take_claim::<32>(bytes, &mut offset)?),
            ObjectDigest::from_bytes(take_claim::<32>(bytes, &mut offset)?),
            u64::from_be_bytes(take_claim::<8>(bytes, &mut offset)?),
        )?;
        let nonce = take_claim::<16>(bytes, &mut offset)?;
        let source_issue = u64::from_be_bytes(take_claim::<8>(bytes, &mut offset)?);
        let names = ProtectedJournalNamesV1::from_bytes(&take_claim::<48>(bytes, &mut offset)?)?;
        let source_packet = ObjectDigest::from_bytes(take_claim::<32>(bytes, &mut offset)?);
        let cache_packet = ObjectDigest::from_bytes(take_claim::<32>(bytes, &mut offset)?);
        let preview_digest = ObjectDigest::from_bytes(take_claim::<32>(bytes, &mut offset)?);
        let client_nonce = take_claim::<16>(bytes, &mut offset)?;
        let cut = staged_closed_policy_signer_challenge_v2(staged, &proposed)?.cut();
        let source_challenge = SourceHoldReadbackChallengeV1::new(nonce, cut)
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        Self::new(
            &proposed,
            staged,
            source_hold,
            source_challenge,
            source_issue,
            names,
            source_packet,
            cache_packet,
            preview_digest,
            client_nonce,
        )
    }
}

/// Identifies one exact protected Root row; this is not a CAS credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedSourceTerminalRecordV1 {
    digest: ObjectDigest,
    held_proof: Option<ObjectDigest>,
}

impl ClosedSourceTerminalRecordV1 {
    /// Returns the checksum-protected record digest for ambiguous-reply replay.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }

    /// Returns an exact nonauthorizing AOSPCP02 companion when one was joined.
    #[must_use]
    pub const fn held_proof_digest(self) -> Option<ObjectDigest> {
        self.held_proof
    }
}

impl ClosedPolicyRootSessionV2<'_> {
    /// Records a Controller-only signed terminal receipt under the held Root writer.
    ///
    /// The caller retains every Controller, Source, Cache-journal, and physical
    /// Cache writer across this call. This V1 row lacks AOSPCP02 and is not
    /// used by the live V7 daemon; it is nonauthorizing.
    ///
    /// # Errors
    ///
    /// Rejects stale Root rows, a changed current Controller credential,
    /// mismatched signer evidence, or failed protected durability.
    pub fn record_staged_source_terminal_v1(
        &mut self,
        claim: ClosedSourceTerminalClaimV1,
        joined: ClosedPolicyRootSignerJoinV2,
        controller_uid: u32,
        current_controller_credential: &[u8],
        controller_packet: &[u8],
    ) -> Result<ClosedSourceTerminalRecordV1, PolicyCompilerJournalErrorV1> {
        self.record_terminal(
            claim,
            joined,
            controller_uid,
            current_controller_credential,
            controller_packet,
            None,
        )
    }

    /// Atomically retains the signed V7 terminal and protected Cache/Source join.
    ///
    /// The caller retains Controller, Source, protected Cache, and physical Cache
    /// writers through this call. AOSPCP02 is historical evidence only: it does
    /// not confer CAS, release, Create, Apply, or effect authority.
    ///
    /// # Errors
    ///
    /// Rejects a changed fixed Cache replay, stale Root or signer cut, changed
    /// current pin, or incomplete protected transaction/readback.
    pub fn record_staged_source_terminal_with_held_proof_v2(
        &mut self,
        claim: ClosedSourceTerminalClaimV1,
        joined: ClosedPolicyRootSignerJoinV2,
        controller_uid: u32,
        current_controller_credential: &[u8],
        controller_packet: &[u8],
    ) -> Result<ClosedSourceTerminalRecordV1, PolicyCompilerJournalErrorV1> {
        let before = read_fixed_policy_cache_hold_v1()
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let record = self.record_terminal(
            claim,
            joined,
            controller_uid,
            current_controller_credential,
            controller_packet,
            Some((before.hold, before.replay.quota_digest)),
        )?;
        let after = read_fixed_policy_cache_hold_v1()
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        if after.hold != before.hold || after.replay.quota_digest != before.replay.quota_digest {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(record)
    }

    fn record_terminal(
        &mut self,
        claim: ClosedSourceTerminalClaimV1,
        joined: ClosedPolicyRootSignerJoinV2,
        controller_uid: u32,
        current_controller_credential: &[u8],
        controller_packet: &[u8],
        cache_observation: Option<(CachePolicyHoldV1, ObjectDigest)>,
    ) -> Result<ClosedSourceTerminalRecordV1, PolicyCompilerJournalErrorV1> {
        self.validate_terminal_claim(claim, joined)?;
        if self.authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(current_controller_credential) {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let bytes = terminal_record_bytes(
            claim,
            controller_uid,
            current_controller_credential,
            controller_packet,
        )?;
        let terminal_digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
        let held_proof = cache_observation
            .map(|(hold, quota)| {
                if joined.physical_cache().hold() != hold
                    || joined.physical_cache().quota_digest() != quota
                {
                    return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
                }
                self.expected_held_proof(claim, terminal_digest, hold, quota)
            })
            .transpose()?;
        let transaction_digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(bytes)
            .chain_update(held_proof.as_ref().map_or(&[][..], |row| row.as_slice()))
            .finalize();
        let transaction_id: [u8; 16] = transaction_digest[..16]
            .try_into()
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let mut records = vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            KEY.to_vec(),
            bytes.to_vec(),
        )];
        if let Some(proof) = held_proof {
            records.push(JournalRecord::put(
                RecordNamespace::DesiredState,
                HELD_PROOF_KEY.to_vec(),
                proof.to_vec(),
            ));
        }
        let transaction = JournalTransaction::new(transaction_id, records)?;
        self.authority.commit(&transaction)?;
        let record = match cache_observation {
            Some(observation) => self.recover_terminal_with_held_proof_observation(
                claim,
                controller_uid,
                observation,
            )?,
            None => self.recover_staged_source_terminal_v1(claim, controller_uid)?,
        }
        .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        self.postcommit = Some(self.authority.snapshot()?);
        Ok(record)
    }

    /// Replays only the exact current protected terminal row after a lost reply.
    ///
    /// Historical replay uses Root's protected pin; it does not admit a new
    /// signature after a deployment credential rotation or authorize CAS.
    ///
    /// # Errors
    ///
    /// Rejects a stale stage/Source challenge, changed claim, corrupt row,
    /// substituted pin, or forged Controller signature.
    pub fn recover_staged_source_terminal_v1(
        &self,
        claim: ClosedSourceTerminalClaimV1,
        controller_uid: u32,
    ) -> Result<Option<ClosedSourceTerminalRecordV1>, PolicyCompilerJournalErrorV1> {
        self.validate_staged_closed_binding_base(claim.staged)?;
        self.require_spent_source_challenge_v1(
            &claim.proposed,
            claim.staged,
            claim.source_challenge,
            claim.source_issue,
        )?;
        let Some(row) = self.authority.get(KEY)? else {
            return Ok(None);
        };
        if row.len() != CLOSED_SOURCE_TERMINAL_RECORD_BYTES_V1
            || row[..8] != MAGIC[..]
            || row[8..10] != 1_u16.to_be_bytes()
            || row[10..16] != [0; 6]
            || row[16..16 + CLAIM_BYTES] != claim.encode()
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let pin = self
            .authority
            .get(CONTROLLER_HOLD_PIN_KEY)?
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let packet = &row[16 + CLAIM_BYTES..BODY_BYTES];
        terminal_record_bytes(claim, controller_uid, pin, packet)?;
        if row[BODY_BYTES..]
            != Sha256::new()
                .chain_update(CHECKSUM_DOMAIN)
                .chain_update(&row[..BODY_BYTES])
                .finalize()[..]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(Some(ClosedSourceTerminalRecordV1 {
            digest: ObjectDigest::from_bytes(Sha256::digest(row).into()),
            held_proof: None,
        }))
    }

    /// Cold-replays the exact terminal and its protected Cache/Source companion.
    ///
    /// Root replays the current fixed Cache hold and quota envelope. Source
    /// writer continuity still requires a fresh held-owner barrier before CAS;
    /// this historical comparison alone is nonauthorizing.
    ///
    /// # Errors
    ///
    /// Rejects a missing or changed companion, pin, Root stage, Source issue,
    /// terminal signature, protected Cache hold, or quota replay.
    pub fn recover_staged_source_terminal_with_held_proof_v2(
        &self,
        claim: ClosedSourceTerminalClaimV1,
        controller_uid: u32,
    ) -> Result<Option<ClosedSourceTerminalRecordV1>, PolicyCompilerJournalErrorV1> {
        let observed = read_fixed_policy_cache_hold_v1()
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        self.recover_terminal_with_held_proof_observation(
            claim,
            controller_uid,
            (observed.hold, observed.replay.quota_digest),
        )
    }

    fn recover_terminal_with_held_proof_observation(
        &self,
        claim: ClosedSourceTerminalClaimV1,
        controller_uid: u32,
        (hold, quota): (CachePolicyHoldV1, ObjectDigest),
    ) -> Result<Option<ClosedSourceTerminalRecordV1>, PolicyCompilerJournalErrorV1> {
        let Some(mut terminal) = self.recover_staged_source_terminal_v1(claim, controller_uid)?
        else {
            return Ok(None);
        };
        let proof = self.expected_held_proof(claim, terminal.digest, hold, quota)?;
        if self.authority.get(HELD_PROOF_KEY)? != Some(proof.as_slice()) {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        terminal.held_proof = Some(ObjectDigest::from_bytes(Sha256::digest(proof).into()));
        Ok(Some(terminal))
    }

    fn expected_held_proof(
        &self,
        claim: ClosedSourceTerminalClaimV1,
        terminal: ObjectDigest,
        hold: CachePolicyHoldV1,
        quota: ObjectDigest,
    ) -> Result<[u8; HELD_PROOF_BYTES], PolicyCompilerJournalErrorV1> {
        let binding = ClosedPolicyRootBindingV2::decode(&claim.proposed)?;
        if !hold.is_held()
            || hold.binding() != claim.source_hold.binding()
            || hold.epoch() != claim.source_hold.epoch()
            || hold.project() != binding.project
            || hold.partition() != binding.physical_partition
            || hold.cache_head() != binding.physical_cache_head
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let source_pin = self
            .authority
            .get(SOURCE_HOLD_PIN_KEY)?
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let cache_pin = self
            .authority
            .get(CACHE_PIN_KEY)?
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let controller_pin = self
            .authority
            .get(CONTROLLER_HOLD_PIN_KEY)?
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let source_signer = PinnedSourceHoldReadbackSignerV1::decode(source_pin)
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let cache_signer = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let controller_signer = PinnedControllerHoldSignerV1::decode(controller_pin)
            .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        if source_signer.verifying_key() == cache_signer.verifying_key()
            || source_signer.verifying_key() == controller_signer.verifying_key()
            || cache_signer.verifying_key() == controller_signer.verifying_key()
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        RootHeldProofV2 {
            terminal,
            binding: hold.binding(),
            epoch: hold.epoch(),
            stage_nonce: claim.staged.challenge(),
            stage_issue: claim.staged.issue_epoch(),
            source_nonce: claim.source_challenge.nonce(),
            source_issue: claim.source_issue,
            names: claim.names,
            source_packet: claim.source_packet,
            cache_packet: claim.cache_packet,
            source_pin: ObjectDigest::from_bytes(Sha256::digest(source_pin).into()),
            cache_pin: ObjectDigest::from_bytes(Sha256::digest(cache_pin).into()),
            controller_pin: ObjectDigest::from_bytes(Sha256::digest(controller_pin).into()),
            source_generation: source_signer.generation(),
            cache_generation: cache_signer.generation(),
            controller_generation: controller_signer.generation(),
            project: hold.project(),
            partition: hold.partition(),
            cache_head: hold.cache_head(),
            quota,
        }
        .encode()
    }

    /// Cold-replays only the exact current row identified by a client digest.
    ///
    /// # Errors
    ///
    /// Rejects changed stages, Root-spent challenges, pins, or signatures.
    pub fn recover_current_source_terminal_digest_v1(
        &mut self,
        digest: ObjectDigest,
        controller_uid: u32,
    ) -> Result<Option<ClosedSourceTerminalRecordV1>, PolicyCompilerJournalErrorV1> {
        let Some(row) = self.authority.get(KEY)? else {
            return Ok(None);
        };
        if row.len() != CLOSED_SOURCE_TERMINAL_RECORD_BYTES_V1
            || Sha256::digest(row)[..] != digest.as_bytes()[..]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let claim =
            ClosedSourceTerminalClaimV1::decode(&row[16..16 + CLAIM_BYTES], self.current_base()?)?;
        let record = self.recover_staged_source_terminal_v1(claim, controller_uid)?;
        if record.is_some() {
            self.postcommit = Some(self.authority.snapshot()?);
        }
        Ok(record)
    }

    /// Replays a V7 terminal digest only when its AOSPCP02 join remains exact.
    ///
    /// # Errors
    ///
    /// Rejects absent or changed protected Cache/Source proof and all V1
    /// terminal replay failures. This does not admit a new CAS or effect.
    pub fn recover_current_source_terminal_digest_with_held_proof_v2(
        &mut self,
        digest: ObjectDigest,
        controller_uid: u32,
    ) -> Result<Option<ClosedSourceTerminalRecordV1>, PolicyCompilerJournalErrorV1> {
        let Some(terminal) =
            self.recover_current_source_terminal_digest_v1(digest, controller_uid)?
        else {
            return Ok(None);
        };
        let row = self
            .authority
            .get(KEY)?
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let claim =
            ClosedSourceTerminalClaimV1::decode(&row[16..16 + CLAIM_BYTES], self.current_base()?)?;
        let joined = self
            .recover_staged_source_terminal_with_held_proof_v2(claim, controller_uid)?
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        if joined.digest() != terminal.digest() {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(Some(joined))
    }

    fn validate_terminal_claim(
        &self,
        claim: ClosedSourceTerminalClaimV1,
        joined: ClosedPolicyRootSignerJoinV2,
    ) -> Result<(), PolicyCompilerJournalErrorV1> {
        self.validate_staged_closed_binding_base(claim.staged)?;
        self.require_spent_source_challenge_v1(
            &claim.proposed,
            claim.staged,
            claim.source_challenge,
            claim.source_issue,
        )?;
        let binding = ClosedPolicyRootBindingV2::decode(&claim.proposed)?;
        let cut = joined.cache_cut();
        if !self.identity.matches(&binding)
            || cut.binding() != claim.source_hold.binding()
            || cut.epoch() != claim.source_hold.epoch()
            || joined.source_packet() != claim.source_packet
            || joined.cache_packet() != claim.cache_packet
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(())
    }
}

fn terminal_record_bytes(
    claim: ClosedSourceTerminalClaimV1,
    controller_uid: u32,
    pin: &[u8],
    packet: &[u8],
) -> Result<[u8; CLOSED_SOURCE_TERMINAL_RECORD_BYTES_V1], PolicyCompilerJournalErrorV1> {
    let signer = PinnedControllerHoldSignerV1::decode(pin)
        .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    let receipt = verify_controller_hold_readback_v1(
        packet,
        &signer,
        claim.controller_challenge()?,
        controller_uid,
    )
    .map_err(|_| PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    if receipt.operation() != claim.source_hold.operation()
        || receipt.sandbox() != claim.source_hold.sandbox()
        || receipt.source() != claim.source_hold.controller_source()
        || receipt.binding() != claim.source_hold.binding()
        || receipt.epoch() != claim.source_hold.epoch()
    {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    encode_terminal_record(claim, packet)
}

fn encode_terminal_record(
    claim: ClosedSourceTerminalClaimV1,
    packet: &[u8],
) -> Result<[u8; CLOSED_SOURCE_TERMINAL_RECORD_BYTES_V1], PolicyCompilerJournalErrorV1> {
    if packet.len() != CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1 {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let mut row = [0; CLOSED_SOURCE_TERMINAL_RECORD_BYTES_V1];
    row[..8].copy_from_slice(MAGIC);
    row[8..10].copy_from_slice(&1_u16.to_be_bytes());
    row[16..16 + CLAIM_BYTES].copy_from_slice(&claim.encode());
    row[16 + CLAIM_BYTES..BODY_BYTES].copy_from_slice(packet);
    let checksum = Sha256::new()
        .chain_update(CHECKSUM_DOMAIN)
        .chain_update(&row[..BODY_BYTES])
        .finalize();
    row[BODY_BYTES..].copy_from_slice(&checksum);
    Ok(row)
}

fn take_claim<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], PolicyCompilerJournalErrorV1> {
    let value = bytes
        .get(*offset..*offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
    *offset += N;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use ed25519_dalek::SigningKey;

    use crate::cache_residency::{
        CacheOwnerReadbackChallengeV1, PinnedCacheOwnerReadbackSignerV1,
        encode_cache_owner_readback_signer_credential_v1, sign_test_cache_owner_readback_v2,
        verify_closed_cache_owner_readback_v2,
    };
    use crate::journal::{ControllerPolicyHoldV1, ProtectedJournalAuthority};
    use crate::policy_compiler::binding_v2::tests::{
        cas_fixture, identity, matching_cache_hold, open_test_root,
    };
    use crate::policy_compiler::controller_hold_readback::{
        encode_controller_hold_signer_credential_v1, sign_test_controller_hold_readback_v1,
    };
    use crate::policy_compiler::source_hold_readback::encode_source_hold_readback_signer_credential_v1;

    use super::*;

    fn append_row(authority: &mut ProtectedJournalAuthority<'_>, row: Vec<u8>, id: u8) {
        authority
            .commit(
                &JournalTransaction::new(
                    [id; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        KEY.to_vec(),
                        row,
                    )],
                )
                .expect("terminal transaction"),
            )
            .expect("protected terminal row");
    }

    #[test]
    fn signed_terminal_cold_replay_fences_forgery_pin_rotation_and_superseded_source() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let binding = cas_fixture();
        let proposed = binding.encode().expect("proposal");
        let binding_digest = closed_policy_binding_digest_v2(&proposed).expect("binding digest");
        let controller_key = SigningKey::from_bytes(&[51; 32]);
        let pin = encode_controller_hold_signer_credential_v1(5, &controller_key.verifying_key())
            .expect("Controller-only pin");
        let mut root = open_test_root(directory.path());
        let mut authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("Root authority");
        authority
            .commit(
                &JournalTransaction::new(
                    [1; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        CONTROLLER_HOLD_PIN_KEY.to_vec(),
                        pin.to_vec(),
                    )],
                )
                .expect("pin transaction"),
            )
            .expect("protected Controller pin");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        let staged = session
            .stage_closed_binding_base(|| Ok([7; 16]))
            .expect("durable Root stage");
        drop(session);
        drop(root);

        let mut root = open_test_root(directory.path());
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("Root-last authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        let (source_challenge, source_issue) = session
            .spend_staged_source_challenge_v1(&proposed, staged, || Ok([8; 16]))
            .expect("spent Root Source challenge");
        let source_hold = SourceDomainPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            ObjectDigest::from_bytes([41; 32]),
            binding.ancestry_head,
            binding_digest,
            binding.handoff_epoch,
        )
        .expect("Source hold");
        let names = ProtectedJournalNamesV1::from_bytes(&[1; 48]).expect("named Source pair");
        let claim = ClosedSourceTerminalClaimV1::new(
            &proposed,
            staged,
            source_hold,
            source_challenge,
            source_issue,
            names,
            ObjectDigest::from_bytes([42; 32]),
            ObjectDigest::from_bytes([43; 32]),
            ObjectDigest::from_bytes([44; 32]),
            [45; 16],
        )
        .expect("terminal claim");
        let controller_hold = ControllerPolicyHoldV1::new(
            binding.operation,
            binding.sandbox,
            source_hold.controller_source(),
            binding_digest,
            binding.handoff_epoch,
        )
        .expect("Controller hold");
        let packet = sign_test_controller_hold_readback_v1(
            controller_hold,
            1234,
            claim.controller_challenge().expect("challenge"),
            5,
            &controller_key,
        )
        .expect("signed Controller receipt");
        let row = terminal_record_bytes(claim, 1234, &pin, &packet).expect("signed terminal row");
        assert_eq!(
            claim
                .record_digest_for_packet(&packet)
                .expect("client-predicted record digest"),
            ObjectDigest::from_bytes(Sha256::digest(row).into())
        );
        let cache_key = SigningKey::from_bytes(&[53; 32]);
        let cache_pin =
            encode_cache_owner_readback_signer_credential_v1(6, &cache_key.verifying_key())
                .expect("Cache pin");
        let cache_signer =
            PinnedCacheOwnerReadbackSignerV1::decode(&cache_pin).expect("pinned Cache signer");
        let staged_signer =
            staged_closed_policy_signer_challenge_v2(staged, &proposed).expect("staged signer cut");
        let cache_challenge =
            CacheOwnerReadbackChallengeV1::new(staged_signer.nonce(), staged_signer.cut())
                .expect("Cache challenge");
        let cache_packet = sign_test_cache_owner_readback_v2(
            cache_challenge,
            6,
            &cache_key,
            1234,
            matching_cache_hold(&binding),
            ObjectDigest::from_bytes([54; 32]),
        )
        .expect("signed physical Cache view");
        let physical = verify_closed_cache_owner_readback_v2(
            &cache_packet,
            &cache_signer,
            cache_challenge,
            1234,
        )
        .expect("verified physical Cache view");
        let joined = ClosedPolicyRootSignerJoinV2 {
            cache_cut: ClosedPolicyRootCacheCutV2 {
                binding: binding_digest,
                epoch: binding.handoff_epoch,
                project: binding.project,
                partition: binding.physical_partition,
                cache_head: binding.physical_cache_head,
            },
            source_packet: claim.source_packet,
            cache_packet: claim.cache_packet,
            physical_cache: physical,
        };
        assert!(
            session
                .record_staged_source_terminal_v1(claim, joined, 1234, &[0; 80], &packet)
                .is_err()
        );
        let mut forged_packet = packet;
        forged_packet[100] ^= 1;
        assert!(
            session
                .record_staged_source_terminal_v1(claim, joined, 1234, &pin, &forged_packet)
                .is_err()
        );
        assert!(
            session
                .authority
                .get(KEY)
                .expect("Root terminal key")
                .is_none()
        );
        let expected = session
            .record_staged_source_terminal_v1(claim, joined, 1234, &pin, &packet)
            .expect("durable signed Root terminal");
        assert_eq!(
            expected.digest(),
            ObjectDigest::from_bytes(Sha256::digest(row).into())
        );
        assert!(expected.held_proof_digest().is_none());
        assert!(
            session
                .recover_terminal_with_held_proof_observation(
                    claim,
                    1234,
                    (
                        matching_cache_hold(&binding),
                        ObjectDigest::from_bytes([54; 32])
                    ),
                )
                .is_err(),
            "a historical terminal without AOSPCP02 cannot replay as a held join"
        );
        let source_key = SigningKey::from_bytes(&[55; 32]);
        let source_pin =
            encode_source_hold_readback_signer_credential_v1(7, &source_key.verifying_key())
                .expect("Source-only pin");
        session
            .authority
            .commit(
                &JournalTransaction::new(
                    [11; 16],
                    vec![
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            SOURCE_HOLD_PIN_KEY.to_vec(),
                            source_pin.to_vec(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            CACHE_PIN_KEY.to_vec(),
                            cache_pin.to_vec(),
                        ),
                    ],
                )
                .expect("independent signer pins"),
            )
            .expect("protected signer pins");
        let held_observation = (
            matching_cache_hold(&binding),
            ObjectDigest::from_bytes([54; 32]),
        );
        assert!(
            session
                .record_terminal(
                    claim,
                    joined,
                    1234,
                    &pin,
                    &packet,
                    Some((held_observation.0, ObjectDigest::from_bytes([56; 32]))),
                )
                .is_err(),
            "Root must reject a Cache quota not signed by the physical owner"
        );
        let joined_record = session
            .record_terminal(claim, joined, 1234, &pin, &packet, Some(held_observation))
            .expect("atomic terminal and AOSPCP02 join");
        assert_eq!(joined_record.digest(), expected.digest());
        assert!(joined_record.held_proof_digest().is_some());
        assert!(
            session
                .recover_terminal_with_held_proof_observation(
                    claim,
                    1234,
                    (
                        matching_cache_hold(&binding),
                        ObjectDigest::from_bytes([56; 32])
                    ),
                )
                .is_err(),
            "changed protected Cache quota must not cold-replay"
        );
        let proof = session
            .authority
            .get(HELD_PROOF_KEY)
            .expect("held proof key")
            .expect("protected proof")
            .to_vec();
        let mut forged_proof = proof.clone();
        forged_proof[184] ^= 1;
        let last = forged_proof.len() - 32;
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.held-proof.v2\0")
            .chain_update(&forged_proof[..last])
            .finalize();
        forged_proof[last..].copy_from_slice(&checksum);
        session
            .authority
            .commit(
                &JournalTransaction::new(
                    [12; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        HELD_PROOF_KEY.to_vec(),
                        forged_proof,
                    )],
                )
                .expect("forged proof transaction"),
            )
            .expect("raw forged proof row");
        assert!(
            session
                .recover_terminal_with_held_proof_observation(claim, 1234, held_observation)
                .is_err(),
            "a checksummed but substituted proof must fail closed"
        );
        session
            .authority
            .commit(
                &JournalTransaction::new(
                    [13; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        HELD_PROOF_KEY.to_vec(),
                        proof,
                    )],
                )
                .expect("restore proof transaction"),
            )
            .expect("restored protected proof");
        assert_eq!(current_root_binding_chain(&session.authority).unwrap().2, 0);
        drop(session);
        drop(root);

        let mut root = open_test_root(directory.path());
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("cold Root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        assert_eq!(
            session
                .recover_staged_source_terminal_v1(claim, 1234)
                .expect("cold exact replay"),
            Some(expected)
        );
        assert_eq!(
            session
                .recover_terminal_with_held_proof_observation(claim, 1234, held_observation)
                .expect("cold held proof replay"),
            Some(joined_record)
        );
        let rotated_source_key = SigningKey::from_bytes(&[57; 32]);
        let rotated_source_pin = encode_source_hold_readback_signer_credential_v1(
            8,
            &rotated_source_key.verifying_key(),
        )
        .expect("rotated Source pin");
        session
            .authority
            .commit(
                &JournalTransaction::new(
                    [14; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        SOURCE_HOLD_PIN_KEY.to_vec(),
                        rotated_source_pin.to_vec(),
                    )],
                )
                .expect("Source pin rotation transaction"),
            )
            .expect("rotated Source pin");
        assert!(
            session
                .recover_terminal_with_held_proof_observation(claim, 1234, held_observation)
                .is_err(),
            "a rotated Source-only signer must invalidate the held proof"
        );
        session
            .authority
            .commit(
                &JournalTransaction::new(
                    [15; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        SOURCE_HOLD_PIN_KEY.to_vec(),
                        source_pin.to_vec(),
                    )],
                )
                .expect("Source pin restoration transaction"),
            )
            .expect("restored Source pin");
        assert_eq!(
            session
                .recover_current_source_terminal_digest_v1(expected.digest(), 1234)
                .expect("digest-only cold replay"),
            Some(expected)
        );
        let wrong_claim = ClosedSourceTerminalClaimV1::new(
            &proposed,
            staged,
            source_hold,
            source_challenge,
            source_issue,
            names,
            ObjectDigest::from_bytes([42; 32]),
            ObjectDigest::from_bytes([43; 32]),
            ObjectDigest::from_bytes([44; 32]),
            [46; 16],
        )
        .expect("foreign client nonce");
        assert!(
            session
                .recover_staged_source_terminal_v1(wrong_claim, 1234)
                .is_err()
        );
        assert!(
            session
                .recover_staged_source_terminal_v1(claim, 4321)
                .is_err()
        );

        let mut forged = row;
        forged[16 + CLAIM_BYTES + 100] ^= 1;
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&forged[..BODY_BYTES])
            .finalize();
        forged[BODY_BYTES..].copy_from_slice(&checksum);
        append_row(&mut session.authority, forged.to_vec(), 3);
        assert!(
            session
                .recover_staged_source_terminal_v1(claim, 1234)
                .is_err()
        );
        append_row(&mut session.authority, row.to_vec(), 4);

        let rotated_key = SigningKey::from_bytes(&[52; 32]);
        let rotated_pin =
            encode_controller_hold_signer_credential_v1(6, &rotated_key.verifying_key())
                .expect("rotated pin");
        assert!(terminal_record_bytes(claim, 1234, &rotated_pin, &packet).is_err());
        session
            .authority
            .commit(
                &JournalTransaction::new(
                    [5; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::DesiredState,
                        CONTROLLER_HOLD_PIN_KEY.to_vec(),
                        rotated_pin.to_vec(),
                    )],
                )
                .expect("pin rotation"),
            )
            .expect("protected pin rotation");
        assert!(
            session
                .recover_staged_source_terminal_v1(claim, 1234)
                .is_err()
        );
        drop(session);
        drop(root);

        let mut root = open_test_root(directory.path());
        let authority = root
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("reopened Root authority");
        let mut session = ClosedPolicyRootSessionV2 {
            authority,
            identity: identity(&binding),
            postcommit: None,
        };
        session
            .spend_staged_source_challenge_v1(&proposed, staged, || Ok([9; 16]))
            .expect("superseding Source challenge");
        assert!(
            session
                .require_spent_source_challenge_v1(
                    &proposed,
                    staged,
                    source_challenge,
                    source_issue,
                )
                .is_err()
        );
        assert!(
            session
                .recover_staged_source_terminal_v1(claim, 1234)
                .is_err()
        );
    }
}
