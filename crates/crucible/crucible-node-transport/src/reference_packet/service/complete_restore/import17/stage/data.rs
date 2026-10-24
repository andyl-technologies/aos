//! Defines closed stage17 DATA used only under explicit stage18 selection.
//!
//! ```text
//! stage = {schema,phase,import_binding_digest,source_birth,source_runtime,
//!   scope_proof,target,prepare:{pair,receipt},commit:{pair,receipt},hold,
//!   arm:null|pair,world:null|pair,native_allocation}
//! ```
//!
//! Complete prior receipts remain distinct from old transfer12 receipts. DATA
//! validation creates no phase permission, physical Hold or published World.

use super::super::{PacketNativeImport17CommitReceipt, PacketNativeImport17PrepareReceipt};
use super::*;
use crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationTarget;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crucible_node_format::{Bytes, ContentRef, Validate};
use serde::{Deserialize, Serialize};

/// Names the complete assigned original and its correlated terminal.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17StagePairData {
    /// Includes the actual original phase proof.
    pub original: ContentRef,
    /// Includes the actual terminal phase receipt.
    pub terminal: ContentRef,
}

/// Retains the complete new-family Prepare receipt beside its literal pair.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17StagePrepareData {
    /// Names the actual completed new18 Prepare exchange.
    pub pair: PacketNativeImport17StagePairData,
    /// Retains the unchanged inner17 receipt with its seven-bank digest.
    pub receipt: PacketNativeImport17PrepareReceipt,
}

/// Retains the complete same-token Commit receipt beside its literal pair.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17StageCommitData {
    /// Names the actual completed new18 Commit exchange.
    pub pair: PacketNativeImport17StagePairData,
    /// Retains the unchanged inner17 installed-mapping receipt.
    pub receipt: PacketNativeImport17CommitReceipt,
}

/// Binds one distinct stage to its complete preceding import correspondence.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport17StageBinding {
    /// Selects exactly the stage17 extension under explicit stage18 negotiation.
    pub schema: String,
    /// Selects the separately spent Arm, World or FirstObserve occurrence.
    pub phase: PacketNativeImport17Stage,
    /// Hashes the full original import18 binding, including all seven banks.
    pub import_binding_digest: Bytes,
    /// Names the same complete original SourceBinding18 body.
    pub source_birth: ContentRef,
    /// Names the actual signed Source Runtime record.
    pub source_runtime: ContentRef,
    /// Names the actual all-owner scope proof.
    pub scope_proof: ContentRef,
    /// Retains all fourteen coordinates of the fresh target.
    pub target: PacketRestorationActivationTarget,
    /// Retains the completed new18 Prepare pair and complete inner17 receipt.
    pub prepare: PacketNativeImport17StagePrepareData,
    /// Retains the completed same-token Commit pair and complete inner17 receipt.
    pub commit: PacketNativeImport17StageCommitData,
    /// Names the separate record18 evidence published while physically held.
    pub hold: ContentRef,
    /// Is null for Arm; otherwise names the completed same-target Arm exchange.
    #[serde(deserialize_with = "required_pair")]
    pub arm: Option<PacketNativeImport17StagePairData>,
    /// Is null through World; FirstObserve names the completed World exchange.
    #[serde(deserialize_with = "required_pair")]
    pub world: Option<PacketNativeImport17StagePairData>,
    /// Retains the separately admitted phase row without creating its grant.
    pub native_allocation: PacketNativeStartupAllocationRow,
}

impl PacketNativeImport17StagePairData {
    pub(super) fn validate_data(&self) -> Result<(), ProviderError> {
        json_reference(&self.original)?;
        json_reference(&self.terminal)?;
        if self.original == self.terminal {
            return Err(invalid());
        }
        Ok(())
    }
}

impl PacketNativeImport17StageBinding {
    /// Checks closed stage DATA, prior receipt joins and exact nullable history.
    ///
    /// Actual full-reference body verification, receipts' MACs, genuine Source
    /// custody, current SDK assignments and native effects remain independent.
    /// Callers admit this walk and serializer controls before inspection.
    ///
    /// # Errors
    /// Refuses another schema, malformed target/reference/digest/receipt, changed
    /// import/token association, inconsistent stage history or encoded overflow.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != NATIVE_IMPORT17_STAGE_EXTENSION {
            return Err(invalid());
        }
        digest32(&self.import_binding_digest)?;
        for reference in [
            &self.source_birth,
            &self.source_runtime,
            &self.scope_proof,
            &self.hold,
        ] {
            json_reference(reference)?;
        }
        validate_target(&self.target)?;
        self.prepare.pair.validate_data()?;
        self.commit.pair.validate_data()?;
        self.prepare.receipt.validate_data()?;
        self.commit.receipt.validate_data()?;
        if self.prepare.receipt.import_binding_digest != self.import_binding_digest
            || self.commit.receipt.import_binding_digest != self.import_binding_digest
            || self.prepare.receipt.transfer_token != self.commit.receipt.transfer_token
        {
            return Err(invalid());
        }
        match (self.phase, &self.arm, &self.world) {
            (PacketNativeImport17Stage::Arm, None, None) => {}
            (PacketNativeImport17Stage::World, Some(arm), None) => arm.validate_data()?,
            (PacketNativeImport17Stage::FirstObserve, Some(arm), Some(world)) => {
                arm.validate_data()?;
                world.validate_data()?;
            }
            _ => return Err(invalid()),
        }
        self.native_allocation.requested_peak_data()?;
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT17_STAGE_BINDING_BYTES)?;
        Ok(())
    }

    /// Hashes every field of the complete unchanged inner stage binding.
    ///
    /// The caller separately admits canonicalization and returned DATA backing.
    ///
    /// # Errors
    /// Refuses invalid DATA or bounded canonical construction failure.
    pub fn digest_data(&self) -> Result<[u8; 32], ProviderError> {
        self.validate_data()?;
        Ok(*blake3::hash(&bounded(self, MAXIMUM_NATIVE_IMPORT17_STAGE_BINDING_BYTES)?).as_bytes())
    }
}

pub(super) fn json_reference(reference: &ContentRef) -> Result<(), ProviderError> {
    reference.validate()?;
    if reference.length.get() == 0 || reference.media_type != "application/json" {
        return Err(invalid());
    }
    Ok(())
}

fn validate_target(target: &PacketRestorationActivationTarget) -> Result<(), ProviderError> {
    if target.native_pid.get() == 0
        || target.native_pid.get() > i32::MAX as u64
        || target.owner_generation.get() == 0
        || target.generation.get() == 0
    {
        return Err(invalid());
    }
    for id in [
        &target.session,
        &target.incarnation,
        &target.node,
        &target.owner,
        &target.activation,
        &target.prepared_token,
        &target.gate,
        &target.admission,
        &target.transaction,
    ] {
        id.validate()?;
    }
    target.binding_hash.validate()?;
    target.world.validate()?;
    if !matches!(
        target.binding_hash.domain.as_str(),
        "cnp.node-binding.v1" | "cnp.owner-binding.v1"
    ) || target.world.domain != "cnp.world-binding.v1"
    {
        return Err(invalid());
    }
    Ok(())
}

// Serde's ordinary Option handling accepts absent fields. These nullable fields
// must be present even before their corresponding stage has completed.
fn required_pair<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<PacketNativeImport17StagePairData>, D::Error> {
    Option::deserialize(decoder)
}
