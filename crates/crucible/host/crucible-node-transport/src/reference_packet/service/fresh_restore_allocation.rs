//! Defines allocation data from an admitted, inactive restoration target.
//!
//! The selected startup query precedes assignment of Prepare. It never uses the
//! active-model Observe handler, opens a gate, reserves restoration inputs or
//! issues a restoration ticket. Source retains the completed original query and
//! its report before performing a separate whole-world allocation check.
//!
//! ```text
//! completed original Admit -> selected readonly Observe -> authenticated report
//! report + actual archived demand + whole context -> separately assigned Prepare
//! ```

use crate::ProviderError;
use crucible_node_format::{Bytes, ContentRef, HashRef, Id, U64, Validate};
use serde::{Deserialize, Serialize};

mod contract;
mod crypto;
mod metadata;
pub(crate) mod policy;
mod startup;

pub(crate) use startup::{
    FreshRestoreAllocationStartupShapes, fresh_restore_allocation_host_shapes,
    fresh_restore_allocation_startup_counter_scratch_data, fresh_restore_allocation_startup_shapes,
};

#[cfg(test)]
mod tests;

pub use contract::{
    PacketNativeFreshRestoreAllocationSchema, fresh_restore_allocation_contract,
    fresh_restore_allocation_schema,
};
pub use crypto::{
    PacketNativeFreshRestoreOriginalRole, fresh_restore_allocation_envelope_digest_data,
    fresh_restore_allocation_nonce_data, fresh_restore_allocation_proof_data,
    verify_fresh_restore_allocation_proof_data,
};

/// Names the independently selected fresh-target allocation family.
pub const PACKET_FRESH_RESTORE_ALLOCATION_FEATURE: &str =
    "source-owned.packet-fresh-restore-allocation/13";
/// Names the startup Observe request's sole envelope extension.
pub const PACKET_FRESH_RESTORE_ALLOCATION_QUERY: &str =
    "source-owned.packet-fresh-restore-allocation-query/13";
/// Names the immutable fresh-target report.
pub const PACKET_FRESH_RESTORE_ALLOCATION_REPORT: &str =
    "source-owned.packet-fresh-restore-allocation-report/13";
/// Names the domain-separated proof over the complete report data.
pub const PACKET_FRESH_RESTORE_ALLOCATION_PROOF: &str =
    "source-owned.packet-fresh-restore-allocation-proof/13";
/// Names the completed startup Observe response's report reference.
pub const PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT: &str =
    "source-owned.packet-fresh-restore-allocation-receipt/13";
/// Names the exact completed startup exchange bound into a later Prepare.
pub const PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING: &str =
    "source-owned.packet-fresh-restore-allocation-prepare-binding/13";
/// Names the report's exact content media type.
pub const PACKET_FRESH_RESTORE_ALLOCATION_MEDIA: &str =
    "application/vnd.source-owned.packet-fresh-restore-allocation.v13+json";
/// Bounds the closed report encoding independently of its allocation arithmetic.
pub const MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES: usize = 16 * 1024;
/// Bounds a closed startup query independently of the negotiated whole frame.
pub const MAXIMUM_FRESH_RESTORE_ALLOCATION_QUERY_BYTES: usize = 1024;
/// Names the keyed canonical report authentication algorithm.
pub const FRESH_RESTORE_ALLOCATION_ALGORITHM: &str = "blake3-keyed-canonical/1";

/// Selects a readonly producer on the same fresh target after its once-only Admit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNative5FreshRestoreAllocationSelection {
    /// Measures the admitted inactive target without activation or Prepare.
    CompletedAdmit13,
}

/// Binds one startup query to the same birth and completed original Admit pair.
///
/// Digests commit complete canonical envelopes, including their proof fields.
/// The native reader checks its retained originals before echoing this data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeFreshRestoreAllocationQuery {
    /// Selects the exact startup query grammar.
    pub schema: String,
    /// Derives from the actual fresh birth key in the separate nonce domain.
    pub nonce: Bytes,
    /// Commits the complete original assigned Admit request.
    pub completed_admit_request: Bytes,
    /// Commits its complete, successful original response.
    pub completed_admit_response: Bytes,
}

impl PacketNativeFreshRestoreAllocationQuery {
    /// Checks closed syntax without authenticating a birth or completed Admit.
    ///
    /// # Errors
    /// Refuses another schema or a nonce or digest with a different extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_FRESH_RESTORE_ALLOCATION_QUERY {
            return Err(invalid());
        }
        digest(&self.nonce)?;
        digest(&self.completed_admit_request)?;
        digest(&self.completed_admit_response)
    }
}

/// Names the actual inactive target and its original protocol association.
///
/// There is deliberately no activation, active cursor or historical authority.
/// Portable identifiers do not replace the retained current native owners.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeFreshRestoreAllocationScope {
    /// Names the process that performed the actual native walk.
    pub native_pid: U64,
    /// Retains the actual session shared by the query and original Admit.
    pub session: Id,
    /// Retains the fresh native incarnation.
    pub incarnation: Id,
    /// Names the selected logical node.
    pub node: Id,
    /// Names the inactive execution owner.
    pub owner: Id,
    /// Retains the selected owner generation.
    pub owner_generation: U64,
    /// Commits the complete freshly installed owner binding.
    pub owner_binding: HashRef,
    /// Commits the complete freshly installed world.
    pub world: HashRef,
    /// Names the actual original prepared realization.
    pub prepared_token: Id,
    /// Names the actual successful once-only admission.
    pub admission: Id,
    /// Names the same cached Realize proof while the physical gate remains closed.
    pub closed_gate_receipt: ContentRef,
    /// Retains the separate fresh-birth query nonce.
    pub nonce: Bytes,
    /// Commits the complete assigned query, including its sole extension.
    pub assigned_query: Bytes,
    /// Commits the actual completed assigned Admit request.
    pub completed_admit_request: Bytes,
    /// Commits the actual completed assigned Admit response.
    pub completed_admit_response: Bytes,
    /// Commits the same native-verified original ACK admission context.
    pub ack_context: Bytes,
}

/// Names independently retained and transient fresh-target requested storage.
///
/// The producer walks actual current owners. Future terms come from closed
/// query/publication and Prepare plans. Input banks, archived reconstruction,
/// model adoption and the host's owners remain separate whole-context terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeFreshRestoreAllocationStorage {
    /// Includes actual current native inline owners and retained backing.
    pub current_retained_bytes: U64,
    /// Includes the report, completed query, proof prefix and retained currency.
    pub query_retained_growth_bytes: U64,
    /// Includes the future original Prepare, issuer and response owners.
    pub prepare_retained_growth_bytes: U64,
    /// Includes all simultaneously live query encoding and proof I/O transients.
    pub query_transient_bytes: U64,
    /// Includes all simultaneously live fixed Prepare verification transients.
    pub prepare_transient_bytes: U64,
    /// Includes the actual observer, root roster and closed counter scratch.
    pub declared_counter_scratch_bytes: U64,
}

impl PacketNativeFreshRestoreAllocationStorage {
    /// Sums retained growth and the largest complete transient phase as data.
    ///
    /// This excludes input and reconstruction owners and grants no allocation.
    ///
    /// # Errors
    /// Refuses a missing component or integer overflow.
    pub fn requested_peak_data(&self) -> Result<u64, ProviderError> {
        let retained = [
            self.current_retained_bytes,
            self.query_retained_growth_bytes,
            self.prepare_retained_growth_bytes,
            self.declared_counter_scratch_bytes,
        ];
        let mut total = 0u64;
        for component in retained {
            if component.get() == 0 {
                return Err(invalid());
            }
            total = total.checked_add(component.get()).ok_or_else(invalid)?;
        }
        if self.query_transient_bytes.get() == 0 || self.prepare_transient_bytes.get() == 0 {
            return Err(invalid());
        }
        total
            .checked_add(
                self.query_transient_bytes
                    .get()
                    .max(self.prepare_transient_bytes.get()),
            )
            .ok_or_else(invalid)
    }
}

/// Contains the complete nonrecursive data authenticated by the fresh report key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeFreshRestoreAllocationData {
    /// Binds the actual inactive target and assigned startup request.
    pub scope: PacketNativeFreshRestoreAllocationScope,
    /// Names the actual retained and prospective fixed fresh-target terms.
    pub storage: PacketNativeFreshRestoreAllocationStorage,
}

impl PacketNativeFreshRestoreAllocationData {
    /// Checks closed data and returns its separately scoped requested peak.
    ///
    /// # Errors
    /// Refuses invalid target references, absent generation/process, truncated
    /// nonce or digests, missing storage terms or arithmetic overflow.
    pub fn validate_data(&self) -> Result<u64, ProviderError> {
        let scope = &self.scope;
        if scope.native_pid.get() == 0
            || scope.native_pid.get() > u32::MAX.into()
            || scope.owner_generation.get() == 0
        {
            return Err(invalid());
        }
        scope.owner_binding.validate()?;
        scope.world.validate()?;
        scope.closed_gate_receipt.validate()?;
        for value in [
            &scope.session,
            &scope.incarnation,
            &scope.node,
            &scope.owner,
            &scope.prepared_token,
            &scope.admission,
        ] {
            value.validate()?;
        }
        for value in [
            &scope.nonce,
            &scope.assigned_query,
            &scope.completed_admit_request,
            &scope.completed_admit_response,
            &scope.ack_context,
        ] {
            digest(value)?;
        }
        self.storage.requested_peak_data()
    }
}

/// Carries keyed data authentication without constructing a native permission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeFreshRestoreAllocationProof {
    /// Selects the separate proof13 grammar.
    pub schema: String,
    /// Names the fixed keyed canonical algorithm.
    pub algorithm: String,
    /// Commits complete canonical report data.
    pub context_digest: Bytes,
    /// Authenticates that data with a separately derived fresh-birth key.
    pub mac: Bytes,
}

impl PacketNativeFreshRestoreAllocationProof {
    /// Checks exact proof syntax without authenticating its key or data.
    ///
    /// # Errors
    /// Refuses another schema, algorithm, digest extent or MAC extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_FRESH_RESTORE_ALLOCATION_PROOF
            || self.algorithm != FRESH_RESTORE_ALLOCATION_ALGORITHM
        {
            return Err(invalid());
        }
        digest(&self.context_digest)?;
        digest(&self.mac)
    }
}

/// Retains the exact fresh-target data and its independently derived key proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeFreshRestoreAllocationReport {
    /// Selects the fresh inactive report13 grammar.
    pub schema: String,
    /// Contains all authenticated target, original and storage fields.
    pub data: PacketNativeFreshRestoreAllocationData,
    /// Authenticates the complete data without any recursive response reference.
    pub proof: PacketNativeFreshRestoreAllocationProof,
}

impl PacketNativeFreshRestoreAllocationReport {
    /// Checks report syntax and arithmetic without issuing a whole-context ticket.
    ///
    /// # Errors
    /// Refuses another schema, malformed data/proof, missing terms or overflow.
    pub fn validate_data(&self) -> Result<u64, ProviderError> {
        if self.schema != PACKET_FRESH_RESTORE_ALLOCATION_REPORT {
            return Err(invalid());
        }
        self.proof.validate_data()?;
        self.data.validate_data()
    }
}

/// Names the exact report returned by the completed selected startup query.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeFreshRestoreAllocationReceipt {
    /// Selects the startup response extension13 grammar.
    pub schema: String,
    /// Retains the complete report reference, including media type and length.
    pub allocation: ContentRef,
}

impl PacketNativeFreshRestoreAllocationReceipt {
    /// Checks the exact bounded report reference as data.
    ///
    /// # Errors
    /// Refuses another schema/media type, invalid reference or report extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT {
            return Err(invalid());
        }
        report_reference(&self.allocation)
    }
}

/// Binds a later assigned Prepare to the same completed startup query and report.
///
/// The full extension remains in the source-signed Prepare envelope digest.
/// Native also compares it with its retained successful fresh-query owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeFreshRestoreAllocationPrepareBinding {
    /// Selects the independent Prepare binding13 grammar.
    pub schema: String,
    /// Commits the complete actual startup request.
    pub assigned_query: Bytes,
    /// Commits its complete actual successful response.
    pub completed_query_response: Bytes,
    /// Retains the exact bounded report reference.
    pub allocation: ContentRef,
}

impl PacketNativeFreshRestoreAllocationPrepareBinding {
    /// Checks binding syntax without authenticating a query or Prepare.
    ///
    /// # Errors
    /// Refuses another schema, digest extent, report media type or report extent.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING {
            return Err(invalid());
        }
        digest(&self.assigned_query)?;
        digest(&self.completed_query_response)?;
        report_reference(&self.allocation)
    }
}

fn report_reference(reference: &ContentRef) -> Result<(), ProviderError> {
    reference.validate()?;
    if reference.media_type != PACKET_FRESH_RESTORE_ALLOCATION_MEDIA
        || reference.length.get() == 0
        || reference.length.get() > MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES as u64
    {
        return Err(invalid());
    }
    Ok(())
}

fn digest(value: &Bytes) -> Result<(), ProviderError> {
    if value.as_slice().len() != 32 {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("fresh inactive restoration allocation data")
}
