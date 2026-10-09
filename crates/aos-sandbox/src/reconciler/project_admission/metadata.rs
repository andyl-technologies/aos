//! Canonical nonauthorizing metadata retained in the original Controller Effect.
//!
//! Decoding preserves historical bytes only. The parent module owns protected
//! admission joins, capacity transfers, authenticated Root proofs, and Source ACK.
//!
//! ```text
//! AOSCPT01 | version:u16 | phase:u8 | terminal-kind:u8 | projection-length:u32 |
//! admission-revision:32 | admission-generation:u64 | source-commitment:32 |
//! sandbox:16 | project:16 | capacity-id:32 | Source-reservation[136] |
//! Source-challenge[232] or zero | Root-terminal[312] or zero |
//! historical-source-heads[160] | retired-floor-digest:32 or zero |
//! immutable-original-AOSPRJ01[projection-length] | domain-separated-checksum:32
//! ```

pub(in crate::reconciler) use aos_sandbox_protocol::domain_ledger::project_admission_metadata::{
    MAXIMUM_RECORD_BYTES, ProjectAdmissionMetadataV1 as ProjectAdmissionMetadata,
    ProjectAdmissionPhaseV1 as ProjectAdmissionPhase,
    RetainedRootProjectTerminalV1 as RetainedRootProjectTerminal,
};

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
