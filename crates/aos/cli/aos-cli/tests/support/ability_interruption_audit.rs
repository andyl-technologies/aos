//! Candidate-linked checks of native interrupted dispatch and exact-intent recovery.

#[path = "ability_audit_common.rs"]
mod common;

fn main() -> anyhow::Result<()> {
    common::run(common::AuditKind::Recovery)
}
