//! Candidate-linked checks of native preflight admission and checked outcomes.

#[path = "ability_audit_common.rs"]
mod common;

fn main() -> anyhow::Result<()> {
    common::run(common::AuditKind::Admission)
}
