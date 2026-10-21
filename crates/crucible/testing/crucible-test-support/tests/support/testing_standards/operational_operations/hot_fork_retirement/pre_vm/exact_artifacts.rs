//! Rejects lost exact-restore artifact custody in complete producer clauses.
//!
//! These mutations check source contracts, not installed Source qualification.

use super::Fixture;

#[test]
fn exact_artifact_preparation_rejects_lost_targets_and_foreign_receivers()
-> Result<(), Box<dyn std::error::Error>> {
    let preparation = Fixture::load(0)?;

    for (path, before, after, reason) in [
        (
            "original_node.rs",
            "retained.owner.is_none() && self.exact_launch.returned()",
            "retained.owner.is_none()",
            "process absence substitutes for actual artifact destruction",
        ),
        (
            "original_node/exact_artifacts.rs",
            "drop(artifacts);",
            "std::mem::forget(artifacts);",
            "artifact closure declared without actual destruction",
        ),
        (
            "original_node/exact_artifacts.rs",
            "ArtifactState::Issued | ArtifactState::Closing | ArtifactState::Uncertain(_) => { return false; }",
            "ArtifactState::Issued | ArtifactState::Closing | ArtifactState::Uncertain(_) => { return true; }",
            "uncertain artifact destruction treated as physical return",
        ),
        (
            "original_node/exact_artifacts.rs",
            "if !matches!(*state, ArtifactState::Closing)",
            "if false",
            "concurrent duplicate disposition erased after destruction",
        ),
        (
            "supervision/exact_restore/artifacts.rs",
            "if !receiver.reserve_exact_artifact_transfer()",
            "if false",
            "process return races ahead of unreserved artifact custody",
        ),
        (
            "supervision/exact_restore/artifacts.rs",
            "binding.source_helper_lender().and_then(|lender| lender.controller())",
            "foreign_binding.source_helper_lender().and_then(|lender| lender.controller())",
            "preparation artifacts borrow a different Source recipient",
        ),
        (
            "supervision/exact_restore.rs",
            "let mut artifacts = IssuedExactRestoreArtifacts::new(&binding, run_directory, target)?; let prepared = artifacts.preparation()?;",
            "run_directory.prepare_vmstate_container_guarded(config.qemu_executable(), &process_contract)?; let mut artifacts = IssuedExactRestoreArtifacts::new(&binding, run_directory, target)?; let prepared = artifacts.preparation()?;",
            "VMState helper effect precedes the retained artifact guard",
        ),
        (
            "supervision/exact_restore.rs",
            "prepared.ram_inputs = Some(ram_inputs);",
            "drop(ram_inputs);",
            "sealed inputs leave custody before launch admission",
        ),
        (
            "supervision/exact_restore.rs",
            "let node = launch_atomic_exact_restore(&config, admission, false, binding, workspace)?; prepared.complete_preparation()?;",
            "prepared.complete_preparation()?; let node = launch_atomic_exact_restore(&config, admission, false, binding, workspace)?;",
            "sealed restore inputs consumed before the actual child restore returns",
        ),
        (
            "spawn/materialization/exact_restore.rs",
            "if self.exact_checkpoint_target.is_some()",
            "if false",
            "preparation can replace an already retained authenticated target",
        ),
        (
            "spawn/materialization/exact_restore.rs",
            "self.exact_checkpoint_target = Some(target);",
            "drop(target);",
            "authenticated target is destroyed before materialization failures",
        ),
        (
            "supervision/node_step_gate.rs",
            "ram_inputs: &'a crate::spawn::SealedAtomicExactRestoreInputs,",
            "ram_inputs: crate::spawn::SealedAtomicExactRestoreInputs,",
            "launch admission consumes sealed inputs outside the retained guard",
        ),
        (
            "process_purpose/source_cleanup.rs",
            "installed.subdivision_index == 0 && installed.index == self.index",
            "installed.index == self.index",
            "artifact recipient can come from a non-Source installed share",
        ),
        (
            "supervision/exact_restore/artifacts.rs",
            "if !same_receiver || owner.node_mut().is_err()",
            "if false",
            "foreign or unassembled Node enters exact artifact handoff",
        ),
        (
            "supervision/exact_restore/artifacts.rs",
            "drop(self); receiver.record_returned_cleanup_failure(primary);",
            "receiver.record_returned_cleanup_failure(primary); drop(self);",
            "failure published before actual files reach their receiver",
        ),
        (
            "supervision/exact_restore/artifacts.rs",
            "if let Some(artifacts) = self.artifacts.take()",
            "if let Some(artifacts) = None",
            "abandoned launch discards actual artifact return",
        ),
        (
            "supervision/exact_restore.rs",
            "node: crate::node::IssuedLaunchOwner, artifacts: IssuedExactRestoreArtifacts,",
            "artifacts: IssuedExactRestoreArtifacts, node: crate::node::IssuedLaunchOwner,",
            "artifact cell returned before the abandoned process owner",
        ),
        (
            "supervision/exact_restore/artifacts.rs",
            "pub(super) ram_inputs: Option<crate::spawn::SealedAtomicExactRestoreInputs>, pub(super) target: Option<crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode>, pub(super) run_directory: QemuPreparedRunDirectory,",
            "pub(super) run_directory: QemuPreparedRunDirectory, pub(super) target: Option<crucible_engine::exact_checkpoint::ExactCheckpointVerifiedNode>, pub(super) ram_inputs: Option<crate::spawn::SealedAtomicExactRestoreInputs>,",
            "directory final custody drops before actual sealed input descriptors",
        ),
        (
            "failed_launch/issued.rs",
            "self.receiver.clone()",
            "foreign_receiver.clone()",
            "joint artifact handoff uses an unrelated process recipient",
        ),
    ] {
        preparation.rejects(path, before, after, reason);
    }
    Ok(())
}
