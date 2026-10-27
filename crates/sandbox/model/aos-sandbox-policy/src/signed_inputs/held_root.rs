//! Shares the held Root signed-input recipe without owning a native role.
//!
//! The recipe expands inside the original caller frame. Its two lexical
//! admission sites keep the genuine native owner's existing debit order;
//! passive readers perform no admission. Neither supplied rows nor successful
//! signatures establish a current Root owner or publication permission.

/// Expands the canonical held-row deployment and project verification recipe.
///
/// The caller supplies its existing pin decoder, error projection and two
/// lexical admission blocks. These blocks remain in the same frame before
/// deployment decoding and project verification; no callback or new owning
/// result is introduced. Output identifiers name the caller's original locals.
///
/// Verification refuses missing rows, substituted input bytes, invalid signed
/// packets, stale signer generations and a mismatched deployment prerequisite.
#[macro_export]
macro_rules! verify_held_root_signed_sources_data_v1 {
    (
        journal: $journal:ident,
        project_input: $project_input:ident,
        deployment_inputs: $deployment_inputs:ident,
        now: $now:ident,
        outputs: ($project:ident, $deployment:ident, $decoded:ident),
        changed_cut: $changed:expr,
        changed_projection: [$($changed_projection:tt)*],
        decode_pins: $pins:ident => $decode_pins:block,
        signed_projection: [$($signed_projection:tt)*],
        before_deployment: $before_deployment:block,
        before_project: $project_packet:ident => $before_project:block $(,)?
    ) => {
        let namespace = $crate::signed_inputs::HeldRootRecordNamespaceV1::DesiredState;
        let $pins = $journal
            .get(namespace, $crate::journal_keys::SIGNER_PINS_KEY)
            .ok_or($changed)?;
        let (deployment_generation, deployment_key, project_generation, project_key) =
            $decode_pins;
        let deployment_packet = $journal
            .get(namespace, $crate::journal_keys::HEAD_KEY)
            .ok_or($changed)?;
        $before_deployment
        let $deployment = $crate::signed_inputs::verify_policy_deployment_head_v1(
            deployment_packet,
            $deployment_inputs,
            &deployment_key,
            $now,
        ) $($signed_projection)* ?;
        let $decoded = $crate::signed_inputs::decode_policy_deployment_sources_v1(
            $deployment_inputs,
            $deployment,
        ) $($signed_projection)* ?;
        let $project_packet = $journal
            .get(namespace, $crate::journal_keys::PROJECT_HEAD_KEY_V2)
            .ok_or($changed)?;
        if $journal.get(namespace, $crate::journal_keys::PROJECT_INPUT_KEY_V2)
            != Some($project_input)
        {
            return Err($changed $($changed_projection)*);
        }
        $before_project
        let $project = $crate::signed_inputs::verify_signed_project_policy_source_v2(
            $project_packet,
            $project_input,
            &project_key,
            $now,
        ) $($signed_projection)* ?;
        if $project.head().deployment_signer_generation() != deployment_generation
            || $project.head().project_signer_generation() != project_generation
            || $project.head().prerequisite_claims()[1] != $deployment.packet_digest()
        {
            return Err($changed $($changed_projection)*);
        }
    };
}
