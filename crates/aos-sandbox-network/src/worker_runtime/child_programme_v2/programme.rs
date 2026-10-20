//! Joins the complete real P programme before its native physical birth.
//!
//! Only the protected same-Netd issuer supplies the signed-model verification
//! term and performs the actual original-ledger debit. This finite geometry is
//! DATA. The recipient can recompute it only as a denial check against its
//! original authenticated paid programme, never as a new bank or Source.

use super::*;
use crate::kernel_mutator::{MutationProgrammeDataV2, mutation_programme_data_v2};
use crate::kernel_reader::{NetworkArtifactPathOriginalV4, NetworkArtifactRoleV4 as Role};
use crate::worker_runtime::child_intake_v2::NetworkPreparationIntakeOriginalV2;
use aos_sandbox_broker::receiving::NetworkChildOriginOriginalV2;
use aos_sandbox_core::BrokerVerb;
use aos_sandbox_linux::process::FixedProcessRunOriginalV3;

pub(crate) struct PreparationWholeProgrammeDataV2 {
    pub(super) recipe: MutationProgrammeDataV2,
    pub(super) demand: ResourceVector,
    pub(super) source_queries: u64,
    pub(super) maximum_table: usize,
}

impl PreparationWholeProgrammeDataV2 {
    pub(crate) fn receiving_obligations_data_v2(&self) -> ResourceVector {
        self.demand
    }
    pub(crate) fn source_queries_data_v2(&self) -> u64 {
        self.source_queries
    }
}

/// Derives the actual held P objects and prospective fixed spawn/scanner row.
fn preparation_fork_table_data_v2(
    plan: &crate::NetworkKernelPlanV1,
    verb: BrokerVerb,
) -> Option<usize> {
    let mut steady = NetworkChildOriginOriginalV2::positive_retained_frontier_files_data_v2()?;
    for role in [
        Role::Ip,
        Role::Nft,
        Role::Enforcement,
        Role::LeaseLoader,
        Role::LeaseObject,
    ] {
        steady =
            steady.checked_add(NetworkArtifactPathOriginalV4::receiving_obligations_v4(role)?.1)?;
    }
    // The completed configuration keeps its directory and same six public
    // originals; the secret File has actually retired before materialization.
    steady = steady
        .checked_add(aos_sandbox_broker::ProtectedBrokerPublicCredentialRole::ALL.len())?
        .checked_add(1)?;
    steady = steady.checked_add(
        crate::journal::NetworkWorkerReplayCapturedJournalOpenV4::positive_retained_frontier_files_data_v2()?,
    )?;
    steady = steady.checked_add(
        [
            "single-thread DIR",
            "bootstrap namespace",
            "stdin duplicate",
            "Netd peer",
        ]
        .len(),
    )?;
    let (donations, inputs, setup) = match verb {
        BrokerVerb::NetworkPrepare => {
            let inputs = usize::from(
                plan.observation_expectation().kind()
                    != aos_sandbox_core::model::NetworkKind::Isolated,
            )
            .checked_add(1)?;
            (
                1usize,
                inputs,
                FixedProcessRunOriginalV3::path_spawn_setup_files_data_v3(true, 0)?,
            )
        }
        BrokerVerb::NetworkDestroy => (
            2usize,
            0usize,
            FixedProcessRunOriginalV3::path_spawn_setup_files_data_v3(false, 0)?,
        ),
        _ => return None,
    };
    // Namespace donors remain owned after positive frame subject/stat proof
    // retirement. Nft input memfds remain on their actual helper originals.
    // Internal current-before proofs retire before setup; failed predecessors
    // cannot reach clone. The same native census independently enforces T.
    steady
        .checked_add(donations)?
        .checked_add(inputs)?
        .checked_add(setup)?
        .checked_add(1) // actual census scanner, closed before clone
}

/// Compiles the full fixed P startup/intake/admission/effect/terminal invoice.
pub(crate) fn preparation_whole_programme_data_v2(
    plan: &crate::NetworkKernelPlanV1,
    verb: BrokerVerb,
    input_bytes: usize,
    signed_request_body_bytes: usize,
    native_limits: [u64; 3],
    signed_verification_demand: ResourceVector,
) -> Option<PreparationWholeProgrammeDataV2> {
    if native_limits.into_iter().any(|limit| limit == 0) {
        return None;
    }
    let table = preparation_fork_table_data_v2(plan, verb)?;
    if u64::try_from(table).ok()? > native_limits[1] {
        return None;
    }
    let recipe = mutation_programme_data_v2(plan, verb, native_limits[1], table)?;
    let frames = input_bytes.div_ceil(super::super::MAXIMUM_FRAME_PAYLOAD_BYTES);
    if frames == 0 {
        return None;
    }
    // Effects include their actual outer and helper pairs. The enclosing
    // initial1/startup2/READY2/intake2N/signed2/result2 add9+2N queries.
    let source_queries = recipe
        .source_queries_data_v2()
        .checked_add(9)?
        .checked_add(u64::try_from(frames.checked_mul(2)?).ok()?)?;
    let startup = preparation_startup_obligations_data_v2().ok()?;
    let replay = NetworkWorkerReplayOpeningOriginalV4::complete_child_receiving_demand_v4().ok()?;
    let intake = NetworkPreparationIntakeOriginalV2::receiving_demand_data_v2(input_bytes)?;
    let signed =
        signed_admission::PreparationSignedOriginalV2::receiving_obligations_data_v2(input_bytes)?;
    let sends = terminal::PreparationPositiveSendOriginalV2::receiving_obligations_data_v2()?;
    let disposition =
        disposition::PreparationDispositionOriginalV2::receiving_obligations_data_v2(input_bytes)?;
    let native = NetworkChildOriginOriginalV2::initial_native_obligations_data_v2()?;
    let terms = [
        native,
        NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(1)?,
        startup, replay, intake, signed,
        aos_sandbox_protocol::authenticated_session::all_methods::request_capture::AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(signed_request_body_bytes)?,
        crate::kernel_plan::compilation_receiving_demand_v4().ok()?,
        recipe.receiving_obligations_data_v2(),
        execution::PreparationExecutionOriginalV2::receiving_obligations_data_v2()?,
        sends, sends, disposition, signed_verification_demand,
        ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(std::mem::size_of::<actor::PreparationActorOriginalV2>().checked_mul(2)?).ok()?)
            .with(D::Pids, 1),
    ];
    let mut demand = terms
        .into_iter()
        .try_fold(ResourceVector::ZERO, |sum, term| sum.checked_add(term).ok())?;
    // All byte/model/error terms stay cumulative. Physical FD envelopes use
    // actual first-failure stop: a failed startup/input cannot enter a helper;
    // completed proof temporaries have actually retired at that next frontier.
    // A failed helper may remain alive through the separately owed custody
    // suffix, so its two-table envelope PLUS that suffix remains payable.
    let staging = [startup, replay, intake, signed, sends, disposition]
        .into_iter()
        .try_fold(
            u64::try_from(
                NetworkChildOriginOriginalV2::positive_retained_frontier_files_data_v2()?,
            )
            .ok()?,
            |sum, term| sum.checked_add(term.get(D::OpenFiles)),
        )?;
    let effects = recipe
        .receiving_obligations_data_v2()
        .get(D::OpenFiles)
        .checked_add(disposition.get(D::OpenFiles))?;
    demand = demand.with(
        D::OpenFiles,
        native.get(D::OpenFiles).max(staging).max(effects),
    );
    Some(PreparationWholeProgrammeDataV2 {
        recipe,
        demand,
        source_queries,
        maximum_table: table,
    })
}
