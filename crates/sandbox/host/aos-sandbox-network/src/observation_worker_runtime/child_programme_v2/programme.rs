//! Joins the complete finite observer invoice on the original parent's bank.
//!
//! The actual protected parent obtains the crypto term from its same Authority
//! and signed quartet before PREBIRTH. This compiler creates only demand DATA;
//! native inherited Source custody and its private payer remain independent.

use super::*;
use crate::kernel_reader::observation_helpers_v2::{
    ObservationProgrammeDataV2, observation_programme_data_v2,
};
use aos_sandbox_broker::receiving::NetworkChildOriginOriginalV2;

/// Retains the finite recipe and the joined prospective whole-child demand.
pub(crate) struct ObserverWholeProgrammeDataV2 {
    pub(super) recipe: Option<ObservationProgrammeDataV2>,
    pub(super) demand: ResourceVector,
    pub(super) source_queries: u64,
}

impl ObserverWholeProgrammeDataV2 {
    /// Reports the whole additional child demand to the actual same-F issuer.
    pub(crate) fn receiving_obligations_data_v2(&self) -> ResourceVector {
        self.demand
    }

    /// Reports the exact positive Source programme; custody ACK adds no query.
    pub(crate) fn source_queries_data_v2(&self) -> u64 {
        self.source_queries
    }
}

/// Derives the actual conditional fork frontier from the closed O programme.
///
/// Successful startup/header proofs and each completed command retire before
/// the next helper. A failed predecessor cannot reach a later clone. Root D,
/// Source and role validation still gate every actual native helper.
pub(super) fn observer_fork_table_data_v2() -> Option<usize> {
    use crate::kernel_reader::{NetworkArtifactPathOriginalV4, NetworkArtifactRoleV4 as Role};
    use aos_sandbox_linux::process::FixedProcessRunOriginalV3;
    let mut steady = NetworkChildOriginOriginalV2::positive_retained_frontier_files_data_v2()?;
    for role in [
        Role::Ip,
        Role::Nft,
        Role::Enforcement,
        Role::BpfObserver,
        Role::LeaseObject,
    ] {
        steady =
            steady.checked_add(NetworkArtifactPathOriginalV4::receiving_obligations_v4(role)?.1)?;
    }
    // Same actual single-thread DIR; stdin socket duplicate and its peer;
    // six original public credentials; full and namespace transport subjects;
    // two donated namespace FDs; admitted read's retained Source stat proof.
    let resident = [
        "single-thread DIR",
        "stdin duplicate",
        "Netd peer",
        "plan public",
        "lease public",
        "plan policy",
        "lease policy",
        "node",
        "boot",
        "full subject",
        "namespace subject",
        "host namespace",
        "target namespace",
        "read stat",
    ]
    .len();
    steady = steady.checked_add(resident)?;
    let setup = FixedProcessRunOriginalV3::path_spawn_setup_files_data_v3(false, 0)?;
    let scanner = 1usize;
    let attestation =
        crate::kernel_reader::NetworkArtifactCurrentOriginalV4::receiving_obligations_v4(
            Role::LeaseObject,
            false,
        )?
        .1;
    steady.checked_add(attestation.max(setup.checked_add(scanner)?))
}

/// Compiles the actual full prospective child programme before PREBIRTH.
///
/// The crypto term must be obtained from the actual same protected Authority's
/// signed-admission supplier and the retained original authorization quartet.
/// A child may pass ZERO only to recompute a deny-only noncrypto lower bound:
/// its financial authority remains the genuine private parent issuer, never
/// this numeric vector. The native carrier cannot replace that parent debit.
pub(crate) fn observer_whole_programme_data_v2(
    plan: &crate::NetworkKernelPlanV1,
    verb: aos_sandbox_model::BrokerVerb,
    sections: [usize; 9],
    native_limits: [u64; 3],
    signed_verification_demand: ResourceVector,
) -> Option<ObserverWholeProgrammeDataV2> {
    crate::observer_handoff_v2::observer_handoff_length_data_v2(sections)?;
    let table = observer_fork_table_data_v2()?;
    if u64::try_from(table).ok()? > native_limits[1] {
        return None;
    }
    let recipe = observation_programme_data_v2(plan, verb, sections[0], native_limits, table)?;
    // Recipe includes opening2, signed read2 and stable boundaries6. The
    // enclosing actual programme adds initial1, startup2, READY2, header/full4,
    // namespace2 and result2. ACK/negative are already-issued custody only.
    let source_queries = recipe.source_queries_data_v2().checked_add(13)?;
    let terms = [
        recipe.receiving_obligations_data_v2(),
        NetworkChildOriginOriginalV2::initial_native_obligations_data_v2()?,
        NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(1)?,
        observer_startup_obligations_data_v2()?,
        ready::observer_ready_obligations_data_v2()?,
        handoff::observer_handoff_obligations_data_v3(sections)?,
        execution::observer_execution_obligations_data_v2(sections[8])?,
        terminal::observer_terminal_send_obligations_data_v2()?,
        disposition::observer_input_disposition_obligations_data_v3(sections)?,
        signed_verification_demand,
        ResourceVector::ZERO.with(D::Pids, 1).with(
            D::MemoryBytes,
            u64::try_from(std::mem::size_of::<actor::ObserverActorOriginalV2>().checked_mul(2)?)
                .ok()?,
        ),
    ];
    let demand = terms
        .into_iter()
        .try_fold(ResourceVector::ZERO, |sum, term| sum.checked_add(term).ok())?;
    Some(ObserverWholeProgrammeDataV2 {
        recipe: Some(recipe),
        demand,
        source_queries,
    })
}
