//! Prices the sole finite typed P mutation recipe before helper allocation.
//!
//! The protected parent joins this passive quote to the actual initial Source,
//! startup, signed intake/admission, terminal and transport terms before birth.
//! It constructs no bank, namespace, signed permission or native resource cap.

use super::*;
use aos_sandbox_model::{BrokerVerb, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::process::{FixedProcessRunOriginalV3, NetworkWorkerForkObservationV4};

/// Keeps the actual typed recipe's bounded dimensions and complete effect demand.
pub(crate) struct MutationProgrammeDataV2 {
    helpers: usize,
    artifacts: usize,
    maximum_table: usize,
    native_nofile: u64,
    source_queries: u64,
    demand: ResourceVector,
}

impl MutationProgrammeDataV2 {
    pub(crate) fn helper_count_data_v2(&self) -> usize { self.helpers }

    pub(crate) fn artifact_count_data_v2(&self) -> usize { self.artifacts }

    pub(crate) fn source_queries_data_v2(&self) -> u64 { self.source_queries }

    pub(crate) fn receiving_obligations_data_v2(&self) -> ResourceVector { self.demand }

    /// Creates only fixed destinations after the enclosing genuine paid gate.
    pub(crate) fn helper_originals_data_v2(&self) -> Option<Vec<NetworkSourceHelperOriginalV2>> {
        (0..self.helpers).map(|_| NetworkSourceHelperOriginalV2::new(
            self.native_nofile, self.maximum_table,
        )).collect()
    }

    pub(crate) fn artifact_originals_data_v2(&self) -> Vec<NetworkSourceArtifactOriginalV2> {
        (0..self.artifacts).map(|_| NetworkSourceArtifactOriginalV2::new()).collect()
    }
}

/// Quotes the real Prepare or Destroy effects, excluding their enclosing actor.
pub(crate) fn mutation_programme_data_v2(
    plan: &crate::NetworkKernelPlanV1,
    verb: BrokerVerb,
    native_nofile: u64,
    maximum_table: usize,
) -> Option<MutationProgrammeDataV2> {
    use NetworkStatusHelperRoleV4 as Role;
    let expectation = plan.observation_expectation();
    let managed = match expectation.kind() {
        NetworkKind::Isolated => false,
        NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published => true,
        NetworkKind::Host => return None,
    };
    let (helpers, artifacts, boundaries, roles) = match verb {
        BrokerVerb::NetworkPrepare => {
            let helpers = preparation_helper_count_data_v2(expectation)?;
            let nft = if managed { 2 } else { 1 };
            let inherited = usize::from(managed);
            let loader = usize::from(managed);
            let ip = helpers.checked_sub(nft)?.checked_sub(inherited)?.checked_sub(loader)?;
            (helpers, preparation_artifact_count_data_v2()?, 4usize,
                [(Role::NftBatch, nft), (Role::IpWithHostNamespace, inherited),
                 (Role::LeaseLoader, loader), (Role::Ip, ip), (Role::Ip, 0)])
        }
        BrokerVerb::NetworkDestroy => {
            let helpers = destroy_helper_count_data_v2(expectation)?;
            let loader = usize::from(managed);
            let inventories = if managed { 3usize } else { 0usize };
            let ip = helpers.checked_sub(1)?.checked_sub(loader)?.checked_sub(inventories)?;
            (helpers, destroy_artifact_count_data_v2()?, 4usize,
                [(Role::NftDestroy, 1usize), (Role::LeaseLoader, loader),
                 (Role::IpLinks, inventories), (Role::Ip, ip), (Role::Ip, 0usize)])
        }
        _ => return None,
    };
    if helpers == 0 || roles.iter().try_fold(0usize,
        |sum, (_, count)| sum.checked_add(*count))? != helpers {
        return None;
    }
    let frontiers = helpers.checked_add(boundaries)?;
    let source_queries = u64::try_from(frontiers.checked_mul(2)?).ok()?;
    let mut demand = NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(source_queries)?;
    let mut bytes = std::mem::size_of::<MutationProgrammeDataV2>().checked_mul(2)?
        .checked_add(std::mem::size_of::<NetworkSourceHelperOriginalV2>()
            .checked_mul(2)?.checked_mul(helpers)?)?
        .checked_add(std::mem::size_of::<NetworkSourceArtifactOriginalV2>()
            .checked_mul(2)?.checked_mul(artifacts)?)?
        .checked_add(std::mem::size_of::<NetworkPrepareEffectsOriginalV2>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<NetworkDestroyEffectsOriginalV2>().checked_mul(2)?)?;
    let directory = FixedProcessRunOriginalV3::task_directory_transient_bytes_data_v3()?;
    let mut metadata = 0usize;
    for (role, count) in roles {
        // Every runner/error owner remains priced per call. Only the exact
        // positive-retired proc-task directory cannot coexist across helpers:
        // failure stops the finite recipe before another entry is possible.
        let native = NetworkStatusHelperOriginalV4::receiving_programme_bytes_data_v2(
            role, native_nofile, maximum_table,
        )?.checked_sub(directory)?;
        bytes = bytes.checked_add(native.checked_mul(count)?)?;
        metadata = metadata.checked_add(
            NetworkArtifactCurrentOriginalV4::receiving_obligations_v4(
                role.artifact(), false,
            )?.2.checked_mul(2)?.checked_mul(count)?,
        )?;
    }
    bytes = bytes.checked_add(directory)?;

    // Every reached artifact/hash/stat original remains resident. Its completed
    // positive native descriptors retire, never its error/metadata backing.
    let mut largest_artifact_files = 0usize;
    for role in [NetworkArtifactRoleV4::Ip, NetworkArtifactRoleV4::Nft,
        NetworkArtifactRoleV4::Enforcement, NetworkArtifactRoleV4::LeaseLoader,
        NetworkArtifactRoleV4::LeaseObject] {
        let term = NetworkArtifactCurrentOriginalV4::receiving_obligations_v4(
            role, matches!(role, NetworkArtifactRoleV4::Enforcement),
        )?;
        let count = artifacts.checked_div(5)?;
        bytes = bytes.checked_add(term.0.checked_mul(count)?)?;
        metadata = metadata.checked_add(term.2.checked_mul(count)?)?;
        largest_artifact_files = largest_artifact_files.max(term.1);
    }
    type Pair = RetainedKernelPairedClockAttemptV1<ClockError>;
    bytes = bytes.checked_add(Pair::dominant_requested_bytes_v1()?
        .checked_mul(2)?.checked_mul(frontiers)?)?;
    metadata = metadata.checked_add(Pair::receiving_metadata_cells_v1()?
        .checked_mul(2)?.checked_mul(frontiers)?)?;
    metadata = metadata.checked_add(
        NetworkWorkerForkObservationV4::programme_metadata_entries_data_v2(
            native_nofile, maximum_table,
        )?.checked_mul(helpers)?,
    )?;
    let kernel = aos_sandbox_linux::kernel_clone::dominant_birth_bytes_data_v1(
        native_nofile.checked_sub(1)?,
        NetworkStatusHelperOriginalV4::maximum_clone_arguments_data_v2()?,
    )?;
    bytes = bytes.checked_add(usize::try_from(kernel).ok()?)?;
    let mut publication_files = 0;
    if verb == BrokerVerb::NetworkPrepare {
        bytes = bytes.checked_add(super::super::nft_receiving_v2::nft_construction_bytes_data_v2(expectation)?)?;
        let publication = NetworkNamespacePublicationOriginalV2::receiving_obligations_data_v2()?;
        publication_files = publication.get(D::OpenFiles);
        demand = demand.checked_add(publication.with(D::OpenFiles, 0)).ok()?;
    } else {
        let pin = crate::namespace_pin::NetworkNamespaceRemovalOriginalV2::receiving_obligations_data_v2()?;
        // The exact native pin programme runs only after all helpers stop.
        // Its fixed result owners stay resident through O handback; its FDs
        // join the conditional physical frontier below, never a refund.
        publication_files = pin.get(D::OpenFiles);
        demand = demand.checked_add(pin.with(D::OpenFiles, 0)).ok()?;
        // One fresh Root pair follows the final Source challenge immediately
        // before unmount, in addition to that frontier's ordinary two bookends.
        bytes = bytes.checked_add(Pair::dominant_requested_bytes_v1()?)?;
        metadata = metadata.checked_add(Pair::receiving_metadata_cells_v1()?)?;
        if managed {
            bytes = bytes.checked_add(destroy_link_inventory_model_bytes_data_v2()?)?;
        }
        // The actual pending-step bridge retains one real plan clone per step.
        let plan_demand = crate::kernel_plan::compilation_receiving_demand_v4().ok()?;
        for _ in 0..3 { demand = demand.checked_add(plan_demand).ok()?; }
    }
    let files = NetworkWorkerForkObservationV4::programme_fork_files_data_v2(
        native_nofile, maximum_table,
    )?
        // A native failure can leave the actual helper unresolved while its
        // independently owed artifact after and three distinct clock posts
        // run. Those new parent descriptors coexist with both copied tables.
        .checked_add(largest_artifact_files)?
        .checked_add(Pair::MAXIMUM_RETAINED_FILES_V1.checked_mul(3)?)?;
    let files = if verb == BrokerVerb::NetworkDestroy {
        // T includes the actual prospective spawn aliases and census scanner.
        // They do not exist during the later pin syscall. All real pinned
        // roots/donations remain on the child while pin and owed clock tails
        // coexist; there is no further helper clone on this path.
        let spawn = FixedProcessRunOriginalV3::path_spawn_setup_files_data_v3(false, 0)?;
        let pin_peak = maximum_table.checked_sub(spawn.checked_add(1)?)?
            .checked_add(usize::try_from(publication_files).ok()?)?
            .checked_add(Pair::MAXIMUM_RETAINED_FILES_V1.checked_mul(3)?)?
            .checked_add(1)?;
        files.max(pin_peak)
    } else { files };
    demand = demand.checked_add(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .with(D::OpenFiles, u64::try_from(files).ok()?.max(publication_files))
        .with(D::MetadataEntries, u64::try_from(metadata).ok()?)
        .with(D::Pids, 1)).ok()?;
    Some(MutationProgrammeDataV2 { helpers, artifacts, maximum_table,
        native_nofile, source_queries, demand })
}


// The existing absence-tolerant Destroy parser accepts arbitrary serde_json
// Value fields before inspecting each ifname. The complete document can be
// foreign, so pricing only the desired interface rows would miss its backing.
// Each sequential inventory drops that document/name set after the actual
// semantic Result and before the next helper; the native stdout stays owned.
fn destroy_link_inventory_model_bytes_data_v2() -> Option<usize> {
    use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
    let wire = NetworkStatusHelperRoleV4::IpLinks.maximum_stdout_bytes_v4();
    use crate::kernel_reader::observation_helpers_v2::{
        ObservationJsonLayoutDataV2, json_receiving_bytes_data_v2,
    };
    // The same qualified JSON geometry as the O reader accepts the entire
    // foreign document. This parser adds only its own borrowed-name set.
    let json = json_receiving_bytes_data_v2(
        ObservationJsonLayoutDataV2 {
            nodes: wire.checked_div(2)?.checked_add(1)?,
            maps: wire.checked_div(5)?.checked_add(1)?,
            arrays: wire.checked_div(2)?.checked_add(1)?,
        },
        wire,
    )?;
    // Every accepted record contains at least {"ifname":"a"}; set keys borrow
    // those already-priced strings rather than cloning their contents.
    let records = wire.checked_div(b"{\"ifname\":\"a\"}".len())?.checked_add(1)?;
    let names = nodes::<&str, ()>(records)?;
    json.checked_add(names)?
        .checked_add(std::mem::size_of::<std::collections::BTreeSet<&str>>())?
        .checked_add(std::mem::size_of::<serde_json::Value>())
}
