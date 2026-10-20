//! Compiles finite observation geometry from the original admitted plan.
//!
//! These values are allocation and refusal DATA. The enclosing protected
//! compiler must join this quote to the actual same-F debit and native profile
//! before constructing the originals; this module creates no permission.

use super::source::{ClockError, ReadFrontierOriginalV2, ReadHelperOriginalV2};
use super::*;
use crate::kernel_mutator::NetworkStatusHelperOriginalV4;
use crate::kernel_observation::*;
use crate::observation_worker_runtime::read_admission_v2::{
    NetworkObserverReadCurrentOriginalV2, NetworkObserverReadOriginalV2,
};
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::receiving::NetworkChildSourceProbeOriginalV2;
use aos_sandbox_core::{BrokerVerb, ResourceDimension as D, ResourceVector};
use std::mem::{MaybeUninit, size_of};

/// Bounds the same strict JSON seed before any container allocation.
#[derive(Clone, Copy)]
pub(crate) struct ObservationJsonLayoutDataV2 {
    pub(crate) nodes: usize,
    pub(crate) maps: usize,
    pub(crate) arrays: usize,
}

/// Carries a compiled finite roster and its passive receiving obligations.
pub(crate) struct ObservationProgrammeDataV2 {
    pub(super) helpers: usize,
    pub(super) boundaries: usize,
    pub(super) maximum_table: usize,
    pub(super) native_limits: [u64; 3],
    pub(super) plan_digest: ObjectDigest,
    pub(super) verb: BrokerVerb,
    pub(super) nft_layout: ObservationJsonLayoutDataV2,
    source_queries: u64,
    obligations: ResourceVector,
}

impl ObservationProgrammeDataV2 {
    /// Reports the complete reader dependency, excluding the enclosing child
    /// bootstrap/840, O6 transport, signed-crypto verification, namespace2
    /// transport and result/ACK actor. These remain mandatory enclosing terms.
    pub(crate) fn receiving_obligations_data_v2(&self) -> ResourceVector {
        self.obligations
    }

    /// Reports exactly the queries issued by opening, admission and this port.
    /// The common initial bootstrap query is separately priced by its owner.
    pub(crate) fn source_queries_data_v2(&self) -> u64 {
        self.source_queries
    }
}

/// Computes the actual two-snapshot recipe without creating authority or IO.
///
/// The native limits and table frontier must come from the genuine selected
/// worker profile. The native census independently checks them at every clone.
/// Overflow, unsupported verbs and a table outside the selected NOFILE refuse.
pub(crate) fn observation_programme_data_v2(
    plan: &crate::NetworkKernelPlanV1,
    verb: BrokerVerb,
    signed_request_body_bytes: usize,
    native_limits: [u64; 3],
    maximum_table: usize,
) -> Option<ObservationProgrammeDataV2> {
    use NetworkStatusHelperRoleV4 as Role;
    let absent = match verb {
        BrokerVerb::NetworkPrepare => false,
        BrokerVerb::NetworkDestroy => true,
        _ => return None,
    };
    if native_limits.into_iter().any(|limit| limit == 0) {
        return None;
    }
    let expected = plan.observation_expectation();
    let managed = expected.kind() != aos_sandbox_core::model::NetworkKind::Isolated;
    let per_snapshot: usize = if managed {
        if absent { 10 } else { 12 }
    } else {
        8
    };
    let helpers = per_snapshot * 2;
    // Entry/final plus two actual namespace transitions in each snapshot.
    let boundaries = 6usize;
    let frontiers = helpers.checked_mul(2)?.checked_add(boundaries)?;
    let source_queries = u64::try_from(frontiers.checked_add(4)?).ok()?;
    let nft_layout = nft_layout(expected, absent)?;
    let mut demand =
        NetworkObserverReadOriginalV2::receiving_obligations_data_v2(signed_request_body_bytes)?;
    demand = demand
        .checked_add(
            NetworkChildSourceProbeOriginalV2::programme_obligations_data_v2(source_queries)?,
        )
        .ok()?;

    let mut bytes = size_of::<NetworkObservationReadProgrammeOriginalV2>()
        .checked_mul(2)?
        .checked_add(size_of::<ObservationProgrammeDataV2>().checked_mul(2)?)?
        .checked_add(
            size_of::<ReadHelperOriginalV2>()
                .checked_mul(2)?
                .checked_mul(helpers)?,
        )?
        .checked_add(
            size_of::<ReadFrontierOriginalV2>()
                .checked_mul(2)?
                .checked_mul(boundaries)?,
        )?
        .checked_add(size_of::<NetworkObservationReadersOriginalV2>().checked_mul(2)?)?;
    let mut files = 0usize;
    let mut metadata = 0usize;
    let mut largest_current_files = 0usize;
    for role in super::opening::ROLES {
        let term = NetworkArtifactOpeningOriginalV4::receiving_obligations_v4(role)?;
        bytes = bytes.checked_add(term.0)?;
        files = files.checked_add(term.1)?;
        metadata = metadata.checked_add(term.2)?;
    }
    // The two actual snapshots have one nft command each. Host inventory adds
    // three ip commands for Prepare, or just the absent-link command for
    // Destroy, and one BPF command in either managed mode.
    let roles = [
        (Role::IpLinks, if managed { 2usize } else { 1 }),
        (Role::IpAddresses, if managed && !absent { 2 } else { 1 }),
        (Role::IpNeighbors, if managed && !absent { 2 } else { 1 }),
        (Role::IpRoutes, 2),
        (Role::IpRules, 2),
        (Role::NftPolicy, 1),
        (Role::BpfGraph, usize::from(managed)),
    ];
    let helper_bytes = roles.into_iter().try_fold(0usize, |sum, (role, count)| {
        sum.checked_add(
            NetworkStatusHelperOriginalV4::receiving_programme_bytes_data_v2(
                role,
                native_limits[1],
                maximum_table,
            )?
            .checked_mul(count)?
            .checked_mul(2)?,
        )
    })?;
    let directory = aos_sandbox_linux::process::FixedProcessRunOriginalV3::task_directory_transient_bytes_data_v3()?;
    let helper_bytes = helper_bytes.checked_sub(directory.checked_mul(helpers.checked_sub(1)?)?)?;
    // Every original/error reservoir stays priced. Successful native helper
    // temporaries can retire after the real semantic Result, with no refund.
    bytes = bytes.checked_add(helper_bytes.checked_add(
        ObservationRecipeV2::argument_storage_bytes_data_v2()?.checked_mul(helpers)?,
    )?)?;
    for role in [
        NetworkArtifactRoleV4::Enforcement,
        NetworkArtifactRoleV4::LeaseObject,
    ] {
        let term = NetworkArtifactCurrentOriginalV4::receiving_obligations_v4(role, false)?;
        bytes = bytes.checked_add(term.0.checked_mul(2)?.checked_mul(helpers)?)?;
        largest_current_files = largest_current_files.max(term.1);
        metadata = metadata.checked_add(term.2.checked_mul(2)?.checked_mul(helpers)?)?;
    }
    let current = NetworkObserverReadCurrentOriginalV2::receiving_obligations_data_v2()?;
    for _ in 0..frontiers.checked_mul(2)? {
        // All observation bytes/results stay resident. Only a failed read's
        // one duplicate can survive; the first failed recipe prevents another
        // helper, with the independently owed after frontier still reached.
        demand = demand.checked_add(current.with(D::OpenFiles, 0)).ok()?;
    }
    let clock_bytes =
        RetainedKernelPairedClockAttemptV1::<ClockError>::dominant_requested_bytes_v1()?;
    let clock_names =
        RetainedKernelPairedClockAttemptV1::<ClockError>::receiving_metadata_cells_v1()?;
    bytes = bytes.checked_add(clock_bytes.checked_mul(2)?.checked_mul(frontiers)?)?;
    files = files.checked_add(
        RetainedKernelPairedClockAttemptV1::<ClockError>::MAXIMUM_RETAINED_FILES_V1
            .checked_mul(8)?,
    )?;
    // Internal helper and outer attestation before/after each own at most
    // the largest fixed role walk. Charging all four remains conservative
    // even though a failed before prevents the actual later fork. A failed
    // helper's before/after plus owed snapshot-restore and stable-final
    // frontiers can each retain two public duplicates; Source replies share their
    // one permanently fenced failure endpoint already priced in demand.
    files = files.checked_add(largest_current_files.checked_mul(4)?)?
        .checked_add(8)?;
    metadata = metadata.checked_add(clock_names.checked_mul(2)?.checked_mul(frontiers)?)?;
    metadata = metadata.checked_add(
        aos_sandbox_linux::process::NetworkWorkerForkObservationV4::programme_metadata_entries_data_v2(
            native_limits[1], maximum_table,
        )?.checked_mul(helpers)?,
    )?;
    // Keep the conservative full additional fork/table envelope. No caller may
    // mistake a positive helper disposal for a new financial FD allowance.
    files = files.checked_add(
        aos_sandbox_linux::process::NetworkWorkerForkObservationV4::programme_fork_files_data_v2(
            native_limits[1],
            maximum_table,
        )?,
    )?;
    bytes = bytes.checked_add(
        usize::try_from(
            aos_sandbox_linux::kernel_clone::dominant_birth_bytes_data_v1(
                native_limits[1].checked_sub(1)?,
                NetworkStatusHelperOriginalV4::maximum_clone_arguments_data_v2()?,
            )?,
        )
        .ok()?,
    )?;
    let notes =
        aos_sandbox_linux::kernel_clone::ConfiguredKernelCloneOriginalV1::receiving_obligations_v1(
        )?;
    bytes = bytes.checked_add(notes.0)?;
    files = files.checked_add(notes.1)?;
    metadata = metadata.checked_add(notes.2)?;
    bytes = bytes
        .checked_add(model_and_json_bytes(nft_layout, absent)?)?
        .checked_add(crate::rtnetlink_reader::deferred_command_result_headers_data_v2()?)?;
    demand = demand
        .checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, u64::try_from(files).ok()?)
                .with(D::MetadataEntries, u64::try_from(metadata).ok()?)
                .with(D::Pids, 1),
        )
        .ok()?;
    Some(ObservationProgrammeDataV2 {
        helpers,
        boundaries,
        maximum_table,
        native_limits,
        plan_digest: plan.digest(),
        verb,
        nft_layout,
        source_queries,
        obligations: demand,
    })
}

fn nft_layout(
    expected: &NetworkKernelExpectationV1,
    absent: bool,
) -> Option<ObservationJsonLayoutDataV2> {
    if absent {
        // nft 1.1.7 table_print_json emits family/name/handle, optional comment
        // and at most 32 flag strings. One of the existing 16,899 objects is
        // metainfo. This includes ignored metadata of every foreign table.
        let tables = 16_899usize.checked_sub(1)?;
        return Some(ObservationJsonLayoutDataV2 {
            nodes: 7usize.checked_add(39usize.checked_mul(tables)?)?,
            maps: 3usize.checked_add(2usize.checked_mul(tables)?)?,
            arrays: 1usize.checked_add(tables)?,
        });
    }
    let flows = expected
        .policy()
        .endpoints()
        .iter()
        .try_fold(0usize, |count, endpoint| {
            count.checked_add(endpoint.flows().len())
        })?;
    let mut families = [0usize; 2];
    for pair in expected.address_pairs() {
        let index = match pair.sandbox {
            ObservedIpAddressV1::Ipv4(_) => 0,
            ObservedIpAddressV1::Ipv6(_) => 1,
        };
        families[index] = families[index].checked_add(1)?;
    }
    let guards = families
        .iter()
        .filter(|count| **count != 0)
        .count()
        .checked_mul(2)?;
    let addresses = families.into_iter().max().unwrap_or(0);
    // Root/metainfo/table/two chains; each flow includes a remote prefix and
    // transport range, and each guard includes its complete address set.
    Some(ObservationJsonLayoutDataV2 {
        nodes: 33usize
            .checked_add(32usize.checked_mul(flows)?)?
            .checked_add(26usize.checked_add(addresses)?.checked_mul(guards)?)?,
        maps: 9usize
            .checked_add(14usize.checked_mul(flows)?)?
            .checked_add(12usize.checked_mul(guards)?)?,
        arrays: 1usize.checked_add(2usize.checked_mul(flows.checked_add(guards)?)?)?,
    })
}

// This layout bounds an internal std BTree node, including its leaf prefix.
// alloc's selected B=6 leaves have 11 slots and at least 5 per nonroot node.
// Charging roots + entries/5 covers aggregate maps without a node per Value.
#[repr(C)]
struct TreeNodeUpper<K, V> {
    parent: usize,
    parent_index: u16,
    length: u16,
    keys: [MaybeUninit<K>; 11],
    values: [MaybeUninit<V>; 11],
    edges: [usize; 12],
}

/// Quotes the existing strict JSON aggregate container and wire geometry.
pub(crate) fn json_receiving_bytes_data_v2(layout: ObservationJsonLayoutDataV2, wire: usize) -> Option<usize> {
    let entries = layout.nodes.checked_add(1)?;
    let trees = layout.maps.checked_add(entries / 5)?.checked_add(1)?;
    let tree_bytes = size_of::<TreeNodeUpper<String, serde_json::Value>>()
        .checked_add(size_of::<TreeNodeUpper<String, ()>>())?
        .checked_mul(trees)?;
    let vectors = layout
        .nodes
        .checked_mul(2)?
        .checked_add(layout.arrays.checked_mul(8)?)?
        .checked_mul(size_of::<serde_json::Value>())?;
    // Total decoded keys/strings, duplicate-key copies and parser growth use
    // the aggregate wire extent, rather than a full wire extent per node.
    tree_bytes
        .checked_add(vectors)?
        .checked_add(wire.checked_mul(6)?)
}

fn model_and_json_bytes(nft: ObservationJsonLayoutDataV2, absent: bool) -> Option<usize> {
    use crate::rtnetlink_reader::*;
    let ip_wire = MAXIMUM_LINK_BYTES
        .checked_add(MAXIMUM_ADDRESS_BYTES)?
        .checked_add(MAXIMUM_NEIGHBOR_BYTES)?
        .checked_add(MAXIMUM_ROUTE_BYTES.checked_mul(2)?)?
        .checked_add(MAXIMUM_RULE_BYTES.checked_mul(2)?)?;
    let ip_max = MAXIMUM_ROUTE_BYTES;
    // Every JSON value except the first needs at least two wire bytes. An
    // allocated (nonempty) map needs braces, a key's quotes and a colon, even
    // if its value is another map. Empty maps allocate no BTree root.
    let ip_json = json_receiving_bytes_data_v2(
        ObservationJsonLayoutDataV2 {
            nodes: ip_max.checked_div(2)?.checked_add(1)?,
            maps: ip_max.checked_div(5)?.checked_add(1)?,
            arrays: ip_max.checked_div(2)?.checked_add(1)?,
        },
        ip_max,
    )?
    .checked_mul(2)?;
    let nft_wire = crate::nftables_reader::MAXIMUM_NFTABLES_OBSERVATION_BYTES;
    let json = ip_json.max(json_receiving_bytes_data_v2(nft, nft_wire)?);

    // Every successfully constructed IP model requires more wire than this
    // address fragment: links require ifindex/name/link fields; addresses
    // require family/local/prefixlen; neighbors require dst/state/lladdr;
    // routes require dst/dev/protocol/flags; rules require priority/src/table.
    // The same lower bound covers the valid prefix before a later rejection.
    let ip_records = ip_wire
        .checked_div(b"{\"local\":\"\",\"prefixlen\":0}".len())?
        .checked_add(1)?;
    let ip_models = size_of::<ObservedLinkV1>()
        .checked_add(size_of::<ObservedAddressV1>())?
        .checked_add(size_of::<ObservedIpv6NeighborV1>())?
        .checked_add(size_of::<ObservedRouteV1>())?
        .checked_add(size_of::<ObservedPolicyRuleV1>())?
        .checked_mul(ip_records)?;
    let link_tree = size_of::<TreeNodeUpper<&'static str, u32>>()
        .max(size_of::<TreeNodeUpper<u32, &'static str>>());
    let link_indices = ip_records
        .checked_div(5)?
        .checked_add(1)?
        .checked_mul(6)?
        .checked_mul(link_tree)?;
    let nft_models = if absent {
        // Destroy parses the whole foreign-table JSON, but constructs no
        // Flow/AntiSpoof/Policy model or interface resolver from that listing.
        0
    } else {
        // A completed fixed rule contains two match statements plus a verdict,
        // hence at least16 JSON values. One additional partial handle insertion
        // can precede a later rule rejection. All guard address values still
        // count against the actual strict seed's total node extent.
        let rules = nft.nodes.checked_div(16)?.checked_add(1)?;
        let models = size_of::<ObservedFlowV1>()
            .checked_add(size_of::<ObservedNftAntiSpoofRuleV1>())?
            .checked_mul(rules)?
            .checked_add(size_of::<ObservedIpAddressV1>().checked_mul(nft.nodes)?)?;
        let handles = rules
            .checked_div(5)?
            .checked_add(8)?
            .checked_mul(size_of::<TreeNodeUpper<u64, ()>>())?;
        let fixed = size_of::<TreeNodeUpper<String, ObservedNftBaseChainV1>>()
            .checked_mul(2)?
            .checked_add(size_of::<TreeNodeUpper<String, serde_json::Value>>().checked_mul(8)?)?;
        models.checked_add(handles)?.checked_add(fixed)?
    };
    // Two snapshots, normalization/Vec growth and expected comparator models.
    let models = ip_models
        .checked_add(link_indices)?
        .checked_add(nft_models)?
        .checked_mul(4)?;
    let headers = size_of::<NetworkKernelObservationV1>()
        .checked_add(size_of::<RtnetlinkNamespaceInventoryV1>())?
        .checked_add(size_of::<RtnetlinkLinkInventoryV1>())?
        .checked_add(size_of::<ObservedNftablesPolicyV1>())?
        .checked_mul(4)?;
    models
        .checked_add(headers)?
        .checked_add(json)?
        .checked_add(ip_wire.checked_mul(4)?)?
        .checked_add(nft_wire.checked_mul(2)?)?
        .checked_add(MAXIMUM_BPF_OBSERVATION_BYTES.checked_mul(8)?)?
        .checked_add(size_of::<RawObservation>().checked_mul(4)?)?
        .checked_add(size_of::<ObservedLeaseGateV1>().checked_mul(4)?)
}
