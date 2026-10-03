//! Fresh-process mapped-index measurements and failure-atomic logical ceilings.
//!
//! No OS file is opened through InodeTable: its handles are logical pins only.
//! The mapping owns a sealed shmem inode. Resource snapshots are observations,
//! not page-cache attribution, isolation, OOM, or production-FUSE evidence.

use std::fs::File;
use std::hint::black_box;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Instant;

use aos_filesystem_view::{
    ForgetRequest, INDEX_MEDIA_TYPE, IndexError, IndexExpectation, InodeError, InodeLookup,
    InodeTable, InodeTableLimits, ROOT_NODE_ID, TreeCompileLimits, ValidatedIndex,
    index_validation_working_bytes, validate_index,
};
use aos_sandbox_core::{MediaType, descriptor_for_bytes};
use aos_sandbox_linux::immutable_file::SealedMemfdMapping;
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

use super::fixture::{self, elapsed_ns, name};
use super::report::{
    BATCHES, Config, Latency, MeasurementReport, OPENS, ResourceSnapshot, TOUCHED, WorkingSet,
    WorkloadReport,
};
use crate::{Result, allocation};

fn sealed_index(path: &Path) -> Result<(OwnedFd, u64)> {
    let mut source = File::open(path)?;
    let bytes = source.metadata()?.len();
    if bytes == 0 || bytes > TreeCompileLimits::default().index_bytes {
        return Err("fixture index exceeds normal index-byte ceiling".into());
    }
    let mut destination = File::from(memfd_create(
        c"aos-metadata-scale",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    let mut scratch = [0; 8192];
    let mut copied = 0_u64;
    loop {
        let read = source.read(&mut scratch)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or("stream length overflow")?;
        if copied > bytes {
            return Err("fixture index changed length".into());
        }
        destination.write_all(&scratch[..read])?;
    }
    if copied != bytes {
        return Err("fixture index truncated".into());
    }
    fcntl_add_seals(
        &destination,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    Ok((destination.into(), bytes))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct State {
    heap: u64,
    nodes: u64,
    references: u64,
    opens: u64,
    pending: u64,
}

fn state(table: &InodeTable<'_, '_>) -> State {
    State {
        heap: table.heap_bytes(),
        nodes: table.live_nodes(),
        references: table.total_lookup_references(),
        opens: table.live_open_handles(),
        pending: table.pending_open_handles(),
    }
}

fn lookup(table: &mut InodeTable<'_, '_>, ordinal: u64) -> Result<u64> {
    match table.lookup_bytes(ROOT_NODE_ID, &name(ordinal, false))? {
        InodeLookup::Positive { attributes, .. } => Ok(attributes.node_id),
        InodeLookup::Negative => Err("fixture positive child missing".into()),
    }
}

fn forget(table: &mut InodeTable<'_, '_>, node: u64, references: u64) -> Result<()> {
    let result = table.forget(&mut [ForgetRequest::new(node, references)])?;
    assert_eq!(result.references_released, references);
    Ok(())
}

fn assert_refused<T>(result: std::result::Result<T, InodeError>) {
    assert!(
        matches!(result, Err(InodeError::LimitExceeded(_))),
        "expected hard-ceiling refusal"
    );
}

fn check_ceilings(index: &ValidatedIndex<'_>) -> Result<(u64, u64, allocation::AllocationPhase)> {
    // Each independent table isolates its ceiling; root has one lookup reference.
    let make = |nodes, references, opens| {
        InodeTable::new(
            index,
            [33; 32],
            InodeTableLimits::new(nodes, 1_048_576, references, TOUCHED, opens),
        )
    };
    let mut table = make(TOUCHED as u64 + 1, TOUCHED as u64 + 2, OPENS as u64)?;
    let mut nodes = [0_u64; TOUCHED];
    for (ordinal, node) in nodes.iter_mut().enumerate() {
        *node = lookup(&mut table, ordinal as u64)?;
    }
    let at_limit = state(&table);
    let touched_heap = at_limit.heap;
    assert_eq!(at_limit.nodes, TOUCHED as u64 + 1);
    assert_refused(table.lookup_bytes(ROOT_NODE_ID, &name(TOUCHED as u64, false)));
    assert_eq!(state(&table), at_limit);
    for node in nodes {
        forget(&mut table, node, 1)?;
    }
    assert_eq!(
        (table.live_nodes(), table.total_lookup_references()),
        (1, 1)
    );
    drop(table);

    let mut table = make(3, TOUCHED as u64 + 1, OPENS as u64)?;
    let node = lookup(&mut table, 0)?;
    for _ in 1..TOUCHED {
        assert_eq!(lookup(&mut table, 0)?, node);
    }
    let at_limit = state(&table);
    assert_refused(table.lookup_bytes(ROOT_NODE_ID, &name(0, false)));
    assert_eq!(state(&table), at_limit);
    forget(&mut table, node, TOUCHED as u64)?;
    assert_eq!(
        (table.live_nodes(), table.total_lookup_references()),
        (1, 1)
    );
    drop(table);

    let mut table = make(3, 3, OPENS as u64)?;
    let node = lookup(&mut table, 0)?;
    let mut handles = [None; OPENS];
    let (result, open_allocation) = allocation::measure(|| -> Result<()> {
        for handle in &mut handles {
            let mut reservation = table.reserve_open(node)?;
            *handle = Some(table.activate_open(&mut reservation)?);
        }
        Ok(())
    });
    result?;
    let at_limit = state(&table);
    assert_refused(table.reserve_open(node));
    assert_eq!(state(&table), at_limit);
    // Forget drops lookup ownership, while every active open must keep the inode.
    forget(&mut table, node, 1)?;
    assert_eq!(table.live_nodes(), 2);
    for handle in handles {
        table.release_open(handle.ok_or("missing active handle")?)?;
    }
    assert_eq!(
        (
            table.live_nodes(),
            table.live_open_handles(),
            table.pending_open_handles()
        ),
        (1, 0, 0)
    );

    let node = lookup(&mut table, 1)?;
    let mut pending: [_; OPENS] = std::array::from_fn(|_| None);
    for slot in &mut pending {
        *slot = Some(table.reserve_open(node)?);
    }
    assert_eq!(table.pending_open_handles(), OPENS as u64);
    let pending_limit = state(&table);
    assert_refused(table.reserve_open(node));
    assert_eq!(state(&table), pending_limit);
    for reservation in &mut pending {
        table.abort_open(reservation.as_mut().ok_or("missing pending reservation")?)?;
    }
    forget(&mut table, node, 1)?;
    assert_eq!(
        (
            table.live_nodes(),
            table.total_lookup_references(),
            table.live_open_handles(),
            table.pending_open_handles()
        ),
        (1, 1, 0, 0)
    );
    drop(table);
    Ok((touched_heap, at_limit.heap, open_allocation))
}

fn working_set(index: &ValidatedIndex<'_>, children: usize) -> Result<WorkingSet> {
    assert!(children <= TOUCHED);
    let baseline = allocation::live_requested_bytes();
    let (result, phase) = allocation::measure(|| -> Result<_> {
        let mut table = InodeTable::new(
            index,
            [35; 32],
            InodeTableLimits::new(TOUCHED as u64 + 1, 1_048_576, 1024, TOUCHED, OPENS as u64),
        )?;
        let mut nodes = [0_u64; TOUCHED];
        for (ordinal, node) in nodes[..children].iter_mut().enumerate() {
            *node = lookup(&mut table, ordinal as u64)?;
        }
        Ok((table, nodes))
    });
    let (mut table, nodes) = result?;
    let modeled_table_heap_bytes = table.heap_bytes();
    let live_nodes_including_root = table.live_nodes();
    assert_eq!(live_nodes_including_root, children as u64 + 1);
    let resident_observation = ResourceSnapshot::take()?;
    for node in &nodes[..children] {
        forget(&mut table, *node, 1)?;
    }
    assert_eq!(
        (table.live_nodes(), table.total_lookup_references()),
        (1, 1)
    );
    drop(table);
    let after_table_drop_requested_bytes = allocation::live_requested_bytes();
    assert_eq!(after_table_drop_requested_bytes, baseline);
    Ok(WorkingSet {
        touched_children: children as u64,
        live_nodes_including_root,
        modeled_table_heap_bytes,
        allocation: phase,
        resident_observation,
        after_table_drop_requested_bytes,
    })
}

fn workloads(index: &ValidatedIndex<'_>, config: Config) -> Result<WorkloadReport> {
    let before = ResourceSnapshot::take()?;
    let mut table = InodeTable::new(
        index,
        [34; 32],
        InodeTableLimits::new(TOUCHED as u64 + 1, 1_048_576, 1024, TOUCHED, OPENS as u64),
    )?;
    let unchanged = state(&table);
    let operations = config.profile.batch_operations();
    let mut negative = [0_u64; BATCHES];
    let (result, negative_allocation) = allocation::measure(|| -> Result<()> {
        for (batch, latency) in negative.iter_mut().enumerate() {
            let start = Instant::now();
            for ordinal in 0..operations {
                assert_eq!(
                    table.lookup_bytes(
                        ROOT_NODE_ID,
                        &name(batch as u64 * operations + ordinal, true)
                    )?,
                    InodeLookup::Negative
                );
            }
            *latency = elapsed_ns(start)?;
            assert_eq!(state(&table), unchanged);
        }
        Ok(())
    });
    result?;
    assert_eq!(negative_allocation.allocation_calls, 0);
    assert_eq!(
        negative_allocation.live_requested_bytes,
        negative_allocation.baseline_requested_bytes
    );
    drop(table);

    let root = index.root()?;
    let mut positive = [0_u64; BATCHES];
    for (batch, latency) in positive.iter_mut().enumerate() {
        let start = Instant::now();
        for ordinal in 0..operations {
            let ordinal = (batch as u64 * operations + ordinal) % config.profile.children();
            black_box(
                index
                    .lookup_child_bytes(&root, &name(ordinal, false))?
                    .ok_or("positive index child missing")?,
            );
        }
        *latency = elapsed_ns(start)?;
    }
    let retained_working_sets = [
        working_set(index, 0)?,
        working_set(index, 16)?,
        working_set(index, TOUCHED)?,
    ];
    let (modeled_inode_heap_bytes, modeled_heap_at_open_ceiling_bytes, open_allocation) =
        check_ceilings(index)?;
    let after = ResourceSnapshot::take()?;
    Ok(WorkloadReport {
        negative: Latency::new(negative, operations),
        borrowed_positive: Latency::new(positive, operations),
        negative_allocation,
        modeled_inode_heap_bytes,
        modeled_heap_at_open_ceiling_bytes,
        open_allocation,
        touched_nodes_including_root: TOUCHED as u64 + 1,
        peak_open_handles: OPENS as u64,
        retained_working_sets,
        before,
        after,
    })
}

struct MeasuredValidation {
    reservation: u64,
    cap: u64,
    normal_refused: bool,
    refusal_phase: allocation::AllocationPhase,
    validated: bool,
    phase: allocation::AllocationPhase,
    before: ResourceSnapshot,
    after: ResourceSnapshot,
    elapsed: u64,
    workload: Option<WorkloadReport>,
}

pub(super) fn run(directory: &Path, config: Config) -> Result<MeasurementReport> {
    let (file, index_bytes) = sealed_index(&directory.join("index.bin"))?;
    let (tree, root) = fixture::descriptors()?;
    let normal = TreeCompileLimits::default().working_bytes;
    // Initialize output's persistent runtime state before the checked drop baseline.
    drop(std::io::stdout().lock());
    let baseline = allocation::live_requested_bytes();
    let mapped = SealedMemfdMapping::run(
        file,
        index_bytes,
        TreeCompileLimits::default().index_bytes,
        |bytes, _| -> Result<_> {
            let descriptor = descriptor_for_bytes(MediaType::new(INDEX_MEDIA_TYPE)?, bytes);
            let expected = IndexExpectation {
                index: &descriptor,
                compiler_abi: fixture::ABI,
                tree: &tree,
                root: &root,
                tree_features: 0,
            };
            let reservation = index_validation_working_bytes(bytes, index_bytes, &expected)?;
            let cap = reservation.min(config.validation_envelope_bytes);
            let (normal_result, normal_phase) =
                allocation::measure(|| validate_index(bytes, index_bytes, normal, &expected));
            let normal_refused = match normal_result {
                Ok(index) => {
                    drop(index);
                    false
                }
                Err(IndexError::LimitExceeded) if reservation > normal => true,
                Err(error) => return Err(error.into()),
            };
            assert_eq!(
                allocation::live_requested_bytes(),
                normal_phase.baseline_requested_bytes
            );

            // Exercise refusal through the real validator, before scalable
            // allocation. The shared estimator is diagnostic, not authority.
            let underbudget = reservation
                .checked_sub(1)
                .ok_or("zero admission estimate")?;
            let (refused, refusal_phase) =
                allocation::measure(|| validate_index(bytes, index_bytes, underbudget, &expected));
            assert!(matches!(refused, Err(IndexError::LimitExceeded)));
            assert_eq!(
                refusal_phase.live_requested_bytes,
                refusal_phase.baseline_requested_bytes
            );
            assert!(
                refusal_phase.peak_requested_bytes
                    <= refusal_phase.baseline_requested_bytes + 4_096,
                "underbudget refusal allocated more than fixed envelope scratch"
            );
            let before = ResourceSnapshot::take()?;
            let started = Instant::now();
            let (result, phase) =
                allocation::measure(|| validate_index(bytes, index_bytes, cap, &expected));
            let elapsed = elapsed_ns(started)?;
            let after = ResourceSnapshot::take()?;
            let (validated, workload) = match result {
                Ok(index) => {
                    assert_eq!(index.summary().records, config.profile.children() + 1);
                    let workload = workloads(&index, config)?;
                    drop(index);
                    (true, Some(workload))
                }
                Err(IndexError::LimitExceeded) if cap < reservation => {
                    assert_eq!(phase.live_requested_bytes, phase.baseline_requested_bytes);
                    (false, None)
                }
                Err(error) => return Err(error.into()),
            };
            Ok(MeasuredValidation {
                reservation,
                cap,
                normal_refused,
                refusal_phase,
                validated,
                phase,
                before,
                after,
                elapsed,
                workload,
            })
        },
    )??;
    let after_drop = allocation::live_requested_bytes();
    assert_eq!(
        after_drop, baseline,
        "index/table allocations survived scoped mapping"
    );
    let after_unmap = ResourceSnapshot::take()?;
    Ok(MeasurementReport {
        index_bytes,
        mapping_kind: "sealed memfd/shmem; not filesystem page-cache or ARC".to_owned(),
        mapped_bytes: index_bytes,
        normal_validation_ceiling_bytes: normal,
        normal_validation_refused: mapped.normal_refused,
        underbudget_validation_refused: true,
        underbudget_validation_allocation: mapped.refusal_phase,
        computed_validation_reservation_bytes: mapped.reservation,
        selected_validation_cap_bytes: mapped.cap,
        validated: mapped.validated,
        refusal: (!mapped.validated).then(|| "declared test-only validation envelope is below the normal validator's reservation; workload did not run".to_owned()),
        validation_elapsed_ns: mapped.elapsed,
        validation_allocation: mapped.phase,
        validation_before: mapped.before,
        validation_after: mapped.after,
        workload: mapped.workload,
        drop_baseline_requested_bytes: baseline,
        after_drop_requested_bytes: after_drop,
        after_unmap,
    })
}
