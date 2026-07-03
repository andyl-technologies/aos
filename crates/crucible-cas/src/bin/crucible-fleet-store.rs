//! Probes the fleet-visible Crucible content-addressed store.
//!
//! This small binary is packaged as the AOS `crucible-fleet-store` component.
//! It intentionally exposes only a deterministic local probe surface for the
//! packaging and fleet-check harnesses; the public store interface remains the
//! `crucible-cas` [`crucible_cas::DagStore`] trait.

use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use crucible_cas::{
    ContentHash, DagStore, ExpansionDedupDecision, FrontierClaimRequest, SharedDagStore,
    SharedDedupIndex, SharedFrontier, SoftHashAffinity,
};

const PROBE_PAYLOAD: &[u8] = b"crucible-fleet-store-probe-v1";
const CONCURRENT_WRITERS: usize = 16;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os();
    let program = match args.next() {
        Some(program) => program,
        None => OsString::from("crucible-fleet-store"),
    };
    let Some(command) = args.next() else {
        print_usage(&program);
        return Err(input_error("missing command"));
    };
    match command.to_string_lossy().as_ref() {
        "probe" => {
            let Some(root) = args.next() else {
                print_usage(&program);
                return Err(input_error("missing probe root"));
            };
            if args.next().is_some() {
                print_usage(&program);
                return Err(input_error("unexpected extra argument"));
            }
            run_probe(PathBuf::from(root))
        }
        _ => {
            print_usage(&program);
            Err(input_error(format!(
                "unknown command `{}`",
                command.to_string_lossy()
            )))
        }
    }
}

fn print_usage(program: &OsString) {
    eprintln!("usage: {} probe <store-root>", program.to_string_lossy());
}

fn input_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn run_probe(root: PathBuf) -> Result<(), Box<dyn Error>> {
    let location_key =
        prove_location_independent_identity(&root.join("host-a"), &root.join("host-b"))?;
    let concurrent_key = prove_concurrent_put_idempotent(&root.join("shared"))?;
    let object_file_count =
        count_regular_files_named(&root.join("shared"), &concurrent_key.to_hex())?;
    if object_file_count != 1 {
        return Err(input_error(
            "shared store probe created duplicate concurrent objects",
        ));
    }
    prove_frontier_claim_leases(&root.join("leases"))?;
    prove_four_layer_dedup(&root.join("dedup"))?;

    println!("crucible-fleet-store probe");
    println!("root={}", root.display());
    println!("object={}", concurrent_key.to_hex());
    println!("interface=DagStore::put,DagStore::get,DagStore::has");
    println!("backend=SharedDagStore");
    println!("location_independent_identity=true");
    println!("location_independent_roots=2");
    println!("location_independent_object={}", location_key.to_hex());
    println!("concurrent_put=idempotent");
    println!("concurrent_writers={CONCURRENT_WRITERS}");
    println!("object_file_count={object_file_count}");
    println!("claim_lease=ttl-hint");
    println!("claim_key=content-addressed");
    println!("claim_path_excludes_host=true");
    println!("expired_lease=reclaimable");
    println!("stale_claim_lock=reclaimable");
    println!("reclaimed_node_byte_identical=true");
    println!("hash_affinity=priority-only");
    println!("affinity_filters_frontier=false");
    println!("static_partitioning=false");
    println!("lease_ttl_ticks=5");
    println!("dedup_layers=exists,coverage-map,reduction-fingerprint,claim-set");
    println!("exists_gated_expansion=skip-existing");
    println!("coverage_map_admission=compare-and-merge");
    println!("coverage_map_repair=entry-markers-before-fingerprint");
    println!("coverage_map_duplicate=skipped");
    println!("reduction_fingerprint=shared-prune");
    println!("claim_set_anti_redundancy=unclaimed-first");
    Ok(())
}

fn prove_location_independent_identity(
    left_root: &Path,
    right_root: &Path,
) -> Result<crucible_cas::ContentHash, Box<dyn Error>> {
    let left = SharedDagStore::new(left_root);
    let right = SharedDagStore::new(right_root);
    let left_key = left.put(PROBE_PAYLOAD)?;
    let right_key = right.put(PROBE_PAYLOAD)?;
    if left_key != right_key {
        return Err(input_error(
            "shared store probe produced root-dependent keys",
        ));
    }
    if left.object_path(&left_key) == right.object_path(&right_key) {
        return Err(input_error(
            "shared store probe used the same path for distinct roots",
        ));
    }
    if left.get(&left_key)? != right.get(&right_key)? {
        return Err(input_error(
            "shared store probe read root-dependent object bytes",
        ));
    }
    Ok(left_key)
}

fn prove_concurrent_put_idempotent(
    root: &Path,
) -> Result<crucible_cas::ContentHash, Box<dyn Error>> {
    let store = Arc::new(SharedDagStore::new(root));
    let start = Arc::new(Barrier::new(CONCURRENT_WRITERS));
    let mut handles = Vec::with_capacity(CONCURRENT_WRITERS);
    for _ in 0..CONCURRENT_WRITERS {
        let store = Arc::clone(&store);
        let start = Arc::clone(&start);
        handles.push(thread::spawn(move || {
            start.wait();
            store.put(PROBE_PAYLOAD)
        }));
    }

    let mut key = None;
    for handle in handles {
        let writer_key = handle
            .join()
            .map_err(|_| input_error("shared store writer panicked"))??;
        match key {
            Some(existing) if existing != writer_key => {
                return Err(input_error(
                    "shared store probe produced non-idempotent concurrent keys",
                ));
            }
            Some(_) => {}
            None => key = Some(writer_key),
        }
    }

    let key =
        key.ok_or_else(|| input_error("shared store probe did not publish a concurrent key"))?;
    if !store.has(&key)? {
        return Err(input_error(
            "shared store probe lost the concurrently published object",
        ));
    }
    if store.get(&key)? != PROBE_PAYLOAD {
        return Err(input_error(
            "shared store probe read back different concurrent bytes",
        ));
    }
    Ok(key)
}

fn prove_frontier_claim_leases(root: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Box::new(source)),
    }
    let store = SharedDagStore::new(root.join("objects"));
    let frontier = SharedFrontier::new(root.join("frontier"));
    let node_a = store.put(b"frontier-lease-a")?;
    let node_b = store.put(b"frontier-lease-b")?;
    frontier.admit(&node_a)?;
    frontier.admit(&node_b)?;

    let without_affinity = frontier.ordered_claimable_nodes(100, &SoftHashAffinity::off())?;
    let with_affinity =
        frontier.ordered_claimable_nodes(100, &SoftHashAffinity::prefer([node_b]))?;
    let mut without_set = without_affinity.clone();
    without_set.sort();
    let mut with_set = with_affinity.clone();
    with_set.sort();
    if with_set != without_set {
        return Err(input_error("soft hash affinity filtered the frontier"));
    }
    if with_affinity.first().copied() != Some(node_b) {
        return Err(input_error(
            "soft hash affinity did not prioritize the preferred node",
        ));
    }

    let preferred_lease = frontier
        .claim_next(
            &FrontierClaimRequest::new("host-a", 100, 5)
                .with_affinity(SoftHashAffinity::prefer([node_b])),
        )?
        .ok_or_else(|| input_error("frontier lease probe did not claim preferred node"))?;
    if preferred_lease.node != node_b {
        return Err(input_error("frontier lease probe claimed the wrong node"));
    }
    let claim_path = frontier.claim_path(&node_b);
    let claim_path_text = claim_path.to_string_lossy();
    if claim_path_text.contains("host-a") || claim_path_text.contains("host-b") {
        return Err(input_error("frontier claim path contains host metadata"));
    }

    let fallback_lease = frontier
        .claim_next(
            &FrontierClaimRequest::new("host-b", 101, 5)
                .with_affinity(SoftHashAffinity::prefer([node_b])),
        )?
        .ok_or_else(|| input_error("affinity filtered non-preferred claimable node"))?;
    if fallback_lease.node == node_b {
        return Err(input_error("unexpired lease was treated as claimable"));
    }

    let reclaimed = frontier
        .claim_next(
            &FrontierClaimRequest::new("host-b", 105, 5)
                .with_affinity(SoftHashAffinity::prefer([node_b])),
        )?
        .ok_or_else(|| input_error("expired frontier lease did not become claimable"))?;
    if reclaimed.node != node_b {
        return Err(input_error("expired lease did not reclaim the same node"));
    }
    if store.put(b"frontier-lease-b")? != node_b {
        return Err(input_error(
            "re-expanded frontier node did not dedup to the same content address",
        ));
    }

    let node_c = store.put(b"frontier-lease-stale-lock")?;
    let stale_frontier = SharedFrontier::new(root.join("stale-lock-frontier"));
    stale_frontier.admit(&node_c)?;
    let stale_lock_path = probe_content_path(&stale_frontier.root().join("claim-locks"), &node_c);
    if let Some(parent) = stale_lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &stale_lock_path,
        probe_claim_lock_record_material(&node_c, 200, 205),
    )?;
    if stale_frontier
        .claim_next(&FrontierClaimRequest::new("host-c", 204, 5))?
        .is_some()
    {
        return Err(input_error("unexpired claim lock was treated as stale"));
    }
    let stale_lock_reclaimed = stale_frontier
        .claim_next(&FrontierClaimRequest::new("host-c", 205, 5))?
        .ok_or_else(|| input_error("expired claim lock did not become reclaimable"))?;
    if stale_lock_reclaimed.node != node_c {
        return Err(input_error(
            "expired claim lock reclaimed a different frontier node",
        ));
    }

    Ok(())
}

fn prove_four_layer_dedup(root: &Path) -> Result<(), Box<dyn Error>> {
    match fs::remove_dir_all(root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(Box::new(source)),
    }
    let store = SharedDagStore::new(root.join("objects"));
    let index = SharedDedupIndex::new(root.join("index"));

    let child = ContentHash::from_bytes(b"four-layer-child");
    if index.exists_gated_expansion(&store, &child)? != ExpansionDedupDecision::Expand {
        return Err(input_error("absent child was not expandable"));
    }
    if store.put(b"four-layer-child")? != child {
        return Err(input_error("four-layer child did not use its content key"));
    }
    if index.exists_gated_expansion(&store, &child)? != ExpansionDedupDecision::SkipExisting {
        return Err(input_error("existing child was not skipped"));
    }

    let edge_a = ContentHash::from_bytes(b"coverage-edge-a");
    let edge_b = ContentHash::from_bytes(b"coverage-edge-b");
    let edge_c = ContentHash::from_bytes(b"coverage-edge-c");
    let coverage_ab = ContentHash::from_bytes(b"coverage-a-b");
    let first_coverage = index.admit_coverage_map(coverage_ab, [edge_a, edge_b])?;
    if !first_coverage.admitted() || first_coverage.new_entries.len() != 2 {
        return Err(input_error("new shared coverage was not admitted"));
    }
    let same_fingerprint = index.admit_coverage_map(coverage_ab, [edge_a, edge_b])?;
    if !same_fingerprint.redundant() || same_fingerprint.duplicate_entries.len() != 2 {
        return Err(input_error(
            "duplicate coverage fingerprint was not skipped",
        ));
    }
    let interrupted_fingerprint = ContentHash::from_bytes(b"coverage-interrupted");
    let interrupted_a = ContentHash::from_bytes(b"coverage-interrupted-a");
    let interrupted_b = ContentHash::from_bytes(b"coverage-interrupted-b");
    let interrupted_path = probe_content_path(
        &index.root().join("coverage-fingerprints"),
        &interrupted_fingerprint,
    );
    if let Some(parent) = interrupted_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &interrupted_path,
        probe_coverage_fingerprint_record_material(
            &interrupted_fingerprint,
            &[interrupted_a, interrupted_b],
        ),
    )?;
    if probe_content_path(&index.root().join("coverage-map"), &interrupted_a).exists() {
        return Err(input_error(
            "interrupted coverage admission already had entry markers",
        ));
    }
    let repaired =
        index.admit_coverage_map(interrupted_fingerprint, [interrupted_a, interrupted_b])?;
    if !repaired.redundant()
        || repaired.duplicate_entries.len() != 2
        || !probe_content_path(&index.root().join("coverage-map"), &interrupted_a).exists()
        || !probe_content_path(&index.root().join("coverage-map"), &interrupted_b).exists()
    {
        return Err(input_error(
            "interrupted coverage admission was not repaired",
        ));
    }
    let duplicate_coverage = index.admit_coverage_map(
        ContentHash::from_bytes(b"coverage-a-b-duplicate"),
        [edge_a, edge_b],
    )?;
    if !duplicate_coverage.redundant() || duplicate_coverage.duplicate_entries.len() != 2 {
        return Err(input_error("duplicate shared coverage was not skipped"));
    }
    let merged_coverage =
        index.admit_coverage_map(ContentHash::from_bytes(b"coverage-b-c"), [edge_b, edge_c])?;
    if merged_coverage.new_entries != vec![edge_c]
        || merged_coverage.duplicate_entries != vec![edge_b]
    {
        return Err(input_error(
            "shared coverage compare-and-merge did not isolate novelty",
        ));
    }

    let reduction_fingerprint = ContentHash::from_bytes(b"symmetry-por-fingerprint");
    let representative = ContentHash::from_bytes(b"canonical-representative");
    let covered = ContentHash::from_bytes(b"covered-equivalent");
    let first_reduction =
        index.admit_reduction_fingerprint(reduction_fingerprint, representative)?;
    if !first_reduction.admitted() || first_reduction.representative != representative {
        return Err(input_error(
            "first shared reduction fingerprint was not retained",
        ));
    }
    let covered_reduction = index.admit_reduction_fingerprint(reduction_fingerprint, covered)?;
    if !covered_reduction.covered()
        || covered_reduction.representative != representative
        || covered_reduction.covered != Some(covered)
    {
        return Err(input_error(
            "shared reduction fingerprint did not prune covered candidate",
        ));
    }

    let frontier = SharedFrontier::new(root.join("frontier"));
    let node_a = store.put(b"claim-anti-redundancy-a")?;
    let node_b = store.put(b"claim-anti-redundancy-b")?;
    frontier.admit(&node_a)?;
    frontier.admit(&node_b)?;
    let first_claim = frontier
        .claim_next(&FrontierClaimRequest::new("host-a", 1, 5))?
        .ok_or_else(|| input_error("first host did not claim a frontier node"))?;
    let second_claim = frontier
        .claim_next(&FrontierClaimRequest::new("host-b", 2, 5))?
        .ok_or_else(|| input_error("second host did not claim fallback frontier node"))?;
    if first_claim.node == second_claim.node {
        return Err(input_error(
            "claim-set anti-redundancy reused a leased node",
        ));
    }
    if frontier.claimable_nodes(3)?.contains(&first_claim.node) {
        return Err(input_error("leased node remained in the claimable set"));
    }

    Ok(())
}

fn probe_content_path(root: &Path, node: &ContentHash) -> PathBuf {
    let hex = node.to_hex();
    root.join(&hex[0..2]).join(hex)
}

fn probe_claim_lock_record_material(
    node: &ContentHash,
    acquired_at_tick: u64,
    expires_at_tick: u64,
) -> String {
    format!(
        "format=crucible.frontier-claim-lock.v1\nnode={}\nacquired_at_tick={acquired_at_tick}\nexpires_at_tick={expires_at_tick}\n",
        node.to_hex()
    )
}

fn probe_coverage_fingerprint_record_material(
    coverage_fingerprint: &ContentHash,
    entries: &[ContentHash],
) -> String {
    let entries = entries
        .iter()
        .map(|entry| entry.to_hex())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "format=crucible.coverage-fingerprint.v1\ncoverage_fingerprint={}\nentries={entries}\n",
        coverage_fingerprint.to_hex()
    )
}

fn count_regular_files_named(root: &Path, file_name: &str) -> Result<usize, io::Error> {
    if !root.exists() {
        return Ok(0);
    }
    let mut count = 0;
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() && entry.file_name() == OsStr::new(file_name) {
                count += 1;
            }
        }
    }
    Ok(count)
}
