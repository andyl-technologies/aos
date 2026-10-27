//! Offline canonical RAM hashing measurements for the selected host implementation.
//!
//! Run this example in release mode with `test-support` and one output-directory
//! argument. It writes `measurements.csv` and `receipt.json`. SHA-256 exists only
//! in this feature-gated comparison; production logical RAM identity is BLAKE3.
//! The inputs match canonical page, leaf, branch, region and scoped-root domains.
//! This measures warm in-process hashing, without native C hashing, paging,
//! persistent-tree allocation, storage, metadata COW or resident-memory evidence.
//!
//! The receipt is a versioned measurement record, separate from capability proof:
//!
//! ```json
//! {"schema":"crucible.ram.offline-hash-measurements","version":1,"profile":"release"}
//! ```
//!
//! CSV rows identify the algorithm, workload, logical/changed page counts, hash
//! and preimage-byte counts, repetitions, sample number and elapsed nanoseconds.

// SPDX-License-Identifier: MIT OR Apache-2.0

// crucible-lint: allow clippy-disallowed-method -- this feature-gated offline executable measures host duration; it never participates in simulated state.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::error::Error;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crucible_ram::{
    Geometry, Limits, NodeDigest, PageDigest, RegionClass, RegionDescriptor, RootRecord, Scope,
    Topology, inner_digest, leaf_digest, region_tree_digest,
};
use sha2::{Digest, Sha256};

const PAGE_BYTES: usize = 4096;
const SAMPLES: usize = 5;
const REGION_ID: &str = "bench.ram";

type BenchmarkResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
enum Algorithm {
    Blake3,
    Sha256,
}

impl Algorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Blake3 => "blake3-host-pure",
            Self::Sha256 => "sha256-offline-comparison",
        }
    }

    // Segmented updates preserve the production domain construction and avoid
    // counting a temporary contiguous-preimage allocation for either library.
    fn hash(self, parts: &[&[u8]]) -> [u8; 32] {
        match self {
            Self::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                for part in parts {
                    hasher.update(black_box(part));
                }
                *hasher.finalize().as_bytes()
            }
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                for part in parts {
                    hasher.update(black_box(part));
                }
                hasher.finalize().into()
            }
        }
    }

    fn page(self, bytes: &[u8]) -> [u8; 32] {
        self.hash(&[
            b"crucible.ram.page.v1\0",
            &(bytes.len() as u32).to_be_bytes(),
            bytes,
        ])
    }

    fn leaf(self, page: &[u8; 32]) -> [u8; 32] {
        self.hash(&[b"crucible.ram.leaf.v1\0", page])
    }

    fn branch(self, height: u32, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        self.hash(&[
            b"crucible.ram.node.v1\0",
            &height.to_be_bytes(),
            left,
            right,
        ])
    }

    fn region(self, geometry: Geometry, node: &[u8; 32]) -> [u8; 32] {
        self.hash(&[
            b"crucible.ram.region-tree.v1\0",
            &geometry.logical_length().to_be_bytes(),
            &geometry.page_count().to_be_bytes(),
            &geometry.height().to_be_bytes(),
            node,
        ])
    }

    fn root(self, topology: &[u8; 32], descriptor: &[u8], region: &[u8; 32]) -> [u8; 32] {
        self.hash(&[
            b"crucible.ram.root.v1\0",
            &1_u32.to_be_bytes(),
            &4096_u32.to_be_bytes(),
            &5_u32.to_be_bytes(),
            b"exact",
            topology,
            &1_u32.to_be_bytes(),
            descriptor,
            region,
        ])
    }
}

struct Row {
    algorithm: &'static str,
    workload: String,
    logical_pages: usize,
    changed_pages: usize,
    hashes_per_iteration: usize,
    preimage_bytes_per_iteration: usize,
    iterations: usize,
    sample: usize,
    elapsed_ns: u128,
}

fn main() -> BenchmarkResult<()> {
    let directory = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("one output-directory argument is required")?;
    std::fs::create_dir_all(&directory)?;
    verify_preimages()?;

    let mut rows = Vec::new();
    for algorithm in [Algorithm::Blake3, Algorithm::Sha256] {
        measure_small(algorithm, &mut rows)?;
        for pages in [256_usize, 4096] {
            for changed in [1, 16, pages] {
                measure_batch(algorithm, pages, changed, &mut rows)?;
            }
        }
    }
    write_results(directory, &rows)
}

fn fixture_page(index: usize) -> [u8; PAGE_BYTES] {
    let mut bytes = [0_u8; PAGE_BYTES];
    let mut state = (index as u64).wrapping_add(0x9e37_79b9_7f4a_7c15);
    for byte in &mut bytes {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 56) as u8;
    }
    bytes
}

fn descriptor(length: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(REGION_ID.len() as u32).to_be_bytes());
    bytes.extend_from_slice(REGION_ID.as_bytes());
    bytes.push(RegionClass::MutableMain as u8);
    bytes.push(7);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes
}

fn topology(length: u64) -> BenchmarkResult<Topology> {
    Ok(Topology::new(
        vec![RegionDescriptor::new(
            REGION_ID,
            RegionClass::MutableMain,
            length,
        )?],
        Limits::default(),
    )?)
}

fn verify_preimages() -> BenchmarkResult<()> {
    let algorithm = Algorithm::Blake3;
    let bytes = fixture_page(7);
    for length in [1, 4095, PAGE_BYTES] {
        if algorithm.page(&bytes[..length]) != *PageDigest::hash(&bytes[..length])?.as_bytes() {
            return Err("page preimage differs from the production canonical commitment".into());
        }
    }
    let page = PageDigest::hash(&bytes)?;
    let leaf = leaf_digest(page);
    if algorithm.leaf(page.as_bytes()) != *leaf.as_bytes() {
        return Err("leaf preimage differs from production".into());
    }
    let right = NodeDigest::from_bytes([3; 32]);
    let branch = inner_digest(1, leaf, right)?;
    if algorithm.branch(1, leaf.as_bytes(), right.as_bytes()) != *branch.as_bytes() {
        return Err("branch preimage differs from production".into());
    }
    let geometry = Geometry::new(8192)?;
    let region = region_tree_digest(geometry, branch);
    if algorithm.region(geometry, branch.as_bytes()) != *region.as_bytes() {
        return Err("region preimage differs from production".into());
    }
    let topology = topology(8192)?;
    let record = RootRecord::new(topology.clone(), Scope::Exact, vec![region])?;
    if algorithm.root(
        topology.digest().as_bytes(),
        &descriptor(8192),
        region.as_bytes(),
    ) != *record.digest().as_bytes()
    {
        return Err("scoped-root preimage differs from production".into());
    }
    Ok(())
}

fn measure_small(algorithm: Algorithm, rows: &mut Vec<Row>) -> BenchmarkResult<()> {
    let bytes = fixture_page(3);
    let page = algorithm.page(&bytes);
    let leaf = algorithm.leaf(&page);
    let geometry = Geometry::new(8192)?;
    let region = algorithm.region(geometry, &leaf);
    let inventory = topology(8192)?;
    let descriptor = descriptor(8192);
    for (name, length, iterations) in [
        ("page-4096", 4096, 50_000),
        ("final-partial-page-4095", 4095, 50_000),
        ("final-partial-page-1", 1, 500_000),
        ("leaf", 0, 500_000),
        ("branch", 0, 500_000),
        ("region-tree", 0, 500_000),
        ("scoped-root-one-region", 0, 200_000),
    ] {
        let input_bytes = match name {
            "leaf" => b"crucible.ram.leaf.v1\0".len() + 32,
            "branch" => b"crucible.ram.node.v1\0".len() + 4 + 64,
            "region-tree" => b"crucible.ram.region-tree.v1\0".len() + 8 + 8 + 4 + 32,
            "scoped-root-one-region" => {
                b"crucible.ram.root.v1\0".len() + 4 + 4 + 4 + 5 + 32 + 4 + descriptor.len() + 32
            }
            _ => b"crucible.ram.page.v1\0".len() + 4 + length,
        };
        let run = || match name {
            "leaf" => algorithm.leaf(&page),
            "branch" => algorithm.branch(1, &leaf, &leaf),
            "region-tree" => algorithm.region(geometry, &leaf),
            "scoped-root-one-region" => {
                algorithm.root(inventory.digest().as_bytes(), &descriptor, &region)
            }
            _ => algorithm.page(&bytes[..length]),
        };
        for _ in 0..1000 {
            black_box(run());
        }
        for sample in 0..SAMPLES {
            let started = Instant::now();
            for _ in 0..iterations {
                black_box(run());
            }
            rows.push(Row {
                algorithm: algorithm.name(),
                workload: name.to_owned(),
                logical_pages: 0,
                changed_pages: 0,
                hashes_per_iteration: 1,
                preimage_bytes_per_iteration: input_bytes,
                iterations,
                sample,
                elapsed_ns: started.elapsed().as_nanos(),
            });
        }
    }
    Ok(())
}

fn measure_batch(
    algorithm: Algorithm,
    pages: usize,
    changed: usize,
    rows: &mut Vec<Row>,
) -> BenchmarkResult<()> {
    let geometry = Geometry::new((pages * PAGE_BYTES) as u64)?;
    let inventory = topology(geometry.logical_length())?;
    let descriptor = descriptor(geometry.logical_length());
    let baseline = algorithm.leaf(&algorithm.page(&[0; PAGE_BYTES]));
    let mut nodes = vec![baseline; pages * 2];
    for index in (1..pages).rev() {
        let height = pages.ilog2() - index.ilog2();
        nodes[index] = algorithm.branch(height, &nodes[index * 2], &nodes[index * 2 + 1]);
    }
    let indices = (0..changed)
        .map(|offset| offset * pages / changed)
        .collect::<Vec<_>>();
    let mut payloads = indices
        .iter()
        .map(|index| fixture_page(*index))
        .collect::<Vec<_>>();
    let mut ancestors = BTreeSet::new();
    for index in &indices {
        let mut parent = (pages + index) / 2;
        while parent > 0 {
            ancestors.insert(parent);
            parent /= 2;
        }
    }
    let ancestors = ancestors.into_iter().rev().collect::<Vec<_>>();
    let hashes = changed * 2 + ancestors.len() + 2;
    let input_bytes = changed
        * (b"crucible.ram.page.v1\0".len() + 4 + PAGE_BYTES + b"crucible.ram.leaf.v1\0".len() + 32)
        + ancestors.len() * (b"crucible.ram.node.v1\0".len() + 4 + 64)
        + b"crucible.ram.region-tree.v1\0".len()
        + 8
        + 8
        + 4
        + 32
        + b"crucible.ram.root.v1\0".len()
        + 4
        + 4
        + 4
        + 5
        + 32
        + 4
        + descriptor.len()
        + 32;
    let iterations = if changed == pages { 16 } else { 500 };
    let mut run = || {
        for (index, bytes) in indices.iter().zip(&mut payloads) {
            // Every declared dirty page changes, including successive rounds.
            bytes[0] ^= 1;
            nodes[pages + index] = algorithm.leaf(&algorithm.page(bytes));
        }
        for index in &ancestors {
            let height = pages.ilog2() - index.ilog2();
            nodes[*index] = algorithm.branch(height, &nodes[index * 2], &nodes[index * 2 + 1]);
        }
        let region = algorithm.region(geometry, &nodes[1]);
        algorithm.root(inventory.digest().as_bytes(), &descriptor, &region)
    };
    black_box(run());
    for sample in 0..SAMPLES {
        let started = Instant::now();
        for _ in 0..iterations {
            black_box(run());
        }
        rows.push(Row {
            algorithm: algorithm.name(),
            workload: if changed == pages {
                "dense-union-update"
            } else {
                "sparse-union-update"
            }
            .to_owned(),
            logical_pages: pages,
            changed_pages: changed,
            hashes_per_iteration: hashes,
            preimage_bytes_per_iteration: input_bytes,
            iterations,
            sample,
            elapsed_ns: started.elapsed().as_nanos(),
        });
    }
    Ok(())
}

fn write_results(directory: PathBuf, rows: &[Row]) -> BenchmarkResult<()> {
    let mut csv = String::from(
        "algorithm,workload,logical_pages,changed_pages,hashes_per_iteration,preimage_bytes_per_iteration,iterations,sample,elapsed_ns,ns_per_iteration\n",
    );
    use std::fmt::Write;
    for row in rows {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{}",
            row.algorithm,
            row.workload,
            row.logical_pages,
            row.changed_pages,
            row.hashes_per_iteration,
            row.preimage_bytes_per_iteration,
            row.iterations,
            row.sample,
            row.elapsed_ns,
            format_args!(
                "{}.{:03}",
                row.elapsed_ns / row.iterations as u128,
                (row.elapsed_ns % row.iterations as u128) * 1000 / row.iterations as u128,
            )
        )?;
    }
    std::fs::write(directory.join("measurements.csv"), csv)?;
    let cpu = std::fs::read_to_string("/proc/cpuinfo")?;
    let model = cpu
        .lines()
        .find_map(|line| line.strip_prefix("model name\t: "))
        .unwrap_or("unreported");
    #[cfg(target_arch = "x86_64")]
    let sha_accelerated = std::is_x86_feature_detected!("sha")
        && std::is_x86_feature_detected!("sse2")
        && std::is_x86_feature_detected!("ssse3")
        && std::is_x86_feature_detected!("sse4.1");
    #[cfg(not(target_arch = "x86_64"))]
    let sha_accelerated = false;
    let receipt = serde_json::json!({
        "schema": "crucible.ram.offline-hash-measurements",
        "version": 1,
        "unix_time_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "architecture": std::env::consts::ARCH,
        "operating_system": std::env::consts::OS,
        "cpu_model": model,
        "cpu_flags": cpu.lines().find_map(|line| line.strip_prefix("flags\t\t: ")).unwrap_or("unreported"),
        "host_blake3": {"crate": "blake3", "version": "1.8.5", "features": ["std", "pure"], "path": "workspace-selected pure Rust implementation; SIMD intrinsics enabled by runtime detection", "detected_platform": format!("{:?}", blake3::platform::Platform::detect()), "simd_degree": blake3::platform::Platform::detect().simd_degree(), "assembly_and_avx512": "disabled by pure feature"},
        "offline_sha256": {"crate": "sha2", "version": "0.10.9", "features": ["default", "compress"], "path": if sha_accelerated {"x86 SHA/SSE2/SSSE3/SSE4.1 runtime-selected intrinsics"} else {"portable fallback; accelerated path not established"}},
        "profile": "release",
        "samples_per_workload": SAMPLES,
        "canonical_preimages_verified_against_production": true,
        "method": "segmented domain-preserving updates; union of changed-page ancestor paths; prebuilt inputs and dense node storage; each declared dirty page changes its first byte every round",
        "limitations": [
            "Warm host-side in-process hashing only; no I/O, pager, whole-VM or memory-peak qualification.",
            "Native C fingerprinting backend was not timed; these results do not cover that implementation.",
            "Batch storage and ancestor sets are preallocated; persistent-tree allocation, metadata COW, concurrency and tracking costs are excluded.",
            "No processor affinity or frequency isolation; samples describe this run and are not a general performance guarantee.",
            "BLAKE3 is the selected pure host implementation; SHA-256 is an offline comparison with runtime acceleration when detected."
        ]
    });
    std::fs::write(
        directory.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_preimages_match_the_selected_host_commitments() -> BenchmarkResult<()> {
        verify_preimages()
    }

    #[test]
    fn union_batches_match_the_actual_persistent_tree() -> BenchmarkResult<()> {
        let pages = 16_usize;
        let algorithm = Algorithm::Blake3;
        let zero = PageDigest::hash(&[0; PAGE_BYTES])?;
        let budget = crucible_ram::MetadataBudget::new(1024 * 1024);
        let baseline = crucible_ram::RegionTree::from_page_digests(
            (pages * PAGE_BYTES) as u64,
            &vec![zero; pages],
            &budget,
        )?;
        for changed in [1, 4, pages] {
            let mut nodes = vec![algorithm.leaf(zero.as_bytes()); pages * 2];
            let mut updates = Vec::new();
            let mut ancestors = BTreeSet::new();
            for offset in 0..changed {
                let index = offset * pages / changed;
                let bytes = fixture_page(index);
                let page = PageDigest::hash(&bytes)?;
                nodes[pages + index] = algorithm.leaf(page.as_bytes());
                updates.push((index as u64, page));
                let mut parent = (pages + index) / 2;
                while parent > 0 {
                    ancestors.insert(parent);
                    parent /= 2;
                }
            }
            // Build unchanged branches first, then replace just the union of
            // changed ancestors, exactly as the timed workload does.
            let original_leaf = algorithm.leaf(zero.as_bytes());
            let mut original = vec![original_leaf; pages * 2];
            for index in (1..pages).rev() {
                original[index] = algorithm.branch(
                    pages.ilog2() - index.ilog2(),
                    &original[index * 2],
                    &original[index * 2 + 1],
                );
                nodes[index] = original[index];
            }
            for index in ancestors.into_iter().rev() {
                nodes[index] = algorithm.branch(
                    pages.ilog2() - index.ilog2(),
                    &nodes[index * 2],
                    &nodes[index * 2 + 1],
                );
            }
            let updated = baseline.updated(&updates)?;
            let actual = algorithm.region(updated.geometry(), &nodes[1]);
            if actual != *updated.digest().as_bytes() {
                return Err("union workload differs from the production persistent tree".into());
            }
        }
        Ok(())
    }
}
