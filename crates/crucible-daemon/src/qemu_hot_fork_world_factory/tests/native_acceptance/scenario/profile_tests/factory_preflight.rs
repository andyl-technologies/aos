//! Exercises storage admission through the real production lifecycle constructor.
//!
//! The recording launcher refuses before process creation. Reaching it proves
//! that original block and 9p assets passed the constructor's binding checks;
//! it does not qualify a guest execution or a hot-fork continuation.

use std::sync::atomic::{AtomicUsize, Ordering};

use crucible::WorldIoNodeKind;
use crucible_api::vm_lifecycle::{
    ProductionVmExactNodeRestoreAdmission, ProductionVmNodeLaunch, ProductionVmNodeLaunchRequest,
    ProductionVmNodeLauncher,
};
use crucible_api::{
    LifecycleApiError, ProductionVmLifecycleConfig,
    build_production_vm_lifecycle_loop_with_launcher,
};

use super::*;

const LAUNCH_REFUSAL: &str = "fixture preflight reached authenticated launch";

#[test]
fn single_profiles_reach_launch_after_authenticating_original_storage() {
    let assets = FixtureAssets::new();
    populate_original_storage(&assets);

    for memory_mib in [None, Some(64)] {
        let source = single_profile(&assets, memory_mib);
        let (error, launches) = preflight(&assets, &source);

        assert_loop_factory_error(error, LAUNCH_REFUSAL);
        assert_eq!(launches, 1);
        assert_original_storage_topology(&source);
    }
}

#[test]
fn missing_original_storage_contract_is_refused_before_launch() {
    let assets = FixtureAssets::new();
    populate_original_storage(&assets);
    let source = single_profile(&assets, None);
    let world = World::from_node_defs_and_links(source.world().nodes().to_vec(), Vec::new())
        .expect("construct missing-contract World");
    let source = source_with_world(&world);

    let (error, launches) = preflight(&assets, &source);

    assert_loop_factory_error(
        error,
        "resolve block durability for `probe-block`: storage action target is not a declared live block device",
    );
    assert_eq!(launches, 0);
}

#[test]
fn changed_block_artifact_length_is_refused_before_launch() {
    let assets = FixtureAssets::new();
    populate_original_storage(&assets);
    let source = single_profile(&assets, None);
    let changed = assets
        .artifacts
        .put(b"changed block bytes")
        .expect("store changed block");
    let mut nodes = source.world().nodes().to_vec();
    for node in &mut nodes {
        if let WorldNodeDef::Io(io) = node
            && let WorldIoNodeKind::Block { base_image, .. } = &mut io.kind
        {
            *base_image = ContentAddressedBlobRef::from_hash(changed);
        }
    }
    let world = World::from_node_defs_and_links(nodes, Vec::new())
        .expect("construct changed-artifact World")
        .with_fault_topology(source.world().fault_topology().clone())
        .expect("retain original storage contract");
    let source = source_with_world(&world);

    let (error, launches) = preflight(&assets, &source);

    assert_loop_factory_error(
        error,
        "World block base image for `probe-block` differs from its declared hash or length",
    );
    assert_eq!(launches, 0);
}

fn single_profile(assets: &FixtureAssets, memory_mib: Option<u32>) -> ScenarioDefForm {
    match memory_mib {
        None => build_single_node_equivalence(
            FIXTURE,
            Arc::clone(&assets.artifacts),
            &assets.kernel,
            &assets.root_image,
        ),
        Some(memory) => build_single_node_equivalence_with_memory(
            FIXTURE,
            Arc::clone(&assets.artifacts),
            memory,
            &assets.kernel,
            &assets.root_image,
        ),
    }
    .expect("construct single-guest profile")
    .0
}

fn source_with_world(world: &World) -> ScenarioDefForm {
    ScenarioDefForm::from_components(
        world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(1),
    )
    .expect("construct negative preflight source")
}

fn populate_original_storage(assets: &FixtureAssets) {
    let base = ScenarioDefForm::from_canonical_toml(FIXTURE).expect("parse original fixture");
    let mut block = vec![0_u8; 1_048_576];
    block[..18].copy_from_slice(b"CRUCIBLE-BLOCK-OK\n");
    // The original materializer's versioned immutable tree contains probe.txt.
    let ninep = [
        b"crucible.device.ninep.fs-tree.v1\0".as_slice(),
        &[0],
        &1_u64.to_le_bytes(),
        &9_u64.to_le_bytes(),
        b"probe.txt",
        &[1],
        &15_u64.to_le_bytes(),
        b"CRUCIBLE-9P-OK\n",
    ]
    .concat();

    for bytes in [block, ninep] {
        let hash = assets
            .artifacts
            .put(&bytes)
            .expect("store immutable fixture asset");
        assert!(base.world().io_nodes().any(|node| match &node.kind {
            WorldIoNodeKind::Block { base_image, .. } => base_image.hash() == hash,
            WorldIoNodeKind::NineP { tree, .. } => tree.hash() == hash,
        }));
    }
}

fn assert_original_storage_topology(source: &ScenarioDefForm) {
    let base = ScenarioDefForm::from_canonical_toml(FIXTURE).expect("parse original fixture");
    let expected = crucible::model::WorldFaultTopology {
        storage_devices: base.world().fault_topology().storage_devices.clone(),
        ..Default::default()
    };
    assert!(!expected.storage_devices.is_empty());
    assert_eq!(source.world().fault_topology(), &expected);
}

fn preflight(assets: &FixtureAssets, source: &ScenarioDefForm) -> (LifecycleApiError, usize) {
    let directory = tempfile::tempdir().expect("create private preflight run directory");
    let calls = Arc::new(AtomicUsize::new(0));
    let config = ProductionVmLifecycleConfig::new(
        "unused-qemu",
        "unused-plugin",
        &assets.kernel,
        &assets.root_image,
        directory.path(),
    )
    .with_world_artifacts(Arc::clone(&assets.artifacts));
    let result = build_production_vm_lifecycle_loop_with_launcher(
        &source.scenario_def(),
        source,
        &config,
        RecordingLauncher(Arc::clone(&calls)),
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("preflight launcher must refuse before creating a guest"),
    };
    (error, calls.load(Ordering::SeqCst))
}

fn assert_loop_factory_error(error: LifecycleApiError, expected: &str) {
    assert!(
        matches!(&error, LifecycleApiError::LoopFactory { message } if message == expected),
        "expected {expected}, got {error}"
    );
}

struct RecordingLauncher(Arc<AtomicUsize>);

impl ProductionVmNodeLauncher for RecordingLauncher {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn launch_fresh(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        _qemu: &Path,
        _root: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        assert_eq!(request.node_name(), "curl");
        assert_eq!(request.generation(), 1);
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(LifecycleApiError::LoopFactory {
            message: LAUNCH_REFUSAL.into(),
        })
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        panic!("fresh preflight must not launch an exact restore")
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        panic!("fresh preflight must not allocate replay authority")
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }
}
