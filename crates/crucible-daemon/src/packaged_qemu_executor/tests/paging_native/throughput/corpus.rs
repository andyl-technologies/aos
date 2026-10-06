//! Immutable single-guest corpus and explicit full installation entitlements.

use super::*;

pub(super) fn source() -> ScenarioDefForm {
    let world = World::from_nodes(vec![crucible::WorldNode {
        id: NodeId {
            name: "memory".into(),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: 512,
        cmdline: String::new(),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("authored 512 MiB single-guest throughput corpus");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(42),
    )
    .expect("canonical immutable throughput corpus")
}

pub(super) fn qemu_build() -> String {
    crucible_qemu::QemuLaunchArtifactIdentity::authenticate(
        environment_path("CRUCIBLE_PAGING_QEMU"),
        environment_path("CRUCIBLE_PAGING_PLUGIN"),
    )
    .expect("matching complete native artifact identity")
    .qemu_build_id()
    .to_owned()
}

pub(super) fn repository(
    source: &ScenarioDefForm,
    storage: environment::NativeCampaignStorage,
) -> Arc<CampaignRepository> {
    let repository = Arc::new(
        CampaignRepository::with_component_authorities(
            storage.backend,
            storage.refs,
            PlannerAuthorityKey::from_bytes([0x31; 32]).expect("actual planner key"),
            DebuggerAuthorityKey::from_bytes([0x47; 32]).expect("separate debugger key"),
        )
        .expect("genuine quota-backed campaign repository"),
    );
    let mut identities = BTreeSet::new();
    for seed in SEEDS {
        let source = seeded_source(source, seed).expect("admitted immutable seeded workload");
        let encoded =
            crate::encode_crucible_scenario_artifact(&source).expect("canonical scenario");
        let scenario = repository
            .publish_scenario_artifact(
                encoded.scenario(),
                encoded.payload_schema(),
                admitted_bytes(encoded.payload()),
            )
            .expect("immutable scenario publication under actual catalog authority");
        let genesis = crate::encode_crucible_configuration_artifact(
            &encoded,
            &Configuration::genesis(source.scenario_def()).schedule,
        )
        .expect("canonical genesis configuration");
        let configuration = repository
            .publish_configuration_artifact(
                encoded.scenario(),
                scenario,
                genesis.configuration(),
                genesis.payload_schema(),
                admitted_bytes(genesis.payload()),
            )
            .expect("actual immutable genesis publication");
        let lineage = CampaignLineage::new(
            encoded.scenario(),
            scenario,
            genesis.configuration(),
            configuration,
            "crucible-test",
            qemu_build(),
            BTreeMap::from([
                ("control".into(), crucible_api::CONTROL_PROTOCOL_VERSION),
                ("shared-memory".into(), crucible::SHMEM_ABI_VERSION),
            ]),
            encoded.payload_schema(),
            crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        )
        .expect("same canonical compatibility as the guarded campaign driver");
        let policy = packaged_policy(encoded.scenario())
            .with_attempt_timeout_policy(
                crucible_campaign::CampaignAttemptTimeoutPolicy::new(
                    None,
                    Some(50_000),
                    Some(1_200_000),
                )
                .expect("finite authored original assignment cap"),
            )
            .expect("policy-bound timeout identity");
        repository
            .create(
                campaign_name(seed).as_str(),
                &lineage,
                &policy,
                &BTreeMap::new(),
            )
            .expect("real prepared campaign compatibility basis");
        crucible::owned_decode::charge_btree_set_entry::<crucible::ContentHash>()
            .expect("original catalog corpus identity bank");
        assert!(
            identities.insert(source.scenario_def().id()),
            "every worker has a distinct immutable scenario"
        );
    }
    assert_eq!(identities.len(), SEEDS.len());
    repository
}

pub(super) const SEEDS: [u64; 63] = {
    let mut seeds = [0; 63];
    let mut index = 0;
    while index < seeds.len() {
        seeds[index] = 1000 + index as u64;
        index += 1;
    }
    seeds
};

pub(super) fn seed(divisor: u64, parallel: usize, repeat: usize, worker: usize) -> u64 {
    let target = TARGET_DIVISORS
        .iter()
        .position(|candidate| *candidate == divisor)
        .expect("authored target inventory");
    let preceding = PARALLEL
        .iter()
        .take_while(|candidate| **candidate != parallel)
        .sum::<usize>();
    let index = target * REPEATS * PARALLEL.iter().sum::<usize>()
        + preceding * REPEATS
        + repeat * parallel
        + worker;
    SEEDS[index]
}

pub(super) fn seeded_source(
    source: &ScenarioDefForm,
    seed: u64,
) -> Result<ScenarioDefForm, crucible::EngineError> {
    ScenarioDefForm::from_components(
        source.world(),
        source.plan(),
        source.properties(),
        Seed::from_u64(seed),
    )
}

fn campaign_name(seed: u64) -> crucible_campaign::CampaignName {
    crucible_campaign::CampaignName::new(format!("throughput-{seed}"))
        .expect("finite canonical corpus campaign name")
}

fn admitted_bytes(source: &[u8]) -> Vec<u8> {
    let mut copied = Vec::new();
    crucible::owned_decode::reserve_vec(&mut copied, source.len())
        .expect("original corpus publication credit");
    copied.extend_from_slice(source);
    copied
}

pub(super) fn catalog_budget() -> environment::NativeCatalogBudget {
    environment::NativeCatalogBudget {
        resources: HostResourceVector {
            resident_peak_bytes: 512 << 20,
            backing_peak_bytes: 8 << 30,
            metadata_bytes: 256 << 20,
            staging_bytes: 32 << 20,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 128,
        },
        // The existing bounded cleanup contract permits 1,048,576 inodes;
        // the corpus still submits all 63 independently Completed campaigns.
        maximum_inodes: 1_048_576,
        installation_capacity: Some(
            ExecutorCapacity::new(4, 10, 16 << 30, 64 << 30, 150_000).expect(
                "four native assignments plus four host worker CPUs and two durable services",
            ),
        ),
        installation_operational_capacity: Some(
            crate::HostOperationalCapacity::new(16, 4096, 65_536, 8 << 30, 1 << 30)
                .expect("explicit independent metadata/task/FD installation ceilings"),
        ),
    }
}

pub(super) fn resources(mut config: PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig {
    config.campaigns = SEEDS.into_iter().map(campaign_name).collect();
    let mut budgets = config
        .host_operation_budgets()
        .expect("original explicit infrastructure roster");
    budgets.classes[HostOperationClass::Preparation as usize].total_timeout =
        Some(Duration::from_secs(3600));
    config = config
        .with_host_operation_budgets(budgets)
        .expect("one finite original whole-matrix Preparation allowance");
    let assignment = HostResourceVector {
        resident_peak_bytes: 1536 << 20,
        backing_peak_bytes: 4 << 30,
        metadata_bytes: 512 << 20,
        staging_bytes: 32 << 20,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 69,
        file_descriptors: 1056,
    };
    config
        .with_assignment_resources(
            assignment,
            AttemptResourceLimits::new(1, 512 << 20, 1 << 30, 50_000)
                .expect("unchanged semantic request limits across placement rows"),
        )
        .expect("actual full-vector native assignment entitlement")
        .with_retained_template_resources(assignment)
        .expect("independent source service entitlement remains available for replay phases")
}

#[test]
fn catalog_profile_respects_the_existing_inode_cleanup_bound() {
    let catalog = catalog_budget();
    let quota = crucible_linux_resource::LinuxProjectQuotaLimits::new(
        catalog.resources.backing_peak_bytes,
        catalog.maximum_inodes,
    )
    .expect("authored throughput catalog respects the production cleanup bound");

    assert_eq!(quota.maximum_inodes(), 1_048_576);
    assert_eq!(quota.requested_bytes(), 8 << 30);
    assert!(
        crucible_linux_resource::LinuxProjectQuotaLimits::new(
            catalog.resources.backing_peak_bytes,
            catalog.maximum_inodes + 1,
        )
        .is_err()
    );
    assert_eq!(SEEDS.len(), 63);
}

#[test]
fn trial_inventory_assigns_every_declared_seed_once() {
    let mut observed = [false; SEEDS.len()];
    for divisor in TARGET_DIVISORS {
        for parallel in PARALLEL {
            for repeat in 0..REPEATS {
                for worker in 0..parallel {
                    let seed = seed(divisor, parallel, repeat, worker);
                    let index = SEEDS
                        .iter()
                        .position(|candidate| *candidate == seed)
                        .expect("authored finite corpus membership");
                    assert!(
                        !observed[index],
                        "campaign names must not disguise a repeated semantic attempt"
                    );
                    observed[index] = true;
                }
            }
        }
    }
    assert!(observed.into_iter().all(|used| used));
}
