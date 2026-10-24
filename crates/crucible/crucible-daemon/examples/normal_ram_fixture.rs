//! Builds immutable semantic inputs for the normal managed-RAM service fixture.
//!
//! This build-time tool authenticates the selected packaged QEMU pair and hashes
//! actual guest files. Its records issue no native or service resource authority.

// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use crucible_store::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

use crucible_engine::{
    Action, Condition, ContentAddressedBlobRef, ContentHash, EventGraphBuilder, Icount, NodeId,
    Plan, Properties, ReadyPoint, ScenarioDefForm, Schedule, Seed, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode,
};
use crucible_campaign::{
    Attempt, AttemptStart, BranchPath, CampaignLineage, CampaignMode, CampaignPolicy,
    CampaignRamAdmission, CampaignRepository, CampaignSeed, ExplorerPolicy, FairnessPolicy,
    RetentionPolicy, StopCondition,
};
use crucible_daemon::{encode_crucible_configuration_artifact, encode_crucible_scenario_artifact};

#[derive(Clone, Copy, PartialEq, Eq)]
enum NativeAssertionProgram {
    FourVcpu,
    BlockRecovery,
}

fn main() -> ExitCode {
    match build() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("normal-ram-fixture: {error}");
            ExitCode::FAILURE
        }
    }
}

fn build() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let (arguments, flight) = match arguments.as_slice() {
        [output, kernel, root, initrd, qemu, plugin] =>
            ([output, kernel, root, initrd, qemu, plugin], None),
        [output, kernel, root, initrd, qemu, plugin, kind] => {
            let flight = match kind.as_str() {
                "four-vcpu" => Some(NativeAssertionProgram::FourVcpu),
                "block-recovery" => Some(NativeAssertionProgram::BlockRecovery),
                _ => return Err("unknown native plugin assertion program".into()),
            };
            ([output, kernel, root, initrd, qemu, plugin], flight)
        }
        _ => return Err("expected output, kernel, root image, initrd, QEMU, plugin and optional native assertion program".into()),
    };
    let [output, kernel, root, initrd, qemu, plugin] = arguments;
    let output = Path::new(output);
    if !output.is_absolute() || output.exists() {
        return Err("output must be a new absolute directory".into());
    }
    let qemu_build = crucible_daemon::packaged_qemu_identity::authenticated_qemu_build_id(
        Path::new(qemu),
        Path::new(plugin),
    )?;
    let world = World::from_nodes(vec![WorldNode {
        id: NodeId {
            name: String::from(match flight {
                None => "memory",
                Some(NativeAssertionProgram::FourVcpu) => "plugin-flight-node",
                Some(NativeAssertionProgram::BlockRecovery) => "block-recovery-hot-fork-node",
            }),
        },
        arch: VmArchitecture::X86_64,
        memory_mib: if flight.is_some() { 128 } else { 64 },
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: if flight == Some(NativeAssertionProgram::FourVcpu) {
            4
        } else {
            1
        },
        kernel: if flight.is_some() {
            None
        } else {
            Some(reference(kernel)?)
        },
        root_image: if flight.is_some() {
            None
        } else {
            Some(reference(root)?)
        },
        initrd: if flight.is_some() {
            None
        } else {
            Some(reference(initrd)?)
        },
    }])?;
    // A declared future terminal event keeps the semantic plan unfinished
    // while the external caller controls the actual live incarnation. The
    // fixture still fails if execution ends before that caller observes it.
    let graph = EventGraphBuilder::default()
        .event("normal-control-window-end")
        .when(Condition::at(VirtualTime { ticks: 120_000_000 }))
        .action(Action::pass())
        .build_for_world(&world)?;
    let plan = if flight.is_some() {
        Plan::empty()
    } else {
        Plan::from_event_graph_for_world(&world, graph)?
    };
    let scenario =
        ScenarioDefForm::from_components(&world, &plan, &Properties::empty(), Seed::from_u64(42))?;
    let schedule = Schedule::empty();
    let scenario_artifact = encode_crucible_scenario_artifact(&scenario)?;
    let configuration = encode_crucible_configuration_artifact(&scenario_artifact, &schedule)?;
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario_artifact.scenario(),
            CampaignSeed::from_bytes([42; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 1,
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::from([String::from("scenario-complete")]),
            FairnessPolicy::new(0, 0)?,
            RetentionPolicy::new(true, 1, true, true),
            false,
        ),
    )?;
    let lineage = CampaignLineage::new(
        scenario_artifact.scenario(),
        scenario_artifact.id()?,
        configuration.configuration(),
        configuration.id()?,
        env!("CARGO_PKG_VERSION"),
        &qemu_build,
        crucible_daemon::packaged_qemu_identity::packaged_qemu_protocol_versions(),
        scenario_artifact.payload_schema(),
        crucible_daemon::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
    )?;
    // Match the genuine repository's sole initial-discovery derivation. The
    // client still authenticates this identity against its current snapshot.
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: lineage.genesis_content(),
        },
        BranchPath::new(Vec::new())?.id()?,
        policy.bound_stop(StopCondition::NextChoice)?,
    )?;

    fs::create_dir(output)?;
    fs::write(output.join("scenario.bin"), scenario.to_compact_binary())?;
    fs::write(output.join("schedule.bin"), schedule.to_compact_binary())?;
    fs::write(output.join("lineage.bin"), lineage.canonical_bytes())?;
    fs::write(output.join("policy.bin"), policy.canonical_bytes())?;
    fs::write(output.join("attempt-id"), format!("{}\n", attempt.id()?))?;
    let repository = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "normal-ram-input",
            output.join("state/objects"),
        )),
        Arc::new(DirectoryRefBackend::new(output.join("state/refs"))),
        CampaignRamAdmission::Unavailable,
    );
    let published_scenario = repository.publish_scenario_artifact(
        scenario_artifact.scenario(),
        scenario_artifact.payload_schema(),
        scenario_artifact.payload().to_vec(),
    )?;
    let published_configuration = repository.publish_configuration_artifact(
        scenario_artifact.scenario(),
        published_scenario,
        configuration.configuration(),
        configuration.payload_schema(),
        configuration.payload().to_vec(),
    )?;
    if published_scenario != lineage.scenario_content()
        || published_configuration != lineage.genesis_content()
    {
        return Err("published semantic fixture changed its authenticated identity".into());
    }
    // This seed has semantic campaign state only: no assignment, execution
    // ledger, Ready marker, native account, or serialized process owner.
    repository.create("normal-ram", &lineage, &policy, &BTreeMap::new())?;

    fs::write(
        output.join("import.toml"),
        format!(
            "schema = \"crucible.campaign-import\"\nversion = 1\n[[configuration]]\nscenario = {:?}\nschedule = {:?}\n",
            output.join("scenario.bin"),
            output.join("schedule.bin"),
        ),
    )?;
    Ok(())
}

fn reference(path: &str) -> Result<ContentAddressedBlobRef, Box<dyn Error>> {
    Ok(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
        &fs::read(path)?,
    )))
}
