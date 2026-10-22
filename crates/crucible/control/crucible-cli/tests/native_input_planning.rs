//! Plain native model planning and execution under one genuine deployed owner.
//!
//! These process tests require the disposable kernel flight's independently
//! installed source, catalog, registry, and guest-resource quotas. They preserve
//! accepted campaign completion and actual native coverage assertions; ordinary
//! hosts run them through that explicit gate rather than a component fallback.

use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use crucible_session::engine as crucible;

#[path = "support/input_scope.rs"]
mod input_scope;

#[test]
fn plain_native_run_plans_and_completes_on_one_deployed_owner() -> Result<(), Box<dyn Error>> {
    let resources = input_scope::open()?;
    resources.authority.verify()?;
    let _scope = resources.decoding.enter();
    let directory = tempfile::TempDir::new()?;
    let scenario = directory.path().join("native-run.toml");
    let world = crucible::World::from_nodes(vec![crucible::WorldNode {
        id: crucible::NodeId {
            name: String::from("native-input-node"),
        },
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: 128,
        cmdline: String::from(
            "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off",
        ),
        ready_point: crucible::ReadyPoint::FixedIcount {
            icount: crucible::Icount { retired: 1_000_000 },
        },
        white_box: crucible::WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let form = crucible::ScenarioDefForm::from_components(
        &world,
        &crucible::Plan::empty(),
        &crucible::Properties::default(),
        crucible::Seed::from_u64(0x1357),
    )?;
    fs::write(&scenario, form.to_canonical_toml()?)?;

    let output = native_command(directory.path())?
        .arg("run")
        .arg(&scenario)
        .args(["--max-quanta", "2"])
        .output()?;
    let stdout = successful_stdout(output)?;
    assert!(
        stdout.contains("operation=run-campaign-default-path"),
        "{stdout}"
    );
    assert!(stdout.contains("owner=campaign"), "{stdout}");
    let trace = read_trace(&resources, directory.path())?;
    let completed = trace
        .lines()
        .find(|line| line.contains("campaign_completed"))
        .ok_or("native run did not publish accepted campaign completion")?;
    assert!(completed.contains("quanta=2"), "{completed}");
    Ok(())
}

#[test]
fn plain_native_fuzz_plans_and_records_real_coverage_on_one_deployed_owner()
-> Result<(), Box<dyn Error>> {
    let resources = input_scope::open()?;
    resources.authority.verify()?;
    let _scope = resources.decoding.enter();
    let directory = tempfile::TempDir::new()?;
    let family = directory.path().join("native-family.toml");
    fs::write(&family, FAMILY)?;

    let output = native_command(directory.path())?
        .arg("fuzz")
        .arg(&family)
        .args(["--runs", "1"])
        .output()?;
    let stdout = successful_stdout(output)?;
    assert!(stdout.contains("operation=fuzz-live-campaign"), "{stdout}");
    let trace = read_trace(&resources, directory.path())?;
    assert!(trace.contains("fuzz_campaign_execution"), "{trace}");
    let feedback = trace
        .lines()
        .find(|line| line.contains("fuzz_coverage_feedback"))
        .ok_or("native fuzz did not publish coverage feedback")?;
    let blocks = feedback
        .split_whitespace()
        .find_map(|field| field.strip_prefix("blocks="))
        .ok_or("native fuzz coverage did not report its actual block count")?
        .parse::<u64>()?;
    assert!(blocks > 0, "{feedback}");
    Ok(())
}

fn native_command(directory: &Path) -> Result<Command, Box<dyn Error>> {
    let executable = std::env::var_os("CRUCIBLE_PROCESS_FLIGHT_BINARY")
        .ok_or("native planning requires the installed source-built flight executable")?;
    let mut command = Command::new(executable);
    command
        .args(["--backend", "qemu", "--seed", "4951", "--store"])
        .arg(directory.join("model-store"))
        .arg("--artifact-dir")
        .arg(directory.join("artifacts"))
        .arg("--trace")
        .arg(directory.join("trace.log"));
    Ok(command)
}

fn successful_stdout(output: Output) -> Result<String, Box<dyn Error>> {
    assert!(
        output.status.success(),
        "native command failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn read_trace(
    resources: &input_scope::NativeInputResources,
    directory: &Path,
) -> Result<String, Box<dyn Error>> {
    use std::io::Read;

    let descriptor = resources
        .authority
        .reserve_resources(1, std::mem::size_of::<fs::File>() as u64)?;
    let file = fs::File::open(directory.join("trace.log"))?;
    let length = file.metadata()?.len();
    let extent = length.checked_add(1).ok_or("native trace size overflow")?;
    resources.decoding.charge_bytes(extent)?;
    let mut trace = String::new();
    trace.try_reserve_exact(usize::try_from(extent)?)?;
    let mut reader = file.take(extent);
    reader.read_to_string(&mut trace)?;
    if trace.len() as u64 != length {
        return Err("native trace changed length while reading".into());
    }
    resources.authority.verify()?;
    drop(reader);
    drop(descriptor);
    Ok(trace)
}

const FAMILY: &str = r#"schema = "crucible.scenario-family.v3"
topology_shapes = ["ring"]
fault_densities = [0]

[seed_space]
kind = "generated"
meta_seed = "0x1357"
count = 1

[topology_size]
min = 1
max = 1

[node_template]
memory_mib = 128
fixed_icount = 1000000
cmdline = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off"
"#;
