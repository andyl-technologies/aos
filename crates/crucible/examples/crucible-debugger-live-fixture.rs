//! Generates a canonical live-debugger scenario bound to concrete boot assets.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Error as IoError, ErrorKind, Write};
use std::path::Path;

use crucible::{
    Action, Condition, ContentAddressedBlobRef, ContentHash, EventGraph, LogLevel, NodeId, Plan,
    Properties, ReadyPoint, ScenarioDefForm, Seed, VirtualTime, VmArchitecture, WhiteBoxPolicy,
    World, WorldNode,
};

fn usage_error(message: impl Into<String>) -> IoError {
    IoError::new(ErrorKind::InvalidInput, message.into())
}

fn parse_architecture(value: &str) -> Result<VmArchitecture, IoError> {
    match value {
        "x86_64" => Ok(VmArchitecture::X86_64),
        "aarch64" => Ok(VmArchitecture::Aarch64),
        _ => Err(usage_error(format!(
            "unsupported architecture `{value}`; expected x86_64 or aarch64"
        ))),
    }
}

fn fixture_kernel_cmdline(architecture: VmArchitecture) -> String {
    let console = match architecture {
        VmArchitecture::X86_64 => "ttyS0",
        VmArchitecture::Aarch64 => "ttyAMA0",
    };
    format!("console={console} reboot=k panic=1 root=/dev/vda ro init=/init")
}

fn file_reference(path: &Path) -> Result<ContentAddressedBlobRef, IoError> {
    let file = fs::File::open(path).map_err(|source| {
        IoError::new(
            source.kind(),
            format!("read debugger fixture asset {}: {source}", path.display()),
        )
    })?;
    Ok(ContentAddressedBlobRef::from_hash(
        ContentHash::from_reader(file)?,
    ))
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os();
    let program = args
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| String::from("crucible-debugger-live-fixture"));
    let architecture = args
        .next()
        .ok_or_else(|| usage_error(format!("usage: {program} ARCH KERNEL ROOT-IMAGE OUTPUT")))?;
    let kernel = args
        .next()
        .ok_or_else(|| usage_error(format!("usage: {program} ARCH KERNEL ROOT-IMAGE OUTPUT")))?;
    let root_image = args
        .next()
        .ok_or_else(|| usage_error(format!("usage: {program} ARCH KERNEL ROOT-IMAGE OUTPUT")))?;
    let output = args
        .next()
        .ok_or_else(|| usage_error(format!("usage: {program} ARCH KERNEL ROOT-IMAGE OUTPUT")))?;
    if args.next().is_some() {
        return Err(usage_error(format!("usage: {program} ARCH KERNEL ROOT-IMAGE OUTPUT")).into());
    }

    let architecture = architecture
        .to_str()
        .ok_or_else(|| usage_error("architecture is not valid UTF-8"))?;
    let architecture = parse_architecture(architecture)?;
    let node = WorldNode {
        id: NodeId {
            name: String::from("debuggee"),
        },
        arch: architecture,
        memory_mib: 256,
        cmdline: fixture_kernel_cmdline(architecture),
        ready_point: ReadyPoint::ConsoleMarker {
            marker: String::from("CRUCIBLE_DEBUG_ACTIVATION_READER_READY"),
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 1,
        icount_shift: 0,
        kernel: Some(file_reference(Path::new(&kernel))?),
        root_image: Some(file_reference(Path::new(&root_image))?),
        initrd: None,
    };
    let world = World::from_nodes(vec![node])?;
    let graph = EventGraph::builder()
        .event("debug-history-1")
        .when(Condition::At {
            at: VirtualTime { ticks: 4_096 },
        })
        .action(Action::log(LogLevel::Info, "debug history boundary 1"))
        .event("debug-history-2")
        .when(Condition::At {
            at: VirtualTime { ticks: 8_192 },
        })
        .action(Action::log(LogLevel::Info, "debug history boundary 2"))
        .event("debug-history-3")
        .when(Condition::At {
            at: VirtualTime { ticks: 12_288 },
        })
        .action(Action::log(LogLevel::Info, "debug history boundary 3"))
        .event("debug-history-4")
        .when(Condition::At {
            at: VirtualTime { ticks: 16_384 },
        })
        .action(Action::log(LogLevel::Info, "debug history boundary 4"))
        .build_for_world(&world)?;
    let plan = Plan::from_event_graph_for_world(&world, graph)?;
    let scenario = ScenarioDefForm::from_components(
        &world,
        &plan,
        &Properties::empty(),
        Seed::from_u64(0xd06),
    )?;

    let mut output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    output_file.write_all(scenario.to_canonical_toml()?.as_bytes())?;
    Ok(())
}
