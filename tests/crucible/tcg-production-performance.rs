// SPDX-License-Identifier: Apache-2.0
//! Real-plugin protocol and deterministic-boundary benchmark fixture.
//!
//! This host fixture uses only the public socket and shared-memory protocols.
//! It starts QEMU directly for local performance measurements, without the
//! production launcher's filesystem and cgroup isolation. It never links QEMU.

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crucible_protocol::app_random_branch_plan::AppRandomBranchPlan;
use crucible_protocol::plugin_setup_plan::PluginSetupPlan;
use crucible_protocol::selectable_catalog_plan::{
    SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanLimits,
};
use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlLifecycleStream, HostHandshakeConfig, SetupDescriptorFds,
};
use crucible_shmem::{
    ABI_VERSION, AdvanceStopCondition, RegionAllocation, RegionConfig, TICKS_PER_INSTRUCTION,
    authorize_advance_ceiling, mmap_setup_region,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn memfd(bytes: &[u8], immutable: bool) -> Result<File> {
    // SAFETY: the name is NUL-terminated and the resulting descriptor is uniquely owned.
    let fd = unsafe {
        libc::memfd_create(
            c"crucible-production-performance".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: memfd_create returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.set_len(bytes.len() as u64)?;
    file.write_all(bytes)?;
    let mut seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;
    if immutable {
        seals |= libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    }
    // SAFETY: fd is live and the seals are the reviewed public protocol policy.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Qmp {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Qmp {
    fn connect(path: &Path) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let socket = loop {
            match UnixStream::connect(path) {
                Ok(socket) => break socket,
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut qmp = Self {
            reader: BufReader::new(socket.try_clone()?),
            writer: socket,
        };
        qmp.read()?;
        qmp.command("qmp_capabilities", json!({}))?;
        Ok(qmp)
    }

    fn read(&mut self) -> Result<Value> {
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                return Err("QMP closed".into());
            }
            let message: Value = serde_json::from_str(&line)?;
            if message.get("event").is_none() {
                return Ok(message);
            }
        }
    }

    fn command(&mut self, command: &str, arguments: Value) -> Result<Value> {
        writeln!(
            self.writer,
            "{}",
            json!({"execute": command, "arguments": arguments})
        )?;
        let response = self.read()?;
        if let Some(error) = response.get("error") {
            return Err(format!("QMP {command}: {error}").into());
        }
        Ok(response["return"].clone())
    }
}

fn cpu_seconds(pid: u32) -> Result<(f64, f64)> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = text
        .rsplit_once(')')
        .ok_or("invalid proc stat")?
        .1
        .split_whitespace()
        .collect();
    // SAFETY: sysconf has no pointer inputs or retained state.
    let frequency = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    Ok((
        fields[11].parse::<f64>()? / frequency,
        fields[12].parse::<f64>()? / frequency,
    ))
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 {
        return Err("usage: driver QEMU PLUGIN BIOS RAW_HORIZON OUTPUT_DIRECTORY CPU".into());
    }
    let target_raw: u64 = args[4].parse()?;
    let target_ticks = target_raw
        .checked_mul(TICKS_PER_INSTRUCTION)
        .ok_or("horizon overflow")?;
    let directory = Path::new(&args[5]);
    fs::create_dir_all(directory)?;
    let socket_path = directory.join("qmp.sock");
    let _ = fs::remove_file(&socket_path);

    let allocation = RegionAllocation::new(RegionConfig::new(1, 4))?;
    let layout = allocation.layout();
    let shared = memfd(&allocation.setup_region_bytes()?, false)?;
    let region = mmap_setup_region(shared.as_fd(), layout.region_size)?;
    let slot = region.node_slot(0)?;
    let plan = PluginSetupPlan::new(
        AppRandomBranchPlan::default(),
        SelectableCatalogPlan::new(
            SelectablePlanLimits::new(1, 1, 1)?,
            Vec::new(),
            SelectablePlanContinuation::cold(),
        )?,
    );
    let plan_file = memfd(&plan.encode()?, true)?;
    // SAFETY: eventfd takes a value and flags and returns a unique owned descriptor.
    let wake_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wake_raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful eventfd returned one owned descriptor.
    let wake = unsafe { File::from_raw_fd(wake_raw) };
    let (host_socket, plugin_socket) = UnixStream::pair()?;
    host_socket.set_read_timeout(Some(Duration::from_secs(20)))?;
    let simfd = plugin_socket.as_raw_fd();
    let cpu: usize = args[6].parse()?;
    if cpu >= libc::CPU_SETSIZE as usize {
        return Err("CPU exceeds affinity set size".into());
    }
    let plugin_argument = format!(
        "{},simfd={simfd},slot=0,fault_node_hash={},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,whitebox=off,coverage=off,fingerprint=off",
        args[2],
        "11".repeat(32)
    );
    let log = File::create(directory.join("qemu.log"))?;
    let mut command = Command::new(&args[1]);
    command.args([
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "none",
        "-no-reboot",
        "-S",
        "-machine",
        "pc",
        "-m",
        "64M",
        "-smp",
        "1",
        "-accel",
        "sim,thread=single",
        "-icount",
        "shift=0,align=off,sleep=off,rr_switch_quantum=4096",
        "-cpu",
        "qemu64,-rdrand,-rdseed",
        "-rtc",
        "base=2026-01-01T00:00:00,clock=vm",
        "-seed",
        "0x0010c004",
        "-bios",
        &args[3],
        "-plugin",
        &plugin_argument,
        "-qmp",
        &format!("unix:{},server=on,wait=off", socket_path.display()),
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    // SAFETY: the child hook only adjusts descriptor flags and CPU affinity through libc.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(simfd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut affinity: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(cpu, &mut affinity);
            if libc::sched_setaffinity(0, std::mem::size_of_val(&affinity), &affinity) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut process = Process(command.spawn()?);
    drop(plugin_socket);

    let mut control = ControlLifecycleStream::connected_unix_stream(host_socket)?;
    control.host_accept_handshake(HostHandshakeConfig {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: ABI_VERSION,
        slot_index: 0,
        node_count: layout.node_count,
    })?;
    control.host_send_setup_with_descriptors(
        layout.region_size,
        SetupDescriptorFds {
            shmem_fd: shared.as_raw_fd(),
            wake_fd: wake.as_raw_fd(),
            plugin_setup_plan_fd: plan_file.as_raw_fd(),
        },
    )?;
    control.host_accept_setup_ack()?;
    control.enter_run_via_shared_memory()?;
    slot.publish_scheduler_advance(
        authorize_advance_ceiling(0, target_ticks, None)?,
        AdvanceStopCondition::Ceiling,
    )?;

    let mut qmp = Qmp::connect(&socket_path)?;
    let before = cpu_seconds(process.0.id())?;
    let start = Instant::now();
    qmp.command("cont", json!({}))?;
    loop {
        let current = slot.snapshot().current_icount;
        if current == target_ticks {
            break;
        }
        if current > target_ticks {
            return Err(format!("ceiling overshoot {current}>{target_ticks}").into());
        }
        if start.elapsed() > Duration::from_secs(120) {
            return Err(format!("horizon timeout at {current}/{target_ticks}").into());
        }
        if process.0.try_wait()?.is_some() {
            return Err("QEMU exited before horizon".into());
        }
        thread::sleep(Duration::from_micros(100));
    }
    let elapsed = start.elapsed().as_secs_f64();
    let after = cpu_seconds(process.0.id())?;
    qmp.command("stop", json!({}))?;
    let registers = qmp.command(
        "human-monitor-command",
        json!({"command-line":"info registers"}),
    )?;
    let ram_path = directory.join("ram.bin");
    qmp.command(
        "pmemsave",
        json!({"val":0x7000, "size":256, "filename":ram_path}),
    )?;
    let ram = fs::read(ram_path)?;
    let status = qmp.command("query-status", json!({}))?;
    if status["status"] != "paused" {
        return Err("QEMU did not pause at the grant ceiling".into());
    }
    let final_ticks = slot.snapshot().current_icount;
    if final_ticks != target_ticks {
        return Err("horizon moved while paused".into());
    }
    qmp.command("quit", json!({}))?;
    if !process.0.wait()?.success() {
        return Err("QEMU did not exit successfully".into());
    }
    println!(
        "{}",
        json!({"seconds":elapsed,"user_seconds":after.0-before.0,"system_seconds":after.1-before.1,"raw_icount":target_raw,"logical_tick":final_ticks,"registers":registers,"ram_sha256":format!("{:x}",Sha256::digest(&ram)),"ram_prefix_hex":ram[..8].iter().map(|byte|format!("{byte:02x}")).collect::<String>(),"status":status,"qemu":args[1],"plugin":args[2],"bios":args[3],"cpu":cpu})
    );
    Ok(())
}
