// SPDX-License-Identifier: Apache-2.0
//! Common serial boot milestone with separate Sim deterministic qualification.
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

use crucible_qemu_protocol::app_random_branch_plan::AppRandomBranchPlan;
use crucible_qemu_protocol::plugin_setup_plan::PluginSetupPlan;
use crucible_qemu_protocol::selectable_catalog_plan::{
    SELECTABLE_NATIVE_HANDOFF_INSTRUCTIONS, SELECTABLE_NATIVE_HANDOFF_TICKS_PS,
    SelectableCatalogPlan, SelectablePlanContinuation, SelectablePlanDeclaration,
    SelectablePlanLimits, SelectablePlanPresence,
};
use crucible_qemu_protocol::selectable_transport::{
    SelectablePendingTransportRecord, WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING,
    WHITEBOX_SHMEM_KIND_SELECTABLE_REGISTERED,
};
use crucible_qemu_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlLifecycleStream, HostHandshakeConfig, SelectableRegister,
    SetupDescriptorFds,
};
use crucible_qemu_shmem::{
    ABI_VERSION, AdvanceStopCondition, NodeSlotSnapshot, RegionAllocation, RegionConfig,
    STATUS_IDLE, authorize_advance_ceiling, mmap_setup_region,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Compares semantic readiness coordinates while allowing publication bookkeeping.
fn same_readiness_state(observed: &NodeSlotSnapshot, stopped: &NodeSlotSnapshot) -> bool {
    observed.current_icount == stopped.current_icount
        && observed.current_ns == stopped.current_ns
        && observed.logical_time_raw_icount == stopped.logical_time_raw_icount
        && observed.idle_wake_icount == stopped.idle_wake_icount
        && observed.status == stopped.status
        && observed.virtual_timer_witness == stopped.virtual_timer_witness
}

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

/// Complete common milestone, emitted before the authenticated Sim request.
const SERIAL_MILESTONE: &[u8] = b"\nCRUCIBLE_TCG_BOOT_READY_V1\n";

struct SerialCapture {
    events: std::sync::mpsc::Receiver<std::result::Result<Instant, String>>,
    worker: Option<thread::JoinHandle<std::io::Result<usize>>>,
    shutdown_socket: UnixStream,
}

impl SerialCapture {
    fn connect(path: &Path, log_path: &Path) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut socket = loop {
            match UnixStream::connect(path) {
                Ok(socket) => break socket,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Err(error) => return Err(error.into()),
            }
        };
        let shutdown_socket = socket.try_clone()?;
        let mut log = File::create(log_path)?;
        let (sender, events) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let mut received = Vec::new();
            let mut count = 0;
            let mut buffer = [0_u8; 4096];
            loop {
                let length = match std::io::Read::read(&mut socket, &mut buffer) {
                    Ok(0) => break,
                    Ok(length) => length,
                    Err(error) => {
                        let _ = sender.send(Err(format!("serial transport: {error}")));
                        return Err(error);
                    }
                };
                // Timestamp token completion before log I/O or control work.
                let arrival = Instant::now();
                received.extend_from_slice(&buffer[..length]);
                let observed = received
                    .windows(SERIAL_MILESTONE.len())
                    .filter(|bytes| *bytes == SERIAL_MILESTONE)
                    .count();
                if observed > count {
                    if observed == 1 {
                        let _ = sender.send(Ok(arrival));
                    } else {
                        let _ = sender.send(Err("duplicate complete serial milestone".to_owned()));
                    }
                    count = observed;
                }
                log.write_all(&buffer[..length])?;
                if received.len() > 16 * 1024 * 1024 {
                    let _ = sender.send(Err("serial diagnostic exceeded 16 MiB".to_owned()));
                    return Err(std::io::Error::other("serial diagnostic limit"));
                }
            }
            if count == 0 {
                let _ = sender.send(Err("serial closed before the complete milestone".to_owned()));
            }
            Ok(count)
        });
        Ok(Self {
            events,
            worker: Some(worker),
            shutdown_socket,
        })
    }

    fn poll(&self, marker: &mut Option<Instant>) -> Result<()> {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Ok(arrival) if marker.is_none() => *marker = Some(arrival),
                Ok(_) => return Err("duplicate complete serial milestone".into()),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        let count = self
            .worker
            .take()
            .ok_or("serial worker already joined")?
            .join()
            .map_err(|_| "serial reader panicked")??;
        if count != 1 {
            return Err(format!("expected one complete serial milestone, observed {count}").into());
        }
        Ok(())
    }
}

impl Drop for SerialCapture {
    fn drop(&mut self) {
        // Closing our socket wakes the reader even if QEMU has not exited yet.
        // Join before returning an error so every failed trial retains its log.
        let _ = self.shutdown_socket.shutdown(std::net::Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Uses identical devices and serial transport for ordinary TCG and Sim.
fn build_command(args: &[String], sockets: &Path, plugin: Option<(&str, i32)>) -> Result<Command> {
    let cpu: usize = args[7].parse()?;
    let directory = Path::new(&args[6]);
    let log = File::create(directory.join("qemu.log"))?;
    let mut command = Command::new(&args[2]);
    command.args([
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-monitor",
        "none",
        "-no-reboot",
        "-S",
        "-machine",
        "pc-q35-9.2",
        "-m",
        &format!("{}M", args[8]),
        "-smp",
        "1",
        "-cpu",
        "qemu64,-rdrand,-rdseed",
        "-rtc",
        "base=2026-01-01T00:00:00,clock=vm",
        "-seed",
        "0x0010c004",
        "-kernel",
        &args[4],
        "-initrd",
        &args[5],
        "-append",
        "console=ttyS0 reboot=k panic=1 quiet rdinit=/init",
        "-qmp",
        &format!(
            "unix:{},server=on,wait=off",
            sockets.join("qmp.sock").display()
        ),
        "-chardev",
        &format!(
            "socket,id=serial0,path={},server=on,wait=off",
            sockets.join("serial.sock").display()
        ),
        "-serial",
        "chardev:serial0",
    ]);
    match args[1].as_str() {
        "sim" => {
            command.args([
                "-accel",
                "sim,thread=single",
                "-icount",
                "shift=0,align=off,sleep=off,rr_switch_quantum=4096",
            ]);
        }
        "tcg-icount" => {
            command.args([
                "-accel",
                "tcg,thread=single",
                "-icount",
                "shift=0,align=off,sleep=off",
            ]);
        }
        "tcg" => {
            command.args(["-accel", "tcg,thread=single"]);
        }
        _ => return Err("mode must be sim, tcg, or tcg-icount".into()),
    }
    let inherited_fd = plugin.map(|(_, fd)| fd);
    if let Some((argument, _)) = plugin {
        command.args(["-plugin", argument]);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    // SAFETY: the child hook only changes descriptor flags and its CPU affinity.
    unsafe {
        command.pre_exec(move || {
            if let Some(fd) = inherited_fd {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            let mut affinity: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(cpu, &mut affinity);
            if libc::sched_setaffinity(0, std::mem::size_of_val(&affinity), &affinity) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

fn validate_arguments(args: &[String]) -> Result<()> {
    if args.len() != 9 {
        return Err(
            "usage: driver MODE QEMU PLUGIN_OR_DASH KERNEL INITRD DIRECTORY CPU RAM_MIB".into(),
        );
    }
    let cpu: usize = args[7].parse()?;
    let ram: u64 = args[8].parse()?;
    if cpu >= libc::CPU_SETSIZE as usize || !(64..=512).contains(&ram) {
        return Err("requires a valid CPU and 64..=512 MiB RAM".into());
    }
    match args[1].as_str() {
        "sim" if args[3] != "-" => {}
        "tcg" | "tcg-icount" if args[3] == "-" => {}
        _ => return Err("Sim requires a plugin; ordinary TCG requires PLUGIN_OR_DASH=-".into()),
    }
    fs::create_dir_all(&args[6])?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    validate_arguments(&args)?;
    if args[1] == "sim" {
        run_sim(&args)
    } else {
        run_stock(&args)
    }
}

fn run_stock(args: &[String]) -> Result<()> {
    let directory = Path::new(&args[6]);
    let sockets = tempfile::Builder::new().prefix("tcg-serial-").tempdir()?;
    if sockets.path().join("serial.sock").as_os_str().len() >= 108 {
        return Err("temporary serial socket exceeds Unix path limit".into());
    }
    let mut command = build_command(args, sockets.path(), None)?;
    let launch_start = Instant::now();
    let mut process = Process(command.spawn()?);
    let serial = SerialCapture::connect(
        &sockets.path().join("serial.sock"),
        &directory.join("serial.log"),
    )?;
    let mut qmp = Qmp::connect(&sockets.path().join("qmp.sock"))?;
    let boot_start = Instant::now();
    qmp.command("cont", json!({}))?;
    let mut marker = None;
    let arrival = loop {
        serial.poll(&mut marker)?;
        if let Some(arrival) = marker {
            break arrival;
        }
        if process.0.try_wait()?.is_some() {
            return Err("QEMU exited before complete serial milestone".into());
        }
        if launch_start.elapsed() > Duration::from_secs(300) {
            return Err("serial milestone timeout after 300 seconds".into());
        }
        thread::sleep(Duration::from_micros(100));
    };
    let cpu = cpu_seconds(process.0.id())?;
    // Everything below is diagnostic cleanup after the common timing endpoint.
    // This stock stop cannot identify the exact instruction that emitted the token.
    qmp.command("stop", json!({}))?;
    let status = qmp.command("query-status", json!({}))?;
    let post_marker_replay = if args[1] == "tcg-icount" {
        Some(qmp.command("query-replay", json!({}))?)
    } else {
        None
    };
    qmp.command("quit", json!({}))?;
    if !process.0.wait()?.success() {
        return Err("QEMU did not exit successfully".into());
    }
    serial.finish()?;
    let serial_bytes = fs::read(directory.join("serial.log"))?;
    println!(
        "{}",
        json!({
            "seconds":arrival.duration_since(launch_start).as_secs_f64(),
            "boot_seconds":arrival.duration_since(boot_start).as_secs_f64(),
            "startup_seconds":boot_start.duration_since(launch_start).as_secs_f64(),
            "user_seconds":cpu.0, "system_seconds":cpu.1,
        "cpu_accounting":"QEMU process totals sampled just after serial-token delivery; includes startup; sampling can include subsequent guest work",
            "mode":args[1], "qemu":args[2], "plugin":null,
            "kernel":args[4], "initrd":args[5], "cpu":args[7].parse::<usize>()?,
            "ram_mib":args[8].parse::<u64>()?, "vcpus":1,
            "milestone":"CRUCIBLE_TCG_BOOT_READY_V1", "milestone_count":1,
            "milestone_scope":"complete pre-request serial token; no authenticated stop",
            "serial_sha256":format!("{:x}",Sha256::digest(&serial_bytes)),
            "status_after_marker":status, "post_marker_stopped_replay":post_marker_replay,
            "post_marker_icount_is_exact_token_coordinate":false,
        })
    );
    Ok(())
}

fn run_sim(args: &[String]) -> Result<()> {
    let directory = Path::new(&args[6]);
    let cpu: usize = args[7].parse()?;
    let ram_mib: u64 = args[8].parse()?;
    let fingerprint = "off";
    if cpu >= libc::CPU_SETSIZE as usize || !(64..=512).contains(&ram_mib) {
        return Err("Linux fixture requires a valid CPU and 64..=512 MiB RAM".into());
    }
    if !matches!(fingerprint, "on" | "off") {
        return Err("fingerprint must be on or off".into());
    }
    fs::create_dir_all(directory)?;
    // Store-output paths can exceed Unix socket limits. The private transport
    // lives outside the witness directory and is removed by its TempDir guard.
    let socket_directory = tempfile::Builder::new().prefix("crucible-qmp-").tempdir()?;
    let socket_path = socket_directory.path().join("qmp.sock");
    if socket_directory
        .path()
        .join("serial.sock")
        .as_os_str()
        .len()
        >= 108
    {
        return Err("runtime temporary directory exceeds the Unix QMP socket path limit".into());
    }

    let allocation = RegionAllocation::new(RegionConfig::new(1, 4))?;
    let layout = allocation.layout();
    let shared = memfd(&allocation.setup_region_bytes()?, false)?;
    let region = mmap_setup_region(shared.as_fd(), layout.region_size)?;
    let slot = region.node_slot(0)?;
    // Independent mapping handles keep the immutable slot view disjoint from
    // the host's mutable SPSC marker-consumer view.
    let mut marker_region = mmap_setup_region(shared.as_fd(), layout.region_size)?;
    let declaration = SelectablePlanDeclaration::new(
        "flight.ready",
        vec![1],
        vec![1],
        vec!["readiness".to_owned()],
        SelectablePlanPresence::Required,
    )?;
    let plan = PluginSetupPlan::new(
        AppRandomBranchPlan::default(),
        SelectableCatalogPlan::new(
            SelectablePlanLimits::new(1, 1, 1)?,
            vec![declaration],
            SelectablePlanContinuation::cold(),
        )?,
    );
    let plan_file = memfd(&plan.encode()?, true)?;
    // SAFETY: eventfd returns one unique descriptor without retaining inputs.
    let wake_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wake_raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful eventfd returned one owned descriptor.
    let wake = unsafe { File::from_raw_fd(wake_raw) };
    let (host_socket, plugin_socket) = UnixStream::pair()?;
    host_socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    let simfd = plugin_socket.as_raw_fd();
    // Coverage and fingerprints default to off in QemuLaunchPluginConfig.
    // Readiness requires whitebox on; the optional fingerprint preset is named
    // explicitly and does not silently change the production default preset.
    let plugin_argument = format!(
        "{},simfd={simfd},slot=0,fault_node_hash={},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,coverage=off,fingerprint={fingerprint}",
        args[3],
        "11".repeat(32),
    );
    let mut command = build_command(
        args,
        socket_directory.path(),
        Some((&plugin_argument, simfd)),
    )?;

    // This primary interval includes exec, plugin setup, QMP setup, firmware,
    // kernel decompression and boot, and PID 1's readiness request. Protocol
    // buffer allocation above and the stopped memory capture below are excluded.
    let launch_start = Instant::now();
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
    let initial_ceiling = 20_000_000_000_000_u64;
    let safety_ceiling = 120_000_000_000_000_u64;
    slot.publish_scheduler_advance(
        authorize_advance_ceiling(0, initial_ceiling, None)?,
        AdvanceStopCondition::Ceiling,
    )?;
    let mut qmp = Qmp::connect(&socket_path)?;
    let serial = SerialCapture::connect(
        &socket_directory.path().join("serial.sock"),
        &directory.join("serial.log"),
    )?;
    let before = cpu_seconds(process.0.id())?;
    let boot_start = Instant::now();
    let startup_seconds = boot_start.duration_since(launch_start).as_secs_f64();
    qmp.command("cont", json!({}))?;

    let expected_registration = SelectableRegister::new(
        1,
        "flight.ready",
        vec![1],
        vec![1],
        vec!["readiness".to_owned()],
    )?;
    let mut registered = false;
    let mut pending = None;
    let mut markers = Vec::new();
    let mut advances = vec![initial_ceiling];
    let diagnostics = std::env::var_os("CRUCIBLE_PERFORMANCE_PROGRESS").is_some();
    let mut next_diagnostic = Instant::now() + Duration::from_secs(5);
    let mut serial_marker = None;
    let stopped = loop {
        serial.poll(&mut serial_marker)?;
        let ring = marker_region.whitebox_marker_ring_mut(0)?;
        while let Some(record) = ring.header.dequeue_whitebox_marker(ring.entries)? {
            let entry = record.validate()?;
            markers.push(json!({
                "kind":entry.kind(), "logical_tick":entry.current_icount(),
                "vcpu":entry.vcpu_index(),
                "payload_hex":entry.payload().iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
            }));
            if entry.kind() == WHITEBOX_SHMEM_KIND_SELECTABLE_REGISTERED {
                if registered
                    || SelectableRegister::decode(entry.payload())? != expected_registration
                {
                    return Err("unexpected readiness registration".into());
                }
                registered = true;
            } else if entry.kind() == WHITEBOX_SHMEM_KIND_SELECTABLE_PENDING {
                let request = SelectablePendingTransportRecord::decode(entry.payload())?;
                if !registered
                    || pending.is_some()
                    || request.request().selectable_id() != "flight.ready"
                    || request.request().instance_key() != "boot"
                    || request.request().sequence() != 2
                    || entry.vcpu_index() != 0
                {
                    return Err("unexpected authenticated readiness request".into());
                }
                pending = Some((request, entry.current_icount()));
            }
        }
        let snapshot = slot.snapshot();
        if diagnostics && Instant::now() >= next_diagnostic {
            // QMP commands can wake the main loop and perturb a stalled native
            // timer handoff. Progress diagnostics read only public shared memory.
            eprintln!("Linux boot: {snapshot:?}");
            next_diagnostic = Instant::now() + Duration::from_secs(5);
        }
        if let Some((request, request_tick)) = &pending {
            let expected_raw = request
                .raw_icount()
                .checked_add(SELECTABLE_NATIVE_HANDOFF_INSTRUCTIONS)
                .ok_or("readiness raw count overflow")?;
            let expected_tick = request_tick
                .checked_add(SELECTABLE_NATIVE_HANDOFF_TICKS_PS)
                .ok_or("readiness logical tick overflow")?;
            if snapshot.logical_time_raw_icount > expected_raw
                || snapshot.current_icount > expected_tick
            {
                return Err("guest ran beyond the authenticated readiness boundary".into());
            }
            if snapshot.logical_time_raw_icount == expected_raw
                && snapshot.current_icount == expected_tick
                && snapshot.status == STATUS_IDLE
                && snapshot.idle_wake_icount == expected_tick
                && serial_marker.is_some()
            {
                break snapshot;
            }
        } else if snapshot.status == STATUS_IDLE
            && snapshot.idle_wake_icount > snapshot.max_advance_icount
        {
            // Only authenticated timer idleness permits another grant. A
            // retained selectable request never receives a reply or a resume.
            let next = snapshot
                .idle_wake_icount
                .checked_add(initial_ceiling)
                .ok_or("boot timer ceiling overflow")?
                .min(safety_ceiling);
            if next <= snapshot.max_advance_icount || next < snapshot.idle_wake_icount {
                return Err("Linux boot exceeded the virtual-time safety limit".into());
            }
            slot.publish_scheduler_advance(
                authorize_advance_ceiling(snapshot.current_icount, next, None)?,
                AdvanceStopCondition::Ceiling,
            )?;
            advances.push(next);
        }
        if launch_start.elapsed() > Duration::from_secs(300) {
            return Err(format!("Linux readiness timeout: {snapshot:?}").into());
        }
        if process.0.try_wait()?.is_some() {
            return Err(
                "QEMU exited before authenticated readiness; inspect serial.log and qemu.log"
                    .into(),
            );
        }
        thread::sleep(Duration::from_micros(100));
    };
    // Slot publication precedes the main loop's deferred native VMStop. Count
    // that acknowledgement latency and wait without forcing a wall-time stop.
    let native_stop_deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        let status = qmp.command("query-status", json!({}))?;
        let observed = slot.snapshot();
        if !same_readiness_state(&observed, &stopped) {
            return Err("readiness moved before native VMStop acknowledgement".into());
        }
        if status["status"] == "paused" {
            break status;
        }
        if Instant::now() >= native_stop_deadline {
            return Err("readiness did not acknowledge its native paused boundary".into());
        }
        thread::sleep(Duration::from_micros(100));
    };
    let native_stop_seconds = launch_start.elapsed().as_secs_f64();
    let arrival = serial_marker.ok_or("native readiness lacked the shared serial milestone")?;
    let seconds = arrival.duration_since(launch_start).as_secs_f64();
    let boot_seconds = arrival.duration_since(boot_start).as_secs_f64();
    let after = cpu_seconds(process.0.id())?;
    // This schema manifest identifies every modeled device projection. The
    // default-off fingerprint preset intentionally does not allocate the
    // plugin capture worker; the manifest is not a device-state fingerprint.
    let device_projection_manifest =
        qmp.command("query-crucible-fingerprint-projection-manifest", json!({}))?;
    let registers = qmp.command(
        "human-monitor-command",
        json!({"command-line":"info registers"}),
    )?;
    let ram_bytes = ram_mib
        .checked_mul(1024 * 1024)
        .ok_or("RAM length overflow")?;
    let ram_path = directory.join("ram.bin");
    qmp.command(
        "pmemsave",
        json!({"val":0,"size":ram_bytes,"filename":ram_path}),
    )?;
    let ram = fs::read(&ram_path)?;
    let capture_status = qmp.command("query-status", json!({}))?;
    if ram.len() as u64 != ram_bytes
        || !same_readiness_state(&slot.snapshot(), &stopped)
        || capture_status["status"] != "paused"
    {
        return Err("stopped RAM capture changed its witness".into());
    }
    qmp.command("quit", json!({}))?;
    if !process.0.wait()?.success() {
        return Err("QEMU did not exit successfully".into());
    }
    serial.finish()?;
    let serial_bytes = fs::read(directory.join("serial.log"))?;
    println!(
        "{}",
        json!({
            "seconds": seconds,
            "native_stop_seconds": native_stop_seconds,
            "mode": "sim",
            "cpu_accounting": "QEMU process totals after native paused acknowledgement; includes startup; not exact serial-token CPU coordinate",
            "milestone": "CRUCIBLE_TCG_BOOT_READY_V1",
            "milestone_count": 1,
            "milestone_scope": "complete pre-request serial token; authenticated stop qualified separately",
            "boot_seconds": boot_seconds,
            "startup_seconds": startup_seconds,
            "user_seconds": after.0,
            "system_seconds": after.1,
            "boot_user_seconds": after.0-before.0,
            "boot_system_seconds": after.1-before.1,
            "raw_icount": stopped.logical_time_raw_icount,
            "logical_tick": stopped.current_icount,
            "idle_wake_tick": stopped.idle_wake_icount,
            "registers": registers,
            "timer_witness": stopped.virtual_timer_witness.map(|witness| json!({
                "generation": witness.generation,
                "deadline_ps": witness.deadline_ps,
                "deadline_tick": witness.deadline_tick,
                "armed_raw_icount": witness.armed_raw_icount,
                "fired_expire_ps": witness.fired_expire_ps,
                "fired_virtual_ps": witness.fired_virtual_ps,
                "fired_raw_icount": witness.fired_raw_icount,
                "completed": witness.completed,
                "reserved": witness.reserved,
            })),
            "device_projection_manifest": device_projection_manifest,
            "ram_sha256": format!("{:x}",Sha256::digest(&ram)),
            "ram_bytes": ram_bytes,
            "serial_sha256": format!("{:x}",Sha256::digest(&serial_bytes)),
            "markers": markers,
            "advances": advances,
            "status": status,
            "qemu": args[2],
            "plugin": args[3],
            "kernel": args[4],
            "initrd": args[5],
            "cpu": cpu,
            "ram_mib": ram_mib,
            "coverage": "off",
            "fingerprint": fingerprint,
            "whitebox": "on",
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn capture(chunks: Vec<Vec<u8>>) -> (SerialCapture, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("serial.sock");
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            for chunk in chunks {
                socket.write_all(&chunk).unwrap();
                thread::sleep(Duration::from_millis(1));
            }
        });
        let capture = SerialCapture::connect(&path, &directory.path().join("serial.log")).unwrap();
        (capture, directory)
    }

    #[test]
    fn complete_marker_survives_split_socket_reads() {
        let (capture, directory) = capture(vec![
            b"kernel diagnostics".to_vec(),
            SERIAL_MILESTONE[..7].to_vec(),
            SERIAL_MILESTONE[7..].to_vec(),
        ]);
        let event = capture.events.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(event.is_ok());
        capture.finish().unwrap();
        assert!(
            fs::read(directory.path().join("serial.log"))
                .unwrap()
                .ends_with(SERIAL_MILESTONE)
        );
    }

    #[test]
    fn partial_marker_and_boot_text_never_succeed() {
        for bytes in [
            SERIAL_MILESTONE[..SERIAL_MILESTONE.len() - 1].to_vec(),
            b"Linux boot ready: CRUCIBLE_TCG_BOOT_READY_V1".to_vec(),
        ] {
            let (capture, _directory) = capture(vec![bytes]);
            assert!(
                capture
                    .events
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .is_err()
            );
            assert!(capture.finish().is_err());
        }
    }

    #[test]
    fn duplicate_marker_is_rejected_after_first_arrival() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("serial.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (release, ready) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.write_all(SERIAL_MILESTONE).unwrap();
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            socket.write_all(SERIAL_MILESTONE).unwrap();
        });
        let capture = SerialCapture::connect(&path, &directory.path().join("serial.log")).unwrap();
        assert!(
            capture
                .events
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .is_ok()
        );
        release.send(()).unwrap();
        assert!(
            capture
                .events
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .is_err()
        );
        assert!(capture.finish().is_err());
    }

    #[test]
    fn error_cleanup_flushes_logs_without_waiting_for_emulator_exit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("serial.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.write_all(b"partial diagnostic").unwrap();
            let mut byte = [0];
            assert_eq!(std::io::Read::read(&mut socket, &mut byte).unwrap(), 0);
        });
        let capture = SerialCapture::connect(&path, &directory.path().join("serial.log")).unwrap();
        thread::sleep(Duration::from_millis(10));
        drop(capture);
        worker.join().unwrap();
        assert_eq!(
            fs::read(directory.path().join("serial.log")).unwrap(),
            b"partial diagnostic"
        );
    }
}
