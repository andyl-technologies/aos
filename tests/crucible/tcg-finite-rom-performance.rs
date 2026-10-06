// SPDX-License-Identifier: Apache-2.0
//! Finite, clock-independent ROM throughput with a common serial endpoint.
//!
//! This standalone host fixture reuses only the frozen Linux helper's public
//! protocol, process, QMP and CPU-accounting support. The builder concatenates
//! that unchanged support prefix after this source; no QEMU code is linked.

struct SerialCapture {
    events: std::sync::mpsc::Receiver<std::result::Result<(bool, Instant), String>>,
    worker: Option<thread::JoinHandle<std::io::Result<()>>>,
    shutdown_socket: UnixStream,
}

impl SerialCapture {
    fn connect(path: &Path, log_path: &Path, start: Vec<u8>, end: Vec<u8>) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let socket = loop {
            match UnixStream::connect(path) {
                Ok(socket) => break socket,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Err(error) => return Err(error.into()),
            }
        };
        Self::from_socket(socket, File::create(log_path)?, start, end)
    }

    fn from_socket(
        mut socket: UnixStream,
        mut log: File,
        start: Vec<u8>,
        end: Vec<u8>,
    ) -> Result<Self> {
        let shutdown_socket = socket.try_clone()?;
        let (sender, events) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let mut received = Vec::new();
            let mut seen = [false; 2];
            let mut buffer = [0_u8; 4096];
            loop {
                let length = std::io::Read::read(&mut socket, &mut buffer)?;
                if length == 0 {
                    break;
                }
                let arrival = Instant::now();
                received.extend_from_slice(&buffer[..length]);
                let prefix_length = end
                    .iter()
                    .position(|byte| *byte == b':')
                    .map_or(end.len() - 1, |position| position + 1);
                let prefix = &end[..prefix_length];
                for (offset, bytes) in received.windows(prefix.len()).enumerate() {
                    if bytes == prefix {
                        let remaining = &received[offset + prefix.len()..];
                        if let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') {
                            let candidate = &received[offset..offset + prefix.len() + newline + 1];
                            if candidate != end {
                                let _ =
                                    sender.send(Err("ROM checksum END token mismatch".to_owned()));
                            }
                        }
                    }
                }
                for (index, token) in [&start, &end].into_iter().enumerate() {
                    let count = received
                        .windows(token.len())
                        .filter(|bytes| *bytes == token)
                        .count();
                    if count > 1 {
                        let _ = sender.send(Err("duplicate ROM serial token".to_owned()));
                    } else if count == 1 && !seen[index] {
                        let position = received
                            .windows(token.len())
                            .position(|bytes| bytes == token);
                        let start_position = received
                            .windows(start.len())
                            .position(|bytes| bytes == start);
                        if index == 1 && (!seen[0] || position < start_position) {
                            let _ = sender.send(Err("ROM END precedes START".to_owned()));
                        }
                        seen[index] = true;
                        let _ = sender.send(Ok((index == 1, arrival)));
                    }
                }
                log.write_all(&buffer[..length])?;
                if received.len() > 1024 * 1024 {
                    let _ = sender.send(Err("ROM serial exceeds diagnostic limit".to_owned()));
                    return Err(std::io::Error::other("serial diagnostic limit"));
                }
            }
            if seen != [true, true] {
                let _ = sender.send(Err(
                    "ROM serial closed without exact START/checksum END".to_owned()
                ));
            }
            Ok(())
        });
        Ok(Self {
            events,
            worker: Some(worker),
            shutdown_socket,
        })
    }

    fn poll(&self, start: &mut Option<Instant>, end: &mut Option<Instant>) -> Result<()> {
        while let Ok(event) = self.events.try_recv() {
            let (is_end, arrival) = event.map_err(std::io::Error::other)?;
            let target = if is_end { &mut *end } else { &mut *start };
            if target.replace(arrival).is_some() {
                return Err("duplicate ROM serial token".into());
            }
        }
        Ok(())
    }

    fn finish(mut self, start: &mut Option<Instant>, end: &mut Option<Instant>) -> Result<()> {
        self.worker
            .take()
            .ok_or("serial already joined")?
            .join()
            .map_err(|_| "serial reader panicked")??;
        self.poll(start, end)?;
        if start.is_none() || end.is_none() {
            return Err("missing exact ROM START/checksum END".into());
        }
        Ok(())
    }
}

impl Drop for SerialCapture {
    fn drop(&mut self) {
        let _ = self.shutdown_socket.shutdown(std::net::Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn register_value(registers: &str, name: &str) -> Result<u64> {
    let prefix = format!("{name}=");
    let value = registers
        .split_whitespace()
        .find_map(|field| field.strip_prefix(&prefix))
        .ok_or_else(|| format!("missing register field {name}"))?;
    Ok(u64::from_str_radix(value, 16)?)
}

fn stock_halt_reached(registers: &str, manifest: &Value) -> Result<bool> {
    let checksum = manifest["checksum"].as_u64().ok_or("missing checksum")?;
    let halted = manifest["halted_address"]
        .as_u64()
        .ok_or("missing halt coordinate")?;
    Ok(register_value(registers, "HLT")? == 1
        && register_value(registers, "EIP")? == halted + 2
        && register_value(registers, "EAX")? == checksum
        && register_value(registers, "ECX")? == 0
        && register_value(registers, "ESP")? == 0x6000
        && register_value(registers, "EFL")? & 0x200 == 0)
}

fn rom_command(args: &[String], sockets: &Path, plugin: Option<(&str, i32)>) -> Result<Command> {
    let cpu: usize = args[6].parse()?;
    let log = File::create(Path::new(&args[5]).join("qemu.log"))?;
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
        "64M",
        "-smp",
        "1",
        "-cpu",
        "qemu64,-rdrand,-rdseed",
        "-rtc",
        "base=2026-01-01T00:00:00,clock=vm",
        "-seed",
        "0x0010c004",
        "-bios",
        &args[4],
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
        "tcg" => {
            command.args(["-accel", "tcg,thread=single"]);
        }
        "tcg-icount" => {
            command.args([
                "-accel",
                "tcg,thread=single",
                "-icount",
                "shift=0,align=off,sleep=off",
            ]);
        }
        "sim" => {
            command.args([
                "-accel",
                "sim,thread=single",
                "-icount",
                "shift=0,align=off,sleep=off,rr_switch_quantum=4096",
            ]);
        }
        _ => return Err("mode must be tcg, tcg-icount or sim".into()),
    }
    let inherited_fd = plugin.map(|(_, fd)| fd);
    if let Some((argument, _)) = plugin {
        command.args(["-plugin", argument]);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    // SAFETY: the child hook only sets inherited descriptor flags and affinity.
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

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 8 {
        return Err("usage: DRIVER MODE QEMU PLUGIN_OR_DASH ROM OUTPUT CPU MANIFEST".into());
    }
    let sim = args[1] == "sim";
    if (args[3] == "-") == sim || args[6].parse::<usize>()? >= libc::CPU_SETSIZE as usize {
        return Err("invalid mode/plugin pairing or CPU".into());
    }
    let directory = Path::new(&args[5]);
    fs::create_dir_all(directory)?;
    let manifest: Value = serde_json::from_slice(&fs::read(&args[7])?)?;
    let start_token = manifest["start_token"]
        .as_str()
        .ok_or("missing START token")?
        .as_bytes()
        .to_vec();
    let end_token = manifest["end_token"]
        .as_str()
        .ok_or("missing checksum END token")?
        .as_bytes()
        .to_vec();
    let sockets = tempfile::Builder::new().prefix("crucible-rom-").tempdir()?;
    if sockets.path().join("serial.sock").as_os_str().len() >= 108 {
        return Err("temporary socket path exceeds Unix limit".into());
    }

    // All allocation precedes the primary timer. Even stock rows construct the
    // same public setup objects; only Sim transmits them to its real plugin.
    let allocation = RegionAllocation::new(RegionConfig::new(1, 4))?;
    let layout = allocation.layout();
    let shared = memfd(&allocation.setup_region_bytes()?, false)?;
    let region = mmap_setup_region(shared.as_fd(), layout.region_size)?;
    let slot = region.node_slot(0)?;
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
    // SAFETY: eventfd returns a unique owned descriptor without pointer inputs.
    let wake_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if wake_fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the successful eventfd descriptor has not acquired another owner.
    let wake = unsafe { File::from_raw_fd(wake_fd) };
    let (host_socket, plugin_socket) = UnixStream::pair()?;
    host_socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    let simfd = plugin_socket.as_raw_fd();
    let plugin_argument = format!(
        "{},simfd={simfd},slot=0,fault_node_hash={},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,whitebox=on,whitebox_setup=x86-port-00e7-unclaimed-v1,coverage=off,fingerprint=off",
        args[3],
        "11".repeat(32)
    );
    let mut command = rom_command(
        &args,
        sockets.path(),
        sim.then_some((plugin_argument.as_str(), simfd)),
    )?;
    let launch_start = Instant::now();
    let mut process = Process(command.spawn()?);
    drop(plugin_socket);
    let ceiling = 20_000_000_000_000_u64;
    let _control = if sim {
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
            authorize_advance_ceiling(0, ceiling, None)?,
            AdvanceStopCondition::Ceiling,
        )?;
        Some(control)
    } else {
        None
    };
    let mut qmp = Qmp::connect(&sockets.path().join("qmp.sock"))?;
    let serial = SerialCapture::connect(
        &sockets.path().join("serial.sock"),
        &directory.join("serial.log"),
        start_token,
        end_token,
    )?;
    let cont_start = Instant::now();
    qmp.command("cont", json!({}))?;
    let mut start = None;
    let mut end = None;
    let mut markers = Vec::new();
    let mut registered = false;
    let mut pending = None;
    let expected_registration = SelectableRegister::new(
        1,
        "flight.ready",
        vec![1],
        vec![1],
        vec!["readiness".to_owned()],
    )?;
    let stopped = loop {
        serial.poll(&mut start, &mut end)?;
        if sim {
            let ring = marker_region.whitebox_marker_ring_mut(0)?;
            while let Some(record) = ring.header.dequeue_whitebox_marker(ring.entries)? {
                let entry = record.validate()?;
                markers.push(json!({
                    "kind": entry.kind(),
                    "logical_tick": entry.current_icount(),
                    "vcpu": entry.vcpu_index(),
                    "payload_hex": entry.payload().iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                }));
                if entry.kind() == WHITEBOX_SHMEM_KIND_SELECTABLE_REGISTERED {
                    if registered
                        || SelectableRegister::decode(entry.payload())? != expected_registration
                    {
                        return Err("unexpected ROM registration".into());
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
                        return Err("unexpected ROM authenticated request".into());
                    }
                    pending = Some((request, entry.current_icount()));
                }
            }
            let snapshot = slot.snapshot();
            if let Some((request, tick)) = &pending {
                let raw = request
                    .raw_icount()
                    .checked_add(SELECTABLE_NATIVE_HANDOFF_INSTRUCTIONS)
                    .ok_or("raw overflow")?;
                let logical = tick
                    .checked_add(SELECTABLE_NATIVE_HANDOFF_TICKS_PS)
                    .ok_or("tick overflow")?;
                if snapshot.logical_time_raw_icount > raw || snapshot.current_icount > logical {
                    return Err("ROM ran beyond exact native boundary".into());
                }
                if snapshot.logical_time_raw_icount == raw
                    && snapshot.current_icount == logical
                    && snapshot.status == STATUS_IDLE
                    && snapshot.idle_wake_icount == logical
                    && end.is_some()
                {
                    break Some(snapshot);
                }
            }
        } else if end.is_some() {
            break None;
        }
        if launch_start.elapsed() > Duration::from_secs(300) {
            return Err("ROM completion timeout after 300 seconds".into());
        }
        if process.0.try_wait()?.is_some() {
            return Err("QEMU exited before ROM completion".into());
        }
        thread::sleep(Duration::from_micros(100));
    };
    if !sim {
        // END can arrive before popal and the protocol epilogue retire. Wait
        // for the permanent CLI/HLT tail after recording the primary endpoint;
        // this qualification latency is excluded from both serial intervals.
        let halt_deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let dump = qmp.command(
                "human-monitor-command",
                json!({"command-line":"info registers"}),
            )?;
            if stock_halt_reached(dump.as_str().ok_or("invalid register response")?, &manifest)? {
                break;
            }
            if Instant::now() >= halt_deadline {
                return Err("ROM failed to reach its permanent halt after END".into());
            }
            if process.0.try_wait()?.is_some() {
                return Err("QEMU exited before ROM halt qualification".into());
            }
            thread::sleep(Duration::from_micros(100));
        }
        qmp.command("stop", json!({}))?;
    }
    let pause_deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        let status = qmp.command("query-status", json!({}))?;
        if stopped
            .as_ref()
            .is_some_and(|reference| !same_readiness_state(&slot.snapshot(), reference))
        {
            return Err("ROM native state moved".into());
        }
        if status["status"] == "paused" {
            break status;
        }
        if Instant::now() >= pause_deadline {
            return Err("ROM native pause acknowledgement timeout".into());
        }
        thread::sleep(Duration::from_micros(100));
    };
    let native_stop_seconds = launch_start.elapsed().as_secs_f64();
    let counters = cpu_seconds(process.0.id())?;
    let registers = qmp.command(
        "human-monitor-command",
        json!({"command-line":"info registers"}),
    )?;
    if !sim
        && !stock_halt_reached(
            registers.as_str().ok_or("invalid register response")?,
            &manifest,
        )?
    {
        return Err("stock stopped capture is not the qualified permanent halt".into());
    }
    let replay = if args[1] == "tcg-icount" {
        Some(qmp.command("query-replay", json!({}))?)
    } else {
        None
    };
    let memory_path = directory.join("ram.bin");
    qmp.command(
        "pmemsave",
        json!({"val":0,"size":64*1024*1024,"filename":memory_path}),
    )?;
    let memory = fs::read(&memory_path)?;
    if memory.len() != 64 * 1024 * 1024
        || qmp.command("query-status", json!({}))?["status"] != "paused"
        || stopped
            .as_ref()
            .is_some_and(|reference| !same_readiness_state(&slot.snapshot(), reference))
    {
        return Err("ROM stopped capture changed state".into());
    }
    let record = &memory[0x7000..0x7010];
    let expected = manifest["record_hex"]
        .as_str()
        .ok_or("missing expected record")?;
    let record_hex: String = record.iter().map(|byte| format!("{byte:02x}")).collect();
    if record_hex != expected {
        return Err("ROM checksum/counter/tag mismatch".into());
    }
    qmp.command("quit", json!({}))?;
    if !process.0.wait()?.success() {
        return Err("QEMU unsuccessful exit".into());
    }
    serial.finish(&mut start, &mut end)?;
    let start = start.ok_or("missing ROM START")?;
    let end = end.ok_or("missing ROM END")?;
    let request_witness = pending.as_ref().map(|(request, tick)| {
        json!({
            "sequence": request.request().sequence(),
            "raw_icount": request.raw_icount(),
            "logical_tick": tick,
            "selectable_id": request.request().selectable_id(),
            "instance_key": request.request().instance_key(),
        })
    });
    let saved_registers = sim.then(|| {
        memory[0x5ff8..0x6000]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    });

    println!(
        "{}",
        json!({
            "mode": args[1],
            "qemu": args[2],
            "plugin": sim.then_some(&args[3]),
            "rom": args[4],
            "cpu": args[6].parse::<usize>()?,

            "seconds": end.duration_since(launch_start).as_secs_f64(),
            "startup_seconds": cont_start.duration_since(launch_start).as_secs_f64(),
            "roi_seconds": end.duration_since(start).as_secs_f64(),
            "native_stop_seconds": sim.then_some(native_stop_seconds),
            "roi_scope": "START receipt through checksum END receipt; includes finite loop plus UART epilogue and transport latency",
            "cpu_accounting": "process totals after paused acknowledgement, not exact END or ROI CPU coordinates",
            "user_seconds": counters.0,
            "system_seconds": counters.1,

            "manifest": manifest,
            "record_hex": record_hex,
            "registers": registers,
            "ram_sha256": format!("{:x}", Sha256::digest(&memory)),
            "captured_ram_bytes": 64*1024*1024,
            "status": status,
            "post_marker_stopped_replay": replay,
            "post_marker_icount_is_exact_token_coordinate": false,

            "markers": markers,
            "request": request_witness,
            "raw_icount": stopped.as_ref().map(|state| state.logical_time_raw_icount),
            "logical_tick": stopped.as_ref().map(|state| state.current_icount),
            "idle_wake_tick": stopped.as_ref().map(|state| state.idle_wake_icount),
            "sim_saved_registers_hex": saved_registers,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_reader(bytes: &[u8]) -> Result<()> {
        let (reader, mut writer) = UnixStream::pair()?;
        let log = tempfile::tempfile()?;
        let capture =
            SerialCapture::from_socket(reader, log, b"START\n".to_vec(), b"DONE:1234\n".to_vec())?;
        for byte in bytes {
            writer.write_all(&[*byte])?;
        }
        drop(writer);
        capture.finish(&mut None, &mut None)
    }

    #[test]
    fn split_complete_tokens_are_accepted() {
        assert!(run_reader(b"START\nDONE:1234\n").is_ok());
    }

    #[test]
    fn checksum_mutation_and_partial_end_are_rejected() {
        assert!(run_reader(b"START\nDONE:1235\n").is_err());
        assert!(run_reader(b"START\nDONE:1234").is_err());
    }

    #[test]
    fn duplicate_tokens_and_reversed_order_are_rejected() {
        assert!(run_reader(b"START\nDONE:1234\nDONE:1234\n").is_err());
        assert!(run_reader(b"DONE:1234\nSTART\n").is_err());
    }

    #[test]
    fn early_epilogue_cannot_be_qualified_as_the_permanent_halt() {
        let manifest = json!({"checksum":0x1234,"halted_address":0xf0100});
        let halted = "EAX=00001234 ECX=00000000 ESP=00006000 EIP=000f0102 EFL=00000002 HLT=1";
        assert!(stock_halt_reached(halted, &manifest).unwrap());
        let early = "EAX=00001234 ECX=00000000 ESP=00006000 EIP=000f00f0 EFL=00000002 HLT=0";
        assert!(!stock_halt_reached(early, &manifest).unwrap());
        assert!(!stock_halt_reached(&halted.replace("000f0102", "000f0101"), &manifest).unwrap());
    }
}
