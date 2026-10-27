// SPDX-License-Identifier: Apache-2.0
//! Common serial boot milestone with separate Sim deterministic qualification.
//!
//! Ordinary TCG controls retain their original raw launch and serial endpoints.
//! Sim dispatches to the isolated accepted-worker runner with full native RAM
//! admission, original supervision, and actual cleanup custody.

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[path = "tcg-managed-performance.rs"]
mod managed;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Reaps the ordinary control process when its measurement scope closes.
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

/// Preserves the ordinary TCG control's original devices and serial transport.
fn build_command(args: &[String], sockets: &Path) -> Result<Command> {
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
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    // SAFETY: the child hook only changes descriptor flags and its CPU affinity.
    unsafe {
        command.pre_exec(move || {
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
        managed::run("linux", &args)
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
    let mut command = build_command(args, sockets.path())?;
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
