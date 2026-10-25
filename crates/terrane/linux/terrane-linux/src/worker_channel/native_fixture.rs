//! Qualifies actual message credentials and descriptor custody in a dedicated guest.
//!
//! Root launches distinct unprivileged children. This transport-only component
//! exercises the private socket layer; it grants no repository authorization,
//! exposure lease, production worker sandbox or FUSE mount acceptance.

/// Orders a genuine prepared grant behind an actual durable drain transition.
pub mod scoped;

use super::{
    BackingRequest, ExposureContext, RequestedBacking, WorkerClient, WorkerIdentity,
    socket::Endpoint,
};
use rustix::net::{
    self, RecvAncillaryBuffer, RecvAncillaryMessage, SendAncillaryBuffer, SendAncillaryMessage,
};
use std::{
    error::Error,
    fs::{self, File},
    io::{self, IoSlice, IoSliceMut, Read, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
const WORKER_UID: u32 = 848;
const BODY: &[u8] = b"original sealed descriptor through actual worker channel";

struct ChildCustody(Child);

impl Drop for ChildCustody {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn packet() -> Result<Vec<u8>> {
    packet_sequence(1)
}

fn packet_sequence(sequence: u64) -> Result<Vec<u8>> {
    Ok(BackingRequest::new(
        ExposureContext::new("0123456789abcdef0123456789abcdef", 1, [3; 32])?,
        sequence,
        RequestedBacking::Index,
    )?
    .encode())
}

fn launch(setpriv: &Path, mode: &str, input: Stdio) -> Result<ChildCustody> {
    Ok(ChildCustody(
        Command::new(setpriv)
            .args([
                "--reuid=848",
                "--regid=848",
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
            ])
            .arg(std::env::current_exe()?)
            .args(["--worker", mode])
            .stdin(input)
            .stdout(Stdio::piped())
            .spawn()?,
    ))
}

// This clock only bounds the dedicated native proof, never repository state.
#[allow(clippy::disallowed_methods)]
fn receive(endpoint: &Endpoint) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match endpoint.receive() {
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

fn descriptors() -> io::Result<usize> {
    Ok(fs::read_dir("/proc/self/fd")?
        .collect::<io::Result<Vec<_>>>()?
        .len())
}

fn exercise(setpriv: &Path, file: &File, unsealed: &Path, mode: &str) -> Result {
    let (server, worker) = super::channel_pair()?;
    let mut child = launch(setpriv, mode, Stdio::from(worker))?;
    let mut unrelated = if mode == "wrong-pid" {
        Some(launch(setpriv, "idle", Stdio::piped())?)
    } else {
        None
    };
    let expected = unrelated
        .as_mut()
        .map_or(&mut child.0, |other| &mut other.0);
    let uid = if mode == "wrong-uid" {
        WORKER_UID + 1
    } else {
        WORKER_UID
    };
    let identity = WorkerIdentity::from_child(expected, uid)?;
    let endpoint = Endpoint::new(server, identity)?;
    let before = descriptors()?;
    let request = receive(&endpoint);
    if mode == "valid" || mode.starts_with("reply-") {
        if request? != packet()? {
            return Err("actual authenticated request differs from original packet".into());
        }
        send_reply(&endpoint, file, unsealed, mode)?;
        if mode == "valid" {
            let second = packet_sequence(2)?;
            if receive(&endpoint)? != second {
                return Err("worker client did not advance the acknowledged sequence".into());
            }
            endpoint.send(&second, file.as_fd())?;
            let third = packet_sequence(3)?;
            if receive(&endpoint)? != third {
                return Err("worker index request lost its original channel sequence".into());
            }
            // This authenticated inode is sealed, but its bytes are not an index.
            endpoint.send(&third, file.as_fd())?;
        }
    } else {
        let error = request
            .err()
            .ok_or("invalid native worker request accepted")?;
        if error.kind() != io::ErrorKind::PermissionDenied || descriptors()? != before {
            return Err(
                "worker refusal lost credential checks or leaked received descriptors".into(),
            );
        }
        endpoint.abort();
    }
    if !child.0.wait()?.success() {
        return Err("native worker child failed".into());
    }
    let mut output = String::new();
    child
        .0
        .stdout
        .take()
        .ok_or("worker stdout absent")?
        .read_to_string(&mut output)?;
    if mode == "valid" {
        let metadata = file.metadata()?;
        if output != format!("ORIGINAL {} {}\n", metadata.dev(), metadata.ino()) {
            return Err("worker received another inode incarnation".into());
        }
    } else if output != "REFUSED\n" {
        return Err("worker refusal delivered bytes or descriptors".into());
    }
    Ok(())
}

fn send_reply(endpoint: &Endpoint, original: &File, unsealed: &Path, mode: &str) -> Result {
    if mode == "valid" || mode == "reply-wrong-uid" {
        endpoint.send(&packet()?, original.as_fd())?;
        return Ok(());
    }
    if mode == "reply-eof" {
        endpoint.abort();
        return Ok(());
    }
    let mut bytes = packet()?;
    if mode == "reply-sequence" {
        bytes[32] = 2;
    }
    if mode == "reply-hash" {
        bytes[40] ^= 1;
    }
    if mode == "reply-truncated" {
        bytes.resize(super::wire::MAX_PACKET + 1, 0);
    }

    let alternate = if mode == "reply-unsealed" || mode == "reply-writable" {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(mode == "reply-writable");
        Some(options.open(unsealed)?)
    } else if mode == "reply-directory" {
        Some(File::open("/")?)
    } else {
        None
    };
    let descriptor = alternate.as_ref().unwrap_or(original).as_fd();
    let rights = [descriptor; 253];
    let count = match mode {
        "reply-no-fd" => 0,
        "reply-extra-fd" => 253,
        _ => 1,
    };
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if count != 0 && !ancillary.push(SendAncillaryMessage::ScmRights(&rights[..count])) {
        return Err("fixture cannot construct reply rights".into());
    }
    if net::sendmsg(
        endpoint,
        &[IoSlice::new(&bytes)],
        &mut ancillary,
        net::SendFlags::NOSIGNAL,
    )? != bytes.len()
    {
        return Err("fixture reply send truncated".into());
    }
    Ok(())
}

fn client_worker(socket: OwnedFd, mode: &str) -> Result {
    let expected_uid = u32::from(mode == "reply-wrong-uid");
    let context = ExposureContext::new("0123456789abcdef0123456789abcdef", 1, [3; 32])?;
    let mut client = WorkerClient::bind(socket, context, expected_uid)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if mode == "valid" {
        let mut first_inode = None;
        for sequence in 1..=2 {
            let reply = if sequence == 1 {
                runtime.block_on(
                    client.request_bounded(RequestedBacking::Index, Duration::from_secs(5)),
                )?
            } else {
                let mut pending = client.request(RequestedBacking::Index)?;
                let reply = receive_client(&mut pending)?;
                if pending.receive().is_ok() {
                    return Err("worker client accepted repeated completion".into());
                }
                reply
            };
            let backing =
                crate::fuse_read::Backing::from_reply(reply, BODY.len() as u64, BODY.len() as u32)?;
            rustix::fs::seek(&backing, rustix::fs::SeekFrom::Start(3))?;
            let mut bytes = vec![0; BODY.len()];
            let length = backing.read(0, BODY.len() as u32, &mut bytes)?;
            let metadata = rustix::fs::fstat(&backing)?;
            if length != BODY.len() || bytes != BODY || metadata.st_size as u64 != BODY.len() as u64
            {
                return Err("worker client read another original body".into());
            }
            bytes.fill(0xaa);
            let length = backing.read(BODY.len() as u64 - 2, BODY.len() as u32, &mut bytes)?;
            if length != 2
                || bytes[..2] != BODY[BODY.len() - 2..]
                || bytes[2..].iter().any(|byte| *byte != 0xaa)
                || backing.read(u64::MAX, 1, &mut [])? != 0
                || rustix::fs::seek(&backing, rustix::fs::SeekFrom::Current(0))? != 3
            {
                return Err("fallback read changed cursor, EOF or untouched output".into());
            }
            bytes.fill(0xaa);
            if !matches!(
                backing.read(0, BODY.len() as u32 + 1, &mut bytes),
                Err(crate::fuse_read::Error::Limit)
            ) || bytes.iter().any(|byte| *byte != 0xaa)
            {
                return Err(
                    "fallback read accepted oversized work or mutated refused output".into(),
                );
            }
            let inode = (metadata.st_dev, metadata.st_ino);
            if first_inode.is_some_and(|first| first != inode) {
                return Err("bounded and manual worker requests received different inodes".into());
            }
            first_inode = Some(inode);
            if sequence == 2 {
                println!("ORIGINAL {} {}", metadata.st_dev, metadata.st_ino);
            }
        }
        let before = descriptors()?;
        let result = runtime.block_on(client.request_index_bounded(65536, Duration::from_secs(5)));
        if !matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData)
            || descriptors()? != before
            || client.request(RequestedBacking::Index).is_ok()
        {
            return Err("invalid sealed index retained a descriptor or usable channel".into());
        }
        eprintln!(
            "PASS authenticated sealed non-index reply closes the refused descriptor and faults its original channel"
        );
        return Ok(());
    }
    let before = descriptors()?;
    let result =
        runtime.block_on(client.request_bounded(RequestedBacking::Index, Duration::from_secs(5)));
    let error = result.err().ok_or("worker client accepted invalid reply")?;
    let expected_kind = match mode {
        "reply-no-fd" | "reply-writable" | "reply-directory" => io::ErrorKind::InvalidData,
        "reply-unsealed" => {
            if error.raw_os_error() != Some(rustix::io::Errno::NODATA.raw_os_error()) {
                return Err("worker client did not reach actual unsealed-file refusal".into());
            }
            error.kind()
        }
        _ => io::ErrorKind::PermissionDenied,
    };
    if error.kind() != expected_kind || descriptors()? != before {
        return Err("worker client accepted invalid reply or leaked descriptors".into());
    }
    if client.request(RequestedBacking::Index).is_ok() {
        return Err("worker client reused a faulted channel".into());
    }
    println!("REFUSED");
    Ok(())
}

// Only the dedicated native proof uses a wall clock to bound its child.
#[allow(clippy::disallowed_methods)]
fn receive_client(pending: &mut super::PendingBacking<'_>) -> io::Result<super::BackingReply> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match pending.receive() {
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

fn worker(mode: &str) -> Result {
    if rustix::process::geteuid().as_raw() != WORKER_UID {
        return Err("worker fixture did not enter its independent identity".into());
    }
    if mode == "idle" {
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte)?;
        return Ok(());
    }
    let socket = std::io::stdin().as_fd().try_clone_to_owned()?;
    if mode == "valid" || mode.starts_with("reply-") {
        return client_worker(socket, mode);
    }
    let bytes = if mode == "truncated" {
        vec![0; super::wire::MAX_PACKET + 1]
    } else {
        packet()?
    };
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let input = File::open("/dev/null")?;
    let rights = [input.as_fd(); 253];
    if mode == "rights" && !ancillary.push(SendAncillaryMessage::ScmRights(&rights)) {
        return Err("fixture cannot construct complete Linux rights limit".into());
    }
    if net::sendmsg(
        &socket,
        &[IoSlice::new(&bytes)],
        &mut ancillary,
        net::SendFlags::NOSIGNAL,
    )? != bytes.len()
    {
        return Err("fixture worker send truncated".into());
    }

    let mut reply = [0; super::wire::MAX_PACKET];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = net::recvmsg(
        &socket,
        &mut [IoSliceMut::new(&mut reply)],
        &mut ancillary,
        net::RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut files: Vec<OwnedFd> = Vec::new();
    for field in ancillary.drain() {
        match field {
            RecvAncillaryMessage::ScmRights(rights) => files.extend(rights),
            _ => return Err("unexpected worker response ancillary data".into()),
        }
    }
    if mode != "valid" {
        if received.bytes != 0 || !files.is_empty() {
            return Err("rejected worker received a disclosure".into());
        }
        println!("REFUSED");
        return Ok(());
    }
    if received
        .flags
        .intersects(net::ReturnFlags::TRUNC | net::ReturnFlags::CTRUNC)
        || reply[..received.bytes] != packet()?
        || files.len() != 1
    {
        return Err("worker received a malformed descriptor response".into());
    }
    let descriptor = files.pop().ok_or("missing actual original backing")?;
    let flags = rustix::fs::fcntl_getfl(&descriptor)?;
    if flags.intersects(
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH,
    ) {
        return Err("worker backing is not read-only".into());
    }
    let mut file = File::from(descriptor);
    crate::verity::measure(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes != BODY {
        return Err("worker read another original sealed body".into());
    }
    let metadata = file.metadata()?;
    println!("ORIGINAL {} {}", metadata.dev(), metadata.ino());
    Ok(())
}

/// Runs the explicitly privileged transport proof or its unprivileged child.
///
/// # Errors
/// Rejects missing native inputs, wrong identities, absent kernel seal support,
/// failed credential/descriptor controls and native child-process failures.
pub fn run() -> Result {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.first().is_some_and(|value| value == "--worker") {
        return worker(
            arguments
                .get(1)
                .and_then(|value| value.to_str())
                .ok_or("missing worker mode")?,
        );
    }
    if rustix::process::geteuid().as_raw() != 0 || arguments.len() != 2 {
        return Err(
            "transport proof requires root, a private ext4 directory and AOS setpriv".into(),
        );
    }
    let directory = Path::new(&arguments[0]);
    let path = directory.join("backing");
    let mut writer = File::create_new(&path)?;
    writer.write_all(BODY)?;
    writer.sync_all()?;
    drop(writer);
    let file = File::open(&path)?;
    crate::verity::enable(&file)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    File::open(directory)?.sync_all()?;
    let unsealed = directory.join("unsealed");
    let mut ordinary = File::create_new(&unsealed)?;
    ordinary.write_all(BODY)?;
    ordinary.sync_all()?;
    drop(ordinary);
    for mode in [
        "valid",
        "wrong-uid",
        "wrong-pid",
        "rights",
        "truncated",
        "reply-wrong-uid",
        "reply-sequence",
        "reply-hash",
        "reply-truncated",
        "reply-no-fd",
        "reply-extra-fd",
        "reply-unsealed",
        "reply-writable",
        "reply-directory",
        "reply-eof",
    ] {
        exercise(Path::new(&arguments[1]), &file, &unsealed, mode)?;
        println!("PASS actual worker seqpacket transport: {mode}");
    }
    println!(
        "PASS native worker transport component; scoped authorization and production worker remain separately qualified"
    );
    Ok(())
}
