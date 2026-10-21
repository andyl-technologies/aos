//! Runs the fixed SourceProvider owner for one installed recovery VM cut.
//!
//! The fixture owns a correctly configured record-subject listener, but signs
//! no synthetic Provider response. Both handshakes and the recovery settlement
//! pass through the production fixed owner. The initial phase holds the old
//! process alive until Mount captures its authenticated session; the recovery
//! phase answers exactly one protected AOSSPR01 and retains its live process
//! until Mount finishes verifying the response.

use std::error::Error;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use aos_sandbox_broker_session_security::ProductionSourceProviderStorageReadbackV1;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use aos_sandbox_source_provider::{
    FixedProviderIngressProgressV1, FixedProviderOwnerStatusV1, FixedProviderOwnerV1,
};
use aos_sandbox_source_provider_protocol::SignedSourceProviderRequestV1;

const SOCKET: &str = "/run/aos/source-provider/control.sock";
const MAXIMUM_WAIT: Duration = Duration::from_secs(60);
const RETRY_PAUSE: Duration = Duration::from_millis(2);
const SIGNED_ACQUIRE: &str = "/var/lib/aos/source-provider/native-vm-signed-acquire";
const SESSION_DATA: &str = "/var/lib/aos/source-provider/native-vm-session";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Initial,
    Recovery,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("SourceProvider owner VM server failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    if !rustix::process::getuid().is_root() || !rustix::process::geteuid().is_root() {
        return Err("fixed Provider VM server requires UID 0".into());
    }
    let arguments: Vec<_> = std::env::args_os().collect();
    let [_, phase, publication, ready, stop] = arguments.as_slice() else {
        return Err("usage: aos-sandbox-source-provider-owner-vm-server initial|recovery PUBLICATION READY STOP".into());
    };
    let phase = match phase.to_str() {
        Some("initial") => Phase::Initial,
        Some("recovery") => Phase::Recovery,
        _ => return Err("invalid Provider VM phase".into()),
    };
    let publication = fs::read(publication)?;
    let ready = Path::new(ready);
    let stop = Path::new(stop);
    let mut listener = RecordSubjectListener::bind(Path::new(SOCKET), 1)?;
    listener.require_local_filesystem_path(Path::new(SOCKET))?;

    let deadline = Instant::now() + MAXIMUM_WAIT;
    let socket = loop {
        if Instant::now() >= deadline {
            return Err("timed out before authenticated RootMount connection".into());
        }
        match listener.accept_descriptor_subject() {
            Ok(socket) => break socket,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                std::thread::sleep(RETRY_PAUSE);
            }
            Err(error) => return Err(error.into()),
        }
    };

    let (mut owner, _) = FixedProviderOwnerV1::open_fixed(socket, &publication)?;
    loop {
        if Instant::now() >= deadline {
            return Err("fixed Provider handshake timed out".into());
        }
        match owner.advance_handshake()? {
            FixedProviderOwnerStatusV1::Ready => break,
            FixedProviderOwnerStatusV1::HandshakePending => std::thread::sleep(RETRY_PAUSE),
            FixedProviderOwnerStatusV1::HeldReadOnly => {
                return Err("held Provider profile is observation-only".into());
            }
        }
    }
    match phase {
        Phase::Initial => {
            let mut head = String::with_capacity(65);
            for byte in owner.native_recovery_vm_catalog_head()? {
                write!(&mut head, "{byte:02x}")?;
            }
            head.push('\n');
            write_data(ready, head.as_bytes())?;
            wait_for_path(Path::new(SIGNED_ACQUIRE), deadline)?;
            let signed =
                SignedSourceProviderRequestV1::from_canonical_bytes(&fs::read(SIGNED_ACQUIRE)?)?;
            let session = owner.native_recovery_vm_session_record(&signed)?;
            write_data(Path::new(SESSION_DATA), &session)?;
            wait_for_path(stop, deadline)
        }
        Phase::Recovery => {
            write_data(ready, b"ready\n")?;
            answer_one_native_recovery(&mut owner, &publication, deadline)?;
            // Sending does not complete the receiver's peer-currentness check.
            // Keep the real owner and process alive until Mount drops its carrier.
            wait_for_path(stop, deadline)
        }
    }
}

fn write_data(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let pending = path.with_extension("writing");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    // Readers wait for the final name, which must expose complete bytes.
    fs::hard_link(&pending, path)?;
    fs::remove_file(pending)?;
    Ok(())
}

fn wait_for_path(path: &Path, deadline: Instant) -> Result<(), Box<dyn Error>> {
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("Provider fixture marker did not appear".into());
        }
        std::thread::sleep(RETRY_PAUSE);
    }
}

fn answer_one_native_recovery(
    owner: &mut FixedProviderOwnerV1,
    publication: &[u8],
    deadline: Instant,
) -> Result<(), Box<dyn Error>> {
    loop {
        if Instant::now() >= deadline {
            return Err("Provider recovery query timed out".into());
        }
        match owner.advance_authenticated_ingress(publication)? {
            FixedProviderIngressProgressV1::Pending => std::thread::sleep(RETRY_PAUSE),
            FixedProviderIngressProgressV1::Recovery(query) => {
                let mut storage = ProductionSourceProviderStorageReadbackV1;
                let settlement = owner
                    .backend_session(&mut storage)
                    .settle_native_no_dispatch_recovery_for_query(&query)?;
                while !owner.send_native_recovery_unavailable(&query, &settlement)? {
                    if Instant::now() >= deadline {
                        return Err("Provider native terminal send timed out".into());
                    }
                    std::thread::sleep(RETRY_PAUSE);
                }
                println!("source-provider-fixed-native-terminal:PASS");
                return Ok(());
            }
            FixedProviderIngressProgressV1::CatalogReplied => {}
            FixedProviderIngressProgressV1::InventoryReadback(_)
            | FixedProviderIngressProgressV1::Source(_)
            | FixedProviderIngressProgressV1::OriginalRootPreparedRetained
            | FixedProviderIngressProgressV1::OriginalPairRetained => {
                return Err("unexpected Provider request during native recovery".into());
            }
        }
    }
}
