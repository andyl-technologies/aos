//! One-shot root/Controller transport for the separate Cache-only signer.
//!
//! Root sends a durably spent challenge first and retains its connection.
//! Controller must then present the exact same challenge under its own peer
//! credentials. The signer reads only its two private, read-only Cache views
//! and returns the same fixed v2 packet to both peers. This transport cannot
//! prove Controller-held writer custody or authorize Q04/Create; root must
//! perform its own spent-challenge, held-cut, and all-owner checks.
//!
//! ```text
//! root:       AOSCSR02 | epoch:u64be | nonce:16 | cut:32
//! controller: AOSCSC02 | epoch:u64be | nonce:16 | cut:32
//! reply:      AOSCSS02 | AOSCRB02 packet[412]
//! ```

use std::error::Error;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use aos_sandbox::cache_residency::{
    CLOSED_CACHE_OWNER_READBACK_BYTES_V2, CacheOwnerReadbackChallengeV1,
    PinnedCacheOwnerReadbackSignerV1, sign_fixed_signer_cache_owner_readback_v2,
    verify_closed_cache_owner_readback_v2,
};
use aos_sandbox::policy_compiler::ClosedCacheReadbackRootChallengeV1;
use aos_sandbox_core::ObjectDigest;
use rustix::event::{PollFd, PollFlags, poll};
use rustix::net::sockopt::{socket_acceptconn, socket_peercred};
use rustix::time::Timespec;

use crate::cache_signer_credential::CacheSignerCredentialV2;

/// Names the sole systemd-owned Cache signer ingress socket.
pub const CACHE_SIGNER_SOCKET_PATH_V2: &str = "/run/aos/sandbox-cache-signerd.sock";

const CREDENTIAL_DIRECTORY: &str = "/run/credentials/aos-sandbox-cache-signerd.service";
const ROOT_MAGIC: &[u8; 8] = b"AOSCSR02";
const CONTROLLER_MAGIC: &[u8; 8] = b"AOSCSC02";
const REPLY_MAGIC: &[u8; 8] = b"AOSCSS02";
const CHALLENGE_BYTES: usize = 64;
const REPLY_BYTES: usize = 8 + CLOSED_CACHE_OWNER_READBACK_BYTES_V2;
const PEER_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(60);
const CONTROLLER_TIMEOUT: Timespec = Timespec {
    tv_sec: 30,
    tv_nsec: 0,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChallengeFrameV2 {
    epoch: u64,
    readback: CacheOwnerReadbackChallengeV1,
}

impl ChallengeFrameV2 {
    fn new(epoch: u64, readback: CacheOwnerReadbackChallengeV1) -> io::Result<Self> {
        if epoch == 0 {
            return Err(invalid_data("zero Cache signer challenge epoch"));
        }
        Ok(Self { epoch, readback })
    }

    fn encode(self, magic: &[u8; 8]) -> [u8; CHALLENGE_BYTES] {
        let mut bytes = [0; CHALLENGE_BYTES];
        bytes[..8].copy_from_slice(magic);
        bytes[8..16].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[16..32].copy_from_slice(&self.readback.nonce());
        bytes[32..64].copy_from_slice(self.readback.cut().as_bytes());
        bytes
    }

    fn decode(bytes: &[u8; CHALLENGE_BYTES], magic: &[u8; 8]) -> io::Result<Self> {
        if &bytes[..8] != magic {
            return Err(invalid_data("foreign Cache signer challenge"));
        }
        let epoch = u64::from_be_bytes(bytes[8..16].try_into().map_err(io::Error::other)?);
        let nonce = bytes[16..32].try_into().map_err(io::Error::other)?;
        let cut = ObjectDigest::from_bytes(bytes[32..64].try_into().map_err(io::Error::other)?);
        let readback = CacheOwnerReadbackChallengeV1::new(nonce, cut)
            .map_err(|_| invalid_data("noncanonical Cache signer challenge"))?;
        Self::new(epoch, readback)
    }
}

/// Retains the root connection until one Controller-matched packet is returned.
///
/// A root caller must hold the protected writer and have durably spent the
/// challenge before constructing this exchange. A verified signature does
/// not itself prove any Controller or Cache held cut.
#[must_use = "keep the root challenge connection until its exact reply arrives"]
pub struct RootCacheSignerExchangeV2 {
    stream: UnixStream,
    challenge: CacheOwnerReadbackChallengeV1,
}

impl RootCacheSignerExchangeV2 {
    /// Waits for the same fixed signer packet returned to Controller.
    ///
    /// # Errors
    ///
    /// Rejects transport loss, wrong framing, trailing bytes, or a packet not
    /// signed by the protected deployment pin. The caller must still verify
    /// the held root session and all-owner cut.
    pub fn finish(
        mut self,
        pinned_signer: &PinnedCacheOwnerReadbackSignerV1,
        expected_owner_uid: u32,
    ) -> io::Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]> {
        self.stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
        read_signed_reply(
            &mut self.stream,
            pinned_signer,
            self.challenge,
            expected_owner_uid,
        )
    }
}

/// Opens the root half of a one-shot Cache signer challenge.
///
/// The typed challenge must come from the root's durably spent session while
/// its writer is held. The socket node is checked, but only [`RootCacheSignerExchangeV2::finish`]
/// authenticates the signer through an independently pinned packet signature.
///
/// # Errors
///
/// Rejects unsafe socket custody, malformed challenge, or transport loss.
pub fn begin_root_cache_signer_exchange_v2(
    challenge: ClosedCacheReadbackRootChallengeV1,
    signer_uid: u32,
    socket_gid: u32,
) -> io::Result<RootCacheSignerExchangeV2> {
    let frame = ChallengeFrameV2::new(challenge.epoch(), challenge.readback())?;
    let mut stream = connect_signer(signer_uid, socket_gid)?;
    write_challenge(&mut stream, frame, ROOT_MAGIC)?;
    Ok(RootCacheSignerExchangeV2 {
        stream,
        challenge: frame.readback,
    })
}

/// Requests the packet for the exact root challenge while Controller holds its writers.
///
/// The Controller caller must keep its typed Cache writer callback alive
/// across this call. The packet signature is checked against an independently
/// pinned key; root still has to compare it against independently held owners.
///
/// # Errors
///
/// Rejects unsafe socket custody, malformed challenge, transport loss, or a
/// reply that does not match the independently pinned signer.
pub fn request_controller_cache_signer_readback_v2(
    challenge: CacheOwnerReadbackChallengeV1,
    epoch: u64,
    signer_uid: u32,
    socket_gid: u32,
    pinned_signer: &PinnedCacheOwnerReadbackSignerV1,
    expected_owner_uid: u32,
) -> io::Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]> {
    let frame = ChallengeFrameV2::new(epoch, challenge)?;
    let mut stream = connect_signer(signer_uid, socket_gid)?;
    write_challenge(&mut stream, frame, CONTROLLER_MAGIC)?;
    stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
    read_signed_reply(
        &mut stream,
        pinned_signer,
        frame.readback,
        expected_owner_uid,
    )
}

fn read_signed_reply(
    stream: &mut UnixStream,
    pinned_signer: &PinnedCacheOwnerReadbackSignerV1,
    challenge: CacheOwnerReadbackChallengeV1,
    expected_owner_uid: u32,
) -> io::Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]> {
    let packet = read_reply(stream)?;
    verify_closed_cache_owner_readback_v2(&packet, pinned_signer, challenge, expected_owner_uid)
        .map_err(io::Error::other)?;
    Ok(packet)
}

fn connect_signer(signer_uid: u32, socket_gid: u32) -> io::Result<UnixStream> {
    if signer_uid == 0 || socket_gid == 0 {
        return Err(invalid_data("invalid Cache signer identity"));
    }
    require_socket_path_custody(signer_uid, socket_gid)?;
    let stream = UnixStream::connect(CACHE_SIGNER_SOCKET_PATH_V2)?;
    // An Accept=no listener is created by systemd. Its peer credentials name
    // PID 1, not the eventual signer; only the pinned reply authenticates it.
    require_socket_path_custody(signer_uid, socket_gid)?;
    stream.set_read_timeout(Some(PEER_TIMEOUT))?;
    stream.set_write_timeout(Some(PEER_TIMEOUT))?;
    Ok(stream)
}

fn write_challenge(
    stream: &mut UnixStream,
    frame: ChallengeFrameV2,
    magic: &[u8; 8],
) -> io::Result<()> {
    stream.write_all(&frame.encode(magic))?;
    stream.shutdown(std::net::Shutdown::Write)
}

fn read_reply(stream: &mut UnixStream) -> io::Result<[u8; CLOSED_CACHE_OWNER_READBACK_BYTES_V2]> {
    let mut bytes = [0; REPLY_BYTES];
    stream.read_exact(&mut bytes)?;
    let mut trailing = [0];
    if &bytes[..8] != REPLY_MAGIC || stream.read(&mut trailing)? != 0 {
        return Err(invalid_data("invalid Cache signer reply"));
    }
    bytes[8..]
        .try_into()
        .map_err(|_| invalid_data("invalid Cache signer packet length"))
}

fn read_challenge(stream: &mut UnixStream, magic: &[u8; 8]) -> io::Result<ChallengeFrameV2> {
    stream.set_read_timeout(Some(PEER_TIMEOUT))?;
    stream.set_write_timeout(Some(PEER_TIMEOUT))?;
    let mut bytes = [0; CHALLENGE_BYTES];
    stream.read_exact(&mut bytes)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(invalid_data("trailing Cache signer challenge bytes"));
    }
    ChallengeFrameV2::decode(&bytes, magic)
}

fn require_peer(stream: &UnixStream, uid: u32, gid: u32) -> io::Result<()> {
    let peer = socket_peercred(stream).map_err(io::Error::other)?;
    if peer.uid.as_raw() != uid || peer.gid.as_raw() != gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected Cache signer peer",
        ));
    }
    Ok(())
}

fn require_socket_path_custody(signer_uid: u32, socket_gid: u32) -> io::Result<()> {
    for path in ["/run", "/run/aos"] {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid_data("unsafe Cache signer socket parent"));
        }
    }

    let metadata = fs::symlink_metadata(CACHE_SIGNER_SOCKET_PATH_V2)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != signer_uid
        || metadata.gid() != socket_gid
        || metadata.mode() & 0o777 != 0o660
        || metadata.nlink() != 1
    {
        return Err(invalid_data("unsafe Cache signer socket node"));
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Serves one root-first, Controller-matched Cache-only signer exchange at a time.
///
/// It requires a single systemd listening socket on stdin and separate
/// signer-private systemd credentials. The signed packet remains evidence only
/// and cannot authorize Q04 or Create without root's later all-owner checks.
///
/// # Errors
///
/// Rejects wrong process identity, socket activation, credentials, or a lost
/// listener. Invalid individual exchanges are logged and consumed without
/// reusing their in-process root epoch.
pub fn run_cache_signer_service_v2(
    controller_uid: u32,
    controller_gid: u32,
    signer_uid: u32,
    signer_gid: u32,
) -> Result<(), Box<dyn Error>> {
    if controller_uid == 0
        || controller_gid == 0
        || signer_uid == 0
        || signer_gid == 0
        || controller_uid == signer_uid
        || rustix::process::getuid().as_raw() != signer_uid
        || rustix::process::geteuid().as_raw() != signer_uid
        || rustix::process::getgid().as_raw() != signer_gid
        || rustix::process::getegid().as_raw() != signer_gid
    {
        return Err(invalid_data("wrong Cache signer process identity").into());
    }
    if std::env::var_os("CREDENTIALS_DIRECTORY").as_deref()
        != Some(std::ffi::OsStr::new(CREDENTIAL_DIRECTORY))
        || std::env::var_os("LISTEN_FDS").is_some()
        || std::env::var_os("LISTEN_PID").is_some()
    {
        return Err(invalid_data("wrong Cache signer activation custody").into());
    }
    let credentials = CacheSignerCredentialV2::load()?;
    let stdin = io::stdin();
    let listener = UnixListener::from(rustix::io::dup(stdin.as_fd())?);
    if !socket_acceptconn(&listener)?
        || listener.local_addr()?.as_pathname() != Some(Path::new(CACHE_SIGNER_SOCKET_PATH_V2))
    {
        return Err(invalid_data("wrong Cache signer listening socket").into());
    }
    require_socket_path_custody(signer_uid, controller_gid)?;

    let mut last_epoch = 0_u64;
    loop {
        let (mut root, _) = listener.accept()?;
        if let Err(error) = serve_exchange(
            &listener,
            &mut root,
            controller_uid,
            controller_gid,
            signer_uid,
            &credentials,
            &mut last_epoch,
        ) {
            eprintln!("aos-sandbox-cache-signerd: rejected exchange: {error}");
        }
    }
}

fn serve_exchange(
    listener: &UnixListener,
    root: &mut UnixStream,
    controller_uid: u32,
    controller_gid: u32,
    signer_uid: u32,
    credentials: &CacheSignerCredentialV2,
    last_epoch: &mut u64,
) -> Result<(), Box<dyn Error>> {
    require_peer(root, 0, controller_gid)?;
    let challenge = read_challenge(root, ROOT_MAGIC)?;
    if challenge.epoch <= *last_epoch {
        return Err(invalid_data("replayed Cache signer challenge epoch").into());
    }
    // Root's protected record is the restart-persistent replay barrier. The
    // local epoch still prevents duplicate service flights before a restart.
    *last_epoch = challenge.epoch;

    let mut ready = [PollFd::new(listener, PollFlags::IN)];
    if poll(&mut ready, Some(&CONTROLLER_TIMEOUT))? == 0 {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "Controller challenge absent").into());
    }
    if ready[0].revents() != PollFlags::IN {
        return Err(invalid_data("unsafe Cache signer listener readiness").into());
    }
    let (mut controller, _) = listener.accept()?;
    require_peer(&controller, controller_uid, controller_gid)?;
    if read_challenge(&mut controller, CONTROLLER_MAGIC)? != challenge {
        return Err(invalid_data("Controller challenge differs from root").into());
    }
    require_socket_path_custody(signer_uid, controller_gid)?;

    let signing_key = credentials.signing_key()?;
    let packet = sign_fixed_signer_cache_owner_readback_v2(
        credentials.maximum_memory_bytes(),
        challenge.readback,
        credentials.generation(),
        &signing_key,
    )?;
    let mut reply = [0; REPLY_BYTES];
    reply[..8].copy_from_slice(REPLY_MAGIC);
    reply[8..].copy_from_slice(&packet);
    root.write_all(&reply)?;
    controller.write_all(&reply)?;
    root.shutdown(std::net::Shutdown::Write)?;
    controller.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_sandbox::cache_residency::encode_cache_owner_readback_signer_credential_v1;
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn challenge_frame_requires_exact_role_and_nonzero_fields() {
        let readback =
            CacheOwnerReadbackChallengeV1::new([7; 16], ObjectDigest::from_bytes([9; 32])).unwrap();
        let frame = ChallengeFrameV2::new(3, readback).unwrap();
        assert_eq!(
            ChallengeFrameV2::decode(&frame.encode(ROOT_MAGIC), ROOT_MAGIC).unwrap(),
            frame
        );
        assert!(ChallengeFrameV2::decode(&frame.encode(CONTROLLER_MAGIC), ROOT_MAGIC).is_err());
        assert!(ChallengeFrameV2::new(0, readback).is_err());

        let mut bad = frame.encode(ROOT_MAGIC);
        bad[16..32].fill(0);
        assert!(ChallengeFrameV2::decode(&bad, ROOT_MAGIC).is_err());
        bad = frame.encode(ROOT_MAGIC);
        bad[32..64].fill(0);
        assert!(ChallengeFrameV2::decode(&bad, ROOT_MAGIC).is_err());
    }

    #[test]
    fn challenge_transport_requires_exact_role_and_end_of_frame() {
        let readback =
            CacheOwnerReadbackChallengeV1::new([7; 16], ObjectDigest::from_bytes([9; 32])).unwrap();
        let frame = ChallengeFrameV2::new(3, readback).unwrap();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        write_challenge(&mut sender, frame, ROOT_MAGIC).unwrap();
        assert_eq!(read_challenge(&mut receiver, ROOT_MAGIC).unwrap(), frame);

        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        write_challenge(&mut sender, frame, CONTROLLER_MAGIC).unwrap();
        assert!(read_challenge(&mut receiver, ROOT_MAGIC).is_err());

        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&frame.encode(ROOT_MAGIC)).unwrap();
        sender.write_all(&[1]).unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(read_challenge(&mut receiver, ROOT_MAGIC).is_err());
    }

    #[test]
    fn signed_reply_rejects_unsigned_packet() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let pin = encode_cache_owner_readback_signer_credential_v1(1, &signing_key.verifying_key())
            .unwrap();
        let signer = PinnedCacheOwnerReadbackSignerV1::decode(&pin).unwrap();
        let challenge =
            CacheOwnerReadbackChallengeV1::new([7; 16], ObjectDigest::from_bytes([9; 32])).unwrap();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let mut reply = [0; REPLY_BYTES];
        reply[..8].copy_from_slice(REPLY_MAGIC);
        sender.write_all(&reply).unwrap();
        sender.shutdown(std::net::Shutdown::Write).unwrap();

        assert!(read_signed_reply(&mut receiver, &signer, challenge, 811).is_err());
    }
}
