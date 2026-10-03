//! Opaque Root V8 settlement evidence from the fixed policy-authority socket.
//!
//! ```text
//! AOSPHQ8S | nonce[16] | reserved[8]=0 | predecessor[32] | epoch:u64 | EOF
//! AOSPHR8S | nonce[16] | predecessor[32] | epoch:u64 |
//!            status:absent|settled | reserved[7]=0 | AOSPC88S[256] | EOF
//! ```
//!
//! The released-terminal R8X exchange cannot replay after settlement because
//! Root atomically retires its fixed A/T/L slots when it records AOSPC88S.

use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;

use super::binding_v2::RootV8SuccessorSettlementV1;
use super::controller_readback_session::fresh_root_nonce;
use super::root_v8_released_proof::POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2;

/// Identifies the distinct Root V8 successor-settlement query.
pub const ROOT_V8_SETTLED_QUERY_MAGIC: &[u8; 8] = b"AOSPHQ8S";
const REPLY_MAGIC: &[u8; 8] = b"AOSPHR8S";
const QUERY_BYTES: usize = 72;
const REPLY_BYTES: usize = 328;
const ROOT_WAIT: Duration = Duration::from_secs(35);

/// Retains one immutable, peer-checked Root V8 successor settlement.
///
/// Only [`query_fixed_root_v8_settled_grant_v1`] can construct this grant.
/// Owner-local pending-release fences must compare their exact released row
/// with its matching digest before accepting a future clear operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootV8SettledGrantV1 {
    marker: RootV8SuccessorSettlementV1,
}

impl RootV8SettledGrantV1 {
    /// Builds a grant from a canonical marker for isolated owner journal tests.
    ///
    /// # Errors
    ///
    /// Rejects malformed or noncanonical Root settlement bytes.
    #[cfg(test)]
    pub(crate) fn from_record_bytes_for_test(bytes: &[u8]) -> io::Result<Self> {
        let marker =
            RootV8SuccessorSettlementV1::from_record_bytes(bytes).map_err(io::Error::other)?;
        Ok(Self { marker })
    }

    /// Returns the settled predecessor binding.
    #[must_use]
    pub const fn predecessor(self) -> ObjectDigest {
        self.marker.predecessor()
    }

    /// Returns the predecessor handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.marker.epoch()
    }

    /// Returns the next permitted Root epoch.
    #[must_use]
    pub const fn next_epoch(self) -> u64 {
        self.marker.next_epoch()
    }

    /// Returns the canonical Controller AOSQ8S01 digest.
    #[must_use]
    pub const fn settlement(self) -> ObjectDigest {
        self.marker.settlement()
    }

    /// Returns the canonical Root AOSPC88L digest.
    #[must_use]
    pub const fn release_marker(self) -> ObjectDigest {
        self.marker.release_marker()
    }

    /// Returns the exact released Cache hold digest.
    #[must_use]
    pub const fn cache_released(self) -> ObjectDigest {
        self.marker.cache_released()
    }

    /// Returns the exact released Source hold digest.
    #[must_use]
    pub const fn source_released(self) -> ObjectDigest {
        self.marker.source_released()
    }

    /// Returns the digest of the signed Controller settlement receipt.
    #[must_use]
    pub const fn signed_receipt(self) -> ObjectDigest {
        self.marker.signed_receipt()
    }
}

/// Queries one settled predecessor through the fixed root-owned socket.
///
/// Absence grants nothing. The caller must still compare the returned digests
/// to its own protected released rows; this query does not clear any hold.
///
/// # Errors
///
/// Rejects invalid claims, a non-Root or substituted socket peer, transport
/// loss, malformed or trailing bytes, and any noncanonical AOSPC88S record.
pub fn query_fixed_root_v8_settled_grant_v1(
    predecessor: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootV8SettledGrantV1>> {
    validate_claim(predecessor, epoch)?;
    let nonce = fresh_root_nonce()?;
    if nonce == [0; 16] {
        return Err(invalid_grant());
    }

    let path = Path::new(POLICY_AUTHORITY_FIXED_SOCKET_PATH_V2);
    let mut stream = UnixStream::connect(path)?;
    let peer = rustix::net::sockopt::socket_peercred(&stream)?;
    if !peer.uid.is_root() || stream.peer_addr()?.as_pathname() != Some(path) {
        return Err(invalid_grant());
    }
    stream.set_read_timeout(Some(ROOT_WAIT))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut query = [0; QUERY_BYTES];
    query[..8].copy_from_slice(ROOT_V8_SETTLED_QUERY_MAGIC);
    query[8..24].copy_from_slice(&nonce);
    query[32..64].copy_from_slice(predecessor.as_bytes());
    query[64..72].copy_from_slice(&epoch.to_be_bytes());
    stream.write_all(&query)?;
    stream.shutdown(Shutdown::Write)?;

    let marker = read_reply(&mut stream, nonce, predecessor, epoch)?;
    Ok(marker.map(|marker| RootV8SettledGrantV1 { marker }))
}

/// Encodes a typed protected Root settlement for its fixed socket server.
///
/// This pure encoder cannot mint a grant. The server must first authenticate
/// its Controller peer and recover the marker from Root's protected journal.
///
/// # Errors
///
/// Rejects an invalid claim or a marker for another predecessor or epoch.
pub fn encode_root_v8_settled_reply_v1(
    nonce: [u8; 16],
    predecessor: ObjectDigest,
    epoch: u64,
    marker: Option<RootV8SuccessorSettlementV1>,
) -> io::Result<[u8; REPLY_BYTES]> {
    let next_epoch = validate_claim(predecessor, epoch)?;
    if nonce == [0; 16] {
        return Err(invalid_grant());
    }

    let mut reply = [0; REPLY_BYTES];
    reply[..8].copy_from_slice(REPLY_MAGIC);
    reply[8..24].copy_from_slice(&nonce);
    reply[24..56].copy_from_slice(predecessor.as_bytes());
    reply[56..64].copy_from_slice(&epoch.to_be_bytes());
    if let Some(marker) = marker {
        if marker.predecessor() != predecessor
            || marker.epoch() != epoch
            || marker.next_epoch() != next_epoch
        {
            return Err(invalid_grant());
        }
        reply[64] = 1;
        reply[72..].copy_from_slice(&marker.record_bytes().map_err(io::Error::other)?);
    }
    Ok(reply)
}

fn read_reply(
    stream: &mut UnixStream,
    nonce: [u8; 16],
    predecessor: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootV8SuccessorSettlementV1>> {
    let mut reply = [0; REPLY_BYTES];
    stream.read_exact(&mut reply)?;
    let mut trailing = [0];
    if stream.read(&mut trailing)? != 0 {
        return Err(invalid_grant());
    }
    decode_reply(&reply, nonce, predecessor, epoch)
}

fn decode_reply(
    reply: &[u8; REPLY_BYTES],
    nonce: [u8; 16],
    predecessor: ObjectDigest,
    epoch: u64,
) -> io::Result<Option<RootV8SuccessorSettlementV1>> {
    let next_epoch = validate_claim(predecessor, epoch)?;
    if nonce == [0; 16]
        || reply[..8] != REPLY_MAGIC[..]
        || reply[8..24] != nonce
        || reply[24..56] != *predecessor.as_bytes()
        || reply[56..64] != epoch.to_be_bytes()
        || reply[65..72] != [0; 7]
    {
        return Err(invalid_grant());
    }
    match reply[64] {
        0 if reply[72..].iter().all(|byte| *byte == 0) => Ok(None),
        1 => {
            let marker = RootV8SuccessorSettlementV1::from_record_bytes(&reply[72..])
                .map_err(io::Error::other)?;
            if marker.predecessor() != predecessor
                || marker.epoch() != epoch
                || marker.next_epoch() != next_epoch
            {
                return Err(invalid_grant());
            }
            Ok(Some(marker))
        }
        _ => Err(invalid_grant()),
    }
}

fn validate_claim(predecessor: ObjectDigest, epoch: u64) -> io::Result<u64> {
    if predecessor.as_bytes() == &[0; 32] || epoch == 0 {
        return Err(invalid_grant());
    }
    epoch.checked_add(1).ok_or_else(invalid_grant)
}

fn invalid_grant() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Root V8 settlement grant",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn sample_marker() -> RootV8SuccessorSettlementV1 {
        let mut bytes = [0; 256];
        bytes[..8].copy_from_slice(b"AOSPC88S");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].fill(1);
        bytes[48..56].copy_from_slice(&2_u64.to_be_bytes());
        bytes[56..64].copy_from_slice(&3_u64.to_be_bytes());
        for (index, value) in [4, 5, 6, 7, 8].into_iter().enumerate() {
            bytes[64 + index * 32..96 + index * 32].fill(value);
        }
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.root-v8-successor-settlement.v1\0")
            .chain_update(&bytes[..224])
            .finalize();
        bytes[224..].copy_from_slice(&checksum);
        RootV8SuccessorSettlementV1::from_record_bytes(&bytes).unwrap()
    }

    #[test]
    fn settled_reply_requires_canonical_exact_claim_and_phase() {
        let marker = sample_marker();
        let nonce = [9; 16];
        let frame = encode_root_v8_settled_reply_v1(
            nonce,
            marker.predecessor(),
            marker.epoch(),
            Some(marker),
        )
        .unwrap();
        assert_eq!(
            decode_reply(&frame, nonce, marker.predecessor(), 2).unwrap(),
            Some(marker)
        );

        for offset in [0, 8, 24, 56, 64, 65, 72, 88, 120, 152, 184, 216, 296] {
            let mut changed = frame;
            changed[offset] ^= 1;
            assert!(decode_reply(&changed, nonce, marker.predecessor(), 2).is_err());
        }
        assert!(decode_reply(&frame, [3; 16], marker.predecessor(), 2).is_err());

        let absent = encode_root_v8_settled_reply_v1(nonce, marker.predecessor(), 2, None).unwrap();
        assert_eq!(
            decode_reply(&absent, nonce, marker.predecessor(), 2).unwrap(),
            None
        );
        let mut false_absence = absent;
        false_absence[72] = 1;
        assert!(decode_reply(&false_absence, nonce, marker.predecessor(), 2).is_err());
        assert!(
            encode_root_v8_settled_reply_v1(nonce, marker.predecessor(), u64::MAX, None).is_err()
        );
    }

    #[test]
    fn settled_reply_rejects_trailing_bytes_and_wrong_marker() {
        let marker = sample_marker();
        let nonce = [9; 16];
        let frame = encode_root_v8_settled_reply_v1(
            nonce,
            marker.predecessor(),
            marker.epoch(),
            Some(marker),
        )
        .unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        server.write_all(&frame).unwrap();
        server.write_all(&[1]).unwrap();
        server.shutdown(Shutdown::Write).unwrap();
        assert!(read_reply(&mut client, nonce, marker.predecessor(), 2).is_err());

        let (mut client, mut server) = UnixStream::pair().unwrap();
        server.write_all(&frame[..frame.len() - 1]).unwrap();
        server.shutdown(Shutdown::Write).unwrap();
        assert!(read_reply(&mut client, nonce, marker.predecessor(), 2).is_err());

        assert!(
            encode_root_v8_settled_reply_v1(
                nonce,
                ObjectDigest::from_bytes([2; 32]),
                2,
                Some(marker)
            )
            .is_err()
        );
        assert!(
            encode_root_v8_settled_reply_v1(nonce, marker.predecessor(), 3, Some(marker)).is_err()
        );
    }
}
