//! Bounded private sequenced-packet framing for one retained TPM helper child.
//!
//! These bytes authenticate no TPM or child. Only the fixed-image/pidfd owner
//! may interpret a response as an authenticated observation. The channel nonce
//! and sequence reject crossed or stale replies within that retained carrier.
//!
//! ```text
//! AOSBTH01 | version:1u16be | reserved:0u16be | nonce:32 |
//! index:u32be | salt-handle:u32be | salt-Name:34 | index-auth:32 | reserved:2 |
//! main-lock:(device:u64be,inode:u64be,uid:u32be) | sidecar-lock:same
//! AOSBTK01 | version:1u16be | reserved:0u16be | nonce:32 | FD-count:2u16be | reserved:2
//! AOSBTQ01 | version:1u16be | op:u8 | reserved:0u8 | nonce:32 |
//! sequence:u64be | input:32
//! AOSBTR01 | version:1u16be | op:u8 | reserved:0u8 | nonce:32 |
//! sequence:u64be | NV-Name:34 | name-alg:u16be | attrs:u32be |
//! size:u16be | policy-length:u16be | value:32
//! ```

use zeroize::Zeroizing;

use super::super::FloorErrorV1;
use super::super::format::FloorEndpointV1;

pub(super) const HELLO_BYTES: usize = 160;
pub(super) const LOCK_ACK_BYTES: usize = 48;
pub(super) const REQUEST_BYTES: usize = 84;
pub(super) const RESPONSE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HelperOperationV1 {
    Read = 1,
    Extend = 2,
}

pub(super) fn encode_hello_v1(
    endpoint: FloorEndpointV1,
    nonce: [u8; 32],
    salt_name: [u8; 34],
    auth: &[u8; 32],
    locks: [(u64, u64, u32); 2],
) -> Result<Zeroizing<[u8; HELLO_BYTES]>, FloorErrorV1> {
    if nonce == [0; 32]
        || salt_name[..2] != 0x000b_u16.to_be_bytes()
        || salt_name[2..] == [0; 32]
        || *auth == [0; 32]
        || locks.iter().any(|(_, inode, _)| *inode == 0)
        || (locks[0].0, locks[0].1) == (locks[1].0, locks[1].1)
        || locks[0].2 != locks[1].2
    {
        return Err(FloorErrorV1::Provisioning);
    }
    let mut bytes = Zeroizing::new([0; HELLO_BYTES]);
    bytes[..8].copy_from_slice(b"AOSBTH01");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[12..44].copy_from_slice(&nonce);
    bytes[44..48].copy_from_slice(&endpoint.nv_index().to_be_bytes());
    bytes[48..52].copy_from_slice(&salt_handle_v1(endpoint).to_be_bytes());
    bytes[52..86].copy_from_slice(&salt_name);
    bytes[86..118].copy_from_slice(auth);
    for (index, (device, inode, uid)) in locks.into_iter().enumerate() {
        let offset = 120 + index * 20;
        bytes[offset..offset + 8].copy_from_slice(&device.to_be_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&inode.to_be_bytes());
        bytes[offset + 16..offset + 20].copy_from_slice(&uid.to_be_bytes());
    }
    Ok(bytes)
}

pub(super) fn require_lock_ack_v1(bytes: &[u8], nonce: [u8; 32]) -> Result<(), FloorErrorV1> {
    if bytes.len() != LOCK_ACK_BYTES
        || &bytes[..8] != b"AOSBTK01"
        || bytes[8..12] != [0, 1, 0, 0]
        || nonce == [0; 32]
        || bytes[12..44] != nonce
        || bytes[44..48] != [0, 2, 0, 0]
    {
        return Err(FloorErrorV1::Encoding);
    }
    Ok(())
}

pub(super) const fn salt_handle_v1(endpoint: FloorEndpointV1) -> u32 {
    match endpoint {
        FloorEndpointV1::ControllerStorageClient => 0x8100_a046,
        FloorEndpointV1::StorageBroker => 0x8100_a047,
    }
}

pub(super) fn encode_request_v1(
    operation: HelperOperationV1,
    nonce: [u8; 32],
    sequence: u64,
    input: [u8; 32],
) -> Result<[u8; REQUEST_BYTES], FloorErrorV1> {
    if nonce == [0; 32]
        || sequence == 0
        || sequence == u64::MAX
        || operation == HelperOperationV1::Read && input != [0; 32]
        || operation == HelperOperationV1::Extend && input == [0; 32]
    {
        return Err(FloorErrorV1::Encoding);
    }
    let mut bytes = [0; REQUEST_BYTES];
    bytes[..8].copy_from_slice(b"AOSBTQ01");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[10] = operation as u8;
    bytes[12..44].copy_from_slice(&nonce);
    bytes[44..52].copy_from_slice(&sequence.to_be_bytes());
    bytes[52..84].copy_from_slice(&input);
    Ok(bytes)
}

/// Decodes only shape and correlation; it is not an authenticated-NV factory.
pub(super) fn decode_response_v1(
    bytes: &[u8],
    operation: HelperOperationV1,
    nonce: [u8; 32],
    sequence: u64,
) -> Result<HelperObservationV1, FloorErrorV1> {
    if bytes.len() != RESPONSE_BYTES
        || &bytes[..8] != b"AOSBTR01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10] != operation as u8
        || bytes[11] != 0
        || nonce == [0; 32]
        || bytes[12..44] != nonce
        || sequence == 0
        || sequence == u64::MAX
        || bytes[44..52] != sequence.to_be_bytes()
    {
        return Err(FloorErrorV1::Encoding);
    }
    Ok(HelperObservationV1 {
        name: array(bytes, 52)?,
        name_algorithm: u16::from_be_bytes(array(bytes, 86)?),
        attributes: u32::from_be_bytes(array(bytes, 88)?),
        size: u16::from_be_bytes(array(bytes, 92)?),
        policy_length: u16::from_be_bytes(array(bytes, 94)?),
        value: array(bytes, 96)?,
    })
}

pub(super) struct HelperObservationV1 {
    pub(super) name: [u8; 34],
    pub(super) name_algorithm: u16,
    pub(super) attributes: u32,
    pub(super) size: u16,
    pub(super) policy_length: u16,
    pub(super) value: [u8; 32],
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], FloorErrorV1> {
    bytes
        .get(offset..offset.checked_add(N).ok_or(FloorErrorV1::Encoding)?)
        .ok_or(FloorErrorV1::Encoding)?
        .try_into()
        .map_err(|_| FloorErrorV1::Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> [u8; RESPONSE_BYTES] {
        let mut bytes = [0; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(b"AOSBTR01");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[12..44].copy_from_slice(&[7; 32]);
        bytes[44..52].copy_from_slice(&1_u64.to_be_bytes());
        bytes[52..54].copy_from_slice(&0x000b_u16.to_be_bytes());
        bytes[54..86].copy_from_slice(&[8; 32]);
        bytes[86..88].copy_from_slice(&0x000b_u16.to_be_bytes());
        bytes[88..92].copy_from_slice(&0x2004_0044_u32.to_be_bytes());
        bytes[92..94].copy_from_slice(&32_u16.to_be_bytes());
        bytes[96..128].copy_from_slice(&[9; 32]);
        bytes
    }

    #[test]
    fn tpm_floor_helper_strict_shape_and_channel_correlation() {
        let bytes = response();
        let decode = |bytes: &[u8]| decode_response_v1(bytes, HelperOperationV1::Read, [7; 32], 1);
        assert_eq!(decode(&bytes).unwrap().value, [9; 32]);
        for offset in [0, 8, 9, 10, 11, 12, 44, 51] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(decode(&changed).is_err(), "offset {offset}");
        }
        assert!(decode(&bytes[..127]).is_err());
        assert!(decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        assert!(decode_response_v1(&bytes, HelperOperationV1::Extend, [7; 32], 1).is_err());
        assert!(decode_response_v1(&bytes, HelperOperationV1::Read, [6; 32], 1).is_err());
        assert!(decode_response_v1(&bytes, HelperOperationV1::Read, [7; 32], 2).is_err());
    }

    #[test]
    fn tpm_floor_helper_hello_and_request_are_bounded_and_role_separated() {
        let mut name = [8; 34];
        name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
        let client = encode_hello_v1(
            FloorEndpointV1::ControllerStorageClient,
            [7; 32],
            name,
            &[9; 32],
            [(1, 2, 3), (1, 4, 3)],
        )
        .unwrap();
        let broker = encode_hello_v1(
            FloorEndpointV1::StorageBroker,
            [7; 32],
            name,
            &[9; 32],
            [(1, 2, 3), (1, 4, 3)],
        )
        .unwrap();
        assert_eq!(client.len(), HELLO_BYTES);
        assert_ne!(client[44..52], broker[44..52]);
        assert_eq!(client[118..120], [0; 2]);
        assert!(
            encode_hello_v1(
                FloorEndpointV1::StorageBroker,
                [0; 32],
                name,
                &[9; 32],
                [(1, 2, 3), (1, 4, 3)]
            )
            .is_err()
        );
        assert!(
            encode_hello_v1(
                FloorEndpointV1::StorageBroker,
                [7; 32],
                name,
                &[0; 32],
                [(1, 2, 3), (1, 4, 3)]
            )
            .is_err()
        );
        assert!(
            encode_hello_v1(
                FloorEndpointV1::StorageBroker,
                [7; 32],
                name,
                &[9; 32],
                [(1, 2, 3), (1, 2, 3)]
            )
            .is_err()
        );

        let read = encode_request_v1(HelperOperationV1::Read, [7; 32], 1, [0; 32]).unwrap();
        assert_eq!(read.len(), REQUEST_BYTES);
        assert_eq!(&read[52..], &[0; 32]);
        assert!(encode_request_v1(HelperOperationV1::Read, [7; 32], 1, [1; 32]).is_err());
        assert!(encode_request_v1(HelperOperationV1::Extend, [7; 32], 1, [0; 32]).is_err());
        assert!(encode_request_v1(HelperOperationV1::Read, [7; 32], u64::MAX, [0; 32]).is_err());
    }

    #[test]
    fn tpm_floor_helper_lock_ack_requires_exact_two_lock_custody() {
        let mut ack = [0; LOCK_ACK_BYTES];
        ack[..8].copy_from_slice(b"AOSBTK01");
        ack[9] = 1;
        ack[12..44].fill(7);
        ack[45] = 2;
        require_lock_ack_v1(&ack, [7; 32]).unwrap();
        for offset in [0, 8, 9, 10, 12, 44, 45, 46, 47] {
            let mut changed = ack;
            changed[offset] ^= 1;
            assert!(require_lock_ack_v1(&changed, [7; 32]).is_err());
        }
        assert!(require_lock_ack_v1(&ack[..47], [7; 32]).is_err());
    }
}
