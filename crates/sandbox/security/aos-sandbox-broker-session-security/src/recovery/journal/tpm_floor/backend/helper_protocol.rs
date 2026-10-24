//! Method-46 policy adapter over the shared private v2 carrier codec.
//!
//! The original caller API and error classifications remain unchanged. The
//! common codec accepts no caller-selected handle; this adapter admits exactly
//! the original Controller Storage and Storage broker roles.

use zeroize::Zeroizing;

use super::super::FloorErrorV1;
use super::super::format::FloorEndpointV1;
use crate::tpm_nv_custody::{NvCustodyEndpointV1, NvCustodyErrorV1};
use crate::tpm_nv_custody::framing;

pub(crate) use framing::{
    AUTH_BYTES, HELLO_BYTES, LOCK_ACK_BYTES, REQUEST_BYTES, RESPONSE_BYTES,
    HelperObservationV1, HelperOperationV1,
};

fn endpoint(endpoint: FloorEndpointV1) -> NvCustodyEndpointV1 {
    match endpoint {
        FloorEndpointV1::ControllerStorageClient => NvCustodyEndpointV1::ControllerStorageClient,
        FloorEndpointV1::StorageBroker => NvCustodyEndpointV1::StorageBroker,
    }
}

fn floor_error(error: NvCustodyErrorV1) -> FloorErrorV1 {
    match error {
        NvCustodyErrorV1::Encoding => FloorErrorV1::Encoding,
        NvCustodyErrorV1::Provisioning => FloorErrorV1::Provisioning,
        NvCustodyErrorV1::Unavailable => FloorErrorV1::Unavailable,
    }
}

pub(crate) fn encode_hello_v2(
    role: FloorEndpointV1,
    nonce: [u8; 32],
    salt_name: [u8; 34],
    locks: [(u64, u64, u32); 2],
) -> Result<Zeroizing<[u8; HELLO_BYTES]>, FloorErrorV1> {
    framing::encode_hello_v2(endpoint(role), nonce, salt_name, locks).map_err(floor_error)
}

pub(crate) fn require_lock_ack_v2(bytes: &[u8], nonce: [u8; 32]) -> Result<(), FloorErrorV1> {
    framing::require_lock_ack_v2(bytes, nonce).map_err(floor_error)
}

pub(crate) fn encode_auth_v2(
    role: FloorEndpointV1,
    nonce: [u8; 32],
    auth: &[u8; 32],
) -> Result<Zeroizing<[u8; AUTH_BYTES]>, FloorErrorV1> {
    framing::encode_auth_v2(endpoint(role), nonce, auth).map_err(floor_error)
}

#[cfg(test)]
pub(super) fn salt_handle_v1(role: FloorEndpointV1) -> u32 {
    framing::salt_handle_v1(endpoint(role))
}

pub(crate) fn encode_request_v2(
    operation: HelperOperationV1,
    nonce: [u8; 32],
    sequence: u64,
    input: [u8; 32],
) -> Result<[u8; REQUEST_BYTES], FloorErrorV1> {
    framing::encode_request_v2(operation, nonce, sequence, input).map_err(floor_error)
}

pub(crate) fn decode_response_v2(
    bytes: &[u8],
    operation: HelperOperationV1,
    nonce: [u8; 32],
    sequence: u64,
) -> Result<HelperObservationV1, FloorErrorV1> {
    framing::decode_response_v2(bytes, operation, nonce, sequence).map_err(floor_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> [u8; RESPONSE_BYTES] {
        let mut bytes = [0; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(b"AOSBTR02");
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
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
        let decode = |bytes: &[u8]| decode_response_v2(bytes, HelperOperationV1::Read, [7; 32], 1);
        assert_eq!(decode(&bytes).unwrap().value, [9; 32]);
        for offset in [0, 8, 9, 10, 11, 12, 44, 51] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(decode(&changed).is_err(), "offset {offset}");
        }
        assert!(decode(&bytes[..127]).is_err());
        assert!(decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        assert!(decode_response_v2(&bytes, HelperOperationV1::Extend, [7; 32], 1).is_err());
        assert!(decode_response_v2(&bytes, HelperOperationV1::Read, [6; 32], 1).is_err());
        assert!(decode_response_v2(&bytes, HelperOperationV1::Read, [7; 32], 2).is_err());
    }

    #[test]
    fn tpm_floor_helper_hello_and_request_are_bounded_and_role_separated() {
        let mut name = [8; 34];
        name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
        let client = encode_hello_v2(
            FloorEndpointV1::ControllerStorageClient,
            [7; 32],
            name,
            [(1, 2, 3), (1, 4, 3)],
        )
        .unwrap();
        let broker = encode_hello_v2(
            FloorEndpointV1::StorageBroker,
            [7; 32],
            name,
            [(1, 2, 3), (1, 4, 3)],
        )
        .unwrap();
        assert_eq!(client.len(), HELLO_BYTES);
        assert_ne!(client[44..52], broker[44..52]);
        assert_eq!(client[86..120], [0; 34]);
        assert!(
            encode_hello_v2(
                FloorEndpointV1::StorageBroker,
                [0; 32],
                name,
                [(1, 2, 3), (1, 4, 3)]
            )
            .is_err()
        );
        assert!(
            encode_hello_v2(
                FloorEndpointV1::StorageBroker,
                [7; 32],
                [0; 34],
                [(1, 2, 3), (1, 4, 3)]
            )
            .is_err()
        );
        assert!(
            encode_hello_v2(
                FloorEndpointV1::StorageBroker,
                [7; 32],
                name,
                [(1, 2, 3), (1, 2, 3)]
            )
            .is_err()
        );

        let read = encode_request_v2(HelperOperationV1::Read, [7; 32], 1, [0; 32]).unwrap();
        assert_eq!(read.len(), REQUEST_BYTES);
        assert_eq!(&read[52..], &[0; 32]);
        assert!(encode_request_v2(HelperOperationV1::Read, [7; 32], 1, [1; 32]).is_err());
        assert!(encode_request_v2(HelperOperationV1::Extend, [7; 32], 1, [0; 32]).is_err());
        assert!(encode_request_v2(HelperOperationV1::Read, [7; 32], u64::MAX, [0; 32]).is_err());

        let auth = encode_auth_v2(FloorEndpointV1::StorageBroker, [7; 32], &[9; 32]).unwrap();
        assert_eq!(auth.len(), AUTH_BYTES);
        assert_eq!(&auth[..12], b"AOSBTA02\0\x02\0\0");
        assert_eq!(&auth[12..44], &[7; 32]);
        assert_eq!(
            &auth[44..48],
            &FloorEndpointV1::StorageBroker.nv_index().to_be_bytes()
        );
        assert_eq!(&auth[48..], &[9; 32]);
        assert!(encode_auth_v2(FloorEndpointV1::StorageBroker, [0; 32], &[9; 32]).is_err());
        assert!(encode_auth_v2(FloorEndpointV1::StorageBroker, [7; 32], &[0; 32]).is_err());
    }

    #[test]
    fn tpm_floor_helper_lock_ack_requires_exact_two_lock_custody() {
        let mut ack = [0; LOCK_ACK_BYTES];
        ack[..8].copy_from_slice(b"AOSBTK02");
        ack[9] = 2;
        ack[12..44].fill(7);
        ack[45] = 2;
        require_lock_ack_v2(&ack, [7; 32]).unwrap();
        for offset in [0, 8, 9, 10, 12, 44, 45, 46, 47] {
            let mut changed = ack;
            changed[offset] ^= 1;
            assert!(require_lock_ack_v2(&changed, [7; 32]).is_err());
        }
        assert!(require_lock_ack_v2(&ack[..47], [7; 32]).is_err());
        ack[..8].copy_from_slice(b"AOSBTK01");
        ack[9] = 1;
        assert!(require_lock_ack_v2(&ack, [7; 32]).is_err());
    }
}
