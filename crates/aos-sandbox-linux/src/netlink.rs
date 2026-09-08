//! Descriptor-only Network namespace identity queries over rtnetlink.
//!
//! [`network_namespace_id`] sends exactly one `RTM_GETNSID` request carrying
//! `NETNSA_FD`. The reply must be one kernel-originated `RTM_NEWNSID` record
//! with the matching sequence and port ID and exactly one `NETNSA_NSID`
//! attribute. An absent mapping is encoded by Linux as `-1` and fails closed.

use std::os::fd::AsRawFd as _;

use crate::pidfd::{NamespaceFd, NamespaceKind};
use crate::{Error, Result, uapi};

const RTM_NEWNSID: u16 = 88;
const RTM_GETNSID: u16 = 90;
const NLM_F_REQUEST: u16 = 1;
const NETNSA_NSID: u16 = 1;
const NETNSA_FD: u16 = 3;
const NETLINK_SEQUENCE: u32 = 0x414f_5301;
const NLMSG_HEADER_BYTES: usize = 16;
const RTGENMSG_BYTES: usize = 1;
const ATTRIBUTE_HEADER_BYTES: usize = 4;
const REQUEST_BYTES: usize = 28;
const MAXIMUM_RESPONSE_BYTES: usize = 64;
const EXCHANGE_TIMEOUT_NANOSECONDS: u64 = 2_000_000_000;

/// Resolves the observer-local ID of one retained peer Network namespace.
///
/// The query carries only the borrowed, kernel-typed namespace descriptor. It
/// never resolves a namespace name or PID and it never creates an ID mapping.
/// Callers compare the returned ID with `IFLA_LINK_NETNSID` observed in the
/// same current Network namespace.
///
/// # Errors
///
/// Returns an error if `namespace` is not a Network namespace, rtnetlink I/O
/// fails, the reply is truncated or malformed, the sender or request identity
/// differs, an unknown field is present, or Linux reports the unassigned `-1`
/// mapping.
pub fn network_namespace_id(namespace: &NamespaceFd) -> Result<u32> {
    if namespace.kind() != NamespaceKind::Network {
        return Err(Error::invalid(
            "Network namespace ID peer",
            "descriptor has the wrong namespace kind",
        ));
    }

    let request = encode_request(namespace.as_fd().as_raw_fd())?;
    let response = uapi::rtnetlink_exchange(
        &request,
        MAXIMUM_RESPONSE_BYTES,
        EXCHANGE_TIMEOUT_NANOSECONDS,
    )?;
    if response.flags & libc::MSG_TRUNC != 0 {
        return malformed("response was truncated");
    }
    if response.sender_pid != 0 || response.sender_groups != 0 {
        return malformed("response did not originate from the kernel");
    }

    decode_response(&response.bytes, NETLINK_SEQUENCE, response.port_id)
}

fn encode_request(namespace_fd: i32) -> Result<[u8; REQUEST_BYTES]> {
    let namespace_fd = u32::try_from(namespace_fd).map_err(|_| {
        Error::invalid("Network namespace ID peer", "descriptor number is negative")
    })?;
    let mut request = [0_u8; REQUEST_BYTES];
    write_u32(&mut request, 0, REQUEST_BYTES as u32);
    write_u16(&mut request, 4, RTM_GETNSID);
    write_u16(&mut request, 6, NLM_F_REQUEST);
    write_u32(&mut request, 8, NETLINK_SEQUENCE);
    write_u32(&mut request, 12, 0);
    request[NLMSG_HEADER_BYTES] = libc::AF_UNSPEC as u8;

    let attribute = align(NLMSG_HEADER_BYTES + RTGENMSG_BYTES);
    write_u16(
        &mut request,
        attribute,
        (ATTRIBUTE_HEADER_BYTES + size_of::<u32>()) as u16,
    );
    write_u16(&mut request, attribute + 2, NETNSA_FD);
    write_u32(
        &mut request,
        attribute + ATTRIBUTE_HEADER_BYTES,
        namespace_fd,
    );
    Ok(request)
}

fn decode_response(bytes: &[u8], sequence: u32, port_id: u32) -> Result<u32> {
    if bytes.len() < align(NLMSG_HEADER_BYTES + RTGENMSG_BYTES) + ATTRIBUTE_HEADER_BYTES {
        return malformed("response is shorter than its fixed fields");
    }
    let length = read_u32(bytes, 0)? as usize;
    if length != bytes.len() || align(length) != length {
        return malformed("response length is not exact and aligned");
    }
    if read_u16(bytes, 4)? != RTM_NEWNSID
        || read_u16(bytes, 6)? != 0
        || read_u32(bytes, 8)? != sequence
        || read_u32(bytes, 12)? != port_id
        || bytes[NLMSG_HEADER_BYTES] != libc::AF_UNSPEC as u8
    {
        return malformed("response header differs from the request");
    }

    let attribute_offset = align(NLMSG_HEADER_BYTES + RTGENMSG_BYTES);
    let attribute_length = usize::from(read_u16(bytes, attribute_offset)?);
    if read_u16(bytes, attribute_offset + 2)? != NETNSA_NSID
        || attribute_length != ATTRIBUTE_HEADER_BYTES + size_of::<i32>()
        || attribute_offset + align(attribute_length) != bytes.len()
    {
        return malformed("response does not contain exactly one namespace ID");
    }
    let namespace_id = read_i32(bytes, attribute_offset + ATTRIBUTE_HEADER_BYTES)?;
    u32::try_from(namespace_id).map_err(|_| Error::MalformedKernelResponse {
        object: "RTM_GETNSID",
        message: "peer namespace ID is unassigned".to_owned(),
    })
}

const fn align(length: usize) -> usize {
    (length + 3) & !3
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| malformed_error("response field is truncated"))?;
    Ok(u16::from_ne_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| malformed_error("response field is truncated"))?;
    Ok(u32::from_ne_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32> {
    read_u32(bytes, offset).map(|value| i32::from_ne_bytes(value.to_ne_bytes()))
}

fn malformed<T>(message: &'static str) -> Result<T> {
    Err(malformed_error(message))
}

fn malformed_error(message: &'static str) -> Error {
    Error::MalformedKernelResponse {
        object: "RTM_GETNSID",
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(namespace_id: i32) -> Vec<u8> {
        let mut bytes = vec![0_u8; REQUEST_BYTES];
        write_u32(&mut bytes, 0, REQUEST_BYTES as u32);
        write_u16(&mut bytes, 4, RTM_NEWNSID);
        write_u32(&mut bytes, 8, NETLINK_SEQUENCE);
        write_u32(&mut bytes, 12, 77);
        bytes[NLMSG_HEADER_BYTES] = libc::AF_UNSPEC as u8;
        let attribute = align(NLMSG_HEADER_BYTES + RTGENMSG_BYTES);
        write_u16(&mut bytes, attribute, 8);
        write_u16(&mut bytes, attribute + 2, NETNSA_NSID);
        write_u32(&mut bytes, attribute + 4, namespace_id as u32);
        bytes
    }

    #[test]
    fn exact_namespace_id_response_is_accepted() {
        assert_eq!(
            decode_response(&response(42), NETLINK_SEQUENCE, 77).unwrap(),
            42
        );
    }

    #[test]
    fn unassigned_or_wrong_peer_response_is_rejected() {
        assert!(decode_response(&response(-1), NETLINK_SEQUENCE, 77).is_err());
        assert!(decode_response(&response(42), NETLINK_SEQUENCE + 1, 77).is_err());
        assert!(decode_response(&response(42), NETLINK_SEQUENCE, 78).is_err());
    }

    #[test]
    fn extra_truncated_or_unknown_attributes_are_rejected() {
        let mut extra = response(42);
        extra.extend_from_slice(&[8, 0, 5, 0, 0, 0, 0, 0]);
        let extra_length = extra.len() as u32;
        write_u32(&mut extra, 0, extra_length);
        assert!(decode_response(&extra, NETLINK_SEQUENCE, 77).is_err());

        let mut truncated = response(42);
        truncated.pop();
        assert!(decode_response(&truncated, NETLINK_SEQUENCE, 77).is_err());

        let mut unknown = response(42);
        let attribute = align(NLMSG_HEADER_BYTES + RTGENMSG_BYTES);
        write_u16(&mut unknown, attribute + 2, NETNSA_FD);
        assert!(decode_response(&unknown, NETLINK_SEQUENCE, 77).is_err());
    }
}
