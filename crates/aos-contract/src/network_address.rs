//! Pure global-address predicates shared by admitted network effect adapters.
//!
//! Resolution and connection pinning remain host effects. This module preserves
//! the Hub address policy without performing DNS or granting network authority.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether `ip` is a globally routable address (not local/internal).
///
/// Rejects every non-global-unicast IANA special-purpose family for IPv4 and
/// IPv6, including multicast, reserved/future-use, site-local, transition and
/// translation prefixes, and IPv4-mapped/compatible IPv6.
#[must_use]
pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => {
            // Unwrap IPv4-mapped/compatible IPv6 to apply the IPv4 rules.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_global_ipv4(mapped);
            }
            if let Some(compat) = v6.to_ipv4() {
                return is_global_ipv4(compat);
            }
            is_global_ipv6(v6)
        }
    }
}

/// Whether an IPv4 address is globally routable (not local/internal).
///
/// Rejects every IANA special-purpose range that is not globally reachable.
/// The `is_shared`/`is_benchmarking`/`is_documentation` std helpers are still
/// unstable (feature `ip`), so the shared-address, benchmarking, protocol-
/// assignment, and documentation ranges are matched explicitly.
#[must_use]
pub fn is_global_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    // 100.64.0.0/10 — RFC 6598 carrier-grade NAT shared address space.
    let is_cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
    // 192.0.0.0/24 — RFC 6890 IETF protocol assignments. Conservatively reject
    // the complete block; none is a valid arbitrary tenant origin.
    let is_protocol = o[0] == 192 && o[1] == 0 && o[2] == 0;
    // 198.18.0.0/15 — RFC 2544 benchmarking.
    let is_benchmarking = o[0] == 198 && (o[1] & 0xfe) == 18;
    // Documentation ranges (RFC 5737): 192.0.2.0/24 (TEST-NET-1),
    // 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3).
    let is_documentation = (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113);
    !(v4.is_loopback()           // 127.0.0.0/8
        || v4.is_private()        // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()     // 169.254.0.0/16 (cloud metadata)
        || v4.is_unspecified()    // 0.0.0.0
        || v4.is_broadcast()      // 255.255.255.255
        || o[0] == 0              // 0.0.0.0/8
        || is_cgnat               // 100.64.0.0/10
        || is_protocol            // 192.0.0.0/24
        || is_benchmarking        // 198.18.0.0/15
        || is_documentation  // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || o[0] >= 224) // multicast 224/4 and reserved/future-use 240/4
}

/// Whether an IPv6 address is globally routable (not local/internal).
#[must_use]
pub fn is_global_ipv6(v6: Ipv6Addr) -> bool {
    let segs = v6.segments();
    let is_unique_local = (segs[0] & 0xfe00) == 0xfc00; // fc00::/7
    let is_link_local = (segs[0] & 0xffc0) == 0xfe80; // fe80::/10
    let is_site_local = (segs[0] & 0xffc0) == 0xfec0; // fec0::/10 (deprecated)
    let is_multicast = (segs[0] & 0xff00) == 0xff00; // ff00::/8
    let is_documentation = segs[0] == 0x2001 && segs[1] == 0x0db8; // 2001:db8::/32
    let is_benchmarking = segs[0] == 0x2001 && segs[1] == 0x0002 && segs[2] == 0; // /48
    let is_orchid = segs[0] == 0x2001 && matches!(segs[1] & 0xfff0, 0x0010 | 0x0020); // /28
    let is_discard = segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0; // /64
    let is_local_translation = segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 1; // /48
    let is_teredo = segs[0] == 0x2001 && segs[1] == 0; // 2001:0000::/32
    let is_6to4 = segs[0] == 0x2002; // embeds an IPv4 address; reject tunnel bypasses
    let is_global_unicast_space = (segs[0] & 0xe000) == 0x2000; // 2000::/3
    !(v6.is_loopback()
        || v6.is_unspecified()
        || is_unique_local
        || is_link_local
        || is_site_local
        || is_multicast
        || is_documentation
        || is_benchmarking
        || is_orchid
        || is_discard
        || is_local_translation
        || is_teredo
        || is_6to4)
        && is_global_unicast_space
}
