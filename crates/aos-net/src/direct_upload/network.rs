//! Exact operator-selected private CIDRs, independent from server discovery.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ProviderError;

#[derive(Clone)]
pub(super) struct PrivateRange {
    network: IpAddr,
    prefix: u32,
}

impl PrivateRange {
    pub(super) fn parse(value: &str) -> Result<Self, ProviderError> {
        if value.len() > 64 {
            return Err(ProviderError::InvalidGrant);
        }
        let (address, prefix) = value.split_once('/').ok_or(ProviderError::InvalidGrant)?;
        let network: IpAddr = address.parse().map_err(|_| ProviderError::InvalidGrant)?;
        let prefix: u32 = prefix.parse().map_err(|_| ProviderError::InvalidGrant)?;
        let result = Self { network, prefix };
        let allowed = match network {
            IpAddr::V4(address) if prefix <= 32 => {
                let first = u32::from(address);
                let host = u32::MAX.checked_shr(prefix).unwrap_or(0);
                let last = Ipv4Addr::from(first | host);
                first & host == 0
                    && ((address.is_private() && last.is_private())
                        || (address.is_loopback() && last.is_loopback()))
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let first = u128::from(address);
                let host = u128::MAX.checked_shr(prefix).unwrap_or(0);
                let last = Ipv6Addr::from(first | host);
                first & host == 0
                    && ((address.is_unique_local() && last.is_unique_local())
                        || (address.is_loopback() && prefix == 128))
            }
            _ => false,
        };
        if !allowed {
            return Err(ProviderError::InvalidGrant);
        }
        // Canonical network notation avoids ambiguous operator policy strings.
        if value != format!("{network}/{prefix}") {
            return Err(ProviderError::InvalidGrant);
        }
        Ok(result)
    }

    pub(super) fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix).unwrap_or(0);
                u32::from(network) == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix).unwrap_or(0);
                u128::from(network) == u128::from(address) & mask
            }
            (IpAddr::V4(_), IpAddr::V6(address)) => address
                .to_ipv4_mapped()
                .is_some_and(|address| self.contains(IpAddr::V4(address))),
            _ => false,
        }
    }
}
