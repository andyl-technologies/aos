//! Shared bounded record exchange used by Storage RPC.

pub(crate) use aos_sandbox_linux::seqpacket::bounded::{
    accept_connection, boottime, receive, send,
};

/// Fixed wall-independent ceiling for one accepted hello/request exchange.
pub(crate) const EXCHANGE_NANOSECONDS: u64 = 10_000_000_000;
