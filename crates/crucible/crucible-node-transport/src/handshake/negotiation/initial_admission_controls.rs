//! Names initialized source controls of original initial SDK negotiation.
//!
//! The defining SDK owns its private Completed wrapper and lease types. This
//! supplier exposes their layouts without constructing a configuration, claim,
//! wrapper or authority. Complete native admission remains a separate caller.

use super::{Handshake, OriginalCompletedHello};
use crate::ProviderError;
use crate::handshake::{
    ConnectionAuthority, HelloRequest, HelloResult, Limits, NegotiationPolicy, TrustedInstallation,
};
use crucible_node_format::{ContractError, Extensions, Id, IdSet};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex, atomic::AtomicU64},
};

// Comparison quoting relies on this closed outer wrapper and its empty map.
const _: fn(&OriginalCompletedHello<'_>) = |value| {
    let OriginalCompletedHello {
        status: _,
        operation_state: _,
        result: _,
        extensions: _,
    } = value;
    let _: &&HelloResult = &value.result;
    let _: &Extensions = &value.extensions;
};

impl Handshake {
    /// Names initialized headers and controls on the original initial-only path.
    ///
    /// Owning backing, concrete validators, tree operations, comparison field
    /// paths and trusted callbacks remain independent constructor terms. The
    /// caller must exclude resumption before using this closed source roster.
    pub(crate) const fn original_initial_admission_controls_data() -> [usize; 2] {
        use std::mem::size_of;

        let transient = size_of::<OriginalCompletedHello<'static>>() * 2
            + size_of::<ConnectionAuthority>() * 3
            + size_of::<Id>() * 5
            + size_of::<Limits>() * 3
            + size_of::<Result<Limits, ContractError>>()
            + size_of::<Option<Id>>()
            + size_of::<Option<IdSet>>()
            + size_of::<Arc<AtomicU64>>() * 2
            + size_of::<Arc<Mutex<()>>>() * 3
            + size_of::<BTreeSet<String>>() * 2
            + size_of::<Result<ConnectionAuthority, ProviderError>>() * 3;
        let scratch = size_of::<&mut Self>() * 3
            + size_of::<&crate::envelope::Envelope>() * 4
            + size_of::<&HelloRequest>() * 3
            + size_of::<&HelloResult>() * 3
            + size_of::<Option<(&HelloRequest, &HelloResult)>>() * 2
            + size_of::<&TrustedInstallation>()
            + size_of::<&NegotiationPolicy>()
            + size_of::<std::sync::MutexGuard<'static, ()>>()
            + size_of::<
                Result<
                    std::sync::MutexGuard<'static, ()>,
                    std::sync::PoisonError<std::sync::MutexGuard<'static, ()>>,
                >,
            >()
            + size_of::<std::collections::btree_map::Iter<'static, String, Id>>()
            + size_of::<
                std::iter::Chain<
                    std::collections::btree_map::Keys<'static, String, Value>,
                    std::collections::btree_map::Keys<'static, String, Value>,
                >,
            >()
            + size_of::<
                std::iter::Chain<std::slice::Iter<'static, Id>, std::slice::Iter<'static, Id>>,
            >()
            + size_of::<std::slice::Iter<'static, Id>>() * 3
            + size_of::<[&crate::envelope::Nullable<Id>; 8]>()
            + size_of::<std::slice::Iter<'static, &'static crate::envelope::Nullable<Id>>>()
            + size_of::<Option<&Id>>() * 5
            + size_of::<&str>() * 4
            + size_of::<&[u8]>() * 4
            + size_of::<std::iter::Zip<std::slice::Iter<'static, u8>, std::slice::Iter<'static, u8>>>(
            )
            + size_of::<Option<(&u8, &u8)>>()
            + size_of::<u8>() * 4
            + size_of::<bool>() * 6
            + size_of::<usize>() * 6
            + size_of::<u64>() * 4
            + size_of::<Option<u64>>()
            + size_of::<ProviderError>() * 3
            + size_of::<Result<(), ProviderError>>() * 5;
        [transient, scratch]
    }
}
