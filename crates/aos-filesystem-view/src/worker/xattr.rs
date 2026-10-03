//! Bounded immutable extended-attribute lookup and listing.
//!
//! The state in this module borrows canonical xattr bytes from the authenticated
//! structural index. It accepts connection-scoped inode identities, never paths,
//! and stages only a complete NUL-delimited list. A transport chooses either a
//! size query or a value reply before any bytes are exposed.
//! Connection admission rejects privileged namespaces until a named authenticated
//! xattr profile exists, so this module serves only the generic portable profile.

use std::mem::size_of;

use crate::{IndexXattrRange, ProjectedNodeKind, ValidatedIndex};

use super::{
    MetadataConnection, RequestBudget, RequestCheckpoint, RequestControl, WorkerError, check,
    map_index, require_output,
};

const XATTR_REPLY_BYTES: u64 = size_of::<ExtendedAttributeReply<'static>>() as u64;
const PORTABLE_MAXIMUM_NAME_BYTES: usize = 255;
const PORTABLE_MAXIMUM_VALUE_BYTES: usize = 1_048_576;

/// Bounds xattr names, values, lists, and per-inode iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedAttributeLimits {
    /// Maximum accepted request-name bytes.
    pub maximum_name_bytes: usize,
    /// Maximum value bytes returned by one request.
    pub maximum_value_bytes: usize,
    /// Maximum encoded bytes returned by one list request.
    pub maximum_list_bytes: usize,
    /// Maximum attributes inspected for one inode.
    pub maximum_attributes_per_inode: usize,
    /// Maximum heap bytes retained by list scratch.
    pub maximum_scratch_heap_bytes: u64,
}

impl ExtendedAttributeLimits {
    /// Validates a portable immutable xattr profile.
    ///
    /// # Errors
    ///
    /// Returns [`ExtendedAttributeError::InvalidLimit`] for zero bounds or for
    /// name/value bounds beyond the portable tree format.
    pub fn validate(self) -> Result<Self, ExtendedAttributeError> {
        if self.maximum_name_bytes == 0
            || self.maximum_name_bytes > PORTABLE_MAXIMUM_NAME_BYTES
            || self.maximum_value_bytes == 0
            || self.maximum_value_bytes > PORTABLE_MAXIMUM_VALUE_BYTES
            || self.maximum_list_bytes == 0
            || u32::try_from(self.maximum_list_bytes).is_err()
            || self.maximum_attributes_per_inode == 0
            || self.maximum_scratch_heap_bytes == 0
            || !matches!(
                u64::try_from(self.maximum_list_bytes),
                Ok(bytes) if bytes <= self.maximum_scratch_heap_bytes
            )
        {
            return Err(ExtendedAttributeError::InvalidLimit);
        }
        Ok(self)
    }
}

/// Carries an exact size in the transport-independent xattr profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedAttributeSize(u32);

impl ExtendedAttributeSize {
    fn from_usize(value: usize) -> Result<Self, ExtendedAttributeError> {
        Ok(Self(
            u32::try_from(value).map_err(|_| ExtendedAttributeError::ResourceExhausted)?,
        ))
    }

    /// Returns the exact byte size required by a value reply.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Borrows the complete result of one immutable xattr request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtendedAttributeReply<'a> {
    /// Reports the exact required capacity for a zero-capacity query.
    Size(ExtendedAttributeSize),
    /// Returns the complete value or NUL-delimited name list.
    Value(&'a [u8]),
}

/// Owns reusable private storage for a complete NUL-delimited xattr list.
pub struct ExtendedAttributeScratch {
    bytes: Vec<u8>,
    maximum_heap_bytes: u64,
}

impl ExtendedAttributeScratch {
    /// Preallocates the complete configured list capacity before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`ExtendedAttributeError::InvalidLimit`] for inconsistent bounds,
    /// or [`ExtendedAttributeError::AllocationRefused`] when allocation fails.
    pub fn allocate(limits: ExtendedAttributeLimits) -> Result<Self, ExtendedAttributeError> {
        let limits = limits.validate()?;
        let requested = u64::try_from(limits.maximum_list_bytes)
            .map_err(|_| ExtendedAttributeError::InvalidLimit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limits.maximum_list_bytes)
            .map_err(|_| ExtendedAttributeError::AllocationRefused)?;
        let retained = u64::try_from(bytes.capacity())
            .map_err(|_| ExtendedAttributeError::AllocationRefused)?;
        if retained > limits.maximum_scratch_heap_bytes || retained < requested {
            return Err(ExtendedAttributeError::AllocationRefused);
        }
        Ok(Self {
            bytes,
            maximum_heap_bytes: limits.maximum_scratch_heap_bytes,
        })
    }

    /// Returns the retained allocation charged to this scratch object.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> u64 {
        self.bytes.capacity() as u64
    }

    fn prepare(&mut self, length: usize) -> Result<(), ExtendedAttributeError> {
        let length =
            u64::try_from(length).map_err(|_| ExtendedAttributeError::ResourceExhausted)?;
        if length > self.maximum_heap_bytes || length > self.bytes.capacity() as u64 {
            return Err(ExtendedAttributeError::ResourceExhausted);
        }
        self.bytes.clear();
        Ok(())
    }

    fn discard(&mut self) {
        self.bytes.fill(0);
        self.bytes.clear();
    }
}

/// Reports immutable xattr validation and sizing failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExtendedAttributeError {
    /// A configured bound is zero, inconsistent, or outside the portable profile.
    #[error("invalid extended-attribute limit")]
    InvalidLimit,
    /// A request name is empty, contains NUL, or exceeds its admitted bound.
    #[error("invalid extended-attribute name")]
    InvalidName,
    /// The generic profile forbids this privileged attribute namespace.
    #[error("extended-attribute namespace requires a named profile")]
    UnsupportedNamespace,
    /// The requested attribute is absent.
    #[error("extended attribute is absent")]
    NotFound,
    /// A nonzero reply capacity is smaller than the complete result.
    #[error("extended-attribute reply buffer is too small")]
    Range,
    /// Work or output exceeded a configured byte or entry ceiling.
    #[error("extended-attribute request exceeds its resource ceiling")]
    ResourceExhausted,
    /// Exact scratch allocation was refused.
    #[error("extended-attribute scratch allocation was refused")]
    AllocationRefused,
    /// Worker identity, lease, cancellation, or authenticated index validation failed.
    #[error("extended-attribute worker failed: {0}")]
    Worker(#[from] WorkerError),
}

/// Executes xattr reads under one validated immutable profile.
#[derive(Debug)]
pub struct ExtendedAttributeState {
    limits: ExtendedAttributeLimits,
    connection_binding: [u8; 32],
    worker_brand: u64,
}

impl ExtendedAttributeState {
    /// Binds a validated xattr profile to one exact worker connection.
    ///
    /// This is a dormant source seam. Constructing it does not enable kernel
    /// callbacks or alter the metadata-only transport's feature negotiation.
    ///
    /// # Errors
    ///
    /// Returns [`ExtendedAttributeError`] for invalid limits, a sentinel
    /// connection binding, authenticated index corruption, or projected xattrs
    /// that exceed the complete connection profile.
    pub fn for_connection(
        connection: &MetadataConnection<'_, '_, '_, '_>,
        limits: ExtendedAttributeLimits,
    ) -> Result<Self, ExtendedAttributeError> {
        let limits = limits.validate()?;
        let connection_binding = connection.connection_binding();
        let worker_brand = connection.callback_instance_brand();
        if connection_binding == [0; 32]
            || worker_brand == 0
            || !connection.extended_attributes_admitted()
        {
            return Err(ExtendedAttributeError::Worker(
                WorkerError::OperationNotSupported,
            ));
        }
        validate_projection(connection, limits)?;
        Ok(Self {
            limits,
            connection_binding,
            worker_brand,
        })
    }

    /// Looks up one exact byte-name and applies Linux size-query semantics.
    ///
    /// `reply_capacity == 0` returns only the required size. A nonzero capacity
    /// must hold the complete value; partial values are never returned.
    ///
    /// # Errors
    ///
    /// Returns [`ExtendedAttributeError`] for invalid names, stale nodes,
    /// absent attributes, insufficient capacity, budget/cancellation failure,
    /// or authenticated index corruption.
    pub fn get<'index>(
        &self,
        connection: &MetadataConnection<'_, 'index, '_, '_>,
        node_id: u64,
        name: &[u8],
        reply_capacity: usize,
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<ExtendedAttributeReply<'index>, ExtendedAttributeError> {
        self.validate_connection(connection)?;
        connection.ready_budget(budget)?;
        connection.authorize_request(control)?;
        validate_name(name, self.limits.maximum_name_bytes)?;
        if requires_named_profile(name) {
            return Err(ExtendedAttributeError::UnsupportedNamespace);
        }
        check(control, RequestCheckpoint::BeforeWork)?;

        let xattrs = projected_xattrs(connection, node_id)?;
        let Some(xattrs) = xattrs else {
            return Err(ExtendedAttributeError::NotFound);
        };
        if xattrs.len() > self.limits.maximum_attributes_per_inode {
            return Err(ExtendedAttributeError::ResourceExhausted);
        }
        let mut found = None;
        for candidate in xattrs {
            check(control, RequestCheckpoint::DuringReadOnlyWork)?;
            let candidate = candidate.map_err(map_index)?;
            match candidate.name().cmp(name) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    found = Some(candidate.value());
                    break;
                }
                std::cmp::Ordering::Greater => break,
            }
        }
        let value = found.ok_or(ExtendedAttributeError::NotFound)?;
        if value.len() > self.limits.maximum_value_bytes {
            return Err(ExtendedAttributeError::ResourceExhausted);
        }
        let required = ExtendedAttributeSize::from_usize(value.len())?;
        require_output(budget, XATTR_REPLY_BYTES)?;
        check(control, RequestCheckpoint::AfterReadOnlyWork)?;

        if reply_capacity == 0 {
            Ok(ExtendedAttributeReply::Size(required))
        } else if reply_capacity < value.len() {
            Err(ExtendedAttributeError::Range)
        } else if value.len() > budget.variable_bytes {
            Err(ExtendedAttributeError::ResourceExhausted)
        } else {
            Ok(ExtendedAttributeReply::Value(value))
        }
    }

    /// Lists canonical names with exactly one trailing NUL per name.
    ///
    /// `reply_capacity == 0` returns only the required size. The result is empty
    /// for synthetic directories and for source nodes with no xattrs.
    ///
    /// # Errors
    ///
    /// Returns [`ExtendedAttributeError`] for stale nodes, insufficient capacity,
    /// exhausted byte/entry budgets, cancellation, or index corruption.
    pub fn list<'scratch>(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        node_id: u64,
        reply_capacity: usize,
        budget: RequestBudget,
        scratch: &'scratch mut ExtendedAttributeScratch,
        control: &impl RequestControl,
    ) -> Result<ExtendedAttributeReply<'scratch>, ExtendedAttributeError> {
        self.validate_connection(connection)?;
        connection.ready_budget(budget)?;
        connection.authorize_request(control)?;
        check(control, RequestCheckpoint::BeforeWork)?;

        let xattrs = projected_xattrs(connection, node_id)?;
        if xattrs.is_some_and(|xattrs| xattrs.len() > self.limits.maximum_attributes_per_inode) {
            return Err(ExtendedAttributeError::ResourceExhausted);
        }
        let mut required_bytes = 0_usize;
        if let Some(xattrs) = xattrs {
            for candidate in xattrs {
                check(control, RequestCheckpoint::DuringReadOnlyWork)?;
                let candidate = candidate.map_err(map_index)?;
                validate_name(candidate.name(), self.limits.maximum_name_bytes)?;
                required_bytes = required_bytes
                    .checked_add(candidate.name().len())
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ExtendedAttributeError::ResourceExhausted)?;
                if required_bytes > self.limits.maximum_list_bytes {
                    return Err(ExtendedAttributeError::ResourceExhausted);
                }
            }
        }
        let required = ExtendedAttributeSize::from_usize(required_bytes)?;
        require_output(budget, XATTR_REPLY_BYTES)?;
        check(control, RequestCheckpoint::AfterReadOnlyWork)?;

        if reply_capacity == 0 {
            return Ok(ExtendedAttributeReply::Size(required));
        }
        if reply_capacity < required_bytes {
            return Err(ExtendedAttributeError::Range);
        }
        if required_bytes > budget.variable_bytes {
            return Err(ExtendedAttributeError::ResourceExhausted);
        }

        scratch.prepare(required_bytes)?;
        if let Some(xattrs) = projected_xattrs(connection, node_id)? {
            for candidate in xattrs {
                check(control, RequestCheckpoint::DuringReadOnlyWork)
                    .inspect_err(|_| scratch.discard())?;
                let candidate = candidate
                    .map_err(map_index)
                    .inspect_err(|_| scratch.discard())?;
                scratch.bytes.extend_from_slice(candidate.name());
                scratch.bytes.push(0);
            }
        }
        check(control, RequestCheckpoint::AfterReadOnlyWork).inspect_err(|_| scratch.discard())?;
        Ok(ExtendedAttributeReply::Value(&scratch.bytes))
    }

    fn validate_connection(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
    ) -> Result<(), ExtendedAttributeError> {
        if connection.connection_binding() != self.connection_binding
            || connection.callback_instance_brand() != self.worker_brand
            || connection.is_faulted()
        {
            return Err(ExtendedAttributeError::Worker(
                WorkerError::IntegrityFailure,
            ));
        }
        Ok(())
    }
}

fn validate_name(name: &[u8], maximum: usize) -> Result<(), ExtendedAttributeError> {
    if name.is_empty() || name.len() > maximum || name.contains(&0) {
        return Err(ExtendedAttributeError::InvalidName);
    }
    Ok(())
}

fn requires_named_profile(name: &[u8]) -> bool {
    name.starts_with(b"security.") || name.starts_with(b"trusted.") || name.starts_with(b"system.")
}

fn validate_projection(
    connection: &MetadataConnection<'_, '_, '_, '_>,
    limits: ExtendedAttributeLimits,
) -> Result<(), ExtendedAttributeError> {
    for projected in connection.projection.nodes() {
        let Some(record) = connection
            .projection
            .source_node(projected)
            .map_err(|_| WorkerError::IntegrityFailure)?
        else {
            continue;
        };
        let semantics = connection
            .index()
            .record_semantics(&record)
            .map_err(map_index)?;
        let xattrs = semantics.xattrs();
        if xattrs.len() > limits.maximum_attributes_per_inode {
            return Err(ExtendedAttributeError::ResourceExhausted);
        }
        let mut list_bytes = 0_usize;
        for xattr in xattrs {
            let xattr = xattr.map_err(map_index)?;
            validate_name(xattr.name(), limits.maximum_name_bytes)?;
            if requires_named_profile(xattr.name()) {
                return Err(ExtendedAttributeError::UnsupportedNamespace);
            }
            if xattr.value().len() > limits.maximum_value_bytes {
                return Err(ExtendedAttributeError::ResourceExhausted);
            }
            list_bytes = list_bytes
                .checked_add(xattr.name().len())
                .and_then(|value| value.checked_add(1))
                .ok_or(ExtendedAttributeError::ResourceExhausted)?;
            if list_bytes > limits.maximum_list_bytes {
                return Err(ExtendedAttributeError::ResourceExhausted);
            }
        }
    }
    Ok(())
}

fn projected_xattrs<'index>(
    connection: &MetadataConnection<'_, 'index, '_, '_>,
    node_id: u64,
) -> Result<Option<IndexXattrRange<'index>>, ExtendedAttributeError> {
    let ordinal = connection.projected_ordinal(node_id)?;
    let projected = connection
        .projection
        .node(ordinal)
        .ok_or(WorkerError::IntegrityFailure)?;
    if matches!(projected.kind(), ProjectedNodeKind::SyntheticDirectory) {
        return Ok(None);
    }
    let record = connection.projected_record(projected)?;
    let index: &'index ValidatedIndex<'_> = connection.index();
    let semantics = index.record_semantics(&record).map_err(map_index)?;
    Ok(Some(semantics.xattrs()))
}
