//! Bounded whole-placement verification for an admitted store graph.

use std::io;

use thiserror::Error;

use super::*;

/// Maximum physical placements authenticated by one production verification.
pub const MAX_STORE_GRAPH_VERIFY_PLACEMENTS: u64 = 65_536;

/// Maximum aggregate logical bytes authenticated by one production verification.
pub const MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES: u64 = 128 * 1024 * 1024 * 1024;

/// Aggregate work limits for one whole-placement verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreGraphVerificationLimits {
    maximum_placements: u64,
    maximum_logical_bytes: u64,
}

impl StoreGraphVerificationLimits {
    /// Production limits shared by every store-administration caller.
    pub const PRODUCTION: Self = Self {
        maximum_placements: MAX_STORE_GRAPH_VERIFY_PLACEMENTS,
        maximum_logical_bytes: MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES,
    };

    /// Builds exact aggregate limits no greater than the production maxima.
    ///
    /// # Errors
    ///
    /// Returns [`StoreGraphVerificationLimitsError`] when either requested
    /// limit exceeds its hard production maximum.
    pub const fn new(
        maximum_placements: u64,
        maximum_logical_bytes: u64,
    ) -> Result<Self, StoreGraphVerificationLimitsError> {
        if maximum_placements > MAX_STORE_GRAPH_VERIFY_PLACEMENTS {
            return Err(StoreGraphVerificationLimitsError::Placements {
                requested: maximum_placements,
            });
        }
        if maximum_logical_bytes > MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES {
            return Err(StoreGraphVerificationLimitsError::LogicalBytes {
                requested: maximum_logical_bytes,
            });
        }
        Ok(Self {
            maximum_placements,
            maximum_logical_bytes,
        })
    }

    /// Returns the maximum number of physical placements.
    #[must_use]
    pub const fn maximum_placements(self) -> u64 {
        self.maximum_placements
    }

    /// Returns the maximum aggregate authenticated logical bytes.
    #[must_use]
    pub const fn maximum_logical_bytes(self) -> u64 {
        self.maximum_logical_bytes
    }
}

/// Requested verification limits exceeded the non-bypassable hard maxima.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StoreGraphVerificationLimitsError {
    /// The requested placement-count bound exceeded the hard maximum.
    #[error(
        "requested physical verification placement limit {requested} exceeds {MAX_STORE_GRAPH_VERIFY_PLACEMENTS}"
    )]
    Placements {
        /// Rejected caller-provided placement limit.
        requested: u64,
    },
    /// The requested logical-byte bound exceeded the hard maximum.
    #[error(
        "requested physical verification logical-byte limit {requested} exceeds {MAX_STORE_GRAPH_VERIFY_LOGICAL_BYTES}"
    )]
    LogicalBytes {
        /// Rejected caller-provided logical-byte limit.
        requested: u64,
    },
}

/// Fixed aggregate limit exceeded by a verification inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreGraphVerificationLimit {
    /// Maximum physical placement count.
    Placements,
    /// Maximum sum of authenticated logical lengths.
    LogicalBytes,
}

/// Stable evidence for one authenticated physical leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreGraphPhysicalVerification {
    node: StoreNodeId,
    backend: String,
    generation: InventoryGeneration,
    placements: u64,
    logical_bytes: u64,
}

impl StoreGraphPhysicalVerification {
    /// Returns the exact admitted graph node.
    #[must_use]
    pub const fn node(&self) -> &StoreNodeId {
        &self.node
    }

    /// Returns the physical backend identity reproduced by both inventories.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Returns the stable inventory generation reproduced after authentication.
    #[must_use]
    pub const fn generation(&self) -> InventoryGeneration {
        self.generation
    }

    /// Returns the exact number of authenticated placements.
    #[must_use]
    pub const fn placements(&self) -> u64 {
        self.placements
    }

    /// Returns the checked sum of authenticated logical lengths.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
}

/// Terminal evidence for one complete set of per-leaf stable inventories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreGraphVerificationReport {
    configuration: StoreGraphConfigurationId,
    placements: u64,
    logical_bytes: u64,
    physical: Vec<StoreGraphPhysicalVerification>,
}

impl StoreGraphVerificationReport {
    /// Returns the exact graph configuration whose placements were verified.
    #[must_use]
    pub const fn configuration(&self) -> StoreGraphConfigurationId {
        self.configuration
    }

    /// Returns the aggregate physical placement count.
    #[must_use]
    pub const fn placements(&self) -> u64 {
        self.placements
    }

    /// Returns the aggregate authenticated logical bytes.
    #[must_use]
    pub const fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    /// Returns physical summaries in canonical graph-node order.
    #[must_use]
    pub fn physical(&self) -> &[StoreGraphPhysicalVerification] {
        &self.physical
    }
}

/// Failure to authenticate one complete stable physical store inventory.
#[derive(Debug, Error)]
pub enum StoreGraphVerificationError {
    /// A physical inventory could not be fenced or completed.
    #[error("cannot inventory physical node {node}: {source}")]
    Inventory {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Classified backend failure.
        #[source]
        source: StoreError,
    },
    /// A terminal inventory returned an unexpected backend identity.
    #[error("physical node {node} returned backend identity {actual:?}, expected {expected:?}")]
    BackendIdentityMismatch {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Node-bound backend identity expected from the inventory.
        expected: String,
        /// Backend identity returned by the terminal inventory.
        actual: String,
    },
    /// The aggregate operation exceeded one fixed work limit.
    #[error("physical inventory exceeds the fixed verification bound at node {node}: {limit:?}")]
    LimitExceeded {
        /// Node being inventoried when the aggregate limit was exceeded.
        node: StoreNodeId,
        /// Exact limit that was exceeded.
        limit: StoreGraphVerificationLimit,
    },
    /// A placement could not be opened from its exact physical leaf.
    #[error("cannot read physical node {node} object {id}: {source}")]
    Read {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Logical object that could not be opened.
        id: ContentId,
        /// Classified backend failure.
        #[source]
        source: StoreError,
    },
    /// An opened handle disagreed with its fenced inventory record.
    #[error(
        "physical node {node} object {id} changed logical length from {inventoried} to {opened}"
    )]
    LogicalLengthChanged {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Logical object whose length changed.
        id: ContentId,
        /// Logical length recorded by the fenced inventory.
        inventoried: u64,
        /// Logical length declared by the opened handle.
        opened: u64,
    },
    /// A complete placement stream failed before authenticated EOF.
    #[error("cannot authenticate physical node {node} object {id}: {source}")]
    Authenticate {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Logical object that did not authenticate completely.
        id: ContentId,
        /// Deferred stream, length, or digest failure.
        #[source]
        source: StoreError,
    },
    /// The leaf's inventory changed while its objects were authenticated.
    #[error("physical node {node} changed while it was verified")]
    InventoryChanged {
        /// Exact admitted physical node.
        node: StoreNodeId,
        /// Opening inventory generation.
        before: InventoryGeneration,
        /// Closing generation when a terminal inventory was available.
        after: Option<InventoryGeneration>,
    },
}

impl StoreGraphAdmin {
    /// Authenticates every physical placement under a stable per-leaf generation.
    ///
    /// Each leaf is inventoried independently under its exclusive
    /// administrative fence. The fence is released before the method streams
    /// every exact placement to
    /// authenticated EOF, then reacquired to reproduce the backend identity,
    /// generation, placement count, and logical-byte total. Limits apply to
    /// the aggregate across all leaves. The report contains only bounded
    /// operational summaries and never discloses placement IDs or deletion
    /// authority. A leaf may change after its closing inventory while a later
    /// leaf is verified; the report does not claim one graph-wide atomic
    /// inventory generation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreGraphVerificationError`] when a fence or inventory
    /// fails, the aggregate work limit is exceeded, a placement cannot be
    /// opened or completely authenticated, its length differs from inventory,
    /// or the terminal inventory basis changes during verification.
    pub fn verify_physical_inventory(
        &self,
        limits: StoreGraphVerificationLimits,
    ) -> Result<StoreGraphVerificationReport, StoreGraphVerificationError> {
        self.verify_physical_inventory_with_observer(limits, &mut |_| {})
    }

    pub(super) fn verify_physical_inventory_with_observer(
        &self,
        limits: StoreGraphVerificationLimits,
        after_reads: &mut dyn FnMut(&StoreNodeId),
    ) -> Result<StoreGraphVerificationReport, StoreGraphVerificationError> {
        let mut placements = 0_u64;
        let mut logical_bytes = 0_u64;
        let mut physical = Vec::with_capacity(self.physical.len());

        for (node, authority) in &self.physical {
            let mut records = Vec::new();
            let first = {
                let mut limit_failure = None;
                let inventory = {
                    let mut fence =
                        authority
                            .admin
                            .acquire_inventory_fence()
                            .map_err(|source| StoreGraphVerificationError::Inventory {
                                node: node.clone(),
                                source,
                            })?;
                    fence.visit_inventory(&mut |record| {
                        placements = placements.checked_add(1).ok_or_else(|| {
                            limit_failure = Some(StoreGraphVerificationLimit::Placements);
                            StoreError::Quota
                        })?;
                        logical_bytes = logical_bytes
                            .checked_add(record.logical_length())
                            .ok_or_else(|| {
                                limit_failure = Some(StoreGraphVerificationLimit::LogicalBytes);
                                StoreError::Quota
                            })?;
                        if placements > limits.maximum_placements {
                            limit_failure = Some(StoreGraphVerificationLimit::Placements);
                            return Err(StoreError::Quota);
                        }
                        if logical_bytes > limits.maximum_logical_bytes {
                            limit_failure = Some(StoreGraphVerificationLimit::LogicalBytes);
                            return Err(StoreError::Quota);
                        }
                        records.push(record);
                        Ok(())
                    })
                };
                match inventory {
                    Ok(summary) => summary,
                    Err(_source) if limit_failure.is_some() => {
                        return Err(StoreGraphVerificationError::LimitExceeded {
                            node: node.clone(),
                            limit: limit_failure.unwrap_or(StoreGraphVerificationLimit::Placements),
                        });
                    }
                    Err(source) => {
                        return Err(StoreGraphVerificationError::Inventory {
                            node: node.clone(),
                            source,
                        });
                    }
                }
            };
            validate_backend_identity(node, &first)?;

            for record in &records {
                let handle = authority
                    .backend
                    .read(record.id(), None)
                    .map_err(|source| StoreGraphVerificationError::Read {
                        node: node.clone(),
                        id: record.id(),
                        source,
                    })?;
                if handle.logical_length() != record.logical_length() {
                    return Err(StoreGraphVerificationError::LogicalLengthChanged {
                        node: node.clone(),
                        id: record.id(),
                        inventoried: record.logical_length(),
                        opened: handle.logical_length(),
                    });
                }
                handle.copy_to(&mut io::sink()).map_err(|source| {
                    StoreGraphVerificationError::Authenticate {
                        node: node.clone(),
                        id: record.id(),
                        source,
                    }
                })?;
            }

            after_reads(node);

            let second = {
                let mut exceeded_opening_count = false;
                let inventory = {
                    let mut fence =
                        authority
                            .admin
                            .acquire_inventory_fence()
                            .map_err(|source| StoreGraphVerificationError::Inventory {
                                node: node.clone(),
                                source,
                            })?;
                    let mut observed = 0_u64;
                    fence.visit_inventory(&mut |_record| {
                        observed = observed.checked_add(1).ok_or(StoreError::Quota)?;
                        if observed > first.objects() {
                            exceeded_opening_count = true;
                            return Err(StoreError::Quota);
                        }
                        Ok(())
                    })
                };
                match inventory {
                    Ok(summary) => summary,
                    Err(_source) if exceeded_opening_count => {
                        return Err(StoreGraphVerificationError::InventoryChanged {
                            node: node.clone(),
                            before: first.generation(),
                            after: None,
                        });
                    }
                    Err(source) => {
                        return Err(StoreGraphVerificationError::Inventory {
                            node: node.clone(),
                            source,
                        });
                    }
                }
            };
            validate_backend_identity(node, &second)?;
            if second != first {
                return Err(StoreGraphVerificationError::InventoryChanged {
                    node: node.clone(),
                    before: first.generation(),
                    after: Some(second.generation()),
                });
            }
            physical.push(StoreGraphPhysicalVerification {
                node: node.clone(),
                backend: first.backend().to_owned(),
                generation: first.generation(),
                placements: first.objects(),
                logical_bytes: first.logical_bytes(),
            });
        }

        Ok(StoreGraphVerificationReport {
            configuration: self.configuration,
            placements,
            logical_bytes,
            physical,
        })
    }
}

fn validate_backend_identity(
    node: &StoreNodeId,
    summary: &BlobInventorySummary,
) -> Result<(), StoreGraphVerificationError> {
    if summary.backend() == node.as_str() {
        return Ok(());
    }
    Err(StoreGraphVerificationError::BackendIdentityMismatch {
        node: node.clone(),
        expected: node.as_str().to_owned(),
        actual: summary.backend().to_owned(),
    })
}
