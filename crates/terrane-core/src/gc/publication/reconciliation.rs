//! Owns the registered local reconciliation record's ordinary format fields.
//!
//! Its authorization digest, fence pointer, exclusion and index digest are
//! represented data. Encoding or decoding cannot establish current authority
//! or permission for a native operation.
//!
//! ```text
//! LocalGcReconciliation = {0: 1, 1: authorization-digest,
//!                          2: [fence-key, fence-digest],
//!                          3: [pack-id, cycle, epoch], 4: index-digest}
//! ```
