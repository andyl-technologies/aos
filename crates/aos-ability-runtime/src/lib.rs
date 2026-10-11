//! Durable activation and recovery of native module operation graphs.
//!
//! [`activation`] reconciles checked desired state through typed handlers.
//! [`journal`] stores bounded, checksummed execution history and supports
//! validated read-only inspection. [`adapter`] supplies cancellation and process
//! budget controls shared by handlers and immutable-source evaluation.

#![forbid(unsafe_code)]

pub mod activation;
pub mod adapter;
pub mod journal;
