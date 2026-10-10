//! Runtime-neutral application services for the AOS Hub.
//!
//! Authorization, indexing, storage coordination, OAuth flows, Connect handlers,
//! and server-rendered pages run identically on native and Worker deployments.
//! Portable identities and policies live in `aos-hub-model`; typed persistence
//! and backend implementations live in `aos-hub-db`. This crate orchestrates
//! those libraries through runtime ports without owning their implementations.

pub mod auth;
pub mod binding_provision;
pub mod cache;
pub mod cache_scan;
pub mod conditional_delete_probe;
pub mod config;
pub mod connect;
mod container_catalog;
pub mod container_rollout;
pub mod coordinator;
pub mod delivery_attestation;
pub mod directory;
pub mod egress_protocol;
pub mod email;
pub mod ephemeral;
pub mod fetch;
pub mod filter;
pub mod gc_controller;
pub mod git;
pub mod gitwrite;
pub mod image_catalog;
pub mod image_http;
pub mod indexer;
pub mod jobs;
pub mod kv;
pub mod lease;
pub mod migrate;
pub mod nix_sign;
pub mod oci;
pub mod oci_gc_controller;
pub mod oci_http;
pub mod oci_inventory_controller;
pub mod placement_read;
pub mod placement_scan;
pub mod ratelimit;
pub mod registry_delete_controller;
pub mod reindex;
pub mod release_evidence;
pub mod robots;
pub mod s3surface;
pub mod service;
pub mod signing;
pub mod sigv4;
pub mod storage_credential;
/// Registry cache-stack values shared by Hub services and package clients.
pub use aos_registry_format::stack;
pub mod surface_write;
pub mod topology_probe;
pub mod web;
pub mod webhook;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod oci_recovery_tests;
