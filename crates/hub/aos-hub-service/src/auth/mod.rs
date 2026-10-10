//! Hub authentication workflows and runtime delivery ports.
//!
//! Portable credential values, token/session secret generation, password
//! hashing, JWT verification, and at-rest sealing live in `aos-hub-model`.
//! This module combines those primitives with typed persistence and runtime
//! ports: OIDC login exchanges, WebAuthn registration/assertion, and transactional
//! email delivery. Native and Worker deployments share the same workflows.

pub mod magic;
pub mod oidc;
pub mod webauthn;
