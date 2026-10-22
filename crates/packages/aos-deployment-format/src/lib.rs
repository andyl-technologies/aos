//! Portable documents binding AOS package artifacts to deployment transactions.
//!
//! [`model`] defines authenticated envelopes and checked desired transactions;
//! [`admission`] validates image-supplied store identities. [`input`] describes
//! immutable evaluation inputs, and [`resolution_lock`] binds dependency choices.
//! [`inventory`] describes installed payload records used during image verification.
//! [`locator`] validates canonical store locators without performing filesystem
//! or subprocess operations. Execution and acquisition belong to `aos-deployment`.

pub mod admission;
pub mod input;
pub mod inventory;
pub mod locator;
pub mod model;
pub mod resolution_lock;
