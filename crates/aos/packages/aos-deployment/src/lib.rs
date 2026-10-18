//! Scope-neutral AOS deployment evaluation and durable activation execution.
//!
//! [`evaluation`] evaluates authenticated module inputs; [`source_views`] supplies
//! bounded immutable snapshots and [`nix`] builds pure evaluator commands.
//! [`handler`] and [`process`] execute bounded operations. [`retention`], [`store`],
//! and [`transaction`] preserve inputs and coordinate journaled generations.
//! [`document`], [`input`], and [`artifact`] acquire and authenticate immutable
//! deployment documents. Portable schemas belong to `aos-deployment-format`;
//! package installation and registry selection remain caller responsibilities.

pub mod artifact;
pub mod document;
pub mod evaluation;
pub mod handler;
pub mod input;
pub mod nix;
pub mod process;
pub mod retention;
pub mod source_views;
pub mod store;
pub mod transaction;
