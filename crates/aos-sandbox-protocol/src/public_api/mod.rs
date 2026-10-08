//! Pure public sandbox message models shared by clients and the Controller.
//!
//! Structural validation does not authenticate a request, adopt its provenance,
//! or grant mutation or effect authority. [`execution_result`] owns terminal
//! result projection; [`grammar_error`] shares the existing bounded-input error
//! vocabulary without owning CLI parsing; [`registry`] owns public feature names.

pub mod execution_result;
pub mod grammar_error;
pub mod registry;
