//! Completes ordinary immutable owners with independently checked index bindings.
//!
//! Index data precedes the completed owner, and detached recipes and optional
//! common Memo records follow that owner's identity. Current policy, producer
//! evidence, authority and same-commit publication remain separate obligations.
//!
//! ```text
//! candidate entries -> index Nodes -> completed owner -> recipe -> optional Memo
//! ```
