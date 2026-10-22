//! Public-process campaign-store composition gate.
//!
//! The owned process flights remain in one shared test module because Phase 4
//! also runs them as a packaged VM acceptance target.

#[path = "campaign_store_process.rs"]
mod campaign_store_process;
