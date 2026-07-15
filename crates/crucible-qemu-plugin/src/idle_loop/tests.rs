//! Test suite for the plugin idle hot loop.
//!
//! Split across submodules (`support` fixtures, `wake_cases`, `inbound_cases`)
//! purely to keep each source file within the engineering-hygiene size limits;
//! there is no behavioural grouping beyond the two case families.

mod support;
mod wake_cases;
mod inbound_cases;
