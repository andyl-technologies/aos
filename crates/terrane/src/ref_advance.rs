//! Owns durable ref transitions and live watches from specification 09.

// Guard diagnostics reuse the operation's actual clock without another tracer.
#[cfg(test)]
pub(crate) use native::PhaseTrace;
