//! Owns durable ref transitions and live watches from specification 09.

// Guard diagnostics reuse the operation's actual clock without another tracer.
#[cfg(test)]
mod phase_trace;
#[cfg(test)]
pub(crate) use phase_trace::PhaseTrace;
