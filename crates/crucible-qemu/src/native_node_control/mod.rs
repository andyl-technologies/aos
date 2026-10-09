//! Original native command custody for the independent strict-boundary channel.
//!
//! This transport retains decoded mechanical facts without projecting them into
//! RFC-0025 execution receipts. It qualifies no simulation-node capability,
//! queue closure, input delivery, owner readiness or exact preservation. An
//! admitted provider must independently authenticate those obligations before
//! using a command or releasing any native resources.

mod transport;

pub use transport::{NativeLaunchEndpoint, NativeQemuControlError, NativeQemuControlTransport};

mod timers;
mod writers;
