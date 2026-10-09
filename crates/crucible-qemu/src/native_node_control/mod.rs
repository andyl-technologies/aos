//! Original native command custody for the independent strict-boundary channel.
//!
//! This transport retains decoded mechanical facts without projecting them into
//! RFC-0025 execution receipts. It qualifies no simulation-node capability,
//! queue closure, input delivery, owner readiness or exact preservation. An
//! admitted provider must independently authenticate those obligations before
//! using a command or releasing any native resources.

mod transport;
pub use transport::administration::NativeAdministrationTransport;

pub use transport::{NativeLaunchEndpoint, NativeQemuControlError, NativeQemuControlTransport};

mod source_fault;
mod timers;
mod writers;

mod initialization;

mod phase;
mod preparation_successor;

mod root;
pub use root::NativeFixedMicrovmParameters;
