//! Conservative causal authorization for activated heterogeneous node worlds.
//!
//! [`CausalScheduler`] derives opaque grants from the sealed graph and current
//! authenticated producer bounds. [`event`] preserves superdense causality and
//! node-wide sequence allocation. Native output-bound observation, input staging
//! and publication adapters must qualify before connected nodes can advance:
//! this module never substitutes an empty queue for that missing evidence.

mod error;
pub mod event;
mod grant;
mod input;
mod observation;
mod policy;
mod scheduler;
mod snapshot;

pub use error::*;
pub use grant::*;
pub use input::*;
pub use observation::*;
pub use policy::*;
pub use scheduler::*;
pub use snapshot::*;
