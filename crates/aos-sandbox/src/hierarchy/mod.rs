//! Pure sandbox hierarchy and filesystem-view planning models.
//!
//! This module deliberately owns no journal, broker, descriptor, or runtime
//! authority. Its bounded reducers validate controller inputs and produce
//! inert facts for a future durable integration layer.

pub mod accounting;
pub mod artifact_codec;
pub mod codec;
pub mod evidence;
pub mod exports;
pub mod graph;
pub mod history;
pub mod inspection;
pub mod model;
pub mod placement;
pub mod realizer;
pub mod recovery;
pub mod state;
