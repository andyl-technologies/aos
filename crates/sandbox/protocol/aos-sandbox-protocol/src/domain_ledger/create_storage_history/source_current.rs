//! Shares exact Source CurrentCut query correlation DATA.
//!
//! The Source responder must independently prove its actual Root peer and its
//! own current protected replay before signing. A decoded Root record or Held
//! receipt supplies no such owner. Reply construction and verification belong
//! to their genuine Source and Root consumers.

mod query;
mod reply;

pub use query::{SOURCE_CURRENT_QUERY_BYTES_V1, SOURCE_CURRENT_QUERY_MAGIC_V1,
    SOURCE_CURRENT_REPLY_MAGIC_V1, SourceCurrentQueryDataV1};

pub use reply::{SOURCE_CURRENT_BODY_BYTES_V1, SOURCE_CURRENT_PACKET_BYTES_V1,
    SOURCE_CURRENT_REPLY_FRAME_BYTES_V1, SOURCE_CURRENT_SIGNATURE_DOMAIN_V1,
    SourceCurrentReplyFieldsV1, SourceCurrentReplyDataV1};
