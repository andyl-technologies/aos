//! Owns the closed inert native17 decoded-cache vocabulary and matching walk.
//!
//! Structs retain every typed field independently from the raw envelope map.
//! Optional wire omissions are checked only where the defining serializer omits
//! them; no successful-method or completion predicate is inferred here.

use super::*;
use crate::envelope::Nullable;
use crate::handshake::{HelloRequest, HelloResult, Limits, ResumeSession, ResumedOperation};
use crate::protocol_snapshot::owned11::typed::historical_struct;
use crate::retained_metadata::ObserveMetadata;
use crucible_node_format::*;
use serde_json::{Map, Value};

#[path = "vocabulary/common.rs"]
mod common;
#[path = "vocabulary/handshake.rs"]
mod handshake;
#[path = "vocabulary/requests.rs"]
mod requests;
#[path = "vocabulary/results.rs"]
mod results;
