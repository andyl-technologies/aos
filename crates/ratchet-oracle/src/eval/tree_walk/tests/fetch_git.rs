//! Tree-walk evaluator tests: fetch git.

use super::*;
mod part_1;
mod part_2;
use crate::attrs::repr::AttrSetReprKind;
use crate::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheFlags, ParseCacheKey,
    ParseFileKey, PersistCache, PersistFileArtifactKey,
};
use crate::heap::HeapGeneration;
use crate::runtime::alloc::{AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint};
use crate::string::NixString;
