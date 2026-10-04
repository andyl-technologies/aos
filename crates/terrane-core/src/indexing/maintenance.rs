//! Owns repeatable maintenance of ordinary immutable index data.
//!
//! Preparation, incremental updates, initialization, explicit rebuilding and
//! closure export have distinct accounting. Maintained states retain canonical
//! route Trees and stable borrowed bytes across successive updates. Their
//! contextual primary, occurrence and gap roles remain ordinary data contracts.
//!
//! This module declaration reserves the shared implementation boundary. The
//! exact maintenance conformance cases fail until their implementation exists.
