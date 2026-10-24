//! Binds the sole passive Root resource-kind recipe inside native Storage.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;

aos_sandbox_protocol::define_root_storage_resource_kind_data_v2!(pub(crate));
