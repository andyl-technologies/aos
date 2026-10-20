//! Owns genuinely C-funded fixed Source construction and native custody.
//!
//! The fixed constructor runs the sole complete cold replay under the actual
//! same-original Source loan. Its private native owner forwards existing
//! canonical mechanics while upper coordinators retain all live semantic,
//! capability, currentness and effect gates. SourceSignerF is a separate
//! readonly role and cannot construct this owner.

mod owner;
pub(crate) mod semantic;
mod construction;

pub use owner::SourceNativeJournalOwnerV1;
pub use construction::SourceJournalConstructionOriginalsV1;
