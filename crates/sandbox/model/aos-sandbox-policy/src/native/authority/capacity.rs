//! Reuses canonical Root-genesis capacity DATA beneath actual native role gates.
//!
//! The sole LedgerReplay recipe owns the hashes and immutable request fields.
//! Native callers still retain their genuine fixed owner, reservation and
//! independently current final crossing; computing DATA grants no transition.

pub(super) use aos_sandbox_ledger_replay::replay::root_genesis_capacity::{
    admission_id, floor_transaction_id, request,
};
