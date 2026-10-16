//! Owns portable schema evaluation over repository-authenticated metadata.
//!
//! Surface adapters consume this repository facility; repository code does not
//! call presentation-layer implementations. The surface task fills this module
//! before claiming schema conformance.
