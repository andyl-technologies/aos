//! Shares passive Delete Root exchange comparison formats.
//!
//! Actual Root and Source roles retain their own native funding, fixed peers,
//! currentness and held C17/six-domain conjunction around these DATA codecs.

pub mod source_current;

pub mod transport;

/// Encodes the explicit fresh D Controller/C17 comparison cut.
pub mod controller_cut;

/// Encodes the distinct authorized-before-Planned Root comparison DATA.
pub mod planning;

/// Shares exact nonauthorizing authorization and Controller cut preimages.
pub mod named_cuts;

/// Shares exact full broker and Cache inventory cut preimages without grants.
pub mod inventory_cuts;

/// Encodes explicit complete authorization witness comparison DATA.
pub mod authorization;

/// Encodes the initial comparison frame and its nonauthorizing verification ACK.
pub mod initial_inventory;

/// Encodes the distinct post-ACK fresh comparison and final approval DATA.
pub mod final_inventory;


/// Frames exact preparatory cleanup plans on the retained Delete stream.
pub mod resource_exchange;

/// Shares finite post26 currentness comparison DATA on the same Delete exchange.
pub mod preparation_current;
pub mod cleanup_current;

/// Frames final physical and Source COMMIT comparisons without disposal authority.
pub mod completion;
pub mod controller_completion;
