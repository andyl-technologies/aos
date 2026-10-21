//! Transfers existing backend owners through prepaid cleanup cells.
//!
//! This module defines operations and physical observations only. The backend
//! owns its concrete partial frame, assembly, and completed execution body.
//! A handoff consumes the already allocated owner; it does not allocate one.

use crate::LifecycleApiError;

/// Names the existing boxed reservation for one cleanup cell and return destination.
///
/// This alias adds no allocation or authority. The concrete implementation
/// retains the same preallocated token through handoff and refusal.
pub type ProductionVmCleanupReservationBox<Failure, PostBody, ReturnDestination> = Box<
    dyn ProductionVmCleanupReservation<
            Failure = Failure,
            PostBody = PostBody,
            ReturnDestination = ReturnDestination,
        >,
>;

/// Returns the original reservation when preparation cannot transfer its destination.
///
/// The refusal carries the same token and preserves its occupied cleanup cell.
pub type ProductionVmCleanupPrepareResult<Failure, PostBody, ReturnDestination> = Result<
    ReturnDestination,
    ProductionVmCleanupReservationBox<Failure, PostBody, ReturnDestination>,
>;

/// Names the existing boxed driver for one authenticated cleanup cell.
///
/// The same allocation remains responsible for its physical stage and history.
pub type ProductionVmCleanupHandoffBox<Failure, PostBody> =
    Box<dyn ProductionVmCleanupHandoff<Failure = Failure, PostBody = PostBody>>;

/// Preserves both original owners when a cleanup-cell transfer refuses.
///
/// Success carries the existing handoff token. Failure returns that same
/// reservation and containing body together, without allocating replacements.
pub type ProductionVmCleanupRetainResult<Failure, PostBody, ReturnDestination> = Result<
    ProductionVmCleanupHandoffBox<Failure, PostBody>,
    (
        ProductionVmCleanupReservationBox<Failure, PostBody, ReturnDestination>,
        Box<dyn ProductionVmCleanupOwner<Failure = Failure, PostBody = PostBody>>,
    ),
>;

/// Retains an existing backend body while retrying its physical cleanup.
///
/// Implementations keep their actual partial or complete resources together.
/// Success permits destruction of that same body outside the queue lock; it
/// does not return the containing charge until destruction itself completes.
pub trait ProductionVmCleanupOwner: Send {
    /// Failure retained in the receiving owner's existing cleanup history.
    type Failure: std::error::Error + Send + 'static;

    /// Existing backend obligations retained after containing-body destruction.
    type PostBody: Send + 'static;

    /// Retries cleanup through this same owner's existing saved authority.
    ///
    /// # Errors
    /// Preserves the complete owner on physical refusal or uncertain custody.
    /// This operation admits no replacement Original, permit, epoch, or budget.
    fn retry_cleanup(&mut self) -> Result<(), Self::Failure>;

    /// Moves existing postbody obligations after successful physical cleanup.
    ///
    /// The receiver calls this before destroying this same Box. A backend with
    /// authentic external obligations must move those actual owners; absence
    /// does not prove native return or authorize release of an occupied role.
    /// Independent rejected bodies retain all their obligations on refusal.
    ///
    /// # Errors
    /// Keeps the body and untransferred obligations on incomplete or uncertain
    /// custody. This operation supplies no replacement allocation or authority.
    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure>;
}

/// Occupies one authenticated cleanup cell before lifecycle effects begin.
///
/// Implementations reserve capacity and retain its exact epoch before this
/// object is constructed. They never search for capacity during handoff. Every
/// reservation links weakly to its queue: a Target can also retain a parent
/// Source, so taking only the Target reservation would not break a strong cycle.
/// The containing Main service drains this queue before retiring its owner.
/// Dropping a reservation alone must not release an uncertain cell.
pub trait ProductionVmCleanupReservation: Send {
    /// Failure retained in the receiving owner's existing cleanup history.
    type Failure: std::error::Error + Send + 'static;

    /// Existing backend obligations retained after containing-body destruction.
    type PostBody: Send + 'static;

    /// Reserves the exact destination for a later external-body return.
    type ReturnDestination: Send + 'static;

    /// Moves this same token into its exclusive external-return destination.
    ///
    /// This pre-export custody operation performs no cleanup. Implementations
    /// validate the original epoch and vacant destination before exporting a
    /// body; the returned value retains the actual containing owner lifetime.
    ///
    /// # Errors
    /// Returns this same token without exporting a body when its original
    /// destination cannot be reserved. No replacement token is allocated.
    fn prepare_return(
        self: Box<Self>,
    ) -> ProductionVmCleanupPrepareResult<Self::Failure, Self::PostBody, Self::ReturnDestination>;

    /// Transfers the actual owner into this reservation's already occupied cell.
    ///
    /// Success returns this same preallocated token as an exact-cell handoff
    /// driver; it allocates neither another token nor an owner. The caller
    /// retains it until physical completion, then drops it before another birth.
    /// This consumes the reservation separately from the owner. The stored
    /// owner must contain no strong reservation edge back to the queue.
    ///
    /// # Errors
    /// Returns the same reservation and owner when the queue no longer exists
    /// or its exact epoch cannot be authenticated. The caller retains both for
    /// the same retry; refusal certifies neither cleanup nor a reusable cell.
    fn retain(
        self: Box<Self>,
        owner: Box<
            dyn ProductionVmCleanupOwner<Failure = Self::Failure, PostBody = Self::PostBody>,
        >,
    ) -> ProductionVmCleanupRetainResult<Self::Failure, Self::PostBody, Self::ReturnDestination>;

    /// Accepts the original externally returned body without waiting on its
    /// prepared-owner borrow. This is fixed custody delivery, not cleanup.
    ///
    /// The canonical implementation serializes only its short control metadata,
    /// retains matching poisoned custody in quarantine, and never executes IO,
    /// callbacks or destructors under that mutex. No replacement Box is born.
    ///
    /// # Errors
    /// Returns both same owners on missing Main, stale epoch or an occupied
    /// destination. Refusal certifies neither destruction nor physical return.
    fn retain_returned(
        self: Box<Self>,
        owner: Box<
            dyn ProductionVmCleanupOwner<Failure = Self::Failure, PostBody = Self::PostBody>,
        >,
    ) -> ProductionVmCleanupRetainResult<Self::Failure, Self::PostBody, Self::ReturnDestination>;
}

/// Reports physical facts about one actual cleanup cell and epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionVmCleanupStage {
    /// The complete containing body remains owned or destruction is uncertain.
    BodyRetained,
    /// The actual body was destroyed, but its containing-body lease remains open.
    BodyDestroyed,
    /// Actual destruction and closure of its containing-body lease completed.
    ///
    /// Aggregate World resources remain owned until their independent native
    /// members and aggregate owner close. This is not an aggregate refund.
    Complete,
}

/// Drives only the exact cell that received an already allocated owner.
///
/// Publication alone is not physical cleanup. The same token Box is retained
/// throughout; no new Original, queue selection or allocation is supplied.
pub trait ProductionVmCleanupHandoff: Send {
    /// Failure retained in the receiving owner's existing cleanup history.
    type Failure: std::error::Error + Send + 'static;

    /// Existing backend obligations retained after containing-body destruction.
    type PostBody: Send + 'static;

    /// Performs one bounded cleanup attempt on this exact cell and epoch.
    ///
    /// # Errors
    /// Refuses a missing containing Main, stale cell, saved-owner cleanup,
    /// destruction uncertainty or containing charge return. The same driver
    /// remains usable; an error does not identify the physical stage.
    fn retry(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;

    /// Observes and latches this cell's physical stage without running cleanup.
    ///
    /// Observing complete closure transfers its first cleanup cause into this
    /// same token before the cell can be reused. A completed receipt remains
    /// factual across later epochs and never drives their owners.
    ///
    /// # Errors
    /// Refuses unavailable or inconsistent custody without claiming closure.
    fn stage(&mut self) -> Result<ProductionVmCleanupStage, LifecycleApiError>;

    /// Borrows the first cleanup cause transferred at physical completion.
    ///
    /// Earlier refusal remains in the exact cell until completion is observed.
    /// This historical cause does not change a factual `Complete` stage.
    fn first_failure(&self) -> Option<&Self::Failure>;

    /// Retains the complete terminal body inside this same preborn token.
    ///
    /// Returns true only after the backend's actual terminal-return checks and
    /// once-only ownership transfer. False leaves the same token responsible;
    /// body completion alone cannot supply native or containing-role closure.
    /// This operation allocates no replacement Box and creates no authority.
    fn retain_post_body(&mut self) -> bool;

    /// Borrows the complete terminal body already retained by this same token.
    ///
    /// This is history access, not cleanup permission or a physical-return cut.
    fn retained_post_body(&self) -> Option<&Self::PostBody>;

    /// Destroys this token allocation before disposing its retained terminal body.
    ///
    /// The terminal body keeps its actual containing role until the original
    /// token and every token-owned first cause have been destroyed. A pending
    /// token still leaves its actual backend-owned body in that same backend.
    fn dispose(self: Box<Self>);

    /// Moves terminal obligations while retaining their actual containing role.
    ///
    /// Body/lease completion alone cannot replace independent native return or
    /// final observer discharge. The returned value must keep its role until
    /// actual nested reports and owners are destroyed. No new Box is allocated.
    ///
    /// # Errors
    /// Returns this same driver while any actual obligation or role is pending.
    fn into_post_body(
        self: Box<Self>,
    ) -> Result<Self::PostBody, ProductionVmCleanupHandoffBox<Self::Failure, Self::PostBody>>;
}
