//! Reviewed notifications, compact disclosure and separately authenticated delivery.
//!
//! Subscription documents reference an already registered destination. Callback
//! bodies omit advisory text, source URLs and acknowledgement notes. A pinned
//! body survives retries; each physical attempt receives a fresh signed timestamp.
//! Work admission and receipt persistence belong to the coordinator, while the
//! same bounded executor runs in Native and Worker placements.

mod auth;
mod configuration;
mod control;
mod delivery;
mod effect;
mod installation;
mod journal;
mod summary;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod selection_tests;

pub use auth::{CallbackSignature, NotificationWorkAuth};
pub use configuration::{
    NotificationConfigurationV1, NotificationFrequency, NotificationSeverityFilter,
    NotificationSuppression, NotificationThreshold, SubscriptionV1, SubscriptionWriteV1,
};
pub use control::{DestinationReviewQueryV1, SubscriptionPageV1, SubscriptionQueryV1};
pub use delivery::{
    DeliveryOutcome, NotificationDestinationV1, NotificationTransport, NotificationWorkPlanV1,
    NotificationWorkReceiptV1, execute_notification, retry_delay,
};
pub use effect::{NOTIFICATION_EFFECT_PATH, NotificationEffectGrantV1, NotificationEffectQueryV1};
pub use installation::{
    InstalledNotificationDestination, NotificationInstallationV1, NotificationSecretBinding,
    WorkerNotificationInstallationV1,
};
pub use journal::{
    NotificationDeliveryPageV1, NotificationDeliveryQueryV1, NotificationDeliveryV1,
    NotificationFailureCode, NotificationIntentState,
};
pub use summary::{NotificationBodyV1, NotificationEventKind, NotificationSummaryV1};

/// Names the independent authenticated notification execution endpoint.
pub const NOTIFICATION_WORK_PATH: &str = "/internal/assessment/notification-work/v1";
