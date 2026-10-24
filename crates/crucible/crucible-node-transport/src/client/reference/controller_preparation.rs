//! Returns the same original session and journals when controller preparation refuses.
//!
//! The constructor performs no control call and creates no replacement owner.
//! An owning launcher retains this failure beside the original source guard.

use super::*;

/// Retains all original preparation inputs after a controller validation failure.
pub struct ReferenceControllerPreparationFailure {
    /// Reports the original refusal without inferring native rollback.
    pub error: ProviderError,
    /// Retains the same independently regenerated profile.
    pub profile: ReferenceProfile,
    /// Retains private original credentials, never serialized or diagnosed.
    pub bootstrap: ReferenceServiceBootstrap,
    /// Retains the actual authenticated connection and registration lease.
    pub session: ClientSession,
    /// Retains original request/content journals, including partial installation.
    pub custody: ClientCustody,
    /// Retains the original whole-exchange physical deadline budget.
    pub budget: Duration,
    /// Retains the original complete host qualification roster.
    pub qualifications: Vec<ContentRef>,
}

impl ReferenceController {
    /// Prepares original public control while returning every owner on refusal.
    ///
    /// Uses the same validation and body installation as `new_qualified`.
    /// No Discover, Realize, Stage or execution call occurs here. The caller
    /// supervises returned session and journals beneath the same source capsule.
    ///
    /// # Errors
    /// Returns all original inputs on invalid private scope, missing negotiated
    /// evidence, malformed source bodies or exhausted original content credit.
    pub fn new_qualified_owned(
        profile: ReferenceProfile,
        bootstrap: ReferenceServiceBootstrap,
        session: ClientSession,
        mut custody: ClientCustody,
        budget: Duration,
        qualifications: Vec<ContentRef>,
    ) -> Result<Self, Box<ReferenceControllerPreparationFailure>> {
        let checked = (|| {
            bootstrap.validate()?;
            profile.bind_qualified(bootstrap.authority.clone(), &qualifications)?;
            for reference in &qualifications {
                let installed = bootstrap
                    .installed_content
                    .iter()
                    .find(|content| content.reference == *reference)
                    .ok_or(ProviderError::Correlation(
                        "private installed qualification bytes unavailable",
                    ))?;
                reference.verify(installed.bytes.as_slice())?;
            }
            if budget.is_zero()
                || session.authority().session_id() != &bootstrap.authority.session_id
                || session.authority().incarnation_id() != &bootstrap.authority.incarnation_id
                || !session
                    .authority()
                    .selected_features()
                    .iter()
                    .any(|feature| feature.as_str() == "cnp.control-evidence/1")
            {
                return Err(ProviderError::Correlation(
                    "reference controller lacks original admitted evidence scope",
                ));
            }
            custody.content_mut().install_borrowed(
                profile
                    .content_objects()
                    .iter()
                    .map(|object| (&object.reference, object.bytes.as_slice()))
                    .chain(
                        bootstrap
                            .installed_content
                            .iter()
                            .map(|object| (&object.reference, object.bytes.as_slice())),
                    ),
            )?;
            Ok::<_, ProviderError>(())
        })();
        if let Err(error) = checked {
            return Err(Box::new(ReferenceControllerPreparationFailure {
                error,
                profile,
                bootstrap,
                session,
                custody,
                budget,
                qualifications,
            }));
        }
        Ok(Self {
            profile,
            bootstrap,
            session,
            custody,
            budget,
            qualifications,
            observer: None,
            transmissions: None,
            conflicts: None,
        })
    }
}
