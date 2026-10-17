//! Returned API values retaining their original owned-output resource custody.

pub(crate) mod wire;

use crucible::{EngineError, owned_decode};

/// An owned API value together with the credits that admitted its storage.
///
/// The value is destroyed before its custody. Moving the parts into a report
/// requires retaining the custody until every corresponding owned field drops.
#[derive(Debug)]
pub struct AdmittedOutput<T> {
    value: T,
    custody: owned_decode::DecodeCustody,
}

impl<T> std::ops::Deref for AdmittedOutput<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for AdmittedOutput<T> {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl<T: PartialEq> PartialEq for AdmittedOutput<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq> Eq for AdmittedOutput<T> {}

impl<T: PartialEq> PartialEq<T> for AdmittedOutput<T> {
    fn eq(&self, other: &T) -> bool {
        self.value == *other
    }
}

impl<T> AdmittedOutput<T> {
    /// Borrows the value while its original credits remain retained.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Restores the retained original account for a bounded synchronous operation.
    ///
    /// The guard is local to the current thread and must not cross an await.
    #[must_use]
    pub fn enter_original_scope(&self) -> Option<owned_decode::DecodeScope> {
        self.custody.enter()
    }

    /// Projects an owned value while preserving the same allocation custody.
    ///
    /// The projection moves existing fields rather than copying physical bodies.
    /// Any additional allocation must be admitted before construction under the
    /// retained original account. The account is installed only for this
    /// synchronous projection and is never held across an await.
    ///
    /// # Errors
    /// Returns the projection's error; unreturned fields close before custody.
    pub fn try_map<U, E>(
        self,
        project: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<AdmittedOutput<U>, E> {
        let Self { value, custody } = self;
        let _scope = custody.enter();
        let value = project(value)?;
        Ok(AdmittedOutput { value, custody })
    }

    /// Moves an owned value into another shape with the same allocation custody.
    ///
    /// Additional allocations must be admitted under the retained original
    /// account before construction. The scope is local to this synchronous
    /// projection and must not cross an await.
    #[must_use]
    pub fn map<U>(self, project: impl FnOnce(T) -> U) -> AdmittedOutput<U> {
        let Self { value, custody } = self;
        let _scope = custody.enter();
        let value = project(value);
        AdmittedOutput { value, custody }
    }

    /// Transfers the value and its credits together to another owning scope.
    #[must_use]
    pub fn into_parts(self) -> (T, owned_decode::DecodeCustody) {
        (self.value, self.custody)
    }

    pub(crate) fn build(
        render: impl FnOnce() -> Result<T, EngineError>,
    ) -> Result<Self, EngineError> {
        Self::try_build(render, admission)
    }

    pub(crate) fn try_build<E>(
        render: impl FnOnce() -> Result<T, E>,
        admission: impl Fn(owned_decode::DecodeAdmissionError) -> E,
    ) -> Result<Self, E> {
        let budget = owned_decode::require_current_child_budget().map_err(&admission)?;
        let _scope = budget.enter();
        let custody = budget.custody();
        let value = render()?;
        budget.check().map_err(admission)?;
        Ok(Self { value, custody })
    }
}

pub(crate) fn admission(source: owned_decode::DecodeAdmissionError) -> EngineError {
    EngineError::ArtifactDecodeAdmission { source }
}

pub(crate) fn text(value: &(impl std::fmt::Display + ?Sized)) -> Result<String, EngineError> {
    owned_decode::display_string(value).map_err(admission)
}

/// Immutable shared API storage retaining its original allocation credits.
///
/// Cloning the enclosing [`std::sync::Arc`] shares both the body and custody.
/// The body is destroyed before its resource receipts on the final drop.
#[derive(Debug)]
pub struct AdmittedShared<T> {
    value: T,
    _custody: owned_decode::DecodeCustody,
}

impl<T> std::ops::Deref for AdmittedShared<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: PartialEq> PartialEq for AdmittedShared<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq> Eq for AdmittedShared<T> {}

impl<T: std::hash::Hash> std::hash::Hash for AdmittedShared<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

/// Admits the actual Arc header, alignment and body before immutable sharing.
pub(crate) fn shared<T>(value: T) -> Result<std::sync::Arc<AdmittedShared<T>>, EngineError> {
    let custody = owned_decode::require_current_custody().map_err(admission)?;
    let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
        .extend(std::alloc::Layout::new::<AdmittedShared<T>>())
        .map_err(|source| admission(owned_decode::DecodeAdmissionError::new(source)))?;
    owned_decode::charge_bytes(layout.pad_to_align().size() as u64).map_err(admission)?;
    Ok(std::sync::Arc::new(AdmittedShared {
        value,
        _custody: custody,
    }))
}

#[cfg(test)]
pub(crate) mod tests;
