//! Reuses bounded derived SQL fences while retaining transactional verification.
//!
//! Building a pointer's provenance plan validates every immutable dependency.
//! New Native control requests can reuse one publication's plan for thirty
//! seconds after its creation. In-flight requests retain their selected plan,
//! while every transaction still executes the exact source, receipt, copy and
//! cardinality fences. No authentication decision or successful mutation is
//! cached. A failed direct transaction discards the shared plan.

use std::future::Future;

use anyhow::Result;

use super::super::Database;
use crate::backend::CheckedStatement;

#[cfg(not(target_arch = "wasm32"))]
use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

#[cfg(not(target_arch = "wasm32"))]
type PlanCell = Arc<tokio::sync::OnceCell<Vec<CheckedStatement>>>;

/// Retains one bounded, derived SQL plan, never a permission or mutation result.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
pub(in crate::db) struct PublicationPlanCache {
    selected: Mutex<Option<CachedPlan>>,
}

#[cfg(not(target_arch = "wasm32"))]
struct CachedPlan {
    publication: String,
    created: tokio::time::Instant,
    statements: PlanCell,
}

#[cfg(not(target_arch = "wasm32"))]
impl PublicationPlanCache {
    fn select(&self, publication: &str) -> PlanCell {
        let Ok(mut selected) = self.selected.lock() else {
            return Arc::new(tokio::sync::OnceCell::new());
        };
        if let Some(plan) = selected.as_ref() {
            if plan.publication == publication
                && plan.created.elapsed() < std::time::Duration::from_secs(30)
            {
                return Arc::clone(&plan.statements);
            }
        }

        let statements = Arc::new(tokio::sync::OnceCell::new());
        *selected = Some(CachedPlan {
            publication: publication.to_owned(),
            created: tokio::time::Instant::now(),
            statements: Arc::clone(&statements),
        });
        statements
    }

    fn invalidate(&self) {
        if let Ok(mut selected) = self.selected.lock() {
            *selected = None;
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct PublicationPlan {
    database: usize,
    publication: String,
    statements: Arc<tokio::sync::OnceCell<Vec<CheckedStatement>>>,
}

#[cfg(not(target_arch = "wasm32"))]
tokio::task_local! {
    static PLAN: RefCell<Option<PublicationPlan>>;
}

impl Database {
    /// Discards derived SQL after a failed transaction without replaying effects.
    pub(crate) fn invalidate_direct_dependency_plan(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        self.direct_dependency_plans.invalidate();
    }

    /// Shares one bounded derived publication dependency plan during a request.
    ///
    /// The scope retains at most one publication and database identity. Other
    /// publications use ordinary uncached reads. Native requests may reuse the
    /// database handle's most recent plan for thirty seconds. This only avoids
    /// reloading immutable terminal originals: every transaction still locks and
    /// checks the exact source, receipt, copy and cardinality pins. Errors pass
    /// through unchanged. Spawned tasks do not inherit the scope. Wasm keeps its
    /// ordinary database path.
    pub async fn with_direct_dependency_plan_scope<F: Future>(request: F) -> F::Output {
        #[cfg(not(target_arch = "wasm32"))]
        {
            PLAN.scope(RefCell::new(None), request).await
        }

        #[cfg(target_arch = "wasm32")]
        request.await
    }
}

pub(super) async fn publication_plan<F, B>(
    database: &Database,
    publication: &str,
    build: B,
) -> Result<Vec<CheckedStatement>>
where
    F: Future<Output = Result<Vec<CheckedStatement>>>,
    B: FnOnce() -> F,
{
    #[cfg(not(target_arch = "wasm32"))]
    {
        // The address distinguishes handles only inside this request. It never
        // crosses a process boundary or substitutes for a SQL identity fence.
        let identity = std::ptr::from_ref(database) as usize;
        let cell = PLAN
            .try_with(|scope| {
                let mut selected = scope.try_borrow_mut().ok()?;
                let plan = selected.get_or_insert_with(|| PublicationPlan {
                    database: identity,
                    publication: publication.to_owned(),
                    statements: database.direct_dependency_plans.select(publication),
                });
                (plan.database == identity && plan.publication == publication)
                    .then(|| Arc::clone(&plan.statements))
            })
            .ok()
            .flatten();

        if let Some(cell) = cell {
            return cell.get_or_try_init(build).await.cloned();
        }
    }

    #[cfg(target_arch = "wasm32")]
    let _ = (database, publication);

    build().await
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
