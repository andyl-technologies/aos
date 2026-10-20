//! Reuses one publication's derived SQL fences within a Native control request.
//!
//! Building a pointer's provenance plan validates every immutable dependency.
//! Items in the same request can share that work, while every transaction still
//! executes the exact source, receipt, copy and cardinality fences. A new request
//! rebuilds the plan; no authentication decision or successful mutation is cached.

use std::future::Future;

use anyhow::Result;

use super::super::Database;
use crate::backend::CheckedStatement;

#[cfg(not(target_arch = "wasm32"))]
use std::{cell::RefCell, sync::Arc};

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
    /// Shares one derived publication dependency plan within a logical request.
    ///
    /// The scope retains at most one publication and database identity. Other
    /// publications use ordinary uncached reads. Transactional fences remain
    /// mandatory, and errors pass through unchanged. Spawned tasks do not inherit
    /// the scope. Wasm keeps its ordinary database path.
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
        let database = std::ptr::from_ref(database) as usize;
        let cell = PLAN
            .try_with(|scope| {
                let mut selected = scope.try_borrow_mut().ok()?;
                let plan = selected.get_or_insert_with(|| PublicationPlan {
                    database,
                    publication: publication.to_owned(),
                    statements: Arc::new(tokio::sync::OnceCell::new()),
                });
                (plan.database == database && plan.publication == publication)
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
