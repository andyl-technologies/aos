//! Exact descendant request retention under the bounded client page budget.

use aos_proto::aos::sandbox::v1 as wire;

use super::validation::valid_tree_request_v1;
use super::{DormantClientStatePlanV1, DormantSandboxRoutingErrorV1};
use crate::public_api::proto_json::CheckedSandboxTreeV1;

/// Consumes request-bound descendant pages under the CLI's fixed page budget.
pub struct DormantSandboxTreePageConsumerV1 {
    next_request: Option<wire::ListDescendantsRequest>,
    remaining_pages: u16,
}

impl DormantSandboxTreePageConsumerV1 {
    /// Constructs a consumer for one exact initial or resumed tree request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] when the root,
    /// page bounds, or server-token/preorder-state pairing is invalid.
    pub fn new(
        request: wire::ListDescendantsRequest,
        client_state: DormantClientStatePlanV1,
    ) -> Result<Self, DormantSandboxRoutingErrorV1> {
        if !valid_tree_request_v1(&request) {
            return Err(DormantSandboxRoutingErrorV1::InvalidRequest);
        }
        Ok(Self {
            next_request: Some(request),
            remaining_pages: client_state.maximum_pages,
        })
    }

    /// Checks and consumes one response against the exact outstanding request.
    ///
    /// A nonterminal response installs the next request with both the original
    /// opaque server token and its exact authenticated preorder state.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] after the page
    /// budget is exhausted or when the response violates its request binding.
    pub fn consume(
        &mut self,
        response: wire::ListDescendantsResponse,
    ) -> Result<CheckedSandboxTreeV1, DormantSandboxRoutingErrorV1> {
        if self.remaining_pages == 0 {
            return Err(DormantSandboxRoutingErrorV1::InvalidRequest);
        }
        let request = self
            .next_request
            .as_ref()
            .ok_or(DormantSandboxRoutingErrorV1::InvalidRequest)?;
        let checked = CheckedSandboxTreeV1::from_response(request, response)
            .map_err(|_| DormantSandboxRoutingErrorV1::InvalidRequest)?;
        let continuation = checked.continuation().cloned();
        let next_request = continuation.map(|continuation| wire::ListDescendantsRequest {
            sandbox_id: request.sandbox_id.clone(),
            maximum_depth: request.maximum_depth,
            page_size: request.page_size,
            page_token: continuation.server_page_token().to_vec(),
            expected_preorder_before: continuation.preorder_before().clone().into(),
            ..Default::default()
        });

        self.remaining_pages -= 1;
        self.next_request = next_request;
        Ok(checked)
    }

    /// Returns the exact next request, including continuation state, when present.
    #[must_use]
    pub const fn next_request(&self) -> Option<&wire::ListDescendantsRequest> {
        self.next_request.as_ref()
    }

    /// Returns the remaining number of responses this consumer will accept.
    #[must_use]
    pub const fn remaining_pages(&self) -> u16 {
        self.remaining_pages
    }
}
